use anyhow::{anyhow, Result};
use serde::Serialize;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::Semaphore;
use walkdir::WalkDir;

use crate::cache::PersistentCache;
use crate::config::AppConfig;
use crate::history::HistoryManager;
use crate::types::{DetectedFlag, FlagFormat};
use crate::{DetectorConfig, FlagDetector};

fn duration_ms_u64(duration: std::time::Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

pub struct AsyncAnalyzer {
    detector: FlagDetector,
    cache: Option<Arc<PersistentCache>>,
    history: Option<Arc<HistoryManager>>,
    max_concurrent: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct AnalysisResult {
    pub file_path: PathBuf,
    pub flags: Vec<DetectedFlag>,
    pub from_cache: bool,
    pub analysis_time_ms: u64,
    pub file_hash: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct BatchResult {
    pub results: Vec<AnalysisResult>,
    pub total_files: usize,
    pub cached_files: usize,
    pub total_flags: usize,
    pub total_time_ms: u64,
}

impl AsyncAnalyzer {
    /// 根据 `AppConfig` 构造异步分析器（含可选缓存与历史记录）。
    ///
    /// # Errors
    ///
    /// 当初始化缓存/历史记录失败，或配置参数无法转换为有效的资源限制时返回错误。
    pub fn new(config: &AppConfig) -> Result<Self> {
        let global_input_max = config.resources.input_max_bytes;
        let detector_input_max = u64::try_from(config.detector.max_file_size).unwrap_or(u64::MAX);
        let effective_input_max = detector_input_max.min(global_input_max);
        let mut detector_config = DetectorConfig {
            min_string_length: config.detector.min_string_length,
            max_string_length: config.detector.max_string_length,
            max_file_size: usize::try_from(effective_input_max).unwrap_or(usize::MAX),
            max_decode_depth: config.detector.max_decode_depth,
            min_confidence: config.detector.min_confidence,
            parallel: config.detector.parallel,
            ..Default::default()
        };
        // 应用 AppConfig 中的自定义 flag 正则（detector.flag_patterns）
        // 说明：无效正则会在 matcher 阶段被跳过（Regex::new 失败即忽略）。
        for (i, pat) in config.detector.flag_patterns.iter().enumerate() {
            let name = format!("custom:{}", i + 1);
            detector_config
                .flag_formats
                .push(FlagFormat::new(&name, pat).with_priority(120));
        }
        let cache = if config.cache.enabled {
            Some(Arc::new(PersistentCache::new(
                config.cache.db_path.as_deref(),
                config.to_cache_config(),
            )?))
        } else {
            None
        };

        let history = Some(Arc::new(HistoryManager::new(None, 1000)?));

        Ok(Self {
            detector: FlagDetector::new(detector_config),
            cache,
            history,
            max_concurrent: num_cpus::get().max(4),
        })
    }

    #[must_use]
    pub fn with_cache(
        mut self,
        cache: Arc<PersistentCache>,
    ) -> Self {
        self.cache = Some(cache);
        self
    }

    /// 分析单个文件并返回结果（可命中缓存）。
    ///
    /// # Errors
    ///
    /// 当读取文件、计算哈希、解析缓存或执行检测流程失败时返回错误。
    pub fn analyze(
        &self,
        file_path: &Path,
    ) -> Result<AnalysisResult> {
        let start = Instant::now();
        let file_hash = PersistentCache::compute_file_hash(file_path)?;

        // 检查缓存
        if let Some(cache) = &self.cache {
            if let Some(entry) = cache.get(&file_hash)? {
                let flags: Vec<DetectedFlag> = serde_json::from_str(&entry.result_json)?;
                return Ok(AnalysisResult {
                    file_path: file_path.to_path_buf(),
                    flags,
                    from_cache: true,
                    analysis_time_ms: duration_ms_u64(start.elapsed()),
                    file_hash,
                });
            }
        }

        // 执行分析
        let flags = self.detector.detect(file_path)?;
        let analysis_time_ms = duration_ms_u64(start.elapsed());

        // 保存到缓存
        if let Some(cache) = &self.cache {
            let json = serde_json::to_string(&flags)?;
            cache.set(file_path, &file_hash, &json)?;
        }

        // 记录历史
        if let Some(history) = &self.history {
            history.add(file_path, &file_hash, flags.len(), analysis_time_ms)?;
        }

        Ok(AnalysisResult {
            file_path: file_path.to_path_buf(),
            flags,
            from_cache: false,
            analysis_time_ms,
            file_hash,
        })
    }

    /// 并发分析多个文件路径。
    ///
    /// # Errors
    ///
    /// 当任意任务初始化失败（例如信号量关闭）或底层分析返回错误时返回错误。
    pub async fn analyze_batch(
        &self,
        paths: Vec<PathBuf>,
        show_progress: bool,
    ) -> Result<BatchResult> {
        let start = Instant::now();
        let semaphore = Arc::new(Semaphore::new(self.max_concurrent));
        let total_paths = paths.len();
        let completed = Arc::new(AtomicUsize::new(0));

        let mut handles = Vec::new();

        for path in paths {
            let sem = semaphore.clone();
            let detector = self.detector.clone();
            let cache = self.cache.clone();
            let history = self.history.clone();
            let completed = completed.clone();

            let handle = tokio::spawn(async move {
                let _permit = sem
                    .acquire()
                    .await
                    .map_err(|_| anyhow!("并发信号量已关闭"))?;
                let result =
                    Self::analyze_single(&detector, cache.as_ref(), history.as_ref(), &path);
                if show_progress {
                    let n = completed.fetch_add(1, Ordering::Relaxed) + 1;
                    if n == total_paths || n.is_multiple_of(50) {
                        log::info!("批量分析进度: {n}/{total_paths}");
                    }
                }
                result
            });

            handles.push(handle);
        }

        let mut results = Vec::new();
        let mut cached_files = 0;
        let mut total_flags = 0;

        for handle in handles {
            if let Ok(Ok(result)) = handle.await {
                if result.from_cache {
                    cached_files += 1;
                }
                total_flags += result.flags.len();
                results.push(result);
            }
        }

        Ok(BatchResult {
            total_files: results.len(),
            cached_files,
            total_flags,
            total_time_ms: duration_ms_u64(start.elapsed()),
            results,
        })
    }

    fn analyze_single(
        detector: &FlagDetector,
        cache: Option<&Arc<PersistentCache>>,
        history: Option<&Arc<HistoryManager>>,
        file_path: &Path,
    ) -> Result<AnalysisResult> {
        let start = Instant::now();
        let file_hash = PersistentCache::compute_file_hash(file_path)?;

        if let Some(cache) = cache {
            if let Some(entry) = cache.get(&file_hash)? {
                let flags: Vec<DetectedFlag> = serde_json::from_str(&entry.result_json)?;
                return Ok(AnalysisResult {
                    file_path: file_path.to_path_buf(),
                    flags,
                    from_cache: true,
                    analysis_time_ms: duration_ms_u64(start.elapsed()),
                    file_hash,
                });
            }
        }

        let flags = detector.detect(file_path)?;
        let analysis_time_ms = duration_ms_u64(start.elapsed());

        if let Some(cache) = cache {
            let json = serde_json::to_string(&flags)?;
            cache.set(file_path, &file_hash, &json)?;
        }

        if let Some(history) = history {
            history.add(file_path, &file_hash, flags.len(), analysis_time_ms)?;
        }

        Ok(AnalysisResult {
            file_path: file_path.to_path_buf(),
            flags,
            from_cache: false,
            analysis_time_ms,
            file_hash,
        })
    }

    pub fn collect_files(
        path: &Path,
        recursive: bool,
    ) -> Vec<PathBuf> {
        if path.is_file() {
            return vec![path.to_path_buf()];
        }

        let walker = if recursive {
            WalkDir::new(path)
        } else {
            WalkDir::new(path).max_depth(1)
        };

        walker
            .into_iter()
            .filter_map(std::result::Result::ok)
            .filter(|e| e.file_type().is_file())
            .map(|e| e.path().to_path_buf())
            .collect()
    }

    #[must_use]
    pub const fn history(&self) -> Option<&Arc<HistoryManager>> {
        match &self.history {
            Some(history) => Some(history),
            None => None,
        }
    }

    #[must_use]
    pub const fn cache(&self) -> Option<&Arc<PersistentCache>> {
        match &self.cache {
            Some(cache) => Some(cache),
            None => None,
        }
    }
}
