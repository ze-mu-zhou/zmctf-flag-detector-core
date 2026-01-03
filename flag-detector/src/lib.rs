#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

pub mod analyzer;
pub mod api;
pub mod archive;
pub mod auto_analyzer;
pub mod cache;
pub mod cipher;
pub mod config;
pub mod decoder;
pub mod encoding; // 共享编码模块
pub mod extractor;
pub mod facade; // 统一接口门面
pub mod hash;
pub mod hashcat;
pub mod history;
pub mod magic;
pub mod matcher;
pub mod pcap;
pub mod prelude;
pub mod rules;
pub mod stego;
pub mod tool_detector; // 工具检测模块
pub mod types;

use anyhow::Result;
use std::path::Path;

// 重新导出所有公共类型
pub use analyzer::{AnalysisResult, AsyncAnalyzer, BatchResult};
pub use cache::{CacheConfig, CacheStats, PersistentCache};
pub use cipher::{Cipher, CipherResult, CipherStep, StringScore};
pub use config::AppConfig;
pub use hash::{HashAnalysis, HashIdentifier, HashMatch};
pub use history::{HistoryEntry, HistoryManager};
pub use types::{
    CacheEntry, DecodedString, DetectedFlag, DetectionResult, DetectorConfig,
    DetectorConfigBuilder, EncodingType, ExtractedString, FileCache, FlagFormat,
};

/// 检测器实例，支持缓存和配置
#[derive(Clone)]
pub struct FlagDetector {
    config: DetectorConfig,
    cache: FileCache,
}

impl Default for FlagDetector {
    fn default() -> Self {
        Self::new(DetectorConfig::default())
    }
}

impl FlagDetector {
    /// 创建新的检测器
    #[must_use]
    pub fn new(config: DetectorConfig) -> Self {
        Self {
            config,
            cache: FileCache::new(),
        }
    }

    /// 使用构建器创建
    pub fn builder() -> DetectorConfigBuilder {
        DetectorConfig::builder()
    }

    /// 获取配置引用
    #[must_use]
    pub const fn config(&self) -> &DetectorConfig {
        &self.config
    }

    /// 获取可变配置引用
    #[must_use]
    pub const fn config_mut(&mut self) -> &mut DetectorConfig {
        &mut self.config
    }

    /// 获取缓存引用
    #[must_use]
    pub const fn cache(&self) -> &FileCache {
        &self.cache
    }

    /// 清空缓存
    pub fn clear_cache(&self) {
        self.cache.clear();
    }

    /// 检测文件中的flag
    ///
    /// # Errors
    ///
    /// 当读取文件失败、解码失败或匹配规则执行失败时返回错误。
    pub fn detect(
        &self,
        file_path: &Path,
    ) -> Result<Vec<DetectedFlag>> {
        detect_flags_with_cache(file_path, &self.config, &self.cache)
    }

    /// 检测并返回完整结果
    ///
    /// # Errors
    ///
    /// 当 `detect()` 返回错误时透传错误。
    pub fn detect_full(
        &self,
        file_path: &Path,
    ) -> Result<DetectionResult> {
        let flags = self.detect(file_path)?;
        Ok(DetectionResult {
            file_path: file_path.to_path_buf(),
            flags,
        })
    }

    /// 批量检测多个文件
    #[must_use]
    pub fn detect_batch(
        &self,
        paths: &[&Path],
    ) -> Vec<Result<DetectionResult>> {
        if self.config.parallel {
            use rayon::prelude::*;
            paths.par_iter().map(|p| self.detect_full(p)).collect()
        } else {
            paths.iter().map(|p| self.detect_full(p)).collect()
        }
    }

    /// 只提取字符串（不解码）
    ///
    /// # Errors
    ///
    /// 当文件读取失败或超过大小上限时返回错误。
    pub fn extract_strings(
        &self,
        file_path: &Path,
    ) -> Result<Vec<ExtractedString>> {
        extractor::extract_strings_cached(file_path, &self.config, &self.cache)
    }

    /// 解码字符串
    ///
    /// # Errors
    ///
    /// 当前实现一般不会返回错误（保留 `Result` 以便未来扩展）。
    pub fn decode_strings(
        &self,
        strings: &[ExtractedString],
    ) -> Result<Vec<DecodedString>> {
        decoder::decode_strings(strings, &self.config)
    }

    /// 匹配flag模式
    ///
    /// # Errors
    ///
    /// 当前实现一般不会返回错误（保留 `Result` 以便未来扩展）。
    pub fn match_flags(
        &self,
        decoded: &[DecodedString],
    ) -> Result<Vec<DetectedFlag>> {
        matcher::match_flags(decoded, &self.config)
    }

    /// 直接解码单个字符串
    #[must_use]
    pub fn decode_string(
        &self,
        input: &str,
    ) -> Vec<DecodedString> {
        let extracted = ExtractedString {
            content: input.to_string(),
            offset: 0,
        };
        decoder::decode_strings(&[extracted], &self.config).unwrap_or_default()
    }
}

/// 简单API：检测文件中的flag
///
/// # Errors
///
/// 当读取文件失败、字符串提取/解码/匹配任一步骤失败时返回错误。
pub fn detect_flags(
    file_path: &Path,
    config: &DetectorConfig,
) -> Result<Vec<DetectedFlag>> {
    log::info!("开始分析文件: {}", file_path.display());

    let extracted = extractor::extract_strings(file_path, config)?;
    let decoded = decoder::decode_strings(&extracted, config)?;
    let flags = matcher::match_flags(&decoded, config)?;

    log::info!("分析完成，找到 {} 个flag", flags.len());
    Ok(flags)
}

/// 带缓存的检测
///
/// # Errors
///
/// 当读取文件失败、字符串提取/解码/匹配任一步骤失败时返回错误。
pub fn detect_flags_with_cache(
    file_path: &Path,
    config: &DetectorConfig,
    cache: &FileCache,
) -> Result<Vec<DetectedFlag>> {
    log::info!("开始分析文件: {}", file_path.display());

    let extracted = extractor::extract_strings_cached(file_path, config, cache)?;
    let decoded = decoder::decode_strings(&extracted, config)?;
    let flags = matcher::match_flags(&decoded, config)?;

    log::info!("分析完成，找到 {} 个flag", flags.len());
    Ok(flags)
}
