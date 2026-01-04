use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use zmctf_constraints::ResourceLimits;

use crate::cache::CacheConfig;
use crate::{DetectorConfig, FlagFormat};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AppConfig {
    #[serde(default)]
    pub detector: DetectorSettings,
    #[serde(default)]
    pub cache: CacheSettings,
    #[serde(default)]
    pub floss: FlossSettings,
    /// 全局资源与安全约束（文件大小、解压输出、外部命令 timeout/截断等）。
    #[serde(default)]
    pub resources: ResourceLimits,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectorSettings {
    #[serde(default = "default_min_string_length")]
    pub min_string_length: usize,
    #[serde(default = "default_max_string_length")]
    pub max_string_length: usize,
    #[serde(default = "default_max_file_size")]
    pub max_file_size: usize,
    #[serde(default = "default_max_decode_depth")]
    pub max_decode_depth: usize,
    #[serde(default = "default_min_confidence")]
    pub min_confidence: f32,
    #[serde(default = "default_parallel")]
    pub parallel: bool,
    #[serde(default)]
    pub flag_patterns: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheSettings {
    #[serde(default = "default_cache_enabled")]
    pub enabled: bool,
    #[serde(default = "default_max_size_mb")]
    pub max_size_mb: u64,
    #[serde(default = "default_max_entries")]
    pub max_entries: usize,
    #[serde(default = "default_ttl_hours")]
    pub ttl_hours: u64,
    #[serde(default)]
    pub db_path: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlossSettings {
    #[serde(default = "default_floss_path")]
    pub path: PathBuf,
    #[serde(default = "default_floss_min_length")]
    pub min_length: usize,
    /// 外部命令资源约束（timeout/stdout/stderr 上限等）请通过 `AppConfig.resources.external_tools` 配置。
    #[serde(flatten)]
    pub primary: FlossStringTypesPrimary,
    #[serde(flatten)]
    pub secondary: FlossStringTypesSecondary,
} // Default functions

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlossStringTypesPrimary {
    #[serde(default = "default_true")]
    pub static_strings: bool,
    #[serde(default = "default_true")]
    pub stack_strings: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlossStringTypesSecondary {
    #[serde(default = "default_true")]
    pub tight_strings: bool,
    #[serde(default = "default_true")]
    pub decoded_strings: bool,
}

const fn default_min_string_length() -> usize {
    4
}
const fn default_max_string_length() -> usize {
    10000
}
const fn default_max_file_size() -> usize {
    100 * 1024 * 1024
}
const fn default_max_decode_depth() -> usize {
    5
}
const fn default_min_confidence() -> f32 {
    0.5
}
const fn default_parallel() -> bool {
    true
}
const fn default_cache_enabled() -> bool {
    true
}
const fn default_max_size_mb() -> u64 {
    500
}
const fn default_max_entries() -> usize {
    10000
}
const fn default_ttl_hours() -> u64 {
    168
}
fn default_floss_path() -> PathBuf {
    PathBuf::from("floss")
}
const fn default_floss_min_length() -> usize {
    4
}
const fn default_true() -> bool {
    true
}

impl Default for DetectorSettings {
    fn default() -> Self {
        Self {
            min_string_length: default_min_string_length(),
            max_string_length: default_max_string_length(),
            max_file_size: default_max_file_size(),
            max_decode_depth: default_max_decode_depth(),
            min_confidence: default_min_confidence(),
            parallel: default_parallel(),
            flag_patterns: vec![
                r"flag\{[^\}]+\}".to_string(),
                r"CTF\{[^\}]+\}".to_string(),
                r"FLAG\{[^\}]+\}".to_string(),
            ],
        }
    }
}

impl Default for CacheSettings {
    fn default() -> Self {
        Self {
            enabled: default_cache_enabled(),
            max_size_mb: default_max_size_mb(),
            max_entries: default_max_entries(),
            ttl_hours: default_ttl_hours(),
            db_path: None,
        }
    }
}

impl Default for FlossSettings {
    fn default() -> Self {
        Self {
            path: default_floss_path(),
            min_length: default_floss_min_length(),
            primary: FlossStringTypesPrimary {
                static_strings: true,
                stack_strings: true,
            },
            secondary: FlossStringTypesSecondary {
                tight_strings: true,
                decoded_strings: true,
            },
        }
    }
}

impl AppConfig {
    /// 从 TOML 配置文件加载配置。
    ///
    /// # Errors
    ///
    /// 当读取文件失败或 TOML 解析失败时返回错误。
    pub fn load(path: &Path) -> Result<Self> {
        let content = fs::read_to_string(path)?;
        let config: Self = toml::from_str(&content)?;
        Ok(config)
    }

    #[must_use]
    pub fn load_or_default(path: Option<&Path>) -> Self {
        path.and_then(|p| Self::load(p).ok())
            .or_else(|| Self::load(&Self::default_config_path()).ok())
            .unwrap_or_default()
    }

    /// 将配置保存为 TOML 文件。
    ///
    /// # Errors
    ///
    /// 当创建父目录、序列化或写入文件失败时返回错误。
    pub fn save(
        &self,
        path: &Path,
    ) -> Result<()> {
        let content = toml::to_string_pretty(self)?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, content)?;
        Ok(())
    }

    #[must_use]
    pub fn default_config_path() -> PathBuf {
        config_base_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("zmctf")
            .join("config.toml")
    }

    #[must_use]
    pub const fn to_cache_config(&self) -> CacheConfig {
        CacheConfig {
            max_size_mb: self.cache.max_size_mb,
            max_entries: self.cache.max_entries,
            ttl_hours: self.cache.ttl_hours,
        }
    }

    /// 将 `AppConfig` 转换为 `DetectorConfig`（供检测器/HTTP API 使用）。
    #[must_use]
    pub fn to_detector_config(&self) -> DetectorConfig {
        let global_input_max = self.resources.input_max_bytes;
        let detector_input_max = u64::try_from(self.detector.max_file_size).unwrap_or(u64::MAX);
        let effective_input_max = detector_input_max.min(global_input_max);

        let mut detector_config = DetectorConfig {
            min_string_length: self.detector.min_string_length,
            max_string_length: self.detector.max_string_length,
            max_file_size: usize::try_from(effective_input_max).unwrap_or(usize::MAX),
            max_decode_depth: self.detector.max_decode_depth,
            min_confidence: self.detector.min_confidence,
            parallel: self.detector.parallel,
            ..Default::default()
        };

        // 应用 AppConfig 中的自定义 flag 正则（detector.flag_patterns）
        // 说明：无效正则会在 matcher 阶段被跳过（Regex::new 失败即忽略）。
        for (i, pat) in self.detector.flag_patterns.iter().enumerate() {
            let name = format!("custom:{}", i + 1);
            detector_config
                .flag_formats
                .push(FlagFormat::new(&name, pat).with_priority(120));
        }

        detector_config
    }

    /// 基础配置校验（防止明显的无效值进入运行态）。
    ///
    /// # Errors
    ///
    /// 当配置字段不满足基本约束时返回错误。
    pub fn validate(&self) -> Result<()> {
        if self.detector.min_string_length == 0 {
            bail!("detector.min_string_length 不能为 0");
        }
        if self.detector.max_string_length < self.detector.min_string_length {
            bail!("detector.max_string_length 不能小于 detector.min_string_length");
        }
        if self.detector.max_decode_depth == 0 {
            bail!("detector.max_decode_depth 不能为 0");
        }
        if !(0.0..=1.0).contains(&self.detector.min_confidence) {
            bail!("detector.min_confidence 必须在 0.0~1.0 范围内");
        }
        if self.resources.input_max_bytes == 0 {
            bail!("resources.input_max_bytes 不能为 0");
        }

        Ok(())
    }

    #[must_use]
    pub fn generate_default_config() -> String {
        toml::to_string_pretty(&Self::default()).unwrap_or_default()
    }
}

fn config_base_dir() -> Option<PathBuf> {
    if let Some(dir) = std::env::var_os("XDG_CONFIG_HOME").map(PathBuf::from) {
        return Some(dir);
    }

    #[cfg(windows)]
    {
        if let Some(dir) = std::env::var_os("APPDATA").map(PathBuf::from) {
            return Some(dir);
        }
    }

    std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".config"))
}
