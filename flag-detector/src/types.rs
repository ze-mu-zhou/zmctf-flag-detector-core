use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EncodingType {
    Plaintext,
    // Base编码
    Base64,
    Base32,
    Base58,
    Base85,
    Base91,
    Base62,
    Base16,
    Ascii85,
    Hex,
    // 经典密码
    Rot13,
    Rot47,
    Caesar(u8),
    Atbash,
    Vigenere(String), // 维吉尼亚密码
    RailFence(usize), // 栅栏密码
    Playfair(String), // Playfair密码
    Affine(u8, u8),   // 仿射密码 (a, b)
    Bacon,            // 培根密码
    // 现代编码
    UrlEncoded,
    HtmlEntity,
    UnicodeEscape,
    // 二进制编码
    Binary,
    Octal,
    // 其他
    Morse,
    Reverse,
    // XOR
    Xor(u8),
    XorMulti(Vec<u8>), // 多字节XOR
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractedString {
    pub content: String,
    pub offset: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecodedString {
    pub original: String,
    pub decoded: String,
    pub encoding_chain: Vec<EncodingType>,
    pub confidence: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectedFlag {
    pub content: String,
    pub pattern: String,
    pub source_offset: usize,
    pub encoding_chain: Vec<EncodingType>,
    pub confidence: f32,
}

/// Flag格式配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlagFormat {
    /// 格式名称 (如 "flag", "CTF", "HCTF")
    pub name: String,
    /// 正则表达式模式
    pub pattern: String,
    /// 是否启用
    pub enabled: bool,
    /// 优先级 (越高越优先)
    pub priority: u8,
}

impl FlagFormat {
    #[must_use]
    pub fn new(
        name: &str,
        pattern: &str,
    ) -> Self {
        Self {
            name: name.to_string(),
            pattern: pattern.to_string(),
            enabled: true,
            priority: 50,
        }
    }

    #[must_use]
    pub const fn with_priority(
        mut self,
        priority: u8,
    ) -> Self {
        self.priority = priority;
        self
    }
}

/// 默认flag格式
#[must_use]
pub fn default_flag_formats() -> Vec<FlagFormat> {
    vec![
        FlagFormat::new("flag", r"flag\{[^}]+\}").with_priority(100),
        FlagFormat::new("FLAG", r"FLAG\{[^}]+\}").with_priority(100),
        FlagFormat::new("CTF", r"CTF\{[^}]+\}").with_priority(90),
        FlagFormat::new("ctf", r"ctf\{[^}]+\}").with_priority(90),
        FlagFormat::new("generic", r"\w+\{[a-zA-Z0-9_\-+=/@!]+\}").with_priority(10),
    ]
}

/// 检测器配置
#[derive(Debug, Clone)]
pub struct DetectorConfig {
    // 字符串提取
    pub min_string_length: usize,
    pub max_string_length: usize,
    pub max_file_size: usize,

    // 解码配置
    pub max_decode_depth: usize,
    pub enabled_encodings: Vec<EncodingType>,
    pub xor_keys: Vec<u8>,

    // Flag匹配
    pub flag_formats: Vec<FlagFormat>,
    pub min_confidence: f32,

    // 性能
    pub parallel: bool,
    pub cache_enabled: bool,
}

impl Default for DetectorConfig {
    fn default() -> Self {
        Self {
            min_string_length: 4,
            max_string_length: 1024,
            max_file_size: 100 * 1024 * 1024,
            max_decode_depth: 3,
            enabled_encodings: vec![
                EncodingType::Base64,
                EncodingType::Base32,
                EncodingType::Base58,
                EncodingType::Base85,
                EncodingType::Base91,
                EncodingType::Base62,
                EncodingType::Base16,
                EncodingType::Ascii85,
                EncodingType::Hex,
                EncodingType::Rot13,
                EncodingType::Rot47,
                EncodingType::Atbash,
                EncodingType::Bacon,
                EncodingType::UrlEncoded,
                EncodingType::HtmlEntity,
                EncodingType::UnicodeEscape,
                EncodingType::Binary,
                EncodingType::Octal,
                EncodingType::Morse,
                EncodingType::Reverse,
            ],
            xor_keys: vec![0x20, 0x41, 0x42, 0x55, 0xAA, 0xFF],
            flag_formats: default_flag_formats(),
            min_confidence: 0.5,
            parallel: true,
            cache_enabled: true,
        }
    }
}

impl DetectorConfig {
    pub fn builder() -> DetectorConfigBuilder {
        DetectorConfigBuilder::default()
    }

    /// 添加自定义flag格式
    pub fn add_flag_format(
        &mut self,
        name: &str,
        pattern: &str,
    ) {
        self.flag_formats.push(FlagFormat::new(name, pattern));
    }

    /// 设置只使用自定义格式
    pub fn set_custom_formats_only(
        &mut self,
        formats: Vec<FlagFormat>,
    ) {
        self.flag_formats = formats;
    }

    /// 启用/禁用特定编码
    pub fn set_encoding_enabled(
        &mut self,
        encoding: EncodingType,
        enabled: bool,
    ) {
        if enabled {
            if !self.enabled_encodings.contains(&encoding) {
                self.enabled_encodings.push(encoding);
            }
        } else {
            self.enabled_encodings.retain(|e| *e != encoding);
        }
    }
}

/// 配置构建器
#[derive(Default)]
#[must_use]
pub struct DetectorConfigBuilder {
    config: DetectorConfig,
}

impl DetectorConfigBuilder {
    pub const fn min_string_length(
        mut self,
        len: usize,
    ) -> Self {
        self.config.min_string_length = len;
        self
    }

    pub const fn max_string_length(
        mut self,
        len: usize,
    ) -> Self {
        self.config.max_string_length = len;
        self
    }

    pub const fn max_decode_depth(
        mut self,
        depth: usize,
    ) -> Self {
        self.config.max_decode_depth = depth;
        self
    }

    pub const fn min_confidence(
        mut self,
        conf: f32,
    ) -> Self {
        self.config.min_confidence = conf;
        self
    }

    pub const fn parallel(
        mut self,
        enabled: bool,
    ) -> Self {
        self.config.parallel = enabled;
        self
    }

    pub const fn cache_enabled(
        mut self,
        enabled: bool,
    ) -> Self {
        self.config.cache_enabled = enabled;
        self
    }

    pub fn flag_format(
        mut self,
        name: &str,
        pattern: &str,
    ) -> Self {
        self.config
            .flag_formats
            .push(FlagFormat::new(name, pattern));
        self
    }

    pub fn clear_default_formats(mut self) -> Self {
        self.config.flag_formats.clear();
        self
    }

    pub fn xor_keys(
        mut self,
        keys: Vec<u8>,
    ) -> Self {
        self.config.xor_keys = keys;
        self
    }

    #[must_use]
    pub fn build(self) -> DetectorConfig {
        self.config
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DetectionResult {
    pub file_path: PathBuf,
    pub flags: Vec<DetectedFlag>,
}

/// 文件缓存条目
#[derive(Debug, Clone)]
pub struct CacheEntry {
    pub strings: Vec<ExtractedString>,
    pub file_hash: u64,
    pub file_size: u64,
}

/// 全局缓存
#[derive(Debug, Clone, Default)]
pub struct FileCache {
    entries: Arc<RwLock<HashMap<PathBuf, CacheEntry>>>,
}

impl FileCache {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn get(
        &self,
        path: &PathBuf,
    ) -> Option<CacheEntry> {
        self.entries.read().ok()?.get(path).cloned()
    }

    pub fn insert(
        &self,
        path: PathBuf,
        entry: CacheEntry,
    ) {
        if let Ok(mut entries) = self.entries.write() {
            entries.insert(path, entry);
        }
    }

    pub fn invalidate(
        &self,
        path: &PathBuf,
    ) {
        if let Ok(mut entries) = self.entries.write() {
            entries.remove(path);
        }
    }

    pub fn clear(&self) {
        if let Ok(mut entries) = self.entries.write() {
            entries.clear();
        }
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.read().map(|e| e.len()).unwrap_or(0)
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
