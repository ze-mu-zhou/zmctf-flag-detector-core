//! Prelude 模块 - 一次性导入所有常用类型
//!
//! ```rust
//! use flag_detector::prelude::*;
//! ```

// 核心检测器
pub use crate::FlagDetector;

// 配置
pub use crate::config::AppConfig;
pub use crate::types::{DetectorConfig, DetectorConfigBuilder, FlagFormat};

// 哈希识别
pub use crate::hash::{HashAnalysis, HashIdentifier, HashMatch};

// 密码解码器
pub use crate::cipher::{Cipher, CipherResult, CipherStep, StringScore};

// 检测结果
pub use crate::types::{
    DecodedString, DetectedFlag, DetectionResult, EncodingType, ExtractedString,
};

// 缓存
pub use crate::cache::{CacheConfig, CacheStats, PersistentCache};
pub use crate::types::{CacheEntry, FileCache};

// 历史记录
pub use crate::history::{HistoryEntry, HistoryManager};

// 异步分析器
pub use crate::analyzer::{AnalysisResult, AsyncAnalyzer, BatchResult};

// 文件魔数检测
pub use crate::magic::{detect_bytes, detect_file, FileCategory, FileMagic, MagicDetector};

// 规则引擎
pub use crate::rules::{Rule, RuleEngine};

// 隐写检测
pub use crate::stego::{analyze_image, analyze_image_bytes, PngChunk, StegoAnalyzer, StegoResult};

// 压缩包分析
pub use crate::archive::{
    analyze_archive, analyze_archive_bytes, ArchiveAnalysis, ArchiveAnalyzer, ArchiveEntry,
};

// PCAP 流量分析
pub use crate::pcap::{
    analyze_pcap, analyze_pcap_bytes, DnsRecord, HttpMessage, IpProtocol, LinkType, Packet,
    PcapAnalysis, PcapAnalyzer, TcpStream,
};

// Hashcat 集成
pub use crate::hashcat::{
    charsets, crack_auto, crack_mask, crack_md5, crack_ntlm, crack_sha1, crack_sha256,
    crack_with_rules, detect_hash_mode, modes, rules, AttackMode, BenchmarkResult, CrackResult,
    DeviceInfo, HashTypeInfo, Hashcat, HashcatConfig,
};

// 自动分析器
pub use crate::auto_analyzer::{
    analyze_brief, analyze_deep, analyze_file, analyze_minimal, analyze_normal, analyze_ultimate,
    AnalysisItem, AnalysisMode, AnalysisReport, AutoAnalyzer, CustomConfig,
};

// 错误处理
pub use anyhow::{Context, Result};
