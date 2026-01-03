//! 自动分析模块 - 提供六种分析模式
//!
//! - 极简分析 (Minimal): 仅基础检测
//! - 简要分析 (Brief): 基础 + 编码检测
//! - 正常分析 (Normal): 标准全面分析
//! - 深度分析 (Deep): 深度递归分析
//! - 最终分析 (Ultimate): 启用所有功能
//! - 自定义分析 (Custom): 用户自定义配置

use crate::{
    archive::ArchiveAnalyzer, cipher::Cipher, hash::HashIdentifier, magic::detect_bytes,
    pcap::PcapAnalyzer, stego::StegoAnalyzer, FlagDetector,
};
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::Path;
use zmctf_constraints::{read_file_with_limit, ResourceLimits};

fn duration_ms_u64(duration: std::time::Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

/// 分析模式
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum AnalysisMode {
    /// 极简分析 - 仅文件类型和基础flag检测
    Minimal,
    /// 简要分析 - 基础 + 编码检测
    Brief,
    /// 正常分析 - 标准全面分析
    #[default]
    Normal,
    /// 深度分析 - 深度递归 + 密码破解
    Deep,
    /// 最终分析 - 启用所有功能
    Ultimate,
    /// 自定义分析
    Custom,
}

/// 自定义分析配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BasicFeatures {
    /// 启用文件魔数检测
    pub magic_detection: bool,
    /// 启用编码检测和解码
    pub encoding_detection: bool,
    /// 启用 flag 模式匹配
    pub flag_matching: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashFeatures {
    /// 启用哈希识别
    pub hash_identification: bool,
    /// 启用哈希破解（需要字典）
    pub hash_cracking: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchiveFeatures {
    /// 启用压缩包分析
    pub archive_analysis: bool,
    /// 启用压缩包密码破解
    pub archive_cracking: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OptionalFeatures {
    /// 启用隐写检测
    pub stego_detection: bool,
    /// 启用 PCAP 流量分析
    pub pcap_analysis: bool,
    /// 启用密码/密文分析
    pub cipher_analysis: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomConfig {
    #[serde(flatten)]
    pub basic: BasicFeatures,
    #[serde(flatten)]
    pub hash: HashFeatures,
    #[serde(flatten)]
    pub archive: ArchiveFeatures,
    #[serde(flatten)]
    pub optional: OptionalFeatures,
    /// 最大递归深度
    pub max_depth: u32,
    /// 启用并行处理
    pub parallel: bool,
    /// 字典路径 (用于破解)
    pub wordlist_path: Option<String>,
}

impl Default for CustomConfig {
    fn default() -> Self {
        Self {
            basic: BasicFeatures {
                magic_detection: true,
                encoding_detection: true,
                flag_matching: true,
            },
            hash: HashFeatures {
                hash_identification: true,
                hash_cracking: false,
            },
            archive: ArchiveFeatures {
                archive_analysis: true,
                archive_cracking: false,
            },
            optional: OptionalFeatures {
                stego_detection: false,
                pcap_analysis: false,
                cipher_analysis: false,
            },
            max_depth: 3,
            parallel: true,
            wordlist_path: None,
        }
    }
}

impl CustomConfig {
    /// 从分析模式创建配置
    #[must_use]
    pub fn from_mode(mode: AnalysisMode) -> Self {
        match mode {
            AnalysisMode::Minimal => Self {
                basic: BasicFeatures {
                    magic_detection: true,
                    encoding_detection: false,
                    flag_matching: true,
                },
                hash: HashFeatures {
                    hash_identification: false,
                    hash_cracking: false,
                },
                archive: ArchiveFeatures {
                    archive_analysis: false,
                    archive_cracking: false,
                },
                optional: OptionalFeatures {
                    stego_detection: false,
                    pcap_analysis: false,
                    cipher_analysis: false,
                },
                max_depth: 1,
                parallel: false,
                wordlist_path: None,
            },
            AnalysisMode::Brief => Self {
                basic: BasicFeatures {
                    magic_detection: true,
                    encoding_detection: true,
                    flag_matching: true,
                },
                hash: HashFeatures {
                    hash_identification: true,
                    hash_cracking: false,
                },
                archive: ArchiveFeatures {
                    archive_analysis: false,
                    archive_cracking: false,
                },
                optional: OptionalFeatures {
                    stego_detection: false,
                    pcap_analysis: false,
                    cipher_analysis: false,
                },
                max_depth: 2,
                parallel: false,
                wordlist_path: None,
            },
            AnalysisMode::Normal | AnalysisMode::Custom => Self::default(),
            AnalysisMode::Deep => Self {
                basic: BasicFeatures {
                    magic_detection: true,
                    encoding_detection: true,
                    flag_matching: true,
                },
                hash: HashFeatures {
                    hash_identification: true,
                    hash_cracking: true,
                },
                archive: ArchiveFeatures {
                    archive_analysis: true,
                    archive_cracking: true,
                },
                optional: OptionalFeatures {
                    stego_detection: true,
                    pcap_analysis: true,
                    cipher_analysis: true,
                },
                max_depth: 5,
                parallel: true,
                wordlist_path: None,
            },
            AnalysisMode::Ultimate => Self {
                basic: BasicFeatures {
                    magic_detection: true,
                    encoding_detection: true,
                    flag_matching: true,
                },
                hash: HashFeatures {
                    hash_identification: true,
                    hash_cracking: true,
                },
                archive: ArchiveFeatures {
                    archive_analysis: true,
                    archive_cracking: true,
                },
                optional: OptionalFeatures {
                    stego_detection: true,
                    pcap_analysis: true,
                    cipher_analysis: true,
                },
                max_depth: 10,
                parallel: true,
                wordlist_path: Some("rockyou.txt".into()),
            },
        }
    }
}

/// 分析报告中的单项结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisItem {
    pub category: String,
    pub name: String,
    pub value: String,
    pub confidence: f32,
    pub details: Option<String>,
}

/// 完整分析报告
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisReport {
    /// 分析模式
    pub mode: AnalysisMode,
    /// 输入来源
    pub source: String,
    /// 文件类型
    pub file_type: Option<String>,
    /// 发现的flag
    pub flags: Vec<String>,
    /// 发现的哈希
    pub hashes: Vec<AnalysisItem>,
    /// 解码结果
    pub decoded: Vec<AnalysisItem>,
    /// 压缩包内容
    pub archive_contents: Vec<AnalysisItem>,
    /// 隐写结果
    pub stego_results: Vec<AnalysisItem>,
    /// 流量分析结果
    pub pcap_results: Vec<AnalysisItem>,
    /// 密码分析结果
    pub cipher_results: Vec<AnalysisItem>,
    /// 所有发现项
    pub all_findings: Vec<AnalysisItem>,
    /// 分析耗时 (毫秒)
    pub duration_ms: u64,
    /// 错误信息
    pub errors: Vec<String>,
}

impl AnalysisReport {
    fn new(
        mode: AnalysisMode,
        source: &str,
    ) -> Self {
        Self {
            mode,
            source: source.to_string(),
            file_type: None,
            flags: Vec::new(),
            hashes: Vec::new(),
            decoded: Vec::new(),
            archive_contents: Vec::new(),
            stego_results: Vec::new(),
            pcap_results: Vec::new(),
            cipher_results: Vec::new(),
            all_findings: Vec::new(),
            duration_ms: 0,
            errors: Vec::new(),
        }
    }

    /// 生成文本报告
    #[must_use]
    pub fn to_text(&self) -> String {
        use std::fmt::Write as _;

        let mut out = String::new();
        out.push_str("===========================================\n");
        out.push_str("ZMctf 自动分析报告\n");
        out.push_str("===========================================\n\n");
        let _ = writeln!(&mut out, "模式: {:?}", self.mode);
        let _ = writeln!(&mut out, "来源: {}", self.source);
        let _ = writeln!(&mut out, "耗时: {}ms", self.duration_ms);
        if let Some(ft) = &self.file_type {
            let _ = writeln!(&mut out, "类型: {ft}");
        }
        out.push('\n');

        if !self.flags.is_empty() {
            out.push_str("【发现的 Flag】\n");
            for f in &self.flags {
                let _ = writeln!(&mut out, "- {f}");
            }
            out.push('\n');
        }

        if !self.hashes.is_empty() {
            out.push_str("【哈希分析】\n");
            for h in &self.hashes {
                let _ = writeln!(&mut out, "- {} -> {}", h.name, h.value);
            }
            out.push('\n');
        }

        if !self.decoded.is_empty() {
            out.push_str("【解码结果】\n");
            for d in &self.decoded {
                let _ = writeln!(&mut out, "- [{}] {}", d.category, d.value);
            }
            out.push('\n');
        }

        if !self.archive_contents.is_empty() {
            out.push_str("【压缩包内容】\n");
            for a in &self.archive_contents {
                let _ = writeln!(&mut out, "- {}: {}", a.name, a.value);
            }
            out.push('\n');
        }

        if !self.stego_results.is_empty() {
            out.push_str("【隐写检测】\n");
            for s in &self.stego_results {
                let _ = writeln!(&mut out, "- [{}] {}", s.category, s.value);
            }
            out.push('\n');
        }

        if !self.pcap_results.is_empty() {
            out.push_str("【流量分析】\n");
            for p in &self.pcap_results {
                let _ = writeln!(&mut out, "- {}: {}", p.name, p.value);
            }
            out.push('\n');
        }

        if !self.cipher_results.is_empty() {
            out.push_str("【密码分析】\n");
            for c in &self.cipher_results {
                let _ = writeln!(&mut out, "- {}", c.value);
            }
            out.push('\n');
        }

        if !self.errors.is_empty() {
            out.push_str("【错误】\n");
            for e in &self.errors {
                let _ = writeln!(&mut out, "- {e}");
            }
        }

        out.push_str("===========================================\n");
        out
    }

    /// 生成 JSON 报告
    ///
    /// # Errors
    ///
    /// 当序列化失败时返回错误。
    pub fn to_json(&self) -> Result<String> {
        Ok(serde_json::to_string_pretty(self)?)
    }
}

/// 自动分析器
pub struct AutoAnalyzer {
    config: CustomConfig,
    mode: AnalysisMode,
    resources: ResourceLimits,
}

impl Default for AutoAnalyzer {
    fn default() -> Self {
        Self::new(AnalysisMode::Normal)
    }
}

impl AutoAnalyzer {
    /// 创建指定模式的分析器
    #[must_use]
    pub fn new(mode: AnalysisMode) -> Self {
        Self {
            config: CustomConfig::from_mode(mode),
            mode,
            resources: ResourceLimits::default(),
        }
    }

    /// 使用自定义配置创建分析器
    #[must_use]
    pub fn with_config(config: CustomConfig) -> Self {
        Self {
            config,
            mode: AnalysisMode::Custom,
            resources: ResourceLimits::default(),
        }
    }

    /// 应用全局资源与安全约束。
    #[must_use]
    pub fn with_resource_limits(
        mut self,
        resources: ResourceLimits,
    ) -> Self {
        self.resources = resources;
        self
    }

    /// 极简分析
    #[must_use]
    pub fn minimal() -> Self {
        Self::new(AnalysisMode::Minimal)
    }

    /// 简要分析
    #[must_use]
    pub fn brief() -> Self {
        Self::new(AnalysisMode::Brief)
    }

    /// 正常分析
    #[must_use]
    pub fn normal() -> Self {
        Self::new(AnalysisMode::Normal)
    }

    /// 深度分析
    #[must_use]
    pub fn deep() -> Self {
        Self::new(AnalysisMode::Deep)
    }

    /// 最终分析
    #[must_use]
    pub fn ultimate() -> Self {
        Self::new(AnalysisMode::Ultimate)
    }

    /// 获取当前配置
    #[must_use]
    pub const fn config(&self) -> &CustomConfig {
        &self.config
    }

    /// 修改配置
    #[must_use]
    pub const fn config_mut(&mut self) -> &mut CustomConfig {
        &mut self.config
    }

    /// 分析文件
    ///
    /// # Errors
    ///
    /// - 当读取文件失败或超过输入大小上限时返回错误。
    pub fn analyze_file(
        &self,
        path: &Path,
    ) -> Result<AnalysisReport> {
        let start = std::time::Instant::now();
        let mut report = AnalysisReport::new(self.mode, &path.display().to_string());

        // 读取文件
        let data = read_file_with_limit(path, self.resources.input_max_bytes)?;
        self.analyze_data_internal(&data, &mut report);

        report.duration_ms = duration_ms_u64(start.elapsed());
        Ok(report)
    }

    /// 分析字节数据
    ///
    /// # Errors
    ///
    /// 当前实现不会返回错误（保留 `Result` 以便与其他入口保持一致）。
    pub fn analyze_bytes(
        &self,
        data: &[u8],
    ) -> Result<AnalysisReport> {
        let start = std::time::Instant::now();
        let mut report = AnalysisReport::new(self.mode, "<bytes>");

        self.analyze_data_internal(data, &mut report);

        report.duration_ms = duration_ms_u64(start.elapsed());
        Ok(report)
    }

    /// 分析字符串
    ///
    /// # Errors
    ///
    /// 当前实现不会返回错误（保留 `Result` 以便与其他入口保持一致）。
    pub fn analyze_string(
        &self,
        input: &str,
    ) -> Result<AnalysisReport> {
        let start = std::time::Instant::now();
        let mut report = AnalysisReport::new(self.mode, "<string>");

        self.analyze_string_internal(input, &mut report);

        report.duration_ms = duration_ms_u64(start.elapsed());
        Ok(report)
    }

    fn analyze_data_internal(
        &self,
        data: &[u8],
        report: &mut AnalysisReport,
    ) {
        // 1. 文件魔数检测
        if self.config.basic.magic_detection {
            let magic = detect_bytes(data);
            let ext = &magic.extension;
            let desc = &magic.description;
            report.file_type = Some(format!("{ext} ({desc})"));

            // 根据文件类型进行特定分析
            match magic.extension.as_str() {
                "zip" | "7z" | "rar" | "tar" | "gz" => {
                    if self.config.archive.archive_analysis {
                        self.analyze_archive(data, report);
                    }
                }
                "png" | "jpg" | "gif" | "bmp" => {
                    if self.config.optional.stego_detection {
                        self.analyze_stego(data, report);
                    }
                }
                "pcap" | "pcapng" => {
                    if self.config.optional.pcap_analysis {
                        self.analyze_pcap(data, report);
                    }
                }
                _ => {}
            }
        }

        // 2. 尝试作为文本分析
        if let Ok(text) = std::str::from_utf8(data) {
            self.analyze_string_internal(text, report);
        }
    }

    fn analyze_string_internal(
        &self,
        input: &str,
        report: &mut AnalysisReport,
    ) {
        // 1. Flag 模式匹配
        if self.config.basic.flag_matching {
            let detector = FlagDetector::default();
            for decoded in detector.decode_string(input) {
                if (decoded.decoded.contains("flag{") || decoded.decoded.contains("FLAG{"))
                    && !report.flags.contains(&decoded.decoded)
                {
                    report.flags.push(decoded.decoded.clone());
                }
                if self.config.basic.encoding_detection && !decoded.encoding_chain.is_empty() {
                    report.decoded.push(AnalysisItem {
                        category: format!("{:?}", decoded.encoding_chain),
                        name: "decoded".into(),
                        value: decoded.decoded,
                        confidence: 1.0,
                        details: None,
                    });
                }
            }
        }

        // 2. 哈希识别
        if self.config.hash.hash_identification {
            let identifier = HashIdentifier::new();
            // 查找可能的哈希
            if let Ok(hash_regex) = regex::Regex::new(r"[a-fA-F0-9]{32,128}") {
                for cap in hash_regex.find_iter(input) {
                    let hash = cap.as_str();
                    let analysis = identifier.identify(hash);
                    if analysis.is_hash && !analysis.possible_types.is_empty() {
                        let top = &analysis.possible_types[0];
                        let mut item = AnalysisItem {
                            category: "hash".into(),
                            name: hash.to_string(),
                            value: top.name.clone(),
                            confidence: top.confidence,
                            details: top.hashcat_mode.map(|m| format!("hashcat -m {m}")),
                        };

                        // 尝试破解
                        if self.config.hash.hash_cracking {
                            if let Some(plain) = identifier.crack(hash) {
                                item.value = format!("{} -> {}", top.name, plain);
                            }
                        }

                        report.hashes.push(item);
                    }
                }
            }
        }

        // 3. 密码分析
        if self.config.optional.cipher_analysis {
            let cipher = Cipher::new(self.config.max_depth as usize);
            let result = cipher.decode(input);
            if result.success {
                for step in &result.steps {
                    report.cipher_results.push(AnalysisItem {
                        category: step.method.clone(),
                        name: "cipher".into(),
                        value: step.output.clone(),
                        confidence: step.confidence,
                        details: None,
                    });
                }
            }
        }
    }

    fn analyze_archive(
        &self,
        data: &[u8],
        report: &mut AnalysisReport,
    ) {
        let analyzer = ArchiveAnalyzer::new();
        match analyzer.analyze_bytes(data, 0) {
            Ok(archive) => {
                for entry in &archive.entries {
                    let uncompressed_size = entry.uncompressed_size;
                    let mut item = AnalysisItem {
                        category: "archive".into(),
                        name: entry.name.clone(),
                        value: format!("{uncompressed_size} bytes"),
                        confidence: 1.0,
                        details: None,
                    };
                    if entry.is_encrypted {
                        item.details = Some("encrypted".into());
                    }
                    report.archive_contents.push(item);

                    // 递归分析内容
                    if let Some(content) = &entry.content {
                        self.analyze_data_internal(content, report);
                    }
                }
                // 收集 flag
                for flag in &archive.all_flags {
                    if !report.flags.contains(flag) {
                        report.flags.push(flag.clone());
                    }
                }
                if archive.is_encrypted {
                    if let Some(pwd) = &archive.cracked_password {
                        report.archive_contents.push(AnalysisItem {
                            category: "cracked".into(),
                            name: "password".into(),
                            value: pwd.clone(),
                            confidence: 1.0,
                            details: None,
                        });
                    }
                }
            }
            Err(e) => report.errors.push(format!("Archive: {e}")),
        }
    }

    fn analyze_stego(
        &self,
        data: &[u8],
        report: &mut AnalysisReport,
    ) {
        let analyzer = StegoAnalyzer::new().with_resource_limits(self.resources.clone());
        match analyzer.analyze_bytes(data) {
            Ok(results) => {
                for r in results {
                    let len = r.data.len();
                    report.stego_results.push(AnalysisItem {
                        category: r.method.clone(),
                        name: "stego".into(),
                        value: r.text.unwrap_or_else(|| format!("{len} bytes")),
                        confidence: r.confidence,
                        details: Some(r.description),
                    });
                }
            }
            Err(e) => report.errors.push(format!("Stego: {e}")),
        }
    }

    fn analyze_pcap(
        &self,
        data: &[u8],
        report: &mut AnalysisReport,
    ) {
        let analyzer = PcapAnalyzer::new().with_resource_limits(self.resources.clone());
        match analyzer.analyze_bytes(data) {
            Ok(pcap) => {
                let packet_count = pcap.packet_count;
                let stream_count = pcap.tcp_streams.len();
                report.pcap_results.push(AnalysisItem {
                    category: "summary".into(),
                    name: "packets".into(),
                    value: format!("{packet_count} packets, {stream_count} streams"),
                    confidence: 1.0,
                    details: None,
                });
                for http in &pcap.http_messages {
                    let method = http.method.as_deref().unwrap_or("?");
                    let uri = http.uri.as_deref().unwrap_or("?");
                    let val = format!("{method} {uri}");
                    report.pcap_results.push(AnalysisItem {
                        category: "http".into(),
                        name: "request".into(),
                        value: val,
                        confidence: 1.0,
                        details: None,
                    });
                }
                for dns in &pcap.dns_records {
                    report.pcap_results.push(AnalysisItem {
                        category: "dns".into(),
                        name: dns.query.clone(),
                        value: dns.answer.clone().unwrap_or_default(),
                        confidence: 1.0,
                        details: None,
                    });
                }
                // 收集 flag
                for flag in &pcap.flags {
                    if !report.flags.contains(flag) {
                        report.flags.push(flag.clone());
                    }
                }
            }
            Err(e) => report.errors.push(format!("PCAP: {e}")),
        }
    }
}

/// 快捷函数：极简分析
///
/// # Errors
///
/// 当分析过程失败时返回错误。
pub fn analyze_minimal(input: &str) -> Result<AnalysisReport> {
    AutoAnalyzer::minimal().analyze_string(input)
}

/// 快捷函数：简要分析
///
/// # Errors
///
/// 当分析过程失败时返回错误。
pub fn analyze_brief(input: &str) -> Result<AnalysisReport> {
    AutoAnalyzer::brief().analyze_string(input)
}

/// 快捷函数：正常分析
///
/// # Errors
///
/// 当分析过程失败时返回错误。
pub fn analyze_normal(input: &str) -> Result<AnalysisReport> {
    AutoAnalyzer::normal().analyze_string(input)
}

/// 快捷函数：深度分析
///
/// # Errors
///
/// 当分析过程失败时返回错误。
pub fn analyze_deep(input: &str) -> Result<AnalysisReport> {
    AutoAnalyzer::deep().analyze_string(input)
}

/// 快捷函数：最终分析
///
/// # Errors
///
/// 当分析过程失败时返回错误。
pub fn analyze_ultimate(input: &str) -> Result<AnalysisReport> {
    AutoAnalyzer::ultimate().analyze_string(input)
}

/// 快捷函数：分析文件
///
/// # Errors
///
/// 当读取文件或分析过程失败时返回错误。
pub fn analyze_file(
    path: &Path,
    mode: AnalysisMode,
) -> Result<AnalysisReport> {
    AutoAnalyzer::new(mode).analyze_file(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_minimal_analysis() -> Result<()> {
        let report = analyze_minimal("flag{test_flag}")?;
        assert_eq!(report.mode, AnalysisMode::Minimal);
        assert!(report.flags.contains(&"flag{test_flag}".to_string()));
        Ok(())
    }

    #[test]
    fn test_hash_detection() -> Result<()> {
        let report = analyze_normal("hash=5d41402abc4b2a76b9719d911017c592")?;
        assert!(!report.hashes.is_empty());
        Ok(())
    }

    #[test]
    fn test_config_from_mode() {
        let minimal = CustomConfig::from_mode(AnalysisMode::Minimal);
        assert!(!minimal.basic.encoding_detection);
        assert!(!minimal.hash.hash_identification);

        let ultimate = CustomConfig::from_mode(AnalysisMode::Ultimate);
        assert!(ultimate.basic.encoding_detection);
        assert!(ultimate.hash.hash_cracking);
        assert!(ultimate.optional.stego_detection);
    }
}
