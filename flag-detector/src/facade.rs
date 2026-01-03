//! 模块统一接口门面
//! 每个子模块通过 `run()` 函数暴露统一入口

use serde::{Deserialize, Serialize};
use zmctf_constraints::{read_file_with_limit, ResourceLimits};

/// 通用模块配置
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ModuleConfig {
    /// 是否启用详细日志
    pub verbose: bool,
    /// 超时时间(秒)
    pub timeout: Option<u64>,
    /// 自定义参数
    pub params: std::collections::HashMap<String, String>,
    /// 全局资源与安全约束（默认使用工程统一默认值）。
    #[serde(default)]
    pub resources: ResourceLimits,
}

/// 通用模块输出
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleOutput {
    /// 模块名称
    pub module: String,
    /// 是否成功
    pub success: bool,
    /// 结果数据 (JSON)
    pub data: serde_json::Value,
    /// 日志
    pub logs: Vec<String>,
    /// 耗时(ms)
    pub elapsed_ms: u64,
}

impl ModuleOutput {
    #[must_use]
    pub fn new(module: &str) -> Self {
        Self {
            module: module.to_string(),
            success: true,
            data: serde_json::Value::Null,
            logs: Vec::new(),
            elapsed_ms: 0,
        }
    }

    #[must_use]
    pub fn with_data<T: Serialize>(
        mut self,
        data: T,
    ) -> Self {
        self.data = serde_json::to_value(data).unwrap_or_default();
        self
    }

    #[must_use]
    pub fn with_error(
        mut self,
        err: &str,
    ) -> Self {
        self.success = false;
        self.logs.push(format!("[ERROR] {err}"));
        self
    }

    pub fn log(
        &mut self,
        msg: &str,
    ) {
        self.logs.push(msg.to_string());
    }
}

fn elapsed_ms(start: std::time::Instant) -> u64 {
    u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX)
}

// ============ 各模块统一入口 ============

/// 1. Magic - 文件类型检测
pub mod magic_facade {
    use anyhow::Result;
    use std::path::Path;

    use super::{elapsed_ms, read_file_with_limit, ModuleConfig, ModuleOutput};
    use crate::magic::MagicDetector;

    /// 运行文件类型检测模块。
    ///
    /// # Errors
    ///
    /// 当序列化输出为 JSON 失败时返回错误。
    pub fn run(
        input: &[u8],
        _config: &ModuleConfig,
    ) -> Result<ModuleOutput> {
        let start = std::time::Instant::now();
        let mut out = ModuleOutput::new("magic");

        out.log("开始文件类型检测");
        let detector = MagicDetector::new();
        let result = detector.detect_bytes(input);

        let category = &result.category;
        out.log(&format!("检测完成: {category:?}"));
        out.data = serde_json::to_value(&result)?;
        out.elapsed_ms = elapsed_ms(start);
        Ok(out)
    }

    /// 从文件读取并运行文件类型检测模块。
    ///
    /// # Errors
    ///
    /// - 当读取文件失败或超过输入大小上限时返回错误。
    /// - 当序列化输出为 JSON 失败时返回错误。
    pub fn run_file(
        path: &Path,
        config: &ModuleConfig,
    ) -> Result<ModuleOutput> {
        let bytes = read_file_with_limit(path, config.resources.input_max_bytes)?;
        run(&bytes, config)
    }
}

/// 2. Archive - 压缩包处理
pub mod archive_facade {
    use anyhow::Result;
    use std::path::Path;

    use super::{elapsed_ms, read_file_with_limit, ModuleConfig, ModuleOutput};
    use crate::archive::ArchiveAnalyzer;

    /// 运行压缩包分析模块。
    ///
    /// # Errors
    ///
    /// - 当压缩包解析失败时返回错误。
    /// - 当序列化输出为 JSON 失败时返回错误。
    pub fn run(
        input: &[u8],
        config: &ModuleConfig,
    ) -> Result<ModuleOutput> {
        let start = std::time::Instant::now();
        let mut out = ModuleOutput::new("archive");

        out.log("开始压缩包分析");
        let analyzer = ArchiveAnalyzer::new().with_resource_limits(config.resources.clone());
        let result = analyzer.analyze_bytes(input, 0)?;

        let count = result.entries.len();
        out.log(&format!("发现 {count} 个文件"));
        out.data = serde_json::to_value(&result)?;
        out.elapsed_ms = elapsed_ms(start);
        Ok(out)
    }

    /// 从文件读取并运行压缩包分析模块。
    ///
    /// # Errors
    ///
    /// - 当读取文件失败或超过输入大小上限时返回错误。
    /// - 当压缩包解析或 JSON 序列化失败时返回错误。
    pub fn run_file(
        path: &Path,
        config: &ModuleConfig,
    ) -> Result<ModuleOutput> {
        let bytes = read_file_with_limit(path, config.resources.input_max_bytes)?;
        run(&bytes, config)
    }
}

/// 3. Extractor - 字符串提取
pub mod extractor_facade {
    use anyhow::Result;
    use std::path::Path;

    use super::{elapsed_ms, ModuleConfig, ModuleOutput};
    use crate::extractor;

    /// 运行字符串提取模块（对输入视为文本并按行切分）。
    ///
    /// # Errors
    ///
    /// 当序列化输出为 JSON 失败时返回错误。
    pub fn run(
        input: &[u8],
        _config: &ModuleConfig,
    ) -> Result<ModuleOutput> {
        let start = std::time::Instant::now();
        let mut out = ModuleOutput::new("extractor");

        out.log("开始字符串提取");
        let content = String::from_utf8_lossy(input).to_string();

        // 直接从内容提取
        let strings: Vec<crate::ExtractedString> = content
            .lines()
            .enumerate()
            .map(|(i, line)| crate::ExtractedString {
                content: line.to_string(),
                offset: i,
            })
            .filter(|s| !s.content.trim().is_empty())
            .collect();

        let count = strings.len();
        out.log(&format!("提取 {count} 个字符串"));
        out.data = serde_json::to_value(&strings)?;
        out.elapsed_ms = elapsed_ms(start);
        Ok(out)
    }

    /// 从文件读取并运行字符串提取模块。
    ///
    /// # Errors
    ///
    /// - 当文件读取或提取失败时返回错误。
    /// - 当序列化输出为 JSON 失败时返回错误。
    pub fn run_file(
        path: &Path,
        _config: &ModuleConfig,
    ) -> Result<ModuleOutput> {
        let start = std::time::Instant::now();
        let mut out = ModuleOutput::new("extractor");

        out.log("开始字符串提取");
        let detector_config = crate::types::DetectorConfig::default();
        let cache = crate::types::FileCache::new();
        let strings = extractor::extract_strings_cached(path, &detector_config, &cache)?;

        let count = strings.len();
        out.log(&format!("提取 {count} 个字符串"));
        out.data = serde_json::to_value(&strings)?;
        out.elapsed_ms = elapsed_ms(start);
        Ok(out)
    }
}

/// 4. Decoder - 编码解码
pub mod decoder_facade {
    use anyhow::Result;

    use super::{elapsed_ms, ModuleConfig, ModuleOutput};
    use crate::decoder;
    use crate::types::{DetectorConfig, ExtractedString};

    /// 运行编码解码模块（对输入作为单条字符串进行解码链探索）。
    ///
    /// # Errors
    ///
    /// 当解码流程或序列化输出为 JSON 失败时返回错误。
    pub fn run(
        input: &str,
        _config: &ModuleConfig,
    ) -> Result<ModuleOutput> {
        let start = std::time::Instant::now();
        let mut out = ModuleOutput::new("decoder");

        out.log("开始解码分析");
        let extracted = vec![ExtractedString {
            content: input.to_string(),
            offset: 0,
        }];
        let config = DetectorConfig::default();
        let decoded = decoder::decode_strings(&extracted, &config)?;

        let count = decoded.len();
        out.log(&format!("生成 {count} 个解码候选"));
        out.data = serde_json::to_value(&decoded)?;
        out.elapsed_ms = elapsed_ms(start);
        Ok(out)
    }
}

/// 5. Cipher - 密码分析
pub mod cipher_facade {
    use anyhow::Result;

    use super::{elapsed_ms, ModuleConfig, ModuleOutput};
    use crate::cipher::Cipher;

    /// 运行密码分析模块。
    ///
    /// # Errors
    ///
    /// 当序列化输出为 JSON 失败时返回错误。
    pub fn run(
        input: &str,
        _config: &ModuleConfig,
    ) -> Result<ModuleOutput> {
        let start = std::time::Instant::now();
        let mut out = ModuleOutput::new("cipher");

        out.log("开始密码分析");
        let cipher = Cipher::default();
        let result = cipher.decode(input);

        let success = result.success;
        out.log(&format!("解码完成: success={success}"));
        out.data = serde_json::to_value(&result)?;
        out.elapsed_ms = elapsed_ms(start);
        Ok(out)
    }
}

/// 6. Hash - 哈希识别
pub mod hash_facade {
    use anyhow::Result;

    use super::{elapsed_ms, ModuleConfig, ModuleOutput};
    use crate::hash::HashIdentifier;

    /// 运行哈希识别模块。
    ///
    /// # Errors
    ///
    /// 当序列化输出为 JSON 失败时返回错误。
    pub fn run(
        input: &str,
        config: &ModuleConfig,
    ) -> Result<ModuleOutput> {
        let start = std::time::Instant::now();
        let mut out = ModuleOutput::new("hash");

        out.log("开始哈希识别");
        let identifier = HashIdentifier::new().with_resource_limits(config.resources.clone());
        let result = identifier.identify(input);

        let count = result.possible_types.len();
        out.log(&format!("识别完成: {count} 个可能类型"));
        out.data = serde_json::to_value(&result)?;
        out.elapsed_ms = elapsed_ms(start);
        Ok(out)
    }
}

/// 7. Hashcat - 哈希破解
pub mod hashcat_facade {
    use anyhow::Result;

    use super::{elapsed_ms, ModuleConfig, ModuleOutput};
    use crate::hashcat::{Hashcat, HashcatConfig};

    /// 运行 hashcat 破解模块。
    ///
    /// # Errors
    ///
    /// - 当外部命令执行失败或超时/输出截断触发错误时返回错误。
    /// - 当序列化输出为 JSON 失败时返回错误。
    pub fn run(
        hash: &str,
        config: &ModuleConfig,
    ) -> Result<ModuleOutput> {
        let start = std::time::Instant::now();
        let mut out = ModuleOutput::new("hashcat");

        out.log("开始哈希破解");
        let hashcat_config = HashcatConfig::default();
        let hashcat = Hashcat::new(hashcat_config).with_resource_limits(config.resources.clone());

        let result = hashcat.crack_auto(hash)?;

        let success = result.success;
        out.log(&format!("破解完成: success={success}"));
        out.data = serde_json::to_value(&result)?;
        out.elapsed_ms = elapsed_ms(start);
        Ok(out)
    }
}

/// 8. Stego - 隐写分析
pub mod stego_facade {
    use anyhow::Result;
    use std::path::Path;

    use super::{elapsed_ms, read_file_with_limit, ModuleConfig, ModuleOutput};
    use crate::stego::{
        BinwalkConfig, ExiftoolConfig, ExternalTools, ExternalToolsConfig, SteghideConfig,
        StegoAnalyzer, Toggle, ZstegConfig,
    };

    /// 运行隐写分析模块（纯内置分析）。
    ///
    /// # Errors
    ///
    /// - 当隐写分析失败时返回错误。
    /// - 当序列化输出为 JSON 失败时返回错误。
    pub fn run(
        input: &[u8],
        config: &ModuleConfig,
    ) -> Result<ModuleOutput> {
        let start = std::time::Instant::now();
        let mut out = ModuleOutput::new("stego");

        out.log("开始隐写分析");
        let analyzer = StegoAnalyzer::new().with_resource_limits(config.resources.clone());
        let results = analyzer.analyze_bytes(input)?;

        let count = results.len();
        out.log(&format!("分析完成: {count} 个发现"));
        out.data = serde_json::to_value(&results)?;
        out.elapsed_ms = elapsed_ms(start);
        Ok(out)
    }

    /// 从文件读取并运行隐写分析模块（纯内置分析）。
    ///
    /// # Errors
    ///
    /// - 当读取文件失败或超过输入大小上限时返回错误。
    /// - 当隐写分析或 JSON 序列化失败时返回错误。
    pub fn run_file(
        path: &Path,
        config: &ModuleConfig,
    ) -> Result<ModuleOutput> {
        let bytes = read_file_with_limit(path, config.resources.input_max_bytes)?;
        run(&bytes, config)
    }

    /// 使用外部工具进行完整分析
    ///
    /// # Errors
    ///
    /// - 当外部工具执行失败、超时或输出截断触发错误时返回错误。
    /// - 当序列化输出为 JSON 失败时返回错误。
    pub fn run_with_external_tools(
        path: &Path,
        config: &ModuleConfig,
    ) -> Result<ModuleOutput> {
        let start = std::time::Instant::now();
        let mut out = ModuleOutput::new("stego_external");

        out.log("开始外部工具隐写分析");

        // 构建外部工具配置
        let tools_config = ExternalToolsConfig {
            steghide_path: config
                .params
                .get("steghide_path")
                .map_or_else(|| "steghide".into(), Into::into),
            zsteg_path: config
                .params
                .get("zsteg_path")
                .map_or_else(|| "zsteg".into(), Into::into),
            binwalk_path: config
                .params
                .get("binwalk_path")
                .map_or_else(|| "binwalk".into(), Into::into),
            exiftool_path: config
                .params
                .get("exiftool_path")
                .map_or_else(|| "exiftool".into(), Into::into),
            strings_path: config
                .params
                .get("strings_path")
                .map_or_else(|| "strings".into(), Into::into),
            foremost_path: config
                .params
                .get("foremost_path")
                .map_or_else(|| "foremost".into(), Into::into),
            stegseek_path: config
                .params
                .get("stegseek_path")
                .map_or_else(|| "stegseek".into(), Into::into),
            resources: config.resources.clone(),
        };

        let tools = ExternalTools::new(tools_config);
        let result = tools.full_analysis(path)?;

        out.log("外部工具分析完成");
        out.data = serde_json::to_value(&result)?;
        out.elapsed_ms = elapsed_ms(start);
        Ok(out)
    }

    /// Steghide提取
    ///
    /// # Errors
    ///
    /// - 当外部工具 `steghide` 不可用或执行失败时返回错误。
    /// - 当序列化输出为 JSON 失败时返回错误。
    pub fn steghide_extract(
        path: &Path,
        passphrase: Option<&str>,
        config: &ModuleConfig,
    ) -> Result<ModuleOutput> {
        let start = std::time::Instant::now();
        let mut out = ModuleOutput::new("steghide");

        let tools_config = ExternalToolsConfig {
            resources: config.resources.clone(),
            ..Default::default()
        };
        let tools = ExternalTools::new(tools_config);

        let verbose = if config.verbose {
            Toggle::Enabled
        } else {
            Toggle::Disabled
        };
        let quiet = if config.verbose {
            Toggle::Disabled
        } else {
            Toggle::Enabled
        };

        let steghide_config = SteghideConfig {
            passphrase: passphrase.map(ToString::to_string),
            force: if config.params.get("force").is_some_and(|s| s == "true") {
                Toggle::Enabled
            } else {
                Toggle::Disabled
            },
            quiet,
            verbose,
            ..Default::default()
        };

        let result = tools.steghide_extract(path, &steghide_config)?;
        out.data = serde_json::to_value(&result)?;
        out.elapsed_ms = elapsed_ms(start);
        Ok(out)
    }

    /// Zsteg分析
    ///
    /// # Errors
    ///
    /// - 当外部工具 `zsteg` 不可用或执行失败时返回错误。
    /// - 当序列化输出为 JSON 失败时返回错误。
    pub fn zsteg_analyze(
        path: &Path,
        config: &ModuleConfig,
    ) -> Result<ModuleOutput> {
        let start = std::time::Instant::now();
        let mut out = ModuleOutput::new("zsteg");

        let tools_config = ExternalToolsConfig {
            resources: config.resources.clone(),
            ..Default::default()
        };
        let tools = ExternalTools::new(tools_config);

        let zsteg_config = ZstegConfig {
            all: if config.params.get("all").is_none_or(|s| s == "true") {
                Toggle::Enabled
            } else {
                Toggle::Disabled
            },
            verbose: if config.verbose {
                Toggle::Enabled
            } else {
                Toggle::Disabled
            },
            ..Default::default()
        };

        let result = tools.zsteg_analyze(path, &zsteg_config)?;
        out.data = serde_json::to_value(&result)?;
        out.elapsed_ms = elapsed_ms(start);
        Ok(out)
    }

    /// Binwalk分析
    ///
    /// # Errors
    ///
    /// - 当外部工具 `binwalk` 不可用或执行失败时返回错误。
    /// - 当序列化输出为 JSON 失败时返回错误。
    pub fn binwalk_analyze(
        path: &Path,
        config: &ModuleConfig,
    ) -> Result<ModuleOutput> {
        let start = std::time::Instant::now();
        let mut out = ModuleOutput::new("binwalk");

        let tools_config = ExternalToolsConfig {
            resources: config.resources.clone(),
            ..Default::default()
        };
        let tools = ExternalTools::new(tools_config);

        let binwalk_config = BinwalkConfig {
            signature: if config.params.get("signature").is_none_or(|s| s == "true") {
                Toggle::Enabled
            } else {
                Toggle::Disabled
            },
            extract: if config.params.get("extract").is_some_and(|s| s == "true") {
                Toggle::Enabled
            } else {
                Toggle::Disabled
            },
            matryoshka: if config.params.get("matryoshka").is_some_and(|s| s == "true") {
                Toggle::Enabled
            } else {
                Toggle::Disabled
            },
            verbose: if config.verbose {
                Toggle::Enabled
            } else {
                Toggle::Disabled
            },
            ..Default::default()
        };

        let result = tools.binwalk_analyze(path, &binwalk_config)?;
        out.data = serde_json::to_value(&result)?;
        out.elapsed_ms = elapsed_ms(start);
        Ok(out)
    }

    /// Exiftool分析
    ///
    /// # Errors
    ///
    /// - 当外部工具 `exiftool` 不可用或执行失败时返回错误。
    /// - 当序列化输出为 JSON 失败时返回错误。
    pub fn exiftool_analyze(
        path: &Path,
        config: &ModuleConfig,
    ) -> Result<ModuleOutput> {
        let start = std::time::Instant::now();
        let mut out = ModuleOutput::new("exiftool");

        let tools_config = ExternalToolsConfig {
            resources: config.resources.clone(),
            ..Default::default()
        };
        let tools = ExternalTools::new(tools_config);

        let exiftool_config = ExiftoolConfig {
            all_tags: if config.params.get("all_tags").is_none_or(|s| s == "true") {
                Toggle::Enabled
            } else {
                Toggle::Disabled
            },
            json: Toggle::Enabled,
            verbose: if config.verbose {
                Toggle::Enabled
            } else {
                Toggle::Disabled
            },
            ..Default::default()
        };

        let result = tools.exiftool_analyze(path, &exiftool_config)?;
        out.data = serde_json::to_value(&result)?;
        out.elapsed_ms = elapsed_ms(start);
        Ok(out)
    }
}

/// 9. Pcap - 网络包分析
pub mod pcap_facade {
    use anyhow::Result;
    use std::path::Path;

    use super::{elapsed_ms, read_file_with_limit, ModuleConfig, ModuleOutput};
    use crate::pcap::{
        PcapAnalyzer, Tshark, TsharkConfig, TsharkOutputFormat, TsharkOutputOptions,
        TsharkVerbosity,
    };

    /// 运行网络包分析模块（纯 Rust 解析）。
    ///
    /// # Errors
    ///
    /// - 当 PCAP/PCAPNG 解析失败时返回错误。
    /// - 当序列化输出为 JSON 失败时返回错误。
    pub fn run(
        input: &[u8],
        config: &ModuleConfig,
    ) -> Result<ModuleOutput> {
        let start = std::time::Instant::now();
        let mut out = ModuleOutput::new("pcap");

        out.log("开始网络包分析");
        let analyzer = PcapAnalyzer::new().with_resource_limits(config.resources.clone());
        let result = analyzer.analyze_bytes(input)?;

        out.log(&format!("分析完成: {} 个数据包", result.packets.len()));
        out.data = serde_json::to_value(&result)?;
        out.elapsed_ms = elapsed_ms(start);
        Ok(out)
    }

    /// 从文件读取并运行网络包分析模块（纯 Rust 解析）。
    ///
    /// # Errors
    ///
    /// - 当读取文件失败或超过输入大小上限时返回错误。
    /// - 当 PCAP/PCAPNG 解析或 JSON 序列化失败时返回错误。
    pub fn run_file(
        path: &Path,
        config: &ModuleConfig,
    ) -> Result<ModuleOutput> {
        let bytes = read_file_with_limit(path, config.resources.input_max_bytes)?;
        run(&bytes, config)
    }

    /// 使用tshark进行分析
    ///
    /// # Errors
    ///
    /// - 当外部工具 `tshark` 不可用或执行失败时返回错误。
    /// - 当 JSON 序列化失败时返回错误。
    pub fn tshark_analyze(
        path: &Path,
        config: &ModuleConfig,
    ) -> Result<ModuleOutput> {
        let start = std::time::Instant::now();
        let mut out = ModuleOutput::new("tshark");

        let output_format = if config.params.get("json").is_none_or(|s| s == "true") {
            TsharkOutputFormat::Json
        } else {
            TsharkOutputFormat::Default
        };
        let verbosity = if config.verbose {
            TsharkVerbosity::Verbose
        } else {
            TsharkVerbosity::Normal
        };

        let tshark_config = TsharkConfig {
            tshark_path: config
                .params
                .get("tshark_path")
                .map_or_else(|| "tshark".into(), Into::into),
            read_file: Some(path.to_path_buf()),
            display_filter: config.params.get("filter").cloned(),
            output: TsharkOutputOptions {
                format: output_format,
                verbosity,
                ..TsharkOutputOptions::default()
            },
            resources: config.resources.clone(),
            ..Default::default()
        };

        let tshark = Tshark::new(tshark_config);
        let result = tshark.analyze_file(path)?;

        out.data = serde_json::to_value(&result)?;
        out.elapsed_ms = elapsed_ms(start);
        Ok(out)
    }

    /// 提取特定字段
    ///
    /// # Errors
    ///
    /// - 当外部工具 `tshark` 不可用或执行失败时返回错误。
    /// - 当 JSON 序列化失败时返回错误。
    pub fn tshark_extract_fields(
        path: &Path,
        fields: &[String],
        config: &ModuleConfig,
    ) -> Result<ModuleOutput> {
        let start = std::time::Instant::now();
        let mut out = ModuleOutput::new("tshark_fields");

        let tshark_config = TsharkConfig {
            read_file: Some(path.to_path_buf()),
            display_filter: config.params.get("filter").cloned(),
            resources: config.resources.clone(),
            ..Default::default()
        };

        let tshark = Tshark::new(tshark_config);
        let field_refs: Vec<&str> = fields.iter().map(String::as_str).collect();
        let result = tshark.extract_fields(path, &field_refs)?;

        out.data = serde_json::to_value(&result)?;
        out.elapsed_ms = elapsed_ms(start);
        Ok(out)
    }

    /// 导出HTTP对象
    ///
    /// # Errors
    ///
    /// - 当外部工具 `tshark` 不可用或执行失败时返回错误。
    /// - 当 JSON 序列化失败时返回错误。
    pub fn tshark_export_http(
        path: &Path,
        output_dir: &Path,
        config: &ModuleConfig,
    ) -> Result<ModuleOutput> {
        let start = std::time::Instant::now();
        let mut out = ModuleOutput::new("tshark_http");

        let tshark_config = TsharkConfig {
            resources: config.resources.clone(),
            ..Default::default()
        };
        let tshark = Tshark::new(tshark_config);
        let result = tshark.export_http_objects(path, output_dir)?;

        out.data = serde_json::to_value(&result)?;
        out.elapsed_ms = elapsed_ms(start);
        Ok(out)
    }

    /// 协议层级统计
    ///
    /// # Errors
    ///
    /// - 当外部工具 `tshark` 不可用或执行失败时返回错误。
    /// - 当 JSON 序列化失败时返回错误。
    pub fn tshark_protocol_hierarchy(
        path: &Path,
        config: &ModuleConfig,
    ) -> Result<ModuleOutput> {
        let start = std::time::Instant::now();
        let mut out = ModuleOutput::new("tshark_protocols");

        let tshark_config = TsharkConfig {
            resources: config.resources.clone(),
            ..Default::default()
        };
        let tshark = Tshark::new(tshark_config);
        let result = tshark.protocol_hierarchy(path)?;

        out.data = serde_json::to_value(&result)?;
        out.elapsed_ms = elapsed_ms(start);
        Ok(out)
    }

    /// 会话统计
    ///
    /// # Errors
    ///
    /// - 当外部工具 `tshark` 不可用或执行失败时返回错误。
    /// - 当 JSON 序列化失败时返回错误。
    pub fn tshark_conversations(
        path: &Path,
        protocol: &str,
        config: &ModuleConfig,
    ) -> Result<ModuleOutput> {
        let start = std::time::Instant::now();
        let mut out = ModuleOutput::new("tshark_conversations");

        let tshark_config = TsharkConfig {
            resources: config.resources.clone(),
            ..Default::default()
        };
        let tshark = Tshark::new(tshark_config);
        let result = tshark.conversations(path, protocol)?;

        out.data = serde_json::to_value(&result)?;
        out.elapsed_ms = elapsed_ms(start);
        Ok(out)
    }

    /// 跟踪TCP流
    ///
    /// # Errors
    ///
    /// - 当外部工具 `tshark` 不可用或执行失败时返回错误。
    /// - 当 JSON 序列化失败时返回错误。
    pub fn tshark_follow_tcp(
        path: &Path,
        stream_id: u32,
        config: &ModuleConfig,
    ) -> Result<ModuleOutput> {
        let start = std::time::Instant::now();
        let mut out = ModuleOutput::new("tshark_tcp_stream");

        let tshark_config = TsharkConfig {
            resources: config.resources.clone(),
            ..Default::default()
        };
        let tshark = Tshark::new(tshark_config);
        let result = tshark.follow_tcp_stream(path, stream_id)?;

        out.data = serde_json::to_value(&result)?;
        out.elapsed_ms = elapsed_ms(start);
        Ok(out)
    }

    /// 搜索字符串
    ///
    /// # Errors
    ///
    /// - 当外部工具 `tshark` 不可用或执行失败时返回错误。
    /// - 当 JSON 序列化失败时返回错误。
    pub fn tshark_search(
        path: &Path,
        pattern: &str,
        config: &ModuleConfig,
    ) -> Result<ModuleOutput> {
        let start = std::time::Instant::now();
        let mut out = ModuleOutput::new("tshark_search");

        let tshark_config = TsharkConfig {
            resources: config.resources.clone(),
            ..Default::default()
        };
        let tshark = Tshark::new(tshark_config);
        let result = tshark.search_string(path, pattern)?;

        out.data = serde_json::to_value(&result)?;
        out.elapsed_ms = elapsed_ms(start);
        Ok(out)
    }
}

/// 10. Rules - 规则引擎
pub mod rules_facade {
    use anyhow::Result;

    use super::{elapsed_ms, ModuleConfig, ModuleOutput};
    use crate::rules::RuleEngine;

    /// 运行规则变换模块，生成常见变体。
    ///
    /// # Errors
    ///
    /// 当序列化输出为 JSON 失败时返回错误。
    pub fn run(
        input: &str,
        _config: &ModuleConfig,
    ) -> Result<ModuleOutput> {
        let start = std::time::Instant::now();
        let mut out = ModuleOutput::new("rules");

        out.log("开始规则变换");
        let _engine = RuleEngine::new();
        let variants = RuleEngine::generate_variants(input);

        out.log(&format!("生成 {} 个变体", variants.len()));
        out.data = serde_json::to_value(&variants)?;
        out.elapsed_ms = elapsed_ms(start);
        Ok(out)
    }
}

/// 11. Matcher - Flag匹配
pub mod matcher_facade {
    use anyhow::Result;

    use super::{elapsed_ms, ModuleConfig, ModuleOutput};
    use crate::matcher;
    use crate::types::{DecodedString, DetectorConfig, EncodingType};

    /// 运行 Flag 匹配模块（将输入视为明文）。
    ///
    /// # Errors
    ///
    /// - 当匹配执行失败时返回错误（当前实现一般不会返回错误）。
    /// - 当序列化输出为 JSON 失败时返回错误。
    pub fn run(
        input: &str,
        _config: &ModuleConfig,
    ) -> Result<ModuleOutput> {
        let start = std::time::Instant::now();
        let mut out = ModuleOutput::new("matcher");

        out.log("开始 Flag 匹配");
        let decoded = vec![DecodedString {
            original: input.to_string(),
            decoded: input.to_string(),
            encoding_chain: vec![EncodingType::Plaintext],
            confidence: 1.0,
        }];
        let config = DetectorConfig::default();
        let flags = matcher::match_flags(&decoded, &config)?;

        out.log(&format!("匹配完成: {} 个 Flag", flags.len()));
        out.data = serde_json::to_value(&flags)?;
        out.elapsed_ms = elapsed_ms(start);
        Ok(out)
    }
}

/// 12. Analyzer - 异步分析器
pub mod analyzer_facade {
    use anyhow::Result;

    use super::{elapsed_ms, ModuleConfig, ModuleOutput};
    use crate::analyzer::AsyncAnalyzer;
    use crate::config::AppConfig;

    /// 运行异步批量分析器。
    ///
    /// # Errors
    ///
    /// - 当初始化分析器或执行分析失败时返回错误。
    /// - 当序列化输出为 JSON 失败时返回错误。
    pub async fn run(
        paths: Vec<std::path::PathBuf>,
        config: &ModuleConfig,
    ) -> Result<ModuleOutput> {
        let start = std::time::Instant::now();
        let mut out = ModuleOutput::new("analyzer");

        out.log("开始批量分析");
        let app_config = AppConfig {
            resources: config.resources.clone(),
            ..AppConfig::default()
        };
        let analyzer = AsyncAnalyzer::new(&app_config)?;
        let result = analyzer.analyze_batch(paths, false).await?;

        out.log(&format!("分析完成: {} 个文件", result.results.len()));
        out.data = serde_json::to_value(&result)?;
        out.elapsed_ms = elapsed_ms(start);
        Ok(out)
    }
}

/// 13. `AutoAnalyzer` - 自动分析
pub mod auto_analyzer_facade {
    use anyhow::Result;
    use std::path::Path;

    use super::{elapsed_ms, ModuleConfig, ModuleOutput};
    use crate::auto_analyzer::{AnalysisMode, AutoAnalyzer};

    /// 运行自动分析模块（文件路径输入）。
    ///
    /// # Errors
    ///
    /// - 当读取/解析文件失败时返回错误。
    /// - 当序列化输出为 JSON 失败时返回错误。
    pub fn run(
        path: &Path,
        config: &ModuleConfig,
    ) -> Result<ModuleOutput> {
        let start = std::time::Instant::now();
        let mut out = ModuleOutput::new("auto_analyzer");

        out.log("开始自动分析");
        let mode = config.params.get("mode").map(String::as_str).map_or(
            AnalysisMode::Ultimate,
            |m| match m {
                "minimal" => AnalysisMode::Minimal,
                "brief" => AnalysisMode::Brief,
                "deep" => AnalysisMode::Deep,
                "ultimate" => AnalysisMode::Ultimate,
                _ => AnalysisMode::Normal,
            },
        );

        let analyzer = AutoAnalyzer::new(mode).with_resource_limits(config.resources.clone());
        let result = analyzer.analyze_file(path)?;

        out.log(&format!("分析完成: {} 个 Flag", result.flags.len()));
        out.data = serde_json::to_value(&result)?;
        out.elapsed_ms = elapsed_ms(start);
        Ok(out)
    }
}

/// 14. Cache - 缓存管理
pub mod cache_facade {
    use anyhow::Result;

    use super::{elapsed_ms, ModuleConfig, ModuleOutput};
    use crate::cache::{CacheConfig, PersistentCache};

    /// 运行缓存管理模块。
    ///
    /// # Errors
    ///
    /// - 当创建/读取/清理缓存失败时返回错误。
    /// - 当序列化输出为 JSON 失败时返回错误。
    pub fn run(
        action: &str,
        key: Option<&str>,
        _value: Option<&str>,
        _config: &ModuleConfig,
    ) -> Result<ModuleOutput> {
        let start = std::time::Instant::now();
        let mut out = ModuleOutput::new("cache");

        let cache_config = CacheConfig::default();
        let cache = PersistentCache::new(None, cache_config)?;

        match action {
            "get" => {
                if let Some(k) = key {
                    let v = cache.get(k)?;
                    out.data = serde_json::to_value(&v)?;
                    out.log(&format!("获取缓存: {k}"));
                }
            }
            "stats" => {
                let stats = cache.stats()?;
                out.data = serde_json::to_value(&stats)?;
                out.log("获取缓存统计");
            }
            "clear" => {
                cache.clear()?;
                out.log("清空缓存");
            }
            _ => {}
        }

        out.elapsed_ms = elapsed_ms(start);
        Ok(out)
    }
}

/// 15. History - 历史记录
pub mod history_facade {
    use anyhow::Result;

    use super::{elapsed_ms, ModuleConfig, ModuleOutput};
    use crate::history::HistoryManager;

    /// 运行历史记录模块。
    ///
    /// # Errors
    ///
    /// - 当读取/写入历史文件失败时返回错误。
    /// - 当序列化输出为 JSON 失败时返回错误。
    pub fn run(
        action: &str,
        _config: &ModuleConfig,
    ) -> Result<ModuleOutput> {
        let start = std::time::Instant::now();
        let mut out = ModuleOutput::new("history");

        let manager = HistoryManager::new(None, 1000)?;

        match action {
            "list" => {
                let entries = manager.list(100)?;
                out.data = serde_json::to_value(&entries)?;
                out.log(&format!("获取 {} 条历史记录", entries.len()));
            }
            "clear" => {
                manager.clear()?;
                out.log("清空历史记录");
            }
            _ => {}
        }

        out.elapsed_ms = elapsed_ms(start);
        Ok(out)
    }
}

// ============ 统一调度器 ============

/// 模块类型枚举
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ModuleType {
    Magic,
    Archive,
    Extractor,
    Decoder,
    Cipher,
    Hash,
    Hashcat,
    Stego,
    Pcap,
    Rules,
    Matcher,
    Analyzer,
    AutoAnalyzer,
    Cache,
    History,
}

impl ModuleType {
    #[must_use]
    pub fn all() -> Vec<Self> {
        vec![
            Self::Magic,
            Self::Archive,
            Self::Extractor,
            Self::Decoder,
            Self::Cipher,
            Self::Hash,
            Self::Hashcat,
            Self::Stego,
            Self::Pcap,
            Self::Rules,
            Self::Matcher,
            Self::Analyzer,
            Self::AutoAnalyzer,
            Self::Cache,
            Self::History,
        ]
    }

    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Magic => "magic",
            Self::Archive => "archive",
            Self::Extractor => "extractor",
            Self::Decoder => "decoder",
            Self::Cipher => "cipher",
            Self::Hash => "hash",
            Self::Hashcat => "hashcat",
            Self::Stego => "stego",
            Self::Pcap => "pcap",
            Self::Rules => "rules",
            Self::Matcher => "matcher",
            Self::Analyzer => "analyzer",
            Self::AutoAnalyzer => "auto_analyzer",
            Self::Cache => "cache",
            Self::History => "history",
        }
    }
}
