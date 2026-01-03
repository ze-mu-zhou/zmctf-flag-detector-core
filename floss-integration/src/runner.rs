use crate::types::{
    FileFormat, FlossAnalysis, FlossConfig, FlossResult, FlossString, Language, StringType,
    Verbosity,
};
use anyhow::{Context, Result};
use serde::Deserialize;
use std::path::{Path, PathBuf};
use tool_runner::{resolve_program, ToolCommand};
use zmctf_constraints::StdoutKind;

fn resolve_floss_path(config: &FlossConfig) -> Result<PathBuf> {
    resolve_program(&config.floss_path).with_context(|| {
        format!(
            "FLOSS 不可用: {}（请安装: `pip install flare-floss`，或在配置中指定 floss 路径）",
            config.floss_path.display()
        )
    })
}

fn push_output_args(
    cmd: &mut ToolCommand,
    config: &FlossConfig,
) {
    if config.output.json_output {
        cmd.arg("--json");
    }
    if config.output.no_progress {
        cmd.arg("--no-progress");
    }
    match config.output.verbosity {
        Verbosity::Normal => {}
        Verbosity::Verbose => {
            cmd.arg("-v");
        }
        Verbosity::Quiet => {
            cmd.arg("-q");
        }
    }
}

fn push_string_type_args(
    cmd: &mut ToolCommand,
    config: &FlossConfig,
) {
    // === 字符串类型控制 (--no) ===
    if !config.string_types.enabled.contains(StringType::Static) {
        cmd.arg("--no").arg("static");
    }
    if !config.string_types.enabled.contains(StringType::Stack) {
        cmd.arg("--no").arg("stack");
    }
    if !config.string_types.enabled.contains(StringType::Tight) {
        cmd.arg("--no").arg("tight");
    }
    if !config.string_types.enabled.contains(StringType::Decoded) {
        cmd.arg("--no").arg("decoded");
    }

    // === 字符串类型控制 (--only) ===
    if !config.string_types.only.is_empty() {
        cmd.arg("--only");
        for t in &config.string_types.only {
            match t {
                StringType::Static => cmd.arg("static"),
                StringType::Stack => cmd.arg("stack"),
                StringType::Tight => cmd.arg("tight"),
                StringType::Decoded => cmd.arg("decoded"),
            };
        }
    }
}

fn push_analysis_args(
    cmd: &mut ToolCommand,
    config: &FlossConfig,
) {
    // === 函数地址 ===
    for func in &config.analysis.functions {
        cmd.arg("--functions").arg(func);
    }
    if let Some(ref f) = config.analysis.functions_from_file {
        cmd.arg("--functions-from-file").arg(f);
    }

    // === 文件格式 ===
    match config.analysis.format {
        FileFormat::Auto => {}
        FileFormat::PE => {
            cmd.arg("-f").arg("pe");
        }
        FileFormat::Sc32 => {
            cmd.arg("-f").arg("sc32");
        }
        FileFormat::Sc64 => {
            cmd.arg("-f").arg("sc64");
        }
    }

    // === 语言 ===
    match config.analysis.language {
        Language::Auto => {}
        Language::Go => {
            cmd.arg("--language").arg("go");
        }
        Language::Rust => {
            cmd.arg("--language").arg("rust");
        }
        Language::Dotnet => {
            cmd.arg("--language").arg("dotnet");
        }
        Language::None => {
            cmd.arg("--language").arg("none");
        }
    }

    // === 高级选项 ===
    if config.analysis.shellcode {
        cmd.arg("--shellcode");
    }
    if config.analysis.large_file {
        cmd.arg("-L");
    }
    if let Some(ref sig_path) = config.advanced.signatures {
        cmd.arg("--signatures").arg(sig_path);
    }
    if let Some(ref load_path) = config.advanced.load_results {
        cmd.arg("-l").arg(load_path);
    }

    // === 分析限制 ===
    if let Some(v) = config.limits.max_address_sweep_diff {
        cmd.arg("--max-address-sweep-diff").arg(v.to_string());
    }
    if let Some(v) = config.limits.max_structure_size {
        cmd.arg("--max-structure-size").arg(v.to_string());
    }
    if let Some(v) = config.limits.max_decoding_loops {
        cmd.arg("--max-decoding-loops").arg(v.to_string());
    }
    if let Some(v) = config.limits.max_insn_count {
        cmd.arg("--max-insn-count").arg(v.to_string());
    }

    // === 工作区 ===
    if let Some(ref p) = config.workspace.save_workspace {
        cmd.arg("--save-workspace").arg(p);
    }
    if let Some(ref p) = config.workspace.load_workspace {
        cmd.arg("--load-workspace").arg(p);
    }

    // === 过滤 ===
    if config.filters.no_filter {
        cmd.arg("--no-filter");
    }
    if config.filters.no_analysis {
        cmd.arg("--no-analysis");
    }

    // === 字符串长度 ===
    cmd.arg("-n").arg(config.length.min_length.to_string());
}

fn build_floss_command(
    file_path: &Path,
    config: &FlossConfig,
) -> Result<ToolCommand> {
    let floss_path = resolve_floss_path(config)?;
    let mut cmd = ToolCommand::new(floss_path);
    cmd.arg(file_path);

    push_output_args(&mut cmd, config);
    push_string_type_args(&mut cmd, config);
    push_analysis_args(&mut cmd, config);

    cmd.apply_limits(&config.tool_limits);
    Ok(cmd)
}

fn ensure_output_ok(
    output: &tool_runner::RunOutput,
    config: &FlossConfig,
) -> Result<()> {
    if output.timed_out {
        anyhow::bail!("FLOSS 执行超时: {} 秒", config.tool_limits.timeout_seconds);
    }

    if config.tool_limits.stdout_kind == StdoutKind::Json && output.stdout_truncated {
        anyhow::bail!(
            "FLOSS stdout 超过上限并被截断（stdout_max_bytes={}），无法可靠解析 JSON；请提高资源上限或减少分析输出",
            output.stdout_max_bytes
        );
    }

    if output.status.success() {
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    let truncated = if output.stderr_truncated {
        "（stderr 已截断）"
    } else {
        ""
    };
    anyhow::bail!("FLOSS 执行失败{truncated}: {stderr}");
}

/// 运行 FLOSS 分析（完整 CLI 参数支持）。
///
/// # Errors
///
/// - 当 FLOSS 不可用或执行失败时返回错误。
/// - 当 stdout 为结构化输出且发生截断时返回错误（C 方案：结构化输出必须完整）。
/// - 当 JSON 解析失败时返回错误。
pub fn run_floss(
    file_path: &Path,
    config: &FlossConfig,
) -> Result<FlossResult> {
    log::info!("运行FLOSS分析: {}", file_path.display());

    let cmd = build_floss_command(file_path, config)?;
    log::debug!("执行命令: {cmd:?}");

    let output = cmd
        .run()
        .with_context(|| format!("执行 FLOSS 失败: {}", config.floss_path.display()))?;

    ensure_output_ok(&output, config)?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    parse_floss_output(&stdout, file_path)
}

fn parse_floss_output(
    json_str: &str,
    file_path: &Path,
) -> Result<FlossResult> {
    #[derive(Deserialize)]
    struct FlossJsonOutput {
        strings: Option<FlossJsonStrings>,
        analysis: Option<FlossJsonAnalysis>,
    }

    #[derive(Deserialize)]
    struct FlossJsonStrings {
        #[serde(default, rename = "static_strings")]
        statics: Vec<FlossJsonString>,
        #[serde(default, rename = "stack_strings")]
        stacks: Vec<FlossJsonString>,
        #[serde(default, rename = "tight_strings")]
        tights: Vec<FlossJsonString>,
        #[serde(default, rename = "decoded_strings")]
        decoded: Vec<FlossJsonString>,
    }

    #[derive(Deserialize)]
    struct FlossJsonString {
        string: String,
        #[serde(default)]
        offset: Option<u64>,
        #[serde(default)]
        encoding: Option<String>,
        #[serde(default)]
        function: Option<String>,
    }

    #[derive(Deserialize)]
    struct FlossJsonAnalysis {
        file_type: Option<String>,
        architecture: Option<String>,
        #[serde(default)]
        total_functions: usize,
        #[serde(default)]
        analyzed_functions: usize,
    }

    log::debug!("解析FLOSS输出");

    let parsed: FlossJsonOutput =
        serde_json::from_str(json_str).with_context(|| "解析FLOSS JSON输出失败")?;

    let mut strings = Vec::new();

    if let Some(floss_strings) = parsed.strings {
        for s in floss_strings.statics {
            strings.push(FlossString {
                string: s.string,
                offset: s.offset,
                string_type: StringType::Static,
                encoding: s.encoding,
                function: s.function,
            });
        }
        for s in floss_strings.stacks {
            strings.push(FlossString {
                string: s.string,
                offset: s.offset,
                string_type: StringType::Stack,
                encoding: s.encoding,
                function: s.function,
            });
        }
        for s in floss_strings.tights {
            strings.push(FlossString {
                string: s.string,
                offset: s.offset,
                string_type: StringType::Tight,
                encoding: s.encoding,
                function: s.function,
            });
        }
        for s in floss_strings.decoded {
            strings.push(FlossString {
                string: s.string,
                offset: s.offset,
                string_type: StringType::Decoded,
                encoding: s.encoding,
                function: s.function,
            });
        }
    }

    let analysis = parsed.analysis.map(|a| FlossAnalysis {
        file_type: a.file_type,
        architecture: a.architecture,
        total_functions: a.total_functions,
        analyzed_functions: a.analyzed_functions,
    });

    log::info!("FLOSS提取到 {} 个字符串", strings.len());

    Ok(FlossResult {
        file_path: file_path.to_path_buf(),
        strings,
        analysis,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn test_parse_floss_output_parses_strings_and_analysis() -> Result<()> {
        let json = r#"
        {
          "strings": {
            "static_strings": [
              {"string": "hello", "offset": 16, "encoding": "utf-8", "function": "main"}
            ],
            "stack_strings": [
              {"string": "world"}
            ],
            "tight_strings": [],
            "decoded_strings": [
              {"string": "flag{test}", "offset": 32}
            ]
          },
          "analysis": {
            "file_type": "PE",
            "architecture": "x86",
            "total_functions": 10,
            "analyzed_functions": 8
          }
        }
        "#;

        let result = parse_floss_output(json, Path::new("sample.bin"))?;
        assert_eq!(result.file_path, std::path::PathBuf::from("sample.bin"));
        assert_eq!(result.strings.len(), 3);
        assert!(matches!(result.strings[0].string_type, StringType::Static));
        assert_eq!(result.strings[0].string, "hello");
        assert!(matches!(result.strings[1].string_type, StringType::Stack));
        assert!(matches!(result.strings[2].string_type, StringType::Decoded));

        let analysis = result.analysis.expect("analysis should exist");
        assert_eq!(analysis.total_functions, 10);
        assert_eq!(analysis.analyzed_functions, 8);
        Ok(())
    }
}
