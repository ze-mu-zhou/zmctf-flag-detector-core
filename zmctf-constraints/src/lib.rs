//! `ZMctf` 全局资源与安全约束模型。
//!
//! 目标：
//! - 统一“文件大小、解压输出、外部命令 timeout、stdout/stderr 截断”的语义与默认值
//! - 为所有子模块提供同一份可序列化/可配置的约束结构
//! - 提供少量通用的受限读取工具函数，避免局部散落的 `read_to_end` OOM 风险

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::Read;
use std::path::Path;

pub const MIB: u64 = 1024 * 1024;

#[derive(Debug)]
pub enum ResourceLimitError {
    TooLarge {
        what: &'static str,
        actual: u64,
        max: u64,
    },
}

impl std::fmt::Display for ResourceLimitError {
    fn fmt(
        &self,
        f: &mut std::fmt::Formatter<'_>,
    ) -> std::fmt::Result {
        match self {
            Self::TooLarge { what, actual, max } => {
                write!(f, "{what} 超过上限: 实际 {actual} bytes > 上限 {max} bytes")
            }
        }
    }
}

impl std::error::Error for ResourceLimitError {}

/// stdout/stderr 截断策略的“语义类型”。
///
/// - `Json`: 结构化输出；stdout 截断视为错误（C 方案：结构化输出必须完整）。
/// - `Text`: 纯文本输出；允许截断，但必须可观测（由调用方在结果中标记）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum StdoutKind {
    Json,
    #[default]
    Text,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolLimits {
    /// 0 表示不设置 timeout（允许长时间运行）。
    #[serde(default = "default_tool_timeout_seconds")]
    pub timeout_seconds: u64,
    #[serde(default = "default_tool_stdout_max_bytes")]
    pub stdout_max_bytes: u64,
    #[serde(default = "default_tool_stderr_max_bytes")]
    pub stderr_max_bytes: u64,
    #[serde(default)]
    pub stdout_kind: StdoutKind,
}

const fn default_tool_timeout_seconds() -> u64 {
    60
}

const fn default_tool_stdout_max_bytes() -> u64 {
    MIB
}

const fn default_tool_stderr_max_bytes() -> u64 {
    MIB
}

impl Default for ToolLimits {
    fn default() -> Self {
        Self {
            timeout_seconds: default_tool_timeout_seconds(),
            stdout_max_bytes: default_tool_stdout_max_bytes(),
            stderr_max_bytes: default_tool_stderr_max_bytes(),
            stdout_kind: StdoutKind::Text,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExternalToolsLimits {
    #[serde(default)]
    pub default: ToolLimits,
    #[serde(default)]
    pub overrides: HashMap<String, ToolLimits>,
}

impl Default for ExternalToolsLimits {
    fn default() -> Self {
        let mut overrides = HashMap::new();
        overrides.insert(
            "floss".to_string(),
            ToolLimits {
                timeout_seconds: 300,
                stdout_max_bytes: 32 * MIB,
                stderr_max_bytes: 8 * MIB,
                stdout_kind: StdoutKind::Json,
            },
        );
        overrides.insert(
            "tshark".to_string(),
            ToolLimits {
                timeout_seconds: 60,
                stdout_max_bytes: 32 * MIB,
                stderr_max_bytes: 8 * MIB,
                stdout_kind: StdoutKind::Text,
            },
        );
        overrides.insert(
            "hashcat".to_string(),
            ToolLimits {
                timeout_seconds: 300,
                stdout_max_bytes: 4 * MIB,
                stderr_max_bytes: 4 * MIB,
                stdout_kind: StdoutKind::Text,
            },
        );
        Self {
            default: ToolLimits::default(),
            overrides,
        }
    }
}

impl ExternalToolsLimits {
    #[must_use]
    pub fn for_tool(
        &self,
        tool_name: &str,
    ) -> ToolLimits {
        self.overrides
            .get(tool_name)
            .copied()
            .unwrap_or(self.default)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArchiveLimits {
    #[serde(default = "default_archive_max_depth")]
    pub max_depth: usize,
    #[serde(default = "default_archive_max_entries")]
    pub max_entries: usize,
    #[serde(default = "default_archive_max_total_uncompressed_bytes")]
    pub max_total_uncompressed_bytes: u64,
    #[serde(default = "default_archive_max_entry_uncompressed_bytes")]
    pub max_entry_uncompressed_bytes: u64,
}

const fn default_archive_max_depth() -> usize {
    5
}

const fn default_archive_max_entries() -> usize {
    4096
}

const fn default_archive_max_total_uncompressed_bytes() -> u64 {
    512 * MIB
}

const fn default_archive_max_entry_uncompressed_bytes() -> u64 {
    64 * MIB
}

impl Default for ArchiveLimits {
    fn default() -> Self {
        Self {
            max_depth: default_archive_max_depth(),
            max_entries: default_archive_max_entries(),
            max_total_uncompressed_bytes: default_archive_max_total_uncompressed_bytes(),
            max_entry_uncompressed_bytes: default_archive_max_entry_uncompressed_bytes(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceLimits {
    #[serde(default = "default_input_max_bytes")]
    pub input_max_bytes: u64,
    #[serde(default)]
    pub archive: ArchiveLimits,
    #[serde(default)]
    pub external_tools: ExternalToolsLimits,
}

const fn default_input_max_bytes() -> u64 {
    100 * MIB
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            input_max_bytes: default_input_max_bytes(),
            archive: ArchiveLimits::default(),
            external_tools: ExternalToolsLimits::default(),
        }
    }
}

/// 从文件读取（硬上限：超过即报错）。
///
/// # Errors
///
/// - 当读取元数据或读取文件失败时返回错误。
/// - 当文件大小超过 `max_bytes` 时返回 [`ResourceLimitError::TooLarge`]。
pub fn read_file_with_limit(
    path: &Path,
    max_bytes: u64,
) -> anyhow::Result<Vec<u8>> {
    let meta = std::fs::metadata(path)?;
    let len = meta.len();
    if len > max_bytes {
        return Err(ResourceLimitError::TooLarge {
            what: "输入文件",
            actual: len,
            max: max_bytes,
        }
        .into());
    }
    Ok(std::fs::read(path)?)
}

/// 受限读取：最多读取 `max_bytes`，若源数据更长则返回 `truncated = true`。
///
/// # Errors
///
/// 当底层 `reader` 读取失败时返回错误。
pub fn read_to_end_with_limit<R: Read>(
    mut reader: R,
    max_bytes: u64,
) -> anyhow::Result<(Vec<u8>, bool)> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 8192];

    if max_bytes == 0 {
        let mut one = [0u8; 1];
        let n = reader.read(&mut one)?;
        return Ok((Vec::new(), n != 0));
    }

    let mut remaining = max_bytes;
    while remaining > 0 {
        let to_read = tmp
            .len()
            .min(usize::try_from(remaining).unwrap_or(usize::MAX));
        let n = reader.read(&mut tmp[..to_read])?;
        if n == 0 {
            return Ok((buf, false));
        }
        buf.extend_from_slice(&tmp[..n]);
        remaining = remaining.saturating_sub(n as u64);
    }

    let mut one = [0u8; 1];
    let n = reader.read(&mut one)?;
    Ok((buf, n != 0))
}
