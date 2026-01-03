#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

pub mod runner;
pub mod types;

use anyhow::Result;
use std::path::Path;

pub use types::{
    FileFormat, FlossAnalysis, FlossConfig, FlossResult, FlossString, Language, StringType,
};

/// 使用 FLOSS 对目标文件进行字符串提取分析。
///
/// # Errors
///
/// 当 FLOSS 不可用、执行失败、输出截断（结构化输出）或解析失败时返回错误。
pub fn analyze_with_floss(
    file_path: &Path,
    config: &FlossConfig,
) -> Result<FlossResult> {
    runner::run_floss(file_path, config)
}
