use anyhow::Result;
use std::collections::HashMap;
use std::path::PathBuf;

/// 外部工具信息
#[derive(Debug, Clone)]
pub struct ToolInfo {
    pub name: &'static str,
    pub description: &'static str,
    pub install_hint: &'static str,
    pub required: bool,
}

/// 工具检测器
pub struct ToolDetector {
    tools: HashMap<&'static str, ToolInfo>,
}

impl ToolDetector {
    #[must_use]
    pub fn new() -> Self {
        let mut tools = HashMap::new();

        tools.insert("unrar", ToolInfo {
            name: "unrar",
            description: "RAR 压缩包解包工具",
            install_hint:
                "安装：Linux `apt install unrar`；macOS `brew install unrar`；Windows 从 rarlab.com 下载",
            required: false,
        });

        tools.insert("hashcat", ToolInfo {
            name: "hashcat",
            description: "密码恢复/破解工具（可选）",
            install_hint:
                "安装：Linux `apt install hashcat`；macOS `brew install hashcat`；Windows 从 hashcat.net 下载",
            required: false,
        });

        tools.insert("tshark", ToolInfo {
            name: "tshark",
            description: "网络协议分析器（Wireshark CLI，可选）",
            install_hint:
                "安装：Linux `apt install tshark`；macOS `brew install wireshark`；Windows 从 wireshark.org 下载",
            required: false,
        });

        tools.insert(
            "steghide",
            ToolInfo {
                name: "steghide",
                description: "隐写工具（可选）",
                install_hint: "安装：Linux `apt install steghide`；macOS `brew install steghide`",
                required: false,
            },
        );

        tools.insert(
            "zsteg",
            ToolInfo {
                name: "zsteg",
                description: "PNG/BMP 隐写检测（可选）",
                install_hint: "安装：`gem install zsteg`",
                required: false,
            },
        );

        tools.insert("binwalk", ToolInfo {
            name: "binwalk",
            description: "固件/文件结构分析工具（可选）",
            install_hint:
                "安装：Linux `apt install binwalk`；macOS `brew install binwalk`；Windows 可尝试 `pip install binwalk`",
            required: false,
        });

        tools.insert("exiftool", ToolInfo {
            name: "exiftool",
            description: "图片元数据提取工具（可选）",
            install_hint:
                "安装：Linux `apt install libimage-exiftool-perl`；macOS `brew install exiftool`；Windows 从 exiftool.org 下载",
            required: false,
        });

        tools.insert(
            "strings",
            ToolInfo {
                name: "strings",
                description: "提取可打印字符串（可选）",
                install_hint: "通常 Unix 系统自带；Windows 可从 GNU binutils 获取（或使用 WSL）",
                required: false,
            },
        );

        Self { tools }
    }

    /// 检测工具是否可用
    #[must_use]
    pub fn check_tool(
        &self,
        tool_name: &str,
    ) -> bool {
        tool_runner::resolve_program(tool_name).is_ok()
    }

    /// 检测工具并返回路径
    #[must_use]
    pub fn find_tool(
        &self,
        tool_name: &str,
    ) -> Option<PathBuf> {
        tool_runner::resolve_program(tool_name).ok()
    }

    /// 检测工具，如果不存在则返回友好的错误信息
    ///
    /// # Errors
    ///
    /// 当工具不在 `PATH` 中时返回错误（错误消息包含安装提示）。
    pub fn require_tool(
        &self,
        tool_name: &str,
    ) -> Result<PathBuf> {
        self.find_tool(tool_name).map_or_else(
            || {
                let hint = self
                    .tools
                    .get(tool_name)
                    .map_or("未在 PATH 中找到该工具", |i| i.install_hint);
                Err(anyhow::anyhow!("必需工具 '{tool_name}' 未找到。\n{hint}"))
            },
            Ok,
        )
    }

    /// 检测所有工具并返回报告
    #[must_use]
    pub fn check_all(&self) -> ToolCheckReport {
        let mut available = Vec::new();
        let mut missing = Vec::new();

        for (name, info) in &self.tools {
            if self.check_tool(name) {
                available.push(info.clone());
            } else {
                missing.push(info.clone());
            }
        }

        available.sort_by_key(|t| t.name);
        missing.sort_by_key(|t| t.name);

        ToolCheckReport { available, missing }
    }

    /// 获取工具信息
    #[must_use]
    pub fn get_tool_info(
        &self,
        tool_name: &str,
    ) -> Option<&ToolInfo> {
        self.tools.get(tool_name)
    }
}

impl Default for ToolDetector {
    fn default() -> Self {
        Self::new()
    }
}

/// 工具检测报告
#[derive(Debug)]
pub struct ToolCheckReport {
    pub available: Vec<ToolInfo>,
    pub missing: Vec<ToolInfo>,
}

impl ToolCheckReport {
    /// 生成文本报告（稳定排序、可用于日志/CLI 输出）。
    #[must_use]
    pub fn to_text(&self) -> String {
        use std::fmt::Write as _;
        let mut out = String::new();
        out.push_str("=== 外部工具状态 ===\n\n");

        if !self.available.is_empty() {
            let available_count = self.available.len();
            let _ = writeln!(&mut out, "可用工具 ({available_count}):");
            for tool in &self.available {
                let name = tool.name;
                let description = tool.description;
                let _ = writeln!(&mut out, "  - {name}（{description}）");
            }
            out.push('\n');
        }

        if !self.missing.is_empty() {
            let missing_count = self.missing.len();
            let _ = writeln!(&mut out, "缺失工具 ({missing_count}):");
            for tool in &self.missing {
                let name = tool.name;
                let description = tool.description;
                let hint = tool.install_hint;
                let _ = writeln!(&mut out, "  - {name}（{description}）");
                let _ = writeln!(&mut out, "    {hint}");
            }
            out.push('\n');
        }

        out.push_str("提示：缺失工具为可选项，不影响核心功能运行。\n");
        out
    }

    /// 打印报告
    pub fn print(&self) {
        let text = self.to_text();
        print!("{text}");
    }

    /// 是否所有必需工具都可用
    #[must_use]
    pub fn all_required_available(&self) -> bool {
        !self.missing.iter().any(|t| t.required)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tool_detector_creation() {
        let detector = ToolDetector::new();
        assert!(!detector.tools.is_empty());
    }

    #[test]
    fn test_check_all() {
        let detector = ToolDetector::new();
        let report = detector.check_all();
        // 至少应该有一些工具被检测到
        assert!(report.available.len() + report.missing.len() > 0);
    }

    #[test]
    fn test_get_tool_info() {
        let detector = ToolDetector::new();
        let info = detector.get_tool_info("unrar");
        assert!(info.is_some());
        assert_eq!(info.unwrap().name, "unrar");
    }
}
