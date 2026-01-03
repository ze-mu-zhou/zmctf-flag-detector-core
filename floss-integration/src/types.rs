use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use zmctf_constraints::{ResourceLimits, ToolLimits};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StringType {
    Static,
    Stack,
    Tight,
    Decoded,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlossString {
    pub string: String,
    pub offset: Option<u64>,
    pub string_type: StringType,
    pub encoding: Option<String>,
    pub function: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlossResult {
    pub file_path: PathBuf,
    pub strings: Vec<FlossString>,
    pub analysis: Option<FlossAnalysis>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlossAnalysis {
    pub file_type: Option<String>,
    pub architecture: Option<String>,
    pub total_functions: usize,
    pub analyzed_functions: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum FileFormat {
    #[default]
    Auto,
    PE,
    Sc32,
    Sc64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum Language {
    #[default]
    Auto,
    Go,
    Rust,
    Dotnet,
    None,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Verbosity {
    #[default]
    Normal,
    Verbose,
    Quiet,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StringTypeSet(u8);

impl StringTypeSet {
    const STATIC: u8 = 1 << 0;
    const STACK: u8 = 1 << 1;
    const TIGHT: u8 = 1 << 2;
    const DECODED: u8 = 1 << 3;

    const fn bit_of(string_type: StringType) -> u8 {
        match string_type {
            StringType::Static => Self::STATIC,
            StringType::Stack => Self::STACK,
            StringType::Tight => Self::TIGHT,
            StringType::Decoded => Self::DECODED,
        }
    }

    #[must_use]
    pub const fn all() -> Self {
        Self(Self::STATIC | Self::STACK | Self::TIGHT | Self::DECODED)
    }

    #[must_use]
    pub const fn contains(
        self,
        string_type: StringType,
    ) -> bool {
        (self.0 & Self::bit_of(string_type)) != 0
    }

    pub const fn enable(
        &mut self,
        string_type: StringType,
    ) {
        self.0 |= Self::bit_of(string_type);
    }

    pub const fn disable(
        &mut self,
        string_type: StringType,
    ) {
        self.0 &= !Self::bit_of(string_type);
    }
}

impl Default for StringTypeSet {
    fn default() -> Self {
        Self::all()
    }
}

#[derive(Debug, Clone, Copy)]
pub struct LengthOptions {
    pub min_length: usize,
    pub max_length: Option<usize>,
}

impl Default for LengthOptions {
    fn default() -> Self {
        Self {
            min_length: 4,
            max_length: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct OutputOptions {
    pub verbosity: Verbosity,
    pub json_output: bool,
    pub no_progress: bool,
}

impl Default for OutputOptions {
    fn default() -> Self {
        Self {
            verbosity: Verbosity::Normal,
            json_output: true,
            no_progress: true,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct StringTypeOptions {
    pub enabled: StringTypeSet,
    pub only: Vec<StringType>,
    pub only_unique: bool,
}

#[derive(Debug, Clone)]
pub struct AnalysisOptions {
    pub functions: Vec<String>,
    pub functions_from_file: Option<PathBuf>,
    pub shellcode: bool,
    pub format: FileFormat,
    pub language: Language,
    pub large_file: bool,
}

impl Default for AnalysisOptions {
    fn default() -> Self {
        Self {
            functions: Vec::new(),
            functions_from_file: None,
            shellcode: false,
            format: FileFormat::Auto,
            language: Language::Auto,
            large_file: false,
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct FlossLimits {
    pub max_address_sweep_diff: Option<u32>,
    pub max_structure_size: Option<u32>,
    pub max_decoding_loops: Option<u32>,
    pub max_insn_count: Option<u32>,
}

#[derive(Debug, Clone, Default)]
pub struct WorkspaceOptions {
    pub save_workspace: Option<PathBuf>,
    pub load_workspace: Option<PathBuf>,
}

#[derive(Debug, Clone, Default)]
pub struct FilterOptions {
    pub no_filter: bool,
    pub no_analysis: bool,
}

#[derive(Debug, Clone, Default)]
pub struct AdvancedOptions {
    pub signatures: Option<PathBuf>,
    pub load_results: Option<PathBuf>,
}

/// FLOSS 完整配置（尽量贴近 CLI 语义）。
#[derive(Debug, Clone)]
pub struct FlossConfig {
    /// FLOSS 可执行文件路径（或可在 PATH 中解析的名字）。
    pub floss_path: PathBuf,
    /// 外部命令资源约束（timeout/stdout/stderr 上限等）。
    pub tool_limits: ToolLimits,
    /// 字符串长度选项（`-n` / 内部限制）。
    pub length: LengthOptions,
    /// 字符串类型控制（`--no` / `--only` 等）。
    pub string_types: StringTypeOptions,
    /// 分析选项（format/language/functions 等）。
    pub analysis: AnalysisOptions,
    /// 输出控制（verbosity/json/progress）。
    pub output: OutputOptions,
    /// 高级选项（signatures/load 等）。
    pub advanced: AdvancedOptions,
    /// 分析限制参数。
    pub limits: FlossLimits,
    /// 工作区保存/加载。
    pub workspace: WorkspaceOptions,
    /// 过滤相关选项。
    pub filters: FilterOptions,
}

impl Default for FlossConfig {
    fn default() -> Self {
        let tool_limits = ResourceLimits::default().external_tools.for_tool("floss");
        Self {
            floss_path: PathBuf::from("floss"),
            tool_limits,
            length: LengthOptions::default(),
            string_types: StringTypeOptions::default(),
            analysis: AnalysisOptions::default(),
            output: OutputOptions::default(),
            advanced: AdvancedOptions::default(),
            limits: FlossLimits::default(),
            workspace: WorkspaceOptions::default(),
            filters: FilterOptions::default(),
        }
    }
}

impl FlossConfig {
    /// 从全局资源与安全约束中同步外部命令限制（timeout/stdout/stderr 上限与输出类型）。
    #[must_use]
    pub fn with_resource_limits(
        mut self,
        resources: &ResourceLimits,
    ) -> Self {
        self.tool_limits = resources.external_tools.for_tool("floss");
        self
    }

    /// 快速模式 - 只提取静态字符串
    #[must_use]
    pub fn fast() -> Self {
        let mut config = Self::default();
        config.string_types.only = vec![StringType::Static];
        config.string_types.enabled = StringTypeSet::all();
        config.string_types.enabled.disable(StringType::Stack);
        config.string_types.enabled.disable(StringType::Tight);
        config.string_types.enabled.disable(StringType::Decoded);
        config
    }

    /// 完整模式 - 所有功能
    #[must_use]
    pub fn full() -> Self {
        Self::default()
    }

    /// Shellcode 模式
    #[must_use]
    pub fn shellcode_mode(bits: u8) -> Self {
        let mut config = Self::default();
        config.analysis.format = if bits == 64 {
            FileFormat::Sc64
        } else {
            FileFormat::Sc32
        };
        config.analysis.shellcode = true;
        config
    }

    /// Go 语言模式
    #[must_use]
    pub fn go_mode() -> Self {
        Self {
            analysis: AnalysisOptions {
                language: Language::Go,
                ..AnalysisOptions::default()
            },
            ..Default::default()
        }
    }

    /// Rust 语言模式
    #[must_use]
    pub fn rust_mode() -> Self {
        Self {
            analysis: AnalysisOptions {
                language: Language::Rust,
                ..AnalysisOptions::default()
            },
            ..Default::default()
        }
    }

    /// .NET 模式
    #[must_use]
    pub fn dotnet_mode() -> Self {
        Self {
            analysis: AnalysisOptions {
                language: Language::Dotnet,
                ..AnalysisOptions::default()
            },
            ..Default::default()
        }
    }

    /// 只提取解码字符串
    #[must_use]
    pub fn decoded_only() -> Self {
        let mut config = Self::default();
        config.string_types.only = vec![StringType::Decoded];
        config.string_types.enabled = StringTypeSet::all();
        config.string_types.enabled.disable(StringType::Static);
        config.string_types.enabled.disable(StringType::Stack);
        config.string_types.enabled.disable(StringType::Tight);
        config
    }

    /// 只提取栈字符串
    #[must_use]
    pub fn stack_only() -> Self {
        let mut config = Self::default();
        config.string_types.only = vec![StringType::Stack];
        config.string_types.enabled = StringTypeSet::all();
        config.string_types.enabled.disable(StringType::Static);
        config.string_types.enabled.disable(StringType::Tight);
        config.string_types.enabled.disable(StringType::Decoded);
        config
    }
}
