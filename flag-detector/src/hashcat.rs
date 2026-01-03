//! Hashcat 集成模块 - 100% CLI参数覆盖
//!
//! 完整封装 hashcat 所有命令行参数
//! 支持所有攻击模式、设备选项、性能调优、会话管理等

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use tool_runner::ToolCommand;
use zmctf_constraints::ResourceLimits;

/// 攻击模式
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum AttackMode {
    #[default]
    Dictionary = 0, // -a 0
    Combinator = 1,     // -a 1
    BruteForce = 3,     // -a 3
    HybridDictMask = 6, // -a 6
    HybridMaskDict = 7, // -a 7
    Association = 9,    // -a 9
}

/// 输出格式
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum OutfileFormat {
    HashPlain = 1,
    #[default]
    Plain = 2,
    Hex = 3,
    HashPlainHex = 4,
    Timestamp = 5,
    // 可组合使用
}

/// 调试模式
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum DebugMode {
    #[default]
    Off = 0,
    FindingRule = 1,
    OriginalWord = 2,
    OriginalWordFindingRule = 3,
    OriginalWordModifiedPlain = 4,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Toggle {
    Enabled,
    Disabled,
}

impl Toggle {
    #[must_use]
    pub const fn is_enabled(self) -> bool {
        matches!(self, Self::Enabled)
    }

    #[must_use]
    pub const fn is_disabled(self) -> bool {
        matches!(self, Self::Disabled)
    }
}

/// Hashcat 完整配置 - 覆盖所有CLI参数
#[derive(Clone, Debug)]
pub struct HashcatConfig {
    // === 基础配置 ===
    pub exe_path: PathBuf,
    pub work_dir: PathBuf,

    // === 哈希与攻击 ===
    pub hash_type: Option<u32>,  // -m, --hash-type
    pub attack_mode: AttackMode, // -a, --attack-mode

    // === 输入源 ===
    pub wordlist: Option<PathBuf>,   // 字典文件
    pub wordlist2: Option<PathBuf>,  // 第二字典(组合攻击)
    pub mask: Option<String>,        // 掩码
    pub rules_file: Option<PathBuf>, // -r, --rules-file
    pub rules_left: Option<String>,  // -j, --rule-left
    pub rules_right: Option<String>, // -k, --rule-right

    // === 输出配置 ===
    pub outfile: Option<PathBuf>,         // -o, --outfile
    pub outfile_format: Option<String>,   // --outfile-format (可组合: 1,2,3)
    pub outfile_autohex: Toggle,          // --outfile-autohex-disable
    pub outfile_check_timer: Option<u32>, // --outfile-check-timer

    // === Potfile ===
    pub potfile_disable: Toggle,       // --potfile-disable
    pub potfile_path: Option<PathBuf>, // --potfile-path

    // === 会话管理 ===
    pub session: Option<String>,            // --session
    pub restore: Toggle,                    // --restore
    pub restore_disable: Toggle,            // --restore-disable
    pub restore_file_path: Option<PathBuf>, // --restore-file-path

    // === 性能调优 ===
    pub workload_profile: u8,              // -w, --workload-profile (1-4)
    pub kernel_accel: Option<u32>,         // -n, --kernel-accel
    pub kernel_loops: Option<u32>,         // -u, --kernel-loops
    pub kernel_threads: Option<u32>,       // -T, --kernel-threads
    pub backend_vector_width: Option<u32>, // --backend-vector-width
    pub spin_damp: Option<u32>,            // --spin-damp

    // === 内核选项 ===
    pub optimized_kernel: Toggle,  // -O, --optimized-kernel-enable
    pub multiply_accel: Toggle,    // -M, --multiply-accel-disable
    pub self_test_disable: Toggle, // --self-test-disable

    // === 设备选择 ===
    pub backend_devices: Option<String>, // -d, --backend-devices
    pub opencl_device_types: Option<String>, // -D, --opencl-device-types
    pub backend_ignore_cuda: Toggle,     // --backend-ignore-cuda
    pub backend_ignore_hip: Toggle,      // --backend-ignore-hip
    pub backend_ignore_metal: Toggle,    // --backend-ignore-metal
    pub backend_ignore_opencl: Toggle,   // --backend-ignore-opencl

    // === 温度监控 ===
    pub hwmon_disable: Toggle,         // --hwmon-disable
    pub hwmon_temp_abort: Option<u32>, // --hwmon-temp-abort

    // === 增量模式 ===
    pub increment: Toggle,         // -i, --increment
    pub increment_min: Option<u8>, // --increment-min
    pub increment_max: Option<u8>, // --increment-max

    // === 自定义字符集 ===
    pub custom_charset1: Option<String>, // -1, --custom-charset1
    pub custom_charset2: Option<String>, // -2, --custom-charset2
    pub custom_charset3: Option<String>, // -3, --custom-charset3
    pub custom_charset4: Option<String>, // -4, --custom-charset4

    // === 限制与跳过 ===
    pub skip: Option<u64>,    // -s, --skip
    pub limit: Option<u64>,   // -l, --limit
    pub keyspace: Toggle,     // --keyspace
    pub runtime: Option<u64>, // --runtime (秒)

    // === Markov ===
    pub markov_disable: Toggle,          // --markov-disable
    pub markov_classic: Toggle,          // --markov-classic
    pub markov_inverse: Toggle,          // --markov-inverse
    pub markov_threshold: Option<u32>,   // --markov-threshold
    pub markov_hcstat2: Option<PathBuf>, // --markov-hcstat2

    // === 状态与输出 ===
    pub status: Toggle,                   // --status
    pub status_json: Toggle,              // --status-json
    pub status_timer: Option<u32>,        // --status-timer
    pub stdin_timeout_abort: Option<u32>, // --stdin-timeout-abort
    pub machine_readable: Toggle,         // --machine-readable
    pub quiet: Toggle,                    // --quiet
    pub force: Toggle,                    // --force
    pub loopback: Toggle,                 // --loopback
    pub slow_candidates: Toggle,          // -S, --slow-candidates

    // === 调试 ===
    pub debug_mode: DebugMode,       // --debug-mode
    pub debug_file: Option<PathBuf>, // --debug-file

    // === 其他 ===
    pub username: Toggle,                 // --username
    pub remove: Toggle,                   // --remove
    pub remove_timer: Option<u32>,        // --remove-timer
    pub keep_guessing: Toggle,            // --keep-guessing
    pub separator: Option<char>,          // --separator
    pub hex_salt: Toggle,                 // --hex-salt
    pub hex_wordlist: Toggle,             // --hex-wordlist
    pub hex_charset: Toggle,              // --hex-charset
    pub encoding_from: Option<String>,    // --encoding-from
    pub encoding_to: Option<String>,      // --encoding-to
    pub wordlist_autohex_disable: Toggle, // --wordlist-autohex-disable

    // === Brain ===
    pub brain_server: Toggle,                    // --brain-server
    pub brain_server_timer: Option<u32>,         // --brain-server-timer
    pub brain_client: Toggle,                    // --brain-client
    pub brain_client_features: Option<u32>,      // --brain-client-features
    pub brain_host: Option<String>,              // --brain-host
    pub brain_port: Option<u16>,                 // --brain-port
    pub brain_password: Option<String>,          // --brain-password
    pub brain_session: Option<String>,           // --brain-session
    pub brain_session_whitelist: Option<String>, // --brain-session-whitelist
}

impl Default for HashcatConfig {
    fn default() -> Self {
        Self {
            exe_path: PathBuf::from(r"D:\hashcat-7.1.2\hashcat.exe"),
            work_dir: std::env::temp_dir().join("zmctf_hashcat"),
            hash_type: None,
            attack_mode: AttackMode::Dictionary,
            wordlist: Some(PathBuf::from(r"D:\hashcat-7.1.2\rockyou.txt")),
            wordlist2: None,
            mask: None,
            rules_file: None,
            rules_left: None,
            rules_right: None,
            outfile: None,
            outfile_format: Some("2".to_string()),
            outfile_autohex: Toggle::Enabled,
            outfile_check_timer: None,
            potfile_disable: Toggle::Disabled,
            potfile_path: None,
            session: None,
            restore: Toggle::Disabled,
            restore_disable: Toggle::Disabled,
            restore_file_path: None,
            workload_profile: 3,
            kernel_accel: None,
            kernel_loops: None,
            kernel_threads: None,
            backend_vector_width: None,
            spin_damp: None,
            optimized_kernel: Toggle::Enabled,
            multiply_accel: Toggle::Enabled,
            self_test_disable: Toggle::Disabled,
            backend_devices: None,
            opencl_device_types: None,
            backend_ignore_cuda: Toggle::Disabled,
            backend_ignore_hip: Toggle::Disabled,
            backend_ignore_metal: Toggle::Disabled,
            backend_ignore_opencl: Toggle::Disabled,
            hwmon_disable: Toggle::Disabled,
            hwmon_temp_abort: None,
            increment: Toggle::Disabled,
            increment_min: None,
            increment_max: None,
            custom_charset1: None,
            custom_charset2: None,
            custom_charset3: None,
            custom_charset4: None,
            skip: None,
            limit: None,
            keyspace: Toggle::Disabled,
            runtime: None,
            markov_disable: Toggle::Disabled,
            markov_classic: Toggle::Disabled,
            markov_inverse: Toggle::Disabled,
            markov_threshold: None,
            markov_hcstat2: None,
            status: Toggle::Disabled,
            status_json: Toggle::Disabled,
            status_timer: None,
            stdin_timeout_abort: None,
            machine_readable: Toggle::Disabled,
            quiet: Toggle::Enabled,
            force: Toggle::Disabled,
            loopback: Toggle::Disabled,
            slow_candidates: Toggle::Disabled,
            debug_mode: DebugMode::Off,
            debug_file: None,
            username: Toggle::Disabled,
            remove: Toggle::Disabled,
            remove_timer: None,
            keep_guessing: Toggle::Disabled,
            separator: None,
            hex_salt: Toggle::Disabled,
            hex_wordlist: Toggle::Disabled,
            hex_charset: Toggle::Disabled,
            encoding_from: None,
            encoding_to: None,
            wordlist_autohex_disable: Toggle::Disabled,
            brain_server: Toggle::Disabled,
            brain_server_timer: None,
            brain_client: Toggle::Disabled,
            brain_client_features: None,
            brain_host: None,
            brain_port: None,
            brain_password: None,
            brain_session: None,
            brain_session_whitelist: None,
        }
    }
}

/// 破解结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrackResult {
    pub hash: String,
    pub plaintext: Option<String>,
    pub hash_type: u32,
    pub success: bool,
    pub error: Option<String>,
    pub time_elapsed: Option<f64>,
}

/// 设备信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceInfo {
    pub id: u32,
    pub name: String,
    pub device_type: String,
    pub memory: Option<u64>,
}

/// 基准测试结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkResult {
    pub hash_mode: u32,
    pub hash_name: String,
    pub speed: String,
}

/// 哈希类型信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashTypeInfo {
    pub mode: u32,
    pub name: String,
    pub category: String,
}

/// Hashcat 包装器 - 完整CLI集成
pub struct Hashcat {
    config: HashcatConfig,
    resources: ResourceLimits,
}

impl Default for Hashcat {
    fn default() -> Self {
        Self::new(HashcatConfig::default())
    }
}

impl Hashcat {
    #[must_use]
    pub fn new(config: HashcatConfig) -> Self {
        Self {
            config,
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

    /// 检查 hashcat 是否可用
    #[must_use]
    pub fn is_available(&self) -> bool {
        self.config.exe_path.exists()
    }

    /// 获取 hashcat 版本
    ///
    /// # Errors
    ///
    /// 当外部工具执行失败时返回错误。
    pub fn version(&self) -> Result<String> {
        let tool_limits = self.resources.external_tools.for_tool("hashcat");
        let output = {
            let mut cmd = ToolCommand::new(self.config.exe_path.clone());
            cmd.apply_limits(&tool_limits)
                .arg("--version")
                .stdout_max_bytes(16 * 1024)
                .stderr_max_bytes(16 * 1024);
            cmd.run().context("执行 hashcat 失败")?
        };
        Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
    }

    /// 构建完整的命令行参数
    fn build_command(
        &self,
        hash_file: &PathBuf,
    ) -> ToolCommand {
        let mut cmd = ToolCommand::new(self.config.exe_path.clone());
        let tool_limits = self.resources.external_tools.for_tool("hashcat");
        cmd.apply_limits(&tool_limits)
            .set_current_dir(self.config.work_dir.clone());

        // === 哈希类型 ===
        if let Some(m) = self.config.hash_type {
            cmd.push_arg("-m").push_arg(m.to_string());
        }

        // === 攻击模式 ===
        cmd.push_arg("-a")
            .push_arg((self.config.attack_mode as u32).to_string());

        self.push_performance_args(&mut cmd);

        self.push_kernel_args(&mut cmd);

        self.push_device_args(&mut cmd);

        self.push_hwmon_args(&mut cmd);

        self.push_outfile_args(&mut cmd);

        self.push_potfile_args(&mut cmd);

        self.push_session_args(&mut cmd);

        self.push_increment_args(&mut cmd);

        self.push_charset_args(&mut cmd);

        self.push_limit_args(&mut cmd);

        self.push_markov_args(&mut cmd);

        self.push_status_args(&mut cmd);

        self.push_debug_args(&mut cmd);

        self.push_rule_args(&mut cmd);

        self.push_misc_args(&mut cmd);

        self.push_brain_args(&mut cmd);

        // === 哈希文件 ===
        cmd.push_arg(hash_file);

        self.push_attack_source_args(&mut cmd);

        cmd
    }

    fn push_performance_args(
        &self,
        cmd: &mut ToolCommand,
    ) {
        cmd.push_arg("-w")
            .push_arg(self.config.workload_profile.to_string());
        if let Some(n) = self.config.kernel_accel {
            cmd.push_arg("-n").push_arg(n.to_string());
        }
        if let Some(u) = self.config.kernel_loops {
            cmd.push_arg("-u").push_arg(u.to_string());
        }
        if let Some(t) = self.config.kernel_threads {
            cmd.push_arg("-T").push_arg(t.to_string());
        }
        if let Some(v) = self.config.backend_vector_width {
            cmd.push_arg("--backend-vector-width")
                .push_arg(v.to_string());
        }
        if let Some(s) = self.config.spin_damp {
            cmd.push_arg("--spin-damp").push_arg(s.to_string());
        }
    }

    fn push_kernel_args(
        &self,
        cmd: &mut ToolCommand,
    ) {
        if self.config.optimized_kernel.is_enabled() {
            cmd.push_arg("-O");
        }
        if self.config.multiply_accel.is_disabled() {
            cmd.push_arg("-M");
        }
        if self.config.self_test_disable.is_enabled() {
            cmd.push_arg("--self-test-disable");
        }
    }

    fn push_device_args(
        &self,
        cmd: &mut ToolCommand,
    ) {
        if let Some(ref d) = self.config.backend_devices {
            cmd.push_arg("-d").push_arg(d);
        }
        if let Some(ref d) = self.config.opencl_device_types {
            cmd.push_arg("-D").push_arg(d);
        }
        if self.config.backend_ignore_cuda.is_enabled() {
            cmd.push_arg("--backend-ignore-cuda");
        }
        if self.config.backend_ignore_hip.is_enabled() {
            cmd.push_arg("--backend-ignore-hip");
        }
        if self.config.backend_ignore_metal.is_enabled() {
            cmd.push_arg("--backend-ignore-metal");
        }
        if self.config.backend_ignore_opencl.is_enabled() {
            cmd.push_arg("--backend-ignore-opencl");
        }
    }

    fn push_hwmon_args(
        &self,
        cmd: &mut ToolCommand,
    ) {
        if self.config.hwmon_disable.is_enabled() {
            cmd.push_arg("--hwmon-disable");
        }
        if let Some(t) = self.config.hwmon_temp_abort {
            cmd.push_arg("--hwmon-temp-abort").push_arg(t.to_string());
        }
    }

    fn push_outfile_args(
        &self,
        cmd: &mut ToolCommand,
    ) {
        if let Some(ref o) = self.config.outfile {
            cmd.push_arg("-o").push_arg(o);
        }
        if let Some(ref f) = self.config.outfile_format {
            cmd.push_arg("--outfile-format").push_arg(f);
        }
        if self.config.outfile_autohex.is_disabled() {
            cmd.push_arg("--outfile-autohex-disable");
        }
        if let Some(t) = self.config.outfile_check_timer {
            cmd.push_arg("--outfile-check-timer")
                .push_arg(t.to_string());
        }
    }

    fn push_potfile_args(
        &self,
        cmd: &mut ToolCommand,
    ) {
        if self.config.potfile_disable.is_enabled() {
            cmd.push_arg("--potfile-disable");
        }
        if let Some(ref p) = self.config.potfile_path {
            cmd.push_arg("--potfile-path").push_arg(p);
        }
    }

    fn push_session_args(
        &self,
        cmd: &mut ToolCommand,
    ) {
        if let Some(ref s) = self.config.session {
            cmd.push_arg("--session").push_arg(s);
        }
        if self.config.restore.is_enabled() {
            cmd.push_arg("--restore");
        }
        if self.config.restore_disable.is_enabled() {
            cmd.push_arg("--restore-disable");
        }
        if let Some(ref p) = self.config.restore_file_path {
            cmd.push_arg("--restore-file-path").push_arg(p);
        }
    }

    fn push_increment_args(
        &self,
        cmd: &mut ToolCommand,
    ) {
        if self.config.increment.is_enabled() {
            cmd.push_arg("-i");
        }
        if let Some(min) = self.config.increment_min {
            cmd.push_arg("--increment-min").push_arg(min.to_string());
        }
        if let Some(max) = self.config.increment_max {
            cmd.push_arg("--increment-max").push_arg(max.to_string());
        }
    }

    fn push_charset_args(
        &self,
        cmd: &mut ToolCommand,
    ) {
        if let Some(ref c) = self.config.custom_charset1 {
            cmd.push_arg("-1").push_arg(c);
        }
        if let Some(ref c) = self.config.custom_charset2 {
            cmd.push_arg("-2").push_arg(c);
        }
        if let Some(ref c) = self.config.custom_charset3 {
            cmd.push_arg("-3").push_arg(c);
        }
        if let Some(ref c) = self.config.custom_charset4 {
            cmd.push_arg("-4").push_arg(c);
        }
    }

    fn push_limit_args(
        &self,
        cmd: &mut ToolCommand,
    ) {
        if let Some(s) = self.config.skip {
            cmd.push_arg("-s").push_arg(s.to_string());
        }
        if let Some(l) = self.config.limit {
            cmd.push_arg("-l").push_arg(l.to_string());
        }
        if self.config.keyspace.is_enabled() {
            cmd.push_arg("--keyspace");
        }
        if let Some(r) = self.config.runtime {
            cmd.push_arg("--runtime").push_arg(r.to_string());
        }
    }

    fn push_markov_args(
        &self,
        cmd: &mut ToolCommand,
    ) {
        if self.config.markov_disable.is_enabled() {
            cmd.push_arg("--markov-disable");
        }
        if self.config.markov_classic.is_enabled() {
            cmd.push_arg("--markov-classic");
        }
        if self.config.markov_inverse.is_enabled() {
            cmd.push_arg("--markov-inverse");
        }
        if let Some(t) = self.config.markov_threshold {
            cmd.push_arg("--markov-threshold").push_arg(t.to_string());
        }
        if let Some(ref p) = self.config.markov_hcstat2 {
            cmd.push_arg("--markov-hcstat2").push_arg(p);
        }
    }

    fn push_status_args(
        &self,
        cmd: &mut ToolCommand,
    ) {
        if self.config.status.is_enabled() {
            cmd.push_arg("--status");
        }
        if self.config.status_json.is_enabled() {
            cmd.push_arg("--status-json");
        }
        if let Some(t) = self.config.status_timer {
            cmd.push_arg("--status-timer").push_arg(t.to_string());
        }
        if let Some(t) = self.config.stdin_timeout_abort {
            cmd.push_arg("--stdin-timeout-abort")
                .push_arg(t.to_string());
        }
        if self.config.machine_readable.is_enabled() {
            cmd.push_arg("--machine-readable");
        }
        if self.config.quiet.is_enabled() {
            cmd.push_arg("--quiet");
        }
        if self.config.force.is_enabled() {
            cmd.push_arg("--force");
        }
        if self.config.loopback.is_enabled() {
            cmd.push_arg("--loopback");
        }
        if self.config.slow_candidates.is_enabled() {
            cmd.push_arg("-S");
        }
    }

    fn push_debug_args(
        &self,
        cmd: &mut ToolCommand,
    ) {
        if self.config.debug_mode != DebugMode::Off {
            cmd.push_arg("--debug-mode")
                .push_arg((self.config.debug_mode as u32).to_string());
        }
        if let Some(ref f) = self.config.debug_file {
            cmd.push_arg("--debug-file").push_arg(f);
        }
    }

    fn push_rule_args(
        &self,
        cmd: &mut ToolCommand,
    ) {
        if let Some(ref r) = self.config.rules_file {
            cmd.push_arg("-r").push_arg(r);
        }
        if let Some(ref r) = self.config.rules_left {
            cmd.push_arg("-j").push_arg(r);
        }
        if let Some(ref r) = self.config.rules_right {
            cmd.push_arg("-k").push_arg(r);
        }
    }

    fn push_misc_args(
        &self,
        cmd: &mut ToolCommand,
    ) {
        if self.config.username.is_enabled() {
            cmd.push_arg("--username");
        }
        if self.config.remove.is_enabled() {
            cmd.push_arg("--remove");
        }
        if let Some(t) = self.config.remove_timer {
            cmd.push_arg("--remove-timer").push_arg(t.to_string());
        }
        if self.config.keep_guessing.is_enabled() {
            cmd.push_arg("--keep-guessing");
        }
        if let Some(s) = self.config.separator {
            cmd.push_arg("--separator").push_arg(s.to_string());
        }
        if self.config.hex_salt.is_enabled() {
            cmd.push_arg("--hex-salt");
        }
        if self.config.hex_wordlist.is_enabled() {
            cmd.push_arg("--hex-wordlist");
        }
        if self.config.hex_charset.is_enabled() {
            cmd.push_arg("--hex-charset");
        }
        if let Some(ref e) = self.config.encoding_from {
            cmd.push_arg("--encoding-from").push_arg(e);
        }
        if let Some(ref e) = self.config.encoding_to {
            cmd.push_arg("--encoding-to").push_arg(e);
        }
        if self.config.wordlist_autohex_disable.is_enabled() {
            cmd.push_arg("--wordlist-autohex-disable");
        }
    }

    fn push_brain_args(
        &self,
        cmd: &mut ToolCommand,
    ) {
        if self.config.brain_server.is_enabled() {
            cmd.push_arg("--brain-server");
        }
        if let Some(t) = self.config.brain_server_timer {
            cmd.push_arg("--brain-server-timer").push_arg(t.to_string());
        }
        if self.config.brain_client.is_enabled() {
            cmd.push_arg("--brain-client");
        }
        if let Some(f) = self.config.brain_client_features {
            cmd.push_arg("--brain-client-features")
                .push_arg(f.to_string());
        }
        if let Some(ref h) = self.config.brain_host {
            cmd.push_arg("--brain-host").push_arg(h);
        }
        if let Some(p) = self.config.brain_port {
            cmd.push_arg("--brain-port").push_arg(p.to_string());
        }
        if let Some(ref p) = self.config.brain_password {
            cmd.push_arg("--brain-password").push_arg(p);
        }
        if let Some(ref s) = self.config.brain_session {
            cmd.push_arg("--brain-session").push_arg(s);
        }
        if let Some(ref w) = self.config.brain_session_whitelist {
            cmd.push_arg("--brain-session-whitelist").push_arg(w);
        }
    }

    fn push_attack_source_args(
        &self,
        cmd: &mut ToolCommand,
    ) {
        match self.config.attack_mode {
            AttackMode::Dictionary | AttackMode::Association => {
                if let Some(ref w) = self.config.wordlist {
                    cmd.push_arg(w);
                }
            }
            AttackMode::Combinator => {
                if let Some(ref w) = self.config.wordlist {
                    cmd.push_arg(w);
                }
                if let Some(ref w2) = self.config.wordlist2 {
                    cmd.push_arg(w2);
                }
            }
            AttackMode::BruteForce => {
                if let Some(ref m) = self.config.mask {
                    cmd.push_arg(m);
                }
            }
            AttackMode::HybridDictMask => {
                if let Some(ref w) = self.config.wordlist {
                    cmd.push_arg(w);
                }
                if let Some(ref m) = self.config.mask {
                    cmd.push_arg(m);
                }
            }
            AttackMode::HybridMaskDict => {
                if let Some(ref m) = self.config.mask {
                    cmd.push_arg(m);
                }
                if let Some(ref w) = self.config.wordlist {
                    cmd.push_arg(w);
                }
            }
        }
    }

    /// 执行破解 - 使用完整配置
    ///
    /// # Errors
    ///
    /// - 当创建临时工作目录或写入哈希文件失败时返回错误。
    /// - 当外部工具 `hashcat` 执行失败或输出解析失败时返回错误。
    pub fn crack_with_config(
        &self,
        hashes: &[String],
        hash_mode: u32,
    ) -> Result<Vec<CrackResult>> {
        if hashes.is_empty() {
            return Ok(Vec::new());
        }

        fs::create_dir_all(&self.config.work_dir)?;
        let hash_file = self.config.work_dir.join("hashes.txt");
        fs::write(&hash_file, hashes.join("\n"))?;

        let output_file = self.config.work_dir.join("cracked.txt");
        let _ = fs::remove_file(&output_file);

        let mut config = self.config.clone();
        config.hash_type = Some(hash_mode);
        config.outfile = Some(output_file.clone());

        let hc = Self::new(config).with_resource_limits(self.resources.clone());
        let cmd = hc.build_command(&hash_file);

        log::info!("执行hashcat命令: {cmd:?}");
        let start = std::time::Instant::now();
        let output = cmd.run().context("执行 hashcat 失败")?;
        let elapsed = start.elapsed().as_secs_f64();

        let mut results: Vec<CrackResult> = hashes
            .iter()
            .map(|h| CrackResult {
                hash: h.clone(),
                plaintext: None,
                hash_type: hash_mode,
                success: false,
                error: None,
                time_elapsed: Some(elapsed),
            })
            .collect();

        // 读取结果
        if output_file.exists() {
            if let Ok(content) = fs::read_to_string(&output_file) {
                for line in content.lines() {
                    if let Some((hash, plain)) = line.split_once(':') {
                        for r in &mut results {
                            if r.hash.eq_ignore_ascii_case(hash) && r.plaintext.is_none() {
                                r.plaintext = Some(plain.to_string());
                                r.success = true;
                            }
                        }
                    }
                }
            }
        }

        if !output.status.success() && results.iter().all(|r| !r.success) {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if !stderr.is_empty() {
                for r in &mut results {
                    r.error = Some(stderr.trim().to_string());
                }
            }
        }

        Ok(results)
    }

    /// 获取设备信息
    ///
    /// # Errors
    ///
    /// 当外部工具 `hashcat` 执行失败或输出解析失败时返回错误。
    pub fn list_devices(&self) -> Result<Vec<DeviceInfo>> {
        let tool_limits = self.resources.external_tools.for_tool("hashcat");
        let output = {
            let mut cmd = ToolCommand::new(self.config.exe_path.clone());
            cmd.apply_limits(&tool_limits).arg("-I");
            cmd.run().context("列出 hashcat 设备失败")?
        };

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut devices = Vec::new();
        let mut current_id = 0u32;

        for line in stdout.lines() {
            if line.contains("Backend Device ID") {
                if let Some(id) = line.split('#').nth(1).and_then(|s| s.trim().parse().ok()) {
                    current_id = id;
                }
            } else if line.contains("Name") && line.contains("..") {
                let name = line.split("..").last().unwrap_or("").trim().to_string();
                devices.push(DeviceInfo {
                    id: current_id,
                    name,
                    device_type: "GPU".to_string(),
                    memory: None,
                });
            }
        }

        Ok(devices)
    }

    /// 列出支持的哈希类型
    ///
    /// # Errors
    ///
    /// 当外部工具 `hashcat` 执行失败或输出解析失败时返回错误。
    pub fn list_hash_types(&self) -> Result<Vec<HashTypeInfo>> {
        let tool_limits = self.resources.external_tools.for_tool("hashcat");
        let output = {
            let mut cmd = ToolCommand::new(self.config.exe_path.clone());
            cmd.apply_limits(&tool_limits).arg("--help");
            cmd.run().context("获取 hashcat 支持的哈希类型失败")?
        };

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut types = Vec::new();
        let mut in_hash_section = false;

        for line in stdout.lines() {
            if line.contains("Hash modes") {
                in_hash_section = true;
                continue;
            }
            if in_hash_section && line.trim().is_empty() {
                break;
            }
            if in_hash_section {
                let parts: Vec<&str> = line.split('|').collect();
                if parts.len() >= 3 {
                    if let Ok(mode) = parts[0].trim().parse() {
                        types.push(HashTypeInfo {
                            mode,
                            name: parts[1].trim().to_string(),
                            category: parts[2].trim().to_string(),
                        });
                    }
                }
            }
        }

        Ok(types)
    }

    /// 运行基准测试
    ///
    /// # Errors
    ///
    /// 当外部工具 `hashcat` 执行失败或输出解析失败时返回错误。
    pub fn benchmark(
        &self,
        hash_mode: Option<u32>,
    ) -> Result<Vec<BenchmarkResult>> {
        let mut cmd = ToolCommand::new(self.config.exe_path.clone());
        let tool_limits = self.resources.external_tools.for_tool("hashcat");
        cmd.apply_limits(&tool_limits);
        cmd.push_arg("-b");

        if let Some(mode) = hash_mode {
            cmd.push_arg("-m").push_arg(mode.to_string());
        }

        let output = cmd.run().context("执行 hashcat 基准测试失败")?;
        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut results = Vec::new();

        for line in stdout.lines() {
            if line.contains("H/s") {
                let parts: Vec<&str> = line.split(':').collect();
                if parts.len() >= 2 {
                    results.push(BenchmarkResult {
                        hash_mode: 0,
                        hash_name: parts[0].trim().to_string(),
                        speed: parts[1].trim().to_string(),
                    });
                }
            }
        }

        Ok(results)
    }

    /// 显示已破解的哈希 (从 potfile)
    ///
    /// # Errors
    ///
    /// - 当写入临时哈希文件失败时返回错误。
    /// - 当外部工具 `hashcat` 执行失败或输出解析失败时返回错误。
    pub fn show_cracked(
        &self,
        hashes: &[String],
        hash_mode: u32,
    ) -> Result<HashMap<String, String>> {
        fs::create_dir_all(&self.config.work_dir)?;

        let hash_file = self.config.work_dir.join("show_hashes.txt");
        fs::write(&hash_file, hashes.join("\n"))?;

        let potfile = self.config.work_dir.join("hashcat.potfile");

        let tool_limits = self.resources.external_tools.for_tool("hashcat");
        let output = {
            let mut cmd = ToolCommand::new(self.config.exe_path.clone());
            cmd.apply_limits(&tool_limits)
                .arg("-m")
                .arg(hash_mode.to_string())
                .arg("--show")
                .arg("--potfile-path")
                .arg(&potfile)
                .arg(&hash_file);
            cmd.run().context("读取 hashcat 破解结果失败")?
        };

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut cracked = HashMap::new();

        for line in stdout.lines() {
            if let Some((hash, plain)) = line.split_once(':') {
                cracked.insert(hash.to_string(), plain.to_string());
            }
        }

        Ok(cracked)
    }

    /// 字典攻击
    ///
    /// # Errors
    ///
    /// 当外部工具 `hashcat` 执行失败或输出解析失败时返回错误。
    pub fn crack(
        &self,
        hash: &str,
        hash_mode: u32,
    ) -> Result<CrackResult> {
        self.crack_with_options(hash, hash_mode, AttackMode::Dictionary, None, None)
    }

    /// 批量字典攻击
    ///
    /// # Errors
    ///
    /// 当外部工具 `hashcat` 执行失败或输出解析失败时返回错误。
    pub fn crack_batch(
        &self,
        hashes: &[String],
        hash_mode: u32,
    ) -> Result<Vec<CrackResult>> {
        self.crack_batch_with_options(hashes, hash_mode, AttackMode::Dictionary, None, None)
    }

    /// 掩码攻击
    ///
    /// # Errors
    ///
    /// 当外部工具 `hashcat` 执行失败或输出解析失败时返回错误。
    pub fn crack_mask(
        &self,
        hash: &str,
        hash_mode: u32,
        mask: &str,
    ) -> Result<CrackResult> {
        self.crack_with_options(hash, hash_mode, AttackMode::BruteForce, Some(mask), None)
    }

    /// 组合攻击 (两个字典组合)
    ///
    /// # Errors
    ///
    /// 当外部工具 `hashcat` 执行失败或输出解析失败时返回错误。
    pub fn crack_combinator(
        &self,
        hash: &str,
        hash_mode: u32,
        dict2: &str,
    ) -> Result<CrackResult> {
        self.crack_with_options(hash, hash_mode, AttackMode::Combinator, None, Some(dict2))
    }

    /// 混合攻击: 字典+掩码
    ///
    /// # Errors
    ///
    /// 当外部工具 `hashcat` 执行失败或输出解析失败时返回错误。
    pub fn crack_hybrid_dict_mask(
        &self,
        hash: &str,
        hash_mode: u32,
        mask: &str,
    ) -> Result<CrackResult> {
        self.crack_with_options(
            hash,
            hash_mode,
            AttackMode::HybridDictMask,
            Some(mask),
            None,
        )
    }

    /// 混合攻击: 掩码+字典
    ///
    /// # Errors
    ///
    /// 当外部工具 `hashcat` 执行失败或输出解析失败时返回错误。
    pub fn crack_hybrid_mask_dict(
        &self,
        hash: &str,
        hash_mode: u32,
        mask: &str,
    ) -> Result<CrackResult> {
        self.crack_with_options(
            hash,
            hash_mode,
            AttackMode::HybridMaskDict,
            Some(mask),
            None,
        )
    }

    /// 带规则的字典攻击
    ///
    /// # Errors
    ///
    /// 当外部工具 `hashcat` 执行失败或输出解析失败时返回错误。
    pub fn crack_with_rules(
        &self,
        hash: &str,
        hash_mode: u32,
        rules_file: &str,
    ) -> Result<CrackResult> {
        let mut config = self.config.clone();
        config.rules_file = Some(PathBuf::from(rules_file));
        let hc = Self::new(config).with_resource_limits(self.resources.clone());
        hc.crack(hash, hash_mode)
    }

    /// 通用攻击接口
    fn crack_with_options(
        &self,
        hash: &str,
        hash_mode: u32,
        attack_mode: AttackMode,
        mask_or_extra: Option<&str>,
        dict2: Option<&str>,
    ) -> Result<CrackResult> {
        let results = self.crack_batch_with_options(
            &[hash.to_string()],
            hash_mode,
            attack_mode,
            mask_or_extra,
            dict2,
        )?;

        Ok(results.into_iter().next().unwrap_or_else(|| CrackResult {
            hash: hash.to_string(),
            plaintext: None,
            hash_type: hash_mode,
            success: false,
            error: Some("未返回任何结果".to_string()),
            time_elapsed: None,
        }))
    }

    /// 批量通用攻击
    fn crack_batch_with_options(
        &self,
        hashes: &[String],
        hash_mode: u32,
        attack_mode: AttackMode,
        mask_or_extra: Option<&str>,
        dict2: Option<&str>,
    ) -> Result<Vec<CrackResult>> {
        if hashes.is_empty() {
            return Ok(Vec::new());
        }

        fs::create_dir_all(&self.config.work_dir)?;

        let hash_file = self.config.work_dir.join("hashes.txt");
        fs::write(&hash_file, hashes.join("\n"))?;

        let output_file = self.config.work_dir.join("cracked.txt");
        let potfile = self.config.work_dir.join("hashcat.potfile");
        let _ = fs::remove_file(&output_file);

        let mut cmd = ToolCommand::new(self.config.exe_path.clone());
        let tool_limits = self.resources.external_tools.for_tool("hashcat");
        cmd.apply_limits(&tool_limits)
            .set_current_dir(self.config.work_dir.clone())
            .push_arg("-m")
            .push_arg(hash_mode.to_string())
            .push_arg("-a")
            .push_arg((attack_mode as u32).to_string())
            .push_arg("--potfile-path")
            .push_arg(&potfile)
            .push_arg("-o")
            .push_arg(&output_file)
            .push_arg("--outfile-format")
            .push_arg("2")
            .push_arg("-w")
            .push_arg(self.config.workload_profile.to_string())
            .push_arg("--quiet");

        if self.config.optimized_kernel.is_enabled() {
            cmd.push_arg("-O");
        }

        if let Some(ref d) = self.config.opencl_device_types {
            cmd.push_arg("-D").push_arg(d);
        }

        cmd.push_arg(&hash_file);

        // 根据攻击模式添加参数
        match attack_mode {
            AttackMode::Dictionary | AttackMode::Association => {
                if let Some(ref w) = self.config.wordlist {
                    cmd.push_arg(w);
                }
                if let Some(ref rules) = self.config.rules_file {
                    cmd.push_arg("-r").push_arg(rules);
                }
            }
            AttackMode::BruteForce => {
                if let Some(mask) = mask_or_extra {
                    cmd.push_arg(mask);
                }
            }
            AttackMode::Combinator => {
                if let Some(ref w) = self.config.wordlist {
                    cmd.push_arg(w);
                }
                if let Some(d2) = dict2 {
                    cmd.push_arg(d2);
                }
            }
            AttackMode::HybridDictMask => {
                if let Some(ref w) = self.config.wordlist {
                    cmd.push_arg(w);
                }
                if let Some(mask) = mask_or_extra {
                    cmd.push_arg(mask);
                }
            }
            AttackMode::HybridMaskDict => {
                if let Some(mask) = mask_or_extra {
                    cmd.push_arg(mask);
                }
                if let Some(ref w) = self.config.wordlist {
                    cmd.push_arg(w);
                }
            }
        }

        let start = std::time::Instant::now();
        let output = cmd.run().context("执行 hashcat 失败")?;
        let elapsed = start.elapsed().as_secs_f64();

        let mut results = Self::init_results(hashes, hash_mode, elapsed);
        Self::read_cracked_files(&mut results, &output_file, &potfile);
        Self::apply_stderr_if_all_failed(&mut results, &output);

        Ok(results)
    }

    /// 自动检测哈希类型并破解
    ///
    /// # Errors
    ///
    /// 当外部工具 `hashcat` 执行失败或输出解析失败时返回错误。
    pub fn crack_auto(
        &self,
        hash: &str,
    ) -> Result<CrackResult> {
        let modes = detect_hash_mode(hash);

        for mode in modes {
            let result = self.crack(hash, mode)?;
            if result.success {
                return Ok(result);
            }
        }

        Ok(CrackResult {
            hash: hash.to_string(),
            plaintext: None,
            hash_type: 0,
            success: false,
            error: Some("未能使用任何检测到的模式完成破解".to_string()),
            time_elapsed: None,
        })
    }

    /// 增量攻击 (纯暴力，指定长度范围)
    ///
    /// # Errors
    ///
    /// 当外部工具 `hashcat` 执行失败或输出解析失败时返回错误。
    pub fn crack_incremental(
        &self,
        hash: &str,
        hash_mode: u32,
        min_len: u8,
        max_len: u8,
        charset: &str,
    ) -> Result<CrackResult> {
        let mask = format!("{}?{}", charset, charset.repeat((max_len - 1) as usize));

        fs::create_dir_all(&self.config.work_dir)?;
        let hash_file = self.config.work_dir.join("hash_inc.txt");
        fs::write(&hash_file, hash)?;

        let output_file = self.config.work_dir.join("cracked_inc.txt");
        let potfile = self.config.work_dir.join("hashcat_inc.potfile");
        let _ = fs::remove_file(&output_file);

        let tool_limits = self.resources.external_tools.for_tool("hashcat");
        let _ = {
            let mut cmd = ToolCommand::new(self.config.exe_path.clone());
            cmd.apply_limits(&tool_limits)
                .current_dir(self.config.work_dir.clone())
                .arg("-m")
                .arg(hash_mode.to_string())
                .arg("-a")
                .arg("3")
                .arg("--increment")
                .arg("--increment-min")
                .arg(min_len.to_string())
                .arg("--increment-max")
                .arg(max_len.to_string())
                .arg("--potfile-path")
                .arg(&potfile)
                .arg("-o")
                .arg(&output_file)
                .arg("--outfile-format")
                .arg("2")
                .arg("--quiet")
                .arg(&hash_file)
                .arg(&mask)
                .stdout_max_bytes(0)
                .stderr_max_bytes(0);
            cmd.run().context("执行 hashcat 增量攻击失败")?
        };

        let mut result = CrackResult {
            hash: hash.to_string(),
            plaintext: None,
            hash_type: hash_mode,
            success: false,
            error: None,
            time_elapsed: None,
        };

        if output_file.exists() {
            if let Ok(content) = fs::read_to_string(&output_file) {
                if let Some(line) = content.lines().next() {
                    if let Some((_, plain)) = line.split_once(':') {
                        result.plaintext = Some(plain.to_string());
                        result.success = true;
                    }
                }
            }
        }

        Ok(result)
    }

    /// 清理工作目录
    ///
    /// # Errors
    ///
    /// 当删除工作目录失败时返回错误。
    pub fn cleanup(&self) -> Result<()> {
        if self.config.work_dir.exists() {
            fs::remove_dir_all(&self.config.work_dir)?;
        }
        Ok(())
    }

    fn init_results(
        hashes: &[String],
        hash_mode: u32,
        elapsed: f64,
    ) -> Vec<CrackResult> {
        hashes
            .iter()
            .map(|h| CrackResult {
                hash: h.clone(),
                plaintext: None,
                hash_type: hash_mode,
                success: false,
                error: None,
                time_elapsed: Some(elapsed),
            })
            .collect()
    }

    fn read_cracked_files(
        results: &mut [CrackResult],
        output_file: &PathBuf,
        potfile: &PathBuf,
    ) {
        for file in [output_file, potfile] {
            if let Ok(content) = fs::read_to_string(file) {
                Self::read_cracked_lines(results, &content);
            }
        }
    }

    fn read_cracked_lines(
        results: &mut [CrackResult],
        content: &str,
    ) {
        for line in content.lines() {
            let Some((hash, plain)) = line.split_once(':') else {
                continue;
            };
            for r in results.iter_mut() {
                if r.hash.eq_ignore_ascii_case(hash) && r.plaintext.is_none() {
                    r.plaintext = Some(plain.to_string());
                    r.success = true;
                }
            }
        }
    }

    fn apply_stderr_if_all_failed(
        results: &mut [CrackResult],
        output: &tool_runner::RunOutput,
    ) {
        if output.status.success() || results.iter().any(|r| r.success) {
            return;
        }
        let stderr = String::from_utf8_lossy(&output.stderr);
        if stderr.is_empty() {
            return;
        }
        let err = stderr.trim().to_string();
        for r in results.iter_mut() {
            r.error = Some(err.clone());
        }
    }
}

/// 根据哈希长度和格式检测可能的 hashcat mode
#[must_use]
pub fn detect_hash_mode(hash: &str) -> Vec<u32> {
    let hash = hash.trim();
    let len = hash.len();

    let is_hex = hash.chars().all(|c| c.is_ascii_hexdigit());

    if !is_hex {
        if hash.starts_with("$2") {
            return vec![3200];
        }
        if hash.starts_with("$6$") {
            return vec![1800];
        }
        if hash.starts_with("$5$") {
            return vec![7400];
        }
        if hash.starts_with("$1$") {
            return vec![500];
        }
        if hash.starts_with("$apr1$") {
            return vec![1600];
        }
        if hash.starts_with("$P$") || hash.starts_with("$H$") {
            return vec![400];
        }
        if hash.starts_with("sha256$") {
            return vec![20200];
        }
        if hash.starts_with("sha512$") {
            return vec![20300];
        }
        if hash.contains('$') && hash.contains(':') {
            return vec![1500];
        } // DES
        return vec![];
    }

    match len {
        32 => vec![0, 1000, 2600, 3000, 4300, 900, 4400],
        40 => vec![100, 300, 4500, 4600, 4700],
        56 => vec![1300], // SHA224
        64 => vec![1400, 10800, 1700],
        96 => vec![10800], // SHA384
        128 => vec![1700, 10800, 6100],
        _ => vec![],
    }
}

/// 常用 hashcat 模式
pub mod modes {
    // 原始哈希
    pub const MD5: u32 = 0;
    pub const SHA1: u32 = 100;
    pub const SHA224: u32 = 1300;
    pub const SHA256: u32 = 1400;
    pub const SHA384: u32 = 10800;
    pub const SHA512: u32 = 1700;
    pub const SHA3_256: u32 = 17400;
    pub const SHA3_512: u32 = 17600;
    pub const MD4: u32 = 900;
    pub const RIPEMD160: u32 = 6000;
    pub const WHIRLPOOL: u32 = 6100;

    // 组合哈希
    pub const MD5_MD5: u32 = 2600;
    pub const SHA1_SHA1: u32 = 4500;
    pub const MD5_SHA1: u32 = 4400;

    // Windows
    pub const NTLM: u32 = 1000;
    pub const LM: u32 = 3000;
    pub const MSCACHE: u32 = 1100;
    pub const MSCACHE2: u32 = 2100;

    // Unix
    pub const MD5CRYPT: u32 = 500;
    pub const SHA256CRYPT: u32 = 7400;
    pub const SHA512CRYPT: u32 = 1800;
    pub const BCRYPT: u32 = 3200;
    pub const DESCRYPT: u32 = 1500;

    // 数据库
    pub const MYSQL323: u32 = 200;
    pub const MYSQL41: u32 = 300;
    pub const MSSQL2000: u32 = 131;
    pub const MSSQL2005: u32 = 132;
    pub const MSSQL2012: u32 = 1731;
    pub const ORACLE11: u32 = 112;
    pub const POSTGRES: u32 = 12;

    // Web
    pub const PHPASS: u32 = 400;
    pub const DJANGO_SHA256: u32 = 20200;
    pub const DJANGO_SHA512: u32 = 20300;
    pub const WORDPRESS: u32 = 400;
    pub const DRUPAL7: u32 = 7900;

    // 网络
    pub const WPA: u32 = 22000;
    pub const NETNTLMV1: u32 = 5500;
    pub const NETNTLMV2: u32 = 5600;

    // 文档
    pub const PDF14: u32 = 10500;
    pub const PDF17: u32 = 10600;
    pub const OFFICE2007: u32 = 9400;
    pub const OFFICE2010: u32 = 9500;
    pub const OFFICE2013: u32 = 9600;

    // 压缩包
    pub const ZIP: u32 = 13600;
    pub const RAR3: u32 = 12500;
    pub const RAR5: u32 = 13000;
    pub const SEVENZIP: u32 = 11600;

    // 加密货币
    pub const BITCOIN: u32 = 11300;
    pub const ETHEREUM: u32 = 15700;
}

/// 常用掩码字符集
pub mod charsets {
    pub const DIGITS: &str = "?d"; // 0-9
    pub const LOWER: &str = "?l"; // a-z
    pub const UPPER: &str = "?u"; // A-Z
    pub const SPECIAL: &str = "?s"; // 特殊字符
    pub const ALL: &str = "?a"; // 所有可打印
    pub const HEX_LOWER: &str = "?h"; // 0-9a-f
    pub const HEX_UPPER: &str = "?H"; // 0-9A-F
}

/// 常用规则文件 (相对于 hashcat 目录)
pub mod rules {
    pub const BEST64: &str = "rules/best64.rule";
    pub const ROCKYOU: &str = "rules/rockyou-30000.rule";
    pub const D3AD0NE: &str = "rules/d3ad0ne.rule";
    pub const DIVE: &str = "rules/dive.rule";
    pub const GENERATED: &str = "rules/generated.rule";
    pub const GENERATED2: &str = "rules/generated2.rule";
    pub const LEETSPEAK: &str = "rules/leetspeak.rule";
    pub const TOGGLES: &str = "rules/toggles1.rule";
    pub const COMBINATOR: &str = "rules/combinator.rule";
}

// 便捷函数
///
/// # Errors
///
/// 当外部工具 `hashcat` 执行失败或输出解析失败时返回错误。
pub fn crack_md5(hash: &str) -> Result<Option<String>> {
    Hashcat::default()
        .crack(hash, modes::MD5)
        .map(|r| r.plaintext)
}

/// # Errors
///
/// 当外部工具 `hashcat` 执行失败或输出解析失败时返回错误。
pub fn crack_sha1(hash: &str) -> Result<Option<String>> {
    Hashcat::default()
        .crack(hash, modes::SHA1)
        .map(|r| r.plaintext)
}

/// # Errors
///
/// 当外部工具 `hashcat` 执行失败或输出解析失败时返回错误。
pub fn crack_sha256(hash: &str) -> Result<Option<String>> {
    Hashcat::default()
        .crack(hash, modes::SHA256)
        .map(|r| r.plaintext)
}

/// # Errors
///
/// 当外部工具 `hashcat` 执行失败或输出解析失败时返回错误。
pub fn crack_ntlm(hash: &str) -> Result<Option<String>> {
    Hashcat::default()
        .crack(hash, modes::NTLM)
        .map(|r| r.plaintext)
}

/// # Errors
///
/// 当外部工具 `hashcat` 执行失败或输出解析失败时返回错误。
pub fn crack_auto(hash: &str) -> Result<Option<String>> {
    Hashcat::default().crack_auto(hash).map(|r| r.plaintext)
}

/// 快速掩码破解 (如6位数字)
///
/// # Errors
///
/// 当外部工具 `hashcat` 执行失败或输出解析失败时返回错误。
pub fn crack_mask(
    hash: &str,
    hash_mode: u32,
    mask: &str,
) -> Result<Option<String>> {
    Hashcat::default()
        .crack_mask(hash, hash_mode, mask)
        .map(|r| r.plaintext)
}

/// 带规则破解
///
/// # Errors
///
/// 当外部工具 `hashcat` 执行失败或输出解析失败时返回错误。
pub fn crack_with_rules(
    hash: &str,
    hash_mode: u32,
    rules_file: &str,
) -> Result<Option<String>> {
    Hashcat::default()
        .crack_with_rules(hash, hash_mode, rules_file)
        .map(|r| r.plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_hash_mode() {
        assert!(detect_hash_mode("5d41402abc4b2a76b9719d911017c592").contains(&0));
        assert!(detect_hash_mode("aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d").contains(&100));
        assert!(detect_hash_mode("$2a$10$abcdefghijklmnopqrstuv").contains(&3200));
    }

    #[test]
    fn test_hashcat_available() {
        let hc = Hashcat::default();
        if hc.is_available() {
            println!("Hashcat version: {:?}", hc.version());
        }
    }

    #[test]
    fn test_read_cracked_lines_populates_results() {
        let hashes = vec!["ABCDEF".to_string(), "001122".to_string()];
        let mut results = Hashcat::init_results(&hashes, modes::MD5, 0.1);

        Hashcat::read_cracked_lines(&mut results, "abcdef:plain1\n001122:plain2\n");

        let a = results.iter().find(|r| r.hash == "ABCDEF").unwrap();
        assert_eq!(a.plaintext.as_deref(), Some("plain1"));
        assert!(a.success);

        let b = results.iter().find(|r| r.hash == "001122").unwrap();
        assert_eq!(b.plaintext.as_deref(), Some("plain2"));
        assert!(b.success);
    }
}
