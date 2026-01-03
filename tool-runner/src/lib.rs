#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

use anyhow::{anyhow, Context, Result};
use std::ffi::{OsStr, OsString};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};
use zmctf_constraints::ToolLimits;

#[derive(Debug, Clone)]
pub struct RunConfig {
    pub current_dir: Option<PathBuf>,
    pub timeout: Option<Duration>,
    pub stdout_max_bytes: usize,
    pub stderr_max_bytes: usize,
    pub env: Vec<(OsString, OsString)>,
}

impl Default for RunConfig {
    fn default() -> Self {
        let limits = ToolLimits::default();
        Self {
            current_dir: None,
            timeout: if limits.timeout_seconds == 0 {
                None
            } else {
                Some(Duration::from_secs(limits.timeout_seconds))
            },
            stdout_max_bytes: usize::try_from(limits.stdout_max_bytes).unwrap_or(usize::MAX),
            stderr_max_bytes: usize::try_from(limits.stderr_max_bytes).unwrap_or(usize::MAX),
            env: Vec::new(),
        }
    }
}

#[derive(Debug)]
pub struct RunOutput {
    pub status: ExitStatus,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub stdout_truncated: bool,
    pub stderr_truncated: bool,
    /// stdout 读取错误（若有）。
    pub stdout_read_error: Option<String>,
    /// stderr 读取错误（若有）。
    pub stderr_read_error: Option<String>,
    pub timed_out: bool,
    /// 实际运行耗时（含等待退出与输出读取）。
    pub elapsed: Duration,
    /// 运行时使用的 stdout 上限（用于诊断）。
    pub stdout_max_bytes: usize,
    /// 运行时使用的 stderr 上限（用于诊断）。
    pub stderr_max_bytes: usize,
    /// 运行时使用的 timeout（用于诊断）。
    pub timeout: Option<Duration>,
}

impl RunOutput {
    #[must_use]
    pub fn stdout_lossy(&self) -> String {
        String::from_utf8_lossy(&self.stdout).to_string()
    }

    #[must_use]
    pub fn stderr_lossy(&self) -> String {
        String::from_utf8_lossy(&self.stderr).to_string()
    }
}

#[derive(Debug, Clone)]
pub struct ToolCommand {
    program: PathBuf,
    args: Vec<OsString>,
    config: RunConfig,
}

impl ToolCommand {
    pub fn new(program: impl Into<PathBuf>) -> Self {
        Self {
            program: program.into(),
            args: Vec::new(),
            config: RunConfig::default(),
        }
    }

    pub fn arg(
        &mut self,
        arg: impl AsRef<OsStr>,
    ) -> &mut Self {
        self.args.push(arg.as_ref().to_owned());
        self
    }

    pub fn push_arg(
        &mut self,
        arg: impl AsRef<OsStr>,
    ) -> &mut Self {
        self.arg(arg)
    }

    pub fn args<I, A>(
        &mut self,
        args: I,
    ) -> &mut Self
    where
        I: IntoIterator<Item = A>,
        A: AsRef<OsStr>,
    {
        self.args
            .extend(args.into_iter().map(|a| a.as_ref().to_owned()));
        self
    }

    pub fn push_args<I, A>(
        &mut self,
        args: I,
    ) -> &mut Self
    where
        I: IntoIterator<Item = A>,
        A: AsRef<OsStr>,
    {
        self.args
            .extend(args.into_iter().map(|a| a.as_ref().to_owned()));
        self
    }

    pub fn current_dir(
        &mut self,
        dir: impl Into<PathBuf>,
    ) -> &mut Self {
        self.config.current_dir = Some(dir.into());
        self
    }

    pub fn set_current_dir(
        &mut self,
        dir: impl Into<PathBuf>,
    ) -> &mut Self {
        self.current_dir(dir)
    }

    pub const fn timeout(
        &mut self,
        timeout: Duration,
    ) -> &mut Self {
        self.config.timeout = Some(timeout);
        self
    }

    pub const fn set_timeout(
        &mut self,
        timeout: Duration,
    ) -> &mut Self {
        self.timeout(timeout)
    }

    /// 从全局约束模型应用 timeout/stdout/stderr 上限。
    pub fn apply_limits(
        &mut self,
        limits: &ToolLimits,
    ) -> &mut Self {
        self.config.timeout = if limits.timeout_seconds == 0 {
            None
        } else {
            Some(Duration::from_secs(limits.timeout_seconds))
        };
        self.config.stdout_max_bytes =
            usize::try_from(limits.stdout_max_bytes).unwrap_or(usize::MAX);
        self.config.stderr_max_bytes =
            usize::try_from(limits.stderr_max_bytes).unwrap_or(usize::MAX);
        self
    }

    pub const fn stdout_max_bytes(
        &mut self,
        bytes: usize,
    ) -> &mut Self {
        self.config.stdout_max_bytes = bytes;
        self
    }

    pub const fn set_stdout_max_bytes(
        &mut self,
        bytes: usize,
    ) -> &mut Self {
        self.stdout_max_bytes(bytes)
    }

    pub const fn stderr_max_bytes(
        &mut self,
        bytes: usize,
    ) -> &mut Self {
        self.config.stderr_max_bytes = bytes;
        self
    }

    pub const fn set_stderr_max_bytes(
        &mut self,
        bytes: usize,
    ) -> &mut Self {
        self.stderr_max_bytes(bytes)
    }

    pub fn env(
        &mut self,
        key: impl Into<OsString>,
        value: impl Into<OsString>,
    ) -> &mut Self {
        self.config.env.push((key.into(), value.into()));
        self
    }

    pub fn set_env(
        &mut self,
        key: impl Into<OsString>,
        value: impl Into<OsString>,
    ) -> &mut Self {
        self.env(key, value)
    }

    /// 执行外部命令并捕获 stdout/stderr。
    ///
    /// # Errors
    ///
    /// 当命令启动失败、等待失败或输出读取线程异常退出时返回错误。
    pub fn run(&self) -> Result<RunOutput> {
        run_tool(&self.program, &self.args, &self.config)
    }
}

/// 解析工具路径：若路径存在则直接返回，否则按 `PATH` 搜索。
///
/// # Errors
///
/// 当工具不存在或 `which` 查询失败时返回错误。
pub fn resolve_program(program: impl AsRef<Path>) -> Result<PathBuf> {
    let program = program.as_ref();
    if program.exists() {
        return Ok(program.to_path_buf());
    }

    if is_path_like(program) {
        return Err(anyhow!("program not found: {}", program.display()));
    }

    resolve_program_from_path(program)
        .with_context(|| format!("program not found: {}", program.display()))
}

fn is_path_like(program: &Path) -> bool {
    program.components().any(|c| {
        matches!(
            c,
            std::path::Component::ParentDir | std::path::Component::CurDir
        )
    }) || program.components().any(|c| {
        matches!(
            c,
            std::path::Component::RootDir | std::path::Component::Prefix(_)
        )
    }) || program
        .as_os_str()
        .to_string_lossy()
        .contains(std::path::MAIN_SEPARATOR)
        || program.as_os_str().to_string_lossy().contains('/')
}

fn resolve_program_from_path(program: &Path) -> Result<PathBuf> {
    let path = std::env::var_os("PATH").ok_or_else(|| anyhow!("PATH is not set"))?;
    let candidates = candidate_program_names(program);

    for dir in std::env::split_paths(&path) {
        for name in &candidates {
            let full = dir.join(name);
            if full.is_file() {
                return Ok(full);
            }
        }
    }

    Err(anyhow!("program not found in PATH"))
}

fn candidate_program_names(program: &Path) -> Vec<OsString> {
    let Some(file_name) = program.file_name() else {
        return Vec::new();
    };

    let mut candidates = vec![file_name.to_os_string()];

    #[cfg(windows)]
    {
        if program.extension().is_none() {
            let pathext = std::env::var_os("PATHEXT")
                .unwrap_or_else(|| OsString::from(".EXE;.CMD;.BAT;.COM"));
            for ext in pathext
                .to_string_lossy()
                .split(';')
                .filter(|s| !s.is_empty())
            {
                candidates.push(OsString::from(format!(
                    "{}{}",
                    file_name.to_string_lossy(),
                    ext
                )));
            }
        }
    }

    candidates
}

/// 运行外部命令并在 `timeout/stdout_max_bytes/stderr_max_bytes` 约束下捕获输出。
///
/// # Errors
///
/// 当命令启动失败、等待失败、stdout/stderr 管道不可用或读取线程异常退出时返回错误。
pub fn run_tool(
    program: &Path,
    args: &[OsString],
    config: &RunConfig,
) -> Result<RunOutput> {
    let start = Instant::now();
    let mut cmd = Command::new(program);
    cmd.args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    if let Some(ref dir) = config.current_dir {
        cmd.current_dir(dir);
    }
    for (k, v) in &config.env {
        cmd.env(k, v);
    }

    log::debug!("执行外部命令: {cmd:?}");

    let mut child = cmd
        .spawn()
        .with_context(|| format!("启动外部命令失败: {}", program.display()))?;

    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| anyhow!("无法捕获 stdout: {}", program.display()))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| anyhow!("无法捕获 stderr: {}", program.display()))?;

    let stdout_max_bytes = config.stdout_max_bytes;
    let stderr_max_bytes = config.stderr_max_bytes;

    let stdout_handle =
        std::thread::spawn(move || read_stream_with_limit(stdout, stdout_max_bytes));
    let stderr_handle =
        std::thread::spawn(move || read_stream_with_limit(stderr, stderr_max_bytes));

    let (status, timed_out) = wait_with_timeout(&mut child, config.timeout)?;

    let stdout_capture = stdout_handle
        .join()
        .map_err(|_| anyhow!("stdout 读取线程异常退出"))?;
    let stderr_capture = stderr_handle
        .join()
        .map_err(|_| anyhow!("stderr 读取线程异常退出"))?;

    Ok(RunOutput {
        status,
        stdout: stdout_capture.buf,
        stderr: stderr_capture.buf,
        stdout_truncated: stdout_capture.truncated,
        stderr_truncated: stderr_capture.truncated,
        stdout_read_error: stdout_capture.error,
        stderr_read_error: stderr_capture.error,
        timed_out,
        elapsed: start.elapsed(),
        stdout_max_bytes,
        stderr_max_bytes,
        timeout: config.timeout,
    })
}

fn wait_with_timeout(
    child: &mut std::process::Child,
    timeout: Option<Duration>,
) -> Result<(ExitStatus, bool)> {
    let Some(timeout) = timeout else {
        let status = child.wait().context("等待外部命令退出失败")?;
        return Ok((status, false));
    };

    let start = Instant::now();
    loop {
        if let Some(status) = child.try_wait().context("轮询外部命令状态失败")? {
            return Ok((status, false));
        }

        if start.elapsed() >= timeout {
            let _ = child.kill();
            let status = child.wait().context("等待被终止的外部命令退出失败")?;
            return Ok((status, true));
        }

        std::thread::sleep(Duration::from_millis(20));
    }
}

#[derive(Debug)]
struct StreamCapture {
    buf: Vec<u8>,
    truncated: bool,
    error: Option<String>,
}

fn read_stream_with_limit<R: Read>(
    mut reader: R,
    max_bytes: usize,
) -> StreamCapture {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 8192];
    let mut truncated = false;
    let mut error = None;

    loop {
        match reader.read(&mut tmp) {
            Ok(0) => break,
            Ok(n) => {
                if buf.len() < max_bytes {
                    let remaining = max_bytes - buf.len();
                    if n <= remaining {
                        buf.extend_from_slice(&tmp[..n]);
                    } else {
                        buf.extend_from_slice(&tmp[..remaining]);
                        truncated = true;
                    }
                } else {
                    truncated = true;
                }
            }
            Err(e) => {
                error = Some(e.to_string());
                break;
            }
        }
    }

    StreamCapture {
        buf,
        truncated,
        error,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{self, Cursor};
    use std::time::Duration;

    #[test]
    fn test_run_captures_stdout() {
        let mut cmd = ToolCommand::new("rustc");
        cmd.arg("--version");

        let output = cmd.run().unwrap();
        assert!(output.status.success());
        assert!(!output.timed_out);
        assert!(output.stdout_lossy().to_lowercase().contains("rustc"));
    }

    #[test]
    fn test_run_truncates_stdout() {
        let mut cmd = ToolCommand::new("rustc");
        cmd.arg("--version");
        cmd.stdout_max_bytes(4);

        let output = cmd.run().unwrap();
        assert!(output.stdout_truncated);
        assert_eq!(output.stdout.len(), 4);
    }

    #[test]
    fn test_run_timeout_sets_flag() {
        #[cfg(windows)]
        {
            let mut cmd = ToolCommand::new("ping");
            cmd.arg("127.0.0.1");
            cmd.arg("-n");
            cmd.arg("6");
            cmd.timeout(Duration::from_millis(200));
            cmd.stdout_max_bytes(0);
            cmd.stderr_max_bytes(0);

            let output = cmd.run().unwrap();
            assert!(output.timed_out);
        }

        #[cfg(not(windows))]
        {
            let mut cmd = ToolCommand::new("sleep");
            cmd.arg("2");
            cmd.timeout(Duration::from_millis(200));
            cmd.stdout_max_bytes(0);
            cmd.stderr_max_bytes(0);

            let output = cmd.run().unwrap();
            assert!(output.timed_out);
        }
    }

    #[test]
    fn test_read_stream_with_limit_marks_truncated_when_max_is_zero() {
        let capture = read_stream_with_limit(Cursor::new(b"hello"), 0);
        assert!(capture.truncated);
        assert!(capture.buf.is_empty());
        assert!(capture.error.is_none());
    }

    #[test]
    fn test_read_stream_with_limit_records_read_error() {
        struct ErrReader {
            calls: usize,
        }

        impl Read for ErrReader {
            fn read(
                &mut self,
                buf: &mut [u8],
            ) -> io::Result<usize> {
                self.calls += 1;
                if self.calls == 1 {
                    let data = b"ok";
                    buf[..data.len()].copy_from_slice(data);
                    Ok(data.len())
                } else {
                    Err(io::Error::other("boom"))
                }
            }
        }

        let capture = read_stream_with_limit(ErrReader { calls: 0 }, 16);
        assert_eq!(capture.buf, b"ok");
        assert!(!capture.truncated);
        assert!(capture.error.is_some());
    }
}
