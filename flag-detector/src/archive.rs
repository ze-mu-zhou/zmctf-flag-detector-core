//! 压缩包分析模块
//!
//! 支持 ZIP/RAR 的递归分析与可选密码爆破。
//!
//! 说明：为了降低依赖复杂度并满足严格的 `clippy::cargo` 检查，`7z/tar` 的内置解析在当前构建中已禁用（会返回可诊断告警）。

use anyhow::Result;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::{Read, Seek, Write};
use std::path::{Component, Path, PathBuf};
use zmctf_constraints::{read_file_with_limit, read_to_end_with_limit, ResourceLimits};

use crate::magic::detect_bytes;

fn disabled_archive_analysis(
    archive_type: &'static str,
    warning: &'static str,
) -> ArchiveAnalysis {
    ArchiveAnalysis {
        archive_type: archive_type.to_string(),
        entries: Vec::new(),
        is_encrypted: false,
        cracked_password: None,
        nested_archives: Vec::new(),
        all_flags: Vec::new(),
        warnings: vec![warning.to_string()],
        errors: Vec::new(),
    }
}

struct RarWorkspace {
    work_dir: PathBuf,
    temp_file: PathBuf,
    extract_dir: PathBuf,
}

impl RarWorkspace {
    fn new(
        base_dir: &Path,
        data: &[u8],
    ) -> Result<Self> {
        use std::time::{SystemTime, UNIX_EPOCH};

        std::fs::create_dir_all(base_dir)?;

        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let work_dir = base_dir.join(format!("zmctf_rar_{}_{}", std::process::id(), nanos));
        std::fs::create_dir_all(&work_dir)?;

        let temp_file = work_dir.join("input.rar");
        std::fs::write(&temp_file, data)?;

        let extract_dir = work_dir.join("extract");
        std::fs::create_dir_all(&extract_dir)?;

        Ok(Self {
            work_dir,
            temp_file,
            extract_dir,
        })
    }
}

impl Drop for RarWorkspace {
    fn drop(&mut self) {
        drop(std::fs::remove_dir_all(&self.work_dir));
    }
}

/// 压缩包条目
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchiveEntry {
    /// 文件名
    pub name: String,
    /// 压缩后大小
    pub compressed_size: u64,
    /// 原始大小
    pub uncompressed_size: u64,
    /// 是否加密
    pub is_encrypted: bool,
    /// 是否为目录
    pub is_directory: bool,
    /// 提取的内容（如果成功）
    pub content: Option<Vec<u8>>,
    /// 内容是否因资源上限被截断
    #[serde(default)]
    pub content_truncated: bool,
    /// 读取/解压错误（非致命；用于可诊断性）
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub read_error: Option<String>,
    /// 检测到的flag
    pub flags: Vec<String>,
}

/// 压缩包分析结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchiveAnalysis {
    /// 压缩包类型
    pub archive_type: String,
    /// 条目列表
    pub entries: Vec<ArchiveEntry>,
    /// 是否加密
    pub is_encrypted: bool,
    /// 破解的密码（如果成功）
    pub cracked_password: Option<String>,
    /// 嵌套的压缩包
    pub nested_archives: Vec<Self>,
    /// 检测到的所有flag
    pub all_flags: Vec<String>,
    /// 非致命告警（例如：条目过多/内容被截断/嵌套解析失败等）
    #[serde(default)]
    pub warnings: Vec<String>,
    /// 非致命错误（例如：条目读取失败等）
    #[serde(default)]
    pub errors: Vec<String>,
}

/// 压缩包分析器
#[derive(Clone)]
pub struct ArchiveAnalyzer {
    /// 全局资源与安全约束
    pub resources: ResourceLimits,
    /// 密码列表
    pub passwords: Vec<String>,
    /// 是否尝试密码爆破
    pub try_crack: bool,
    /// 临时目录
    pub temp_dir: PathBuf,
}

impl Default for ArchiveAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl ArchiveAnalyzer {
    #[must_use]
    pub fn new() -> Self {
        Self {
            resources: ResourceLimits::default(),
            passwords: default_passwords(),
            try_crack: true,
            temp_dir: std::env::temp_dir().join("zmctf_archive"),
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

    /// 设置密码列表
    #[must_use]
    pub fn with_passwords(
        mut self,
        passwords: Vec<String>,
    ) -> Self {
        self.passwords = passwords;
        self
    }

    /// 从文件加载密码列表
    ///
    /// # Errors
    ///
    /// 当读取文件失败时返回错误。
    pub fn load_passwords_from_file(
        &mut self,
        path: &Path,
    ) -> Result<()> {
        let content = std::fs::read_to_string(path)?;
        self.passwords = content.lines().map(ToString::to_string).collect();
        Ok(())
    }

    /// 分析压缩包文件
    ///
    /// # Errors
    ///
    /// 当读取文件失败或解析流程返回错误时返回错误。
    pub fn analyze_file(
        &self,
        path: &Path,
    ) -> Result<ArchiveAnalysis> {
        let data = read_file_with_limit(path, self.resources.input_max_bytes)?;
        self.analyze_bytes(&data, 0)
    }

    /// 分析压缩包字节
    ///
    /// # Errors
    ///
    /// 当超过递归深度上限或遇到不支持的格式时返回错误。
    pub fn analyze_bytes(
        &self,
        data: &[u8],
        depth: usize,
    ) -> Result<ArchiveAnalysis> {
        if depth > self.resources.archive.max_depth {
            anyhow::bail!("超过最大递归深度上限: {}", self.resources.archive.max_depth);
        }

        let magic = detect_bytes(data);

        match magic.extension.as_str() {
            "zip" => self.analyze_zip(data, depth),
            "rar" => self.analyze_rar(data, depth),
            "gz" => self.analyze_gzip(data, depth),
            "tar" => Ok(Self::analyze_tar_disabled()),
            "7z" => Ok(Self::analyze_7z_disabled()),
            _ => {
                // 尝试作为ZIP处理
                if data.starts_with(b"PK\x03\x04") {
                    self.analyze_zip(data, depth)
                } else {
                    anyhow::bail!("不支持的压缩格式: {}", magic.extension)
                }
            }
        }
    }

    fn zip_limits_reached(
        entries_len: usize,
        remaining_total: u64,
        limits: zmctf_constraints::ArchiveLimits,
        warnings: &mut Vec<String>,
    ) -> bool {
        if entries_len >= limits.max_entries {
            warnings.push(format!(
                "ZIP 条目数量超过上限 {}，已停止继续解析",
                limits.max_entries
            ));
            return true;
        }
        if remaining_total == 0 {
            warnings.push("已达到解压总量上限，停止继续解析 ZIP 条目".to_string());
            return true;
        }
        false
    }

    fn zip_open_entry<'a, R: Read + Seek>(
        archive: &'a mut zip::ZipArchive<R>,
        idx: usize,
        is_encrypted: &mut bool,
        warnings: &mut Vec<String>,
        errors: &mut Vec<String>,
    ) -> Option<zip::read::ZipFile<'a>> {
        match archive.by_index(idx) {
            Ok(f) => Some(f),
            Err(zip::result::ZipError::UnsupportedArchive(msg))
                if msg.contains("Password") || msg.contains("encrypted") =>
            {
                *is_encrypted = true;
                warnings.push(format!("ZIP 条目疑似加密（index={idx}），已跳过该条目"));
                None
            }
            Err(e) => {
                errors.push(format!("读取 ZIP 条目失败: index={idx} err={e}"));
                None
            }
        }
    }

    fn zip_read_file_content(
        file: &mut zip::read::ZipFile<'_>,
        uncompressed_size: u64,
        limits: zmctf_constraints::ArchiveLimits,
        remaining_total: &mut u64,
        warnings: &mut Vec<String>,
    ) -> Result<Option<(Vec<u8>, bool, u64)>> {
        let allowed = limits.max_entry_uncompressed_bytes.min(*remaining_total);
        if allowed == 0 {
            warnings.push("已达到解压总量上限，停止继续解析 ZIP 条目".to_string());
            return Ok(None);
        }

        let to_read = uncompressed_size.min(allowed);
        let (content, truncated_by_read) = read_to_end_with_limit(file, to_read)?;
        let truncated = truncated_by_read || uncompressed_size > to_read;
        *remaining_total = remaining_total.saturating_sub(content.len() as u64);
        Ok(Some((content, truncated, to_read)))
    }

    fn maybe_analyze_nested_archive(
        &self,
        depth: usize,
        name: &str,
        content: &[u8],
        all_flags: &mut Vec<String>,
        nested_archives: &mut Vec<ArchiveAnalysis>,
        warnings: &mut Vec<String>,
    ) {
        if depth >= self.resources.archive.max_depth {
            return;
        }

        let nested_magic = detect_bytes(content);
        if !nested_magic.is_archive {
            return;
        }

        match self.analyze_bytes(content, depth + 1) {
            Ok(nested) => {
                all_flags.extend(nested.all_flags.clone());
                nested_archives.push(nested);
            }
            Err(e) => warnings.push(format!("嵌套压缩包解析失败（已跳过）: {name}: {e}")),
        }
    }

    fn analyze_zip(
        &self,
        data: &[u8],
        depth: usize,
    ) -> Result<ArchiveAnalysis> {
        use std::io::Cursor;

        let reader = Cursor::new(data);
        let mut archive =
            zip::ZipArchive::new(reader).map_err(|e| anyhow::anyhow!("解析 ZIP 失败: {e}"))?;

        let limits = self.resources.archive;
        let mut entries = Vec::new();
        let mut all_flags = Vec::new();
        let mut nested_archives = Vec::new();
        let mut is_encrypted = false;
        let mut warnings = Vec::new();
        let mut errors = Vec::new();
        let mut remaining_total = limits.max_total_uncompressed_bytes;

        for idx in 0..archive.len() {
            if Self::zip_limits_reached(entries.len(), remaining_total, limits, &mut warnings) {
                break;
            }

            let Some(mut file) = Self::zip_open_entry(
                &mut archive,
                idx,
                &mut is_encrypted,
                &mut warnings,
                &mut errors,
            ) else {
                continue;
            };

            let name = file.name().to_string();
            let is_dir = file.is_dir();
            let compressed_size = file.compressed_size();
            let uncompressed_size = file.size();

            if is_dir {
                entries.push(ArchiveEntry {
                    name,
                    compressed_size,
                    uncompressed_size,
                    is_encrypted: false,
                    is_directory: true,
                    content: None,
                    content_truncated: false,
                    read_error: None,
                    flags: Vec::new(),
                });
                continue;
            }

            let Some((content, truncated, to_read)) = Self::zip_read_file_content(
                &mut file,
                uncompressed_size,
                limits,
                &mut remaining_total,
                &mut warnings,
            )?
            else {
                break;
            };

            let flags = find_flags_in_bytes(&content);
            all_flags.extend(flags.clone());

            if truncated {
                warnings.push(format!(
                    "ZIP 条目内容超过上限并被截断: {name} ({uncompressed_size} bytes > {to_read} bytes)"
                ));
            } else {
                self.maybe_analyze_nested_archive(
                    depth,
                    &name,
                    &content,
                    &mut all_flags,
                    &mut nested_archives,
                    &mut warnings,
                );
            }

            entries.push(ArchiveEntry {
                name,
                compressed_size,
                uncompressed_size,
                is_encrypted: false,
                is_directory: false,
                content: if content.is_empty() {
                    None
                } else {
                    Some(content)
                },
                content_truncated: truncated,
                read_error: None,
                flags,
            });
        }

        Ok(ArchiveAnalysis {
            archive_type: "ZIP".to_string(),
            entries,
            is_encrypted,
            cracked_password: None,
            nested_archives,
            all_flags,
            warnings,
            errors,
        })
    }

    fn analyze_gzip(
        &self,
        data: &[u8],
        depth: usize,
    ) -> Result<ArchiveAnalysis> {
        use flate2::read::GzDecoder;
        use std::io::Cursor;

        let reader = Cursor::new(data);
        let mut decoder = GzDecoder::new(reader);
        let limits = self.resources.archive;
        let max_bytes = limits
            .max_entry_uncompressed_bytes
            .min(limits.max_total_uncompressed_bytes);
        let (decompressed, truncated) = read_to_end_with_limit(&mut decoder, max_bytes)?;

        let mut all_flags = find_flags_in_bytes(&decompressed);
        let mut nested_archives = Vec::new();
        let mut warnings = Vec::new();
        let errors = Vec::new();

        // 检测是否为tar.gz
        let nested_magic = detect_bytes(&decompressed);
        if truncated {
            warnings.push(format!(
                "GZIP 解压内容超过上限并被截断（{max_bytes} bytes），已跳过嵌套解析"
            ));
        } else if nested_magic.extension == "tar" {
            warnings.push("检测到 tar.gz，但内置 TAR 解析已禁用（可选依赖已移除）".to_string());
        } else if nested_magic.is_archive && depth < self.resources.archive.max_depth {
            match self.analyze_bytes(&decompressed, depth + 1) {
                Ok(nested) => {
                    all_flags.extend(nested.all_flags.clone());
                    nested_archives.push(nested);
                }
                Err(e) => warnings.push(format!("嵌套压缩包解析失败（已跳过）: {e}")),
            }
        }

        Ok(ArchiveAnalysis {
            archive_type: "GZIP".to_string(),
            entries: vec![ArchiveEntry {
                name: "decompressed".to_string(),
                compressed_size: data.len() as u64,
                uncompressed_size: decompressed.len() as u64,
                is_encrypted: false,
                is_directory: false,
                content: Some(decompressed),
                content_truncated: truncated,
                read_error: None,
                flags: all_flags.clone(),
            }],
            is_encrypted: false,
            cracked_password: None,
            nested_archives,
            all_flags,
            warnings,
            errors,
        })
    }

    fn analyze_tar_disabled() -> ArchiveAnalysis {
        disabled_archive_analysis("TAR", "内置 TAR 解析已禁用（可选依赖已移除）")
    }

    fn analyze_7z_disabled() -> ArchiveAnalysis {
        disabled_archive_analysis("7Z", "内置 7Z 解析已禁用（可选依赖已移除）")
    }

    fn recreate_dir(path: &Path) -> Result<()> {
        if path.exists() {
            std::fs::remove_dir_all(path)?;
        }
        std::fs::create_dir_all(path)?;
        Ok(())
    }

    fn unrar_extract(
        temp_file: &Path,
        extract_dir: &Path,
        tool_limits: &zmctf_constraints::ToolLimits,
        password: Option<&str>,
    ) -> bool {
        use tool_runner::ToolCommand;

        let mut cmd = ToolCommand::new("unrar");
        cmd.apply_limits(tool_limits)
            .args(["x", "-y", "-o+"])
            .arg(temp_file.as_os_str())
            .arg(extract_dir.as_os_str())
            .stdout_max_bytes(16 * 1024)
            .stderr_max_bytes(16 * 1024);

        if let Some(pwd) = password {
            cmd.arg(format!("-p{pwd}"));
        }

        cmd.run().is_ok_and(|out| out.status.success())
    }

    fn unrar_test_password(
        temp_file: &Path,
        tool_limits: &zmctf_constraints::ToolLimits,
        password: &str,
    ) -> bool {
        use tool_runner::ToolCommand;

        let mut cmd = ToolCommand::new("unrar");
        cmd.apply_limits(tool_limits)
            .arg("t")
            .arg(format!("-p{password}"))
            .arg(temp_file.as_os_str())
            .stdout_max_bytes(16 * 1024)
            .stderr_max_bytes(16 * 1024);

        cmd.run().is_ok_and(|out| out.status.success())
    }

    fn try_crack_rar_password(
        &self,
        temp_file: &Path,
        tool_limits: &zmctf_constraints::ToolLimits,
    ) -> Option<String> {
        self.passwords.par_iter().find_map_any(|pwd| {
            if Self::unrar_test_password(temp_file, tool_limits, pwd) {
                Some(pwd.clone())
            } else {
                None
            }
        })
    }

    fn scan_rar_extracted(
        &self,
        extract_dir: &Path,
        depth: usize,
        is_encrypted: bool,
        warnings: &mut Vec<String>,
        errors: &mut Vec<String>,
    ) -> (Vec<ArchiveEntry>, Vec<String>, Vec<ArchiveAnalysis>) {
        use walkdir::WalkDir;

        let limits = self.resources.archive;
        let mut entries = Vec::new();
        let mut all_flags = Vec::new();
        let mut nested_archives = Vec::new();
        let mut remaining_total = limits.max_total_uncompressed_bytes;

        for entry in WalkDir::new(extract_dir)
            .into_iter()
            .filter_map(std::result::Result::ok)
        {
            if entries.len() >= limits.max_entries {
                warnings.push(format!(
                    "RAR 解压条目数量超过上限 {}，已停止继续解析",
                    limits.max_entries
                ));
                break;
            }
            if remaining_total == 0 {
                warnings.push("已达到解压总量上限，停止继续解析 RAR 条目".to_string());
                break;
            }

            if !entry.file_type().is_file() {
                continue;
            }

            let path = entry.path();
            let name = path
                .strip_prefix(extract_dir)
                .unwrap_or(path)
                .to_string_lossy()
                .to_string();

            let meta = match std::fs::metadata(path) {
                Ok(m) => m,
                Err(e) => {
                    errors.push(format!("读取 RAR 解压文件元数据失败: {name}: {e}"));
                    continue;
                }
            };

            let size = meta.len();
            let allowed = limits.max_entry_uncompressed_bytes.min(remaining_total);
            if allowed == 0 {
                warnings.push("已达到解压总量上限，停止继续解析 RAR 条目".to_string());
                break;
            }

            let to_read = size.min(allowed);
            let (content, truncated_by_read) = match File::open(path) {
                Ok(f) => read_to_end_with_limit(f, to_read).map_err(|e| e.to_string()),
                Err(e) => Err(e.to_string()),
            }
            .unwrap_or_else(|e| {
                errors.push(format!("读取 RAR 解压文件失败: {name}: {e}"));
                (Vec::new(), false)
            });

            let truncated = truncated_by_read || size > to_read;
            if truncated {
                warnings.push(format!(
                    "RAR 条目内容超过上限并被截断: {name} ({size} bytes > {to_read} bytes)"
                ));
            }

            remaining_total = remaining_total.saturating_sub(content.len() as u64);

            let flags = if content.is_empty() {
                Vec::new()
            } else {
                let flags = find_flags_in_bytes(&content);
                all_flags.extend(flags.clone());
                flags
            };

            if !truncated
                && !content.is_empty()
                && depth < self.resources.archive.max_depth
                && detect_bytes(&content).is_archive
            {
                match self.analyze_bytes(&content, depth + 1) {
                    Ok(nested) => {
                        all_flags.extend(nested.all_flags.clone());
                        nested_archives.push(nested);
                    }
                    Err(e) => warnings.push(format!("嵌套压缩包解析失败（已跳过）: {name}: {e}")),
                }
            }

            entries.push(ArchiveEntry {
                name,
                compressed_size: size,
                uncompressed_size: size,
                is_encrypted,
                is_directory: false,
                content: if content.is_empty() {
                    None
                } else {
                    Some(content)
                },
                content_truncated: truncated,
                read_error: None,
                flags,
            });
        }

        (entries, all_flags, nested_archives)
    }

    /// 分析RAR文件 - 使用外部unrar工具
    fn analyze_rar(
        &self,
        data: &[u8],
        depth: usize,
    ) -> Result<ArchiveAnalysis> {
        let tool_limits = self.resources.external_tools.for_tool("unrar");
        let mut warnings = Vec::new();
        let mut errors = Vec::new();

        // 检查unrar是否可用
        if tool_runner::resolve_program("unrar").is_err() {
            // 回退到基本检测
            let is_encrypted = data.len() > 10 && (data[10] & 0x04) != 0;
            return Ok(ArchiveAnalysis {
                archive_type: "RAR".to_string(),
                entries: Vec::new(),
                is_encrypted,
                cracked_password: None,
                nested_archives: Vec::new(),
                all_flags: Vec::new(),
                warnings: vec!["未安装 `unrar`，无法解析 RAR（可选依赖）".to_string()],
                errors: Vec::new(),
            });
        }

        let workspace = RarWorkspace::new(&self.temp_dir, data)?;

        let mut cracked_password = None;
        let mut extracted = Self::unrar_extract(
            &workspace.temp_file,
            &workspace.extract_dir,
            &tool_limits,
            None,
        );

        if !extracted && self.try_crack {
            cracked_password = self.try_crack_rar_password(&workspace.temp_file, &tool_limits);
            if let Some(ref pwd) = cracked_password {
                Self::recreate_dir(&workspace.extract_dir)?;
                extracted = Self::unrar_extract(
                    &workspace.temp_file,
                    &workspace.extract_dir,
                    &tool_limits,
                    Some(pwd),
                );
            }
        }

        let is_encrypted =
            cracked_password.is_some() || (!extracted && data.len() > 10 && (data[10] & 0x04) != 0);

        let (entries, all_flags, nested_archives) = if extracted {
            self.scan_rar_extracted(
                &workspace.extract_dir,
                depth,
                cracked_password.is_some(),
                &mut warnings,
                &mut errors,
            )
        } else {
            (Vec::new(), Vec::new(), Vec::new())
        };

        Ok(ArchiveAnalysis {
            archive_type: "RAR".to_string(),
            entries,
            is_encrypted,
            cracked_password,
            nested_archives,
            all_flags,
            warnings,
            errors,
        })
    }

    /// 提取所有文件到目录
    ///
    /// # Errors
    ///
    /// - 当输出目录创建失败时返回错误。
    /// - 当压缩包解析失败或超过递归深度上限时返回错误。
    /// - 当写入文件失败时返回错误。
    pub fn extract_to_dir(
        &self,
        data: &[u8],
        output_dir: &Path,
    ) -> Result<Vec<PathBuf>> {
        std::fs::create_dir_all(output_dir)?;

        let analysis = self.analyze_bytes(data, 0)?;
        let mut extracted = Vec::new();

        for entry in analysis.entries {
            if !entry.is_directory {
                if let Some(content) = entry.content {
                    let Some(relative) = sanitize_archive_entry_path(&entry.name) else {
                        log::warn!("跳过不安全的压缩包条目路径: {}", entry.name);
                        continue;
                    };

                    let path = output_dir.join(relative);
                    if let Some(parent) = path.parent() {
                        std::fs::create_dir_all(parent)?;
                    }
                    let mut file = File::create(&path)?;
                    file.write_all(&content)?;
                    extracted.push(path);
                }
            }
        }

        Ok(extracted)
    }
}

fn sanitize_archive_entry_path(entry_name: &str) -> Option<PathBuf> {
    let mut relative = PathBuf::new();

    for component in Path::new(entry_name).components() {
        match component {
            Component::CurDir => {}
            Component::Normal(part) => relative.push(part),
            Component::Prefix(_) | Component::RootDir | Component::ParentDir => return None,
        }
    }

    if relative.as_os_str().is_empty() {
        None
    } else {
        Some(relative)
    }
}

/// 在字节中查找flag
fn find_flags_in_bytes(data: &[u8]) -> Vec<String> {
    let mut flags = Vec::new();

    // 尝试转换为字符串
    if let Ok(text) = String::from_utf8(data.to_vec()) {
        flags.extend(find_flags_in_text(&text));
    } else {
        // 有损转换
        let text = String::from_utf8_lossy(data);
        flags.extend(find_flags_in_text(&text));
    }

    flags
}

/// 在文本中查找flag
fn find_flags_in_text(text: &str) -> Vec<String> {
    let mut flags = Vec::new();

    // 常见flag模式
    let patterns = [
        r"flag\{[^}]+\}",
        r"FLAG\{[^}]+\}",
        r"ctf\{[^}]+\}",
        r"CTF\{[^}]+\}",
        r"[a-zA-Z]+\{[a-zA-Z0-9_\-+=/@!]+\}",
    ];

    for pattern in patterns {
        if let Ok(re) = regex::Regex::new(pattern) {
            for cap in re.find_iter(text) {
                flags.push(cap.as_str().to_string());
            }
        }
    }

    flags.sort();
    flags.dedup();
    flags
}

/// 默认密码列表
fn default_passwords() -> Vec<String> {
    vec![
        String::new(),
        "password".to_string(),
        "123456".to_string(),
        "12345678".to_string(),
        "qwerty".to_string(),
        "abc123".to_string(),
        "111111".to_string(),
        "123123".to_string(),
        "admin".to_string(),
        "letmein".to_string(),
        "welcome".to_string(),
        "monkey".to_string(),
        "dragon".to_string(),
        "master".to_string(),
        "1234567890".to_string(),
        "password1".to_string(),
        "password123".to_string(),
        "flag".to_string(),
        "ctf".to_string(),
        "secret".to_string(),
        "test".to_string(),
        "guest".to_string(),
        "root".to_string(),
        "toor".to_string(),
        "pass".to_string(),
        "1234".to_string(),
        "12345".to_string(),
        "1q2w3e4r".to_string(),
        "qwerty123".to_string(),
        "iloveyou".to_string(),
        "sunshine".to_string(),
        "princess".to_string(),
        "football".to_string(),
        "baseball".to_string(),
        "trustno1".to_string(),
        "superman".to_string(),
        "batman".to_string(),
        "starwars".to_string(),
        "hello".to_string(),
        "charlie".to_string(),
        "donald".to_string(),
        "passw0rd".to_string(),
        "shadow".to_string(),
        "michael".to_string(),
        "jennifer".to_string(),
        "hunter".to_string(),
        "buster".to_string(),
        "soccer".to_string(),
        "harley".to_string(),
        "ranger".to_string(),
        "george".to_string(),
        "maggie".to_string(),
        "pepper".to_string(),
        "ginger".to_string(),
        "joshua".to_string(),
        "matthew".to_string(),
        "taylor".to_string(),
        "robert".to_string(),
        "thomas".to_string(),
        "jordan".to_string(),
        "daniel".to_string(),
        "andrew".to_string(),
        "access".to_string(),
        "love".to_string(),
        "killer".to_string(),
        "nicole".to_string(),
        "jessica".to_string(),
        "ashley".to_string(),
        "qazwsx".to_string(),
        "123qwe".to_string(),
        "zxcvbn".to_string(),
        "asdfgh".to_string(),
        "qweasd".to_string(),
        "1qaz2wsx".to_string(),
        "q1w2e3r4".to_string(),
        "zaq12wsx".to_string(),
        "!@#$%^&*".to_string(),
        "P@ssw0rd".to_string(),
        "P@ssword".to_string(),
        "Passw0rd".to_string(),
        "Password1".to_string(),
        "Password123".to_string(),
        "Admin123".to_string(),
        "Root123".to_string(),
        "2020".to_string(),
        "2021".to_string(),
        "2022".to_string(),
        "2023".to_string(),
        "2024".to_string(),
        "2025".to_string(),
    ]
}

/// 便捷函数：分析压缩包文件
///
/// # Errors
///
/// 当读取文件或解析压缩包失败时返回错误。
pub fn analyze_archive(path: &Path) -> Result<ArchiveAnalysis> {
    ArchiveAnalyzer::new().analyze_file(path)
}

/// 便捷函数：分析压缩包字节
///
/// # Errors
///
/// 当解析压缩包失败或超过递归深度上限时返回错误。
pub fn analyze_archive_bytes(data: &[u8]) -> Result<ArchiveAnalysis> {
    ArchiveAnalyzer::new().analyze_bytes(data, 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use std::time::{SystemTime, UNIX_EPOCH};
    use zip::write::FileOptions;

    #[test]
    fn test_find_flags() {
        let text = "Hello flag{test_flag_123} world CTF{another_flag}";
        let flags = find_flags_in_text(text);
        assert!(flags.contains(&"flag{test_flag_123}".to_string()));
        assert!(flags.contains(&"CTF{another_flag}".to_string()));
    }

    #[test]
    fn test_default_passwords() {
        let passwords = default_passwords();
        assert!(passwords.contains(&"password".to_string()));
        assert!(passwords.contains(&"123456".to_string()));
    }

    #[test]
    fn test_extract_to_dir_rejects_path_traversal() -> Result<()> {
        let mut bytes = Vec::new();
        {
            let cursor = Cursor::new(&mut bytes);
            let mut zip = zip::ZipWriter::new(cursor);
            let opts = FileOptions::<()>::default();

            zip.start_file("good.txt", opts)?;
            zip.write_all(b"ok")?;

            zip.start_file("../evil.txt", opts)?;
            zip.write_all(b"evil")?;

            zip.finish()?;
        }

        let uniq = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let base = std::env::temp_dir().join(format!(
            "zmctf_archive_test_{}_{}",
            std::process::id(),
            uniq
        ));
        let out_dir = base.join("out");
        std::fs::create_dir_all(&out_dir)?;

        let analyzer = ArchiveAnalyzer::new();
        let extracted = analyzer.extract_to_dir(&bytes, &out_dir)?;

        assert!(out_dir.join("good.txt").exists());
        assert!(!base.join("evil.txt").exists());
        assert_eq!(extracted.len(), 1);
        assert!(extracted[0].starts_with(&out_dir));

        let _ = std::fs::remove_dir_all(&base);
        Ok(())
    }

    #[test]
    fn test_analyze_zip_respects_max_entries() -> Result<()> {
        let mut bytes = Vec::new();
        {
            let cursor = Cursor::new(&mut bytes);
            let mut zip = zip::ZipWriter::new(cursor);
            let opts = FileOptions::<()>::default();

            zip.start_file("a.txt", opts)?;
            zip.write_all(b"a")?;

            zip.start_file("b.txt", opts)?;
            zip.write_all(b"b")?;

            zip.finish()?;
        }

        let mut resources = ResourceLimits::default();
        resources.archive.max_entries = 1;

        let analyzer = ArchiveAnalyzer::new().with_resource_limits(resources);
        let analysis = analyzer.analyze_bytes(&bytes, 0)?;

        assert_eq!(analysis.entries.len(), 1);
        assert!(analysis
            .warnings
            .iter()
            .any(|w| w.contains("条目数量超过上限")));
        Ok(())
    }

    #[test]
    fn test_analyze_zip_truncates_entry_content() -> Result<()> {
        let mut bytes = Vec::new();
        {
            let cursor = Cursor::new(&mut bytes);
            let mut zip = zip::ZipWriter::new(cursor);
            let opts = FileOptions::<()>::default();

            zip.start_file("big.txt", opts)?;
            zip.write_all(b"12345")?;

            zip.finish()?;
        }

        let mut resources = ResourceLimits::default();
        resources.archive.max_entry_uncompressed_bytes = 3;

        let analyzer = ArchiveAnalyzer::new().with_resource_limits(resources);
        let analysis = analyzer.analyze_bytes(&bytes, 0)?;

        let entry = analysis
            .entries
            .iter()
            .find(|e| e.name == "big.txt")
            .expect("entry should exist");
        assert!(entry.content_truncated);
        assert_eq!(entry.content.as_deref(), Some(&b"123"[..]));
        assert!(analysis.warnings.iter().any(|w| w.contains("被截断")));
        Ok(())
    }
}
