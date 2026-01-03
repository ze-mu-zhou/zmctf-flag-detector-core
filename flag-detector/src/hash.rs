//! 哈希识别与破解
//!
//! 基于 Name-That-Hash 的模式原型（`nth_patterns.rs`），提供哈希类型识别、内置弱口令彩虹表与基于 wordlist 的离线爆破。

use anyhow::{Context, Result};
use md5::Md5;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha512};
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader, Read};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use zmctf_constraints::ResourceLimits;

mod nth_patterns {
    include!("nth_patterns.rs");
}

/// 哈希类型匹配结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashMatch {
    pub name: String,
    pub hashcat_mode: Option<u32>,
    pub john_format: Option<String>,
    pub extended: bool,
    pub confidence: f32,
    pub description: Option<String>,
}

/// 哈希识别分析结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashAnalysis {
    pub input: String,
    pub possible_types: Vec<HashMatch>,
    pub is_hash: bool,
}

#[derive(Clone, Debug)]
struct HashPrototype {
    regex: regex::Regex,
    modes: &'static [nth_patterns::ModeDef],
}

/// 哈希识别器（模式 + 彩虹表）
pub struct HashIdentifier {
    prototypes: Vec<HashPrototype>,
    rainbow_table: HashMap<String, String>,
    resources: ResourceLimits,
}

impl Default for HashIdentifier {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for HashIdentifier {
    fn clone(&self) -> Self {
        // Regex不能直接clone，所以重新构建实例
        Self::new().with_resource_limits(self.resources.clone())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CrackAlgorithm {
    Md5,
    Sha1,
    Sha256,
    Sha512,
    Ntlm,
    DoubleMd5,
}

impl HashIdentifier {
    #[must_use]
    pub fn new() -> Self {
        let prototypes = nth_patterns::NTH_PROTOTYPES
            .iter()
            .filter_map(|p| {
                let pattern = p.pattern;
                let pat = if p.ignore_case {
                    format!("(?i){pattern}")
                } else {
                    pattern.to_string()
                };

                match regex::Regex::new(&pat) {
                    Ok(regex) => Some(HashPrototype {
                        regex,
                        modes: p.modes,
                    }),
                    Err(err) => {
                        log::warn!("跳过无效 hash 模式正则: {pat} ({err})");
                        None
                    }
                }
            })
            .collect::<Vec<_>>();

        // 内置弱口令彩虹表（用于快速命中常见哈希）
        let rainbow_table: HashMap<String, String> = [
            ("d41d8cd98f00b204e9800998ecf8427e", ""),
            ("e10adc3949ba59abbe56e057f20f883e", "123456"),
            ("25d55ad283aa400af464c76d713c07ad", "12345678"),
            ("5f4dcc3b5aa765d61d8327deb882cf99", "password"),
            ("e99a18c428cb38d5f260853678922e03", "abc123"),
            ("d8578edf8458ce06fbc5bb76a58c5ca4", "qwerty"),
            ("96e79218965eb72c92a549dd5a330112", "111111"),
            ("827ccb0eea8a706c4c34a16891f84e7b", "12345"),
            ("25f9e794323b453885f5181f1b624d0b", "123456789"),
            ("fcea920f7412b5da7be0cf42b8c93759", "1234567"),
            ("0192023a7bbd73250516f069df18b500", "admin123"),
            ("21232f297a57a5a743894a0e4a801fc3", "admin"),
            ("098f6bcd4621d373cade4e832627b4f6", "test"),
            ("5d41402abc4b2a76b9719d911017c592", "hello"),
            ("7c6a180b36896a65c3f8ea8e8fdb1a77", "letmein"),
            ("6cb75f652a9b52798eb6cf2201057c73", "password123"),
            ("f25a2fc72690b780b2a14e140ef6a9e0", "iloveyou"),
            ("0d107d09f5bbe40cade3de5c71e9e9b7", "123123"),
            ("e807f1fcf82d132f9bb018ca6738a19f", "1234567890"),
        ]
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();

        Self {
            prototypes,
            rainbow_table,
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

    /// 识别单个哈希（按置信度降序返回可能类型）
    #[must_use]
    pub fn identify(
        &self,
        hash: &str,
    ) -> HashAnalysis {
        let hash = hash.trim();
        let mut matches: Vec<HashMatch> = Vec::new();

        for proto in &self.prototypes {
            if proto.regex.is_match(hash) {
                for mode in proto.modes {
                    let confidence = if mode.extended { 0.55 } else { 0.85 };
                    matches.push(HashMatch {
                        name: mode.name.to_string(),
                        hashcat_mode: mode.hashcat,
                        john_format: mode.john.map(ToString::to_string),
                        extended: mode.extended,
                        confidence,
                        description: mode.description.map(ToString::to_string),
                    });
                }
            }
        }

        // 置信度优先，其次名称稳定排序
        matches.sort_by(|a, b| {
            b.confidence
                .partial_cmp(&a.confidence)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| a.name.cmp(&b.name))
        });

        HashAnalysis {
            input: hash.to_string(),
            is_hash: !matches.is_empty(),
            possible_types: matches,
        }
    }

    /// 在文本中扫描并返回可能的哈希类型集合
    #[must_use]
    pub fn identify_all(
        &self,
        text: &str,
    ) -> Vec<HashMatch> {
        let mut matches: Vec<HashMatch> = Vec::new();

        for proto in &self.prototypes {
            if proto.regex.find_iter(text).next().is_some() {
                for mode in proto.modes {
                    let confidence = if mode.extended { 0.55 } else { 0.85 };
                    matches.push(HashMatch {
                        name: mode.name.to_string(),
                        hashcat_mode: mode.hashcat,
                        john_format: mode.john.map(ToString::to_string),
                        extended: mode.extended,
                        confidence,
                        description: mode.description.map(ToString::to_string),
                    });
                }
            }
        }

        matches.sort_by(|a, b| {
            b.confidence
                .partial_cmp(&a.confidence)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| a.name.cmp(&b.name))
        });

        matches
    }

    /// 使用内置彩虹表快速破解（目前主要覆盖常见 MD5）
    #[must_use]
    pub fn crack(
        &self,
        hash: &str,
    ) -> Option<String> {
        let hash_lower = hash.trim().to_ascii_lowercase();
        self.rainbow_table.get(&hash_lower).cloned()
    }

    /// 使用 wordlist 破解无盐哈希（默认并行）
    ///
    /// # Errors
    ///
    /// 当读取字典文件失败或解析过程中发生 I/O 错误时返回错误。
    pub fn crack_with_wordlist(
        &self,
        hash: &str,
        wordlist_path: &Path,
    ) -> Result<Option<String>> {
        self.crack_with_wordlist_parallel(hash, wordlist_path, true)
    }

    /// 使用 wordlist 破解（可选并行）
    ///
    /// # Errors
    ///
    /// 当读取字典文件失败或解析过程中发生 I/O 错误时返回错误。
    pub fn crack_with_wordlist_parallel(
        &self,
        hash: &str,
        wordlist_path: &Path,
        parallel: bool,
    ) -> Result<Option<String>> {
        let hash = hash.trim();
        let analysis = self.identify(hash);
        if !analysis.is_hash {
            return Ok(None);
        }

        let target = hash.to_ascii_lowercase();

        let mut algorithms: Vec<CrackAlgorithm> = Vec::new();
        for m in &analysis.possible_types {
            match m.hashcat_mode {
                Some(0) => algorithms.push(CrackAlgorithm::Md5),
                Some(100) => algorithms.push(CrackAlgorithm::Sha1),
                Some(1400) => algorithms.push(CrackAlgorithm::Sha256),
                Some(1700) => algorithms.push(CrackAlgorithm::Sha512),
                Some(1000) => algorithms.push(CrackAlgorithm::Ntlm),
                Some(2600) => algorithms.push(CrackAlgorithm::DoubleMd5),
                _ => {}
            }
        }

        algorithms.sort_by_key(|a| *a as u8);
        algorithms.dedup();

        if algorithms.is_empty() {
            algorithms = match target.len() {
                32 => vec![CrackAlgorithm::Md5],
                40 => vec![CrackAlgorithm::Sha1],
                64 => vec![CrackAlgorithm::Sha256],
                128 => vec![CrackAlgorithm::Sha512],
                _ => Vec::new(),
            };
        }
        if algorithms.is_empty() {
            return Ok(None);
        }

        if parallel {
            self.crack_parallel(&target, wordlist_path, &algorithms)
        } else {
            Self::crack_sequential(&target, wordlist_path, &algorithms)
        }
    }

    /// 并行字典破解
    fn crack_parallel(
        &self,
        target: &str,
        wordlist_path: &Path,
        algorithms: &[CrackAlgorithm],
    ) -> Result<Option<String>> {
        let meta = std::fs::metadata(wordlist_path)?;
        if meta.len() > self.resources.input_max_bytes {
            log::warn!(
                "wordlist 过大（{} bytes），为避免内存膨胀已自动降级为顺序模式: {}",
                meta.len(),
                wordlist_path.display()
            );
            return Self::crack_sequential(target, wordlist_path, algorithms);
        }
        let mut file = File::open(wordlist_path)
            .with_context(|| format!("打开 wordlist 失败: {}", wordlist_path.display()))?;

        let mut content = Vec::new();
        file.read_to_end(&mut content)?;

        let found = AtomicBool::new(false);
        let target = target.to_string();
        let algorithms = algorithms.to_vec();

        let lines: Vec<&[u8]> = content.split(|&b| b == b'\n').collect();

        let result = lines.par_chunks(2048).find_map_any(|chunk| {
            if found.load(Ordering::Relaxed) {
                return None;
            }

            for line in chunk {
                let mut word = *line;
                if word.ends_with(b"\r") {
                    word = &word[..word.len() - 1];
                }
                if word.is_empty() {
                    continue;
                }

                for alg in &algorithms {
                    let digest = compute_hash(word, *alg);
                    if digest == target {
                        found.store(true, Ordering::Relaxed);
                        return Some(String::from_utf8_lossy(word).into_owned());
                    }
                }
            }
            None
        });

        Ok(result)
    }

    /// 顺序字典破解
    fn crack_sequential(
        target: &str,
        wordlist_path: &Path,
        algorithms: &[CrackAlgorithm],
    ) -> Result<Option<String>> {
        let file = File::open(wordlist_path)
            .with_context(|| format!("打开 wordlist 失败: {}", wordlist_path.display()))?;
        let mut reader = BufReader::with_capacity(1024 * 1024, file);
        let mut buf: Vec<u8> = Vec::with_capacity(128);

        loop {
            buf.clear();
            let read = reader.read_until(b'\n', &mut buf)?;
            if read == 0 {
                break;
            }

            while matches!(buf.last(), Some(b'\n' | b'\r')) {
                buf.pop();
            }
            if buf.is_empty() {
                continue;
            }

            for alg in algorithms {
                let digest = compute_hash(&buf, *alg);
                if digest == target {
                    return Ok(Some(String::from_utf8_lossy(&buf).into_owned()));
                }
            }
        }

        Ok(None)
    }

    /// 批量识别多个哈希（保持输入顺序）
    #[must_use]
    pub fn identify_batch(
        &self,
        hashes: &[&str],
    ) -> Vec<HashAnalysis> {
        hashes.iter().map(|h| self.identify(h)).collect()
    }
}

/// 计算哈希（共享函数）
fn compute_hash(
    data: &[u8],
    alg: CrackAlgorithm,
) -> String {
    match alg {
        CrackAlgorithm::Md5 => {
            let mut h = Md5::new();
            h.update(data);
            hex::encode(h.finalize())
        }
        CrackAlgorithm::Sha1 => {
            let mut h = Sha1::new();
            h.update(data);
            hex::encode(h.finalize())
        }
        CrackAlgorithm::Sha256 => {
            let mut h = Sha256::new();
            h.update(data);
            hex::encode(h.finalize())
        }
        CrackAlgorithm::Sha512 => {
            let mut h = Sha512::new();
            h.update(data);
            hex::encode(h.finalize())
        }
        CrackAlgorithm::Ntlm => compute_ntlm(data),
        CrackAlgorithm::DoubleMd5 => {
            let mut h = Md5::new();
            h.update(data);
            let first = hex::encode(h.finalize());
            let mut h2 = Md5::new();
            h2.update(first.as_bytes());
            hex::encode(h2.finalize())
        }
    }
}

/// 计算 NTLM 哈希 (MD4 of UTF-16LE encoded password)
fn compute_ntlm(password: &[u8]) -> String {
    // 将密码转换为 UTF-16LE
    let utf16: Vec<u8> = String::from_utf8_lossy(password)
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();

    // 使用 MD4 计算哈希 (简化实现)
    md4_hash(&utf16)
}

/// 简化的 MD4 实现
fn md4_hash(data: &[u8]) -> String {
    // MD4 常量
    const SHIFTS: [[u32; 4]; 3] = [[3, 7, 11, 19], [3, 5, 9, 13], [3, 9, 11, 15]];

    const fn md4_f(
        word_x: u32,
        word_y: u32,
        word_z: u32,
    ) -> u32 {
        (word_x & word_y) | (!word_x & word_z)
    }

    const fn md4_g(
        word_x: u32,
        word_y: u32,
        word_z: u32,
    ) -> u32 {
        (word_x & word_y) | (word_x & word_z) | (word_y & word_z)
    }

    const fn md4_h(
        word_x: u32,
        word_y: u32,
        word_z: u32,
    ) -> u32 {
        word_x ^ word_y ^ word_z
    }

    // 填充
    let mut msg = data.to_vec();
    let orig_len = msg.len();
    msg.push(0x80);
    while (msg.len() % 64) != 56 {
        msg.push(0);
    }
    let bit_len = (orig_len as u64) * 8;
    msg.extend_from_slice(&bit_len.to_le_bytes());

    // 初始化
    let mut state_a: u32 = 0x6745_2301;
    let mut state_b: u32 = 0xefcd_ab89;
    let mut state_c: u32 = 0x98ba_dcfe;
    let mut state_d: u32 = 0x1032_5476;

    // 处理每个 64 字节块
    for chunk in msg.chunks(64) {
        let mut block_words = [0u32; 16];
        for (word_index, word_bytes) in chunk.chunks(4).enumerate() {
            block_words[word_index] =
                u32::from_le_bytes([word_bytes[0], word_bytes[1], word_bytes[2], word_bytes[3]]);
        }

        let (saved_a, saved_b, saved_c, saved_d) = (state_a, state_b, state_c, state_d);

        // Round 1
        for round_index in 0..16 {
            let word_index = round_index;
            let shift = SHIFTS[0][round_index % 4];
            let temp = state_a
                .wrapping_add(md4_f(state_b, state_c, state_d))
                .wrapping_add(block_words[word_index]);
            state_a = state_d;
            state_d = state_c;
            state_c = state_b;
            state_b = temp.rotate_left(shift);
        }

        // Round 2
        let order2 = [0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15];
        for round_index in 0..16 {
            let word_index = order2[round_index];
            let shift = SHIFTS[1][round_index % 4];
            let temp = state_a
                .wrapping_add(md4_g(state_b, state_c, state_d))
                .wrapping_add(block_words[word_index])
                .wrapping_add(0x5a82_7999);
            state_a = state_d;
            state_d = state_c;
            state_c = state_b;
            state_b = temp.rotate_left(shift);
        }

        // Round 3
        let order3 = [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15];
        for round_index in 0..16 {
            let word_index = order3[round_index];
            let shift = SHIFTS[2][round_index % 4];
            let temp = state_a
                .wrapping_add(md4_h(state_b, state_c, state_d))
                .wrapping_add(block_words[word_index])
                .wrapping_add(0x6ed9_eba1);
            state_a = state_d;
            state_d = state_c;
            state_c = state_b;
            state_b = temp.rotate_left(shift);
        }

        state_a = state_a.wrapping_add(saved_a);
        state_b = state_b.wrapping_add(saved_b);
        state_c = state_c.wrapping_add(saved_c);
        state_d = state_d.wrapping_add(saved_d);
    }

    format!(
        "{:08x}{:08x}{:08x}{:08x}",
        state_a.swap_bytes(),
        state_b.swap_bytes(),
        state_c.swap_bytes(),
        state_d.swap_bytes()
    )
}

/// 便捷函数：计算 MD5
///
/// # Examples
///
/// ```
/// use flag_detector::hash::hash_md5;
/// let result = hash_md5(b"hello");
/// assert_eq!(result, "5d41402abc4b2a76b9719d911017c592");
/// ```
#[must_use]
pub fn hash_md5(data: &[u8]) -> String {
    let mut h = Md5::new();
    h.update(data);
    hex::encode(h.finalize())
}

/// 便捷函数：计算 SHA1
#[must_use]
pub fn hash_sha1(data: &[u8]) -> String {
    let mut h = Sha1::new();
    h.update(data);
    hex::encode(h.finalize())
}

/// 便捷函数：计算 SHA256
///
/// # Examples
///
/// ```
/// use flag_detector::hash::hash_sha256;
/// let result = hash_sha256(b"hello");
/// assert_eq!(result, "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824");
/// ```
#[must_use]
pub fn hash_sha256(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    hex::encode(h.finalize())
}

/// 便捷函数：计算 SHA512
#[must_use]
pub fn hash_sha512(data: &[u8]) -> String {
    let mut h = Sha512::new();
    h.update(data);
    hex::encode(h.finalize())
}

/// 便捷函数：计算 NTLM
#[must_use]
pub fn hash_ntlm(password: &str) -> String {
    compute_ntlm(password.as_bytes())
}

/// 便捷函数：计算 Double MD5
#[must_use]
pub fn hash_double_md5(data: &[u8]) -> String {
    let first = hash_md5(data);
    hash_md5(first.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_patterns_loaded_counts() {
        let identifier = HashIdentifier::new();
        assert!(identifier.prototypes.len() >= 200);
        let mode_count: usize = identifier.prototypes.iter().map(|p| p.modes.len()).sum();
        assert!(mode_count >= 350);
    }

    #[test]
    fn test_md5_identification_contains_md5() {
        let identifier = HashIdentifier::new();
        let result = identifier.identify("5d41402abc4b2a76b9719d911017c592");
        assert!(result.is_hash);
        assert!(result
            .possible_types
            .iter()
            .any(|m| m.name.eq_ignore_ascii_case("MD5")));
    }

    #[test]
    fn test_sha256_identification_contains_sha256() {
        let identifier = HashIdentifier::new();
        let result =
            identifier.identify("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        assert!(result.is_hash);
        assert!(result
            .possible_types
            .iter()
            .any(|m| m.name.contains("SHA-256") || m.name.contains("SHA256")));
    }

    #[test]
    fn test_crc32_identification() {
        let identifier = HashIdentifier::new();
        let result = identifier.identify("cbf43926");
        assert!(result.is_hash);
        assert!(result.possible_types.iter().any(|m| m.name.contains("CRC")));
    }

    #[test]
    fn test_crack_common_md5_table() {
        let identifier = HashIdentifier::new();
        assert_eq!(
            identifier.crack("5d41402abc4b2a76b9719d911017c592"),
            Some("hello".to_string())
        );
        assert_eq!(
            identifier.crack("e10adc3949ba59abbe56e057f20f883e"),
            Some("123456".to_string())
        );
    }

    #[test]
    fn test_crack_wordlist_md5() {
        use std::time::{SystemTime, UNIX_EPOCH};

        let identifier = HashIdentifier::new();
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "zmctf_wordlist_test_{}_{}.txt",
            std::process::id(),
            nanos
        ));
        std::fs::write(&path, b"foo\nhello\nbar\n").unwrap();

        let cracked = identifier
            .crack_with_wordlist("5d41402abc4b2a76b9719d911017c592", &path)
            .unwrap();
        assert_eq!(cracked.as_deref(), Some("hello"));

        let _ = std::fs::remove_file(&path);
    }
}
