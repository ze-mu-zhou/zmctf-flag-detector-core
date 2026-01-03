//! 内置 Cipher 模块 - 自动解码器
//! 类似 Ciphey 的自动化解码功能

use crate::encoding;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};

/// 解码结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CipherResult {
    pub input: String,
    pub output: String,
    pub steps: Vec<CipherStep>,
    pub success: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CipherStep {
    pub method: String,
    pub input: String,
    pub output: String,
    pub confidence: f32,
}

/// 字符串相关性评分（`StringSifter` 风格）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StringScore {
    pub string: String,
    pub score: f32,
    pub reasons: Vec<String>,
}

/// Cipher 解码器
pub struct Cipher {
    max_depth: usize,
}

impl Default for Cipher {
    fn default() -> Self {
        Self { max_depth: 10 }
    }
}

impl Cipher {
    #[must_use]
    pub const fn new(max_depth: usize) -> Self {
        Self { max_depth }
    }

    /// 自动解码字符串
    #[must_use]
    pub fn decode(
        &self,
        input: &str,
    ) -> CipherResult {
        let mut steps = Vec::new();
        let mut current = input.to_string();
        let mut success = false;

        for _ in 0..self.max_depth {
            if let Some(step) = Self::try_decode_once(&current) {
                current.clone_from(&step.output);
                steps.push(step);

                if Self::is_readable(&current) {
                    success = true;
                    break;
                }
            } else {
                break;
            }
        }

        CipherResult {
            input: input.to_string(),
            output: current,
            steps,
            success,
        }
    }

    /// 字符串相关性评分（`StringSifter` 风格）
    #[must_use]
    pub fn score_string(
        &self,
        s: &str,
    ) -> StringScore {
        let mut score = 0.0f32;
        let mut reasons = Vec::new();

        if encoding::contains_flag(s) {
            score += 1.0;
            reasons.push("contains_flag_pattern".into());
        }

        let keywords = [
            "password", "secret", "key", "token", "api", "admin", "root", "shell", "exec", "cmd",
            "http", "ftp",
        ];
        for kw in keywords {
            if s.to_lowercase().contains(kw) {
                score += 0.3;
                reasons.push(format!("keyword:{kw}"));
            }
        }

        if (s.contains('/') || s.contains('\\'))
            && (s.contains("etc/passwd") || s.contains("windows\\system"))
        {
            score += 0.5;
            reasons.push("suspicious_path".into());
        }

        if s.contains("://") || s.matches('.').count() == 3 {
            score += 0.2;
            reasons.push("network_indicator".into());
        }

        let entropy = Self::calculate_entropy(s);
        if entropy > 4.5 {
            score += 0.2;
            reasons.push(format!("high_entropy:{entropy:.2}"));
        }

        StringScore {
            string: s.to_string(),
            score,
            reasons,
        }
    }

    /// 批量评分并排序
    #[must_use]
    pub fn rank_strings(
        &self,
        strings: &[String],
    ) -> Vec<StringScore> {
        let mut scores: Vec<_> = strings.iter().map(|s| self.score_string(s)).collect();
        scores.sort_by(|a, b| {
            b.score
                .partial_cmp(&a.score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        scores
    }

    /// 多字节XOR分析 (xortool风格)
    #[must_use]
    pub fn xor_analyze(
        &self,
        data: &[u8],
    ) -> Vec<(Vec<u8>, String)> {
        let mut results = Vec::new();
        for key_len in 1..=16 {
            if let Some(key) = Self::guess_xor_key(data, key_len) {
                let decoded = encoding::xor_multi(data, &key);
                if let Ok(s) = String::from_utf8(decoded) {
                    if encoding::is_printable(&s, 0.8) {
                        results.push((key, s));
                    }
                }
            }
        }
        results
    }

    fn guess_xor_key(
        data: &[u8],
        key_len: usize,
    ) -> Option<Vec<u8>> {
        let mut key = Vec::with_capacity(key_len);
        for i in 0..key_len {
            let chunk: Vec<u8> = data.iter().skip(i).step_by(key_len).copied().collect();
            if chunk.is_empty() {
                return None;
            }
            let mut freq = [0u32; 256];
            for &b in &chunk {
                freq[b as usize] += 1;
            }
            let most_common_idx = freq.iter().enumerate().max_by_key(|(_, &c)| c)?.0;
            let most_common = u8::try_from(most_common_idx).ok()?;
            key.push(most_common ^ 0x20);
        }
        Some(key)
    }

    fn calculate_entropy(s: &str) -> f64 {
        fn usize_to_f64_saturating(value: usize) -> f64 {
            f64::from(u32::try_from(value).unwrap_or(u32::MAX))
        }

        let mut freq = [0u32; 256];
        for b in s.bytes() {
            freq[b as usize] += 1;
        }
        let len = usize_to_f64_saturating(s.len());
        let entropy: f64 = freq
            .iter()
            .filter(|&&c| c > 0)
            .map(|&c| {
                let p = f64::from(c) / len;
                -p * p.log2()
            })
            .sum();
        entropy
    }

    fn try_decode_once(input: &str) -> Option<CipherStep> {
        // 使用共享模块的解码函数
        type DecoderFn = fn(&str) -> Option<String>;
        let decoders: Vec<(&str, DecoderFn)> = vec![
            ("Base64", |s| encoding::decode_base64(s)),
            ("Base32", |s| encoding::decode_base32(s)),
            ("Base58", |s| encoding::decode_base58(s)),
            ("Base85", |s| encoding::decode_base85(s)),
            ("Base91", |s| encoding::decode_base91(s)),
            ("Base62", |s| encoding::decode_base62(s)),
            ("ASCII85", |s| encoding::decode_ascii85(s)),
            ("Hex", |s| encoding::decode_hex(s)),
            ("ROT13", |s| encoding::decode_rot13(s)),
            ("ROT47", |s| encoding::decode_rot47(s)),
            ("URL", |s| encoding::decode_url(s)),
            ("HTML", |s| encoding::decode_html_entity(s)),
            ("Unicode", |s| encoding::decode_unicode_escape(s)),
            ("Binary", |s| encoding::decode_binary(s)),
            ("Octal", |s| encoding::decode_octal(s)),
            ("Morse", |s| encoding::decode_morse(s)),
            ("Bacon", |s| encoding::decode_bacon(s)),
            ("Reverse", |s| {
                let r = encoding::decode_reverse(s);
                if encoding::contains_flag(&r) {
                    Some(r)
                } else {
                    None
                }
            }),
            ("Atbash", |s| encoding::decode_atbash(s)),
            ("Vigenere", |s| decode_vigenere_auto(s)),
            ("Beaufort", |s| decode_beaufort_auto(s)),
            ("Autokey", |s| decode_autokey_auto(s)),
            ("Affine", |s| decode_affine_auto(s)),
            ("RailFence", |s| decode_rail_fence_auto(s)),
            ("Columnar", |s| decode_columnar_auto(s)),
            ("Playfair", |s| decode_playfair_auto(s)),
        ];

        for (name, decoder) in decoders {
            if let Some(output) = decoder(input) {
                if output != input && Self::is_better(&output, input) {
                    return Some(CipherStep {
                        method: name.to_string(),
                        input: input.to_string(),
                        output,
                        confidence: 0.8,
                    });
                }
            }
        }

        // Caesar 暴力破解
        for shift in 1..26u8 {
            if shift == 13 {
                continue;
            }
            let output = encoding::caesar_shift(input, shift);
            if encoding::contains_flag(&output) {
                return Some(CipherStep {
                    method: format!("Caesar({shift})"),
                    input: input.to_string(),
                    output,
                    confidence: 0.9,
                });
            }
        }

        // XOR 暴力破解
        for key in [0x20u8, 0x41, 0x42, 0x55, 0xAA, 0xFF] {
            let output = encoding::xor_single(input, key);
            if encoding::contains_flag(&output) {
                return Some(CipherStep {
                    method: format!("XOR(0x{key:02X})"),
                    input: input.to_string(),
                    output,
                    confidence: 0.9,
                });
            }
        }

        None
    }

    fn is_readable(s: &str) -> bool {
        encoding::is_printable(s, 0.9) && encoding::contains_flag(s)
    }

    fn is_better(
        new: &str,
        old: &str,
    ) -> bool {
        fn ratio_as_f64(
            numer: usize,
            denom: usize,
        ) -> f64 {
            if denom == 0 {
                return 0.0;
            }
            let numer = f64::from(u32::try_from(numer).unwrap_or(u32::MAX));
            let denom = f64::from(u32::try_from(denom).unwrap_or(u32::MAX));
            numer / denom
        }

        if new.is_empty() || new.len() < 3 {
            return false;
        }
        let new_printable = new
            .chars()
            .filter(|c| c.is_ascii_graphic() || c.is_whitespace())
            .count();
        let old_printable = old
            .chars()
            .filter(|c| c.is_ascii_graphic() || c.is_whitespace())
            .count();
        let new_p = ratio_as_f64(new_printable, new.len());
        let old_p = ratio_as_f64(old_printable, old.len());
        new_p >= old_p * 0.9
    }
}

// === 自动解码辅助函数 ===

fn decode_vigenere_auto(s: &str) -> Option<String> {
    for key in ["KEY", "FLAG", "CTF", "SECRET", "PASS"] {
        let decoded = encoding::vigenere_decrypt(s, key);
        if encoding::contains_flag(&decoded) {
            return Some(decoded);
        }
    }
    None
}

fn decode_beaufort_auto(s: &str) -> Option<String> {
    for key in ["KEY", "FLAG", "CTF", "SECRET"] {
        let decoded = encoding::beaufort_decrypt(s, key);
        if encoding::contains_flag(&decoded) {
            return Some(decoded);
        }
    }
    None
}

fn decode_autokey_auto(s: &str) -> Option<String> {
    for key in ["KEY", "FLAG", "CTF", "SECRET"] {
        let decoded = encoding::autokey_decrypt(s, key);
        if encoding::contains_flag(&decoded) {
            return Some(decoded);
        }
    }
    None
}

fn decode_affine_auto(s: &str) -> Option<String> {
    const VALID_A: [u8; 12] = [1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25];
    VALID_A
        .par_iter()
        .flat_map(|&a| (0..26u8).into_par_iter().map(move |b| (a, b)))
        .find_map_any(|(a, b)| {
            let decoded = encoding::affine_decrypt(s, a, b);
            if encoding::contains_flag(&decoded) {
                Some(decoded)
            } else {
                None
            }
        })
}

fn decode_rail_fence_auto(s: &str) -> Option<String> {
    for rails in 2..=5 {
        let decoded = encoding::rail_fence_decrypt(s, rails);
        if encoding::contains_flag(&decoded) {
            return Some(decoded);
        }
    }
    None
}

fn decode_columnar_auto(s: &str) -> Option<String> {
    for cols in 2..=8 {
        let decoded = encoding::columnar_decrypt(s, cols);
        if encoding::contains_flag(&decoded) {
            return Some(decoded);
        }
    }
    None
}

fn decode_playfair_auto(s: &str) -> Option<String> {
    for key in ["KEY", "FLAG", "CTF", "SECRET", "PLAYFAIR"] {
        let decoded = encoding::playfair_decrypt(s, key);
        if encoding::contains_flag(&decoded) {
            return Some(decoded);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cipher_base64() {
        let cipher = Cipher::default();
        let result = cipher.decode("ZmxhZ3t0ZXN0fQ==");
        assert!(result.output.contains("flag{test}"));
    }

    #[test]
    fn test_cipher_rot13() {
        let cipher = Cipher::default();
        let result = cipher.decode("synt{grfg}");
        assert!(result.output.contains("flag{test}"));
    }
}
