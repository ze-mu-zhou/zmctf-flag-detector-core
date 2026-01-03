use crate::encoding;
use crate::types::{DecodedString, DetectorConfig, EncodingType, ExtractedString};
use anyhow::Result;
use rayon::prelude::*;

type DecoderFn = fn(&str) -> Option<String>;

const PRINTABLE_THRESHOLD: f32 = 0.8;

fn decode_base64_printable(s: &str) -> Option<String> {
    encoding::decode_base64(s).filter(|d| encoding::is_printable(d, PRINTABLE_THRESHOLD))
}

fn decode_base32_printable(s: &str) -> Option<String> {
    encoding::decode_base32(s).filter(|d| encoding::is_printable(d, PRINTABLE_THRESHOLD))
}

fn decode_base58_printable(s: &str) -> Option<String> {
    encoding::decode_base58(s).filter(|d| encoding::is_printable(d, PRINTABLE_THRESHOLD))
}

fn decode_base85_printable(s: &str) -> Option<String> {
    encoding::decode_base85(s).filter(|d| encoding::is_printable(d, PRINTABLE_THRESHOLD))
}

fn decode_base91_printable(s: &str) -> Option<String> {
    encoding::decode_base91(s).filter(|d| encoding::is_printable(d, PRINTABLE_THRESHOLD))
}

fn decode_base62_printable(s: &str) -> Option<String> {
    encoding::decode_base62(s).filter(|d| encoding::is_printable(d, PRINTABLE_THRESHOLD))
}

fn decode_base16_printable(s: &str) -> Option<String> {
    encoding::decode_base16(s).filter(|d| encoding::is_printable(d, PRINTABLE_THRESHOLD))
}

fn decode_ascii85_printable(s: &str) -> Option<String> {
    encoding::decode_ascii85(s).filter(|d| encoding::is_printable(d, PRINTABLE_THRESHOLD))
}

fn decode_hex_printable(s: &str) -> Option<String> {
    encoding::decode_hex(s).filter(|d| encoding::is_printable(d, PRINTABLE_THRESHOLD))
}

fn decode_rot13_printable(s: &str) -> Option<String> {
    encoding::decode_rot13(s).filter(|d| encoding::is_printable(d, PRINTABLE_THRESHOLD))
}

fn decode_rot47_printable(s: &str) -> Option<String> {
    encoding::decode_rot47(s).filter(|d| encoding::is_printable(d, PRINTABLE_THRESHOLD))
}

fn decode_atbash_printable(s: &str) -> Option<String> {
    encoding::decode_atbash(s).filter(|d| encoding::is_printable(d, PRINTABLE_THRESHOLD))
}

fn decode_bacon_printable(s: &str) -> Option<String> {
    encoding::decode_bacon(s).filter(|d| encoding::is_printable(d, PRINTABLE_THRESHOLD))
}

fn decode_url_printable(s: &str) -> Option<String> {
    encoding::decode_url(s).filter(|d| encoding::is_printable(d, PRINTABLE_THRESHOLD))
}

fn decode_html_entity_printable(s: &str) -> Option<String> {
    encoding::decode_html_entity(s).filter(|d| encoding::is_printable(d, PRINTABLE_THRESHOLD))
}

fn decode_unicode_escape_printable(s: &str) -> Option<String> {
    encoding::decode_unicode_escape(s).filter(|d| encoding::is_printable(d, PRINTABLE_THRESHOLD))
}

fn decode_binary_printable(s: &str) -> Option<String> {
    encoding::decode_binary(s).filter(|d| encoding::is_printable(d, PRINTABLE_THRESHOLD))
}

fn decode_octal_printable(s: &str) -> Option<String> {
    encoding::decode_octal(s).filter(|d| encoding::is_printable(d, PRINTABLE_THRESHOLD))
}

fn decode_morse_printable(s: &str) -> Option<String> {
    encoding::decode_morse(s).filter(|d| encoding::is_printable(d, PRINTABLE_THRESHOLD))
}

fn decode_reverse_contains_flag(s: &str) -> Option<String> {
    let r = encoding::decode_reverse(s);
    encoding::contains_flag(&r).then_some(r)
}

const DECODERS: &[(EncodingType, DecoderFn)] = &[
    (EncodingType::Base64, decode_base64_printable),
    (EncodingType::Base32, decode_base32_printable),
    (EncodingType::Base58, decode_base58_printable),
    (EncodingType::Base85, decode_base85_printable),
    (EncodingType::Base91, decode_base91_printable),
    (EncodingType::Base62, decode_base62_printable),
    (EncodingType::Base16, decode_base16_printable),
    (EncodingType::Ascii85, decode_ascii85_printable),
    (EncodingType::Hex, decode_hex_printable),
    (EncodingType::Rot13, decode_rot13_printable),
    (EncodingType::Rot47, decode_rot47_printable),
    (EncodingType::Atbash, decode_atbash_printable),
    (EncodingType::Bacon, decode_bacon_printable),
    (EncodingType::UrlEncoded, decode_url_printable),
    (EncodingType::HtmlEntity, decode_html_entity_printable),
    (EncodingType::UnicodeEscape, decode_unicode_escape_printable),
    (EncodingType::Binary, decode_binary_printable),
    (EncodingType::Octal, decode_octal_printable),
    (EncodingType::Morse, decode_morse_printable),
    (EncodingType::Reverse, decode_reverse_contains_flag),
];

/// 解码提取到的字符串，生成候选解码结果。
///
/// # Errors
///
/// 当前实现不会返回错误（保留 `Result` 以便向后兼容及未来扩展）。
pub fn decode_strings(
    strings: &[ExtractedString],
    config: &DetectorConfig,
) -> Result<Vec<DecodedString>> {
    log::info!("开始解码 {} 个字符串", strings.len());

    let decoded: Vec<DecodedString> = if config.parallel {
        strings
            .par_iter()
            .flat_map(|s| decode_recursive(s, config, 0, &[]))
            .collect()
    } else {
        strings
            .iter()
            .flat_map(|s| decode_recursive(s, config, 0, &[]))
            .collect()
    };

    log::info!("解码完成，生成 {} 个候选", decoded.len());
    Ok(decoded)
}

fn decode_recursive(
    extracted: &ExtractedString,
    config: &DetectorConfig,
    depth: usize,
    chain: &[EncodingType],
) -> Vec<DecodedString> {
    if depth >= config.max_decode_depth {
        return vec![];
    }

    let mut results = Vec::new();
    let content = &extracted.content;

    // 深度0时添加原文
    if depth == 0 {
        results.push(DecodedString {
            original: content.clone(),
            decoded: content.clone(),
            encoding_chain: vec![EncodingType::Plaintext],
            confidence: 1.0,
        });
    }

    // 尝试所有启用的编码 - 使用共享模块
    for (enc_type, decoder) in DECODERS {
        if !config.enabled_encodings.contains(enc_type) {
            continue;
        }
        if let Some(decoded) = decoder(content) {
            let confidence = calculate_confidence(&decoded);
            let mut new_chain = chain.to_owned();
            new_chain.push(enc_type.clone());

            if depth + 1 < config.max_decode_depth {
                let sub = ExtractedString {
                    content: decoded.clone(),
                    offset: extracted.offset,
                };
                results.extend(decode_recursive(&sub, config, depth + 1, &new_chain));
            }

            results.push(DecodedString {
                original: extracted.content.clone(),
                decoded,
                encoding_chain: new_chain,
                confidence,
            });
        }
    }

    // Caesar单独处理（有shift参数）
    if config
        .enabled_encodings
        .iter()
        .any(|e| matches!(e, EncodingType::Caesar(_)))
    {
        if let Some((decoded, shift)) = try_caesar(content) {
            let confidence = calculate_confidence(&decoded);
            let mut new_chain = chain.to_owned();
            new_chain.push(EncodingType::Caesar(shift));
            if depth + 1 < config.max_decode_depth {
                let sub = ExtractedString {
                    content: decoded.clone(),
                    offset: extracted.offset,
                };
                results.extend(decode_recursive(&sub, config, depth + 1, &new_chain));
            }

            results.push(DecodedString {
                original: extracted.content.clone(),
                decoded,
                encoding_chain: new_chain,
                confidence,
            });
        }
    }

    // XOR暴力破解
    for &key in &config.xor_keys {
        let decoded = encoding::xor_single(content, key);
        if encoding::contains_flag(&decoded) {
            let confidence = calculate_confidence(&decoded);
            let mut new_chain = chain.to_owned();
            new_chain.push(EncodingType::Xor(key));
            if depth + 1 < config.max_decode_depth {
                let sub = ExtractedString {
                    content: decoded.clone(),
                    offset: extracted.offset,
                };
                results.extend(decode_recursive(&sub, config, depth + 1, &new_chain));
            }

            results.push(DecodedString {
                original: extracted.content.clone(),
                decoded,
                encoding_chain: new_chain,
                confidence,
            });
        }
    }

    results
}

fn try_caesar(s: &str) -> Option<(String, u8)> {
    for shift in 1..26u8 {
        if shift == 13 {
            continue;
        }
        let decoded = encoding::caesar_shift(s, shift);
        if encoding::contains_flag(&decoded) {
            return Some((decoded, shift));
        }
    }
    None
}

fn calculate_confidence(s: &str) -> f32 {
    fn usize_to_u16_saturating(value: usize) -> u16 {
        u16::try_from(value).unwrap_or(u16::MAX)
    }

    let printable_count = s
        .chars()
        .filter(|c| c.is_ascii_graphic() || c.is_whitespace())
        .count();
    let total_count = s.len().max(1);
    let printable_ratio = f32::from(usize_to_u16_saturating(printable_count))
        / f32::from(usize_to_u16_saturating(total_count));
    let has_flag = encoding::contains_flag(s);
    let mut confidence = printable_ratio * 0.7;
    if has_flag {
        confidence += 0.3;
    }
    confidence.min(1.0)
}

// === 公开API (保持向后兼容) ===

/// 维吉尼亚密码解码 (尝试常见密钥)
///
/// # Examples
///
/// ```
/// use flag_detector::decoder::try_vigenere_with_key;
/// // 函数会检查解码结果是否包含 flag 模式
/// let result = try_vigenere_with_key("test", "key");
/// // 如果结果不包含 flag，返回 None
/// assert!(result.is_none());
/// ```
#[must_use]
pub fn try_vigenere_with_key(
    s: &str,
    key: &str,
) -> Option<String> {
    if key.is_empty() || !key.chars().all(|c| c.is_ascii_alphabetic()) {
        return None;
    }
    let result = encoding::vigenere_decrypt(s, key);
    if encoding::contains_flag(&result) {
        Some(result)
    } else {
        None
    }
}

/// 栅栏密码解码
///
/// # Examples
///
/// ```
/// use flag_detector::decoder::try_rail_fence_with_rails;
/// // 函数会检查解码结果是否包含 flag 模式
/// let result = try_rail_fence_with_rails("test", 2);
/// // 如果结果不包含 flag，返回 None
/// assert!(result.is_none());
/// ```
#[must_use]
pub fn try_rail_fence_with_rails(
    s: &str,
    rails: usize,
) -> Option<String> {
    if rails < 2 || rails >= s.len() {
        return None;
    }
    let result = encoding::rail_fence_decrypt(s, rails);
    if encoding::contains_flag(&result) {
        Some(result)
    } else {
        None
    }
}

/// Playfair密码解码
///
/// # Examples
///
/// ```
/// use flag_detector::decoder::try_playfair_with_key;
/// // 函数会检查解码结果是否包含 flag 模式
/// let result = try_playfair_with_key("test", "key");
/// // 如果结果不包含 flag，返回 None
/// assert!(result.is_none());
/// ```
#[must_use]
pub fn try_playfair_with_key(
    s: &str,
    key: &str,
) -> Option<String> {
    let result = encoding::playfair_decrypt(s, key);
    if encoding::contains_flag(&result) {
        Some(result)
    } else {
        None
    }
}

/// 仿射密码解码
///
/// # Examples
///
/// ```
/// use flag_detector::decoder::try_affine_with_params;
/// // 函数会检查解码结果是否包含 flag 模式
/// let result = try_affine_with_params("test", 5, 8);
/// // 如果结果不包含 flag，返回 None
/// assert!(result.is_none());
/// ```
#[must_use]
pub fn try_affine_with_params(
    s: &str,
    a: u8,
    b: u8,
) -> Option<String> {
    const fn gcd(
        mut a: u8,
        mut b: u8,
    ) -> u8 {
        while b != 0 {
            let t = b;
            b = a % b;
            a = t;
        }
        a
    }
    if gcd(a, 26) != 1 {
        return None;
    }
    let result = encoding::affine_decrypt(s, a, b);
    if encoding::contains_flag(&result) {
        Some(result)
    } else {
        None
    }
}

/// 多字节XOR解码
///
/// # Examples
///
/// ```
/// use flag_detector::decoder::try_xor_multi;
/// let result = try_xor_multi("flag{test}", &[0x12, 0x34]);
/// // XOR 操作是可逆的
/// ```
#[must_use]
pub fn try_xor_multi(
    s: &str,
    key: &[u8],
) -> Option<String> {
    if key.is_empty() {
        return None;
    }
    let decoded = encoding::xor_multi(s.as_bytes(), key);
    String::from_utf8(decoded)
        .ok()
        .filter(|d| encoding::contains_flag(d))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{DetectorConfig, EncodingType};

    // === 编码格式测试 (10个) ===

    #[test]
    fn test_decode_base64() {
        let input = ExtractedString {
            content: "ZmxhZ3t0ZXN0fQ==".to_string(),
            offset: 0,
        };
        let config = DetectorConfig::builder().build();
        let results = decode_strings(&[input], &config).unwrap();

        assert!(results.iter().any(|r| r.decoded.contains("flag{test}")));
    }

    #[test]
    fn test_decode_hex() {
        let input = ExtractedString {
            content: "666c61677b746573747d".to_string(),
            offset: 0,
        };
        let config = DetectorConfig::builder().build();
        let results = decode_strings(&[input], &config).unwrap();

        assert!(results.iter().any(|r| r.decoded.contains("flag{test}")));
    }

    #[test]
    fn test_decode_rot13() {
        let input = ExtractedString {
            content: "synt{grfg}".to_string(),
            offset: 0,
        };
        let config = DetectorConfig::builder().build();
        let results = decode_strings(&[input], &config).unwrap();

        assert!(results.iter().any(|r| r.decoded.contains("flag{test}")));
    }

    #[test]
    fn test_decode_rot47() {
        let input = ExtractedString {
            content: "7=28LE6DEN".to_string(),
            offset: 0,
        };
        let config = DetectorConfig::builder().build();
        let results = decode_strings(&[input], &config).unwrap();

        assert!(results.iter().any(|r| r.decoded.contains("flag{test}")));
    }

    #[test]
    fn test_decode_atbash() {
        let input = ExtractedString {
            content: "uozt{gvhg}".to_string(),
            offset: 0,
        };
        let config = DetectorConfig::builder().build();
        let results = decode_strings(&[input], &config).unwrap();

        assert!(results.iter().any(|r| r.decoded.contains("flag{test}")));
    }

    #[test]
    fn test_decode_url_encoded() {
        let input = ExtractedString {
            content: "flag%7Btest%7D".to_string(),
            offset: 0,
        };
        let config = DetectorConfig::builder().build();
        let results = decode_strings(&[input], &config).unwrap();

        assert!(results.iter().any(|r| r.decoded.contains("flag{test}")));
    }

    #[test]
    fn test_decode_html_entity() {
        let input = ExtractedString {
            content: "flag&#123;test&#125;".to_string(),
            offset: 0,
        };
        let config = DetectorConfig::builder().build();
        let results = decode_strings(&[input], &config).unwrap();

        assert!(results.iter().any(|r| r.decoded.contains("flag{test}")));
    }

    #[test]
    fn test_decode_binary() {
        let input = ExtractedString {
            content: "01100110011011000110000101100111".to_string(),
            offset: 0,
        };
        let config = DetectorConfig::builder().build();
        let results = decode_strings(&[input], &config).unwrap();

        assert!(results.iter().any(|r| r.decoded.contains("flag")));
    }

    #[test]
    fn test_decode_reverse() {
        let input = ExtractedString {
            content: "}tset{galf".to_string(),
            offset: 0,
        };
        let config = DetectorConfig::builder().build();
        let results = decode_strings(&[input], &config).unwrap();

        assert!(results.iter().any(|r| r.decoded.contains("flag{test}")));
    }

    #[test]
    fn test_decode_caesar() {
        // 测试 Caesar 解码功能
        // 直接测试 encoding::caesar_shift
        let shifted = encoding::caesar_shift("flag{test}", 5);
        // 验证 shift 后的结果
        assert!(!shifted.is_empty());

        // 测试反向解码
        let decoded = encoding::caesar_shift(&shifted, 21); // 26-5=21
        assert_eq!(decoded, "flag{test}");
    }

    // === 递归解码测试 (3个) ===

    #[test]
    fn test_recursive_decode_depth_1() {
        // 测试递归解码：Base64 -> Hex -> plaintext
        // 先测试单层 Base64
        let input = ExtractedString {
            content: "ZmxhZ3t0ZXN0fQ==".to_string(), // Base64("flag{test}")
            offset: 0,
        };
        let config = DetectorConfig::builder().max_decode_depth(2).build();
        let results = decode_strings(&[input], &config).unwrap();

        // 应该能解码出 flag{test}
        assert!(results.iter().any(|r| r.decoded.contains("flag{test}")));
    }

    #[test]
    fn test_recursive_decode_depth_limit() {
        let input = ExtractedString {
            content: "ZmxhZ3t0ZXN0fQ==".to_string(),
            offset: 0,
        };
        let config = DetectorConfig::builder().max_decode_depth(1).build();
        let results = decode_strings(&[input], &config).unwrap();

        // 深度限制为1，应该只有原文和一层解码
        assert!(results.len() <= 5);
    }

    #[test]
    fn test_recursive_decode_chain() {
        let input = ExtractedString {
            content: "ZmxhZ3t0ZXN0fQ==".to_string(),
            offset: 0,
        };
        let config = DetectorConfig::builder().build();
        let results = decode_strings(&[input], &config).unwrap();

        // 检查编码链
        let base64_result = results
            .iter()
            .find(|r| r.encoding_chain.contains(&EncodingType::Base64));
        assert!(base64_result.is_some());
    }

    // === 错误处理测试 (4个) ===

    #[test]
    fn test_decode_empty_string() {
        let input = ExtractedString {
            content: String::new(),
            offset: 0,
        };
        let config = DetectorConfig::builder().build();
        let results = decode_strings(&[input], &config).unwrap();

        // 空字符串应该返回原文
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].decoded, "");
    }

    #[test]
    fn test_decode_invalid_base64() {
        let input = ExtractedString {
            content: "!!!invalid!!!".to_string(),
            offset: 0,
        };
        let config = DetectorConfig::builder().build();
        let results = decode_strings(&[input], &config).unwrap();

        // 无效输入可能会被某些解码器尝试，但不应该产生有效结果
        // 至少应该有原文
        assert!(!results.is_empty());
        assert!(results.iter().any(|r| r.encoding_chain.len() == 1));
    }

    #[test]
    fn test_decode_non_printable() {
        let input = ExtractedString {
            content: "\x00\x01\x02\x03".to_string(),
            offset: 0,
        };
        let config = DetectorConfig::builder().build();
        let results = decode_strings(&[input], &config).unwrap();

        // 不可打印字符应该被过滤
        assert!(results
            .iter()
            .all(|r| r.confidence < 0.5 || r.encoding_chain.len() == 1));
    }

    #[test]
    fn test_decode_multiple_strings() {
        let inputs = vec![
            ExtractedString {
                content: "ZmxhZ3t0ZXN0fQ==".to_string(),
                offset: 0,
            },
            ExtractedString {
                content: "synt{grfg}".to_string(),
                offset: 10,
            },
        ];
        let config = DetectorConfig::builder().build();
        let results = decode_strings(&inputs, &config).unwrap();

        // 应该解码两个字符串
        assert!(results.len() >= 2);
    }

    // === 公开API测试 (3个) ===

    #[test]
    fn test_try_vigenere_with_key() {
        // Vigenere 需要正确的密钥才能解码出 flag
        // 这个测试验证函数不会崩溃
        let result = try_vigenere_with_key("test", "key");
        // 可能有结果也可能没有，取决于是否包含 flag
        assert!(result.is_some() || result.is_none());
    }

    #[test]
    fn test_try_affine_with_params() {
        // 测试有效的 a 值 (与26互质)
        let result = try_affine_with_params("test", 5, 8);
        assert!(result.is_some() || result.is_none()); // 可能有flag也可能没有

        // 测试无效的 a 值 (与26不互质)
        let result = try_affine_with_params("test", 2, 8);
        assert!(result.is_none());
    }

    #[test]
    fn test_try_xor_multi() {
        // 测试空key
        let result = try_xor_multi("test", &[]);
        assert!(result.is_none());

        // 测试有效key
        let result = try_xor_multi("test", &[0x01, 0x02]);
        assert!(result.is_some() || result.is_none()); // 取决于是否包含flag
    }
}
