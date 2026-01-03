//! 共享编码/解码模块
//! 提供所有基础解码函数，供 decoder.rs 和 cipher.rs 共用

// === 辅助函数 ===

const BASE91_CHARS: &[u8] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&()*+,./:;<=>?@[]^_`{|}~\"";
const BASE62_CHARS: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
const BACON_ALPHABET: [char; 24] = [
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T',
    'U', 'W', 'X', 'Y', 'Z',
];

/// 检查字符串是否可能是明文
///
/// # Examples
///
/// ```
/// use flag_detector::encoding::is_printable;
/// assert!(is_printable("Hello World", 0.8));
/// assert!(!is_printable("\x00\x01\x02", 0.8));
/// ```
#[must_use]
pub fn is_printable(
    s: &str,
    threshold: f32,
) -> bool {
    if s.is_empty() {
        return false;
    }
    let printable = s
        .chars()
        .filter(|c| c.is_ascii_graphic() || c.is_whitespace())
        .count();
    let printable = u32::try_from(printable).unwrap_or(u32::MAX);
    let len = u32::try_from(s.len()).unwrap_or(u32::MAX);
    f64::from(printable) / f64::from(len) >= f64::from(threshold)
}

/// 检查是否包含flag模式
///
/// # Examples
///
/// ```
/// use flag_detector::encoding::contains_flag;
/// assert!(contains_flag("flag{test}"));
/// assert!(contains_flag("CTF{hello}"));
/// assert!(!contains_flag("hello world"));
/// ```
#[must_use]
pub fn contains_flag(s: &str) -> bool {
    let lower = s.to_lowercase();
    lower.contains("flag{") || lower.contains("ctf{") || lower.contains("flag:")
}

/// 模逆运算
#[must_use]
pub fn mod_inverse(
    a: u8,
    m: u8,
) -> Option<u8> {
    let m_u16 = u16::from(m);
    let a_u16 = u16::from(a);
    (1..m).find(|&x| (a_u16 * u16::from(x)) % m_u16 == 1)
}

// === Base编码 ===

/// 解码 Base64 字符串
///
/// # Examples
///
/// ```
/// use flag_detector::encoding::decode_base64;
/// let result = decode_base64("SGVsbG8=");
/// assert_eq!(result, Some("Hello".to_string()));
/// ```
#[must_use]
pub fn decode_base64(s: &str) -> Option<String> {
    use base64::{engine::general_purpose, Engine};
    let cleaned = s.trim();
    if cleaned.len() < 4 {
        return None;
    }
    general_purpose::STANDARD
        .decode(cleaned)
        .ok()
        .or_else(|| general_purpose::URL_SAFE.decode(cleaned).ok())
        .and_then(|bytes| String::from_utf8(bytes).ok())
}

/// 解码 Base32 字符串
///
/// # Examples
///
/// ```
/// use flag_detector::encoding::decode_base32;
/// let result = decode_base32("JBSWY3DPEBLW64TMMQ======");
/// assert_eq!(result, Some("Hello World".to_string()));
/// ```
#[must_use]
pub fn decode_base32(s: &str) -> Option<String> {
    let cleaned = s.trim().to_uppercase();
    if cleaned.len() < 4 {
        return None;
    }
    data_encoding::BASE32
        .decode(cleaned.as_bytes())
        .ok()
        .and_then(|bytes| String::from_utf8(bytes).ok())
}

#[must_use]
pub fn decode_base58(s: &str) -> Option<String> {
    let cleaned = s.trim();
    if cleaned.len() < 4 {
        return None;
    }
    bs58::decode(cleaned)
        .into_vec()
        .ok()
        .and_then(|bytes| String::from_utf8(bytes).ok())
}

#[must_use]
pub fn decode_base85(s: &str) -> Option<String> {
    let cleaned = s.trim();
    if cleaned.len() < 4 {
        return None;
    }
    z85::decode(cleaned)
        .ok()
        .and_then(|bytes| String::from_utf8(bytes).ok())
}

#[must_use]
pub fn decode_base91(s: &str) -> Option<String> {
    let cleaned = s.trim();
    if cleaned.len() < 4 {
        return None;
    }

    let mut result = Vec::new();
    let mut v: u32 = 0;
    let mut b: u32 = 0;

    for c in cleaned.bytes() {
        let idx = u32::try_from(BASE91_CHARS.iter().position(|&x| x == c)?).ok()?;
        if b & 1 == 0 {
            v = idx;
            b = 1;
        } else {
            v = v.saturating_add(idx.saturating_mul(91));
            result.push(u8::try_from(v & 0xFF).ok()?);
            v >>= 8;
            if v > 0xFF || b > 13 {
                result.push(u8::try_from(v & 0xFF).ok()?);
                v = 0;
            }
            b = 0;
        }
    }
    if b == 1 {
        result.push(u8::try_from(v).ok()?);
    }
    String::from_utf8(result).ok()
}

#[must_use]
pub fn decode_base62(s: &str) -> Option<String> {
    let cleaned = s.trim();
    if cleaned.len() < 4 || !cleaned.chars().all(|c| c.is_ascii_alphanumeric()) {
        return None;
    }

    let mut num = 0u128;
    for c in cleaned.bytes() {
        let idx = BASE62_CHARS.iter().position(|&x| x == c)?;
        num = num.checked_mul(62)?.checked_add(idx as u128)?;
    }

    let mut bytes = Vec::new();
    while num > 0 {
        bytes.push((num & 0xFF) as u8);
        num >>= 8;
    }
    bytes.reverse();
    String::from_utf8(bytes).ok()
}

#[must_use]
pub fn decode_base16(s: &str) -> Option<String> {
    let cleaned = s.trim().to_uppercase().replace(' ', "");
    if !cleaned.len().is_multiple_of(2) || cleaned.len() < 4 {
        return None;
    }
    if !cleaned.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    hex::decode(&cleaned)
        .ok()
        .and_then(|bytes| String::from_utf8(bytes).ok())
}

#[must_use]
pub fn decode_ascii85(s: &str) -> Option<String> {
    let cleaned = s.trim();
    let data = if cleaned.starts_with("<~") && cleaned.ends_with("~>") {
        &cleaned[2..cleaned.len() - 2]
    } else {
        cleaned
    };
    if data.len() < 4 {
        return None;
    }

    let mut result = Vec::new();
    let mut group: u32 = 0;
    let mut count = 0;
    let push_byte = |out: &mut Vec<u8>, value: u32| -> Option<()> {
        out.push(u8::try_from(value & 0xFF).ok()?);
        Some(())
    };

    for c in data.chars() {
        if c.is_whitespace() {
            continue;
        }
        if c == 'z' && count == 0 {
            result.extend_from_slice(&[0, 0, 0, 0]);
            continue;
        }
        if !('!'..='u').contains(&c) {
            return None;
        }
        group = group.saturating_mul(85).saturating_add(c as u32 - 33);
        count += 1;
        if count == 5 {
            push_byte(&mut result, group >> 24)?;
            push_byte(&mut result, group >> 16)?;
            push_byte(&mut result, group >> 8)?;
            push_byte(&mut result, group)?;
            group = 0;
            count = 0;
        }
    }

    if count > 0 {
        for _ in count..5 {
            group = group.saturating_mul(85).saturating_add(84);
        }
        for i in 0..(count - 1) {
            push_byte(&mut result, group >> (24 - i * 8))?;
        }
    }
    String::from_utf8(result).ok()
}

/// 解码十六进制字符串
///
/// # Examples
///
/// ```
/// use flag_detector::encoding::decode_hex;
/// let result = decode_hex("48656c6c6f");
/// assert_eq!(result, Some("Hello".to_string()));
/// ```
#[must_use]
pub fn decode_hex(s: &str) -> Option<String> {
    let cleaned = s.trim().replace(' ', "").replace("0x", "");
    if !cleaned.len().is_multiple_of(2) || cleaned.len() < 4 {
        return None;
    }
    hex::decode(&cleaned)
        .ok()
        .and_then(|bytes| String::from_utf8(bytes).ok())
}

// === 经典密码 ===

/// 解码 ROT13 字符串
///
/// # Examples
///
/// ```
/// use flag_detector::encoding::decode_rot13;
/// let result = decode_rot13("Uryyb");
/// assert_eq!(result, Some("Hello".to_string()));
/// ```
#[must_use]
pub fn decode_rot13(s: &str) -> Option<String> {
    let decoded: String = s
        .chars()
        .map(|c| match c {
            'A'..='M' | 'a'..='m' => ((c as u8) + 13) as char,
            'N'..='Z' | 'n'..='z' => ((c as u8) - 13) as char,
            _ => c,
        })
        .collect();
    if decoded == s {
        None
    } else {
        Some(decoded)
    }
}

#[must_use]
pub fn decode_rot47(s: &str) -> Option<String> {
    let decoded: String = s
        .chars()
        .map(|c| {
            if ('!'..='~').contains(&c) {
                ((c as u8 - 33 + 47) % 94 + 33) as char
            } else {
                c
            }
        })
        .collect();
    if decoded == s {
        None
    } else {
        Some(decoded)
    }
}

#[must_use]
pub fn decode_atbash(s: &str) -> Option<String> {
    let decoded: String = s
        .chars()
        .map(|c| {
            if c.is_ascii_uppercase() {
                (b'Z' - (c as u8 - b'A')) as char
            } else if c.is_ascii_lowercase() {
                (b'z' - (c as u8 - b'a')) as char
            } else {
                c
            }
        })
        .collect();
    if decoded == s {
        None
    } else {
        Some(decoded)
    }
}

#[must_use]
pub fn caesar_shift(
    s: &str,
    shift: u8,
) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii_uppercase() {
                (((c as u8 - b'A') + 26 - shift) % 26 + b'A') as char
            } else if c.is_ascii_lowercase() {
                (((c as u8 - b'a') + 26 - shift) % 26 + b'a') as char
            } else {
                c
            }
        })
        .collect()
}

#[must_use]
pub fn decode_bacon(s: &str) -> Option<String> {
    let cleaned = s.trim().to_uppercase();
    let binary: String = if cleaned
        .chars()
        .all(|c| c == 'A' || c == 'B' || c.is_whitespace())
    {
        cleaned
            .chars()
            .filter(|c| !c.is_whitespace())
            .map(|c| if c == 'A' { '0' } else { '1' })
            .collect()
    } else if cleaned
        .chars()
        .all(|c| c == '0' || c == '1' || c.is_whitespace())
    {
        cleaned.chars().filter(|c| !c.is_whitespace()).collect()
    } else {
        return None;
    };

    if !binary.len().is_multiple_of(5) || binary.len() < 5 {
        return None;
    }

    let mut result = String::new();
    for chunk in binary.as_bytes().chunks(5) {
        let s = std::str::from_utf8(chunk).ok()?;
        let idx = u8::from_str_radix(s, 2).ok()? as usize;
        if idx >= BACON_ALPHABET.len() {
            return None;
        }
        result.push(BACON_ALPHABET[idx]);
    }
    Some(result)
}

// === 现代编码 ===

/// 解码 URL 编码字符串
///
/// # Examples
///
/// ```
/// use flag_detector::encoding::decode_url;
/// let result = decode_url("Hello%20World");
/// assert_eq!(result, Some("Hello World".to_string()));
/// ```
#[must_use]
pub fn decode_url(s: &str) -> Option<String> {
    if !s.contains('%') {
        return None;
    }
    urlencoding::decode(s)
        .ok()
        .map(std::borrow::Cow::into_owned)
        .filter(|d| d != s)
}

#[must_use]
pub fn decode_html_entity(s: &str) -> Option<String> {
    if !s.contains('&') || !s.contains(';') {
        return None;
    }
    let decoded = html_escape::decode_html_entities(s).into_owned();
    if decoded == s {
        None
    } else {
        Some(decoded)
    }
}

#[must_use]
pub fn decode_unicode_escape(s: &str) -> Option<String> {
    if !s.contains("\\u") && !s.contains("\\x") && !s.contains("\\U") {
        return None;
    }
    let mut result = String::new();
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.peek() {
                Some('u') => {
                    chars.next();
                    let hex: String = chars.by_ref().take(4).collect();
                    if let Ok(n) = u32::from_str_radix(&hex, 16) {
                        if let Some(ch) = char::from_u32(n) {
                            result.push(ch);
                            continue;
                        }
                    }
                    result.push('\\');
                    result.push('u');
                    result.push_str(&hex);
                }
                Some('U') => {
                    chars.next();
                    let hex: String = chars.by_ref().take(8).collect();
                    if let Ok(n) = u32::from_str_radix(&hex, 16) {
                        if let Some(ch) = char::from_u32(n) {
                            result.push(ch);
                            continue;
                        }
                    }
                    result.push('\\');
                    result.push('U');
                    result.push_str(&hex);
                }
                Some('x') => {
                    chars.next();
                    let hex: String = chars.by_ref().take(2).collect();
                    if let Ok(n) = u8::from_str_radix(&hex, 16) {
                        result.push(n as char);
                        continue;
                    }
                    result.push('\\');
                    result.push('x');
                    result.push_str(&hex);
                }
                _ => result.push(c),
            }
        } else {
            result.push(c);
        }
    }
    if result == s {
        None
    } else {
        Some(result)
    }
}

// === 二进制编码 ===

/// 解码二进制字符串
///
/// # Examples
///
/// ```
/// use flag_detector::encoding::decode_binary;
/// let result = decode_binary("01001000 01101001");
/// assert_eq!(result, Some("Hi".to_string()));
/// ```
#[must_use]
pub fn decode_binary(s: &str) -> Option<String> {
    let cleaned = s.trim().replace(' ', "");
    if !cleaned.len().is_multiple_of(8) || !cleaned.chars().all(|c| c == '0' || c == '1') {
        return None;
    }
    let bytes: Vec<u8> = cleaned
        .as_bytes()
        .chunks(8)
        .filter_map(|chunk| {
            let s = std::str::from_utf8(chunk).ok()?;
            u8::from_str_radix(s, 2).ok()
        })
        .collect();
    String::from_utf8(bytes).ok()
}

#[must_use]
pub fn decode_octal(s: &str) -> Option<String> {
    let parts: Vec<&str> = s.split([' ', '\\']).filter(|p| !p.is_empty()).collect();
    if parts.len() < 4 {
        return None;
    }
    let bytes: Vec<u8> = parts
        .iter()
        .filter_map(|p| u8::from_str_radix(p, 8).ok())
        .collect();
    if bytes.len() != parts.len() {
        return None;
    }
    String::from_utf8(bytes).ok()
}

// === Morse ===

pub const MORSE_TABLE: &[(&str, char)] = &[
    (".-", 'A'),
    ("-...", 'B'),
    ("-.-.", 'C'),
    ("-..", 'D'),
    (".", 'E'),
    ("..-.", 'F'),
    ("--.", 'G'),
    ("....", 'H'),
    ("..", 'I'),
    (".---", 'J'),
    ("-.-", 'K'),
    (".-..", 'L'),
    ("--", 'M'),
    ("-.", 'N'),
    ("---", 'O'),
    (".--.", 'P'),
    ("--.-", 'Q'),
    (".-.", 'R'),
    ("...", 'S'),
    ("-", 'T'),
    ("..-", 'U'),
    ("...-", 'V'),
    (".--", 'W'),
    ("-..-", 'X'),
    ("-.--", 'Y'),
    ("--..", 'Z'),
    (".----", '1'),
    ("..---", '2'),
    ("...--", '3'),
    ("....-", '4'),
    (".....", '5'),
    ("-....", '6'),
    ("--...", '7'),
    ("---..", '8'),
    ("----.", '9'),
    ("-----", '0'),
    (".-.-.-", '.'),
    ("--..--", ','),
    ("..--..", '?'),
    ("-.-.--", '!'),
    ("---...", ':'),
    ("-.-.-.", ';'),
    ("-.--.", '('),
    ("-.--.-", ')'),
    ("-....-", '-'),
    ("..--.-", '_'),
    ("-...-", '='),
    (".-.-.", '+'),
    ("-..-.", '/'),
    (".----.", '\''),
    (".-...", '&'),
    (".--.-.", '@'),
];

#[must_use]
pub fn decode_morse(s: &str) -> Option<String> {
    if !s.contains('.') && !s.contains('-') {
        return None;
    }
    let words: Vec<&str> = s.split("  ").collect();
    let mut result = String::new();
    for word in words {
        for code in word.split(' ') {
            if code.is_empty() {
                continue;
            }
            if let Some(&(_, ch)) = MORSE_TABLE.iter().find(|&&(m, _)| m == code) {
                result.push(ch);
            } else {
                return None;
            }
        }
        result.push(' ');
    }
    let result = result.trim().to_string();
    if result.is_empty() {
        None
    } else {
        Some(result)
    }
}

// === 其他 ===

#[must_use]
pub fn decode_reverse(s: &str) -> String {
    s.chars().rev().collect()
}

#[must_use]
pub fn xor_single(
    s: &str,
    key: u8,
) -> String {
    s.bytes().map(|b| (b ^ key) as char).collect()
}

#[must_use]
pub fn xor_multi(
    data: &[u8],
    key: &[u8],
) -> Vec<u8> {
    data.iter()
        .enumerate()
        .map(|(i, &b)| b ^ key[i % key.len()])
        .collect()
}

// === 高级密码 ===

#[must_use]
pub fn vigenere_decrypt(
    text: &str,
    key: &str,
) -> String {
    let key_bytes: Vec<u8> = key.to_uppercase().bytes().map(|b| b - b'A').collect();
    let mut key_idx = 0;
    text.chars()
        .map(|c| {
            if c.is_ascii_alphabetic() {
                let base = if c.is_uppercase() { b'A' } else { b'a' };
                let shift = key_bytes[key_idx % key_bytes.len()];
                key_idx += 1;
                ((c as u8 - base + 26 - shift) % 26 + base) as char
            } else {
                c
            }
        })
        .collect()
}

#[must_use]
pub fn affine_decrypt(
    text: &str,
    a: u8,
    b: u8,
) -> String {
    let a_inv = mod_inverse(a, 26).unwrap_or(1);
    text.chars()
        .map(|c| {
            if c.is_ascii_alphabetic() {
                let base = if c.is_uppercase() { b'A' } else { b'a' };
                let y = c as u8 - base;
                let x = (u16::from(a_inv) * (u16::from(y) + 26 - u16::from(b)) % 26) as u8;
                (x + base) as char
            } else {
                c
            }
        })
        .collect()
}

#[must_use]
pub fn rail_fence_decrypt(
    text: &str,
    rails: usize,
) -> String {
    let chars: Vec<char> = text.chars().collect();
    let len = chars.len();
    if len == 0 || rails < 2 {
        return text.to_string();
    }

    let cycle = 2 * rails - 2;
    let mut result = vec![' '; len];
    let mut idx = 0;

    for rail in 0..rails {
        let mut i = rail;
        let mut down = true;
        while i < len {
            result[i] = chars.get(idx).copied().unwrap_or(' ');
            idx += 1;
            if rail == 0 || rail == rails - 1 {
                i += cycle;
            } else {
                i += if down {
                    2 * (rails - 1 - rail)
                } else {
                    2 * rail
                };
                down = !down;
            }
        }
    }
    result.into_iter().collect()
}

#[must_use]
pub fn playfair_decrypt(
    text: &str,
    key: &str,
) -> String {
    let mut matrix = [[' '; 5]; 5];
    let mut used = [false; 26];
    used[9] = true; // J = I

    let mut idx = 0;
    for c in key.to_uppercase().chars().chain('A'..='Z') {
        if !c.is_ascii_uppercase() {
            continue;
        }
        let c_idx = (c as u8 - b'A') as usize;
        if c_idx == 9 {
            continue;
        }
        if !used[c_idx] {
            used[c_idx] = true;
            matrix[idx / 5][idx % 5] = c;
            idx += 1;
            if idx >= 25 {
                break;
            }
        }
    }

    let find_pos = |c: char| -> Option<(usize, usize)> {
        let c = if c == 'J' { 'I' } else { c };
        for (i, row) in matrix.iter().enumerate() {
            if let Some(j) = row.iter().position(|&x| x == c) {
                return Some((i, j));
            }
        }
        None
    };

    let cleaned: String = text
        .to_uppercase()
        .chars()
        .filter(char::is_ascii_uppercase)
        .collect();
    if !cleaned.len().is_multiple_of(2) {
        return text.to_string();
    }

    let mut result = String::new();
    let chars: Vec<char> = cleaned.chars().collect();

    for pair in chars.chunks(2) {
        if let (Some((r1, c1)), Some((r2, c2))) = (find_pos(pair[0]), find_pos(pair[1])) {
            if r1 == r2 {
                result.push(matrix[r1][(c1 + 4) % 5]);
                result.push(matrix[r2][(c2 + 4) % 5]);
            } else if c1 == c2 {
                result.push(matrix[(r1 + 4) % 5][c1]);
                result.push(matrix[(r2 + 4) % 5][c2]);
            } else {
                result.push(matrix[r1][c2]);
                result.push(matrix[r2][c1]);
            }
        }
    }
    result
}

#[must_use]
pub fn beaufort_decrypt(
    text: &str,
    key: &str,
) -> String {
    let key_bytes: Vec<u8> = key.to_uppercase().bytes().map(|b| b - b'A').collect();
    let mut key_idx = 0;
    text.chars()
        .map(|c| {
            if c.is_ascii_alphabetic() {
                let base = if c.is_uppercase() { b'A' } else { b'a' };
                let k = key_bytes[key_idx % key_bytes.len()];
                let p = c as u8 - base;
                key_idx += 1;
                ((k + 26 - p) % 26 + base) as char
            } else {
                c
            }
        })
        .collect()
}

#[must_use]
pub fn autokey_decrypt(
    text: &str,
    primer: &str,
) -> String {
    let mut key: Vec<u8> = primer.to_uppercase().bytes().map(|b| b - b'A').collect();
    let mut result = String::new();

    for c in text.chars() {
        if c.is_ascii_alphabetic() {
            let base = if c.is_uppercase() { b'A' } else { b'a' };
            let y = c as u8 - base;
            let k = key.remove(0);
            let x = (y + 26 - k) % 26;
            result.push((x + base) as char);
            key.push(x);
        } else {
            result.push(c);
        }
    }
    result
}

#[must_use]
pub fn columnar_decrypt(
    text: &str,
    cols: usize,
) -> String {
    let chars: Vec<char> = text.chars().collect();
    let len = chars.len();
    if len == 0 || cols < 2 {
        return text.to_string();
    }

    let rows = len.div_ceil(cols);
    let full_cols = len % cols;
    let full_cols = if full_cols == 0 { cols } else { full_cols };

    let mut result = vec![' '; len];
    let mut idx = 0;

    for col in 0..cols {
        let col_len = if col < full_cols { rows } else { rows - 1 };
        for row in 0..col_len {
            let pos = row * cols + col;
            if pos < len && idx < len {
                result[pos] = chars[idx];
                idx += 1;
            }
        }
    }
    result.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base64() {
        assert_eq!(decode_base64("ZmxhZ3t0ZXN0fQ=="), Some("flag{test}".into()));
    }

    #[test]
    fn test_rot13() {
        assert_eq!(decode_rot13("synt{grfg}"), Some("flag{test}".into()));
    }

    #[test]
    fn test_hex() {
        assert_eq!(decode_hex("666c6167"), Some("flag".into()));
    }

    #[test]
    fn test_contains_flag() {
        assert!(contains_flag("flag{test}"));
        assert!(contains_flag("CTF{hello}"));
        assert!(!contains_flag("hello world"));
    }
}
