//! 密码规则引擎
//!
//! 实现hashcat风格的密码变换规则，用于字典攻击

use serde::{Deserialize, Serialize};

/// 密码变换规则
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Rule {
    /// `:` - 不做任何操作
    Noop,
    /// `l` - 全部小写
    Lowercase,
    /// `u` - 全部大写
    Uppercase,
    /// `c` - 首字母大写，其余小写
    Capitalize,
    /// `C` - 首字母小写，其余大写
    InvertCapitalize,
    /// `t` - 切换每个字符的大小写
    ToggleCase,
    /// `TN` - 切换位置N的大小写
    ToggleAt(usize),
    /// `r` - 反转字符串
    Reverse,
    /// `d` - 复制整个字符串
    Duplicate,
    /// `pN` - 复制字符串N次
    DuplicateTimes(usize),
    /// `f` - 反射（追加反转的字符串）
    Reflect,
    /// `{` - 左旋转
    RotateLeft,
    /// `}` - 右旋转
    RotateRight,
    /// `$X` - 追加字符X
    Append(char),
    /// `^X` - 前置字符X
    Prepend(char),
    /// `[` - 删除第一个字符
    DeleteFirst,
    /// `]` - 删除最后一个字符
    DeleteLast,
    /// `DN` - 删除位置N的字符
    DeleteAt(usize),
    /// `xNM` - 从位置N提取M个字符
    Extract(usize, usize),
    /// `ONM` - 从位置N删除M个字符
    Omit(usize, usize),
    /// `iNX` - 在位置N插入字符X
    Insert(usize, char),
    /// `oNX` - 用字符X覆盖位置N
    Overstrike(usize, char),
    /// `'N` - 截断到N个字符
    Truncate(usize),
    /// `sXY` - 将所有X替换为Y
    Replace(char, char),
    /// `@X` - 删除所有X字符
    Purge(char),
    /// `zN` - 复制第一个字符N次
    DupeFirstN(usize),
    /// `ZN` - 复制最后一个字符N次
    DupeLastN(usize),
    /// `q` - 复制每个字符
    DupeAll,
    /// `k` - 交换前两个字符
    SwapFirst,
    /// `K` - 交换后两个字符
    SwapLast,
    /// `*NM` - 交换位置N和M的字符
    SwapAt(usize, usize),
    /// `+N` - 位置N的字符ASCII值+1
    Increment(usize),
    /// `-N` - 位置N的字符ASCII值-1
    Decrement(usize),
    /// `E` - 标题格式（每个单词首字母大写）
    Title,
    /// Leetspeak变换
    Leetspeak,
    /// 追加数字序列 (1, 12, 123, etc.)
    AppendNumbers(usize),
    /// 追加年份 (2020, 2021, etc.)
    AppendYear(u16),
    /// 追加常见后缀 (!, @, #, 123, etc.)
    AppendCommonSuffix,
}

/// 规则引擎
#[derive(Debug, Clone, Default)]
pub struct RuleEngine {
    rules: Vec<Rule>,
}

impl RuleEngine {
    #[must_use]
    pub const fn new() -> Self {
        Self { rules: Vec::new() }
    }

    /// 从规则列表创建
    #[must_use]
    pub const fn with_rules(rules: Vec<Rule>) -> Self {
        Self { rules }
    }

    /// 添加规则
    pub fn add_rule(
        &mut self,
        rule: Rule,
    ) {
        self.rules.push(rule);
    }

    /// 解析 hashcat 规则字符串。
    ///
    /// # Errors
    ///
    /// 当规则字符串包含未知指令或参数不完整时返回错误。
    pub fn parse_rule(rule_str: &str) -> Result<Vec<Rule>, String> {
        let mut rules = Vec::new();
        let chars: Vec<char> = rule_str.chars().collect();
        let mut i = 0;

        while i < chars.len() {
            if matches!(chars[i], ' ' | '\t') {
                i += 1;
                continue;
            }

            let rule = parse_rule_at(&chars, &mut i)?;
            rules.push(rule);
            i += 1;
        }

        Ok(rules)
    }

    /// 应用单个规则到密码
    #[must_use]
    pub fn apply_rule(
        word: &str,
        rule: &Rule,
    ) -> String {
        match rule {
            Rule::Noop => word.to_string(),
            Rule::Lowercase => word.to_lowercase(),
            Rule::Uppercase => word.to_uppercase(),
            Rule::Capitalize => capitalize_lower(word),
            Rule::InvertCapitalize => invert_capitalize(word),
            Rule::ToggleCase => toggle_case(word),
            Rule::ToggleAt(n) => toggle_at(word, *n),
            Rule::Reverse => word.chars().rev().collect(),
            Rule::Duplicate => format!("{word}{word}"),
            Rule::DuplicateTimes(n) => word.repeat(n.saturating_add(1)),
            Rule::Reflect => reflect(word),
            Rule::RotateLeft => rotate_left(word),
            Rule::RotateRight => rotate_right(word),
            Rule::Append(c) => format!("{word}{c}"),
            Rule::Prepend(c) => format!("{c}{word}"),
            Rule::DeleteFirst => delete_first(word),
            Rule::DeleteLast => delete_last(word),
            Rule::DeleteAt(n) => delete_at(word, *n),
            Rule::Extract(n, m) => extract_range(word, *n, *m),
            Rule::Omit(n, m) => omit_range(word, *n, *m),
            Rule::Insert(n, c) => insert_at(word, *n, *c),
            Rule::Overstrike(n, c) => overstrike(word, *n, *c),
            Rule::Truncate(n) => truncate_chars(word, *n),
            Rule::Replace(x, y) => replace_char(word, *x, *y),
            Rule::Purge(c) => purge_char(word, *c),
            Rule::DupeFirstN(n) => dupe_first_n(word, *n),
            Rule::DupeLastN(n) => dupe_last_n(word, *n),
            Rule::DupeAll => dupe_all(word),
            Rule::SwapFirst => swap_first(word),
            Rule::SwapLast => swap_last(word),
            Rule::SwapAt(n, m) => swap_at(word, *n, *m),
            Rule::Increment(n) => inc_char(word, *n),
            Rule::Decrement(n) => dec_char(word, *n),
            Rule::Title => title_case(word),
            Rule::Leetspeak => leetspeak(word),
            Rule::AppendNumbers(n) => append_numbers(word, *n),
            Rule::AppendYear(year) => format!("{word}{year}"),
            Rule::AppendCommonSuffix => {
                // 返回原始密码，实际使用时会生成多个变体
                word.to_string()
            }
        }
    }

    /// 应用所有规则到密码
    #[must_use]
    pub fn apply(
        &self,
        word: &str,
    ) -> String {
        let mut result = word.to_string();
        for rule in &self.rules {
            result = Self::apply_rule(&result, rule);
        }
        result
    }

    /// 生成密码的所有常见变体
    #[must_use]
    pub fn generate_variants(word: &str) -> Vec<String> {
        let mut variants = vec![word.to_string()];

        // 大小写变体
        variants.push(word.to_lowercase());
        variants.push(word.to_uppercase());
        variants.push(Self::apply_rule(word, &Rule::Capitalize));

        // Leetspeak
        variants.push(Self::apply_rule(word, &Rule::Leetspeak));

        // 常见后缀
        for suffix in [
            "1", "12", "123", "!", "@", "#", "1!", "123!", "2020", "2021", "2022", "2023", "2024",
            "2025",
        ] {
            variants.push(format!("{word}{suffix}"));
            let lower = word.to_lowercase();
            variants.push(format!("{lower}{suffix}"));
            let capitalized = Self::apply_rule(word, &Rule::Capitalize);
            variants.push(format!("{capitalized}{suffix}"));
        }

        // 常见前缀
        for prefix in ["1", "123", "@"] {
            variants.push(format!("{prefix}{word}"));
        }

        // 反转
        variants.push(Self::apply_rule(word, &Rule::Reverse));

        // 复制
        variants.push(Self::apply_rule(word, &Rule::Duplicate));

        // 去重
        variants.sort();
        variants.dedup();
        variants
    }
}

fn parse_rule_at(
    chars: &[char],
    i: &mut usize,
) -> Result<Rule, String> {
    let c = *chars.get(*i).ok_or_else(|| "期望规则字符".to_string())?;

    match c {
        ':' => Ok(Rule::Noop),
        'l' => Ok(Rule::Lowercase),
        'u' => Ok(Rule::Uppercase),
        'c' => Ok(Rule::Capitalize),
        'C' => Ok(Rule::InvertCapitalize),
        't' => Ok(Rule::ToggleCase),
        'T' => Ok(Rule::ToggleAt(parse_pos(chars, i)?)),
        'r' => Ok(Rule::Reverse),
        'd' => Ok(Rule::Duplicate),
        'p' => Ok(Rule::DuplicateTimes(parse_pos(chars, i)?)),
        'f' => Ok(Rule::Reflect),
        '{' => Ok(Rule::RotateLeft),
        '}' => Ok(Rule::RotateRight),
        '$' => Ok(Rule::Append(next_char(
            chars,
            i,
            "Expected character after $",
        )?)),
        '^' => Ok(Rule::Prepend(next_char(
            chars,
            i,
            "Expected character after ^",
        )?)),
        '[' => Ok(Rule::DeleteFirst),
        ']' => Ok(Rule::DeleteLast),
        'D' => Ok(Rule::DeleteAt(parse_pos(chars, i)?)),
        'x' => {
            let n = parse_pos(chars, i)?;
            let m = parse_pos(chars, i)?;
            Ok(Rule::Extract(n, m))
        }
        'O' => {
            let n = parse_pos(chars, i)?;
            let m = parse_pos(chars, i)?;
            Ok(Rule::Omit(n, m))
        }
        'i' => {
            let n = parse_pos(chars, i)?;
            Ok(Rule::Insert(
                n,
                next_char(chars, i, "Expected character after position in 'i'")?,
            ))
        }
        'o' => {
            let n = parse_pos(chars, i)?;
            Ok(Rule::Overstrike(
                n,
                next_char(chars, i, "Expected character after position in 'o'")?,
            ))
        }
        '\'' => Ok(Rule::Truncate(parse_pos(chars, i)?)),
        's' => {
            let x = next_char(chars, i, "Expected first character after 's'")?;
            let y = next_char(chars, i, "Expected second character after 's'")?;
            Ok(Rule::Replace(x, y))
        }
        '@' => Ok(Rule::Purge(next_char(
            chars,
            i,
            "Expected character after @",
        )?)),
        'z' => Ok(Rule::DupeFirstN(parse_pos(chars, i)?)),
        'Z' => Ok(Rule::DupeLastN(parse_pos(chars, i)?)),
        'q' => Ok(Rule::DupeAll),
        'k' => Ok(Rule::SwapFirst),
        'K' => Ok(Rule::SwapLast),
        '*' => {
            let n = parse_pos(chars, i)?;
            let m = parse_pos(chars, i)?;
            Ok(Rule::SwapAt(n, m))
        }
        '+' => Ok(Rule::Increment(parse_pos(chars, i)?)),
        '-' => Ok(Rule::Decrement(parse_pos(chars, i)?)),
        'E' => Ok(Rule::Title),
        _ => Err(format!("未知规则字符: {c}")),
    }
}

fn next_char(
    chars: &[char],
    i: &mut usize,
    msg: &str,
) -> Result<char, String> {
    *i += 1;
    chars.get(*i).copied().ok_or_else(|| msg.to_string())
}

fn capitalize_lower(word: &str) -> String {
    let mut result = word.to_lowercase();
    if let Some(c) = result.chars().next() {
        let upper: String = c.to_uppercase().collect();
        result = upper + &result[c.len_utf8()..];
    }
    result
}

fn invert_capitalize(word: &str) -> String {
    let mut result = word.to_uppercase();
    if let Some(c) = result.chars().next() {
        let lower: String = c.to_lowercase().collect();
        result = lower + &result[c.len_utf8()..];
    }
    result
}

fn toggle_case(word: &str) -> String {
    word.chars()
        .map(|c| {
            if c.is_uppercase() {
                c.to_lowercase().next().unwrap_or(c)
            } else {
                c.to_uppercase().next().unwrap_or(c)
            }
        })
        .collect()
}

fn toggle_at(
    word: &str,
    n: usize,
) -> String {
    let mut chars: Vec<char> = word.chars().collect();
    if n < chars.len() {
        let c = chars[n];
        chars[n] = if c.is_uppercase() {
            c.to_lowercase().next().unwrap_or(c)
        } else {
            c.to_uppercase().next().unwrap_or(c)
        };
    }
    chars.into_iter().collect()
}

fn reflect(word: &str) -> String {
    let rev: String = word.chars().rev().collect();
    format!("{word}{rev}")
}

fn rotate_left(word: &str) -> String {
    let mut it = word.chars();
    let Some(first) = it.next() else {
        return String::new();
    };
    it.chain(std::iter::once(first)).collect()
}

fn rotate_right(word: &str) -> String {
    let mut chars: Vec<char> = word.chars().collect();
    if chars.is_empty() {
        return String::new();
    }
    let last = chars.pop().unwrap_or_default();
    std::iter::once(last).chain(chars).collect()
}

fn delete_first(word: &str) -> String {
    word.chars().skip(1).collect()
}

fn delete_last(word: &str) -> String {
    let mut chars: Vec<char> = word.chars().collect();
    let _ = chars.pop();
    chars.into_iter().collect()
}

fn delete_at(
    word: &str,
    n: usize,
) -> String {
    let mut chars: Vec<char> = word.chars().collect();
    if n < chars.len() {
        chars.remove(n);
        return chars.into_iter().collect();
    }
    word.to_string()
}

fn extract_range(
    word: &str,
    n: usize,
    m: usize,
) -> String {
    let chars: Vec<char> = word.chars().collect();
    if n >= chars.len() {
        return String::new();
    }
    let end = n.saturating_add(m).min(chars.len());
    chars[n..end].iter().collect()
}

fn omit_range(
    word: &str,
    n: usize,
    m: usize,
) -> String {
    let chars: Vec<char> = word.chars().collect();
    if n >= chars.len() {
        return word.to_string();
    }
    let end = n.saturating_add(m).min(chars.len());
    let mut out = chars[..n].to_vec();
    out.extend(&chars[end..]);
    out.into_iter().collect()
}

fn insert_at(
    word: &str,
    n: usize,
    c: char,
) -> String {
    let mut chars: Vec<char> = word.chars().collect();
    let pos = n.min(chars.len());
    chars.insert(pos, c);
    chars.into_iter().collect()
}

fn overstrike(
    word: &str,
    n: usize,
    c: char,
) -> String {
    let mut chars: Vec<char> = word.chars().collect();
    if n < chars.len() {
        chars[n] = c;
    }
    chars.into_iter().collect()
}

fn truncate_chars(
    word: &str,
    n: usize,
) -> String {
    word.chars().take(n).collect()
}

fn replace_char(
    word: &str,
    x: char,
    y: char,
) -> String {
    word.chars().map(|c| if c == x { y } else { c }).collect()
}

fn purge_char(
    word: &str,
    x: char,
) -> String {
    word.chars().filter(|c| *c != x).collect()
}

fn dupe_first_n(
    word: &str,
    n: usize,
) -> String {
    let Some(first) = word.chars().next() else {
        return String::new();
    };
    let prefix: String = std::iter::repeat_n(first, n).collect();
    format!("{prefix}{word}")
}

fn dupe_last_n(
    word: &str,
    n: usize,
) -> String {
    let Some(last) = word.chars().next_back() else {
        return String::new();
    };
    let suffix: String = std::iter::repeat_n(last, n).collect();
    format!("{word}{suffix}")
}

fn dupe_all(word: &str) -> String {
    word.chars().flat_map(|c| [c, c]).collect()
}

fn swap_first(word: &str) -> String {
    let mut chars: Vec<char> = word.chars().collect();
    if chars.len() >= 2 {
        chars.swap(0, 1);
    }
    chars.into_iter().collect()
}

fn swap_last(word: &str) -> String {
    let mut chars: Vec<char> = word.chars().collect();
    if chars.len() >= 2 {
        let len = chars.len();
        chars.swap(len - 2, len - 1);
    }
    chars.into_iter().collect()
}

fn swap_at(
    word: &str,
    n: usize,
    m: usize,
) -> String {
    let mut chars: Vec<char> = word.chars().collect();
    if n < chars.len() && m < chars.len() {
        chars.swap(n, m);
    }
    chars.into_iter().collect()
}

fn inc_char(
    word: &str,
    n: usize,
) -> String {
    let mut chars: Vec<char> = word.chars().collect();
    if n < chars.len() {
        chars[n] = (chars[n] as u8).wrapping_add(1) as char;
    }
    chars.into_iter().collect()
}

fn dec_char(
    word: &str,
    n: usize,
) -> String {
    let mut chars: Vec<char> = word.chars().collect();
    if n < chars.len() {
        chars[n] = (chars[n] as u8).wrapping_sub(1) as char;
    }
    chars.into_iter().collect()
}

fn title_case(word: &str) -> String {
    let mut out = String::new();
    let mut capitalize_next = true;
    for c in word.chars() {
        if c.is_whitespace() {
            capitalize_next = true;
            out.push(c);
        } else if capitalize_next {
            out.extend(c.to_uppercase());
            capitalize_next = false;
        } else {
            out.extend(c.to_lowercase());
        }
    }
    out
}

fn leetspeak(word: &str) -> String {
    word.chars()
        .map(|c| match c.to_ascii_lowercase() {
            'a' => '4',
            'e' => '3',
            'i' | 'l' => '1',
            'o' => '0',
            's' => '5',
            't' => '7',
            _ => c,
        })
        .collect()
}

fn append_numbers(
    word: &str,
    n: usize,
) -> String {
    let nums: String = (1..=n)
        .map(|i| {
            let digit = u32::try_from(i % 10).unwrap_or_default();
            char::from_digit(digit, 10).unwrap_or('0')
        })
        .collect();
    format!("{word}{nums}")
}

/// 解析位置参数（支持0-9和A-Z表示10-35）
fn parse_pos(
    chars: &[char],
    i: &mut usize,
) -> Result<usize, String> {
    *i += 1;
    let c = chars
        .get(*i)
        .copied()
        .ok_or_else(|| "期望位置参数".to_string())?;
    match c {
        '0'..='9' => Ok((c as usize) - ('0' as usize)),
        'A'..='Z' => Ok((c as usize) - ('A' as usize) + 10),
        _ => Err(format!("无效的位置字符: {c}")),
    }
}

/// 预定义的常用规则集
pub mod presets {
    use super::Rule;

    /// 基础规则集
    #[must_use]
    pub fn basic() -> Vec<Rule> {
        vec![
            Rule::Noop,
            Rule::Lowercase,
            Rule::Uppercase,
            Rule::Capitalize,
        ]
    }

    /// 数字后缀规则集
    #[must_use]
    pub fn number_suffix() -> Vec<Vec<Rule>> {
        vec![
            vec![Rule::Append('1')],
            vec![Rule::Append('1'), Rule::Append('2')],
            vec![Rule::Append('1'), Rule::Append('2'), Rule::Append('3')],
            vec![Rule::Append('!')],
            vec![Rule::Append('1'), Rule::Append('!')],
        ]
    }

    /// Leetspeak规则
    #[must_use]
    pub fn leetspeak() -> Vec<Rule> {
        vec![Rule::Leetspeak]
    }

    /// 年份后缀
    #[must_use]
    pub fn year_suffix() -> Vec<Vec<Rule>> {
        (2020..=2025).map(|y| vec![Rule::AppendYear(y)]).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::{Rule, RuleEngine};

    #[test]
    fn test_lowercase() {
        assert_eq!(RuleEngine::apply_rule("HeLLo", &Rule::Lowercase), "hello");
    }

    #[test]
    fn test_uppercase() {
        assert_eq!(RuleEngine::apply_rule("hello", &Rule::Uppercase), "HELLO");
    }

    #[test]
    fn test_capitalize() {
        assert_eq!(RuleEngine::apply_rule("hELLO", &Rule::Capitalize), "Hello");
    }

    #[test]
    fn test_reverse() {
        assert_eq!(RuleEngine::apply_rule("hello", &Rule::Reverse), "olleh");
    }

    #[test]
    fn test_append() {
        assert_eq!(
            RuleEngine::apply_rule("hello", &Rule::Append('!')),
            "hello!"
        );
    }

    #[test]
    fn test_prepend() {
        assert_eq!(
            RuleEngine::apply_rule("hello", &Rule::Prepend('@')),
            "@hello"
        );
    }

    #[test]
    fn test_leetspeak() {
        assert_eq!(RuleEngine::apply_rule("leet", &Rule::Leetspeak), "1337");
    }

    #[test]
    fn test_parse_rule() {
        let rules = RuleEngine::parse_rule("l$1").unwrap();
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0], Rule::Lowercase);
        assert_eq!(rules[1], Rule::Append('1'));
    }

    #[test]
    fn test_rotate() {
        assert_eq!(RuleEngine::apply_rule("hello", &Rule::RotateLeft), "elloh");
        assert_eq!(RuleEngine::apply_rule("hello", &Rule::RotateRight), "ohell");
    }

    #[test]
    fn test_duplicate() {
        assert_eq!(RuleEngine::apply_rule("hi", &Rule::Duplicate), "hihi");
        assert_eq!(
            RuleEngine::apply_rule("hi", &Rule::DuplicateTimes(2)),
            "hihihi"
        );
    }

    #[test]
    fn test_parse_rule_consumes_position_params() {
        let rules = RuleEngine::parse_rule("T0l").unwrap();
        assert_eq!(rules, vec![Rule::ToggleAt(0), Rule::Lowercase]);

        let rules = RuleEngine::parse_rule("p2u").unwrap();
        assert_eq!(rules, vec![Rule::DuplicateTimes(2), Rule::Uppercase]);
    }

    #[test]
    fn test_parse_rule_two_pos_and_two_char() {
        let rules = RuleEngine::parse_rule("x01sAZ").unwrap();
        assert_eq!(rules, vec![Rule::Extract(0, 1), Rule::Replace('A', 'Z')]);
    }

    #[test]
    fn test_parse_rule_pos_range_a_z() {
        let rules = RuleEngine::parse_rule("TA").unwrap();
        assert_eq!(rules, vec![Rule::ToggleAt(10)]);
    }
}
