use crate::types::{DecodedString, DetectedFlag, DetectorConfig};
use anyhow::Result;
use regex::Regex;

/// 根据配置中的 `flag_formats` 对解码结果进行匹配。
///
/// # Errors
///
/// 当前实现不会返回错误（保留 `Result` 以便向后兼容及未来扩展）。
pub fn match_flags(
    decoded: &[DecodedString],
    config: &DetectorConfig,
) -> Result<Vec<DetectedFlag>> {
    log::info!("开始匹配flag模式");

    // 从配置构建正则表达式，按优先级排序
    let mut formats: Vec<_> = config.flag_formats.iter().filter(|f| f.enabled).collect();
    formats.sort_by(|a, b| b.priority.cmp(&a.priority));

    let patterns: Vec<(String, Regex)> = formats
        .iter()
        .filter_map(|f| Regex::new(&f.pattern).ok().map(|r| (f.name.clone(), r)))
        .collect();

    let pattern_count = patterns.len();
    log::debug!("使用 {pattern_count} 个模式进行匹配");

    let mut flags = Vec::new();

    for decoded_str in decoded {
        for (name, pattern) in &patterns {
            if let Some(mat) = pattern.find(&decoded_str.decoded) {
                let content = mat.as_str().to_string();
                let confidence =
                    decoded_str.confidence * calculate_match_confidence(&content, name);

                if confidence >= config.min_confidence {
                    log::trace!("匹配成功: {content} (置信度: {confidence:.2})");

                    flags.push(DetectedFlag {
                        content,
                        pattern: pattern.as_str().to_string(),
                        source_offset: 0,
                        encoding_chain: decoded_str.encoding_chain.clone(),
                        confidence,
                    });
                }
            }
        }
    }

    flags.sort_by(|a, b| b.confidence.total_cmp(&a.confidence));
    flags.dedup_by(|a, b| a.content == b.content);

    log::info!("找到 {} 个潜在flag", flags.len());
    Ok(flags)
}

fn calculate_match_confidence(
    flag: &str,
    format_name: &str,
) -> f32 {
    let mut confidence: f32 = 0.5;

    if flag.len() >= 10 && flag.len() <= 100 {
        confidence += 0.2;
    }

    if flag.contains('{') && flag.contains('}') {
        confidence += 0.2;
    }

    // 高优先级格式加分
    let lower = flag.to_lowercase();
    if lower.starts_with("flag{") || lower.starts_with("ctf{") {
        confidence += 0.1;
    }

    // generic格式降低置信度
    if format_name == "generic" {
        confidence -= 0.1;
    }

    if confidence.is_nan() {
        1.0
    } else {
        confidence.clamp(0.0, 1.0)
    }
}
