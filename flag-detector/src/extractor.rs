use crate::types::{CacheEntry, DetectorConfig, ExtractedString, FileCache};
use anyhow::{Context, Result};
use memmap2::Mmap;
use std::collections::hash_map::DefaultHasher;
use std::fs::File;
use std::hash::{Hash, Hasher};
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;
use std::time::UNIX_EPOCH;

const CACHE_SIGNATURE_SAMPLE_BYTES: usize = 4096;

/// 带缓存的字符串提取
///
/// # Errors
///
/// - 当读取文件元数据、打开/读取文件失败时返回错误。
/// - 当文件超过大小上限时返回错误。
pub fn extract_strings_cached(
    file_path: &Path,
    config: &DetectorConfig,
    cache: &FileCache,
) -> Result<Vec<ExtractedString>> {
    let path_buf = file_path.to_path_buf();

    let metadata = std::fs::metadata(file_path)?;
    let signature = calculate_file_signature(file_path, &metadata)?;

    // 检查缓存
    if config.cache_enabled {
        if let Some(entry) = cache.get(&path_buf) {
            if entry.file_size == metadata.len() && entry.file_hash == signature {
                log::debug!("使用缓存: {}", file_path.display());
                return Ok(entry.strings);
            }
        }
    }

    // 提取字符串
    let strings = extract_strings(file_path, config)?;

    // 更新缓存
    if config.cache_enabled {
        let metadata = std::fs::metadata(file_path)?;
        let signature = calculate_file_signature(file_path, &metadata)?;
        cache.insert(
            path_buf,
            CacheEntry {
                strings: strings.clone(),
                file_hash: signature,
                file_size: metadata.len(),
            },
        );
    }

    Ok(strings)
}

/// 从文件提取可打印 ASCII 字符串。
///
/// # Errors
///
/// - 当无法打开/映射文件时返回错误。
/// - 当文件超过大小上限时返回错误。
pub fn extract_strings(
    file_path: &Path,
    config: &DetectorConfig,
) -> Result<Vec<ExtractedString>> {
    log::info!("开始从文件提取字符串: {}", file_path.display());

    let file =
        File::open(file_path).with_context(|| format!("无法打开文件: {}", file_path.display()))?;

    let metadata = file.metadata()?;
    let max_file_size = u64::try_from(config.max_file_size).unwrap_or(u64::MAX);
    if metadata.len() > max_file_size {
        anyhow::bail!("文件大小超过限制: {} bytes", metadata.len());
    }

    let mmap = unsafe { Mmap::map(&file)? };
    let mut strings = Vec::new();

    extract_ascii_strings(&mmap, config, &mut strings);

    log::info!("提取到 {} 个候选字符串", strings.len());
    Ok(strings)
}

fn extract_ascii_strings(
    data: &[u8],
    config: &DetectorConfig,
    output: &mut Vec<ExtractedString>,
) {
    let mut current = String::new();
    let mut start_offset = 0;

    for (i, &byte) in data.iter().enumerate() {
        if is_printable_ascii(byte) {
            if current.is_empty() {
                start_offset = i;
            }
            current.push(byte as char);
        } else {
            if current.len() >= config.min_string_length
                && current.len() <= config.max_string_length
            {
                log::trace!("字符串 @ 0x{start_offset:x}: {current}");
                output.push(ExtractedString {
                    content: current.clone(),
                    offset: start_offset,
                });
            }
            current.clear();
        }
    }

    if current.len() >= config.min_string_length && current.len() <= config.max_string_length {
        output.push(ExtractedString {
            content: current,
            offset: start_offset,
        });
    }
}

fn is_printable_ascii(byte: u8) -> bool {
    (0x20..=0x7E).contains(&byte) || byte == b'\t' || byte == b'\n' || byte == b'\r'
}

fn calculate_file_signature(
    path: &Path,
    metadata: &std::fs::Metadata,
) -> Result<u64> {
    let mut hasher = DefaultHasher::new();

    metadata.len().hash(&mut hasher);
    if let Ok(modified) = metadata.modified() {
        if let Ok(d) = modified.duration_since(UNIX_EPOCH) {
            d.as_nanos().hash(&mut hasher);
        }
    }

    let mut file = File::open(path)?;
    let mut head_buf = vec![0u8; CACHE_SIGNATURE_SAMPLE_BYTES];
    let head_len = file.read(&mut head_buf)?;
    head_buf.truncate(head_len);
    head_buf.hash(&mut hasher);

    let len = metadata.len();
    let sample_len = u64::try_from(CACHE_SIGNATURE_SAMPLE_BYTES).unwrap_or(u64::MAX);
    if len > sample_len {
        let tail_len_u64 = sample_len.min(len);
        file.seek(SeekFrom::Start(len.saturating_sub(tail_len_u64)))?;
        let tail_len = usize::try_from(tail_len_u64).unwrap_or(usize::MAX);
        let mut tail_buf = vec![0u8; tail_len];
        file.read_exact(&mut tail_buf)?;
        tail_buf.hash(&mut hasher);
    }

    Ok(hasher.finish())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn test_extract_strings_cached_invalidates_on_content_change_same_size() -> Result<()> {
        let uniq = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "zmctf_extractor_cache_test_{}_{}",
            std::process::id(),
            uniq
        ));
        std::fs::create_dir_all(&dir)?;
        let file_path = dir.join("sample.txt");

        std::fs::write(&file_path, "AAAA flag{one} BBBB")?;

        let config = DetectorConfig::default();
        let cache = FileCache::new();

        let strings_v1 = extract_strings_cached(&file_path, &config, &cache)?;
        assert!(strings_v1.iter().any(|s| s.content.contains("flag{one}")));

        // 保持文件大小不变，修改内容；旧实现只按 size 命中缓存会返回过期结果。
        std::fs::write(&file_path, "AAAA flag{two} BBBB")?;

        let strings_v2 = extract_strings_cached(&file_path, &config, &cache)?;
        assert!(strings_v2.iter().any(|s| s.content.contains("flag{two}")));
        assert!(!strings_v2.iter().any(|s| s.content.contains("flag{one}")));

        drop(std::fs::remove_dir_all(&dir));
        Ok(())
    }
}
