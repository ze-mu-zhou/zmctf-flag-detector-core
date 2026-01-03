use anyhow::{Context, Result};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::io::{BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheEntry {
    pub file_hash: String,
    pub file_path: String,
    pub file_size: u64,
    pub result_json: String,
    pub created_at: DateTime<Utc>,
    pub accessed_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct CacheConfig {
    pub max_size_mb: u64,
    pub max_entries: usize,
    pub ttl_hours: u64,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            max_size_mb: 500,
            max_entries: 10_000,
            ttl_hours: 168,
        }
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct CacheStore {
    entries: HashMap<String, CacheEntry>,
}

pub struct PersistentCache {
    path: PathBuf,
    store: Arc<Mutex<CacheStore>>,
    config: CacheConfig,
}

impl PersistentCache {
    /// Creates a persistent cache backed by a single JSON file.
    ///
    /// # Errors
    ///
    /// Returns an error if the cache file cannot be loaded or saved.
    pub fn new(
        db_path: Option<&Path>,
        config: CacheConfig,
    ) -> Result<Self> {
        let path = db_path.map_or_else(Self::default_db_path, Path::to_path_buf);

        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).with_context(|| {
                format!("failed to create cache directory: {}", parent.display())
            })?;
        }

        let store = load_store(&path).unwrap_or_default();

        let cache = Self {
            path,
            store: Arc::new(Mutex::new(store)),
            config,
        };
        cache.cleanup()?;
        Ok(cache)
    }

    fn default_db_path() -> PathBuf {
        cache_base_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("zmctf")
            .join("cache.db")
    }

    /// 计算文件的 SHA-256 哈希（流式读取，避免一次性加载到内存）。
    ///
    /// # Errors
    ///
    /// 当文件无法打开或读取失败时返回错误。
    pub fn compute_file_hash(path: &Path) -> Result<String> {
        let file = fs::File::open(path)
            .with_context(|| format!("failed to open file: {}", path.display()))?;
        let mut reader = BufReader::new(file);
        let mut hasher = Sha256::new();
        let mut buf = vec![0u8; 64 * 1024];

        loop {
            let read = reader
                .read(&mut buf)
                .with_context(|| format!("failed to read file: {}", path.display()))?;
            if read == 0 {
                break;
            }
            hasher.update(&buf[..read]);
        }

        Ok(format!("{:x}", hasher.finalize()))
    }

    /// 获取缓存条目（并更新访问时间）。
    ///
    /// # Errors
    ///
    /// - 当缓存互斥锁被 poison 时返回错误。
    /// - 当缓存文件写入失败时返回错误。
    pub fn get(
        &self,
        file_hash: &str,
    ) -> Result<Option<CacheEntry>> {
        let mut store = self
            .store
            .lock()
            .map_err(|e| anyhow::anyhow!("cache mutex poisoned: {e}"))?;

        let Some(mut entry) = store.entries.get(file_hash).cloned() else {
            return Ok(None);
        };

        entry.accessed_at = Utc::now();
        store.entries.insert(file_hash.to_string(), entry.clone());
        let bytes = serde_json::to_vec_pretty(&*store).context("failed to serialize cache")?;
        drop(store);
        atomic_write(&self.path, &bytes)?;
        Ok(Some(entry))
    }

    /// 设置缓存条目（以文件 hash 作为键）。
    ///
    /// # Errors
    ///
    /// - 当读取文件元数据失败时返回错误。
    /// - 当缓存文件写入失败时返回错误。
    pub fn set(
        &self,
        file_path: &Path,
        file_hash: &str,
        result_json: &str,
    ) -> Result<()> {
        let file_size = fs::metadata(file_path)
            .with_context(|| format!("failed to stat file: {}", file_path.display()))?
            .len();

        let now = Utc::now();
        let entry = CacheEntry {
            file_hash: file_hash.to_string(),
            file_path: file_path.to_string_lossy().to_string(),
            file_size,
            result_json: result_json.to_string(),
            created_at: now,
            accessed_at: now,
        };

        let mut store = self
            .store
            .lock()
            .map_err(|e| anyhow::anyhow!("cache mutex poisoned: {e}"))?;
        store.entries.insert(file_hash.to_string(), entry);
        self.apply_cleanup_locked(&mut store);
        let bytes = serde_json::to_vec_pretty(&*store).context("failed to serialize cache")?;
        drop(store);
        atomic_write(&self.path, &bytes)
    }

    /// 执行缓存清理（TTL、最大条目数、最大总大小）。
    ///
    /// # Errors
    ///
    /// 当缓存文件写入失败时返回错误。
    pub fn cleanup(&self) -> Result<()> {
        let mut store = self
            .store
            .lock()
            .map_err(|e| anyhow::anyhow!("cache mutex poisoned: {e}"))?;

        self.apply_cleanup_locked(&mut store);
        let bytes = serde_json::to_vec_pretty(&*store).context("failed to serialize cache")?;
        drop(store);
        atomic_write(&self.path, &bytes)
    }

    /// 清空所有缓存条目。
    ///
    /// # Errors
    ///
    /// 当缓存文件写入失败时返回错误。
    pub fn clear(&self) -> Result<()> {
        let mut store = self
            .store
            .lock()
            .map_err(|e| anyhow::anyhow!("cache mutex poisoned: {e}"))?;
        store.entries.clear();
        let bytes = serde_json::to_vec_pretty(&*store).context("failed to serialize cache")?;
        drop(store);
        atomic_write(&self.path, &bytes)
    }

    /// 获取缓存统计信息。
    ///
    /// # Errors
    ///
    /// 当缓存互斥锁被 poison 时返回错误。
    pub fn stats(&self) -> Result<CacheStats> {
        let store = self
            .store
            .lock()
            .map_err(|e| anyhow::anyhow!("cache mutex poisoned: {e}"))?;

        let total_size = store.entries.values().map(|e| e.file_size).sum::<u64>();

        Ok(CacheStats {
            count: store.entries.len(),
            total_size_bytes: total_size,
        })
    }

    fn apply_cleanup_locked(
        &self,
        store: &mut CacheStore,
    ) {
        if self.config.ttl_hours != 0 {
            let ttl = Duration::hours(i64::try_from(self.config.ttl_hours).unwrap_or(i64::MAX));
            let cutoff = Utc::now() - ttl;
            store.entries.retain(|_, v| v.accessed_at >= cutoff);
        }

        if store.entries.len() > self.config.max_entries {
            let mut keys = store
                .entries
                .iter()
                .map(|(k, v)| (k.clone(), v.accessed_at))
                .collect::<Vec<_>>();
            keys.sort_by_key(|(_, t)| std::cmp::Reverse(*t));

            let keep = keys
                .into_iter()
                .take(self.config.max_entries)
                .map(|(k, _)| k)
                .collect::<std::collections::HashSet<_>>();

            store.entries.retain(|k, _| keep.contains(k));
        }

        let max_bytes = self.config.max_size_mb.saturating_mul(1024 * 1024);
        if max_bytes == 0 {
            return;
        }

        let mut total = store.entries.values().map(|e| e.file_size).sum::<u64>();
        if total <= max_bytes {
            return;
        }

        let mut by_oldest = store
            .entries
            .iter()
            .map(|(k, v)| (k.clone(), v.accessed_at, v.file_size))
            .collect::<Vec<_>>();
        by_oldest.sort_by_key(|(_, t, _)| *t);

        for (k, _, size) in by_oldest {
            if total <= max_bytes {
                break;
            }
            store.entries.remove(&k);
            total = total.saturating_sub(size);
        }
    }

    // I/O 操作已移出锁持有范围；不再需要 `save_locked`。
}

#[derive(Debug, Clone, Serialize)]
pub struct CacheStats {
    pub count: usize,
    pub total_size_bytes: u64,
}

fn load_store(path: &Path) -> Result<CacheStore> {
    if !path.exists() {
        return Ok(CacheStore::default());
    }
    let bytes =
        fs::read(path).with_context(|| format!("failed to read cache file: {}", path.display()))?;
    serde_json::from_slice(&bytes).context("failed to parse cache JSON")
}

fn atomic_write(
    path: &Path,
    bytes: &[u8],
) -> Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let mut tmp = parent.to_path_buf();
    tmp.push(format!(
        ".tmp_{}_{}",
        std::process::id(),
        Utc::now().timestamp_nanos_opt().unwrap_or(0)
    ));

    {
        let mut f = fs::File::create(&tmp)
            .with_context(|| format!("failed to create temp file: {}", tmp.display()))?;
        f.write_all(bytes)
            .with_context(|| format!("failed to write temp file: {}", tmp.display()))?;
        f.sync_all()
            .with_context(|| format!("failed to sync temp file: {}", tmp.display()))?;
    }

    if path.exists() {
        fs::remove_file(path)
            .with_context(|| format!("failed to remove existing cache file: {}", path.display()))?;
    }
    fs::rename(&tmp, path).with_context(|| {
        format!(
            "failed to replace cache file: tmp={} dest={}",
            tmp.display(),
            path.display()
        )
    })
}

fn cache_base_dir() -> Option<PathBuf> {
    if let Some(dir) = std::env::var_os("XDG_CACHE_HOME").map(PathBuf::from) {
        return Some(dir);
    }

    #[cfg(windows)]
    {
        if let Some(dir) = std::env::var_os("LOCALAPPDATA").map(PathBuf::from) {
            return Some(dir);
        }
        if let Some(dir) = std::env::var_os("APPDATA").map(PathBuf::from) {
            return Some(dir);
        }
    }

    std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".cache"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn test_compute_file_hash_streaming_matches_expected() -> Result<()> {
        let uniq = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "zmctf_cache_hash_test_{}_{}",
            std::process::id(),
            uniq
        ));
        fs::create_dir_all(&dir)?;
        let file_path = dir.join("big.bin");

        let mut file = fs::File::create(&file_path)?;
        let mut expected_hasher = Sha256::new();
        let chunk = [b'a'; 4096];

        let total = 200_000usize;
        let full_chunks = total / chunk.len();
        let remainder = total % chunk.len();
        for _ in 0..full_chunks {
            file.write_all(&chunk)?;
            expected_hasher.update(chunk);
        }
        if remainder > 0 {
            file.write_all(&chunk[..remainder])?;
            expected_hasher.update(&chunk[..remainder]);
        }

        let expected = format!("{:x}", expected_hasher.finalize());
        let actual = PersistentCache::compute_file_hash(&file_path)?;
        assert_eq!(actual, expected);

        drop(fs::remove_dir_all(&dir));
        Ok(())
    }
}
