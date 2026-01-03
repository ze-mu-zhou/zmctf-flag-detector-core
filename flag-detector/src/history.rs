use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoryEntry {
    pub id: i64,
    pub file_path: String,
    pub file_hash: String,
    pub flags_found: usize,
    pub analysis_time_ms: u64,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct HistoryStore {
    next_id: i64,
    entries: Vec<HistoryEntry>,
}

pub struct HistoryManager {
    path: PathBuf,
    store: Arc<Mutex<HistoryStore>>,
    max_entries: usize,
}

impl HistoryManager {
    /// 创建一个由 JSON 文件持久化的历史记录管理器。
    ///
    /// # Errors
    ///
    /// 当历史文件无法加载或保存时返回错误。
    pub fn new(
        db_path: Option<&Path>,
        max_entries: usize,
    ) -> Result<Self> {
        let path = db_path.map_or_else(Self::default_db_path, Path::to_path_buf);

        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).with_context(|| {
                format!("failed to create history directory: {}", parent.display())
            })?;
        }

        let store = load_store(&path).unwrap_or_default();
        let mgr = Self {
            path,
            store: Arc::new(Mutex::new(store)),
            max_entries,
        };

        mgr.compact()?;
        Ok(mgr)
    }

    fn default_db_path() -> PathBuf {
        data_base_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("zmctf")
            .join("history.db")
    }

    /// 追加一条历史记录并持久化到磁盘。
    ///
    /// # Errors
    ///
    /// - 当互斥锁被污染（poisoned）时返回错误。
    /// - 当创建目录、写入或替换历史文件失败时返回错误。
    pub fn add(
        &self,
        file_path: &Path,
        file_hash: &str,
        flags_found: usize,
        analysis_time_ms: u64,
    ) -> Result<i64> {
        let (id, snapshot) = {
            let mut store = self
                .store
                .lock()
                .map_err(|e| anyhow::anyhow!("history mutex poisoned: {e}"))?;

            if store.next_id <= 0 {
                store.next_id = 1;
            }
            let id = store.next_id;
            store.next_id = store.next_id.saturating_add(1);

            store.entries.push(HistoryEntry {
                id,
                file_path: file_path.to_string_lossy().to_string(),
                file_hash: file_hash.to_string(),
                flags_found,
                analysis_time_ms,
                created_at: Utc::now(),
            });

            if store.entries.len() > self.max_entries {
                let drain = store.entries.len() - self.max_entries;
                store.entries.drain(0..drain);
            }

            (id, store.clone())
        };

        save_store(&self.path, &snapshot)?;
        Ok(id)
    }

    /// 按时间倒序列出最近的历史记录。
    ///
    /// # Errors
    ///
    /// 当互斥锁被污染（poisoned）时返回错误。
    pub fn list(
        &self,
        limit: usize,
    ) -> Result<Vec<HistoryEntry>> {
        let mut out = {
            let store = self
                .store
                .lock()
                .map_err(|e| anyhow::anyhow!("history mutex poisoned: {e}"))?;
            store.entries.clone()
        };
        out.sort_by_key(|e| std::cmp::Reverse(e.created_at));
        out.truncate(limit);
        Ok(out)
    }

    /// 返回历史记录统计信息。
    ///
    /// # Errors
    ///
    /// 当互斥锁被污染（poisoned）时返回错误。
    pub fn stats(&self) -> Result<HistoryStats> {
        let total_entries = {
            let store = self
                .store
                .lock()
                .map_err(|e| anyhow::anyhow!("history mutex poisoned: {e}"))?;
            store.entries.len()
        };

        Ok(HistoryStats { total_entries })
    }

    /// 清空所有历史记录并持久化到磁盘。
    ///
    /// # Errors
    ///
    /// - 当互斥锁被污染（poisoned）时返回错误。
    /// - 当替换历史文件失败时返回错误。
    pub fn clear(&self) -> Result<()> {
        let snapshot = {
            let mut store = self
                .store
                .lock()
                .map_err(|e| anyhow::anyhow!("history mutex poisoned: {e}"))?;
            store.entries.clear();
            store.clone()
        };
        save_store(&self.path, &snapshot)
    }

    fn compact(&self) -> Result<()> {
        let snapshot = {
            let mut store = self
                .store
                .lock()
                .map_err(|e| anyhow::anyhow!("history mutex poisoned: {e}"))?;

            if store.entries.len() > self.max_entries {
                let drain = store.entries.len() - self.max_entries;
                store.entries.drain(0..drain);
            }

            if store.next_id <= 0 {
                store.next_id = 1;
            }

            store.clone()
        };

        save_store(&self.path, &snapshot)
    }
}

impl Default for HistoryManager {
    fn default() -> Self {
        Self::new(None, 1000).unwrap_or_else(|_| Self {
            path: PathBuf::from("history.db"),
            store: Arc::new(Mutex::new(HistoryStore::default())),
            max_entries: 1000,
        })
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct HistoryStats {
    pub total_entries: usize,
}

fn load_store(path: &Path) -> Result<HistoryStore> {
    if !path.exists() {
        return Ok(HistoryStore::default());
    }
    let bytes = fs::read(path)
        .with_context(|| format!("failed to read history file: {}", path.display()))?;
    serde_json::from_slice(&bytes).context("failed to parse history JSON")
}

fn save_store(
    path: &Path,
    store: &HistoryStore,
) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(store).context("failed to serialize history")?;

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
        f.write_all(&bytes)
            .with_context(|| format!("failed to write temp file: {}", tmp.display()))?;
        f.sync_all()
            .with_context(|| format!("failed to sync temp file: {}", tmp.display()))?;
    }

    if path.exists() {
        let _ = fs::remove_file(path);
    }
    fs::rename(&tmp, path)
        .with_context(|| format!("failed to replace history file: {}", path.display()))
}

fn data_base_dir() -> Option<PathBuf> {
    if let Some(dir) = std::env::var_os("XDG_DATA_HOME").map(PathBuf::from) {
        return Some(dir);
    }

    #[cfg(windows)]
    {
        if let Some(dir) = std::env::var_os("APPDATA").map(PathBuf::from) {
            return Some(dir);
        }
        if let Some(dir) = std::env::var_os("LOCALAPPDATA").map(PathBuf::from) {
            return Some(dir);
        }
    }

    std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".local").join("share"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add_and_list_keeps_latest_entries() -> Result<()> {
        let dir = std::env::temp_dir().join(format!("zmctf_history_test_{}", std::process::id()));
        fs::create_dir_all(&dir)?;
        let path = dir.join("history.db");

        let mgr = HistoryManager::new(Some(&path), 3)?;

        mgr.add(Path::new("a.bin"), "h1", 1, 10)?;
        mgr.add(Path::new("b.bin"), "h2", 2, 20)?;
        mgr.add(Path::new("c.bin"), "h3", 3, 30)?;
        mgr.add(Path::new("d.bin"), "h4", 4, 40)?;

        let items = mgr.list(10)?;
        assert_eq!(items.len(), 3);
        assert_eq!(items[0].file_hash, "h4");
        assert!(items
            .iter()
            .all(|e| ["h2", "h3", "h4"].contains(&e.file_hash.as_str())));

        let _ = fs::remove_dir_all(&dir);
        Ok(())
    }
}
