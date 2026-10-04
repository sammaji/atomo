//! `kernel.db`: plugin key-value storage and persisted plugin enablement.
//!
//! SQLite in WAL mode. Platform plugins keep their own databases (journal,
//! properties, index) in their data directory; this one belongs to the kernel.

use std::path::Path;
use std::sync::Arc;

use parking_lot::Mutex;
use rusqlite::{params, Connection, OptionalExtension};
use serde_json::Value;

use crate::{ErrorCode, KernelError, KernelResult};

fn db_error(e: rusqlite::Error) -> KernelError {
    KernelError::new(ErrorCode::Storage, e.to_string())
}

#[derive(Clone)]
pub(crate) struct KernelDb(Arc<Mutex<Connection>>);

impl KernelDb {
    /// `None` opens an in-memory database. Used by tests and `--ephemeral` runs.
    pub fn open(dir: Option<&Path>) -> KernelResult<KernelDb> {
        let conn = match dir {
            Some(dir) => {
                std::fs::create_dir_all(dir).map_err(|e| KernelError::io(e.to_string()))?;
                let conn = Connection::open(dir.join("kernel.db")).map_err(db_error)?;
                conn.pragma_update(None, "journal_mode", "WAL")
                    .map_err(db_error)?;
                conn
            }
            None => Connection::open_in_memory().map_err(db_error)?,
        };
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS kv (
                 plugin TEXT NOT NULL, scope TEXT NOT NULL, key TEXT NOT NULL, value TEXT NOT NULL,
                 PRIMARY KEY (plugin, scope, key));
             CREATE TABLE IF NOT EXISTS plugin_enabled (id TEXT PRIMARY KEY, enabled INTEGER NOT NULL);",
        )
        .map_err(db_error)?;
        Ok(KernelDb(Arc::new(Mutex::new(conn))))
    }

    /// Run `f` on the connection (the broker's tables live here too).
    pub fn with<R>(&self, f: impl FnOnce(&Connection) -> rusqlite::Result<R>) -> KernelResult<R> {
        f(&self.0.lock()).map_err(db_error)
    }

    pub fn disabled_plugins(&self) -> KernelResult<Vec<String>> {
        let conn = self.0.lock();
        let mut stmt = conn
            .prepare("SELECT id FROM plugin_enabled WHERE enabled = 0")
            .map_err(db_error)?;
        let rows = stmt.query_map([], |r| r.get(0)).map_err(db_error)?;
        rows.collect::<Result<_, _>>().map_err(db_error)
    }

    pub fn set_enabled(&self, id: &str, enabled: bool) -> KernelResult<()> {
        self.0
            .lock()
            .execute(
                "INSERT INTO plugin_enabled (id, enabled) VALUES (?1, ?2)
                 ON CONFLICT(id) DO UPDATE SET enabled = excluded.enabled",
                params![id, enabled],
            )
            .map(drop)
            .map_err(db_error)
    }
}

/// A plugin's private key-value store (`ctx.storage`). Values are JSON.
/// `scope` is `""` for global keys or a canonical location URI for per-location keys.
#[derive(Clone)]
pub struct PluginStorage {
    db: KernelDb,
    plugin: String,
}

impl PluginStorage {
    pub(crate) fn new(db: KernelDb, plugin: String) -> Self {
        Self { db, plugin }
    }

    pub fn get(&self, scope: &str, key: &str) -> KernelResult<Option<Value>> {
        let text: Option<String> = self
            .db
            .0
            .lock()
            .query_row(
                "SELECT value FROM kv WHERE plugin = ?1 AND scope = ?2 AND key = ?3",
                params![self.plugin, scope, key],
                |r| r.get(0),
            )
            .optional()
            .map_err(db_error)?;
        Ok(text.and_then(|t| serde_json::from_str(&t).ok()))
    }

    pub fn set(&self, scope: &str, key: &str, value: &Value) -> KernelResult<()> {
        self.db
            .0
            .lock()
            .execute(
                "INSERT INTO kv (plugin, scope, key, value) VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT(plugin, scope, key) DO UPDATE SET value = excluded.value",
                params![self.plugin, scope, key, value.to_string()],
            )
            .map(drop)
            .map_err(db_error)
    }

    pub fn delete(&self, scope: &str, key: &str) -> KernelResult<()> {
        self.db
            .0
            .lock()
            .execute(
                "DELETE FROM kv WHERE plugin = ?1 AND scope = ?2 AND key = ?3",
                params![self.plugin, scope, key],
            )
            .map(drop)
            .map_err(db_error)
    }

    pub fn keys(&self, scope: &str) -> KernelResult<Vec<String>> {
        let conn = self.db.0.lock();
        let mut stmt = conn
            .prepare("SELECT key FROM kv WHERE plugin = ?1 AND scope = ?2 ORDER BY key")
            .map_err(db_error)?;
        let rows = stmt
            .query_map(params![self.plugin, scope], |r| r.get(0))
            .map_err(db_error)?;
        rows.collect::<Result<_, _>>().map_err(db_error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn kv_is_per_plugin_and_scope() {
        let db = KernelDb::open(None).unwrap();
        let a = PluginStorage::new(db.clone(), "t.a".into());
        let b = PluginStorage::new(db.clone(), "t.b".into());
        a.set("", "k", &json!({ "x": 1 })).unwrap();
        a.set("file:///x/", "k", &json!(2)).unwrap();
        assert_eq!(a.get("", "k").unwrap(), Some(json!({ "x": 1 })));
        assert_eq!(a.get("file:///x/", "k").unwrap(), Some(json!(2)));
        assert_eq!(
            b.get("", "k").unwrap(),
            None,
            "plugins can't read each other's keys"
        );
        a.delete("", "k").unwrap();
        assert_eq!(a.keys("").unwrap(), Vec::<String>::new());

        db.set_enabled("t.a", false).unwrap();
        db.set_enabled("t.b", false).unwrap();
        db.set_enabled("t.b", true).unwrap();
        assert_eq!(db.disabled_plugins().unwrap(), ["t.a"]);
    }

    #[test]
    fn persists_on_disk() {
        let dir = tempfile::tempdir().unwrap();
        {
            let db = KernelDb::open(Some(dir.path())).unwrap();
            PluginStorage::new(db, "t.a".into())
                .set("", "k", &json!("v"))
                .unwrap();
        }
        let db = KernelDb::open(Some(dir.path())).unwrap();
        assert_eq!(
            PluginStorage::new(db, "t.a".into()).get("", "k").unwrap(),
            Some(json!("v"))
        );
    }
}
