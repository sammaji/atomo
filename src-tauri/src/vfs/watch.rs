use std::collections::HashMap;
use std::sync::Mutex;

use tokio::sync::mpsc;
use uuid::Uuid;

use crate::events::EventBus;

use super::engine::VfsEngine;
use super::error::VfsError;
use super::provider::WatchHandle;
use super::uri::VfsUri;

/// Tracks live watch sessions so `vfs_unwatch` (or window teardown) can drop
/// the corresponding `WatchHandle`, which is what actually stops the watch.
pub struct WatchSessions {
    inner: Mutex<HashMap<Uuid, WatchHandle>>,
}

impl Default for WatchSessions {
    fn default() -> Self {
        Self::new()
    }
}

impl WatchSessions {
    pub fn new() -> Self {
        WatchSessions {
            inner: Mutex::new(HashMap::new()),
        }
    }

    /// Duplicate watches on the same uri are allowed; each is its own session.
    pub async fn watch(
        &self,
        engine: &VfsEngine,
        events: &EventBus,
        uri: VfsUri,
        recursive: bool,
    ) -> Result<Uuid, VfsError> {
        let provider = engine.provider_for(&uri)?;
        let (tx, mut rx) = mpsc::channel(256);
        let handle = provider.watch(&uri, recursive, tx).await?;
        let id = Uuid::new_v4();
        self.inner.lock().unwrap().insert(id, handle);

        let events = events.clone();
        tokio::spawn(async move {
            while let Some(event) = rx.recv().await {
                events.emit_fs(event);
            }
        });

        Ok(id)
    }

    pub fn unwatch(&self, id: Uuid) {
        self.inner.lock().unwrap().remove(&id);
    }

    pub fn unwatch_all(&self) {
        self.inner.lock().unwrap().clear();
    }
}
