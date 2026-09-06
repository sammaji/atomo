use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use bytes::Bytes;
use futures::stream::{self, StreamExt};
use tokio_util::sync::CancellationToken;

use super::error::VfsError;
use super::provider::{ByteStream, EventSink, FsProvider, WatchHandle};
use super::types::{
    CopyOpts, DeleteOpts, DirEntry, FileType, FsEvent, FsEventKind, ListOpts, ProviderCaps, Stat,
    WriteOpts,
};
use super::uri::VfsUri;

#[derive(Clone)]
enum Node {
    File { data: Vec<u8>, modified_ms: u64 },
    Dir { modified_ms: u64 },
}

struct WatchReg {
    id: u64,
    root: VfsUri,
    recursive: bool,
    sink: EventSink,
}

struct WatchGuard {
    id: u64,
    watchers: Arc<Mutex<Vec<WatchReg>>>,
}

impl Drop for WatchGuard {
    fn drop(&mut self) {
        self.watchers.lock().unwrap().retain(|w| w.id != self.id);
    }
}

pub struct MemProvider {
    tree: RwLock<HashMap<VfsUri, Node>>,
    watchers: Arc<Mutex<Vec<WatchReg>>>,
    next_watch_id: AtomicU64,
}

impl Default for MemProvider {
    fn default() -> Self {
        Self::new()
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

impl MemProvider {
    pub fn new() -> Self {
        MemProvider {
            tree: RwLock::new(HashMap::new()),
            watchers: Arc::new(Mutex::new(Vec::new())),
            next_watch_id: AtomicU64::new(0),
        }
    }

    fn is_root(uri: &VfsUri) -> bool {
        uri.segments().next().is_none()
    }

    fn notify(&self, event: FsEvent) {
        let watchers = self.watchers.lock().unwrap();
        for reg in watchers.iter() {
            let matches = if reg.recursive {
                reg.root == event.uri || reg.root.is_ancestor_of(&event.uri)
            } else {
                Some(reg.root.clone()) == event.uri.parent() || reg.root == event.uri
            };
            if matches {
                let _ = reg.sink.try_send(event.clone());
            }
        }
    }

    fn collect_subtree(tree: &HashMap<VfsUri, Node>, root: &VfsUri) -> Vec<VfsUri> {
        tree.keys()
            .filter(|k| *k == root || root.is_ancestor_of(k))
            .cloned()
            .collect()
    }
}

#[async_trait]
impl FsProvider for MemProvider {
    fn scheme(&self) -> &str {
        "mem"
    }

    fn caps(&self) -> ProviderCaps {
        ProviderCaps {
            read: true,
            write: true,
            watch: true,
            trash: false,
            copy_within: true,
            case_sensitive: true,
        }
    }

    async fn stat(&self, uri: &VfsUri, _ct: CancellationToken) -> Result<Stat, VfsError> {
        if Self::is_root(uri) {
            return Ok(Stat {
                file_type: FileType::Directory,
                size: 0,
                modified_ms: None,
                created_ms: None,
                readonly: false,
                symlink_target: None,
            });
        }
        let tree = self.tree.read().unwrap();
        match tree.get(uri) {
            Some(Node::File { data, modified_ms }) => Ok(Stat {
                file_type: FileType::File,
                size: data.len() as u64,
                modified_ms: Some(*modified_ms),
                created_ms: Some(*modified_ms),
                readonly: false,
                symlink_target: None,
            }),
            Some(Node::Dir { modified_ms }) => Ok(Stat {
                file_type: FileType::Directory,
                size: 0,
                modified_ms: Some(*modified_ms),
                created_ms: Some(*modified_ms),
                readonly: false,
                symlink_target: None,
            }),
            None => Err(VfsError::NotFound(uri.clone())),
        }
    }

    async fn list(
        &self,
        uri: &VfsUri,
        opts: ListOpts,
        _ct: CancellationToken,
    ) -> Result<Vec<DirEntry>, VfsError> {
        let tree = self.tree.read().unwrap();
        if !Self::is_root(uri) {
            match tree.get(uri) {
                Some(Node::Dir { .. }) => {}
                Some(Node::File { .. }) => return Err(VfsError::NotADirectory(uri.clone())),
                None => return Err(VfsError::NotFound(uri.clone())),
            }
        }
        let mut entries = Vec::new();
        for (key, node) in tree.iter() {
            if key.parent().as_ref() != Some(uri) {
                continue;
            }
            let name = key.name().unwrap_or_default().to_string();
            let hidden = name.starts_with('.');
            if hidden && !opts.include_hidden {
                continue;
            }
            let (file_type, size, modified_ms, mime) = match node {
                Node::File { data, modified_ms } => (
                    FileType::File,
                    data.len() as u64,
                    Some(*modified_ms),
                    mime_guess::from_path(&name).first().map(|m| m.to_string()),
                ),
                Node::Dir { modified_ms } => (FileType::Directory, 0, Some(*modified_ms), None),
            };
            entries.push(DirEntry {
                uri: key.clone(),
                name,
                file_type,
                size,
                modified_ms,
                hidden,
                mime,
            });
        }
        Ok(entries)
    }

    async fn read(
        &self,
        uri: &VfsUri,
        range: Option<std::ops::Range<u64>>,
        ct: CancellationToken,
    ) -> Result<ByteStream, VfsError> {
        if ct.is_cancelled() {
            return Err(VfsError::Cancelled);
        }
        let tree = self.tree.read().unwrap();
        match tree.get(uri) {
            Some(Node::File { data, .. }) => {
                let slice = match range {
                    Some(r) => {
                        let start = (r.start as usize).min(data.len());
                        let end = (r.end as usize).min(data.len()).max(start);
                        data[start..end].to_vec()
                    }
                    None => data.clone(),
                };
                Ok(Box::pin(stream::once(
                    async move { Ok(Bytes::from(slice)) },
                )))
            }
            Some(Node::Dir { .. }) => Err(VfsError::IsADirectory(uri.clone())),
            None => Err(VfsError::NotFound(uri.clone())),
        }
    }

    async fn write(
        &self,
        uri: &VfsUri,
        mut data: ByteStream,
        opts: WriteOpts,
        ct: CancellationToken,
    ) -> Result<(), VfsError> {
        let mut buf = Vec::new();
        while let Some(chunk) = data.next().await {
            if ct.is_cancelled() {
                return Err(VfsError::Cancelled);
            }
            buf.extend_from_slice(&chunk?);
        }

        let mut tree = self.tree.write().unwrap();
        if let Some(Node::Dir { .. }) = tree.get(uri) {
            return Err(VfsError::IsADirectory(uri.clone()));
        }
        if !opts.overwrite {
            if let Some(Node::File { .. }) = tree.get(uri) {
                return Err(VfsError::AlreadyExists(uri.clone()));
            }
        }
        if let Some(parent) = uri.parent() {
            if !Self::is_root(&parent) && !matches!(tree.get(&parent), Some(Node::Dir { .. })) {
                if opts.create_parents {
                    tree.insert(
                        parent.clone(),
                        Node::Dir {
                            modified_ms: now_ms(),
                        },
                    );
                } else {
                    return Err(VfsError::NotFound(parent));
                }
            }
        }
        let existed = tree.contains_key(uri);
        tree.insert(
            uri.clone(),
            Node::File {
                data: buf,
                modified_ms: now_ms(),
            },
        );
        drop(tree);
        self.notify(FsEvent {
            kind: if existed {
                FsEventKind::Modified
            } else {
                FsEventKind::Created
            },
            uri: uri.clone(),
            renamed_to: None,
        });
        Ok(())
    }

    async fn mkdir(&self, uri: &VfsUri, _ct: CancellationToken) -> Result<(), VfsError> {
        let mut tree = self.tree.write().unwrap();
        if tree.contains_key(uri) {
            return Err(VfsError::AlreadyExists(uri.clone()));
        }
        if let Some(parent) = uri.parent() {
            if !Self::is_root(&parent) && !matches!(tree.get(&parent), Some(Node::Dir { .. })) {
                return Err(VfsError::NotFound(parent));
            }
        }
        tree.insert(
            uri.clone(),
            Node::Dir {
                modified_ms: now_ms(),
            },
        );
        drop(tree);
        self.notify(FsEvent {
            kind: FsEventKind::Created,
            uri: uri.clone(),
            renamed_to: None,
        });
        Ok(())
    }

    async fn delete(
        &self,
        uri: &VfsUri,
        opts: DeleteOpts,
        _ct: CancellationToken,
    ) -> Result<(), VfsError> {
        let mut tree = self.tree.write().unwrap();
        match tree.get(uri) {
            None => return Err(VfsError::NotFound(uri.clone())),
            Some(Node::Dir { .. }) => {
                let subtree = Self::collect_subtree(&tree, uri);
                if subtree.len() > 1 && !opts.recursive {
                    return Err(VfsError::DirectoryNotEmpty(uri.clone()));
                }
                for k in subtree {
                    tree.remove(&k);
                }
            }
            Some(Node::File { .. }) => {
                tree.remove(uri);
            }
        }
        drop(tree);
        self.notify(FsEvent {
            kind: FsEventKind::Removed,
            uri: uri.clone(),
            renamed_to: None,
        });
        Ok(())
    }

    async fn rename(
        &self,
        from: &VfsUri,
        to: &VfsUri,
        overwrite: bool,
        _ct: CancellationToken,
    ) -> Result<(), VfsError> {
        let mut tree = self.tree.write().unwrap();
        if !tree.contains_key(from) {
            return Err(VfsError::NotFound(from.clone()));
        }
        if tree.contains_key(to) && !overwrite {
            return Err(VfsError::AlreadyExists(to.clone()));
        }
        let subtree = Self::collect_subtree(&tree, from);
        let from_len = from.segments().count();
        for old_key in subtree {
            if let Some(node) = tree.remove(&old_key) {
                let mut new_key = to.clone();
                let suffix: Vec<&str> = old_key.segments().skip(from_len).collect();
                for seg in suffix {
                    new_key = new_key.join(seg)?;
                }
                tree.insert(new_key, node);
            }
        }
        drop(tree);
        self.notify(FsEvent {
            kind: FsEventKind::Renamed,
            uri: from.clone(),
            renamed_to: Some(to.clone()),
        });
        Ok(())
    }

    async fn copy_within(
        &self,
        from: &VfsUri,
        to: &VfsUri,
        opts: CopyOpts,
        _ct: CancellationToken,
    ) -> Result<(), VfsError> {
        let mut tree = self.tree.write().unwrap();
        if !tree.contains_key(from) {
            return Err(VfsError::NotFound(from.clone()));
        }
        if tree.contains_key(to) && !opts.overwrite {
            return Err(VfsError::AlreadyExists(to.clone()));
        }
        let subtree = Self::collect_subtree(&tree, from);
        let from_len = from.segments().count();
        let mut inserts = Vec::new();
        for old_key in &subtree {
            if let Some(node) = tree.get(old_key) {
                let mut new_key = to.clone();
                let suffix: Vec<&str> = old_key.segments().skip(from_len).collect();
                for seg in suffix {
                    new_key = new_key.join(seg)?;
                }
                inserts.push((new_key, node.clone()));
            }
        }
        for (k, v) in inserts {
            tree.insert(k, v);
        }
        drop(tree);
        self.notify(FsEvent {
            kind: FsEventKind::Created,
            uri: to.clone(),
            renamed_to: None,
        });
        Ok(())
    }

    async fn watch(
        &self,
        uri: &VfsUri,
        recursive: bool,
        sink: EventSink,
    ) -> Result<WatchHandle, VfsError> {
        let id = self.next_watch_id.fetch_add(1, Ordering::SeqCst);
        self.watchers.lock().unwrap().push(WatchReg {
            id,
            root: uri.clone(),
            recursive,
            sink,
        });
        Ok(WatchHandle::new(WatchGuard {
            id,
            watchers: self.watchers.clone(),
        }))
    }
}
