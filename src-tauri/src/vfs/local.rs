use std::future::Future;
use std::ops::Range;
use std::path::Path;
use std::pin::Pin;
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use futures::stream::StreamExt;
use notify::Watcher as _;
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use tokio_util::io::ReaderStream;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use super::error::VfsError;
use super::provider::{ByteStream, EventSink, FsProvider, WatchHandle};
use super::types::{
    CopyOpts, DeleteOpts, DirEntry, FileType, FsEvent, FsEventKind, ListOpts, ProviderCaps, Stat,
    WriteOpts,
};
use super::uri::VfsUri;

pub struct LocalProvider;

impl Default for LocalProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl LocalProvider {
    pub fn new() -> Self {
        LocalProvider
    }
}

fn ms_from(t: std::io::Result<SystemTime>) -> Option<u64> {
    t.ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_millis() as u64)
}

fn file_type_from(meta: &std::fs::Metadata) -> FileType {
    if meta.file_type().is_symlink() {
        FileType::Symlink
    } else if meta.is_dir() {
        FileType::Directory
    } else {
        FileType::File
    }
}

#[cfg(windows)]
fn is_hidden(name: &str, meta: Option<&std::fs::Metadata>) -> bool {
    use std::os::windows::fs::MetadataExt;
    const FILE_ATTRIBUTE_HIDDEN: u32 = 0x2;
    meta.map(|m| m.file_attributes() & FILE_ATTRIBUTE_HIDDEN != 0)
        .unwrap_or(false)
        || name.starts_with('.')
}

#[cfg(not(windows))]
fn is_hidden(name: &str, _meta: Option<&std::fs::Metadata>) -> bool {
    name.starts_with('.')
}

fn copy_dir_recursive<'a>(
    from: &'a Path,
    to: &'a Path,
    ct: &'a CancellationToken,
) -> Pin<Box<dyn Future<Output = Result<(), VfsError>> + Send + 'a>> {
    Box::pin(async move {
        tokio::fs::create_dir_all(to)
            .await
            .map_err(|e| VfsError::Io {
                message: e.to_string(),
            })?;
        let mut rd = tokio::fs::read_dir(from).await.map_err(|e| VfsError::Io {
            message: e.to_string(),
        })?;
        while let Some(entry) = rd.next_entry().await.map_err(|e| VfsError::Io {
            message: e.to_string(),
        })? {
            if ct.is_cancelled() {
                return Err(VfsError::Cancelled);
            }
            let file_type = entry.file_type().await.map_err(|e| VfsError::Io {
                message: e.to_string(),
            })?;
            let src = entry.path();
            let dst = to.join(entry.file_name());
            if file_type.is_dir() {
                copy_dir_recursive(&src, &dst, ct).await?;
            } else {
                tokio::fs::copy(&src, &dst)
                    .await
                    .map_err(|e| VfsError::Io {
                        message: e.to_string(),
                    })?;
            }
        }
        Ok(())
    })
}

fn translate_notify_event(event: &notify::Event) -> Vec<FsEvent> {
    use notify::EventKind;
    let to_uri = |p: &Path| VfsUri::from_local_path(p).ok();
    let mut out = Vec::new();
    match &event.kind {
        EventKind::Create(_) => {
            for p in &event.paths {
                if let Some(uri) = to_uri(p) {
                    out.push(FsEvent {
                        kind: FsEventKind::Created,
                        uri,
                        renamed_to: None,
                    });
                }
            }
        }
        EventKind::Modify(notify::event::ModifyKind::Name(_)) => {
            // Notify's rename pairing is platform-messy; rather than guess which
            // path is old/new when ambiguous, emit both a Removed and a Created.
            match event.paths.as_slice() {
                [old, new] => {
                    if let Some(uri) = to_uri(old) {
                        out.push(FsEvent {
                            kind: FsEventKind::Removed,
                            uri,
                            renamed_to: None,
                        });
                    }
                    if let Some(uri) = to_uri(new) {
                        out.push(FsEvent {
                            kind: FsEventKind::Created,
                            uri,
                            renamed_to: None,
                        });
                    }
                }
                paths => {
                    for p in paths {
                        if let Some(uri) = to_uri(p) {
                            out.push(FsEvent {
                                kind: FsEventKind::Removed,
                                uri: uri.clone(),
                                renamed_to: None,
                            });
                            out.push(FsEvent {
                                kind: FsEventKind::Created,
                                uri,
                                renamed_to: None,
                            });
                        }
                    }
                }
            }
        }
        EventKind::Modify(_) => {
            for p in &event.paths {
                if let Some(uri) = to_uri(p) {
                    out.push(FsEvent {
                        kind: FsEventKind::Modified,
                        uri,
                        renamed_to: None,
                    });
                }
            }
        }
        EventKind::Remove(_) => {
            for p in &event.paths {
                if let Some(uri) = to_uri(p) {
                    out.push(FsEvent {
                        kind: FsEventKind::Removed,
                        uri,
                        renamed_to: None,
                    });
                }
            }
        }
        _ => {}
    }
    out
}

#[async_trait]
impl FsProvider for LocalProvider {
    fn scheme(&self) -> &str {
        "file"
    }

    fn caps(&self) -> ProviderCaps {
        ProviderCaps {
            read: true,
            write: true,
            watch: true,
            trash: true,
            copy_within: true,
            case_sensitive: !(cfg!(windows) || cfg!(target_os = "macos")),
        }
    }

    async fn stat(&self, uri: &VfsUri, _ct: CancellationToken) -> Result<Stat, VfsError> {
        let path = uri.to_local_path()?;
        let meta = tokio::fs::metadata(&path)
            .await
            .map_err(|e| VfsError::from_io(e, uri))?;
        Ok(Stat {
            file_type: if meta.is_dir() {
                FileType::Directory
            } else {
                FileType::File
            },
            size: if meta.is_dir() { 0 } else { meta.len() },
            modified_ms: ms_from(meta.modified()),
            created_ms: ms_from(meta.created()),
            readonly: meta.permissions().readonly(),
            symlink_target: None,
        })
    }

    async fn list(
        &self,
        uri: &VfsUri,
        opts: ListOpts,
        ct: CancellationToken,
    ) -> Result<Vec<DirEntry>, VfsError> {
        let path = uri.to_local_path()?;
        let meta = tokio::fs::metadata(&path)
            .await
            .map_err(|e| VfsError::from_io(e, uri))?;
        if !meta.is_dir() {
            return Err(VfsError::NotADirectory(uri.clone()));
        }
        let mut rd = tokio::fs::read_dir(&path)
            .await
            .map_err(|e| VfsError::from_io(e, uri))?;
        let mut out = Vec::new();
        loop {
            if ct.is_cancelled() {
                return Err(VfsError::Cancelled);
            }
            let entry = match rd
                .next_entry()
                .await
                .map_err(|e| VfsError::from_io(e, uri))?
            {
                Some(e) => e,
                None => break,
            };
            let name = entry.file_name().to_string_lossy().into_owned();
            let child_uri = match uri.join(&name) {
                Ok(u) => u,
                Err(_) => continue,
            };
            // Tolerate per-entry metadata failures: skip the field, not the entry.
            let lmeta = tokio::fs::symlink_metadata(entry.path()).await.ok();
            let hidden = is_hidden(&name, lmeta.as_ref());
            if hidden && !opts.include_hidden {
                continue;
            }
            let (file_type, size, modified_ms) = match &lmeta {
                Some(m) => (
                    file_type_from(m),
                    if m.is_dir() { 0 } else { m.len() },
                    ms_from(m.modified()),
                ),
                None => (FileType::File, 0, None),
            };
            let mime = if file_type == FileType::File {
                mime_guess::from_path(&name).first().map(|m| m.to_string())
            } else {
                None
            };
            out.push(DirEntry {
                uri: child_uri,
                name,
                file_type,
                size,
                modified_ms,
                hidden,
                mime,
            });
        }
        Ok(out)
    }

    async fn read(
        &self,
        uri: &VfsUri,
        range: Option<Range<u64>>,
        ct: CancellationToken,
    ) -> Result<ByteStream, VfsError> {
        if ct.is_cancelled() {
            return Err(VfsError::Cancelled);
        }
        let path = uri.to_local_path()?;
        let meta = tokio::fs::metadata(&path)
            .await
            .map_err(|e| VfsError::from_io(e, uri))?;
        if meta.is_dir() {
            return Err(VfsError::IsADirectory(uri.clone()));
        }
        let mut file = tokio::fs::File::open(&path)
            .await
            .map_err(|e| VfsError::from_io(e, uri))?;
        let remaining = if let Some(r) = &range {
            file.seek(std::io::SeekFrom::Start(r.start))
                .await
                .map_err(|e| VfsError::from_io(e, uri))?;
            Some(r.end.saturating_sub(r.start))
        } else {
            None
        };
        let uri_for_err = uri.clone();
        const CHUNK: usize = 256 * 1024;
        let stream: ByteStream = match remaining {
            Some(n) => Box::pin(
                ReaderStream::with_capacity(file.take(n), CHUNK)
                    .map(move |r| r.map_err(|e| VfsError::from_io(e, &uri_for_err))),
            ),
            None => Box::pin(
                ReaderStream::with_capacity(file, CHUNK)
                    .map(move |r| r.map_err(|e| VfsError::from_io(e, &uri_for_err))),
            ),
        };
        Ok(stream)
    }

    async fn write(
        &self,
        uri: &VfsUri,
        mut data: ByteStream,
        opts: WriteOpts,
        ct: CancellationToken,
    ) -> Result<(), VfsError> {
        let path = uri.to_local_path()?;
        if opts.create_parents {
            if let Some(parent_uri) = uri.parent() {
                let parent_path = parent_uri.to_local_path()?;
                tokio::fs::create_dir_all(&parent_path)
                    .await
                    .map_err(|e| VfsError::from_io(e, &parent_uri))?;
            }
        }
        // Racy by construction: existence is checked, then the temp file is
        // renamed into place. A concurrent writer can still win between the
        // check and the rename; documented, not fixed, for M1.
        if !opts.overwrite {
            if let Ok(true) = tokio::fs::try_exists(&path).await {
                return Err(VfsError::AlreadyExists(uri.clone()));
            }
        }
        let dir = path
            .parent()
            .ok_or_else(|| VfsError::InvalidUri(format!("uri has no parent directory: {uri}")))?;
        let tmp_path = dir.join(format!(".atomo-tmp-{}", Uuid::new_v4()));
        let mut file = tokio::fs::File::create(&tmp_path)
            .await
            .map_err(|e| VfsError::from_io(e, uri))?;
        while let Some(chunk) = data.next().await {
            if ct.is_cancelled() {
                let _ = tokio::fs::remove_file(&tmp_path).await;
                return Err(VfsError::Cancelled);
            }
            let bytes = match chunk {
                Ok(b) => b,
                Err(e) => {
                    let _ = tokio::fs::remove_file(&tmp_path).await;
                    return Err(e);
                }
            };
            if let Err(e) = file.write_all(&bytes).await {
                let _ = tokio::fs::remove_file(&tmp_path).await;
                return Err(VfsError::from_io(e, uri));
            }
        }
        if let Err(e) = file.flush().await {
            let _ = tokio::fs::remove_file(&tmp_path).await;
            return Err(VfsError::from_io(e, uri));
        }
        if let Err(e) = file.sync_all().await {
            let _ = tokio::fs::remove_file(&tmp_path).await;
            return Err(VfsError::from_io(e, uri));
        }
        drop(file);
        if let Err(e) = tokio::fs::rename(&tmp_path, &path).await {
            let _ = tokio::fs::remove_file(&tmp_path).await;
            return Err(VfsError::from_io(e, uri));
        }
        Ok(())
    }

    async fn mkdir(&self, uri: &VfsUri, _ct: CancellationToken) -> Result<(), VfsError> {
        let path = uri.to_local_path()?;
        tokio::fs::create_dir(&path)
            .await
            .map_err(|e| VfsError::from_io(e, uri))
    }

    async fn delete(
        &self,
        uri: &VfsUri,
        opts: DeleteOpts,
        _ct: CancellationToken,
    ) -> Result<(), VfsError> {
        let path = uri.to_local_path()?;
        if opts.use_trash {
            let path2 = path.clone();
            return tokio::task::spawn_blocking(move || trash::delete(&path2))
                .await
                .map_err(|e| VfsError::Io {
                    message: e.to_string(),
                })?
                .map_err(|e| VfsError::Provider {
                    code: "trash".into(),
                    message: e.to_string(),
                });
        }
        let meta = tokio::fs::symlink_metadata(&path)
            .await
            .map_err(|e| VfsError::from_io(e, uri))?;
        if meta.is_dir() {
            if opts.recursive {
                tokio::fs::remove_dir_all(&path)
                    .await
                    .map_err(|e| VfsError::from_io(e, uri))
            } else {
                tokio::fs::remove_dir(&path)
                    .await
                    .map_err(|e| VfsError::from_io(e, uri))
            }
        } else {
            tokio::fs::remove_file(&path)
                .await
                .map_err(|e| VfsError::from_io(e, uri))
        }
    }

    async fn rename(
        &self,
        from: &VfsUri,
        to: &VfsUri,
        overwrite: bool,
        _ct: CancellationToken,
    ) -> Result<(), VfsError> {
        let from_path = from.to_local_path()?;
        let to_path = to.to_local_path()?;
        if !overwrite {
            if let Ok(true) = tokio::fs::try_exists(&to_path).await {
                return Err(VfsError::AlreadyExists(to.clone()));
            }
        }
        match tokio::fs::rename(&from_path, &to_path).await {
            Ok(()) => Ok(()),
            Err(e) => {
                const EXDEV: i32 = 18;
                if e.raw_os_error() == Some(EXDEV) {
                    let meta = tokio::fs::symlink_metadata(&from_path)
                        .await
                        .map_err(|e| VfsError::from_io(e, from))?;
                    if meta.is_dir() {
                        return Err(VfsError::Io {
                            message: format!(
                                "cross-device rename of a directory is not supported for {from}"
                            ),
                        });
                    }
                    tokio::fs::copy(&from_path, &to_path)
                        .await
                        .map_err(|e| VfsError::from_io(e, from))?;
                    tokio::fs::remove_file(&from_path)
                        .await
                        .map_err(|e| VfsError::from_io(e, from))?;
                    Ok(())
                } else {
                    Err(VfsError::from_io(e, from))
                }
            }
        }
    }

    async fn copy_within(
        &self,
        from: &VfsUri,
        to: &VfsUri,
        opts: CopyOpts,
        ct: CancellationToken,
    ) -> Result<(), VfsError> {
        let from_path = from.to_local_path()?;
        let to_path = to.to_local_path()?;
        if !opts.overwrite {
            if let Ok(true) = tokio::fs::try_exists(&to_path).await {
                return Err(VfsError::AlreadyExists(to.clone()));
            }
        }
        let meta = tokio::fs::symlink_metadata(&from_path)
            .await
            .map_err(|e| VfsError::from_io(e, from))?;
        if meta.is_dir() {
            copy_dir_recursive(&from_path, &to_path, &ct).await
        } else {
            tokio::fs::copy(&from_path, &to_path)
                .await
                .map(|_| ())
                .map_err(|e| VfsError::from_io(e, from))
        }
    }

    async fn watch(
        &self,
        uri: &VfsUri,
        recursive: bool,
        sink: EventSink,
    ) -> Result<WatchHandle, VfsError> {
        let path = uri.to_local_path()?;
        let mode = if recursive {
            notify::RecursiveMode::Recursive
        } else {
            notify::RecursiveMode::NonRecursive
        };
        let sink = sink.clone();
        let mut watcher = notify::recommended_watcher(move |res: notify::Result<notify::Event>| {
            if let Ok(event) = res {
                for fs_event in translate_notify_event(&event) {
                    let _ = sink.try_send(fs_event);
                }
            }
        })
        .map_err(|e| VfsError::Io {
            message: e.to_string(),
        })?;
        watcher.watch(&path, mode).map_err(|e| VfsError::Io {
            message: e.to_string(),
        })?;
        Ok(WatchHandle::new(watcher))
    }
}
