use std::sync::Arc;

use futures::stream::StreamExt;
use tauri::ipc::Channel;
use tauri::State;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::events::EventBus;
use crate::vfs::ops::OpCtx;
use crate::vfs::watch::WatchSessions;
use crate::vfs::{
    CopyOpts, DeleteOpts, DirEntry, ListOpts, OpProgress, PerSourceResult, Stat, VfsEngine,
    VfsError, VfsUri, WriteOpts,
};

/// Guards `vfs_read` against accidentally loading huge files into memory
/// through the small-write IPC path; big reads should use the `vfs://` protocol.
const DEFAULT_MAX_READ: u64 = 16 * 1024 * 1024;

#[tauri::command]
pub async fn vfs_stat(engine: State<'_, Arc<VfsEngine>>, uri: VfsUri) -> Result<Stat, VfsError> {
    engine.stat(&uri).await
}

#[tauri::command]
pub async fn vfs_list(
    engine: State<'_, Arc<VfsEngine>>,
    uri: VfsUri,
    opts: Option<ListOpts>,
) -> Result<Vec<DirEntry>, VfsError> {
    engine.list(&uri, opts.unwrap_or_default()).await
}

#[tauri::command]
pub async fn vfs_read(
    engine: State<'_, Arc<VfsEngine>>,
    uri: VfsUri,
    range: Option<(u64, u64)>,
    max_size: Option<u64>,
) -> Result<Vec<u8>, VfsError> {
    let max = max_size.unwrap_or(DEFAULT_MAX_READ);
    match range {
        Some((start, end)) => {
            if end.saturating_sub(start) > max {
                return Err(VfsError::TooLarge { limit: max });
            }
            let mut stream = engine
                .read_stream(&uri, Some(start..end), CancellationToken::new())
                .await?;
            let mut buf = Vec::new();
            while let Some(chunk) = stream.next().await {
                buf.extend_from_slice(&chunk?);
            }
            Ok(buf)
        }
        None => engine.read_all(&uri, max).await,
    }
}

#[tauri::command]
pub async fn vfs_write(
    engine: State<'_, Arc<VfsEngine>>,
    uri: VfsUri,
    data: Vec<u8>,
    opts: Option<WriteOpts>,
) -> Result<(), VfsError> {
    engine
        .write_bytes(
            &uri,
            data,
            opts.unwrap_or_default(),
            CancellationToken::new(),
        )
        .await
}

#[tauri::command]
pub async fn vfs_mkdir(engine: State<'_, Arc<VfsEngine>>, uri: VfsUri) -> Result<(), VfsError> {
    engine.mkdir(&uri).await
}

#[tauri::command]
pub async fn vfs_delete(
    engine: State<'_, Arc<VfsEngine>>,
    uris: Vec<VfsUri>,
    opts: Option<DeleteOpts>,
    op_id: Uuid,
) -> Result<Vec<PerSourceResult>, VfsError> {
    let (ct, _guard) = engine.ops.start(op_id);
    Ok(engine.delete_many(uris, opts.unwrap_or_default(), ct).await)
}

#[tauri::command]
pub async fn vfs_rename(
    engine: State<'_, Arc<VfsEngine>>,
    from: VfsUri,
    to: VfsUri,
    overwrite: bool,
) -> Result<(), VfsError> {
    engine.rename(&from, &to, overwrite).await
}

#[tauri::command]
pub async fn vfs_copy(
    engine: State<'_, Arc<VfsEngine>>,
    sources: Vec<VfsUri>,
    dest_dir: VfsUri,
    opts: Option<CopyOpts>,
    op_id: Uuid,
    on_progress: Channel<OpProgress>,
) -> Result<Vec<PerSourceResult>, VfsError> {
    let (ct, _guard) = engine.ops.start(op_id);
    let op = OpCtx::new(op_id, ct, move |p: OpProgress| {
        let _ = on_progress.send(p);
    });
    Ok(engine
        .copy(sources, dest_dir, opts.unwrap_or_default(), &op)
        .await)
}

#[tauri::command]
pub async fn vfs_move(
    engine: State<'_, Arc<VfsEngine>>,
    sources: Vec<VfsUri>,
    dest_dir: VfsUri,
    opts: Option<CopyOpts>,
    op_id: Uuid,
    on_progress: Channel<OpProgress>,
) -> Result<Vec<PerSourceResult>, VfsError> {
    let (ct, _guard) = engine.ops.start(op_id);
    let op = OpCtx::new(op_id, ct, move |p: OpProgress| {
        let _ = on_progress.send(p);
    });
    Ok(engine
        .move_(sources, dest_dir, opts.unwrap_or_default(), &op)
        .await)
}

#[tauri::command]
pub fn vfs_cancel_op(engine: State<'_, Arc<VfsEngine>>, op_id: Uuid) {
    engine.ops.cancel(op_id);
}

#[tauri::command]
pub async fn vfs_watch(
    engine: State<'_, Arc<VfsEngine>>,
    watches: State<'_, Arc<WatchSessions>>,
    events: State<'_, EventBus>,
    uri: VfsUri,
    recursive: bool,
) -> Result<Uuid, VfsError> {
    watches.watch(&engine, &events, uri, recursive).await
}

#[tauri::command]
pub fn vfs_unwatch(watches: State<'_, Arc<WatchSessions>>, watch_id: Uuid) {
    watches.unwatch(watch_id);
}

#[tauri::command]
pub fn vfs_home_dir() -> Result<VfsUri, VfsError> {
    let home = dirs::home_dir().ok_or_else(|| VfsError::Io {
        message: "could not determine home directory".into(),
    })?;
    VfsUri::from_local_path(&home)
}
