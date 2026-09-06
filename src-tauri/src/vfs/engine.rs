use std::collections::HashMap;
use std::future::Future;
use std::ops::Range;
use std::pin::Pin;
use std::sync::{Arc, RwLock};

use bytes::Bytes;
use futures::stream::{self, StreamExt};
use tokio_util::sync::CancellationToken;

use crate::events::EventBus;

use super::error::VfsError;
use super::ops::OpCtx;
pub use super::ops::OpRegistry;
use super::provider::{ByteStream, FsProvider};
use super::types::{
    CopyOpts, DeleteOpts, DirEntry, FileType, FsEvent, FsEventKind, ListOpts, PerSourceResult,
    Stat, WriteOpts,
};
use super::uri::VfsUri;

pub struct VfsEngine {
    providers: RwLock<HashMap<String, Arc<dyn FsProvider>>>,
    pub ops: OpRegistry,
    events: EventBus,
}

impl VfsEngine {
    pub fn new(events: EventBus) -> Self {
        VfsEngine {
            providers: RwLock::new(HashMap::new()),
            ops: OpRegistry::new(),
            events,
        }
    }

    pub fn register_provider(&self, provider: Arc<dyn FsProvider>) {
        self.providers
            .write()
            .unwrap()
            .insert(provider.scheme().to_string(), provider);
    }

    pub fn provider_for(&self, uri: &VfsUri) -> Result<Arc<dyn FsProvider>, VfsError> {
        self.providers
            .read()
            .unwrap()
            .get(uri.scheme())
            .cloned()
            .ok_or_else(|| VfsError::NoProvider(uri.scheme().to_string()))
    }

    pub async fn stat(&self, uri: &VfsUri) -> Result<Stat, VfsError> {
        self.provider_for(uri)?
            .stat(uri, CancellationToken::new())
            .await
    }

    pub async fn list(&self, uri: &VfsUri, opts: ListOpts) -> Result<Vec<DirEntry>, VfsError> {
        self.provider_for(uri)?
            .list(uri, opts, CancellationToken::new())
            .await
    }

    pub async fn read_stream(
        &self,
        uri: &VfsUri,
        range: Option<Range<u64>>,
        ct: CancellationToken,
    ) -> Result<ByteStream, VfsError> {
        self.provider_for(uri)?.read(uri, range, ct).await
    }

    pub async fn read_all(&self, uri: &VfsUri, max_size: u64) -> Result<Vec<u8>, VfsError> {
        let mut stream = self
            .read_stream(uri, None, CancellationToken::new())
            .await?;
        let mut buf = Vec::new();
        while let Some(chunk) = stream.next().await {
            let bytes = chunk?;
            if buf.len() as u64 + bytes.len() as u64 > max_size {
                return Err(VfsError::TooLarge { limit: max_size });
            }
            buf.extend_from_slice(&bytes);
        }
        Ok(buf)
    }

    pub async fn mkdir(&self, uri: &VfsUri) -> Result<(), VfsError> {
        self.provider_for(uri)?
            .mkdir(uri, CancellationToken::new())
            .await?;
        self.events.emit_fs(FsEvent {
            kind: FsEventKind::Created,
            uri: uri.clone(),
            renamed_to: None,
        });
        Ok(())
    }

    pub async fn write_bytes(
        &self,
        uri: &VfsUri,
        data: Vec<u8>,
        opts: WriteOpts,
        ct: CancellationToken,
    ) -> Result<(), VfsError> {
        let provider = self.provider_for(uri)?;
        // Determining write-new vs write-existing: stat before write.
        let existed = provider.stat(uri, ct.clone()).await.is_ok();
        let stream: ByteStream = Box::pin(stream::once(async move { Ok(Bytes::from(data)) }));
        provider.write(uri, stream, opts, ct).await?;
        self.events.emit_fs(FsEvent {
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

    pub async fn delete_many(
        &self,
        uris: Vec<VfsUri>,
        opts: DeleteOpts,
        ct: CancellationToken,
    ) -> Vec<PerSourceResult> {
        let mut out = Vec::with_capacity(uris.len());
        for uri in uris {
            if ct.is_cancelled() {
                out.push(PerSourceResult {
                    source: uri,
                    ok: false,
                    error: Some(VfsError::Cancelled),
                });
                continue;
            }
            let result = match self.provider_for(&uri) {
                Ok(p) => p.delete(&uri, opts, ct.clone()).await,
                Err(e) => Err(e),
            };
            match result {
                Ok(()) => {
                    self.events.emit_fs(FsEvent {
                        kind: FsEventKind::Removed,
                        uri: uri.clone(),
                        renamed_to: None,
                    });
                    out.push(PerSourceResult {
                        source: uri,
                        ok: true,
                        error: None,
                    });
                }
                Err(e) => out.push(PerSourceResult {
                    source: uri,
                    ok: false,
                    error: Some(e),
                }),
            }
        }
        out
    }

    pub async fn rename(
        &self,
        from: &VfsUri,
        to: &VfsUri,
        overwrite: bool,
    ) -> Result<(), VfsError> {
        if from.scheme() != to.scheme() || from.authority() != to.authority() {
            return Err(VfsError::NotSupported {
                capability: "cross-provider rename".into(),
            });
        }
        self.provider_for(from)?
            .rename(from, to, overwrite, CancellationToken::new())
            .await?;
        self.events.emit_fs(FsEvent {
            kind: FsEventKind::Renamed,
            uri: from.clone(),
            renamed_to: Some(to.clone()),
        });
        Ok(())
    }

    pub async fn copy(
        &self,
        sources: Vec<VfsUri>,
        dest_dir: VfsUri,
        opts: CopyOpts,
        op: &OpCtx,
    ) -> Vec<PerSourceResult> {
        let mut out = Vec::with_capacity(sources.len());
        let mut plans = Vec::new();
        let mut total_bytes = 0u64;
        let mut total_files = 0u64;

        for source in &sources {
            match self.plan_copy(source, &dest_dir, op).await {
                Ok((dest, from_provider, to_provider, entries)) => {
                    for (_, st) in &entries {
                        total_files += 1;
                        total_bytes += st.size;
                    }
                    plans.push((source.clone(), dest, from_provider, to_provider, entries));
                }
                Err(e) => out.push(PerSourceResult {
                    source: source.clone(),
                    ok: false,
                    error: Some(e),
                }),
            }
        }

        let mut done_bytes = 0u64;
        let mut done_files = 0u64;
        for (source, dest, from_provider, to_provider, entries) in plans {
            let result = self
                .copy_one(
                    &source,
                    &dest,
                    &from_provider,
                    &to_provider,
                    opts,
                    op,
                    &entries,
                    &mut done_bytes,
                    &mut done_files,
                    total_bytes,
                    total_files,
                )
                .await;
            match result {
                Ok(()) => out.push(PerSourceResult {
                    source,
                    ok: true,
                    error: None,
                }),
                Err(e) => out.push(PerSourceResult {
                    source,
                    ok: false,
                    error: Some(e),
                }),
            }
        }
        out
    }

    pub async fn move_(
        &self,
        sources: Vec<VfsUri>,
        dest_dir: VfsUri,
        opts: CopyOpts,
        op: &OpCtx,
    ) -> Vec<PerSourceResult> {
        let mut out = Vec::with_capacity(sources.len());
        for source in sources {
            let dest = match dest_dir.join(source.name().unwrap_or_default()) {
                Ok(d) => d,
                Err(e) => {
                    out.push(PerSourceResult {
                        source,
                        ok: false,
                        error: Some(e),
                    });
                    continue;
                }
            };
            if source == dest || source.is_ancestor_of(&dest) {
                out.push(PerSourceResult {
                    source: source.clone(),
                    ok: false,
                    error: Some(VfsError::InvalidTarget(format!(
                        "cannot move {source} into itself"
                    ))),
                });
                continue;
            }
            let same_provider =
                source.scheme() == dest.scheme() && source.authority() == dest.authority();
            let result: Result<(), VfsError> = if same_provider {
                match self.provider_for(&source) {
                    Ok(p) => {
                        p.rename(&source, &dest, opts.overwrite, op.ct.clone())
                            .await
                    }
                    Err(e) => Err(e),
                }
            } else {
                // Cross-provider: copy this source fully, then delete the
                // source only after that copy fully succeeded.
                let copy_results = self
                    .copy(vec![source.clone()], dest_dir.clone(), opts, op)
                    .await;
                match copy_results.into_iter().next() {
                    Some(PerSourceResult { ok: true, .. }) => match self.provider_for(&source) {
                        Ok(p) => {
                            p.delete(
                                &source,
                                DeleteOpts {
                                    recursive: true,
                                    use_trash: false,
                                },
                                op.ct.clone(),
                            )
                            .await
                        }
                        Err(e) => Err(e),
                    },
                    Some(PerSourceResult { error, .. }) => Err(error.unwrap_or(VfsError::Io {
                        message: "copy failed".into(),
                    })),
                    None => Err(VfsError::Io {
                        message: "copy produced no result".into(),
                    }),
                }
            };
            match result {
                Ok(()) => {
                    self.events.emit_fs(FsEvent {
                        kind: FsEventKind::Renamed,
                        uri: source.clone(),
                        renamed_to: Some(dest.clone()),
                    });
                    out.push(PerSourceResult {
                        source,
                        ok: true,
                        error: None,
                    });
                }
                Err(e) => out.push(PerSourceResult {
                    source,
                    ok: false,
                    error: Some(e),
                }),
            }
        }
        out
    }

    async fn plan_copy(
        &self,
        source: &VfsUri,
        dest_dir: &VfsUri,
        op: &OpCtx,
    ) -> Result<
        (
            VfsUri,
            Arc<dyn FsProvider>,
            Arc<dyn FsProvider>,
            Vec<(VfsUri, Stat)>,
        ),
        VfsError,
    > {
        let dest = dest_dir.join(source.name().unwrap_or_default())?;
        if source == &dest || source.is_ancestor_of(&dest) {
            return Err(VfsError::InvalidTarget(format!(
                "cannot copy {source} into itself"
            )));
        }
        let from_provider = self.provider_for(source)?;
        let to_provider = self.provider_for(&dest)?;
        let entries = walk(&from_provider, source, &op.ct).await?;
        Ok((dest, from_provider, to_provider, entries))
    }

    #[allow(clippy::too_many_arguments)]
    async fn copy_one(
        &self,
        source: &VfsUri,
        dest: &VfsUri,
        from_provider: &Arc<dyn FsProvider>,
        to_provider: &Arc<dyn FsProvider>,
        opts: CopyOpts,
        op: &OpCtx,
        entries: &[(VfsUri, Stat)],
        done_bytes: &mut u64,
        done_files: &mut u64,
        total_bytes: u64,
        total_files: u64,
    ) -> Result<(), VfsError> {
        op.check_cancelled()?;
        let same_provider =
            source.scheme() == dest.scheme() && source.authority() == dest.authority();

        if same_provider && from_provider.caps().copy_within {
            match from_provider
                .copy_within(source, dest, opts, op.ct.clone())
                .await
            {
                Ok(()) => {
                    *done_bytes += entries.iter().map(|(_, s)| s.size).sum::<u64>();
                    *done_files += entries.len() as u64;
                    op.report(
                        *done_bytes,
                        total_bytes,
                        *done_files,
                        total_files,
                        Some(dest.clone()),
                    );
                    self.events.emit_fs(FsEvent {
                        kind: FsEventKind::Created,
                        uri: dest.clone(),
                        renamed_to: None,
                    });
                    return Ok(());
                }
                Err(VfsError::NotSupported { .. }) => {}
                Err(e) => return Err(e),
            }
        }

        let from_len = source.segments().count();
        for (entry_uri, stat) in entries {
            op.check_cancelled()?;
            let mut rel = dest.clone();
            for seg in entry_uri.segments().skip(from_len) {
                rel = rel.join(seg)?;
            }
            match stat.file_type {
                FileType::Directory => match to_provider.mkdir(&rel, op.ct.clone()).await {
                    Ok(()) => self.events.emit_fs(FsEvent {
                        kind: FsEventKind::Created,
                        uri: rel.clone(),
                        renamed_to: None,
                    }),
                    Err(VfsError::AlreadyExists(_)) => {}
                    Err(e) => return Err(e),
                },
                FileType::File | FileType::Symlink => {
                    if !opts.overwrite && to_provider.stat(&rel, op.ct.clone()).await.is_ok() {
                        return Err(VfsError::AlreadyExists(rel));
                    }
                    let byte_stream = from_provider.read(entry_uri, None, op.ct.clone()).await?;
                    let write_opts = WriteOpts {
                        overwrite: opts.overwrite,
                        create_parents: true,
                    };
                    to_provider
                        .write(&rel, byte_stream, write_opts, op.ct.clone())
                        .await?;
                    self.events.emit_fs(FsEvent {
                        kind: FsEventKind::Created,
                        uri: rel.clone(),
                        renamed_to: None,
                    });
                }
            }
            *done_files += 1;
            *done_bytes += stat.size;
            op.report(
                *done_bytes,
                total_bytes,
                *done_files,
                total_files,
                Some(rel),
            );
        }
        Ok(())
    }
}

type WalkResult = Result<Vec<(VfsUri, Stat)>, VfsError>;

fn walk<'a>(
    provider: &'a Arc<dyn FsProvider>,
    root: &'a VfsUri,
    ct: &'a CancellationToken,
) -> Pin<Box<dyn Future<Output = WalkResult> + Send + 'a>> {
    Box::pin(async move {
        let stat = provider.stat(root, ct.clone()).await?;
        let mut out = vec![(root.clone(), stat.clone())];
        if stat.file_type == FileType::Directory {
            let children = provider
                .list(
                    root,
                    ListOpts {
                        include_hidden: true,
                    },
                    ct.clone(),
                )
                .await?;
            for child in children {
                if ct.is_cancelled() {
                    return Err(VfsError::Cancelled);
                }
                let sub = walk(provider, &child.uri, ct).await?;
                out.extend(sub);
            }
        }
        Ok(out)
    })
}
