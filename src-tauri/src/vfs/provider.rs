use std::ops::Range;
use std::pin::Pin;

use async_trait::async_trait;
use bytes::Bytes;
use futures::Stream;
use tokio_util::sync::CancellationToken;

use super::error::VfsError;
use super::types::{DeleteOpts, DirEntry, FsEvent, ListOpts, ProviderCaps, Stat, WriteOpts};
use super::uri::VfsUri;

pub type ByteStream = Pin<Box<dyn Stream<Item = Result<Bytes, VfsError>> + Send>>;

pub type EventSink = tokio::sync::mpsc::Sender<FsEvent>;

/// Dropping the handle stops the watch (providers should tie teardown to `Drop`).
/// The payload is never read; it exists to be dropped.
pub struct WatchHandle(#[allow(dead_code)] pub Box<dyn Send>);

impl WatchHandle {
    pub fn new<T: Send + 'static>(inner: T) -> Self {
        WatchHandle(Box::new(inner))
    }
}

#[async_trait]
pub trait FsProvider: Send + Sync + 'static {
    fn scheme(&self) -> &str;
    fn caps(&self) -> ProviderCaps;

    async fn stat(&self, uri: &VfsUri, ct: CancellationToken) -> Result<Stat, VfsError>;
    async fn list(
        &self,
        uri: &VfsUri,
        opts: ListOpts,
        ct: CancellationToken,
    ) -> Result<Vec<DirEntry>, VfsError>;
    async fn read(
        &self,
        uri: &VfsUri,
        range: Option<Range<u64>>,
        ct: CancellationToken,
    ) -> Result<ByteStream, VfsError>;
    async fn write(
        &self,
        uri: &VfsUri,
        data: ByteStream,
        opts: WriteOpts,
        ct: CancellationToken,
    ) -> Result<(), VfsError>;
    async fn mkdir(&self, uri: &VfsUri, ct: CancellationToken) -> Result<(), VfsError>;
    async fn delete(
        &self,
        uri: &VfsUri,
        opts: DeleteOpts,
        ct: CancellationToken,
    ) -> Result<(), VfsError>;
    async fn rename(
        &self,
        from: &VfsUri,
        to: &VfsUri,
        overwrite: bool,
        ct: CancellationToken,
    ) -> Result<(), VfsError>;

    /// Optional fast path; the engine falls back to read+write streaming when
    /// this returns `NotSupported`.
    async fn copy_within(
        &self,
        _from: &VfsUri,
        _to: &VfsUri,
        _opts: super::types::CopyOpts,
        _ct: CancellationToken,
    ) -> Result<(), VfsError> {
        Err(VfsError::NotSupported {
            capability: "copyWithin".into(),
        })
    }

    /// Optional; providers that can't watch return `NotSupported`.
    async fn watch(
        &self,
        _uri: &VfsUri,
        _recursive: bool,
        _sink: EventSink,
    ) -> Result<WatchHandle, VfsError> {
        Err(VfsError::NotSupported {
            capability: "watch".into(),
        })
    }
}
