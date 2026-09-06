use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::uri::VfsUri;

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum FileType {
    File,
    Directory,
    Symlink,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Stat {
    pub file_type: FileType,
    pub size: u64,
    pub modified_ms: Option<u64>,
    pub created_ms: Option<u64>,
    pub readonly: bool,
    pub symlink_target: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DirEntry {
    pub uri: VfsUri,
    pub name: String,
    pub file_type: FileType,
    pub size: u64,
    pub modified_ms: Option<u64>,
    pub hidden: bool,
    pub mime: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ProviderCaps {
    pub read: bool,
    pub write: bool,
    pub watch: bool,
    pub trash: bool,
    pub copy_within: bool,
    pub case_sensitive: bool,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Default)]
#[serde(rename_all = "camelCase")]
pub struct WriteOpts {
    pub overwrite: bool,
    pub create_parents: bool,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Default)]
#[serde(rename_all = "camelCase")]
pub struct DeleteOpts {
    pub recursive: bool,
    pub use_trash: bool,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Default)]
#[serde(rename_all = "camelCase")]
pub struct CopyOpts {
    pub overwrite: bool,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Default)]
#[serde(rename_all = "camelCase")]
pub struct ListOpts {
    pub include_hidden: bool,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum FsEventKind {
    Created,
    Modified,
    Removed,
    Renamed,
    Overflow,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct FsEvent {
    pub kind: FsEventKind,
    pub uri: VfsUri,
    pub renamed_to: Option<VfsUri>,
}

/// Crosses IPC host→client only (never deserialized on the Rust side), since
/// `VfsError`'s hand-written `Serialize` has no matching `Deserialize`.
#[derive(Serialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct PerSourceResult {
    pub source: VfsUri,
    pub ok: bool,
    pub error: Option<super::error::VfsError>,
}

#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct OpProgress {
    pub op_id: Uuid,
    pub done_bytes: u64,
    pub total_bytes: u64,
    pub done_files: u64,
    pub total_files: u64,
    pub current: Option<VfsUri>,
}
