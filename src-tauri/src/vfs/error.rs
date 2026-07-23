use std::io;

use serde::{Serialize, Serializer};

use super::uri::VfsUri;

#[derive(thiserror::Error, Debug, Clone)]
pub enum VfsError {
    #[error("not found: {0}")]
    NotFound(VfsUri),
    #[error("already exists: {0}")]
    AlreadyExists(VfsUri),
    #[error("permission denied: {0}")]
    PermissionDenied(VfsUri),
    #[error("not a directory: {0}")]
    NotADirectory(VfsUri),
    #[error("is a directory: {0}")]
    IsADirectory(VfsUri),
    #[error("directory not empty: {0}")]
    DirectoryNotEmpty(VfsUri),
    #[error("invalid uri: {0}")]
    InvalidUri(String),
    #[error("invalid target: {0}")]
    InvalidTarget(String),
    #[error("no provider for scheme: {0}")]
    NoProvider(String),
    #[error("not supported: {capability}")]
    NotSupported { capability: String },
    #[error("cancelled")]
    Cancelled,
    #[error("too large: limit is {limit} bytes")]
    TooLarge { limit: u64 },
    #[error("io error: {message}")]
    Io { message: String },
    #[error("provider error [{code}]: {message}")]
    Provider { code: String, message: String },
}

impl VfsError {
    pub fn code(&self) -> &'static str {
        match self {
            VfsError::NotFound(_) => "not_found",
            VfsError::AlreadyExists(_) => "already_exists",
            VfsError::PermissionDenied(_) => "permission_denied",
            VfsError::NotADirectory(_) => "not_a_directory",
            VfsError::IsADirectory(_) => "is_a_directory",
            VfsError::DirectoryNotEmpty(_) => "directory_not_empty",
            VfsError::InvalidUri(_) => "invalid_uri",
            VfsError::InvalidTarget(_) => "invalid_target",
            VfsError::NoProvider(_) => "no_provider",
            VfsError::NotSupported { .. } => "not_supported",
            VfsError::Cancelled => "cancelled",
            VfsError::TooLarge { .. } => "too_large",
            VfsError::Io { .. } => "io",
            VfsError::Provider { .. } => "provider",
        }
    }

    pub fn uri(&self) -> Option<&VfsUri> {
        match self {
            VfsError::NotFound(u)
            | VfsError::AlreadyExists(u)
            | VfsError::PermissionDenied(u)
            | VfsError::NotADirectory(u)
            | VfsError::IsADirectory(u)
            | VfsError::DirectoryNotEmpty(u) => Some(u),
            _ => None,
        }
    }

    /// Maps an `io::Error` encountered while operating on `uri` to a typed
    /// VfsError instead of letting a bare io string cross the IPC boundary.
    pub fn from_io(err: io::Error, uri: &VfsUri) -> Self {
        match err.kind() {
            io::ErrorKind::NotFound => VfsError::NotFound(uri.clone()),
            io::ErrorKind::PermissionDenied => VfsError::PermissionDenied(uri.clone()),
            io::ErrorKind::AlreadyExists => VfsError::AlreadyExists(uri.clone()),
            io::ErrorKind::DirectoryNotEmpty => VfsError::DirectoryNotEmpty(uri.clone()),
            _ => {
                // ENOTEMPTY is not consistently mapped to DirectoryNotEmpty on all
                // platforms/rust versions; check the raw code as a fallback.
                #[cfg(unix)]
                const ENOTEMPTY: i32 = 39; // linux/macos value
                #[cfg(unix)]
                if err.raw_os_error() == Some(ENOTEMPTY) {
                    return VfsError::DirectoryNotEmpty(uri.clone());
                }
                VfsError::Io {
                    message: err.to_string(),
                }
            }
        }
    }
}

#[derive(Serialize)]
struct SerializedVfsError<'a> {
    code: &'static str,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    uri: Option<&'a VfsUri>,
}

impl Serialize for VfsError {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        SerializedVfsError {
            code: self.code(),
            message: self.to_string(),
            uri: self.uri(),
        }
        .serialize(serializer)
    }
}
