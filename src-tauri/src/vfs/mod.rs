#[cfg(test)]
mod conformance_tests;
pub mod engine;
#[cfg(test)]
mod engine_tests;
pub mod error;
pub mod local;
pub mod mem;
pub mod ops;
pub mod provider;
pub mod types;
pub mod uri;
pub mod watch;

pub use engine::VfsEngine;
pub use error::VfsError;
#[allow(unused_imports)]
pub use provider::{ByteStream, EventSink, FsProvider, WatchHandle};
pub use types::*;
pub use uri::VfsUri;
