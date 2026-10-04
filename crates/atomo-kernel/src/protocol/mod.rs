mod cancellation;
mod dispatch;
mod methods;
mod params;

use std::sync::Arc;

use serde_json::Value;

pub use cancellation::CallCancellation;
pub(crate) use dispatch::{typed_method, BoxFuture, Method, MethodEntry};

/// Where a method streams events (a Tauri Channel in the app, a closure in tests).
pub type EventSink = Arc<dyn Fn(Value) + Send + Sync>;

/// Who is calling a protocol method.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum Caller {
    /// The shell: trusted, and the only source of user gestures.
    #[default]
    Shell,
    /// A plugin half calling the public API through a host bridge (the
    /// shell's sandbox host, a runtime host). The bridge binds the identity;
    /// the plugin never claims it. Only API methods are reachable.
    Plugin(String),
}

impl Caller {
    /// The plugin this call acts for, if any.
    pub fn plugin(&self) -> Option<&str> {
        match self {
            Caller::Plugin(id) => Some(id),
            _ => None,
        }
    }
}

/// Who may call a protocol method.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Visibility {
    /// The internal kernel <-> shell protocol - only shell can call.
    Internal,
    /// Part of the public plugin API: also callable by `Caller::Plugin`.
    /// Handlers must act with the caller's identity and grants.
    Api,
}

/// Per-call context of a protocol method.
#[derive(Clone, Default)]
pub struct CallContext {
    /// Present when the call came through `kernel_subscribe`.
    pub sink: Option<EventSink>,
    pub caller: Caller,
}
