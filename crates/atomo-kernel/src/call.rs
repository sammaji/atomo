use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::Value;

use crate::{KernelError, KernelResult};

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
    /// The internal kernel <-> shell protocol: the shell only.
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

pub(crate) type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send>>;
pub(crate) type Method =
    Arc<dyn Fn(CallContext, Value) -> BoxFuture<KernelResult<Value>> + Send + Sync>;

/// A registered protocol method.
pub(crate) struct MethodEntry {
    pub visibility: Visibility,
    pub handler: Method,
}

/// Wrap a typed handler: params are deserialized (a mismatch is
/// `invalid_params`) and the result serialized.
pub(crate) fn typed_method<P, R, F, Fut>(handler: F) -> Method
where
    P: DeserializeOwned + Send + 'static,
    R: Serialize + 'static,
    F: Fn(CallContext, P) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = KernelResult<R>> + Send + 'static,
{
    let handler = Arc::new(handler);
    Arc::new(move |ctx, params| {
        let handler = handler.clone();
        Box::pin(async move {
            let params: P = serde_json::from_value(params)
                .map_err(|e| KernelError::invalid_params(e.to_string()))?;
            let result = handler(ctx, params).await?;
            serde_json::to_value(result).map_err(|e| KernelError::internal(e.to_string()))
        })
    })
}
