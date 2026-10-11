//! The method table: registering handlers and dispatching calls to them.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::Value;

use super::{CallContext, Caller, Visibility};
use crate::{Kernel, KernelError, KernelResult};

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

impl Kernel {
    /// Call a protocol method. Plugin callers reach only API methods.
    pub async fn call(&self, ctx: CallContext, method: &str, params: Value) -> KernelResult<Value> {
        let (visibility, handler) = self
            .0
            .registrations
            .method(method)
            .ok_or_else(|| KernelError::not_found(format!("no such method: {method}")))?;
        if let (Caller::Plugin(id), Visibility::Internal) = (&ctx.caller, visibility) {
            return Err(KernelError::forbidden(format!(
                "`{method}` is not part of the plugin API (called by `{id}`)"
            )));
        }
        handler(ctx, params).await
    }

    pub(crate) fn register_method(&self, name: &str, visibility: Visibility, handler: Method) {
        self.0
            .registrations
            .insert_method(name, visibility, handler);
    }

    /// Register a method the kernel itself provides; the handler gets a kernel handle.
    pub(super) fn kernel_method<P, R, F, Fut>(&self, name: &str, visibility: Visibility, handler: F)
    where
        P: DeserializeOwned + Send + 'static,
        R: Serialize + 'static,
        F: Fn(Kernel, CallContext, P) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = KernelResult<R>> + Send + 'static,
    {
        let kernel = self.clone();
        let method = typed_method(move |call, params: P| handler(kernel.clone(), call, params));
        self.register_method(name, visibility, method);
    }
}
