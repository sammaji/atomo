//! The protocol methods the kernel itself provides. Internal ones serve the
//! shell; API ones are also reachable by plugins, which act with their own
//! identity and grants.

mod api;
mod broker;
mod shell;

use std::future::Future;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::call::{typed_method, CallContext, Caller, Visibility};
use crate::{Kernel, KernelError, KernelResult};

impl Kernel {
    pub(crate) fn register_methods(&self) {
        shell::register(self);
        api::register(self);
        broker::register(self);
    }

    fn kernel_method<P, R, F, Fut>(&self, name: &str, handler: F)
    where
        P: DeserializeOwned + Send + 'static,
        R: Serialize + 'static,
        F: Fn(Kernel, CallContext, P) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = KernelResult<R>> + Send + 'static,
    {
        self.kernel_register(name, Visibility::Internal, handler);
    }

    fn kernel_api<P, R, F, Fut>(&self, name: &str, handler: F)
    where
        P: DeserializeOwned + Send + 'static,
        R: Serialize + 'static,
        F: Fn(Kernel, CallContext, P) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = KernelResult<R>> + Send + 'static,
    {
        self.kernel_register(name, Visibility::Api, handler);
    }

    fn kernel_register<P, R, F, Fut>(&self, name: &str, visibility: Visibility, handler: F)
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

    /// Fails unless the shell itself is calling.
    fn require_shell(call: &CallContext, what: &str) -> KernelResult<()> {
        if call.caller == Caller::Shell {
            Ok(())
        } else {
            Err(KernelError::forbidden(format!("only the shell {what}")))
        }
    }
}

/// Params of a method a frontend half calls about itself. In-realm frontends
/// call through the shell, which is trusted to name the plugin; behind a
/// bridge (`Caller::Plugin`) the bound identity overrides whatever is claimed.
#[derive(Deserialize)]
struct AsPlugin<T> {
    #[serde(default)]
    plugin: String,
    #[serde(flatten)]
    rest: T,
}

impl<T> AsPlugin<T> {
    fn bind(mut self, call: &CallContext) -> KernelResult<Self> {
        if let Caller::Plugin(id) = &call.caller {
            self.plugin = id.clone();
        }
        if self.plugin.is_empty() {
            return Err(KernelError::invalid_params("missing `plugin`"));
        }
        Ok(self)
    }
}
