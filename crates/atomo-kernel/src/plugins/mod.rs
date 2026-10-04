//! Plugins: what a backend implements, what it sees while activating, and
//! its lifecycle (activation, disposal, reloads, enabling and consent).

mod activation;
mod host;
mod lifecycle;
mod management;
mod state;

pub use activation::ActivationContext;
pub use host::{NativePlugin, RuntimeHost};
pub use management::{PluginReloaded, ReloadReason};
pub(crate) use state::{ManifestSource, Plugins};

use crate::{ErrorCode, Kernel, KernelError};

impl Kernel {
    pub(crate) fn plugins(&self) -> &Plugins {
        &self.0.plugins
    }

    pub(crate) fn not_a_plugin(id: &str) -> KernelError {
        KernelError::new(ErrorCode::NotFound, format!("no plugin `{id}`"))
    }
}
