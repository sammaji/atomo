//! What runs a plugin's backend: compiled-in native plugins and runtime hosts.

use std::path::Path;
use std::sync::Arc;

use atomo_manifest::{BackendRuntime, Manifest};

use super::ActivationContext;
use crate::{Kernel, KernelResult};

/// A first-party plugin compiled into the binary (the `native` runtime).
pub trait NativePlugin: Send + Sync + 'static {
    /// The plugin's `atomo-plugin.json`, usually `include_str!("../atomo-plugin.json")`.
    fn manifest(&self) -> &'static str;
    fn activate(&self, ctx: &mut ActivationContext<'_>) -> KernelResult<()>;
    /// Optional cleanup; the kernel disposes registrations either way.
    fn deactivate(&self) {}
}

/// Runs backend halves that are not compiled in (e.g. `wasm`).
///
/// `activate` must not run plugin code, so that no third-party code runs at
/// startup: it validates the package and registers lazy proxies (a thumbnail
/// generator, a VFS provider…) with the platform plugins, which instantiate
/// the backend on first use.
pub trait RuntimeHost: Send + Sync + 'static {
    fn runtime(&self) -> BackendRuntime;
    fn activate(
        &self,
        manifest: &Manifest,
        dir: Option<&Path>,
        ctx: &mut ActivationContext<'_>,
    ) -> KernelResult<()>;
    fn deactivate(&self, _plugin_id: &str) {}
}

impl Kernel {
    pub(crate) fn host_for(&self, manifest: &Manifest) -> Option<Arc<dyn RuntimeHost>> {
        let runtime = manifest.backend.as_ref()?.runtime;
        self.plugins()
            .hosts
            .iter()
            .find(|h| h.runtime() == runtime)
            .cloned()
    }

    /// Whether this build can run the plugin's backend half.
    pub(crate) fn runs_backend(&self, id: &str) -> bool {
        self.plugins().natives.contains_key(id)
            || self
                .registry_state()
                .manifests
                .get(id)
                .is_some_and(|m| self.host_for(m).is_some())
    }
}
