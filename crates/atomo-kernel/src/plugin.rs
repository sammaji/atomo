//! What plugin backends implement, and what they see while activating.

use std::any::TypeId;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use atomo_manifest::{BackendRuntime, Manifest};
use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::Value;
use tokio_util::sync::CancellationToken;

use crate::call::{typed_method, CallContext, Visibility};
use crate::command::{typed_command, CommandEntry};
use crate::{
    Contribution, ErrorCode, Invocation, Kernel, KernelError, KernelResult, PluginStorage,
    RegistrySnapshot, RightChecker, Tier,
};

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

/// Registrations a plugin instance owns, disposed on deactivation.
#[derive(Default)]
pub(crate) struct Ledger {
    pub methods: Vec<String>,
    pub commands: Vec<String>,
    pub services: Vec<TypeId>,
    /// Whether it defined rights (`ActivationContext::define_rights`).
    pub rights: bool,
    pub cancel: CancellationToken,
}

/// What a backend sees while activating. Everything registered through it
/// is owned by the plugin and disposed on deactivation.
pub struct ActivationContext<'a> {
    pub(crate) kernel: &'a Kernel,
    pub(crate) plugin_id: String,
    pub(crate) cancel: CancellationToken,
}

impl ActivationContext<'_> {
    pub fn plugin_id(&self) -> &str {
        &self.plugin_id
    }

    pub fn runtime(&self) -> &tokio::runtime::Handle {
        self.kernel.runtime()
    }

    /// A handle for use after activation (executing commands, publishing events…).
    pub fn kernel(&self) -> Kernel {
        self.kernel.clone()
    }

    /// Cancelled when the plugin deactivates; tie background tasks to it.
    pub fn cancellation(&self) -> CancellationToken {
        self.cancel.clone()
    }

    /// Spawn a task that is cancelled when the plugin deactivates.
    pub fn spawn(&self, task: impl Future<Output = ()> + Send + 'static) {
        let cancel = self.cancel.clone();
        self.kernel.runtime().spawn(async move {
            tokio::select! {
                _ = task => {}
                _ = cancel.cancelled() => {}
            }
        });
    }

    fn ledger<R>(&self, f: impl FnOnce(&mut Ledger) -> R) -> R {
        f(self
            .kernel
            .0
            .ledgers
            .lock()
            .get_mut(&self.plugin_id)
            .expect("activating"))
    }

    /// Provide a service other plugins can look up by type.
    pub fn provide<T: Send + Sync + 'static>(&mut self, service: Arc<T>) {
        self.kernel
            .0
            .services
            .write()
            .insert(TypeId::of::<T>(), (self.plugin_id.clone(), service));
        self.ledger(|l| l.services.push(TypeId::of::<T>()));
    }

    /// A service provided by an active plugin (declare it in `dependencies`).
    pub fn service<T: Send + Sync + 'static>(&self) -> KernelResult<Arc<T>> {
        self.kernel.service().ok_or_else(|| {
            KernelError::not_found(format!(
                "{} needs service {} which no active plugin provides",
                self.plugin_id,
                std::any::type_name::<T>()
            ))
        })
    }

    /// Register an internal protocol method with typed params and result.
    pub fn method<P, R, F, Fut>(&mut self, name: &str, handler: F)
    where
        P: DeserializeOwned + Send + 'static,
        R: Serialize + 'static,
        F: Fn(CallContext, P) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = KernelResult<R>> + Send + 'static,
    {
        self.register(name, Visibility::Internal, handler);
    }

    /// Register a public plugin API method: callable by other plugins through
    /// a bridge. The handler must act with `call.caller`'s grants.
    pub fn api<P, R, F, Fut>(&mut self, name: &str, handler: F)
    where
        P: DeserializeOwned + Send + 'static,
        R: Serialize + 'static,
        F: Fn(CallContext, P) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = KernelResult<R>> + Send + 'static,
    {
        self.register(name, Visibility::Api, handler);
    }

    fn register<P, R, F, Fut>(&mut self, name: &str, visibility: Visibility, handler: F)
    where
        P: DeserializeOwned + Send + 'static,
        R: Serialize + 'static,
        F: Fn(CallContext, P) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = KernelResult<R>> + Send + 'static,
    {
        self.kernel
            .register_method(name, visibility, typed_method(handler));
        self.ledger(|l| l.methods.push(name.to_owned()));
    }

    /// Define rights and their scope semantics: core-tier plugins only.
    /// Removed when the plugin deactivates.
    pub fn define_rights(&mut self, checker: Arc<dyn RightChecker>) -> KernelResult<()> {
        let core = self
            .kernel
            .0
            .registry
            .load()
            .snapshot
            .plugin(&self.plugin_id)
            .is_some_and(|p| p.tier == Tier::Core);
        if !core {
            return Err(KernelError::forbidden(format!(
                "only core-tier plugins define rights ({})",
                self.plugin_id
            )));
        }
        if !self
            .kernel
            .0
            .broker
            .register_checker(&self.plugin_id, checker)
        {
            return Err(KernelError::new(
                ErrorCode::Conflict,
                format!("{}: a right it defines is already defined", self.plugin_id),
            ));
        }
        self.ledger(|l| l.rights = true);
        Ok(())
    }

    /// Bind behaviour to a command declared in this plugin's manifest.
    /// Undeclared IDs must still carry the plugin's prefix and stay private.
    pub fn command<P, R, F, Fut>(&mut self, id: &str, handler: F) -> KernelResult<()>
    where
        P: DeserializeOwned + Send + 'static,
        R: Serialize + 'static,
        F: Fn(Invocation, P) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = KernelResult<R>> + Send + 'static,
    {
        if !atomo_manifest::has_prefix(id, &self.plugin_id) {
            return Err(KernelError::invalid_params(format!(
                "command `{id}` must be prefixed with `{}.`",
                self.plugin_id
            )));
        }
        if let Some(info) = self.kernel.0.registry.load().snapshot.command(id) {
            if info.plugin != self.plugin_id {
                return Err(KernelError::forbidden(format!(
                    "`{id}` belongs to {}",
                    info.plugin
                )));
            }
        }
        self.kernel.0.commands.write().insert(
            id.to_owned(),
            CommandEntry {
                owner: self.plugin_id.clone(),
                handler: typed_command(handler),
            },
        );
        self.ledger(|l| l.commands.push(id.to_owned()));
        Ok(())
    }

    /// Set a context key in this plugin's namespace (`plugin.<id>.<key>`), for when-clauses.
    pub fn set_context(&self, key: &str, value: Value) {
        self.kernel.set_plugin_context(&self.plugin_id, key, value);
    }

    pub fn publish(&self, topic: &str, payload: Value) -> KernelResult<()> {
        self.kernel.publish(&self.plugin_id, topic, payload)
    }

    pub fn storage(&self) -> PluginStorage {
        self.kernel.storage(&self.plugin_id)
    }

    pub fn data_dir(&self) -> Option<PathBuf> {
        self.kernel.plugin_data_dir(&self.plugin_id)
    }

    pub fn cache_dir(&self) -> Option<PathBuf> {
        self.kernel.plugin_cache_dir(&self.plugin_id)
    }

    pub fn setting(&self, key: &str) -> Option<Value> {
        self.kernel.setting(key)
    }

    /// The contributions to an extension point, from usable plugins, in activation order.
    pub fn contributions(&self, point: &str) -> Vec<Contribution> {
        self.kernel
            .0
            .registry
            .load()
            .snapshot
            .contributions(point)
            .to_vec()
    }

    pub fn registry(&self) -> Arc<RegistrySnapshot> {
        self.kernel.registry()
    }
}
