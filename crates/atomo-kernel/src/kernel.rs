//! The kernel handle and its shared state.

use std::any::{Any, TypeId};
use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, AtomicU64};
use std::sync::Arc;

use arc_swap::ArcSwap;
use atomo_manifest::Manifest;
use parking_lot::{Mutex, RwLock};
use serde::Serialize;
use serde_json::Value;
use tokio_util::sync::CancellationToken;
use ts_rs::TS;

use crate::builder::KernelBuilder;
use crate::call::{CallContext, Caller, Method, MethodEntry, Visibility};
use crate::command::CommandEntry;
use crate::plugin::{Ledger, NativePlugin, RuntimeHost};
use crate::settings::Settings;
use crate::storage::KernelDb;
use crate::{
    Broker, ErrorCode, EventBus, GrantLease, KernelError, KernelResult, PluginState, PluginStorage,
    RegistrySnapshot, Schema, Tier,
};

/// Directories the kernel and plugins persist to. `None` keeps everything in memory.
#[derive(Debug, Clone, Default)]
pub struct KernelConfig {
    pub data_dir: Option<PathBuf>,
    pub config_dir: Option<PathBuf>,
    pub cache_dir: Option<PathBuf>,
    /// Start with core-tier plugins only.
    pub safe_mode: bool,
}

/// The boot payload: the registry, settings and context in one call.
#[derive(Debug, Clone, Serialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export)]
pub struct Bootstrap {
    pub registry: RegistrySnapshot,
    #[ts(type = "Record<string, unknown>")]
    pub settings: BTreeMap<String, Value>,
    #[ts(type = "Record<string, unknown>")]
    pub context: BTreeMap<String, Value>,
}

/// `macos`, `windows` or `linux`, matching when-clause values.
pub fn platform_os() -> &'static str {
    std::env::consts::OS
}

pub(crate) struct RegistryState {
    pub snapshot: Arc<RegistrySnapshot>,
    pub manifests: HashMap<String, Manifest>,
    pub schemas: HashMap<String, Schema>,
}

impl RegistryState {
    pub fn empty() -> Self {
        RegistryState {
            snapshot: Arc::new(RegistrySnapshot {
                hash: String::new(),
                plugins: vec![],
                extension_points: vec![],
                contributions: BTreeMap::new(),
                commands: vec![],
                settings: BTreeMap::new(),
            }),
            manifests: HashMap::new(),
            schemas: HashMap::new(),
        }
    }
}

/// A manifest the registry is built from.
pub(crate) struct ManifestSource {
    pub text: &'static str,
    pub tier: Tier,
    /// The unpacked package directory, for plugins loaded from disk.
    pub dir: Option<PathBuf>,
}

impl ManifestSource {
    pub fn is(&self, id: &str) -> bool {
        Manifest::parse(self.text).is_ok_and(|m| m.id == id)
    }
}

/// A runtime state reported for one half of a plugin.
#[derive(Debug, Clone)]
pub(crate) struct LiveState {
    pub state: PluginState,
    pub error: Option<String>,
}

/// A live `events.subscribe` stream.
pub(crate) struct SubscriptionEntry {
    /// The plugin that opened it; `None` for the shell.
    pub owner: Option<String>,
    pub cancel: CancellationToken,
}

type AnyService = Arc<dyn Any + Send + Sync>;

pub(crate) struct Inner {
    pub runtime: tokio::runtime::Handle,
    pub config: KernelConfig,
    /// Every manifest the registry is built from; disk ones can be reloaded.
    pub sources: RwLock<Vec<ManifestSource>>,
    pub natives: HashMap<String, Arc<dyn NativePlugin>>,
    pub hosts: Vec<Arc<dyn RuntimeHost>>,
    pub registry: ArcSwap<RegistryState>,
    /// Runtime state of backend halves (overlays the snapshot's build-time state).
    pub states: RwLock<HashMap<String, LiveState>>,
    /// Frontend halves, as reported by the shell.
    pub frontend_states: RwLock<HashMap<String, LiveState>>,
    pub services: RwLock<HashMap<TypeId, (String, AnyService)>>,
    pub methods: RwLock<HashMap<String, MethodEntry>>,
    pub commands: RwLock<HashMap<String, CommandEntry>>,
    pub ledgers: Mutex<HashMap<String, Ledger>>,
    /// Serializes activation and deactivation.
    pub lifecycle: Mutex<()>,
    pub events: EventBus,
    pub settings: Settings,
    pub context: RwLock<BTreeMap<String, Value>>,
    pub db: KernelDb,
    pub broker: Broker,
    pub subscriptions: Mutex<HashMap<u32, SubscriptionEntry>>,
    pub next_subscription: AtomicU32,
    /// Numbers command invocations (intent-grant bindings).
    pub next_invocation: AtomicU64,
    /// Intent grants of frontend command invocations the shell runs itself.
    pub frontend_invocations: Mutex<HashMap<String, GrantLease>>,
}

/// A cheap, clonable handle to the kernel.
#[derive(Clone)]
pub struct Kernel(pub(crate) Arc<Inner>);

impl Kernel {
    pub fn builder(runtime: tokio::runtime::Handle) -> KernelBuilder {
        KernelBuilder::new(runtime)
    }

    /// The capability broker: checks, grants, prompts, audit, secrets.
    pub fn broker(&self) -> &Broker {
        &self.0.broker
    }

    pub fn runtime(&self) -> &tokio::runtime::Handle {
        &self.0.runtime
    }

    pub fn events(&self) -> &EventBus {
        &self.0.events
    }

    /// The directories the kernel persists to.
    pub fn config(&self) -> &KernelConfig {
        &self.0.config
    }

    /// The host-level cache directory (runtime hosts keep compiled artifacts there).
    pub fn cache_dir(&self) -> Option<PathBuf> {
        self.0.config.cache_dir.clone()
    }

    /// The registry with live plugin states overlaid.
    pub fn registry(&self) -> Arc<RegistrySnapshot> {
        let state = self.0.registry.load();
        let states = self.0.states.read();
        let frontend = self.0.frontend_states.read();
        if states.is_empty() && frontend.is_empty() {
            return state.snapshot.clone();
        }
        let mut snapshot = (*state.snapshot).clone();
        for p in &mut snapshot.plugins {
            if p.state != PluginState::Resolved {
                continue;
            }
            // A frontend report only matters for plugins without a backend.
            let frontend = frontend.get(&p.id).filter(|_| !p.has_backend);
            for live in [states.get(&p.id), frontend].into_iter().flatten() {
                p.state = live.state;
                p.error = live.error.clone();
            }
        }
        Arc::new(snapshot)
    }

    pub fn plugin_state(&self, id: &str) -> Option<PluginState> {
        if let Some(live) = self.0.states.read().get(id) {
            return Some(live.state);
        }
        self.0.registry.load().snapshot.plugin(id).map(|p| p.state)
    }

    pub fn service<T: Send + Sync + 'static>(&self) -> Option<Arc<T>> {
        self.0
            .services
            .read()
            .get(&TypeId::of::<T>())
            .and_then(|(_, s)| s.clone().downcast::<T>().ok())
    }

    /// Call a protocol method. Plugin callers reach only API methods.
    pub async fn call(&self, ctx: CallContext, method: &str, params: Value) -> KernelResult<Value> {
        let (visibility, handler) = self
            .0
            .methods
            .read()
            .get(method)
            .map(|m| (m.visibility, m.handler.clone()))
            .ok_or_else(|| KernelError::not_found(format!("no such method: {method}")))?;
        if let (Caller::Plugin(id), Visibility::Internal) = (&ctx.caller, visibility) {
            return Err(KernelError::forbidden(format!(
                "`{method}` is not part of the plugin API (called by `{id}`)"
            )));
        }
        handler(ctx, params).await
    }

    pub(crate) fn register_method(&self, name: &str, visibility: Visibility, handler: Method) {
        let entry = MethodEntry {
            visibility,
            handler,
        };
        let previous = self.0.methods.write().insert(name.to_owned(), entry);
        assert!(previous.is_none(), "method {name} registered twice");
    }

    pub(crate) fn emit_kernel(&self, topic: &str, payload: Value) {
        self.0.events.emit("kernel", topic, payload);
    }

    /// Publish an event as `plugin`. Plugins may only publish in their own
    /// namespace (`<id>.*`, or `<short>.*` for first-party `atomo.<short>`).
    pub fn publish(&self, plugin: &str, topic: &str, payload: Value) -> KernelResult<()> {
        let owns = self
            .0
            .registry
            .load()
            .manifests
            .get(plugin)
            .is_some_and(|m| m.owns_name(topic));
        if !owns {
            return Err(KernelError::forbidden(format!(
                "`{plugin}` may not publish `{topic}`"
            )));
        }
        self.0.events.emit(plugin, topic, payload);
        Ok(())
    }

    /// Package directories of every plugin loaded from disk.
    pub fn plugin_dirs(&self) -> Vec<PathBuf> {
        self.0
            .sources
            .read()
            .iter()
            .filter_map(|s| s.dir.clone())
            .collect()
    }

    /// The package directory of a plugin loaded from disk.
    pub fn plugin_dir(&self, id: &str) -> Option<PathBuf> {
        self.0
            .sources
            .read()
            .iter()
            .find(|s| s.is(id))
            .and_then(|s| s.dir.clone())
    }

    pub(crate) fn host_for(&self, manifest: &Manifest) -> Option<Arc<dyn RuntimeHost>> {
        let runtime = manifest.backend.as_ref()?.runtime;
        self.0
            .hosts
            .iter()
            .find(|h| h.runtime() == runtime)
            .cloned()
    }

    /// Whether this build can run the plugin's backend half.
    pub(crate) fn runs_backend(&self, id: &str) -> bool {
        self.0.natives.contains_key(id)
            || self
                .0
                .registry
                .load()
                .manifests
                .get(id)
                .is_some_and(|m| self.host_for(m).is_some())
    }

    /// A plugin's key-value store.
    pub fn storage(&self, plugin: &str) -> PluginStorage {
        PluginStorage::new(self.0.db.clone(), plugin.to_owned())
    }

    /// `<data>/plugin-data/<id>/`, created on demand. `None` when running in memory.
    pub fn plugin_data_dir(&self, plugin: &str) -> Option<PathBuf> {
        let dir = self
            .0
            .config
            .data_dir
            .as_ref()?
            .join("plugin-data")
            .join(plugin);
        std::fs::create_dir_all(&dir).ok()?;
        Some(dir)
    }

    /// `<cache>/plugins/<id>/`, created on demand. Evictable.
    pub fn plugin_cache_dir(&self, plugin: &str) -> Option<PathBuf> {
        let dir = self
            .0
            .config
            .cache_dir
            .as_ref()?
            .join("plugins")
            .join(plugin);
        std::fs::create_dir_all(&dir).ok()?;
        Some(dir)
    }

    pub(crate) fn not_a_plugin(id: &str) -> KernelError {
        KernelError::new(ErrorCode::NotFound, format!("no plugin `{id}`"))
    }
}
