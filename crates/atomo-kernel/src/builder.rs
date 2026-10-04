use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use std::sync::atomic::AtomicU32;
use std::sync::Arc;

use arc_swap::ArcSwap;
use atomo_manifest::Manifest;
use parking_lot::{Mutex, RwLock};
use serde_json::Value;

use crate::broker::{self, Broker, SecretStore};
use crate::kernel::{Inner, ManifestSource, RegistryState};
use crate::settings::Settings;
use crate::storage::KernelDb;
use crate::{
    platform_os, ErrorCode, EventBus, Kernel, KernelConfig, KernelError, KernelResult,
    NativePlugin, RuntimeHost, Tier,
};

pub struct KernelBuilder {
    runtime: tokio::runtime::Handle,
    config: KernelConfig,
    natives: Vec<Box<dyn NativePlugin>>,
    manifests: Vec<ManifestSource>,
    hosts: Vec<Arc<dyn RuntimeHost>>,
    secrets: Option<Arc<dyn SecretStore>>,
}

impl KernelBuilder {
    pub(crate) fn new(runtime: tokio::runtime::Handle) -> Self {
        KernelBuilder {
            runtime,
            config: KernelConfig::default(),
            natives: Vec::new(),
            manifests: Vec::new(),
            hosts: Vec::new(),
            secrets: None,
        }
    }

    /// Where plugin secrets live. By default, it uses the OS keychain when the
    /// kernel persists (`data_dir`), otherwise, uses an in-memory store.
    pub fn secret_store(mut self, store: Arc<dyn SecretStore>) -> Self {
        self.secrets = Some(store);
        self
    }

    pub fn config(mut self, config: KernelConfig) -> Self {
        self.config = config;
        self
    }

    /// A compiled-in plugin with a native backend (core tier).
    pub fn native(mut self, plugin: impl NativePlugin) -> Self {
        self.natives.push(Box::new(plugin));
        self
    }

    pub fn natives(mut self, plugins: Vec<Box<dyn NativePlugin>>) -> Self {
        self.natives.extend(plugins);
        self
    }

    /// A plugin without native code: declarative, or with a frontend half the shell loads.
    pub fn manifest(mut self, json: &'static str, tier: Tier) -> Self {
        self.manifests.push(ManifestSource {
            text: json,
            tier,
            dir: None,
        });
        self
    }

    /// A host for backends that are not compiled in (e.g. the WASM runtime).
    pub fn runtime_host(mut self, host: Arc<dyn RuntimeHost>) -> Self {
        self.hosts.push(host);
        self
    }

    /// Load unpacked plugins from disk: `dir` itself if it holds an
    /// `atomo-plugin.json`, otherwise each subdirectory that does. A missing
    /// directory is not an error. Unreadable manifests become `Invalid` plugins.
    pub fn plugin_dir(mut self, dir: impl Into<PathBuf>, tier: Tier) -> Self {
        let dir = dir.into();
        let mut dirs = if dir.join("atomo-plugin.json").is_file() {
            vec![dir]
        } else {
            std::fs::read_dir(&dir)
                .map(|it| {
                    it.filter_map(Result::ok)
                        .map(|e| e.path())
                        .filter(|p| p.join("atomo-plugin.json").is_file())
                        .collect()
                })
                .unwrap_or_default()
        };
        dirs.sort();
        for dir in dirs {
            let text = std::fs::read_to_string(dir.join("atomo-plugin.json"))
                .unwrap_or_else(|e| format!("unreadable manifest: {e}"));
            self.manifests.push(ManifestSource {
                // Manifests live as long as the process, like compiled-in ones.
                text: Box::leak(text.into_boxed_str()),
                tier,
                dir: Some(dir),
            });
        }
        self
    }

    /// Build the registry and activate the plugins that start eagerly. A
    /// plugin that fails is attributed and skipped; the kernel still starts.
    pub fn start(self) -> KernelResult<Kernel> {
        let mut sources = Vec::new();
        let mut natives = HashMap::new();
        for plugin in self.natives {
            let text = plugin.manifest();
            let id = Manifest::parse(text).map(|m| m.id).map_err(|e| {
                KernelError::new(
                    ErrorCode::InvalidManifest,
                    format!("compiled-in plugin: {e}"),
                )
            })?;
            sources.push(ManifestSource {
                text,
                tier: Tier::Core,
                dir: None,
            });
            natives.insert(id, Arc::from(plugin));
        }
        sources.extend(self.manifests);

        let db = KernelDb::open(self.config.data_dir.as_deref())?;
        let events = EventBus::default();
        let broker = Broker::new(db.clone(), events.clone())?;
        broker.set_secret_store(self.secrets.unwrap_or_else(|| {
            if self.config.data_dir.is_some() {
                Arc::new(broker::KeychainSecrets)
            } else {
                Arc::new(broker::MemorySecrets::default())
            }
        }));
        let settings = Settings::load(self.config.config_dir.as_deref());
        let context = BTreeMap::from([
            ("platform.os".to_owned(), Value::from(platform_os())),
            (
                "platform.arch".to_owned(),
                Value::from(std::env::consts::ARCH),
            ),
        ]);

        let kernel = Kernel(Arc::new(Inner {
            runtime: self.runtime,
            config: self.config,
            sources: RwLock::new(sources),
            natives,
            hosts: self.hosts,
            registry: ArcSwap::from_pointee(RegistryState::empty()),
            states: Default::default(),
            frontend_states: Default::default(),
            services: Default::default(),
            methods: Default::default(),
            commands: Default::default(),
            ledgers: Default::default(),
            lifecycle: Mutex::new(()),
            events,
            settings,
            context: RwLock::new(context),
            db,
            broker,
            subscriptions: Default::default(),
            next_subscription: AtomicU32::new(1),
            next_invocation: Default::default(),
            frontend_invocations: Default::default(),
        }));
        kernel.rebuild_registry()?;
        kernel.register_methods();
        kernel.activate_eager();
        Ok(kernel)
    }
}
