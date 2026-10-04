//! The kernel handle and the state its clones share.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;

use arc_swap::{ArcSwap, Guard};
use parking_lot::RwLock;
use serde::Serialize;
use serde_json::Value;
use ts_rs::TS;

use crate::builder::KernelBuilder;
use crate::commands::Invocations;
use crate::events::Subscriptions;
use crate::plugins::Plugins;
use crate::registrations::Registrations;
use crate::registry::RegistryState;
use crate::settings::Settings;
use crate::storage::KernelDb;
use crate::{Broker, EventBus, RegistrySnapshot};

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

pub(crate) struct Inner {
    pub runtime: tokio::runtime::Handle,
    pub config: KernelConfig,
    pub plugins: Plugins,
    pub registry: ArcSwap<RegistryState>,
    pub registrations: Registrations,
    pub events: EventBus,
    pub subscriptions: Subscriptions,
    pub invocations: Invocations,
    pub settings: Settings,
    pub context: RwLock<BTreeMap<String, Value>>,
    pub db: KernelDb,
    pub broker: Broker,
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

    pub(crate) fn bootstrap(&self) -> Bootstrap {
        Bootstrap {
            registry: (*self.registry()).clone(),
            settings: self.settings(),
            context: self.context(),
        }
    }

    /// The registry as built, with manifests and compiled schemas, without live states.
    pub(crate) fn registry_state(&self) -> Guard<Arc<RegistryState>> {
        self.0.registry.load()
    }
}
