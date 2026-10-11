//! The plugins the kernel knows, and the live state of each half.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;

use atomo_manifest::Manifest;
use parking_lot::{Mutex, RwLock};
use serde_json::json;

use super::{NativePlugin, RuntimeHost};
use crate::registrations::Ledger;
use crate::{Kernel, PluginState, Tier};

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

pub(crate) struct Plugins {
    /// Every manifest the registry is built from; disk ones can be reloaded.
    pub sources: RwLock<Vec<ManifestSource>>,
    pub natives: HashMap<String, Arc<dyn NativePlugin>>,
    pub hosts: Vec<Arc<dyn RuntimeHost>>,
    /// Backend halves (overlays the snapshot's build-time state).
    pub backend_states: RwLock<HashMap<String, LiveState>>,
    /// Frontend halves, as reported by the shell.
    pub frontend_states: RwLock<HashMap<String, LiveState>>,
    pub ledgers: Mutex<HashMap<String, Ledger>>,
    /// Serializes activation and deactivation.
    pub lifecycle: Mutex<()>,
}

impl Plugins {
    pub fn new(
        sources: Vec<ManifestSource>,
        natives: HashMap<String, Arc<dyn NativePlugin>>,
        hosts: Vec<Arc<dyn RuntimeHost>>,
    ) -> Self {
        Plugins {
            sources: RwLock::new(sources),
            natives,
            hosts,
            backend_states: Default::default(),
            frontend_states: Default::default(),
            ledgers: Default::default(),
            lifecycle: Mutex::new(()),
        }
    }
}

impl Kernel {
    pub fn plugin_state(&self, id: &str) -> Option<PluginState> {
        if let Some(live) = self.plugins().backend_states.read().get(id) {
            return Some(live.state);
        }
        self.registry_state().snapshot.plugin(id).map(|p| p.state)
    }

    pub(super) fn set_state(&self, id: &str, state: PluginState, error: Option<String>) {
        self.plugins().backend_states.write().insert(
            id.to_owned(),
            LiveState {
                state,
                error: error.clone(),
            },
        );
        self.emit_kernel(
            "plugin.stateChanged",
            json!({ "id": id, "state": state, "error": error }),
        );
    }

    /// Record the state of a plugin's frontend half, as the shell reports it.
    pub(crate) fn set_frontend_state(&self, id: &str, state: PluginState, error: Option<String>) {
        self.plugins().frontend_states.write().insert(
            id.to_owned(),
            LiveState {
                state,
                error: error.clone(),
            },
        );
        self.emit_kernel(
            "plugin.stateChanged",
            json!({ "id": id, "half": "frontend", "state": state, "error": error }),
        );
    }

    pub(super) fn active_plugins(&self) -> HashSet<String> {
        self.plugins()
            .backend_states
            .read()
            .iter()
            .filter(|(_, live)| live.state == PluginState::Active)
            .map(|(id, _)| id.clone())
            .collect()
    }

    /// Package directories of every plugin loaded from disk.
    pub fn plugin_dirs(&self) -> Vec<PathBuf> {
        self.plugins()
            .sources
            .read()
            .iter()
            .filter_map(|s| s.dir.clone())
            .collect()
    }

    /// The package directory of a plugin loaded from disk.
    pub fn plugin_dir(&self, id: &str) -> Option<PathBuf> {
        self.plugins()
            .sources
            .read()
            .iter()
            .find(|s| s.is(id))
            .and_then(|s| s.dir.clone())
    }
}
