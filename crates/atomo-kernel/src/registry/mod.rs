//! The plugin registry: built from manifests without running plugin code,
//! then served with live plugin states overlaid.

mod build;
mod types;

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;

use atomo_manifest::Manifest;
use serde_json::{json, Value};

use crate::broker::PluginFacts;
use crate::schema::Schema;
use crate::{Kernel, KernelResult};
use build::Input;
pub use types::{
    CommandInfo, Contribution, ExtensionPointInfo, PluginInfo, PluginState, RegistrySnapshot,
    SettingInfo, Tier,
};

/// The built registry with what the kernel needs besides the snapshot.
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

impl Kernel {
    /// The registry with live plugin states overlaid.
    pub fn registry(&self) -> Arc<RegistrySnapshot> {
        let state = self.registry_state();
        let states = self.plugins().backend_states.read();
        let frontend = self.plugins().frontend_states.read();
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

    /// Rebuild the registry from the manifest sources, persisted enablement
    /// and consent holds, and hand the broker the new plugin facts.
    pub(crate) fn rebuild_registry(&self) -> KernelResult<()> {
        let mut disabled: BTreeSet<String> = self.0.db.disabled_plugins()?.into_iter().collect();
        let inputs = self
            .plugins()
            .sources
            .read()
            .iter()
            .enumerate()
            .map(|(i, s)| {
                let parsed = Manifest::parse(s.text);
                let fallback_id = serde_json::from_str::<Value>(s.text)
                    .ok()
                    .and_then(|v| v.get("id").and_then(Value::as_str).map(str::to_owned))
                    .unwrap_or_else(|| format!("invalid.manifest-{i}"));
                if self.0.config.safe_mode && s.tier != Tier::Core {
                    disabled.insert(fallback_id.clone());
                }
                Input {
                    backend_runnable: parsed.as_ref().is_ok_and(|m| {
                        self.plugins().natives.contains_key(&m.id) || self.host_for(m).is_some()
                    }),
                    held: parsed
                        .as_ref()
                        .ok()
                        .and_then(|m| self.0.broker.consent_hold(s.tier, m)),
                    source: parsed.map_err(|e| e.to_string()),
                    fallback_id,
                    tier: s.tier,
                    dir: s.dir.clone(),
                }
            })
            .collect();
        let built = build::build(inputs, &disabled);
        for p in &built.snapshot.plugins {
            if let Some(err) = &p.error {
                eprintln!("[atomo] plugin {} is {:?}: {err}", p.id, p.state);
            }
        }
        let facts = built
            .snapshot
            .plugins
            .iter()
            .filter_map(|p| {
                let m = built.manifests.get(&p.id)?;
                let facts = PluginFacts {
                    tier: p.tier,
                    manifest: Arc::new(m.clone()),
                };
                Some((p.id.clone(), facts))
            })
            .collect();
        self.0.broker.set_plugins(facts);
        let held: Vec<&str> = built
            .snapshot
            .plugins
            .iter()
            .filter(|p| p.needs_consent)
            .map(|p| p.id.as_str())
            .collect();
        if !held.is_empty() {
            self.emit_kernel("broker.consentRequired", json!({ "plugins": held }));
        }
        self.0.registry.store(Arc::new(RegistryState {
            snapshot: Arc::new(built.snapshot),
            manifests: built.manifests,
            schemas: built.schemas,
        }));
        Ok(())
    }
}
