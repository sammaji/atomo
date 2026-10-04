//! Plugin lifecycle: building the registry, activation in dependency order,
//! deactivation with disposal of everything a plugin registered, enabling,
//! consent and reloads.

use std::collections::{BTreeSet, HashSet};
use std::panic::AssertUnwindSafe;
use std::sync::Arc;

use atomo_manifest::Manifest;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use ts_rs::TS;

use crate::broker::PluginFacts;
use crate::kernel::{LiveState, RegistryState};
use crate::plugin::{ActivationContext, Ledger};
use crate::registry::{self, Input};
use crate::{ErrorCode, Kernel, KernelError, KernelResult, PluginState, Tier};

/// Why a plugin was restarted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export)]
pub enum ReloadReason {
    /// Its settings were saved.
    Settings,
    /// Its files changed on disk (dev hot reload).
    Dev,
}

/// Payload of the kernel event `plugin.reloaded`: the shell restarts the
/// plugin's frontend half and re-renders its views.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export)]
pub struct PluginReloaded {
    pub id: String,
    pub reason: ReloadReason,
}

fn panic_message(panic: Box<dyn std::any::Any + Send>) -> String {
    panic
        .downcast_ref::<String>()
        .cloned()
        .or_else(|| panic.downcast_ref::<&str>().map(|s| s.to_string()))
        .unwrap_or_else(|| "panic".into())
}

impl Kernel {
    /// Mark an active plugin Failed after the fact, e.g. when a runtime host's
    /// background compile fails. Its registrations are disposed.
    pub fn report_failure(&self, id: &str, error: impl Into<String>) {
        let _guard = self.0.lifecycle.lock();
        let error = error.into();
        eprintln!("[atomo] plugin {id} failed: {error}");
        self.dispose(id);
        self.set_state(id, PluginState::Failed, Some(error));
    }

    /// Re-read a disk plugin's manifest and restart it (dev hot reload).
    /// Dependents are deactivated and come back with it.
    pub fn reload_plugin(&self, id: &str) -> KernelResult<()> {
        {
            let mut sources = self.0.sources.write();
            let source = sources
                .iter_mut()
                .find(|s| s.dir.is_some() && s.is(id))
                .ok_or_else(|| KernelError::not_found(format!("`{id}` is not loaded from disk")))?;
            let path = source
                .dir
                .as_ref()
                .expect("disk source")
                .join("atomo-plugin.json");
            let text = std::fs::read_to_string(&path)
                .map_err(|e| KernelError::io(format!("{}: {e}", path.display())))?;
            // The previous text stays leaked: reloads are rare and human-paced.
            source.text = Box::leak(text.into_boxed_str());
        }
        let was_active = self.active_plugins();
        self.deactivate(id);
        self.0.states.write().remove(id);
        self.0.frontend_states.write().remove(id);
        self.rebuild_registry()?;
        self.reactivate(&was_active);
        let hash = self.0.registry.load().snapshot.hash.clone();
        self.emit_kernel("registry.changed", json!({ "hash": hash, "reloaded": id }));
        self.emit_reloaded(id, ReloadReason::Dev);
        Ok(())
    }

    /// Restart a plugin's backend (and its active dependents) if it is
    /// running, then tell the shell to restart its frontend.
    pub(crate) fn restart_plugin(&self, id: &str, reason: ReloadReason) {
        if self.plugin_state(id) == Some(PluginState::Active) {
            let was_active = self.active_plugins();
            self.deactivate(id);
            self.reactivate(&was_active);
        }
        self.emit_reloaded(id, reason);
    }

    fn emit_reloaded(&self, id: &str, reason: ReloadReason) {
        let payload = PluginReloaded {
            id: id.to_owned(),
            reason,
        };
        self.emit_kernel(
            "plugin.reloaded",
            serde_json::to_value(payload).expect("serializes"),
        );
    }

    fn active_plugins(&self) -> HashSet<String> {
        self.0
            .states
            .read()
            .iter()
            .filter(|(_, live)| live.state == PluginState::Active)
            .map(|(id, _)| id.clone())
            .collect()
    }

    /// Activate, in dependency order, every plugin that was active before or
    /// starts eagerly and is not active now.
    fn reactivate(&self, was_active: &HashSet<String>) {
        let snapshot = self.0.registry.load().snapshot.clone();
        for p in snapshot.activation_order() {
            if self.plugin_state(&p.id) != Some(PluginState::Active)
                && (was_active.contains(&p.id) || self.activates_eagerly(&p.id))
            {
                // A failure is attributed to the plugin; the others still start.
                let _ = self.activate(&p.id);
            }
        }
    }

    /// Activate every plugin that starts eagerly, in dependency order.
    pub(crate) fn activate_eager(&self) {
        self.reactivate(&HashSet::new());
    }

    /// The user approved (or refused) a plugin's permissions. Approval records
    /// the consent, grants the required permissions and lets the plugin run;
    /// refusal disables it.
    pub fn consent(&self, plugin: &str, allow: bool) -> KernelResult<()> {
        let manifest = self
            .0
            .registry
            .load()
            .manifests
            .get(plugin)
            .cloned()
            .ok_or_else(|| Kernel::not_a_plugin(plugin))?;
        if allow {
            self.0.broker.record_consent(&manifest)?;
        }
        self.0.db.set_enabled(plugin, allow)?;
        self.refresh()
    }

    /// Enable or disable a plugin, persistently, and apply it now.
    pub fn set_enabled(&self, id: &str, enabled: bool) -> KernelResult<()> {
        if !self.0.sources.read().iter().any(|s| s.is(id)) {
            return Err(Kernel::not_a_plugin(id));
        }
        self.0.db.set_enabled(id, enabled)?;
        self.refresh()
    }

    /// Rebuild the registry and apply it: deactivate what is no longer
    /// usable, activate what became usable, tell the shells.
    fn refresh(&self) -> KernelResult<()> {
        self.rebuild_registry()?;
        let snapshot = self.0.registry.load().snapshot.clone();
        let active: Vec<String> = self.active_plugins().into_iter().collect();
        for p in &active {
            if snapshot
                .plugin(p)
                .is_none_or(|i| i.state != PluginState::Resolved)
            {
                self.deactivate(p);
            }
        }
        self.activate_eager();
        self.emit_kernel("registry.changed", json!({ "hash": snapshot.hash }));
        Ok(())
    }

    pub(crate) fn rebuild_registry(&self) -> KernelResult<()> {
        let mut disabled: BTreeSet<String> = self.0.db.disabled_plugins()?.into_iter().collect();
        let inputs = self
            .0
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
                        self.0.natives.contains_key(&m.id) || self.host_for(m).is_some()
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
        let built = registry::build(inputs, &disabled);
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

    /// Backends start at startup unless their manifest lists activation
    /// events without `onStartup`; those wait for first use.
    fn activates_eagerly(&self, id: &str) -> bool {
        if !self.runs_backend(id) {
            return false;
        }
        self.0.registry.load().manifests.get(id).is_some_and(|m| {
            m.activation_events.is_empty()
                || m.activation_events
                    .iter()
                    .any(|e| e.starts_with("onStartup"))
        })
    }

    fn set_state(&self, id: &str, state: PluginState, error: Option<String>) {
        self.0.states.write().insert(
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
        self.0.frontend_states.write().insert(
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

    /// Activate a plugin's backend (and, first, its hard dependencies).
    pub fn activate(&self, id: &str) -> KernelResult<()> {
        let _guard = self.0.lifecycle.lock();
        self.activate_locked(id)
    }

    fn activate_locked(&self, id: &str) -> KernelResult<()> {
        if self.plugin_state(id) == Some(PluginState::Active) {
            return Ok(());
        }
        let registry = self.0.registry.load_full();
        let info = registry
            .snapshot
            .plugin(id)
            .ok_or_else(|| Kernel::not_a_plugin(id))?;
        if info.state != PluginState::Resolved {
            return Err(KernelError::new(
                ErrorCode::Unavailable,
                format!(
                    "`{id}` is {:?}: {}",
                    info.state,
                    info.error.as_deref().unwrap_or("")
                ),
            ));
        }
        let manifest = &registry.manifests[id];
        for dep in manifest.dependencies.keys() {
            if self.runs_backend(dep) {
                self.activate_locked(dep).map_err(|e| {
                    let err = KernelError::new(
                        ErrorCode::DependencyFailed,
                        format!("`{dep}`: {}", e.message),
                    );
                    self.set_state(id, PluginState::Failed, Some(err.message.clone()));
                    err
                })?;
            }
        }
        let native = self.0.natives.get(id).cloned();
        let host = if native.is_none() {
            self.host_for(manifest)
        } else {
            None
        };
        if native.is_none() && host.is_none() {
            return Ok(()); // Nothing to run on this side.
        }
        let dir = self.plugin_dir(id);

        self.set_state(id, PluginState::Activating, None);
        let ledger = Ledger::default();
        let cancel = ledger.cancel.clone();
        self.0.ledgers.lock().insert(id.to_owned(), ledger);
        let mut ctx = ActivationContext {
            kernel: self,
            plugin_id: id.to_owned(),
            cancel,
        };
        // A panicking plugin must not take the kernel down: it fails alone.
        let result = std::panic::catch_unwind(AssertUnwindSafe(|| match (&native, &host) {
            (Some(native), _) => native.activate(&mut ctx),
            (None, Some(host)) => host.activate(manifest, dir.as_deref(), &mut ctx),
            (None, None) => unreachable!(),
        }))
        .unwrap_or_else(|panic| {
            Err(KernelError::internal(format!(
                "panicked during activation: {}",
                panic_message(panic)
            )))
        });
        match result {
            Ok(()) => {
                self.set_state(id, PluginState::Active, None);
                Ok(())
            }
            Err(e) => {
                self.dispose(id);
                eprintln!("[atomo] plugin {id} failed to activate: {e}");
                self.set_state(id, PluginState::Failed, Some(e.to_string()));
                Err(e)
            }
        }
    }

    /// Deactivate a plugin and every active plugin that depends on it.
    pub fn deactivate(&self, id: &str) {
        let _guard = self.0.lifecycle.lock();
        self.deactivate_locked(id);
    }

    fn deactivate_locked(&self, id: &str) {
        if self.plugin_state(id) != Some(PluginState::Active) {
            return;
        }
        let registry = self.0.registry.load_full();
        let dependents: Vec<String> = registry
            .manifests
            .iter()
            .filter(|(_, m)| m.dependencies.contains_key(id))
            .map(|(d, _)| d.clone())
            .collect();
        for d in dependents {
            self.deactivate_locked(&d);
        }
        if let Some(native) = self.0.natives.get(id) {
            let _ = std::panic::catch_unwind(AssertUnwindSafe(|| native.deactivate()));
        } else if let Some(host) = registry.manifests.get(id).and_then(|m| self.host_for(m)) {
            let _ = std::panic::catch_unwind(AssertUnwindSafe(|| host.deactivate(id)));
        }
        self.dispose(id);
        self.0.states.write().remove(id);
        self.emit_kernel(
            "plugin.stateChanged",
            json!({ "id": id, "state": PluginState::Resolved, "error": null }),
        );
    }

    /// Remove everything the plugin registered and cancel its tasks.
    fn dispose(&self, id: &str) {
        let Some(ledger) = self.0.ledgers.lock().remove(id) else {
            return;
        };
        ledger.cancel.cancel();
        let mut methods = self.0.methods.write();
        for m in ledger.methods {
            methods.remove(&m);
        }
        let mut commands = self.0.commands.write();
        for c in ledger.commands {
            commands.remove(&c);
        }
        let mut services = self.0.services.write();
        for s in ledger.services {
            services.remove(&s);
        }
        if ledger.rights {
            self.0.broker.unregister_checkers(id);
        }
    }
}
