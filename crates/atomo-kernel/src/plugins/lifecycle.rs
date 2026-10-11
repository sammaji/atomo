//! Activation in dependency order, and deactivation with disposal of
//! everything a plugin registered. A failing or panicking plugin fails alone.

use std::collections::HashSet;
use std::panic::AssertUnwindSafe;

use serde_json::json;
use tokio_util::sync::CancellationToken;

use super::ActivationContext;
use crate::registrations::Ledger;
use crate::{ErrorCode, Kernel, KernelError, KernelResult, PluginState};

fn panic_message(panic: Box<dyn std::any::Any + Send>) -> String {
    panic
        .downcast_ref::<String>()
        .cloned()
        .or_else(|| panic.downcast_ref::<&str>().map(|s| s.to_string()))
        .unwrap_or_else(|| "panic".into())
}

impl Kernel {
    /// Activate a plugin's backend (and, first, its hard dependencies).
    pub fn activate(&self, id: &str) -> KernelResult<()> {
        let _guard = self.plugins().lifecycle.lock();
        self.activate_locked(id)
    }

    /// Deactivate a plugin and every active plugin that depends on it.
    pub fn deactivate(&self, id: &str) {
        let _guard = self.plugins().lifecycle.lock();
        self.deactivate_locked(id);
    }

    /// Fail an active plugin after the fact, e.g. when a runtime host's
    /// background compile fails: it is deactivated (with its dependents) and
    /// marked Failed. `activation` is the token of the activation that failed
    /// ([`ActivationContext::cancellation`]); once that activation has ended,
    /// the report is stale and ignored.
    pub fn report_failure(
        &self,
        id: &str,
        activation: &CancellationToken,
        error: impl Into<String>,
    ) {
        let _guard = self.plugins().lifecycle.lock();
        if activation.is_cancelled() {
            return;
        }
        let error = error.into();
        eprintln!("[atomo] plugin {id} failed: {error}");
        self.deactivate_locked(id);
        self.set_state(id, PluginState::Failed, Some(error));
    }

    /// Remove everything the plugin registered and cancel its tasks.
    fn dispose(&self, id: &str) {
        let Some(ledger) = self.plugins().ledgers.lock().remove(id) else {
            return;
        };
        ledger.cancel.cancel();
        self.0.registrations.remove(&ledger);
        if ledger.rights {
            self.0.broker.unregister_checkers(id);
        }
    }

    /// Activate every plugin that starts eagerly, in dependency order.
    pub(crate) fn activate_eager(&self) {
        self.reactivate(&HashSet::new());
    }

    /// Activate, in dependency order, every plugin that was active before or
    /// starts eagerly and is not active now.
    pub(super) fn reactivate(&self, was_active: &HashSet<String>) {
        let snapshot = self.registry_state().snapshot.clone();
        for p in snapshot.activation_order() {
            if self.plugin_state(&p.id) != Some(PluginState::Active)
                && (was_active.contains(&p.id) || self.activates_eagerly(&p.id))
            {
                // A failure is attributed to the plugin; the others still start.
                let _ = self.activate(&p.id);
            }
        }
    }

    /// Backends start at startup unless their manifest lists activation
    /// events without `onStartup`; those wait for first use.
    fn activates_eagerly(&self, id: &str) -> bool {
        if !self.runs_backend(id) {
            return false;
        }
        self.registry_state().manifests.get(id).is_some_and(|m| {
            m.activation_events.is_empty()
                || m.activation_events
                    .iter()
                    .any(|e| e.starts_with("onStartup"))
        })
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
        let native = self.plugins().natives.get(id).cloned();
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
        self.plugins().ledgers.lock().insert(id.to_owned(), ledger);
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
        if let Some(native) = self.plugins().natives.get(id) {
            let _ = std::panic::catch_unwind(AssertUnwindSafe(|| native.deactivate()));
        } else if let Some(host) = registry.manifests.get(id).and_then(|m| self.host_for(m)) {
            let _ = std::panic::catch_unwind(AssertUnwindSafe(|| host.deactivate(id)));
        }
        self.dispose(id);
        self.plugins().backend_states.write().remove(id);
        self.emit_kernel(
            "plugin.stateChanged",
            json!({ "id": id, "state": PluginState::Resolved, "error": null }),
        );
    }
}
