//! Changing which plugins run: enabling, consent, and restarts after a
//! settings save or a change on disk.

use serde::{Deserialize, Serialize};
use serde_json::json;
use ts_rs::TS;

use crate::{Kernel, KernelError, KernelResult, PluginState};

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

impl Kernel {
    /// Enable or disable a plugin, persistently, and apply it now.
    pub fn set_enabled(&self, id: &str, enabled: bool) -> KernelResult<()> {
        if !self.plugins().sources.read().iter().any(|s| s.is(id)) {
            return Err(Kernel::not_a_plugin(id));
        }
        self.0.db.set_enabled(id, enabled)?;
        self.refresh()
    }

    /// The user approved (or refused) a plugin's permissions. Approval records
    /// the consent, grants the required permissions and lets the plugin run;
    /// refusal disables it.
    pub fn consent(&self, plugin: &str, allow: bool) -> KernelResult<()> {
        let manifest = self
            .registry_state()
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

    /// Re-read a disk plugin's manifest and restart it (dev hot reload).
    /// Dependents are deactivated and come back with it.
    pub fn reload_plugin(&self, id: &str) -> KernelResult<()> {
        {
            let mut sources = self.plugins().sources.write();
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
        self.plugins().backend_states.write().remove(id);
        self.plugins().frontend_states.write().remove(id);
        self.rebuild_registry()?;
        self.reactivate(&was_active);
        let hash = self.registry_state().snapshot.hash.clone();
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

    /// Rebuild the registry and apply it: deactivate what is no longer
    /// usable, activate what became usable, tell the shells.
    fn refresh(&self) -> KernelResult<()> {
        self.rebuild_registry()?;
        let snapshot = self.registry_state().snapshot.clone();
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
}
