//! Context keys that when-clauses read. Plugins write only their own
//! `plugin.<id>.*` keys and never see other plugins' ones.

use std::collections::BTreeMap;

use serde_json::{json, Value};

use crate::{Caller, Kernel, KernelError, KernelResult};

impl Kernel {
    pub fn context(&self) -> BTreeMap<String, Value> {
        self.0.context.read().clone()
    }

    /// The context as `caller` may see it: other plugins' private keys
    /// (`plugin.<id>.*`) are not a plugin's business.
    pub(crate) fn context_for(&self, caller: &Caller) -> BTreeMap<String, Value> {
        let mut ctx = self.context();
        if let Some(id) = caller.plugin() {
            let own = format!("plugin.{id}");
            ctx.retain(|key, _| {
                !key.starts_with("plugin.") || atomo_manifest::has_prefix(key, &own)
            });
        }
        ctx
    }

    /// Set `plugin.<plugin>.<key>` (for use after activation, e.g. from jobs).
    pub fn set_plugin_context(&self, plugin: &str, key: &str, value: Value) {
        self.set_context(format!("plugin.{plugin}.{key}"), value);
    }

    /// Set a full key on behalf of `plugin`, which must be in its own namespace.
    pub(crate) fn set_context_as(
        &self,
        plugin: &str,
        key: String,
        value: Value,
    ) -> KernelResult<()> {
        let prefix = format!("plugin.{plugin}");
        if !atomo_manifest::has_prefix(&key, &prefix) {
            return Err(KernelError::forbidden(format!(
                "plugins set only `{prefix}.*` keys"
            )));
        }
        self.set_context(key, value);
        Ok(())
    }

    /// Set (or, with `null`, remove) a key; emits `context.changed` if it changed.
    fn set_context(&self, key: String, value: Value) {
        let changed = {
            let mut ctx = self.0.context.write();
            if value.is_null() {
                ctx.remove(&key).is_some()
            } else {
                ctx.insert(key.clone(), value.clone()).as_ref() != Some(&value)
            }
        };
        if changed {
            self.emit_kernel("context.changed", json!({ "key": key, "value": value }));
        }
    }
}
