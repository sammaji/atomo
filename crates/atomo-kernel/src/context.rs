use std::collections::BTreeMap;

use serde_json::{json, Value};

use crate::Kernel;

impl Kernel {
    pub fn context(&self) -> BTreeMap<String, Value> {
        self.0.context.read().clone()
    }

    /// Set `plugin.<plugin>.<key>` (for use after activation, e.g. from jobs).
    pub fn set_plugin_context(&self, plugin: &str, key: &str, value: Value) {
        self.set_context(format!("plugin.{plugin}.{key}"), value);
    }

    /// Set (or, with `null`, remove) a key; emits `context.changed` if it changed.
    pub(crate) fn set_context(&self, key: String, value: Value) {
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
