//! What the shell's permission UI needs from the kernel besides the broker
//! itself: pending requests, and the selections of views that may read them.

use serde_json::{json, Value};

use crate::{Kernel, KernelError, KernelResult, PermissionSummary};

/// Does `m` contribute an item `id` whose `access` includes `token`?
fn declares_access(m: &atomo_manifest::Manifest, id: &str, token: &str) -> bool {
    fn walk(v: &Value, id: &str, token: &str, depth: usize) -> bool {
        match v {
            Value::Object(o) => {
                let hit = o.get("id").and_then(Value::as_str) == Some(id)
                    && o.get("access")
                        .and_then(Value::as_array)
                        .is_some_and(|a| a.iter().any(|t| t.as_str() == Some(token)));
                hit || (depth < 3 && o.values().any(|x| walk(x, id, token, depth + 1)))
            }
            Value::Array(a) => depth < 3 && a.iter().any(|x| walk(x, id, token, depth + 1)),
            _ => false,
        }
    }
    m.contributes.values().any(|v| walk(v, id, token, 0))
}

impl Kernel {
    /// Prompts waiting for an answer, and plugins held until the user
    /// reviews their permissions.
    pub(crate) fn pending_permissions(&self) -> Value {
        let consents: Vec<PermissionSummary> = self
            .registry()
            .plugins
            .iter()
            .filter(|p| p.needs_consent)
            .filter_map(|p| self.0.broker.summary(&p.id))
            .collect();
        json!({
            "prompts": self.0.broker.pending_prompts(),
            "consents": consents,
        })
    }

    /// The shell reports what a view shows as selected; only views that
    /// declare `selection:read` access receive it as grants.
    pub(crate) fn set_view_selection(
        &self,
        plugin: &str,
        view_id: &str,
        resources: &[String],
    ) -> KernelResult<()> {
        let declares = self
            .0
            .broker
            .plugin_manifest(plugin)
            .is_some_and(|(_, m)| declares_access(&m, view_id, "selection:read"));
        if !declares {
            return Err(KernelError::forbidden(format!(
                "`{plugin}` declares no `selection:read` view `{view_id}`"
            )));
        }
        self.0
            .broker
            .set_view_selection(plugin, view_id, resources)
            .detach();
        Ok(())
    }
}
