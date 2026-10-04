//! Layered settings: defaults (from manifests) < user < policy.
//!
//! The user layer is `settings.json` in the config directory; the policy layer
//! (admin-locked) is `policy.json` next to it. Every value is validated against
//! its schema; an invalid value is ignored, and the layer below shows through.

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use ts_rs::TS;

use crate::lifecycle::ReloadReason;
use crate::registry::RegistrySnapshot;
use crate::schema::Schema;
use crate::{ErrorCode, Kernel, KernelError, KernelResult};

#[derive(Debug, Clone, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export)]
pub struct SaveSettingsParams {
    pub plugin: String,
    /// Setting key → new value; `null` resets it to its default.
    #[ts(type = "Record<string, unknown>")]
    pub values: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export)]
pub struct SaveSettingsResult {
    /// The keys whose effective value changed.
    pub changed: Vec<String>,
}

pub(crate) struct Settings {
    file: Option<PathBuf>,
    user: RwLock<Map<String, Value>>,
    policy: Map<String, Value>,
}

fn read_json(path: &Path) -> Map<String, Value> {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|t| serde_json::from_str::<Map<String, Value>>(&t).ok())
        .unwrap_or_default()
}

fn schema_key(key: &str) -> String {
    format!("setting:{key}")
}

impl Settings {
    pub fn load(config_dir: Option<&Path>) -> Settings {
        let file = config_dir.map(|d| d.join("settings.json"));
        let user = file.as_deref().map(read_json).unwrap_or_default();
        let policy = config_dir
            .map(|d| read_json(&d.join("policy.json")))
            .unwrap_or_default();
        Settings {
            file,
            user: RwLock::new(user),
            policy,
        }
    }

    /// Effective values for every declared setting.
    pub fn effective(
        &self,
        registry: &RegistrySnapshot,
        schemas: &HashMap<String, Schema>,
    ) -> BTreeMap<String, Value> {
        let user = self.user.read();
        registry
            .settings
            .iter()
            .map(|(key, info)| {
                let valid = |v: &&Value| {
                    schemas
                        .get(&schema_key(key))
                        .is_none_or(|s| s.validate(v).is_ok())
                };
                let value = self
                    .policy
                    .get(key)
                    .filter(valid)
                    .or_else(|| user.get(key).filter(valid))
                    .cloned()
                    .unwrap_or_else(|| info.default.clone());
                (key.clone(), value)
            })
            .collect()
    }

    /// Why the user may not set `key` to `value` (`None`: reset), if they may not.
    fn refusal(
        &self,
        key: &str,
        value: Option<&Value>,
        registry: &RegistrySnapshot,
        schemas: &HashMap<String, Schema>,
    ) -> Option<KernelError> {
        if !registry.settings.contains_key(key) {
            return Some(KernelError::not_found(format!("no setting `{key}`")));
        }
        if self.policy.contains_key(key) {
            return Some(KernelError::new(
                ErrorCode::Locked,
                format!("`{key}` is set by policy"),
            ));
        }
        let schema = schemas.get(&schema_key(key));
        if let (Some(v), Some(schema)) = (value, schema) {
            if let Err(e) = schema.validate(v) {
                return Some(KernelError::invalid_params(format!("{key}: {e}")));
            }
        }
        None
    }

    /// Apply validated changes to the user layer and persist it. Either every
    /// change is written or none is.
    fn write(&self, changes: Vec<(String, Option<Value>)>) -> KernelResult<()> {
        let mut user = self.user.write();
        let mut next = user.clone();
        for (key, value) in changes {
            match value {
                Some(v) => next.insert(key, v),
                None => next.remove(&key),
            };
        }
        if next == *user {
            return Ok(());
        }
        if let Some(file) = &self.file {
            // Write-then-rename so a crash never leaves a truncated settings file.
            let tmp = file.with_extension("json.tmp");
            let text = serde_json::to_string_pretty(&next).expect("settings serialize");
            let dir = file.parent().expect("settings file has a parent");
            std::fs::create_dir_all(dir)
                .and_then(|_| std::fs::write(&tmp, text))
                .and_then(|_| std::fs::rename(&tmp, file))
                .map_err(|e| KernelError::io(e.to_string()))?;
        }
        *user = next;
        Ok(())
    }
}

impl Kernel {
    /// Effective value of a setting.
    pub fn setting(&self, key: &str) -> Option<Value> {
        self.settings().remove(key)
    }

    pub fn settings(&self) -> BTreeMap<String, Value> {
        let state = self.0.registry.load();
        self.0.settings.effective(&state.snapshot, &state.schemas)
    }

    /// Set (or reset, with `None`) one user setting; emits `settings.changed`.
    /// The owning plugin keeps running (for shell-owned toggles).
    pub fn set_setting(&self, key: &str, value: Option<Value>) -> KernelResult<()> {
        let state = self.0.registry.load();
        let settings = &self.0.settings;
        if let Some(e) = settings.refusal(key, value.as_ref(), &state.snapshot, &state.schemas) {
            return Err(e);
        }
        self.write_settings(vec![(key.to_owned(), value)])?;
        Ok(())
    }

    /// Save several settings of one plugin at once, then restart it so it
    /// picks them up. Every key must be a setting `plugin` declares, and every
    /// value is validated before anything is written: on any error nothing
    /// changes and the error (`invalid_settings`) maps each bad key to why.
    pub fn save_settings(&self, params: SaveSettingsParams) -> KernelResult<SaveSettingsResult> {
        let SaveSettingsParams { plugin, values } = params;
        let state = self.0.registry.load();
        if state.snapshot.plugin(&plugin).is_none() {
            return Err(Kernel::not_a_plugin(&plugin));
        }
        let settings = &self.0.settings;
        let mut errors = BTreeMap::new();
        let mut changes = Vec::with_capacity(values.len());
        for (key, value) in values {
            let value = Some(value).filter(|v| !v.is_null());
            let owner = state.snapshot.settings.get(&key).map(|s| s.plugin.as_str());
            let refusal = match owner {
                Some(owner) if owner != plugin => {
                    Some(format!("`{key}` is a setting of `{owner}`, not `{plugin}`"))
                }
                _ => settings
                    .refusal(&key, value.as_ref(), &state.snapshot, &state.schemas)
                    .map(|e| e.message),
            };
            match refusal {
                Some(why) => {
                    errors.insert(key, why);
                }
                None => changes.push((key, value)),
            }
        }
        if !errors.is_empty() {
            let message = match errors.len() {
                1 => "1 setting is invalid".to_owned(),
                n => format!("{n} settings are invalid"),
            };
            return Err(KernelError::new(ErrorCode::InvalidSettings, message)
                .with_data(json!({ "errors": errors })));
        }
        drop(state);
        let changed = self.write_settings(changes)?;
        if !changed.is_empty() {
            self.restart_plugin(&plugin, ReloadReason::Settings);
        }
        Ok(SaveSettingsResult { changed })
    }

    /// Write validated changes and emit `settings.changed` for every key whose
    /// effective value changed (storing a key's default, for instance, does
    /// not change it). Returns those keys.
    fn write_settings(&self, changes: Vec<(String, Option<Value>)>) -> KernelResult<Vec<String>> {
        let before = self.settings();
        let keys: Vec<String> = changes.iter().map(|(k, _)| k.clone()).collect();
        self.0.settings.write(changes)?;
        let after = self.settings();
        let changed: Vec<String> = keys
            .into_iter()
            .filter(|k| before.get(k) != after.get(k))
            .collect();
        for key in &changed {
            let value = after.get(key).cloned().unwrap_or(Value::Null);
            self.emit_kernel("settings.changed", json!({ "key": key, "value": value }));
        }
        Ok(changed)
    }
}
