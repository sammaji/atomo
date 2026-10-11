//! The registry snapshot: every known plugin, extension point, contribution,
//! command and setting, as the shell and plugins see them.

use std::collections::BTreeMap;

use atomo_manifest::{Cardinality, CommandDecl, FrontendRuntime, Half, Resolution};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use ts_rs::TS;

/// How much we trust a plugin. Assigned by the loader, never self-declared.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export)]
pub enum Tier {
    Core,
    Verified,
    Community,
    Dev,
}

/// Lifecycle. `Invalid`/`Unresolved` come from the registry build; the
/// rest are runtime states the kernel (or the shell, for frontend halves) reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export)]
pub enum PluginState {
    Invalid,
    Unresolved,
    Disabled,
    Resolved,
    Activating,
    Active,
    Failed,
}

#[derive(Debug, Clone, Serialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export)]
pub struct PluginInfo {
    pub id: String,
    pub version: String,
    pub display_name: String,
    pub description: String,
    pub tier: Tier,
    pub state: PluginState,
    pub error: Option<String>,
    pub warnings: Vec<String>,
    pub has_backend: bool,
    pub frontend: Option<FrontendRuntime>,
    /// The frontend half's bundle inside the package (`frontend.module`).
    #[serde(skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub frontend_module: Option<String>,
    pub dependencies: Vec<String>,
    /// Activation events: declared plus implied by contributions.
    pub activation_events: Vec<String>,
    /// Held (state `disabled`) until the user reviews its permissions: a new
    /// install, or an update whose permissions or dependencies grew.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    #[ts(optional, as = "Option<bool>")]
    pub needs_consent: bool,
}

#[derive(Debug, Clone, Serialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export)]
pub struct ExtensionPointInfo {
    pub id: String,
    /// `None` for kernel-owned points.
    pub owner: Option<String>,
    pub description: String,
    pub cardinality: Cardinality,
    pub resolution: Resolution,
}

#[derive(Debug, Clone, Serialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export)]
pub struct Contribution {
    pub plugin: String,
    #[ts(type = "unknown")]
    pub value: Value,
}

#[derive(Debug, Clone, Serialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export)]
pub struct CommandInfo {
    #[serde(flatten)]
    pub decl: CommandDecl,
    pub plugin: String,
    /// Resolved: the declaration's `handler` or the plugin's default half.
    pub half: Half,
}

#[derive(Debug, Clone, Serialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export)]
pub struct SettingInfo {
    pub plugin: String,
    #[ts(type = "unknown")]
    pub schema: Value,
    #[ts(type = "unknown")]
    pub default: Value,
}

/// The immutable registry. Rebuilt on install, update or enable changes.
#[derive(Debug, Clone, Serialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export)]
pub struct RegistrySnapshot {
    /// Content hash of the inputs; equal hashes mean an identical registry.
    pub hash: String,
    /// Every known plugin. Usable ones come first, in activation (dependency) order.
    pub plugins: Vec<PluginInfo>,
    pub extension_points: Vec<ExtensionPointInfo>,
    /// Point ID → contributions from usable plugins, in activation order.
    pub contributions: BTreeMap<String, Vec<Contribution>>,
    pub commands: Vec<CommandInfo>,
    pub settings: BTreeMap<String, SettingInfo>,
}

impl RegistrySnapshot {
    pub fn plugin(&self, id: &str) -> Option<&PluginInfo> {
        self.plugins.iter().find(|p| p.id == id)
    }

    pub fn command(&self, id: &str) -> Option<&CommandInfo> {
        self.commands.iter().find(|c| c.decl.id == id)
    }

    pub fn contributions(&self, point: &str) -> &[Contribution] {
        self.contributions.get(point).map_or(&[], Vec::as_slice)
    }

    /// Plugins whose backend may run, in dependency order.
    pub fn activation_order(&self) -> impl Iterator<Item = &PluginInfo> {
        self.plugins
            .iter()
            .filter(|p| matches!(p.state, PluginState::Resolved | PluginState::Active))
    }
}
