use serde::Deserialize;
use serde_json::Value;

use super::{CallContext, Caller};
use crate::{InvocationSource, KernelError, KernelResult, PluginState, PromptDecision};

/// Params of a method a frontend half calls about itself. In-realm frontends
/// call through the shell, which is trusted to name the plugin; behind a
/// bridge (`Caller::Plugin`) the bound identity overrides whatever is claimed.
#[derive(Deserialize)]
pub(super) struct AsPlugin<T> {
    #[serde(default)]
    pub plugin: String,
    #[serde(flatten)]
    pub rest: T,
}

impl<T> AsPlugin<T> {
    pub fn bind(mut self, call: &CallContext) -> KernelResult<Self> {
        if let Caller::Plugin(id) = &call.caller {
            self.plugin = id.clone();
        }
        if self.plugin.is_empty() {
            return Err(KernelError::invalid_params("missing `plugin`"));
        }
        Ok(self)
    }
}

// Plugins

#[derive(Deserialize)]
pub(super) struct PluginId {
    pub id: String,
}

#[derive(Deserialize)]
pub(super) struct SetEnabled {
    pub id: String,
    pub enabled: bool,
}

#[derive(Deserialize)]
pub(super) struct ReportState {
    pub id: String,
    pub state: PluginState,
    pub error: Option<String>,
}

// Settings and context

#[derive(Deserialize)]
pub(super) struct SetSetting {
    pub key: String,
    pub value: Option<Value>,
}

#[derive(Deserialize)]
pub(super) struct ContextSet {
    pub key: String,
    pub value: Value,
}

// Events

#[derive(Deserialize)]
pub(super) struct Publish {
    pub topic: String,
    #[serde(default)]
    pub payload: Value,
}

#[derive(Deserialize)]
pub(super) struct Subscribe {
    #[serde(default)]
    pub topics: Vec<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct Unsubscribe {
    pub subscription_id: u32,
}

// Storage and secrets

#[derive(Deserialize)]
pub(super) struct StorageKey {
    #[serde(default)]
    pub scope: String,
    pub key: String,
    #[serde(default)]
    pub value: Option<Value>,
}

#[derive(Deserialize)]
pub(super) struct SecretKey {
    #[serde(default)]
    pub plugin: Option<String>,
    pub key: String,
    #[serde(default)]
    pub value: Option<String>,
}

// Broker

#[derive(Deserialize)]
pub(super) struct OptionalPlugin {
    #[serde(default)]
    pub plugin: Option<String>,
}

#[derive(Deserialize)]
pub(super) struct Plugin {
    pub plugin: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct Revoke {
    pub grant_id: String,
}

#[derive(Deserialize)]
pub(super) struct Audit {
    #[serde(default)]
    pub plugin: Option<String>,
    #[serde(default)]
    pub limit: Option<u32>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) enum ConsentDecision {
    Allow,
    Deny,
}

#[derive(Deserialize)]
pub(super) struct Consent {
    pub plugin: String,
    pub decision: ConsentDecision,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct Respond {
    pub prompt_id: String,
    pub decision: PromptDecision,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct ViewSelection {
    pub plugin: String,
    pub view_id: String,
    #[serde(default)]
    pub resources: Vec<String>,
}

// Invocations

#[derive(Deserialize)]
pub(super) struct BeginInvocation {
    pub command: String,
    pub source: InvocationSource,
    #[serde(default)]
    pub resources: Vec<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct EndInvocation {
    pub invocation_id: String,
}
