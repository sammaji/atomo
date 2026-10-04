//! The broker's vocabulary: principals, grants, decisions, audit records and
//! the consent UI's payloads.

use std::fmt;

use serde::{Deserialize, Serialize};
use ts_rs::TS;

use super::summary::SummaryLine;
use crate::registry::Tier;
use crate::Caller;

/// Who is acting.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Principal {
    /// The shell on direct user input: the TCB, full authority.
    User,
    /// A plugin, by ID (the tier decides how much it is trusted).
    Plugin(String),
}

impl Principal {
    /// `user`, `plugin:<id>` or a bare plugin ID (the form `Invocation::caller`
    /// and the operations journal use).
    pub fn parse(s: &str) -> Principal {
        match s {
            "user" => Principal::User,
            _ => Principal::Plugin(s.strip_prefix("plugin:").unwrap_or(s).to_owned()),
        }
    }

    /// Only the user acts with the user's own authority.
    pub fn has_user_authority(&self) -> bool {
        matches!(self, Principal::User)
    }

    pub fn plugin(&self) -> Option<&str> {
        match self {
            Principal::Plugin(id) => Some(id),
            _ => None,
        }
    }
}

impl fmt::Display for Principal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Principal::User => f.write_str("user"),
            Principal::Plugin(id) => f.write_str(id),
        }
    }
}

impl From<&Caller> for Principal {
    fn from(c: &Caller) -> Self {
        match c {
            Caller::Shell => Principal::User,
            Caller::Plugin(id) => Principal::Plugin(id.clone()),
        }
    }
}

/// What a grant covers. `Exact` and `Tree` hold canonical resources; `Pattern`
/// holds a manifest string (`paths`, `hosts`, `binaries` entry) interpreted by
/// the right's checker.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, TS)]
#[serde(tag = "kind", content = "value", rename_all = "camelCase")]
#[ts(export, rename = "GrantScope")]
pub enum Scope {
    /// Everything this right covers (rights without resources: `secrets`…).
    Any,
    /// Exactly this resource.
    Exact(String),
    /// This resource and everything under it (selected folders are recursive).
    Tree(String),
    /// A declared pattern: a path or glob, a host, a binary.
    Pattern(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export)]
pub enum GrantKind {
    Standing,
    Intent,
}

/// What a grant's lifetime is tied to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(tag = "kind", content = "id", rename_all = "camelCase")]
#[ts(export, rename = "GrantBinding")]
pub enum Binding {
    /// Until revoked (standing grants).
    Persistent,
    /// Until it expires (`Allow once`).
    Timed,
    /// One command invocation.
    Invocation(String),
    /// One operations job.
    Job(String),
    /// A view's visible selection (`<plugin>/<viewId>`).
    View(String),
    /// A resource the shell opened in one of the plugin's tabs, until the
    /// tab closes (`broker.closeResource`).
    Resource(String),
}

#[derive(Debug, Clone, PartialEq, Serialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export)]
pub struct Grant {
    pub id: String,
    /// Principal (`user` or a plugin ID).
    pub principal: String,
    pub right: String,
    pub scope: Scope,
    pub kind: GrantKind,
    /// `manifest`, `prompt`, `user`, an access token (`selection:read`),
    /// `delegated:<plugin>`, `retained`.
    pub source: String,
    pub binding: Binding,
    /// An explicit per-path grant that reaches past the sensitive-path denylist.
    pub overrides_denylist: bool,
    pub created_ms: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub expires_ms: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Deny(String),
    /// Not covered, but the plugin declared it may ask: show a consent prompt.
    Prompt,
}

/// One line of the append-only audit log.
#[derive(Debug, Clone, PartialEq, Serialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export)]
pub struct AuditEntry {
    pub id: f64,
    pub time_ms: f64,
    pub principal: String,
    pub right: String,
    pub resource: String,
    /// `allow`, `deny`, `prompt`, `allowOnce`, `allowAlways`, `denied`
    /// (by the user), `timeout`, `rate_limited`, `grant`, `revoke`.
    pub decision: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub reason: Option<String>,
    /// What caused it: `check`, a gesture (`selection:read via menu`), `consent`…
    #[serde(skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub source: Option<String>,
}

/// `broker.promptRequested`: a host-rendered consent request.
#[derive(Debug, Clone, PartialEq, Serialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export)]
pub struct PromptRequest {
    pub prompt_id: String,
    pub plugin: String,
    pub display_name: String,
    pub tier: Option<Tier>,
    pub right: String,
    /// Canonical resources asked for.
    pub resources: Vec<String>,
    /// Plain-language "what" (e.g. "Reads files in ~/Documents").
    pub text: String,
    /// The plugin's declared reason ("why").
    #[serde(skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub reason: Option<String>,
    /// At least one resource is on the sensitive-path denylist: show a warning.
    pub sensitive: bool,
    pub created_ms: f64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export)]
pub enum PromptDecision {
    Once,
    Always,
    Deny,
}

/// What `broker.summary` and the consent dialogs show for one plugin.
#[derive(Debug, Clone, PartialEq, Serialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export)]
pub struct PermissionSummary {
    pub plugin: String,
    pub display_name: String,
    pub version: String,
    pub tier: Tier,
    pub lines: Vec<SummaryLine>,
    /// Positive badge: nothing but what the user hands over.
    pub needs_no_permissions: bool,
    /// Waiting for install or update consent.
    pub needs_consent: bool,
    /// Lines not covered by the previous consent (an update's escalation).
    pub added: Vec<SummaryLine>,
    pub dependencies: Vec<String>,
    /// Dependencies not covered by the previous consent.
    pub added_dependencies: Vec<String>,
}

/// How much of an opened resource a plugin tab may use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export)]
pub enum ResourceAccess {
    Read,
    Write,
}

impl ResourceAccess {
    /// The intent-access token whose grants an opened resource keeps.
    pub(super) fn token(self) -> &'static str {
        match self {
            ResourceAccess::Read => "opened:read",
            ResourceAccess::Write => "opened:write",
        }
    }
}

/// `broker.openResource` (shell only).
#[derive(Debug, Clone, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export)]
pub struct OpenResourceParams {
    pub plugin: String,
    pub uri: String,
    pub access: ResourceAccess,
}

#[derive(Debug, Clone, Serialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export)]
pub struct OpenResourceResult {
    /// Pass to `broker.closeResource` when the tab closes.
    pub grant_id: String,
}

/// `broker.closeResource` (shell only).
#[derive(Debug, Clone, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export)]
pub struct CloseResourceParams {
    pub grant_id: String,
}
