//! The capability broker: the single place that decides whether a principal
//! may use a right on a resource.
//!
//! `check(principal, right, resource)` answers `Allow`, `Deny(reason)` or
//! `Prompt` from a grant table:
//!
//! - **Principals**: the user (the shell acting on direct input, full
//!   authority) and plugins by ID (core-tier plugins acting on their own
//!   behalf are trusted).
//!   Core-tier services acting *for* a caller check the caller's principal,
//!   never their own, so a plugin cannot borrow a trusted service's authority.
//! - **Rights** are defined by [`RightChecker`]s, which only core-tier
//!   plugins may register (`atomo.vfs` defines the `fs.*` rights); the kernel
//!   defines `net`, `exec` and `secrets`.
//! - **Standing grants** come from the manifest's required permissions on
//!   consent (persisted, revocable) or from "Always allow". A manifest whose
//!   permissions or dependencies grow puts the plugin on hold until the user
//!   approves the difference.
//! - **Intent grants** are minted only for trusted gestures, scoped to exactly
//!   the invocation's resources and bound to the invocation, a job or a
//!   view's visible selection. Delegation never amplifies: a callee receives
//!   at most the caller's rights, and at most what its command declares.
//!
//! Deny beats allow: a sensitive resource is denied under any broad scope;
//! only an explicit per-path grant reaches it. Every decision about an
//! untrusted principal is audited, and destructive rights are rate-limited.
//! `Prompt` becomes a consent request the shell's trusted UI answers; no
//! answer means deny.

mod check;
mod consent;
mod db;
mod grants;
mod invocations;
mod prompt;
mod rights;
pub mod secrets;
pub mod summary;
mod types;

#[cfg(test)]
mod tests;

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use atomo_manifest::Manifest;
use parking_lot::{Mutex, RwLock};
use serde_json::json;
use tokio::sync::oneshot;

pub use consent::consent_atoms;
pub use grants::GrantLease;
pub use rights::RightChecker;
pub use secrets::{KeychainSecrets, MemorySecrets, SecretStore};
pub use summary::{LineKind, Risk, SummaryLine};
pub use types::{
    AuditEntry, Binding, CloseResourceParams, Decision, Grant, GrantKind, OpenResourceParams,
    OpenResourceResult, PermissionSummary, Principal, PromptDecision, PromptRequest,
    ResourceAccess, Scope,
};

use crate::events::EventBus;
use crate::registry::Tier;
use crate::storage::KernelDb;
use crate::{KernelError, KernelResult};

/// How long a consent prompt waits for the user before it counts as "deny".
pub const DEFAULT_PROMPT_TIMEOUT: Duration = Duration::from_secs(120);
/// "Allow once" covers the request and its immediate follow-ups for this long.
pub const ONCE_TTL: Duration = Duration::from_secs(300);

fn now_ms() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as f64)
        .unwrap_or(0.0)
}

fn forbidden(message: impl Into<String>) -> KernelError {
    KernelError::forbidden(message)
}

/// What the broker knows about a plugin (refreshed on every registry rebuild).
#[derive(Clone)]
pub(crate) struct PluginFacts {
    pub tier: Tier,
    pub manifest: Arc<Manifest>,
}

type PendingPrompt = (PromptRequest, oneshot::Sender<PromptDecision>);

struct Inner {
    db: KernelDb,
    events: EventBus,
    checkers: RwLock<Vec<(String, Arc<dyn RightChecker>)>>,
    plugins: RwLock<HashMap<String, PluginFacts>>,
    /// Persistent grants (mirrors the `grants` table).
    standing: RwLock<Vec<Grant>>,
    /// In-memory grants: intent, delegated, retained, "allow once".
    intents: RwLock<Vec<Grant>>,
    next: AtomicU64,
    prompts: Mutex<HashMap<String, PendingPrompt>>,
    prompt_timeout: RwLock<Duration>,
    buckets: Mutex<HashMap<(String, String), check::Bucket>>,
    recent: Mutex<HashMap<(String, String, String, String), Instant>>,
    secrets: RwLock<Arc<dyn SecretStore>>,
    /// Frontend command invocations from a user gesture, in progress:
    /// invocation ID → (plugin, started).
    user_invocations: Mutex<HashMap<String, (String, Instant)>>,
}

/// The broker handle (`Kernel::broker()`). Cheap to clone.
#[derive(Clone)]
pub struct Broker(Arc<Inner>);

impl Broker {
    pub(crate) fn new(db: KernelDb, events: EventBus) -> KernelResult<Broker> {
        db::init(&db)?;
        let standing = db::load_grants(&db)?;
        let next = standing
            .iter()
            .filter_map(|g| g.id.strip_prefix('s').and_then(|n| n.parse::<u64>().ok()))
            .max()
            .unwrap_or(0)
            + 1;
        let broker = Broker(Arc::new(Inner {
            db,
            events,
            checkers: Default::default(),
            plugins: Default::default(),
            standing: RwLock::new(standing),
            intents: Default::default(),
            next: AtomicU64::new(next),
            prompts: Default::default(),
            prompt_timeout: RwLock::new(DEFAULT_PROMPT_TIMEOUT),
            buckets: Default::default(),
            recent: Default::default(),
            secrets: RwLock::new(Arc::new(MemorySecrets::default())),
            user_invocations: Default::default(),
        }));
        broker.register_checker("kernel", Arc::new(rights::KernelRights));
        Ok(broker)
    }

    pub(crate) fn set_secret_store(&self, store: Arc<dyn SecretStore>) {
        *self.0.secrets.write() = store;
    }

    /// How long prompts wait for an answer (tests shorten it).
    pub fn set_prompt_timeout(&self, timeout: Duration) {
        *self.0.prompt_timeout.write() = timeout;
    }

    pub(crate) fn set_plugins(&self, plugins: HashMap<String, PluginFacts>) {
        *self.0.plugins.write() = plugins;
    }

    /// Register the rights `checker` defines, owned by `owner` (kernel or a
    /// core-tier plugin). A right already defined by another owner is refused.
    pub(crate) fn register_checker(&self, owner: &str, checker: Arc<dyn RightChecker>) -> bool {
        let mut checkers = self.0.checkers.write();
        let taken = checker.rights().iter().any(|r| {
            checkers
                .iter()
                .any(|(o, c)| o != owner && c.rights().contains(r))
        });
        if taken {
            return false;
        }
        checkers.push((owner.to_owned(), checker));
        true
    }

    pub(crate) fn unregister_checkers(&self, owner: &str) {
        self.0.checkers.write().retain(|(o, _)| o != owner);
    }

    /// Every right currently defined.
    pub fn rights(&self) -> Vec<String> {
        let mut out: Vec<String> = self
            .0
            .checkers
            .read()
            .iter()
            .flat_map(|(_, c)| c.rights())
            .map(str::to_owned)
            .collect();
        out.sort();
        out
    }

    fn checker(&self, right: &str) -> Option<Arc<dyn RightChecker>> {
        self.0
            .checkers
            .read()
            .iter()
            .find(|(_, c)| c.rights().contains(&right))
            .map(|(_, c)| c.clone())
    }

    fn facts(&self, plugin: &str) -> Option<PluginFacts> {
        self.0.plugins.read().get(plugin).cloned()
    }

    /// Core-tier plugins acting on their own behalf, and the user.
    pub fn is_trusted(&self, principal: &Principal) -> bool {
        match principal {
            Principal::User => true,
            Principal::Plugin(id) => self.facts(id).is_some_and(|f| f.tier == Tier::Core),
        }
    }

    fn next_id(&self, prefix: char) -> String {
        format!("{prefix}{}", self.0.next.fetch_add(1, Ordering::Relaxed))
    }

    /// The plugin's manifest and tier, as the registry last saw them.
    pub(crate) fn plugin_manifest(&self, plugin: &str) -> Option<(Tier, Arc<Manifest>)> {
        self.facts(plugin).map(|f| (f.tier, f.manifest))
    }

    fn grants_changed(&self, principal: &str) {
        self.0.events.emit(
            "kernel",
            "broker.grantsChanged",
            json!({ "plugin": principal }),
        );
    }
}
