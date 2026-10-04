//! Granting and revoking: intent grants for gestures, delegation, retention
//! by jobs, standing grants.

use std::collections::BTreeSet;
use std::fmt;
use std::sync::{Arc, Weak};

use super::{
    db, forbidden, now_ms, Binding, Broker, Decision, Grant, GrantKind, Inner, Principal,
    ResourceAccess, RightChecker, Scope,
};
use crate::{KernelError, KernelResult};

/// Keeps a set of in-memory grants alive; dropping it revokes them.
#[must_use = "the grants are revoked when the lease is dropped"]
pub struct GrantLease {
    broker: Weak<Inner>,
    ids: Vec<String>,
    principal: String,
}

impl GrantLease {
    pub(super) fn empty() -> Self {
        GrantLease {
            broker: Weak::new(),
            ids: Vec::new(),
            principal: String::new(),
        }
    }

    /// The grants this lease keeps alive.
    pub fn ids(&self) -> &[String] {
        &self.ids
    }

    pub fn is_empty(&self) -> bool {
        self.ids.is_empty()
    }

    /// Let the grants outlive the lease; [`Broker::release`] (by binding) or
    /// [`Broker::revoke`] ends them.
    pub fn detach(mut self) {
        self.ids.clear();
    }
}

impl fmt::Debug for GrantLease {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GrantLease")
            .field("ids", &self.ids)
            .finish()
    }
}

impl Drop for GrantLease {
    fn drop(&mut self) {
        if self.ids.is_empty() {
            return;
        }
        if let Some(inner) = self.broker.upgrade() {
            let b = Broker(inner);
            b.0.intents.write().retain(|g| !self.ids.contains(&g.id));
            b.grants_changed(&self.principal);
        }
    }
}

impl Broker {
    pub(super) fn push_intents(&self, principal: &str, grants: Vec<Grant>) -> GrantLease {
        if grants.is_empty() {
            return GrantLease::empty();
        }
        let ids = grants.iter().map(|g| g.id.clone()).collect();
        self.0.intents.write().extend(grants);
        self.grants_changed(principal);
        GrantLease {
            broker: Arc::downgrade(&self.0),
            ids,
            principal: principal.to_owned(),
        }
    }

    pub(super) fn intent_grant(
        &self,
        principal: &str,
        right: &str,
        scope: Scope,
        source: &str,
        binding: &Binding,
    ) -> Grant {
        Grant {
            id: self.next_id('i'),
            principal: principal.to_owned(),
            right: right.to_owned(),
            scope,
            kind: GrantKind::Intent,
            source: source.to_owned(),
            binding: binding.clone(),
            overrides_denylist: false,
            created_ms: now_ms(),
            expires_ms: None,
            reason: None,
        }
    }

    /// The `(right, scope)` pairs an access token mints over one resource.
    pub(super) fn intent_pairs(&self, access: &str, resource: &str) -> Vec<(&'static str, Scope)> {
        let checkers: Vec<Arc<dyn RightChecker>> = self
            .0
            .checkers
            .read()
            .iter()
            .map(|(_, c)| c.clone())
            .collect();
        checkers
            .iter()
            .flat_map(|c| c.intent(access, resource))
            .collect()
    }

    /// Mint intent grants for a trusted gesture: exactly `resources`,
    /// for what `access` declares. Callers (the kernel's command router and the
    /// shell's view-selection method) guarantee the gesture.
    pub(crate) fn mint(
        &self,
        plugin: &str,
        access: &[String],
        resources: &[String],
        binding: Binding,
        gesture: &str,
    ) -> GrantLease {
        let mut grants = Vec::new();
        for a in access {
            for r in resources {
                for (right, scope) in self.intent_pairs(a, r) {
                    let resource = match &scope {
                        Scope::Exact(x) | Scope::Tree(x) | Scope::Pattern(x) => x.clone(),
                        Scope::Any => String::new(),
                    };
                    self.audit(
                        plugin,
                        right,
                        &resource,
                        "grant",
                        None,
                        Some(&format!("{a} via {gesture}")),
                    );
                    grants.push(self.intent_grant(plugin, right, scope, a, &binding));
                }
            }
        }
        self.push_intents(plugin, grants)
    }

    /// Delegation: `from` passes resources to `to`'s command. `to`
    /// receives, per resource, only rights `from` holds on it *and* `to`
    /// declares in `access`. Never more than the caller has: no amplification.
    pub(crate) fn delegate(
        &self,
        from: &Principal,
        to: &str,
        access: &[String],
        resources: &[String],
        binding: Binding,
    ) -> GrantLease {
        let mut grants = Vec::new();
        let source = format!("delegated:{from}");
        for a in access {
            for r in resources {
                for (right, scope) in self.intent_pairs(a, r) {
                    let target = match &scope {
                        Scope::Exact(x) | Scope::Tree(x) => x.clone(),
                        _ => continue,
                    };
                    if self.decide(from, right, &target, None).0 == Decision::Allow
                        && !grants
                            .iter()
                            .any(|g: &Grant| g.right == right && g.scope == scope)
                    {
                        grants.push(self.intent_grant(to, right, scope, &source, &binding));
                    }
                }
            }
        }
        self.push_intents(to, grants)
    }

    /// Keep the principal's current *intent* grants covering `resources` alive
    /// for `binding` (e.g. an operations job outliving the invocation that
    /// started it). The copies keep the originals' scopes: longer, never wider.
    /// Fails `forbidden` if a resource isn't covered for one of `rights`.
    pub fn retain(
        &self,
        principal: &Principal,
        rights: &[&str],
        resources: &[String],
        binding: Binding,
    ) -> KernelResult<GrantLease> {
        if self.is_trusted(principal) {
            return Ok(GrantLease::empty());
        }
        let who = principal.to_string();
        let mut keep: Vec<Grant> = Vec::new();
        for right in rights {
            let Some(checker) = self.checker(right) else {
                return Err(forbidden(format!("unknown right `{right}`")));
            };
            for r in resources {
                let (d, res, _) = self.decide(principal, right, r, None);
                if let Decision::Deny(why) = d {
                    return Err(forbidden(why));
                }
                for g in self.0.intents.read().iter().filter(|g| {
                    g.principal == who
                        && checker.implies(&g.right, right)
                        && checker.covers(right, &g.scope, &res)
                }) {
                    if !keep
                        .iter()
                        .any(|k| k.right == g.right && k.scope == g.scope)
                    {
                        let mut copy = g.clone();
                        copy.id = self.next_id('i');
                        copy.source = "retained".into();
                        copy.binding = binding.clone();
                        keep.push(copy);
                    }
                }
            }
        }
        Ok(self.push_intents(&who, keep))
    }

    /// Persist a standing grant (consent, "Always allow", or the user granting
    /// access from the Plugins page). Returns its ID.
    pub fn grant_standing(
        &self,
        principal: &Principal,
        right: &str,
        scope: Scope,
        source: &str,
        overrides_denylist: bool,
    ) -> KernelResult<String> {
        let who = principal.to_string();
        let grant = Grant {
            id: self.next_id('s'),
            principal: who.clone(),
            right: right.to_owned(),
            scope,
            kind: GrantKind::Standing,
            source: source.to_owned(),
            binding: Binding::Persistent,
            overrides_denylist,
            created_ms: now_ms(),
            expires_ms: None,
            reason: None,
        };
        db::insert_grant(&self.0.db, &grant)?;
        let id = grant.id.clone();
        self.audit(
            &who,
            right,
            &scope_text(&grant.scope),
            "grant",
            None,
            Some(source),
        );
        self.0.standing.write().push(grant);
        self.grants_changed(&who);
        Ok(id)
    }

    /// Standing and live in-memory grants, optionally of one principal.
    pub fn grants(&self, principal: Option<&str>) -> Vec<Grant> {
        let now = now_ms();
        let mut out: Vec<Grant> = self
            .0
            .standing
            .read()
            .iter()
            .chain(self.0.intents.read().iter())
            .filter(|g| principal.is_none_or(|p| g.principal == p))
            .filter(|g| g.expires_ms.is_none_or(|e| e > now))
            .cloned()
            .collect();
        out.sort_by(|a, b| a.created_ms.total_cmp(&b.created_ms));
        out
    }

    /// Revoke a grant (standing or in-memory).
    pub fn revoke(&self, id: &str) -> KernelResult<()> {
        let removed = {
            let mut standing = self.0.standing.write();
            standing
                .iter()
                .position(|g| g.id == id)
                .map(|i| standing.remove(i))
        };
        let removed = match removed {
            Some(g) => {
                db::delete_grant(&self.0.db, id)?;
                Some(g)
            }
            None => {
                let mut intents = self.0.intents.write();
                intents
                    .iter()
                    .position(|g| g.id == id)
                    .map(|i| intents.remove(i))
            }
        };
        let g = removed.ok_or_else(|| KernelError::not_found(format!("no grant {id}")))?;
        self.audit(
            &g.principal,
            &g.right,
            &scope_text(&g.scope),
            "revoke",
            None,
            Some("user"),
        );
        self.grants_changed(&g.principal);
        Ok(())
    }

    /// Revoke every in-memory grant bound to `binding` (a job that ended, a
    /// view that closed).
    pub fn release(&self, binding: &Binding) {
        let mut principals = BTreeSet::new();
        self.0.intents.write().retain(|g| {
            let hit = &g.binding == binding;
            if hit {
                principals.insert(g.principal.clone());
            }
            !hit
        });
        for p in principals {
            self.grants_changed(&p);
        }
    }

    /// Replace the grants a view holds on its visible selection
    /// (`selection:read` while the view shows it). Empty `resources` revokes.
    pub(crate) fn set_view_selection(
        &self,
        plugin: &str,
        view: &str,
        resources: &[String],
    ) -> GrantLease {
        let binding = Binding::View(format!("{plugin}/{view}"));
        self.release(&binding);
        self.mint(
            plugin,
            &["selection:read".to_owned()],
            resources,
            binding,
            "visible selection",
        )
    }
}

impl Broker {
    /// Keep what a running invocation handed `plugin` on `resource` alive
    /// after the invocation ends, until [`Broker::close_resource`]: the shell
    /// opens one of the plugin's tabs on the resource. Only a resource the
    /// invocation named (exactly, not something inside it), and never more
    /// access than the invocation granted (`write` needs a declared write
    /// intent). Returns the handle `close_resource` takes.
    pub fn open_resource(
        &self,
        plugin: &str,
        resource: &str,
        access: ResourceAccess,
    ) -> KernelResult<String> {
        let id = self.next_id('r');
        if self.is_trusted(&Principal::Plugin(plugin.to_owned())) {
            return Ok(id);
        }
        let token = access.token();
        let wanted = self.intent_pairs(token, resource);
        if wanted.is_empty() {
            return Err(forbidden(format!(
                "{resource} cannot be opened by a plugin"
            )));
        }
        let handed: Vec<Grant> = self
            .0
            .intents
            .read()
            .iter()
            .filter(|g| g.principal == plugin && matches!(g.binding, Binding::Invocation(_)))
            .cloned()
            .collect();
        let binding = Binding::Resource(id.clone());
        let mut grants = Vec::with_capacity(wanted.len());
        for (right, scope) in wanted {
            let Some(checker) = self.checker(right) else {
                return Err(forbidden(format!("unknown right `{right}`")));
            };
            let held = handed.iter().any(|g| {
                checker.implies(&g.right, right) && same_root(&*checker, right, &g.scope, &scope)
            });
            if !held {
                return Err(forbidden(format!(
                    "{plugin} was not handed {resource} for `{right}` by an invocation"
                )));
            }
            self.audit(
                plugin,
                right,
                &scope_text(&scope),
                "grant",
                None,
                Some(&format!("{token} via tab")),
            );
            grants.push(self.intent_grant(plugin, right, scope, token, &binding));
        }
        self.push_intents(plugin, grants).detach();
        Ok(id)
    }

    /// End the grants [`Broker::open_resource`] returned `id` for (the tab
    /// closed). Unknown handles are ignored.
    pub fn close_resource(&self, id: &str) {
        self.release(&Binding::Resource(id.to_owned()));
    }
}

/// Does the held scope name the same resource as `wanted`, and reach at
/// least as far (a tree for a tree)?
fn same_root(checker: &dyn RightChecker, right: &str, held: &Scope, wanted: &Scope) -> bool {
    match (held, wanted) {
        (Scope::Tree(h), Scope::Tree(w)) | (Scope::Tree(h) | Scope::Exact(h), Scope::Exact(w)) => {
            checker.covers(right, &Scope::Exact(h.clone()), w)
        }
        _ => false,
    }
}

pub(super) fn scope_text(s: &Scope) -> String {
    match s {
        Scope::Any => "*".into(),
        Scope::Exact(x) | Scope::Tree(x) | Scope::Pattern(x) => x.clone(),
    }
}
