//! Decisions: grant lookup, the sensitive-path denylist, rate limiting and
//! the audit log.

use std::sync::Arc;
use std::time::{Duration, Instant};

use serde_json::json;

use super::consent::permission_scopes;
use super::{db, forbidden, now_ms, Broker, Decision, Grant, Principal, RightChecker, Scope};
use crate::events::Event;
use crate::{AuditEntry, KernelResult};

/// Identical audit records within this window are recorded once.
const AUDIT_DEDUPE: Duration = Duration::from_secs(2);
/// Token bucket for destructive rights, per plugin and right.
const RATE_BURST: f64 = 200.0;
const RATE_REFILL_PER_S: f64 = 50.0;

pub(super) struct Bucket {
    tokens: f64,
    at: Instant,
}

impl Broker {
    pub(super) fn live_grants(&self, principal: &str) -> Vec<Grant> {
        let now = now_ms();
        let mut out: Vec<Grant> = self
            .0
            .intents
            .read()
            .iter()
            .filter(|g| g.principal == principal && g.expires_ms.is_none_or(|e| e > now))
            .cloned()
            .collect();
        out.extend(
            self.0
                .standing
                .read()
                .iter()
                .filter(|g| g.principal == principal)
                .cloned(),
        );
        out
    }

    /// `check` without the audit record, for hot paths that filter (event
    /// delivery, listings) rather than act.
    pub fn allows(&self, principal: &Principal, right: &str, resource: &str) -> bool {
        self.decide(principal, right, resource, None).0 == Decision::Allow
    }

    /// The decision for one resource, without prompting. Audited.
    pub fn check(&self, principal: &Principal, right: &str, resource: &str) -> Decision {
        self.decide(principal, right, resource, Some("check")).0
    }

    /// `(decision, canonical resource, sensitive)`. `audit: None` = silent.
    pub(super) fn decide(
        &self,
        principal: &Principal,
        right: &str,
        resource: &str,
        audit: Option<&str>,
    ) -> (Decision, String, bool) {
        if principal.has_user_authority() {
            return (Decision::Allow, resource.to_owned(), false);
        }
        let Some(checker) = self.checker(right) else {
            return (
                Decision::Deny(format!("unknown right `{right}`")),
                resource.to_owned(),
                false,
            );
        };
        let res = match checker.canonicalize(right, resource) {
            Ok(r) => r,
            Err(e) => return (Decision::Deny(e), resource.to_owned(), false),
        };
        if self.is_trusted(principal) {
            return (Decision::Allow, res, false);
        }
        let who = principal.to_string();
        let covering: Vec<Grant> = self
            .live_grants(&who)
            .into_iter()
            .filter(|g| checker.implies(&g.right, right) && checker.covers(right, &g.scope, &res))
            .collect();
        let sensitive = checker.sensitive(right, &res);
        let optional = self.optional_covers(principal, &*checker, right, &res, sensitive.is_some());
        let mut decision = match &sensitive {
            Some(_) if covering.iter().any(|g| g.overrides_denylist) => Decision::Allow,
            Some(_) if optional => Decision::Prompt,
            Some(why) => Decision::Deny(format!("{res} is protected ({why})")),
            None if !covering.is_empty() => Decision::Allow,
            None if optional => Decision::Prompt,
            None => Decision::Deny(format!("{who} holds no `{right}` grant for {res}")),
        };
        if decision == Decision::Allow
            && checker.destructive(right)
            && !self.take_token(&who, right)
        {
            decision = Decision::Deny(format!("{who} is using `{right}` too fast"));
            self.audit(&who, right, &res, "rate_limited", None, audit);
            return (decision, res, sensitive.is_some());
        }
        if let Some(source) = audit {
            let (word, reason) = match &decision {
                Decision::Allow => ("allow", None),
                Decision::Deny(r) => ("deny", Some(r.as_str())),
                Decision::Prompt => ("prompt", None),
            };
            self.audit(&who, right, &res, word, reason, Some(source));
        }
        (decision, res, sensitive.is_some())
    }

    /// Did the plugin declare an optional permission it may prompt for?
    /// Sensitive resources need an explicit per-path declaration.
    pub(super) fn optional_covers(
        &self,
        principal: &Principal,
        checker: &dyn RightChecker,
        right: &str,
        res: &str,
        sensitive: bool,
    ) -> bool {
        let Some(facts) = principal.plugin().and_then(|p| self.facts(p)) else {
            return false;
        };
        facts
            .manifest
            .permissions
            .optional
            .iter()
            .filter_map(permission_scopes)
            .filter(|(r, _)| checker.implies(r, right))
            .any(|(r, scopes)| {
                scopes.iter().any(|s| {
                    if sensitive {
                        matches!(s, Scope::Pattern(p) if !p.contains(['*', '?', '[']))
                            && checker.covers(&r, s, res)
                    } else {
                        checker.covers(&r, s, res)
                    }
                })
            })
    }

    pub(super) fn take_token(&self, who: &str, right: &str) -> bool {
        let mut buckets = self.0.buckets.lock();
        let b = buckets
            .entry((who.to_owned(), right.to_owned()))
            .or_insert(Bucket {
                tokens: RATE_BURST,
                at: Instant::now(),
            });
        b.tokens = (b.tokens + b.at.elapsed().as_secs_f64() * RATE_REFILL_PER_S).min(RATE_BURST);
        b.at = Instant::now();
        if b.tokens < 1.0 {
            return false;
        }
        b.tokens -= 1.0;
        true
    }

    pub(super) fn audit(
        &self,
        principal: &str,
        right: &str,
        resource: &str,
        decision: &str,
        reason: Option<&str>,
        source: Option<&str>,
    ) {
        let key = (
            principal.to_owned(),
            right.to_owned(),
            resource.to_owned(),
            decision.to_owned(),
        );
        {
            let mut recent = self.0.recent.lock();
            if recent.get(&key).is_some_and(|t| t.elapsed() < AUDIT_DEDUPE) {
                return;
            }
            if recent.len() > 4096 {
                recent.retain(|_, t| t.elapsed() < AUDIT_DEDUPE);
            }
            recent.insert(key, Instant::now());
        }
        let entry = AuditEntry {
            id: 0.0,
            time_ms: now_ms(),
            principal: principal.to_owned(),
            right: right.to_owned(),
            resource: resource.to_owned(),
            decision: decision.to_owned(),
            reason: reason.map(str::to_owned),
            source: source.map(str::to_owned),
        };
        if let Err(e) = db::append_audit(&self.0.db, &entry) {
            eprintln!("[atomo] audit log: {e}");
        }
    }

    /// Why `resource` is on the sensitive-path denylist for `right`, if it
    /// is. Lets trusted callers that walk many resources (a disk-usage scan)
    /// stay out of protected places too.
    pub fn sensitive(&self, right: &str, resource: &str) -> Option<String> {
        let checker = self.checker(right)?;
        let res = checker.canonicalize(right, resource).ok()?;
        checker.sensitive(right, &res)
    }

    /// Record what an allowed principal did with a right (e.g. the command
    /// line a plugin ran) in the audit log. Never record secrets or content.
    pub fn record(&self, principal: &Principal, right: &str, resource: &str, what: &str) {
        if !principal.has_user_authority() {
            self.audit(
                &principal.to_string(),
                right,
                resource,
                what,
                None,
                Some("use"),
            );
        }
    }

    /// Check every resource; prompt (once, for all of them) when the plugin
    /// declared it may ask. Returns the canonical resources, or `forbidden`.
    pub async fn authorize(
        &self,
        principal: &Principal,
        right: &str,
        resources: &[String],
    ) -> KernelResult<Vec<String>> {
        let mut out = Vec::with_capacity(resources.len());
        let mut ask = Vec::new();
        let mut sensitive = false;
        for r in resources {
            let (d, canonical, s) = self.decide(principal, right, r, Some("check"));
            match d {
                Decision::Allow => {}
                Decision::Deny(why) => {
                    return Err(
                        forbidden(why).with_data(json!({ "right": right, "resource": canonical }))
                    )
                }
                Decision::Prompt => {
                    sensitive |= s;
                    ask.push(canonical.clone());
                }
            }
            out.push(canonical);
        }
        if !ask.is_empty() {
            self.prompt(principal, right, ask, sensitive).await?;
        }
        Ok(out)
    }

    /// Does the principal hold any grant covering `resource`? A plugin may
    /// only pass on resources it holds.
    pub fn holds(&self, principal: &Principal, resource: &str) -> bool {
        if self.is_trusted(principal) {
            return true;
        }
        let rights: Vec<String> = self.rights();
        rights.iter().any(|right| {
            let Some(c) = self.checker(right) else {
                return false;
            };
            c.canonicalize(right, resource).is_ok()
                && matches!(
                    self.decide(principal, right, resource, None).0,
                    Decision::Allow
                )
        })
    }

    /// The scopes of `right` (or a right implying it) the principal holds;
    /// `None` means unrestricted (user, core tier). Used to confine
    /// providers to the granted roots.
    pub fn scopes(&self, principal: &Principal, right: &str) -> Option<Vec<Scope>> {
        if self.is_trusted(principal) {
            return None;
        }
        let checker = self.checker(right)?;
        Some(
            self.live_grants(&principal.to_string())
                .into_iter()
                .filter(|g| checker.implies(&g.right, right))
                .map(|g| g.scope)
                .collect(),
        )
    }

    /// The event as an untrusted subscriber may see it, or `None`.
    /// Kernel topics pass, except the broker's own (other plugins' prompts and
    /// grants); right checkers narrow their domains' topics (`vfs.changed`).
    pub fn filter_event(&self, principal: &Principal, event: &Event) -> Option<Event> {
        if self.is_trusted(principal) {
            return Some(event.clone());
        }
        if atomo_manifest::has_prefix(&event.topic, "broker") {
            return None;
        }
        let checkers: Vec<Arc<dyn RightChecker>> = self
            .0
            .checkers
            .read()
            .iter()
            .map(|(_, c)| c.clone())
            .collect();
        for c in checkers {
            if let Some(verdict) = c.filter_event(self, principal, event) {
                return verdict.map(|payload| Event {
                    payload,
                    ..event.clone()
                });
            }
        }
        Some(event.clone())
    }

    /// The audit log, newest first, optionally of one principal.
    pub fn audit_log(&self, principal: Option<&str>, limit: u32) -> KernelResult<Vec<AuditEntry>> {
        db::audit(&self.0.db, principal, limit.clamp(1, 10_000))
    }
}
