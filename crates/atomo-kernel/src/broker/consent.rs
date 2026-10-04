//! Install and update consent: what the user approved, whether a plugin must
//! wait for approval, and the summary the consent dialogs show.

use std::collections::BTreeSet;

use atomo_manifest::Manifest;
use serde_json::Value;

use super::summary::{self, LineKind};
use super::{db, now_ms, Broker, PermissionSummary, Principal, Scope};
use crate::registry::Tier;
use crate::KernelResult;

/// The `(right, scopes)` of one manifest permission entry.
pub(super) fn permission_scopes(p: &Value) -> Option<(String, Vec<Scope>)> {
    let right = p.get("id")?.as_str()?.to_owned();
    let mut scopes = Vec::new();
    for key in ["paths", "hosts", "binaries"] {
        for s in p.get(key).and_then(Value::as_array).into_iter().flatten() {
            if let Some(s) = s.as_str() {
                scopes.push(Scope::Pattern(s.to_owned()));
            }
        }
    }
    if scopes.is_empty() {
        scopes.push(Scope::Any);
    }
    Some((right, scopes))
}

/// The atoms of what a user consents to: one per `(right, scope)` of the
/// required permissions, one per dependency. An update escalates when it adds
/// an atom (new dependencies count too).
pub fn consent_atoms(m: &Manifest) -> Vec<String> {
    let mut atoms = BTreeSet::new();
    for p in &m.permissions.required {
        if let Some((right, scopes)) = permission_scopes(p) {
            for s in scopes {
                atoms.insert(match s {
                    Scope::Pattern(p) => format!("{right} {p}"),
                    _ => right.clone(),
                });
            }
        }
    }
    for dep in m.dependencies.keys() {
        atoms.insert(format!("dependency {dep}"));
    }
    atoms.into_iter().collect()
}

impl Broker {
    /// Why a plugin must wait for consent before it may run, if it must:
    /// non-core plugins whose required permissions are not yet consented, or
    /// whose permissions or dependencies grew since the last consent.
    pub(crate) fn consent_hold(&self, tier: Tier, manifest: &Manifest) -> Option<String> {
        if tier == Tier::Core {
            return None;
        }
        let atoms = consent_atoms(manifest);
        match db::consent(&self.0.db, &manifest.id).ok().flatten() {
            Some(consented) => {
                let added: Vec<&String> = atoms.iter().filter(|a| !consented.contains(a)).collect();
                (!added.is_empty()).then(|| {
                    format!(
                        "the update asks for more than you approved ({}); review its permissions",
                        added
                            .iter()
                            .map(|s| s.as_str())
                            .collect::<Vec<_>>()
                            .join(", ")
                    )
                })
            }
            None if !manifest.permissions.required.is_empty() => {
                Some("waiting for you to review its permissions".into())
            }
            None => None,
        }
    }

    /// The user approved `manifest`'s permissions: remember what, and grant
    /// the required permissions as standing grants (replacing older ones).
    pub(crate) fn record_consent(&self, manifest: &Manifest) -> KernelResult<()> {
        let id = &manifest.id;
        db::set_consent(
            &self.0.db,
            id,
            &consent_atoms(manifest),
            &manifest.version,
            now_ms() as i64,
        )?;
        db::delete_grants_from(&self.0.db, id, "manifest")?;
        self.0
            .standing
            .write()
            .retain(|g| !(g.principal == *id && g.source == "manifest"));
        let principal = Principal::Plugin(id.clone());
        for p in &manifest.permissions.required {
            if let Some((right, scopes)) = permission_scopes(p) {
                for s in scopes {
                    self.grant_standing(&principal, &right, s, "manifest", false)?;
                }
            }
        }
        self.audit(
            id,
            "consent",
            &manifest.version,
            "allow",
            None,
            Some("consent"),
        );
        Ok(())
    }

    /// The consent record's atoms for `plugin` (escalation diffs).
    pub(crate) fn consented_atoms(&self, plugin: &str) -> Option<Vec<String>> {
        db::consent(&self.0.db, plugin).ok().flatten()
    }

    /// The plain-language summary of a plugin's permissions, with the diff
    /// against its last consent.
    pub fn summary(&self, plugin: &str) -> Option<PermissionSummary> {
        let facts = self.facts(plugin)?;
        let m = &facts.manifest;
        let lines = summary::summarize(m);
        let consented = self.consented_atoms(plugin);
        let hold = self.consent_hold(facts.tier, m);
        let (added, added_dependencies) = match (&consented, &hold) {
            (Some(c), Some(_)) => {
                let added = m
                    .permissions
                    .required
                    .iter()
                    .filter(|p| {
                        permission_scopes(p).is_some_and(|(right, scopes)| {
                            scopes.iter().any(|s| {
                                let atom = match s {
                                    Scope::Pattern(p) => format!("{right} {p}"),
                                    _ => right.clone(),
                                };
                                !c.contains(&atom)
                            })
                        })
                    })
                    .map(|p| summary::describe_permission(p, LineKind::Required))
                    .collect();
                let deps = m
                    .dependencies
                    .keys()
                    .filter(|d| !c.contains(&format!("dependency {d}")))
                    .cloned()
                    .collect();
                (added, deps)
            }
            _ => (Vec::new(), Vec::new()),
        };
        Some(PermissionSummary {
            plugin: plugin.to_owned(),
            display_name: m.display_name.clone(),
            version: m.version.clone(),
            tier: facts.tier,
            needs_no_permissions: lines.is_empty(),
            lines,
            needs_consent: hold.is_some(),
            added,
            dependencies: m.dependencies.keys().cloned().collect(),
            added_dependencies,
        })
    }
}
