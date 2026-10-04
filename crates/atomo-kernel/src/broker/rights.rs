//! How rights are defined: the [`RightChecker`] trait and the kernel's own rights.

use serde_json::Value;

use super::{Broker, Principal, Scope};
use crate::events::Event;

/// Defines rights and their scope semantics. Registered by core-tier plugins
/// (`ActivationContext::define_rights`) or the kernel itself.
pub trait RightChecker: Send + Sync + 'static {
    /// The rights it defines.
    fn rights(&self) -> Vec<&'static str>;

    /// The canonical form every check and grant uses; `Err` refuses the resource.
    fn canonicalize(&self, right: &str, resource: &str) -> Result<String, String>;

    /// Does `scope` cover the canonical `resource`?
    fn covers(&self, right: &str, scope: &Scope, resource: &str) -> bool;

    /// Holding `held` also grants `wanted` (e.g. `fs.write` implies `fs.create`).
    fn implies(&self, held: &str, wanted: &str) -> bool {
        held == wanted
    }

    /// Why the resource is on the denylist, if it is (deny beats allow).
    fn sensitive(&self, _right: &str, _resource: &str) -> Option<String> {
        None
    }

    /// Destructive rights are rate-limited per plugin.
    fn destructive(&self, _right: &str) -> bool {
        false
    }

    /// The scope "Always allow" remembers for a resource.
    fn remember_scope(&self, _right: &str, resource: &str) -> Scope {
        Scope::Exact(resource.to_owned())
    }

    /// The `(right, scope)` grants an intent-access token mints over one
    /// resource (`selection:read` → `fs.read` on the resource's tree).
    fn intent(&self, _access: &str, _resource: &str) -> Vec<(&'static str, Scope)> {
        Vec::new()
    }

    /// Filter an event delivered to an untrusted subscriber:
    /// `None` = not this checker's topic; `Some(None)` = drop it;
    /// `Some(Some(payload))` = deliver this (narrowed) payload.
    fn filter_event(
        &self,
        _broker: &Broker,
        _principal: &Principal,
        _event: &Event,
    ) -> Option<Option<Value>> {
        None
    }

    /// A resource as the consent prompt shows it.
    fn display(&self, _right: &str, resource: &str) -> String {
        resource.to_owned()
    }
}

/// The rights the kernel itself defines.
pub(super) struct KernelRights;

impl RightChecker for KernelRights {
    fn rights(&self) -> Vec<&'static str> {
        vec!["net", "exec", "secrets"]
    }

    fn canonicalize(&self, right: &str, resource: &str) -> Result<String, String> {
        match right {
            // `https://host:443/x`, `host:port` or `host` → `host[:port]`, lowercase.
            "net" => {
                let r = resource.trim();
                let r = r.split_once("://").map_or(r, |(_, rest)| rest);
                let host = r.split('/').next().unwrap_or("").to_ascii_lowercase();
                if host.is_empty() {
                    Err(format!("`{resource}` names no host"))
                } else {
                    Ok(host)
                }
            }
            // The program as the plugin names it: a bare name (resolved on the
            // trusted PATH by whoever runs it) or an absolute path. Never a
            // relative path, which would depend on the working directory.
            "exec" if atomo_manifest::is_valid_binary(resource) => Ok(resource.to_owned()),
            "exec" => Err(format!(
                "`{resource}` is neither a program name nor an absolute path"
            )),
            _ => Ok(resource.to_owned()),
        }
    }

    fn covers(&self, right: &str, scope: &Scope, resource: &str) -> bool {
        match scope {
            Scope::Any => true,
            Scope::Exact(r) | Scope::Tree(r) => r == resource,
            Scope::Pattern(p) => match right {
                "net" => {
                    let p = p.split_once("://").map_or(p.as_str(), |(_, rest)| rest);
                    let p = p.trim_end_matches('/').to_ascii_lowercase();
                    let (host, _port) = resource.split_once(':').unwrap_or((resource, ""));
                    p == resource
                        || p == host
                        || p.strip_prefix("*.").is_some_and(|d| {
                            host.len() > d.len() && host.ends_with(d) && {
                                host.as_bytes()[host.len() - d.len() - 1] == b'.'
                            }
                        })
                }
                "exec" => p == resource,
                _ => true,
            },
        }
    }

    fn destructive(&self, right: &str) -> bool {
        right == "exec"
    }
}
