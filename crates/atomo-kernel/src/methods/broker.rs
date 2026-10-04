//! The broker's internal methods (the shell's trusted consent UI and the
//! Plugins page) and the secrets API.

use std::sync::atomic::Ordering;
use std::time::Duration;

use serde::Deserialize;
use serde_json::{json, Value};

use crate::broker::{CloseResourceParams, OpenResourceParams, OpenResourceResult, Principal};
use crate::call::{CallContext, Caller};
use crate::{
    Invocation, InvocationSource, Kernel, KernelError, KernelResult, PermissionSummary,
    PromptDecision,
};

/// A frontend command invocation the shell never ends still releases its
/// grants after this long.
const FRONTEND_INVOCATION_TTL: Duration = Duration::from_secs(600);

#[derive(Deserialize)]
struct OptionalPlugin {
    #[serde(default)]
    plugin: Option<String>,
}

#[derive(Deserialize)]
struct Plugin {
    plugin: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Revoke {
    grant_id: String,
}

#[derive(Deserialize)]
struct Audit {
    #[serde(default)]
    plugin: Option<String>,
    #[serde(default)]
    limit: Option<u32>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
enum ConsentDecision {
    Allow,
    Deny,
}

#[derive(Deserialize)]
struct Consent {
    plugin: String,
    decision: ConsentDecision,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Respond {
    prompt_id: String,
    decision: PromptDecision,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ViewSelection {
    plugin: String,
    view_id: String,
    #[serde(default)]
    resources: Vec<String>,
}

#[derive(Deserialize)]
struct BeginInvocation {
    command: String,
    source: InvocationSource,
    #[serde(default)]
    resources: Vec<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct EndInvocation {
    invocation_id: String,
}

#[derive(Deserialize)]
struct SecretKey {
    #[serde(default)]
    plugin: Option<String>,
    key: String,
    #[serde(default)]
    value: Option<String>,
}

/// Secrets are namespaced by the caller's own plugin ID.
fn secret_principal(call: &CallContext, claimed: Option<String>) -> KernelResult<Principal> {
    match (&call.caller, claimed) {
        (Caller::Plugin(id), _) => Ok(Principal::Plugin(id.clone())),
        // In-realm frontends act through the shell, which names them.
        (_, Some(id)) => Ok(Principal::Plugin(id)),
        _ => Err(KernelError::invalid_params("missing `plugin`")),
    }
}

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

pub(super) fn register(k: &Kernel) {
    k.kernel_method("broker.grants", |k, _, p: OptionalPlugin| async move {
        Ok(k.0.broker.grants(p.plugin.as_deref()))
    });
    k.kernel_method("broker.revoke", |k, _, p: Revoke| async move {
        k.0.broker.revoke(&p.grant_id)
    });
    k.kernel_method("broker.audit", |k, _, p: Audit| async move {
        k.0.broker
            .audit_log(p.plugin.as_deref(), p.limit.unwrap_or(200))
    });
    k.kernel_method("broker.consent", |k, _, p: Consent| async move {
        k.consent(&p.plugin, matches!(p.decision, ConsentDecision::Allow))
    });
    k.kernel_method("broker.summary", |k, _, p: Plugin| async move {
        k.0.broker
            .summary(&p.plugin)
            .ok_or_else(|| Kernel::not_a_plugin(&p.plugin))
    });
    k.kernel_method("broker.respond", |k, call, p: Respond| async move {
        // Only host-rendered UI can grant.
        Kernel::require_shell(&call, "answers prompts")?;
        k.0.broker.respond(&p.prompt_id, p.decision)
    });
    k.kernel_method("broker.pending", |k, _, _: Value| async move {
        let consents: Vec<PermissionSummary> = k
            .registry()
            .plugins
            .iter()
            .filter(|p| p.needs_consent)
            .filter_map(|p| k.0.broker.summary(&p.id))
            .collect();
        Ok(json!({
            "prompts": k.0.broker.pending_prompts(),
            "consents": consents,
        }))
    });
    k.kernel_method(
        "broker.viewSelection",
        |k, call, p: ViewSelection| async move {
            Kernel::require_shell(&call, "reports selections")?;
            let declares =
                k.0.broker
                    .plugin_manifest(&p.plugin)
                    .is_some_and(|(_, m)| declares_access(&m, &p.view_id, "selection:read"));
            if !declares {
                return Err(KernelError::forbidden(format!(
                    "`{}` declares no `selection:read` view `{}`",
                    p.plugin, p.view_id
                )));
            }
            k.0.broker
                .set_view_selection(&p.plugin, &p.view_id, &p.resources)
                .detach();
            Ok(())
        },
    );

    // Frontend commands run in the shell (or a sandbox), not here: the shell
    // brackets a gesture-invoked one with begin/end so its declared `access`
    // is minted exactly as for backend commands.
    k.kernel_method(
        "broker.beginInvocation",
        |k, call, p: BeginInvocation| async move {
            if call.caller != Caller::Shell || !p.source.is_gesture() {
                return Err(KernelError::forbidden(
                    "only the shell's trusted gestures mint intent grants",
                ));
            }
            let info =
                k.registry().command(&p.command).cloned().ok_or_else(|| {
                    KernelError::not_found(format!("no such command: {}", p.command))
                })?;
            let invocation = Invocation {
                source: p.source,
                trusted_gesture: true,
                caller: "user".into(),
                window: None,
                resources: p.resources,
            };
            let lease = k.intent_lease(&info.plugin, &info.decl.access, &invocation);
            let id = format!("fi{}", k.0.next_invocation.fetch_add(1, Ordering::Relaxed));
            k.0.broker.begin_user_invocation(&id, &info.plugin);
            if let Some(lease) = lease {
                k.0.frontend_invocations.lock().insert(id.clone(), lease);
                let (k2, id2) = (k.clone(), id.clone());
                k.0.runtime.spawn(async move {
                    tokio::time::sleep(FRONTEND_INVOCATION_TTL).await;
                    k2.0.frontend_invocations.lock().remove(&id2);
                });
            }
            Ok(json!({ "invocationId": id }))
        },
    );
    k.kernel_method(
        "broker.endInvocation",
        |k, _, p: EndInvocation| async move {
            k.0.frontend_invocations.lock().remove(&p.invocation_id);
            k.0.broker.end_user_invocation(&p.invocation_id);
            Ok(())
        },
    );

    // A plugin tab opened on a resource during the plugin's invocation keeps
    // that resource until the tab closes. Nothing is persisted: a tab restored
    // with the session gets its resource back only when a gesture reopens it.
    k.kernel_method(
        "broker.openResource",
        |k, call, p: OpenResourceParams| async move {
            Kernel::require_shell(&call, "opens resources in tabs")?;
            let grant_id = k.0.broker.open_resource(&p.plugin, &p.uri, p.access)?;
            Ok(OpenResourceResult { grant_id })
        },
    );
    k.kernel_method(
        "broker.closeResource",
        |k, call, p: CloseResourceParams| async move {
            Kernel::require_shell(&call, "closes resources")?;
            k.0.broker.close_resource(&p.grant_id);
            Ok(())
        },
    );

    k.kernel_api("secrets.get", |k, call, p: SecretKey| async move {
        let who = secret_principal(&call, p.plugin)?;
        k.0.broker.secret_get(&who, &p.key)
    });
    k.kernel_api("secrets.set", |k, call, p: SecretKey| async move {
        let who = secret_principal(&call, p.plugin)?;
        let value = p
            .value
            .ok_or_else(|| KernelError::invalid_params("missing `value`"))?;
        k.0.broker.secret_set(&who, &p.key, &value)
    });
    k.kernel_api("secrets.delete", |k, call, p: SecretKey| async move {
        let who = secret_principal(&call, p.plugin)?;
        k.0.broker.secret_delete(&who, &p.key)
    });
}
