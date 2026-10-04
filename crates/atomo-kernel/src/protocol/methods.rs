use serde_json::{json, Value};

use super::params::*;
use super::Visibility::{Api, Internal};
use super::{CallContext, Caller};
use crate::broker::{CloseResourceParams, OpenResourceParams, OpenResourceResult};
use crate::{ExecuteParams, Kernel, KernelError, KernelResult, SaveSettingsParams};

/// Fails unless the shell itself is calling.
fn require_shell(call: &CallContext, what: &str) -> KernelResult<()> {
    if call.caller == Caller::Shell {
        Ok(())
    } else {
        Err(KernelError::forbidden(format!("only the shell {what}")))
    }
}

impl Kernel {
    pub(crate) fn register_methods(&self) {
        // Boot and registry
        self.kernel_method("kernel.bootstrap", Internal, |k, _, _: Value| async move {
            Ok(k.bootstrap())
        });
        self.kernel_method("registry.snapshot", Internal, |k, _, _: Value| async move {
            Ok((*k.registry()).clone())
        });

        // Plugins
        self.kernel_method("plugins.reload", Internal, |k, _, p: PluginId| async move {
            k.reload_plugin(&p.id)
        });
        self.kernel_method(
            "plugins.setEnabled",
            Internal,
            |k, _, p: SetEnabled| async move { k.set_enabled(&p.id, p.enabled) },
        );
        self.kernel_method(
            "plugins.reportFrontendState",
            Internal,
            |k, _, p: ReportState| async move {
                k.set_frontend_state(&p.id, p.state, p.error);
                Ok(())
            },
        );

        // Settings
        self.kernel_method("settings.getAll", Api, |k, call, _: Value| async move {
            Ok(k.settings_for(&call.caller))
        });
        self.kernel_method("settings.set", Internal, |k, _, p: SetSetting| async move {
            k.set_setting(&p.key, p.value.filter(|v| !v.is_null()))
        });
        self.kernel_method(
            "settings.save",
            Internal,
            |k, _, p: SaveSettingsParams| async move { k.save_settings(p) },
        );

        // Commands
        self.kernel_method(
            "commands.execute",
            Api,
            |k, call, p: ExecuteParams| async move { k.execute_for(&call.caller, p).await },
        );

        // Context keys
        self.kernel_method("context.get", Api, |k, call, _: Value| async move {
            Ok(k.context_for(&call.caller))
        });
        self.kernel_method(
            "context.set",
            Api,
            |k, call, p: AsPlugin<ContextSet>| async move {
                let p = p.bind(&call)?;
                k.set_context_as(&p.plugin, p.rest.key, p.rest.value)
            },
        );

        // Events
        self.kernel_method(
            "events.publish",
            Api,
            |k, call, p: AsPlugin<Publish>| async move {
                let p = p.bind(&call)?;
                k.publish(&p.plugin, &p.rest.topic, p.rest.payload)
            },
        );
        self.kernel_method(
            "events.subscribe",
            Api,
            |k, call, p: Subscribe| async move {
                let id = k.subscribe_events(call, p.topics)?;
                Ok(json!({ "subscriptionId": id }))
            },
        );
        self.kernel_method(
            "events.unsubscribe",
            Api,
            |k, call, p: Unsubscribe| async move { k.unsubscribe(&call.caller, p.subscription_id) },
        );

        // Storage
        self.kernel_method(
            "storage.get",
            Api,
            |k, call, p: AsPlugin<StorageKey>| async move {
                let p = p.bind(&call)?;
                k.storage(&p.plugin).get(&p.rest.scope, &p.rest.key)
            },
        );
        self.kernel_method(
            "storage.set",
            Api,
            |k, call, p: AsPlugin<StorageKey>| async move {
                let p = p.bind(&call)?;
                let value = p.rest.value.filter(|v| !v.is_null());
                k.storage(&p.plugin)
                    .set_or_delete(&p.rest.scope, &p.rest.key, value)
            },
        );

        // Secrets
        self.kernel_method("secrets.get", Api, |k, call, p: SecretKey| async move {
            k.secret_get(&call.caller, p.plugin, &p.key)
        });
        self.kernel_method("secrets.set", Api, |k, call, p: SecretKey| async move {
            k.secret_set(&call.caller, p.plugin, &p.key, p.value)
        });
        self.kernel_method("secrets.delete", Api, |k, call, p: SecretKey| async move {
            k.secret_delete(&call.caller, p.plugin, &p.key)
        });

        // Broker: grants, audit and consent (the shell's trusted UI and the Plugins page)
        self.kernel_method(
            "broker.grants",
            Internal,
            |k, _, p: OptionalPlugin| async move { Ok(k.broker().grants(p.plugin.as_deref())) },
        );
        self.kernel_method("broker.revoke", Internal, |k, _, p: Revoke| async move {
            k.broker().revoke(&p.grant_id)
        });
        self.kernel_method("broker.audit", Internal, |k, _, p: Audit| async move {
            k.broker()
                .audit_log(p.plugin.as_deref(), p.limit.unwrap_or(200))
        });
        self.kernel_method("broker.consent", Internal, |k, _, p: Consent| async move {
            k.consent(&p.plugin, matches!(p.decision, ConsentDecision::Allow))
        });
        self.kernel_method("broker.summary", Internal, |k, _, p: Plugin| async move {
            k.broker()
                .summary(&p.plugin)
                .ok_or_else(|| Kernel::not_a_plugin(&p.plugin))
        });
        self.kernel_method(
            "broker.respond",
            Internal,
            |k, call, p: Respond| async move {
                // Only host-rendered UI can grant.
                require_shell(&call, "answers prompts")?;
                k.broker().respond(&p.prompt_id, p.decision)
            },
        );
        self.kernel_method("broker.pending", Internal, |k, _, _: Value| async move {
            Ok(k.pending_permissions())
        });
        self.kernel_method(
            "broker.viewSelection",
            Internal,
            |k, call, p: ViewSelection| async move {
                require_shell(&call, "reports selections")?;
                k.set_view_selection(&p.plugin, &p.view_id, &p.resources)
            },
        );

        // Invocations and resources. Frontend commands run in the shell (or a
        // sandbox), not here: the shell brackets a gesture-invoked one with
        // begin/end so its declared `access` is minted exactly as for backend
        // commands.
        self.kernel_method(
            "broker.beginInvocation",
            Internal,
            |k, call, p: BeginInvocation| async move {
                let id =
                    k.begin_frontend_invocation(&call.caller, &p.command, p.source, p.resources)?;
                Ok(json!({ "invocationId": id }))
            },
        );
        self.kernel_method(
            "broker.endInvocation",
            Internal,
            |k, _, p: EndInvocation| async move {
                k.end_frontend_invocation(&p.invocation_id);
                Ok(())
            },
        );
        // A plugin tab opened on a resource during the plugin's invocation
        // keeps that resource until the tab closes. Nothing is persisted: a
        // tab restored with the session gets its resource back only when a
        // gesture reopens it.
        self.kernel_method(
            "broker.openResource",
            Internal,
            |k, call, p: OpenResourceParams| async move {
                require_shell(&call, "opens resources in tabs")?;
                let grant_id = k.broker().open_resource(&p.plugin, &p.uri, p.access)?;
                Ok(OpenResourceResult { grant_id })
            },
        );
        self.kernel_method(
            "broker.closeResource",
            Internal,
            |k, call, p: CloseResourceParams| async move {
                require_shell(&call, "closes resources")?;
                k.broker().close_resource(&p.grant_id);
                Ok(())
            },
        );
    }
}
