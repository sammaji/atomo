//! Methods of the public plugin API: commands, settings, context keys, events
//! and storage. Each acts for the calling plugin only.

use std::sync::atomic::Ordering;

use serde::Deserialize;
use serde_json::{json, Value};
use tokio_util::sync::CancellationToken;

use super::AsPlugin;
use crate::broker::Principal;
use crate::call::Caller;
use crate::kernel::SubscriptionEntry;
use crate::{EventMessage, ExecuteParams, Invocation, InvocationSource, Kernel, KernelError};

#[derive(Deserialize)]
struct ContextSet {
    key: String,
    value: Value,
}

#[derive(Deserialize)]
struct Publish {
    topic: String,
    #[serde(default)]
    payload: Value,
}

#[derive(Deserialize)]
struct StorageKey {
    #[serde(default)]
    scope: String,
    key: String,
    #[serde(default)]
    value: Option<Value>,
}

#[derive(Deserialize)]
struct Subscribe {
    #[serde(default)]
    topics: Vec<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Unsubscribe {
    subscription_id: u32,
}

pub(super) fn register(k: &Kernel) {
    k.kernel_api("commands.execute", |k, call, p: ExecuteParams| async move {
        let (caller, source, trusted) = match (&call.caller, &p.caller_plugin) {
            // The bridge's identity wins over anything the plugin claims.
            (Caller::Plugin(plugin), _) | (Caller::Shell, Some(plugin)) => {
                (plugin.clone(), InvocationSource::Plugin, false)
            }
            (Caller::Shell, None) => ("user".to_owned(), p.source, p.source.is_gesture()),
        };
        // No amplification: a plugin passes along only resources it already
        // holds grants for.
        let principal = Principal::parse(&caller);
        if !principal.has_user_authority() {
            if let Some(r) = p
                .resources
                .iter()
                .find(|r| !k.0.broker.holds(&principal, r))
            {
                return Err(KernelError::forbidden(format!(
                    "{caller} holds no grant for {r} and cannot pass it on"
                )));
            }
        }
        let invocation = Invocation {
            source,
            trusted_gesture: trusted,
            caller,
            window: p.window,
            resources: p.resources,
        };
        k.execute_command(&p.id, p.args, invocation).await
    });

    k.kernel_api("settings.getAll", |k, call, _: Value| async move {
        let mut all = k.settings();
        // Plugins read their own settings only; the shell reads all.
        if let Some(id) = call.caller.plugin() {
            let manifest = k.0.registry.load().manifests.get(id).cloned();
            all.retain(|key, _| manifest.as_ref().is_some_and(|m| m.owns_name(key)));
        }
        Ok(all)
    });

    k.kernel_api("context.get", |k, call, _: Value| async move {
        let mut ctx = k.context();
        // Other plugins' private keys (`plugin.<id>.*`) are not a plugin's business.
        if let Some(id) = call.caller.plugin() {
            let own = format!("plugin.{id}");
            ctx.retain(|key, _| {
                !key.starts_with("plugin.") || atomo_manifest::has_prefix(key, &own)
            });
        }
        Ok(ctx)
    });
    k.kernel_api(
        "context.set",
        |k, call, p: AsPlugin<ContextSet>| async move {
            let p = p.bind(&call)?;
            let prefix = format!("plugin.{}", p.plugin);
            if !atomo_manifest::has_prefix(&p.rest.key, &prefix) {
                return Err(KernelError::forbidden(format!(
                    "plugins set only `{prefix}.*` keys"
                )));
            }
            k.set_context(p.rest.key, p.rest.value);
            Ok(())
        },
    );

    k.kernel_api(
        "events.publish",
        |k, call, p: AsPlugin<Publish>| async move {
            let p = p.bind(&call)?;
            k.publish(&p.plugin, &p.rest.topic, p.rest.payload)
        },
    );
    k.kernel_api("events.subscribe", |k, call, p: Subscribe| async move {
        let sink = call
            .sink
            .ok_or_else(|| KernelError::invalid_params("events.subscribe needs a channel"))?;
        let id = k.0.next_subscription.fetch_add(1, Ordering::Relaxed);
        let cancel = CancellationToken::new();
        k.0.subscriptions.lock().insert(
            id,
            SubscriptionEntry {
                owner: call.caller.plugin().map(str::to_owned),
                cancel: cancel.clone(),
            },
        );
        let mut sub = k.0.events.subscribe(p.topics);
        // What a plugin receives is filtered by its grants.
        let filter = match &call.caller {
            Caller::Plugin(id) => Some((k.0.broker.clone(), Principal::Plugin(id.clone()))),
            _ => None,
        };
        k.0.runtime.spawn(async move {
            loop {
                tokio::select! {
                    msg = sub.recv() => match msg {
                        Some(EventMessage::Event { event }) => {
                            let event = match &filter {
                                Some((broker, who)) => broker.filter_event(who, &event),
                                None => Some(event),
                            };
                            if let Some(event) = event {
                                sink(serde_json::to_value(EventMessage::Event { event }).expect("events serialize"));
                            }
                        }
                        Some(msg) => sink(serde_json::to_value(msg).expect("events serialize")),
                        None => break,
                    },
                    _ = cancel.cancelled() => break,
                }
            }
        });
        Ok(json!({ "subscriptionId": id }))
    });
    k.kernel_api("events.unsubscribe", |k, call, p: Unsubscribe| async move {
        let mut subs = k.0.subscriptions.lock();
        // A plugin may only cancel its own streams; the shell may cancel any.
        let allowed = match (subs.get(&p.subscription_id), call.caller.plugin()) {
            (Some(entry), Some(caller)) => entry.owner.as_deref() == Some(caller),
            (Some(_), None) => true,
            (None, _) => return Ok(()),
        };
        if !allowed {
            return Err(KernelError::forbidden("not your subscription"));
        }
        if let Some(entry) = subs.remove(&p.subscription_id) {
            entry.cancel.cancel();
        }
        Ok(())
    });

    k.kernel_api(
        "storage.get",
        |k, call, p: AsPlugin<StorageKey>| async move {
            let p = p.bind(&call)?;
            k.storage(&p.plugin).get(&p.rest.scope, &p.rest.key)
        },
    );
    k.kernel_api(
        "storage.set",
        |k, call, p: AsPlugin<StorageKey>| async move {
            let p = p.bind(&call)?;
            let storage = k.storage(&p.plugin);
            match p.rest.value.filter(|v| !v.is_null()) {
                Some(v) => storage.set(&p.rest.scope, &p.rest.key, &v),
                None => storage.delete(&p.rest.scope, &p.rest.key),
            }
        },
    );
}
