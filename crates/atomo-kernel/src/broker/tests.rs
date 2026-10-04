//! The broker through a real kernel: a fake core plugin defines `t.read` /
//! `t.write` over `/`-paths (as `atomo.vfs` does for `file://`), and
//! third-party plugins run through a fake runtime host (as WASM plugins do).

use std::sync::Arc;
use std::time::Duration;

use serde_json::{json, Value};

use super::rights::KernelRights;
use super::*;
use crate::events::Event;
use crate::{
    ActivationContext, CallContext, Caller, EventMessage, Invocation, InvocationSource, Kernel,
    KernelConfig, NativePlugin, PluginState, RuntimeHost,
};

/// `/`-paths; trees by prefix; `**` patterns; `.ssh` is sensitive.
struct FakeFs;

fn under(path: &str, root: &str) -> bool {
    path == root || path.starts_with(&format!("{}/", root.trim_end_matches('/')))
}

impl RightChecker for FakeFs {
    fn rights(&self) -> Vec<&'static str> {
        vec!["t.read", "t.write"]
    }
    fn canonicalize(&self, _: &str, r: &str) -> Result<String, String> {
        if r.starts_with('/') && !r.contains("..") {
            Ok(r.trim_end_matches('/').to_owned())
        } else {
            Err(format!("{r} is not a canonical path"))
        }
    }
    fn covers(&self, _: &str, scope: &Scope, r: &str) -> bool {
        match scope {
            Scope::Any => true,
            Scope::Exact(x) => x == r,
            Scope::Tree(x) => under(r, x),
            Scope::Pattern(p) => match p.strip_suffix("/**") {
                // Globs never match hidden files implicitly.
                Some(base) => under(r, base) && !r[base.len()..].contains("/."),
                None => under(r, p),
            },
        }
    }
    fn sensitive(&self, _: &str, r: &str) -> Option<String> {
        r.contains("/.ssh").then(|| "credentials".into())
    }
    fn destructive(&self, right: &str) -> bool {
        right == "t.write"
    }
    fn remember_scope(&self, _: &str, r: &str) -> Scope {
        Scope::Tree(r.to_owned())
    }
    fn intent(&self, access: &str, r: &str) -> Vec<(&'static str, Scope)> {
        match access {
            "selection:read" | "location:read" | "opened:read" => {
                vec![("t.read", Scope::Tree(r.to_owned()))]
            }
            "selection:write" | "location:write" | "opened:write" => vec![
                ("t.read", Scope::Tree(r.to_owned())),
                ("t.write", Scope::Tree(r.to_owned())),
            ],
            _ => vec![],
        }
    }
    fn filter_event(&self, b: &Broker, who: &Principal, e: &Event) -> Option<Option<Value>> {
        if e.topic != "t.changed" {
            return None;
        }
        let paths: Vec<Value> = e.payload["paths"]
            .as_array()?
            .iter()
            .filter(|p| {
                p.as_str()
                    .is_some_and(|p| b.check(who, "t.read", p) == Decision::Allow)
            })
            .cloned()
            .collect();
        Some((!paths.is_empty()).then(|| json!({ "paths": paths })))
    }
}

struct Rights;

impl NativePlugin for Rights {
    fn manifest(&self) -> &'static str {
        r#"{ "manifestVersion": 1, "id": "t.rights", "version": "1.0.0", "displayName": "Rights",
             "description": "", "engines": { "atomo": "^0.1.0" }, "backend": { "runtime": "native" } }"#
    }
    fn activate(&self, ctx: &mut ActivationContext<'_>) -> KernelResult<()> {
        ctx.define_rights(Arc::new(FakeFs))
    }
}

/// Runs third-party "wasm" plugins: each command reports what its plugin's
/// principal may read, then (for `.probe`) the results.
struct Host;

impl RuntimeHost for Host {
    fn runtime(&self) -> atomo_manifest::BackendRuntime {
        atomo_manifest::BackendRuntime::Wasm
    }
    fn activate(
        &self,
        manifest: &Manifest,
        _dir: Option<&std::path::Path>,
        ctx: &mut ActivationContext<'_>,
    ) -> KernelResult<()> {
        let me = Principal::Plugin(manifest.id.clone());
        for c in manifest.commands() {
            let (k, me) = (ctx.kernel(), me.clone());
            ctx.command(&c.id, move |inv: Invocation, args: Value| {
                let (k, me) = (k.clone(), me.clone());
                async move {
                    // `forward`: call another plugin's command with resources.
                    if let Some(target) = args.get("forward").and_then(Value::as_str) {
                        let call = CallContext {
                            sink: None,
                            caller: Caller::Plugin(me.to_string()),
                        };
                        let params = json!({ "id": target, "source": "plugin", "resources": inv.resources, "args": { "probe": args["probe"] } });
                        return k.call(call, "commands.execute", params).await;
                    }
                    let probes: Vec<String> = args["probe"]
                        .as_array()
                        .map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_owned)).collect())
                        .unwrap_or_default();
                    let out: Vec<bool> = probes
                        .iter()
                        .map(|p| k.broker().check(&me, "t.read", p) == Decision::Allow)
                        .collect();
                    Ok(json!(out))
                }
            })?;
        }
        Ok(())
    }
}

fn plugin(id: &str, extra: Value) -> &'static str {
    let mut m = json!({
        "manifestVersion": 1, "id": id, "version": "1.0.0", "displayName": id,
        "description": "", "engines": { "atomo": "^0.1.0" }, "backend": { "runtime": "wasm" }
    });
    m.as_object_mut()
        .unwrap()
        .extend(extra.as_object().unwrap().clone());
    Box::leak(m.to_string().into_boxed_str())
}

fn viewer() -> &'static str {
    plugin(
        "acme.viewer",
        json!({ "contributes": { "commands": [
            { "id": "acme.viewer.read", "title": "Read", "access": ["selection:read"] },
            { "id": "acme.viewer.forward", "title": "Forward", "access": ["selection:read"] }
        ]}}),
    )
}

fn spy() -> &'static str {
    plugin(
        "acme.spy",
        json!({ "contributes": { "commands": [
            { "id": "acme.spy.read", "title": "Read", "access": ["selection:write"] }
        ]}}),
    )
}

fn kernel_with(dir: Option<&std::path::Path>, manifests: &[&'static str]) -> Kernel {
    let mut b = Kernel::builder(tokio::runtime::Handle::current())
        .config(KernelConfig {
            data_dir: dir.map(|d| d.to_owned()),
            ..Default::default()
        })
        .secret_store(Arc::new(MemorySecrets::default()))
        .runtime_host(Arc::new(Host))
        .native(Rights);
    for m in manifests {
        b = b.manifest(m, Tier::Dev);
    }
    b.start().unwrap()
}

fn gesture(resources: &[&str]) -> Invocation {
    Invocation {
        source: InvocationSource::Menu,
        trusted_gesture: true,
        caller: "user".into(),
        window: None,
        resources: resources.iter().map(|s| s.to_string()).collect(),
    }
}

fn acme(id: &str) -> Principal {
    Principal::Plugin(id.into())
}

#[tokio::test]
async fn selection_scoped_action_reads_exactly_the_selection() {
    let k = kernel_with(None, &[viewer()]);
    let probe =
        json!({ "probe": ["/home/a/x.txt", "/home/a", "/home/b/y.txt", "/home/a/sub/z", "/home"] });
    let out = k
        .execute_command("acme.viewer.read", probe.clone(), gesture(&["/home/a"]))
        .await
        .unwrap();
    // The selected folder (recursively), nothing else.
    assert_eq!(out, json!([true, true, false, true, false]));
    // The grant ended with the handler.
    assert!(k.broker().grants(Some("acme.viewer")).is_empty());
    assert!(matches!(
        k.broker()
            .check(&acme("acme.viewer"), "t.read", "/home/a/x.txt"),
        Decision::Deny(_)
    ));
    // The audit log recorded the mint and the decisions.
    let log = k.broker().audit_log(Some("acme.viewer"), 50).unwrap();
    assert!(log
        .iter()
        .any(|e| e.decision == "grant" && e.source.as_deref() == Some("selection:read via menu")));
    assert!(log
        .iter()
        .any(|e| e.decision == "deny" && e.resource == "/home/b/y.txt"));
}

#[tokio::test]
async fn non_gesture_invocations_never_mint() {
    let k = kernel_with(None, &[viewer()]);
    let probe = json!({ "probe": ["/home/a/x"] });
    for (caller, source, trusted) in [
        ("acme.other", InvocationSource::Plugin, false),
        ("user", InvocationSource::Plugin, false),
        ("user", InvocationSource::Menu, false),
    ] {
        let inv = Invocation {
            source,
            trusted_gesture: trusted,
            caller: caller.into(),
            ..gesture(&["/home/a"])
        };
        let out = k
            .execute_command("acme.viewer.read", probe.clone(), inv)
            .await
            .unwrap();
        assert_eq!(out, json!([false]), "{caller} {source:?}");
    }
    // Through the protocol: a plugin is never a gesture.
    let plugin = CallContext {
        sink: None,
        caller: Caller::Plugin("acme.other".into()),
    };
    let out = k
        .call(
            plugin,
            "commands.execute",
            json!({ "id": "acme.viewer.read", "source": "menu", "resources": ["/home/a"], "args": probe }),
        )
        .await
        .unwrap();
    assert_eq!(out, json!([false]));
    // The shell's menu gesture does mint.
    let out = k
        .call(
            CallContext::default(),
            "commands.execute",
            json!({ "id": "acme.viewer.read", "source": "menu", "resources": ["/home/a"], "args": probe }),
        )
        .await
        .unwrap();
    assert_eq!(out, json!([true]));
}

#[tokio::test]
async fn no_amplification_through_commands() {
    let k = kernel_with(None, &[viewer(), spy()]);
    let shell = CallContext::default();
    // acme.viewer holds /home/a (its own invocation) and forwards it to
    // acme.spy: spy gets read on /home/a only, though it declares write.
    let out = k
        .call(
            shell.clone(),
            "commands.execute",
            json!({ "id": "acme.viewer.forward", "source": "menu", "resources": ["/home/a"],
                    "args": { "forward": "acme.spy.read", "probe": ["/home/a/f", "/home/b"] } }),
        )
        .await
        .unwrap();
    assert_eq!(out, json!([true, false]));
    // Without its own grant, acme.viewer cannot pass /etc on.
    let plugin = CallContext {
        sink: None,
        caller: Caller::Plugin("acme.viewer".into()),
    };
    let err = k
        .call(
            plugin,
            "commands.execute",
            json!({ "id": "acme.spy.read", "source": "menu", "resources": ["/etc"] }),
        )
        .await
        .unwrap_err();
    assert_eq!(err.code, "forbidden");
    // Delegated grants never include write, and none outlive the call.
    assert!(k.broker().grants(Some("acme.spy")).is_empty());
}

#[tokio::test]
async fn sensitive_paths_beat_broad_grants_and_globs_skip_hidden_files() {
    let k = kernel_with(None, &[]);
    let b = k.broker();
    let who = acme("acme.sync");
    b.grant_standing(&who, "t.read", Scope::Tree("/home".into()), "user", false)
        .unwrap();
    assert_eq!(b.check(&who, "t.read", "/home/me/doc"), Decision::Allow);
    assert!(matches!(
        b.check(&who, "t.read", "/home/me/.ssh/id_rsa"),
        Decision::Deny(why) if why.contains("protected")
    ));
    // Only an explicit per-path grant overrides the denylist.
    b.grant_standing(
        &who,
        "t.read",
        Scope::Exact("/home/me/.ssh/config".into()),
        "user",
        true,
    )
    .unwrap();
    assert_eq!(
        b.check(&who, "t.read", "/home/me/.ssh/config"),
        Decision::Allow
    );
    assert!(matches!(
        b.check(&who, "t.read", "/home/me/.ssh/id_rsa"),
        Decision::Deny(_)
    ));

    let globber = acme("acme.glob");
    b.grant_standing(
        &globber,
        "t.read",
        Scope::Pattern("/w/**".into()),
        "manifest",
        false,
    )
    .unwrap();
    assert_eq!(b.check(&globber, "t.read", "/w/a/b"), Decision::Allow);
    assert!(matches!(
        b.check(&globber, "t.read", "/w/.git/config"),
        Decision::Deny(_)
    ));
    // Unknown rights and non-canonical resources are refused.
    assert!(matches!(
        b.check(&who, "t.nope", "/home"),
        Decision::Deny(_)
    ));
    assert!(matches!(
        b.check(&who, "t.read", "/home/../etc"),
        Decision::Deny(_)
    ));
    // The user and core plugins are not confined.
    assert_eq!(
        b.check(&Principal::User, "t.read", "/home/me/.ssh/id_rsa"),
        Decision::Allow
    );
    assert_eq!(b.check(&acme("t.rights"), "t.read", "/x"), Decision::Allow);
}

#[tokio::test]
async fn prompts_once_always_deny_and_timeout() {
    let k = kernel_with(
        None,
        &[plugin(
            "acme.asker",
            json!({ "permissions": { "optional": [{ "id": "t.read", "paths": ["/data"], "reason": "to index" }] } }),
        )],
    );
    let b = k.broker().clone();
    let who = acme("acme.asker");
    assert_eq!(b.check(&who, "t.read", "/data/x"), Decision::Prompt);
    assert!(matches!(
        b.check(&who, "t.read", "/other"),
        Decision::Deny(_)
    ));

    let mut events = k.events().subscribe(vec!["broker.promptRequested".into()]);

    // Once: allowed now, as a timed grant.
    let task = {
        let (b, who) = (b.clone(), who.clone());
        tokio::spawn(async move { b.authorize(&who, "t.read", &["/data/x".into()]).await })
    };
    let req = next_prompt(&mut events).await;
    assert_eq!(
        (req.plugin.as_str(), req.reason.as_deref()),
        ("acme.asker", Some("to index"))
    );
    assert_eq!(b.pending_prompts().len(), 1);
    // Plugins cannot answer.
    let plugin = CallContext {
        sink: None,
        caller: Caller::Plugin("acme.asker".into()),
    };
    assert_eq!(
        k.call(
            plugin,
            "broker.respond",
            json!({ "promptId": req.prompt_id, "decision": "always" })
        )
        .await
        .unwrap_err()
        .code,
        "forbidden"
    );
    k.call(
        CallContext::default(),
        "broker.respond",
        json!({ "promptId": req.prompt_id, "decision": "once" }),
    )
    .await
    .unwrap();
    assert_eq!(task.await.unwrap().unwrap(), ["/data/x"]);
    assert_eq!(b.check(&who, "t.read", "/data/x"), Decision::Allow);
    assert_eq!(b.check(&who, "t.read", "/data/y"), Decision::Prompt);

    // Always: a standing grant on the tree.
    let task = {
        let (b, who) = (b.clone(), who.clone());
        tokio::spawn(async move { b.authorize(&who, "t.read", &["/data/y".into()]).await })
    };
    let req = next_prompt(&mut events).await;
    b.respond(&req.prompt_id, PromptDecision::Always).unwrap();
    task.await.unwrap().unwrap();
    assert!(b
        .grants(Some("acme.asker"))
        .iter()
        .any(|g| g.kind == GrantKind::Standing && g.scope == Scope::Tree("/data/y".into())));

    // Deny.
    let task = {
        let (b, who) = (b.clone(), who.clone());
        tokio::spawn(async move { b.authorize(&who, "t.read", &["/data/z".into()]).await })
    };
    let req = next_prompt(&mut events).await;
    b.respond(&req.prompt_id, PromptDecision::Deny).unwrap();
    assert_eq!(task.await.unwrap().unwrap_err().code, "forbidden");

    // No answer: deny.
    b.set_prompt_timeout(Duration::from_millis(50));
    let err = b
        .authorize(&who, "t.read", &["/data/w".into()])
        .await
        .unwrap_err();
    assert!(err.message.contains("no answer"));
    let log = b.audit_log(Some("acme.asker"), 100).unwrap();
    for word in ["allowOnce", "allowAlways", "denied", "timeout"] {
        assert!(log.iter().any(|e| e.decision == word), "{word} missing");
    }
}

async fn next_prompt(sub: &mut crate::Subscription) -> PromptRequest {
    loop {
        let msg = tokio::time::timeout(Duration::from_secs(5), sub.recv())
            .await
            .expect("a prompt")
            .unwrap();
        if let EventMessage::Event { event } = msg {
            let v = event.payload;
            return PromptRequest {
                prompt_id: v["promptId"].as_str().unwrap().into(),
                plugin: v["plugin"].as_str().unwrap().into(),
                display_name: v["displayName"].as_str().unwrap_or_default().into(),
                tier: None,
                right: v["right"].as_str().unwrap().into(),
                resources: vec![],
                text: v["text"].as_str().unwrap_or_default().into(),
                reason: v["reason"].as_str().map(str::to_owned),
                sensitive: v["sensitive"].as_bool().unwrap_or(false),
                created_ms: 0.0,
            };
        }
    }
}

#[tokio::test]
async fn retained_grants_outlive_the_invocation_until_the_job_ends() {
    let k = kernel_with(None, &[]);
    let b = k.broker();
    let who = acme("acme.viewer");
    let lease = b.mint(
        "acme.viewer",
        &["selection:write".into()],
        &["/home/a".into()],
        Binding::Invocation("x#1".into()),
        "menu",
    );
    let job = b
        .retain(
            &who,
            &["t.write"],
            &["/home/a/f".into()],
            Binding::Job("j1".into()),
        )
        .unwrap();
    assert!(b
        .retain(
            &who,
            &["t.write"],
            &["/elsewhere".into()],
            Binding::Job("j1".into())
        )
        .is_err());
    drop(lease);
    // The job keeps the scope it was started with, and nothing wider.
    assert_eq!(b.check(&who, "t.write", "/home/a/f"), Decision::Allow);
    assert!(matches!(
        b.check(&who, "t.read", "/home/a/f"),
        Decision::Deny(_)
    ));
    drop(job);
    assert!(matches!(
        b.check(&who, "t.write", "/home/a/f"),
        Decision::Deny(_)
    ));
    // Release by binding (a view's selection).
    b.set_view_selection("acme.viewer", "v", &["/p".into()])
        .detach();
    assert_eq!(b.check(&who, "t.read", "/p/q"), Decision::Allow);
    b.release(&Binding::View("acme.viewer/v".into()));
    assert!(matches!(b.check(&who, "t.read", "/p/q"), Decision::Deny(_)));
}

#[tokio::test]
async fn revoke_and_protocol_methods() {
    let k = kernel_with(None, &[]);
    let who = acme("acme.x");
    let id = k
        .broker()
        .grant_standing(&who, "t.read", Scope::Tree("/a".into()), "user", false)
        .unwrap();
    let shell = CallContext::default;
    let grants = k
        .call(shell(), "broker.grants", json!({ "plugin": "acme.x" }))
        .await
        .unwrap();
    assert_eq!(grants[0]["scope"], json!({ "kind": "tree", "value": "/a" }));
    k.call(shell(), "broker.revoke", json!({ "grantId": id }))
        .await
        .unwrap();
    assert!(matches!(
        k.broker().check(&who, "t.read", "/a"),
        Decision::Deny(_)
    ));
    let audit = k
        .call(
            shell(),
            "broker.audit",
            json!({ "plugin": "acme.x", "limit": 10 }),
        )
        .await
        .unwrap();
    assert_eq!(audit[0]["decision"], "deny");
    assert!(audit
        .as_array()
        .unwrap()
        .iter()
        .any(|e| e["decision"] == "revoke"));
    // Plugins never reach the broker's protocol.
    let plugin = CallContext {
        sink: None,
        caller: Caller::Plugin("acme.x".into()),
    };
    assert_eq!(
        k.call(plugin, "broker.grants", json!({}))
            .await
            .unwrap_err()
            .code,
        "forbidden"
    );
}

#[tokio::test]
async fn permission_escalation_holds_the_plugin_until_consent() {
    let dir = tempfile::tempdir().unwrap();
    let v1 = plugin(
        "acme.sync",
        json!({
            "permissions": { "required": [{ "id": "t.read", "paths": ["/data"], "reason": "sync" }] },
            "contributes": { "commands": [{ "id": "acme.sync.go", "title": "Go" }] }
        }),
    );
    {
        let k = kernel_with(Some(dir.path()), &[v1]);
        let info = k.registry().plugin("acme.sync").cloned().unwrap();
        assert!(info.needs_consent && info.state == PluginState::Disabled);
        let pending = k
            .call(CallContext::default(), "broker.pending", json!({}))
            .await
            .unwrap();
        assert_eq!(pending["consents"][0]["plugin"], "acme.sync");
        assert_eq!(
            pending["consents"][0]["lines"][0]["text"],
            "Uses the `t.read` permission"
        );
        k.call(
            CallContext::default(),
            "broker.consent",
            json!({ "plugin": "acme.sync", "decision": "allow" }),
        )
        .await
        .unwrap();
        assert_eq!(k.plugin_state("acme.sync"), Some(PluginState::Active));
        assert_eq!(
            k.broker().check(&acme("acme.sync"), "t.read", "/data/f"),
            Decision::Allow
        );
    }
    // Restart with the same manifest: still consented.
    {
        let k = kernel_with(Some(dir.path()), &[v1]);
        assert_eq!(k.plugin_state("acme.sync"), Some(PluginState::Active));
    }
    // An update that asks for more is held, with the diff.
    let v2 = plugin(
        "acme.sync",
        json!({
            "version": "1.1.0",
            "permissions": { "required": [
                { "id": "t.read", "paths": ["/data"] },
                { "id": "net", "hosts": ["evil.example"] }
            ] },
            "contributes": { "commands": [{ "id": "acme.sync.go", "title": "Go" }] }
        }),
    );
    let k = kernel_with(Some(dir.path()), &[v2]);
    let info = k.registry().plugin("acme.sync").cloned().unwrap();
    assert!(info.needs_consent, "{info:?}");
    assert_ne!(k.plugin_state("acme.sync"), Some(PluginState::Active));
    let err = k
        .execute_command("acme.sync.go", json!({}), gesture(&[]))
        .await
        .unwrap_err();
    assert_eq!(err.code, "not_found", "a held plugin contributes nothing");
    let summary = k.broker().summary("acme.sync").unwrap();
    assert_eq!(summary.added.len(), 1);
    assert_eq!(summary.added[0].text, "Connects to evil.example");
    // Refusing disables it.
    k.consent("acme.sync", false).unwrap();
    let info = k.registry().plugin("acme.sync").cloned().unwrap();
    assert_eq!(info.state, PluginState::Disabled);
}

#[tokio::test]
async fn secrets_are_namespaced_per_plugin() {
    let k = kernel_with(
        None,
        &[
            plugin(
                "acme.a",
                json!({ "permissions": { "required": [{ "id": "secrets" }] } }),
            ),
            plugin("acme.b", json!({})),
        ],
    );
    k.consent("acme.a", true).unwrap();
    let as_plugin = |id: &str| CallContext {
        sink: None,
        caller: Caller::Plugin(id.into()),
    };
    k.call(
        as_plugin("acme.a"),
        "secrets.set",
        json!({ "key": "token", "value": "s3cret", "plugin": "acme.b" }),
    )
    .await
    .unwrap();
    // The bridge identity wins over the claimed plugin: it went to acme.a.
    assert_eq!(
        k.call(
            as_plugin("acme.a"),
            "secrets.get",
            json!({ "key": "token" })
        )
        .await
        .unwrap(),
        json!("s3cret")
    );
    // acme.b holds no `secrets` grant, and could not see acme.a's anyway.
    assert_eq!(
        k.call(
            as_plugin("acme.b"),
            "secrets.get",
            json!({ "key": "token" })
        )
        .await
        .unwrap_err()
        .code,
        "forbidden"
    );
    k.broker()
        .grant_standing(&acme("acme.b"), "secrets", Scope::Any, "user", false)
        .unwrap();
    assert_eq!(
        k.call(
            as_plugin("acme.b"),
            "secrets.get",
            json!({ "key": "token" })
        )
        .await
        .unwrap(),
        Value::Null
    );
    k.call(
        as_plugin("acme.a"),
        "secrets.delete",
        json!({ "key": "token" }),
    )
    .await
    .unwrap();
    assert_eq!(
        k.call(
            as_plugin("acme.a"),
            "secrets.get",
            json!({ "key": "token" })
        )
        .await
        .unwrap(),
        Value::Null
    );
}

#[tokio::test]
async fn event_delivery_is_filtered_by_grants() {
    let k = kernel_with(
        None,
        &[
            plugin("acme.watch", json!({})),
            plugin("t.emitter", json!({})),
        ],
    );
    k.broker()
        .grant_standing(
            &acme("acme.watch"),
            "t.read",
            Scope::Tree("/mine".into()),
            "user",
            false,
        )
        .unwrap();
    let got = Arc::new(parking_lot::Mutex::new(Vec::<Value>::new()));
    let sink = {
        let got = got.clone();
        Arc::new(move |v: Value| got.lock().push(v))
    };
    k.call(
        CallContext {
            sink: Some(sink),
            caller: Caller::Plugin("acme.watch".into()),
        },
        "events.subscribe",
        json!({ "topics": [""] }),
    )
    .await
    .unwrap();
    tokio::time::sleep(Duration::from_millis(20)).await;
    k.events().emit(
        "t.rights",
        "t.changed",
        json!({ "paths": ["/mine/a", "/theirs/b"] }),
    );
    k.events()
        .emit("t.rights", "t.changed", json!({ "paths": ["/theirs/c"] }));
    k.events().emit(
        "kernel",
        "broker.promptRequested",
        json!({ "plugin": "other" }),
    );
    k.events()
        .emit("kernel", "settings.changed", json!({ "key": "k" }));
    tokio::time::sleep(Duration::from_millis(100)).await;
    let got = got.lock().clone();
    let topics: Vec<&str> = got
        .iter()
        .filter_map(|m| m["event"]["topic"].as_str())
        .collect();
    assert_eq!(topics, ["t.changed", "settings.changed"], "{got:?}");
    assert_eq!(got[0]["event"]["payload"], json!({ "paths": ["/mine/a"] }));
}

#[tokio::test]
async fn only_core_plugins_define_rights_and_rights_are_unique() {
    struct Again;
    impl NativePlugin for Again {
        fn manifest(&self) -> &'static str {
            r#"{ "manifestVersion": 1, "id": "t.again", "version": "1.0.0", "displayName": "Again",
                 "description": "", "engines": { "atomo": "^0.1.0" }, "backend": { "runtime": "native" } }"#
        }
        fn activate(&self, ctx: &mut ActivationContext<'_>) -> KernelResult<()> {
            ctx.define_rights(Arc::new(FakeFs))
        }
    }
    let k = Kernel::builder(tokio::runtime::Handle::current())
        .native(Rights)
        .native(Again)
        .start()
        .unwrap();
    assert!(k.broker().rights().contains(&"t.read".to_owned()));
    let states = [k.plugin_state("t.rights"), k.plugin_state("t.again")];
    assert!(
        states.contains(&Some(PluginState::Active)) && states.contains(&Some(PluginState::Failed))
    );
    // Deactivating the definer removes its rights.
    let definer = if states[0] == Some(PluginState::Active) {
        "t.rights"
    } else {
        "t.again"
    };
    k.deactivate(definer);
    assert!(!k.broker().rights().contains(&"t.read".to_owned()));
}

#[test]
fn principals_and_atoms() {
    for s in ["user", "acme.x"] {
        assert_eq!(Principal::parse(s).to_string(), s);
    }
    assert_eq!(Principal::parse("plugin:acme.x"), acme("acme.x"));
    let m = Manifest::parse(plugin(
        "acme.z",
        json!({ "dependencies": { "acme.y": "^1" }, "permissions": { "required": [
            { "id": "net", "hosts": ["a.example", "b.example"] }, { "id": "secrets" }
        ] } }),
    ))
    .unwrap();
    assert_eq!(
        consent_atoms(&m),
        [
            "dependency acme.y",
            "net a.example",
            "net b.example",
            "secrets"
        ]
    );
}

#[test]
fn net_patterns() {
    let k = KernelRights;
    let c = |p: &str, r: &str| {
        let r = k.canonicalize("net", r).unwrap();
        k.covers("net", &Scope::Pattern(p.into()), &r)
    };
    assert!(c("api.example.com", "https://API.example.com/v1"));
    assert!(c("*.example.com", "a.b.example.com:443"));
    assert!(!c("*.example.com", "example.com.evil.net"));
    assert!(!c("*.example.com", "badexample.com"));
}

#[tokio::test]
async fn frontend_commands_get_their_grants_from_the_shell_bracket() {
    let k = kernel_with(
        None,
        &[Box::leak(
            json!({
                "manifestVersion": 1, "id": "acme.front", "version": "1.0.0", "displayName": "Front",
                "description": "", "engines": { "atomo": "^0.1.0" }, "frontend": { "runtime": "sandbox" },
                "contributes": { "commands": [{ "id": "acme.front.go", "title": "Go", "access": ["selection:read"] }] }
            })
            .to_string()
            .into_boxed_str(),
        )],
    );
    let who = acme("acme.front");
    let begin = json!({ "command": "acme.front.go", "source": "menu", "resources": ["/sel"] });
    let r = k
        .call(
            CallContext::default(),
            "broker.beginInvocation",
            begin.clone(),
        )
        .await
        .unwrap();
    assert_eq!(k.broker().check(&who, "t.read", "/sel/a"), Decision::Allow);
    k.call(
        CallContext::default(),
        "broker.endInvocation",
        json!({ "invocationId": r["invocationId"] }),
    )
    .await
    .unwrap();
    assert!(matches!(
        k.broker().check(&who, "t.read", "/sel/a"),
        Decision::Deny(_)
    ));
    // Not a gesture, or not the shell: nothing.
    let plugin = CallContext {
        sink: None,
        caller: Caller::Plugin("acme.front".into()),
    };
    assert_eq!(
        k.call(plugin, "broker.beginInvocation", begin)
            .await
            .unwrap_err()
            .code,
        "forbidden"
    );
    let from_plugin = json!({ "command": "acme.front.go", "source": "plugin", "resources": ["/sel"] });
    assert_eq!(
        k.call(CallContext::default(), "broker.beginInvocation", from_plugin)
            .await
            .unwrap_err()
            .code,
        "forbidden"
    );
}

fn front(id: &str, access: &[&str]) -> &'static str {
    Box::leak(
        json!({
            "manifestVersion": 1, "id": id, "version": "1.0.0", "displayName": id,
            "description": "", "engines": { "atomo": "^0.1.0" }, "frontend": { "runtime": "sandbox" },
            "contributes": { "commands": [{ "id": format!("{id}.go"), "title": "Go", "access": access }] }
        })
        .to_string()
        .into_boxed_str(),
    )
}

async fn shell_call(k: &Kernel, method: &str, params: Value) -> KernelResult<Value> {
    k.call(CallContext::default(), method, params).await
}

#[tokio::test]
async fn location_commands_get_exactly_the_pane_location() {
    let k = kernel_with(
        None,
        &[plugin(
            "acme.here",
            json!({ "contributes": { "commands": [
                { "id": "acme.here.scan", "title": "Scan", "access": ["location:read"] }
            ]}}),
        )],
    );
    let probe = json!({ "probe": ["/home/a", "/home/a/sub/deep/z", "/home/b", "/home"] });
    let out = k
        .execute_command("acme.here.scan", probe, gesture(&["/home/a"]))
        .await
        .unwrap();
    assert_eq!(out, json!([true, true, false, false]));
    assert!(k.broker().grants(Some("acme.here")).is_empty());
    let line = summary::describe_access("location:read");
    assert_eq!(line.text, "Reads the folder you are in");
}

#[tokio::test]
async fn opened_resources_outlive_the_invocation_until_closed() {
    let k = kernel_with(
        None,
        &[
            front("acme.reader", &["location:read"]),
            front("acme.editor", &["selection:write"]),
        ],
    );
    let reader = acme("acme.reader");
    let begin = |cmd: &str| json!({ "command": cmd, "source": "menu", "resources": ["/docs"] });
    let inv = shell_call(&k, "broker.beginInvocation", begin("acme.reader.go"))
        .await
        .unwrap();
    let open = |plugin: &str, uri: &str, access: &str| json!({ "plugin": plugin, "uri": uri, "access": access });

    // Write access needs a declared write intent.
    let err = shell_call(
        &k,
        "broker.openResource",
        open("acme.reader", "/docs", "write"),
    )
    .await
    .unwrap_err();
    assert_eq!(err.code, "forbidden");
    // Only the resource the invocation named, not one inside or beside it.
    for uri in ["/docs/a.md", "/elsewhere"] {
        let err = shell_call(&k, "broker.openResource", open("acme.reader", uri, "read"))
            .await
            .unwrap_err();
        assert_eq!(err.code, "forbidden", "{uri}");
    }
    // A plugin without an invocation gets nothing.
    let err = shell_call(
        &k,
        "broker.openResource",
        open("acme.editor", "/docs", "read"),
    )
    .await
    .unwrap_err();
    assert_eq!(err.code, "forbidden");
    // Only the shell opens resources.
    let plugin_call = CallContext {
        sink: None,
        caller: Caller::Plugin("acme.reader".into()),
    };
    let err = k
        .call(
            plugin_call,
            "broker.openResource",
            open("acme.reader", "/docs", "read"),
        )
        .await
        .unwrap_err();
    assert_eq!(err.code, "forbidden");

    let opened = shell_call(
        &k,
        "broker.openResource",
        open("acme.reader", "/docs", "read"),
    )
    .await
    .unwrap();
    let grant_id = opened["grantId"].as_str().unwrap().to_owned();
    shell_call(
        &k,
        "broker.endInvocation",
        json!({ "invocationId": inv["invocationId"] }),
    )
    .await
    .unwrap();
    // The tab keeps the resource after the invocation ended…
    assert_eq!(
        k.broker().check(&reader, "t.read", "/docs/a.md"),
        Decision::Allow
    );
    assert!(matches!(
        k.broker().check(&reader, "t.write", "/docs/a.md"),
        Decision::Deny(_)
    ));
    // …and loses it when the tab closes.
    shell_call(&k, "broker.closeResource", json!({ "grantId": grant_id }))
        .await
        .unwrap();
    assert!(matches!(
        k.broker().check(&reader, "t.read", "/docs/a.md"),
        Decision::Deny(_)
    ));
    // Nothing to reopen once the invocation is over.
    let err = shell_call(
        &k,
        "broker.openResource",
        open("acme.reader", "/docs", "read"),
    )
    .await
    .unwrap_err();
    assert_eq!(err.code, "forbidden");

    // A declared write intent lets the tab write.
    let editor = acme("acme.editor");
    shell_call(&k, "broker.beginInvocation", begin("acme.editor.go"))
        .await
        .unwrap();
    shell_call(
        &k,
        "broker.openResource",
        open("acme.editor", "/docs", "write"),
    )
    .await
    .unwrap();
    assert_eq!(
        k.broker().check(&editor, "t.write", "/docs/a.md"),
        Decision::Allow
    );
}

#[tokio::test]
async fn streamed_calls_are_cancelled_by_unsubscribe_or_drop() {
    let k = kernel_with(None, &[]);
    let seen = Arc::new(parking_lot::Mutex::new(Vec::<Value>::new()));
    let sink_seen = seen.clone();
    let call = CallContext {
        sink: Some(Arc::new(move |v| sink_seen.lock().push(v))),
        caller: Caller::Plugin("acme.x".into()),
    };
    let cancel = k.call_cancellation(&call);
    let id = seen.lock()[0]["subscriptionId"].clone();
    assert_eq!(seen.lock()[0]["type"], "started");
    // Another plugin cannot cancel it.
    let other = CallContext {
        sink: None,
        caller: Caller::Plugin("acme.y".into()),
    };
    let unsubscribe = json!({ "subscriptionId": id });
    assert!(k
        .call(other, "events.unsubscribe", unsubscribe.clone())
        .await
        .is_err());
    assert!(!cancel.token().is_cancelled());
    k.call(call.clone(), "events.unsubscribe", unsubscribe)
        .await
        .unwrap();
    assert!(cancel.token().is_cancelled());

    let without_sink = k.call_cancellation(&CallContext::default());
    let token = without_sink.token().clone();
    drop(without_sink);
    assert!(token.is_cancelled());
}

#[test]
fn exec_names_programs_by_name_or_absolute_path() {
    let k = KernelRights;
    assert_eq!(k.canonicalize("exec", "git").unwrap(), "git");
    assert!(k.canonicalize("exec", "/usr/bin/git").is_ok());
    for bad in ["./git", "bin/git", "git status", "..", ""] {
        assert!(k.canonicalize("exec", bad).is_err(), "{bad}");
    }
    let git = Scope::Pattern("git".into());
    assert!(k.covers("exec", &git, "git"));
    assert!(!k.covers("exec", &git, "/tmp/evil/git"));
}
