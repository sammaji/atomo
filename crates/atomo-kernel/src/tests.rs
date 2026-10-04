use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use atomo_manifest::Manifest;
use serde::Deserialize;
use serde_json::{json, Value};

use super::*;

mod settings;

struct Counter(AtomicU32);

/// A test plugin: a manifest plus an activation closure.
struct TestPlugin {
    manifest: &'static str,
    activate: fn(&mut ActivationContext<'_>) -> KernelResult<()>,
}

impl NativePlugin for TestPlugin {
    fn manifest(&self) -> &'static str {
        self.manifest
    }
    fn activate(&self, ctx: &mut ActivationContext<'_>) -> KernelResult<()> {
        (self.activate)(ctx)
    }
}

pub(super) fn leak(v: Value) -> &'static str {
    let mut m = json!({
        "manifestVersion": 1, "version": "1.0.0", "description": "",
        "engines": { "atomo": "^0.1.0" }, "backend": { "runtime": "native" }
    });
    m.as_object_mut()
        .unwrap()
        .extend(v.as_object().unwrap().clone());
    m["displayName"] = m["id"].clone();
    Box::leak(m.to_string().into_boxed_str())
}

fn provider() -> TestPlugin {
    TestPlugin {
        manifest: leak(json!({ "id": "t.provider" })),
        activate: |ctx| {
            ctx.provide(Arc::new(Counter(AtomicU32::new(0))));
            Ok(())
        },
    }
}

fn consumer() -> TestPlugin {
    TestPlugin {
        manifest: leak(json!({
            "id": "t.consumer",
            "dependencies": { "t.provider": "^1" },
            "contributes": {
                "commands": [{ "id": "t.consumer.add", "title": "Add",
                               "args": { "type": "object", "properties": { "n": { "type": "integer" } }, "required": ["n"] } }],
                "settings": { "t.consumer.step": { "type": "integer", "default": 1, "minimum": 1 } }
            }
        })),
        activate: |ctx| {
            let counter = ctx.service::<Counter>()?;
            let c = counter.clone();
            ctx.method("test.add", move |_ctx, n: u32| {
                let c = c.clone();
                async move { Ok(c.0.fetch_add(n, Ordering::SeqCst) + n) }
            });
            #[derive(Deserialize)]
            struct Args {
                n: u32,
            }
            ctx.command("t.consumer.add", move |inv: Invocation, a: Args| {
                let c = counter.clone();
                async move { Ok(json!({ "total": c.0.fetch_add(a.n, Ordering::SeqCst) + a.n, "trusted": inv.trusted_gesture })) }
            })?;
            Ok(())
        },
    }
}

fn kernel(plugins: Vec<TestPlugin>) -> Kernel {
    let mut b = Kernel::builder(tokio::runtime::Handle::current());
    for p in plugins {
        b = b.native(p);
    }
    b.start().unwrap()
}

fn user(source: InvocationSource) -> Invocation {
    Invocation {
        source,
        trusted_gesture: source.is_gesture(),
        caller: "user".into(),
        window: None,
        resources: vec![],
    }
}

#[tokio::test]
async fn services_methods_and_dependency_order() {
    // Listed consumer-first: the kernel orders activation from manifests.
    let k = kernel(vec![consumer(), provider()]);
    assert_eq!(
        k.call(CallContext::default(), "test.add", 2.into())
            .await
            .unwrap(),
        2
    );
    assert_eq!(
        k.call(CallContext::default(), "test.add", 3.into())
            .await
            .unwrap(),
        5
    );
    let err = k
        .call(CallContext::default(), "test.add", "x".into())
        .await
        .unwrap_err();
    assert_eq!(err.code, "invalid_params");
    assert!(k.service::<Counter>().is_some());
    assert_eq!(k.plugin_state("t.consumer"), Some(PluginState::Active));
}

#[tokio::test]
async fn missing_dependency_is_unresolved_not_fatal() {
    let k = kernel(vec![consumer()]);
    let info = k.registry().plugin("t.consumer").cloned().unwrap();
    assert_eq!(info.state, PluginState::Unresolved);
    assert!(info.error.unwrap().contains("t.provider"));
}

#[tokio::test]
async fn commands_validate_args_and_report_gestures() {
    let k = kernel(vec![provider(), consumer()]);
    let out = k
        .execute_command(
            "t.consumer.add",
            json!({ "n": 4 }),
            user(InvocationSource::Menu),
        )
        .await
        .unwrap();
    assert_eq!(out, json!({ "total": 4, "trusted": true }));
    let err = k
        .execute_command(
            "t.consumer.add",
            json!({ "n": "four" }),
            user(InvocationSource::Menu),
        )
        .await
        .unwrap_err();
    assert_eq!(err.code, "invalid_params");

    // Through the protocol: a plugin-initiated call never counts as a gesture.
    let out = k
        .call(
            CallContext::default(),
            "commands.execute",
            json!({ "id": "t.consumer.add", "args": { "n": 1 }, "source": "menu", "callerPlugin": "t.other" }),
        )
        .await
        .unwrap();
    assert_eq!(out["trusted"], json!(false));
    let out = k
        .call(
            CallContext {
                caller: Caller::Plugin("t.provider".into()),
                ..Default::default()
            },
            "commands.execute",
            json!({ "id": "t.consumer.add", "args": { "n": 1 }, "source": "keybinding" }),
        )
        .await
        .unwrap();
    assert_eq!(
        out["trusted"],
        json!(false),
        "a plugin behind a bridge never mints gestures"
    );
}

#[tokio::test]
async fn lazy_activation_on_command() {
    let lazy = TestPlugin {
        manifest: leak(json!({
            "id": "t.lazy",
            "activationEvents": ["onCommand:t.lazy.go"],
            "contributes": { "commands": [{ "id": "t.lazy.go", "title": "Go" }] }
        })),
        activate: |ctx| ctx.command("t.lazy.go", |_, _: Value| async { Ok("went") }),
    };
    let k = kernel(vec![lazy]);
    assert_eq!(k.plugin_state("t.lazy"), Some(PluginState::Resolved));
    let out = k
        .execute_command("t.lazy.go", Value::Null, user(InvocationSource::Palette))
        .await
        .unwrap();
    assert_eq!(out, json!("went"));
    assert_eq!(k.plugin_state("t.lazy"), Some(PluginState::Active));
}

#[tokio::test]
async fn failures_and_panics_are_contained() {
    let panics = TestPlugin {
        manifest: leak(json!({ "id": "t.panics" })),
        activate: |_| panic!("boom"),
    };
    let dependent = TestPlugin {
        manifest: leak(json!({ "id": "t.dependent", "dependencies": { "t.panics": "^1" } })),
        activate: |_| Ok(()),
    };
    let k = kernel(vec![panics, dependent, provider()]);
    let r = k.registry();
    assert_eq!(r.plugin("t.panics").unwrap().state, PluginState::Failed);
    assert!(r
        .plugin("t.panics")
        .unwrap()
        .error
        .as_ref()
        .unwrap()
        .contains("boom"));
    assert_eq!(r.plugin("t.dependent").unwrap().state, PluginState::Failed);
    assert_eq!(r.plugin("t.provider").unwrap().state, PluginState::Active);
}

#[tokio::test]
async fn disable_disposes_registrations_and_enable_restores() {
    let k = kernel(vec![provider(), consumer()]);
    k.set_enabled("t.provider", false).unwrap();
    assert!(k.service::<Counter>().is_none());
    assert_eq!(
        k.call(CallContext::default(), "test.add", 1.into())
            .await
            .unwrap_err()
            .code,
        "not_found"
    );
    assert_eq!(k.plugin_state("t.consumer"), Some(PluginState::Unresolved));
    k.set_enabled("t.provider", true).unwrap();
    assert_eq!(
        k.call(CallContext::default(), "test.add", 1.into())
            .await
            .unwrap(),
        1
    );
}

#[tokio::test]
async fn settings_layers_and_events() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("settings.json"),
        r#"{ "t.consumer.step": 0 }"#,
    )
    .unwrap();
    let k = Kernel::builder(tokio::runtime::Handle::current())
        .config(KernelConfig {
            config_dir: Some(dir.path().into()),
            ..Default::default()
        })
        .native(provider())
        .native(consumer())
        .start()
        .unwrap();
    // 0 violates `minimum: 1`, so the default shows through.
    assert_eq!(k.setting("t.consumer.step"), Some(json!(1)));

    let mut sub = k.events().subscribe(vec!["settings".into()]);
    k.set_setting("t.consumer.step", Some(json!(5))).unwrap();
    assert_eq!(k.setting("t.consumer.step"), Some(json!(5)));
    match sub.recv().await.unwrap() {
        EventMessage::Event { event } => assert_eq!(event.payload["value"], json!(5)),
        other => panic!("{other:?}"),
    }
    assert!(k.set_setting("t.consumer.step", Some(json!("x"))).is_err());
    assert!(k.set_setting("t.nope", Some(json!(1))).is_err());
    let saved = std::fs::read_to_string(dir.path().join("settings.json")).unwrap();
    assert!(saved.contains('5'));
}

#[tokio::test]
async fn publishing_is_namespaced() {
    let k = kernel(vec![provider()]);
    assert!(k
        .publish("t.provider", "t.provider.thing", json!(1))
        .is_ok());
    assert_eq!(
        k.publish("t.provider", "vfs.changed", json!(1))
            .unwrap_err()
            .code,
        "forbidden"
    );
    let err = k
        .call(
            CallContext::default(),
            "context.set",
            json!({ "plugin": "t.provider", "key": "pane.location", "value": 1 }),
        )
        .await
        .unwrap_err();
    assert_eq!(err.code, "forbidden");
}

#[tokio::test]
async fn bootstrap_and_subscriptions_over_the_protocol() {
    let k = kernel(vec![provider(), consumer()]);
    let boot = k
        .call(CallContext::default(), "kernel.bootstrap", Value::Null)
        .await
        .unwrap();
    assert_eq!(boot["settings"]["t.consumer.step"], json!(1));
    assert_eq!(boot["context"]["platform.os"], json!(platform_os()));
    assert_eq!(
        boot["registry"]["commands"][0]["id"],
        json!("t.consumer.add")
    );

    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let sink: EventSink = Arc::new(move |v| {
        let _ = tx.send(v);
    });
    let sub = k
        .call(
            CallContext {
                sink: Some(sink),
                ..Default::default()
            },
            "events.subscribe",
            json!({ "topics": ["t.provider"] }),
        )
        .await
        .unwrap();
    k.publish("t.provider", "t.provider.ping", json!("hi"))
        .unwrap();
    let msg = rx.recv().await.unwrap();
    assert_eq!(msg["type"], json!("event"));
    assert_eq!(msg["event"]["payload"], json!("hi"));
    k.call(CallContext::default(), "events.unsubscribe", sub)
        .await
        .unwrap();
}

#[tokio::test]
async fn plugin_callers_reach_only_the_api_with_their_own_identity() {
    let k = kernel(vec![provider(), consumer()]);
    let as_plugin = || CallContext {
        caller: Caller::Plugin("t.provider".into()),
        ..Default::default()
    };
    // Internal protocol methods are off limits.
    let err = k
        .call(
            as_plugin(),
            "plugins.setEnabled",
            json!({ "id": "t.consumer", "enabled": false }),
        )
        .await
        .unwrap_err();
    assert_eq!(err.code, "forbidden");
    assert_eq!(
        k.call(as_plugin(), "test.add", 1.into())
            .await
            .unwrap_err()
            .code,
        "forbidden"
    );

    // API methods bind the bridge's identity, whatever the plugin claims.
    k.call(
        as_plugin(),
        "storage.set",
        json!({ "plugin": "t.consumer", "key": "k", "value": 1 }),
    )
    .await
    .unwrap();
    assert_eq!(
        k.storage("t.provider").get("", "k").unwrap(),
        Some(json!(1))
    );
    assert_eq!(k.storage("t.consumer").get("", "k").unwrap(), None);
    let out = k
        .call(
            as_plugin(),
            "commands.execute",
            json!({ "id": "t.consumer.add", "args": { "n": 1 }, "source": "menu" }),
        )
        .await
        .unwrap();
    assert_eq!(out["trusted"], json!(false), "plugins never carry gestures");
}

struct FakeHost(Arc<AtomicU32>);

impl RuntimeHost for FakeHost {
    fn runtime(&self) -> atomo_manifest::BackendRuntime {
        atomo_manifest::BackendRuntime::Wasm
    }
    fn activate(
        &self,
        manifest: &Manifest,
        dir: Option<&std::path::Path>,
        ctx: &mut ActivationContext<'_>,
    ) -> KernelResult<()> {
        assert!(dir.is_some_and(|d| d.join("atomo-plugin.json").is_file()));
        self.0.fetch_add(1, Ordering::SeqCst);
        let id = manifest.id.clone();
        ctx.api("test.hosted", move |call: CallContext, _: Value| {
            let id = id.clone();
            async move { Ok(json!({ "host": id, "caller": call.caller.plugin() })) }
        });
        Ok(())
    }
}

#[tokio::test]
async fn disk_plugins_runtime_hosts_and_schema_paths() {
    let root = tempfile::tempdir().unwrap();
    let write = |dir: &str, manifest: Value| {
        let d = root.path().join(dir);
        std::fs::create_dir_all(d.join("schemas")).unwrap();
        std::fs::write(d.join("atomo-plugin.json"), manifest.to_string()).unwrap();
        d
    };
    let base = |id: &str| {
        json!({ "manifestVersion": 1, "id": id, "version": "1.0.0", "displayName": id,
                "description": "", "engines": { "atomo": "^0.1.0" } })
    };
    let mut owner = base("dev.owner");
    owner["extensionPoints"] = json!({ "things": { "description": "d", "resolution": "all", "schema": "schemas/things.json" } });
    let d = write("owner", owner);
    std::fs::write(
        d.join("schemas/things.json"),
        r#"{ "type": "array", "items": { "type": "string" } }"#,
    )
    .unwrap();
    let mut good = base("dev.good");
    good["contributes"] = json!({ "dev.owner/things": ["a"] });
    write("good", good);
    let mut bad = base("dev.bad");
    bad["contributes"] = json!({ "dev.owner/things": [1] });
    write("bad", bad);
    let mut escape = base("dev.escape");
    escape["extensionPoints"] = json!({ "x": { "description": "d", "resolution": "all", "schema": "../owner/schemas/things.json" } });
    write("escape", escape);
    let mut wasm = base("dev.wasm");
    wasm["backend"] = json!({ "runtime": "wasm", "module": "backend/x.wasm" });
    write("wasm", wasm);
    let mut native = base("dev.native");
    native["backend"] = json!({ "runtime": "native" });
    write("native", native);

    let activations = Arc::new(AtomicU32::new(0));
    let k = Kernel::builder(tokio::runtime::Handle::current())
        .runtime_host(Arc::new(FakeHost(activations.clone())))
        .plugin_dir(root.path(), Tier::Dev)
        .start()
        .unwrap();
    let r = k.registry();
    assert_eq!(r.contributions("dev.owner/things").len(), 1);
    assert_eq!(r.plugin("dev.bad").unwrap().state, PluginState::Invalid);
    assert!(r.plugin("dev.escape").unwrap().warnings[0].contains("inside the package"));
    assert_eq!(
        r.plugin("dev.native").unwrap().state,
        PluginState::Invalid,
        "native is core-only"
    );
    assert_eq!(r.plugin("dev.wasm").unwrap().tier, Tier::Dev);
    assert_eq!(k.plugin_state("dev.wasm"), Some(PluginState::Active));
    assert_eq!(activations.load(Ordering::SeqCst), 1);
    let out = k
        .call(
            CallContext {
                caller: Caller::Plugin("dev.good".into()),
                ..Default::default()
            },
            "test.hosted",
            Value::Null,
        )
        .await
        .unwrap();
    assert_eq!(out, json!({ "host": "dev.wasm", "caller": "dev.good" }));
    assert!(k.plugin_dir("dev.wasm").is_some());

    // Without a host, a wasm backend can't run.
    let k = Kernel::builder(tokio::runtime::Handle::current())
        .plugin_dir(root.path().join("wasm"), Tier::Dev)
        .start()
        .unwrap();
    let info = k.registry().plugin("dev.wasm").cloned().unwrap();
    assert_eq!(info.state, PluginState::Invalid);
    assert!(info.error.unwrap().contains("runtime host"));
}

#[tokio::test]
async fn plugin_reads_and_unsubscribes_are_scoped_to_itself() {
    let k = kernel(vec![provider(), consumer()]);
    let as_ = |id: &str| CallContext {
        caller: Caller::Plugin(id.into()),
        ..Default::default()
    };
    let settings = k
        .call(as_("t.provider"), "settings.getAll", Value::Null)
        .await
        .unwrap();
    assert_eq!(settings, json!({}), "t.consumer.step belongs to t.consumer");
    let settings = k
        .call(as_("t.consumer"), "settings.getAll", Value::Null)
        .await
        .unwrap();
    assert_eq!(settings, json!({ "t.consumer.step": 1 }));

    k.set_plugin_context("t.consumer", "secret", json!(1));
    k.set_plugin_context("t.provider", "mine", json!(2));
    let ctx = k
        .call(as_("t.provider"), "context.get", Value::Null)
        .await
        .unwrap();
    assert!(ctx.get("plugin.t.consumer.secret").is_none());
    assert_eq!(ctx["plugin.t.provider.mine"], json!(2));
    assert!(ctx.get("platform.os").is_some());

    let sink: EventSink = Arc::new(|_| {});
    let sub = k
        .call(
            CallContext {
                sink: Some(sink),
                caller: Caller::Plugin("t.consumer".into()),
            },
            "events.subscribe",
            json!({ "topics": [] }),
        )
        .await
        .unwrap();
    let err = k
        .call(as_("t.provider"), "events.unsubscribe", sub.clone())
        .await
        .unwrap_err();
    assert_eq!(err.code, "forbidden");
    k.call(as_("t.consumer"), "events.unsubscribe", sub)
        .await
        .unwrap();
}

#[tokio::test]
async fn disk_plugins_reload_and_late_failures_are_attributed() {
    let root = tempfile::tempdir().unwrap();
    let write = |version: &str| {
        let m = json!({ "manifestVersion": 1, "id": "dev.hot", "version": version, "displayName": "Hot",
                        "description": "", "engines": { "atomo": "^0.1.0" },
                        "backend": { "runtime": "wasm", "module": "x.wasm" } });
        std::fs::write(root.path().join("atomo-plugin.json"), m.to_string()).unwrap();
    };
    write("1.0.0");
    let activations = Arc::new(AtomicU32::new(0));
    let k = Kernel::builder(tokio::runtime::Handle::current())
        .runtime_host(Arc::new(FakeHost(activations.clone())))
        .plugin_dir(root.path(), Tier::Dev)
        .start()
        .unwrap();
    assert_eq!(activations.load(Ordering::SeqCst), 1);
    write("1.1.0");
    let mut sub = k.events().subscribe(vec!["plugin.reloaded".into()]);
    k.reload_plugin("dev.hot").unwrap();
    match sub.recv().await {
        Some(EventMessage::Event { event }) => {
            assert_eq!(event.payload, json!({ "id": "dev.hot", "reason": "dev" }))
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(k.registry().plugin("dev.hot").unwrap().version, "1.1.0");
    assert_eq!(activations.load(Ordering::SeqCst), 2);
    assert_eq!(k.plugin_state("dev.hot"), Some(PluginState::Active));
    assert_eq!(k.reload_plugin("t.nope").unwrap_err().code, "not_found");

    k.report_failure("dev.hot", "compile failed");
    let info = k.registry().plugin("dev.hot").cloned().unwrap();
    assert_eq!(info.state, PluginState::Failed);
    assert_eq!(info.error.as_deref(), Some("compile failed"));
    let err = k
        .call(CallContext::default(), "test.hosted", Value::Null)
        .await
        .unwrap_err();
    assert_eq!(err.code, "not_found", "registrations were disposed");
}
