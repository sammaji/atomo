//! `settings.save`: validation before writing, resets, and restarting the
//! plugin (with its dependents) once its settings changed.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use serde_json::{json, Value};

use super::leak;
use crate::{
    ActivationContext, CallContext, Caller, ErrorCode, EventMessage, Kernel, KernelConfig,
    KernelResult, NativePlugin, PluginState, SaveSettingsParams, Subscription,
};

/// A plugin that counts its activations.
struct Counted {
    manifest: &'static str,
    activations: Arc<AtomicU32>,
}

impl NativePlugin for Counted {
    fn manifest(&self) -> &'static str {
        self.manifest
    }
    fn activate(&self, _: &mut ActivationContext<'_>) -> KernelResult<()> {
        self.activations.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

struct Fixture {
    kernel: Kernel,
    base: Arc<AtomicU32>,
    dependent: Arc<AtomicU32>,
    other: Arc<AtomicU32>,
    dir: tempfile::TempDir,
}

impl Fixture {
    fn activations(&self) -> [u32; 3] {
        [&self.base, &self.dependent, &self.other].map(|c| c.load(Ordering::SeqCst))
    }

    fn save(&self, plugin: &str, values: Value) -> KernelResult<Vec<String>> {
        let params = SaveSettingsParams {
            plugin: plugin.into(),
            values: serde_json::from_value(values).unwrap(),
        };
        self.kernel.save_settings(params).map(|r| r.changed)
    }

    fn saved_file(&self) -> String {
        std::fs::read_to_string(self.dir.path().join("settings.json")).unwrap_or_default()
    }
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("policy.json"),
        r#"{ "t.base.locked": true }"#,
    )
    .unwrap();
    let counter = || Arc::new(AtomicU32::new(0));
    let (base, dependent, other) = (counter(), counter(), counter());
    let kernel = Kernel::builder(tokio::runtime::Handle::current())
        .config(KernelConfig {
            config_dir: Some(dir.path().into()),
            ..Default::default()
        })
        .native(Counted {
            manifest: leak(json!({
                "id": "t.base",
                "contributes": { "settings": {
                    "t.base.size": { "type": "integer", "default": 1, "minimum": 1 },
                    "t.base.name": { "type": "string", "default": "a" },
                    "t.base.locked": { "type": "boolean", "default": false }
                } }
            })),
            activations: base.clone(),
        })
        .native(Counted {
            manifest: leak(json!({
                "id": "t.dependent",
                "dependencies": { "t.base": "^1" },
                "contributes": { "settings": {
                    "t.dependent.x": { "type": "integer", "default": 0 }
                } }
            })),
            activations: dependent.clone(),
        })
        .native(Counted {
            manifest: leak(json!({ "id": "t.other" })),
            activations: other.clone(),
        })
        .start()
        .unwrap();
    Fixture {
        kernel,
        base,
        dependent,
        other,
        dir,
    }
}

/// The next `(topic, payload)` on the subscription.
async fn next(sub: &mut Subscription) -> (String, Value) {
    match sub.recv().await {
        Some(EventMessage::Event { event }) => (event.topic, event.payload),
        other => panic!("{other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn saving_writes_then_restarts_the_plugin_and_its_dependents() {
    let f = fixture();
    assert_eq!(f.activations(), [1, 1, 1]);
    let mut sub = f
        .kernel
        .events()
        .subscribe(vec!["settings".into(), "plugin.reloaded".into()]);

    let changed = f
        .save("t.base", json!({ "t.base.size": 5, "t.base.name": "a" }))
        .unwrap();
    assert_eq!(
        changed,
        ["t.base.size"],
        "an unchanged value is not a change"
    );
    assert_eq!(f.kernel.setting("t.base.size"), Some(json!(5)));
    assert!(f.saved_file().contains("\"t.base.size\": 5"));

    assert_eq!(
        next(&mut sub).await,
        (
            "settings.changed".into(),
            json!({ "key": "t.base.size", "value": 5 })
        )
    );
    assert_eq!(
        next(&mut sub).await,
        (
            "plugin.reloaded".into(),
            json!({ "id": "t.base", "reason": "settings" })
        )
    );
    assert_eq!(
        f.activations(),
        [2, 2, 1],
        "dependents restart, others don't"
    );
    for id in ["t.base", "t.dependent", "t.other"] {
        assert_eq!(f.kernel.plugin_state(id), Some(PluginState::Active), "{id}");
    }

    // Saving the same values again changes nothing and restarts nothing.
    assert!(f
        .save("t.base", json!({ "t.base.size": 5 }))
        .unwrap()
        .is_empty());
    assert_eq!(f.activations(), [2, 2, 1]);
}

#[tokio::test(flavor = "multi_thread")]
async fn null_resets_to_the_default() {
    let f = fixture();
    f.save("t.base", json!({ "t.base.size": 5 })).unwrap();
    let changed = f.save("t.base", json!({ "t.base.size": null })).unwrap();
    assert_eq!(changed, ["t.base.size"]);
    assert_eq!(f.kernel.setting("t.base.size"), Some(json!(1)));
    assert!(!f.saved_file().contains("t.base.size"));
}

#[tokio::test(flavor = "multi_thread")]
async fn one_invalid_value_writes_nothing() {
    let f = fixture();
    let err = f
        .save("t.base", json!({ "t.base.size": 0, "t.base.name": "b" }))
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::InvalidSettings);
    let errors = &err.data.as_ref().unwrap()["errors"];
    assert!(errors["t.base.size"].as_str().unwrap().contains("minimum"));
    assert!(errors.get("t.base.name").is_none(), "{errors}");
    assert_eq!(f.kernel.setting("t.base.name"), Some(json!("a")));
    assert_eq!(f.saved_file(), "");
    assert_eq!(f.activations(), [1, 1, 1]);
}

#[tokio::test(flavor = "multi_thread")]
async fn foreign_unknown_and_locked_keys_are_refused() {
    let f = fixture();
    let err = f
        .save(
            "t.base",
            json!({ "t.dependent.x": 1, "t.base.nope": 1, "t.base.locked": false, "t.base.size": 2 }),
        )
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::InvalidSettings);
    let errors = err.data.unwrap()["errors"].clone();
    let keys: Vec<&String> = errors.as_object().unwrap().keys().collect();
    assert_eq!(keys, ["t.base.locked", "t.base.nope", "t.dependent.x"]);
    assert!(errors["t.dependent.x"]
        .as_str()
        .unwrap()
        .contains("t.dependent"));
    assert!(errors["t.base.locked"].as_str().unwrap().contains("policy"));
    assert_eq!(f.kernel.setting("t.base.size"), Some(json!(1)));

    let err = f.save("t.nope", json!({})).unwrap_err();
    assert_eq!(err.code, ErrorCode::NotFound);
}

#[tokio::test(flavor = "multi_thread")]
async fn only_the_shell_saves_settings() {
    let f = fixture();
    let params = json!({ "plugin": "t.base", "values": { "t.base.size": 3 } });
    let result = f
        .kernel
        .call(CallContext::default(), "settings.save", params.clone())
        .await
        .unwrap();
    assert_eq!(result, json!({ "changed": ["t.base.size"] }));
    let as_plugin = CallContext {
        caller: Caller::Plugin("t.base".into()),
        ..Default::default()
    };
    let err = f
        .kernel
        .call(as_plugin, "settings.save", params)
        .await
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::Forbidden);
}

#[tokio::test(flavor = "multi_thread")]
async fn settings_of_an_inactive_backend_only_restart_the_frontend() {
    let f = fixture();
    f.kernel.deactivate("t.base");
    let mut sub = f.kernel.events().subscribe(vec!["plugin.reloaded".into()]);
    f.save("t.base", json!({ "t.base.size": 2 })).unwrap();
    assert_eq!(
        next(&mut sub).await.1,
        json!({ "id": "t.base", "reason": "settings" })
    );
    assert_eq!(f.activations(), [1, 1, 1]);
    assert_eq!(f.kernel.plugin_state("t.base"), Some(PluginState::Resolved));
}
