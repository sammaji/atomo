//! Internal methods for the shell: boot, the registry, plugin management and settings.

use serde::Deserialize;
use serde_json::Value;

use crate::{Bootstrap, Kernel, PluginState, SaveSettingsParams};

#[derive(Deserialize)]
struct PluginId {
    id: String,
}

#[derive(Deserialize)]
struct SetEnabled {
    id: String,
    enabled: bool,
}

#[derive(Deserialize)]
struct ReportState {
    id: String,
    state: PluginState,
    error: Option<String>,
}

#[derive(Deserialize)]
struct SetSetting {
    key: String,
    value: Option<Value>,
}

pub(super) fn register(k: &Kernel) {
    k.kernel_method("kernel.bootstrap", |k, _, _: Value| async move {
        Ok(Bootstrap {
            registry: (*k.registry()).clone(),
            settings: k.settings(),
            context: k.context(),
        })
    });
    k.kernel_method("registry.snapshot", |k, _, _: Value| async move {
        Ok((*k.registry()).clone())
    });

    k.kernel_method("plugins.reload", |k, _, p: PluginId| async move {
        k.reload_plugin(&p.id)
    });
    k.kernel_method("plugins.setEnabled", |k, _, p: SetEnabled| async move {
        k.set_enabled(&p.id, p.enabled)
    });
    k.kernel_method(
        "plugins.reportFrontendState",
        |k, _, p: ReportState| async move {
            k.set_frontend_state(&p.id, p.state, p.error);
            Ok(())
        },
    );

    k.kernel_method("settings.set", |k, _, p: SetSetting| async move {
        k.set_setting(&p.key, p.value.filter(|v| !v.is_null()))
    });
    k.kernel_method("settings.save", |k, _, p: SaveSettingsParams| async move {
        k.save_settings(p)
    });
}
