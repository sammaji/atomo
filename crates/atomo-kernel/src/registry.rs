//! The registry build: manifests in, one immutable [`RegistrySnapshot`] out.
//!
//! Everything here is data. No plugin code runs while the snapshot is built,
//! which is what lets the host render menus, settings and columns before any
//! plugin activates.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::hash::{Hash, Hasher};

use atomo_manifest::{
    split_point, Cardinality, CommandDecl, FrontendRuntime, Half, Manifest, Resolution, Version,
    VersionReq, HOST_API_VERSION,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use ts_rs::TS;

use crate::schema::Schema;

/// How much we trust a plugin. Assigned by the loader, never self-declared.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export)]
pub enum Tier {
    Core,
    Verified,
    Community,
    Dev,
}

/// Lifecycle. `Invalid`/`Unresolved` come from the registry build; the
/// rest are runtime states the kernel (or the shell, for frontend halves) reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export)]
pub enum PluginState {
    Invalid,
    Unresolved,
    Disabled,
    Resolved,
    Activating,
    Active,
    Failed,
}

#[derive(Debug, Clone, Serialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export)]
pub struct PluginInfo {
    pub id: String,
    pub version: String,
    pub display_name: String,
    pub description: String,
    pub tier: Tier,
    pub state: PluginState,
    pub error: Option<String>,
    pub warnings: Vec<String>,
    pub has_backend: bool,
    pub frontend: Option<FrontendRuntime>,
    /// The frontend half's bundle inside the package (`frontend.module`).
    #[serde(skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub frontend_module: Option<String>,
    pub dependencies: Vec<String>,
    /// Activation events: declared plus implied by contributions.
    pub activation_events: Vec<String>,
    /// Held (state `disabled`) until the user reviews its permissions: a new
    /// install, or an update whose permissions or dependencies grew.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    #[ts(optional, as = "Option<bool>")]
    pub needs_consent: bool,
}

#[derive(Debug, Clone, Serialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export)]
pub struct ExtensionPointInfo {
    pub id: String,
    /// `None` for kernel-owned points.
    pub owner: Option<String>,
    pub description: String,
    pub cardinality: Cardinality,
    pub resolution: Resolution,
}

#[derive(Debug, Clone, Serialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export)]
pub struct Contribution {
    pub plugin: String,
    #[ts(type = "unknown")]
    pub value: Value,
}

#[derive(Debug, Clone, Serialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export)]
pub struct CommandInfo {
    #[serde(flatten)]
    pub decl: CommandDecl,
    pub plugin: String,
    /// Resolved: the declaration's `handler` or the plugin's default half.
    pub half: Half,
}

#[derive(Debug, Clone, Serialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export)]
pub struct SettingInfo {
    pub plugin: String,
    #[ts(type = "unknown")]
    pub schema: Value,
    #[ts(type = "unknown")]
    pub default: Value,
}

/// The immutable registry. Rebuilt on install, update or enable changes.
#[derive(Debug, Clone, Serialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export)]
pub struct RegistrySnapshot {
    /// Content hash of the inputs; equal hashes mean an identical registry.
    pub hash: String,
    /// Every known plugin. Usable ones come first, in activation (dependency) order.
    pub plugins: Vec<PluginInfo>,
    pub extension_points: Vec<ExtensionPointInfo>,
    /// Point ID → contributions from usable plugins, in activation order.
    pub contributions: BTreeMap<String, Vec<Contribution>>,
    pub commands: Vec<CommandInfo>,
    pub settings: BTreeMap<String, SettingInfo>,
}

impl RegistrySnapshot {
    pub fn plugin(&self, id: &str) -> Option<&PluginInfo> {
        self.plugins.iter().find(|p| p.id == id)
    }

    pub fn command(&self, id: &str) -> Option<&CommandInfo> {
        self.commands.iter().find(|c| c.decl.id == id)
    }

    pub fn contributions(&self, point: &str) -> &[Contribution] {
        self.contributions.get(point).map_or(&[], Vec::as_slice)
    }

    /// Plugins whose backend may run, in dependency order.
    pub fn activation_order(&self) -> impl Iterator<Item = &PluginInfo> {
        self.plugins
            .iter()
            .filter(|p| matches!(p.state, PluginState::Resolved | PluginState::Active))
    }
}

/// One manifest as handed to the registry build.
pub(crate) struct Input {
    pub source: Result<Manifest, String>,
    /// For invalid manifests, the best ID we could recover (for attribution).
    pub fallback_id: String,
    pub tier: Tier,
    /// A native plugin or a runtime host can run its backend half.
    pub backend_runnable: bool,
    /// Package directory (plugins loaded from disk): resolves schema paths.
    pub dir: Option<std::path::PathBuf>,
    /// Waiting for permission consent: why (the broker decides).
    pub held: Option<String>,
}

pub(crate) struct Built {
    pub snapshot: RegistrySnapshot,
    pub manifests: HashMap<String, Manifest>,
    pub schemas: HashMap<String, Schema>,
}

/// Kernel-owned points. Their contributions are checked by the manifest crate.
fn kernel_points() -> Vec<ExtensionPointInfo> {
    vec![
        ExtensionPointInfo {
            id: "commands".into(),
            owner: None,
            description: "Commands".into(),
            cardinality: Cardinality::Many,
            resolution: Resolution::All,
        },
        ExtensionPointInfo {
            id: "settings".into(),
            owner: None,
            description: "Setting schemas with defaults".into(),
            cardinality: Cardinality::Many,
            resolution: Resolution::All,
        },
    ]
}

pub(crate) fn build(inputs: Vec<Input>, disabled: &BTreeSet<String>) -> Built {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    let mut infos: BTreeMap<String, PluginInfo> = BTreeMap::new();
    let mut manifests: BTreeMap<String, Manifest> = BTreeMap::new();
    let mut dirs: HashMap<String, std::path::PathBuf> = HashMap::new();
    let host = Version::parse(HOST_API_VERSION).expect("host version");

    for input in inputs {
        match input.source {
            Err(error) => {
                error.hash(&mut hasher);
                infos
                    .entry(input.fallback_id.clone())
                    .or_insert(PluginInfo {
                        id: input.fallback_id,
                        version: String::new(),
                        display_name: String::new(),
                        description: String::new(),
                        tier: input.tier,
                        state: PluginState::Invalid,
                        error: Some(error),
                        warnings: vec![],
                        has_backend: false,
                        frontend: None,
                        frontend_module: None,
                        dependencies: vec![],
                        activation_events: vec![],
                        needs_consent: false,
                    });
            }
            Ok(m) => {
                serde_json::to_string(&m)
                    .unwrap_or_default()
                    .hash(&mut hasher);
                let mut info = PluginInfo {
                    id: m.id.clone(),
                    version: m.version.clone(),
                    display_name: m.display_name.clone(),
                    description: m.description.clone(),
                    tier: input.tier,
                    state: PluginState::Resolved,
                    error: None,
                    warnings: vec![],
                    has_backend: m.backend.is_some(),
                    frontend: m.frontend.as_ref().map(|f| f.runtime),
                    frontend_module: m.frontend.as_ref().and_then(|f| f.module.clone()),
                    dependencies: m.dependencies.keys().cloned().collect(),
                    activation_events: activation_events(&m),
                    needs_consent: false,
                };
                if infos.contains_key(&m.id) {
                    // One version per plugin ID: the first one wins.
                    continue;
                }
                let fail = |info: &mut PluginInfo, msg: String| {
                    info.state = PluginState::Invalid;
                    info.error = Some(msg);
                };
                if input.tier != Tier::Core {
                    if matches!(
                        m.backend.as_ref().map(|b| b.runtime),
                        Some(atomo_manifest::BackendRuntime::Native)
                    ) {
                        fail(&mut info, "native backends are core-tier only".into());
                    }
                    if info.frontend == Some(FrontendRuntime::InRealm) {
                        fail(&mut info, "in-realm frontends are core-tier only".into());
                    }
                }
                if let Some(backend) = &m.backend {
                    if !input.backend_runnable {
                        let msg = match backend.runtime {
                            atomo_manifest::BackendRuntime::Native => {
                                "declares a native backend that is not compiled into this build"
                                    .to_owned()
                            }
                            other => {
                                format!("no runtime host for `{other:?}` backends in this build")
                                    .to_lowercase()
                            }
                        };
                        fail(&mut info, msg);
                    }
                }
                if !VersionReq::parse(&m.engines.atomo).is_ok_and(|r| r.matches(&host)) {
                    fail(
                        &mut info,
                        format!(
                            "engines.atomo `{}` does not match host API {HOST_API_VERSION}",
                            m.engines.atomo
                        ),
                    );
                }
                if let Some(reason) = input.held {
                    reason.hash(&mut hasher);
                    if info.state == PluginState::Resolved {
                        info.state = PluginState::Disabled;
                        info.error = Some(reason);
                        info.needs_consent = true;
                    }
                }
                infos.insert(m.id.clone(), info);
                if let Some(dir) = input.dir {
                    dirs.insert(m.id.clone(), dir);
                }
                manifests.insert(m.id.clone(), m);
            }
        }
    }
    disabled.iter().for_each(|d| d.hash(&mut hasher));

    // Dependency resolution: hard deps must exist, be usable and match their range.
    // Contributing to `owner/point` implies an *optional* dependency on `owner`:
    // ordering only, and the contribution is inert when the owner is missing.
    let mut edges: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for (id, m) in &manifests {
        let mut deps: BTreeSet<String> = m.dependencies.keys().cloned().collect();
        deps.extend(m.optional_dependencies.keys().cloned());
        for point in m.contributes.keys() {
            if let Some((Some(owner), _)) = split_point(point) {
                if owner != id {
                    deps.insert(owner.to_owned());
                }
            }
        }
        deps.retain(|d| manifests.contains_key(d));
        edges.insert(id.clone(), deps);
    }

    if let Some(order_err) = topo_order(&edges).err() {
        for id in order_err {
            if let Some(info) = infos.get_mut(&id) {
                info.state = PluginState::Invalid;
                info.error = Some("part of a dependency cycle".into());
            }
        }
    }
    for id in disabled {
        if let Some(info) = infos.get_mut(id) {
            if info.state == PluginState::Resolved {
                info.state = PluginState::Disabled;
            }
        }
    }

    // Propagate unusable dependencies until stable (dependents of broken plugins are unresolved).
    loop {
        let mut changed = false;
        for (id, m) in &manifests {
            if infos[id].state != PluginState::Resolved {
                continue;
            }
            let mut problem = None;
            for (dep, range) in &m.dependencies {
                let Some(dep_info) = infos.get(dep) else {
                    problem = Some(format!("missing dependency `{dep}`"));
                    break;
                };
                if !matches!(dep_info.state, PluginState::Resolved) {
                    problem =
                        Some(format!("dependency `{dep}` is {:?}", dep_info.state).to_lowercase());
                    break;
                }
                let ok = Version::parse(&dep_info.version)
                    .ok()
                    .zip(VersionReq::parse(range).ok())
                    .is_some_and(|(v, r)| r.matches(&v));
                if !ok {
                    problem = Some(format!(
                        "`{dep}` {} does not satisfy `{range}`",
                        dep_info.version
                    ));
                    break;
                }
            }
            if let Some(p) = problem {
                let info = infos.get_mut(id).unwrap();
                info.state = PluginState::Unresolved;
                info.error = Some(p);
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }

    let usable = |id: &str, infos: &BTreeMap<String, PluginInfo>| {
        infos
            .get(id)
            .is_some_and(|i| i.state == PluginState::Resolved)
    };
    let order: Vec<String> = topo_order(
        &edges
            .iter()
            .filter(|(id, _)| usable(id, &infos))
            .map(|(id, deps)| {
                (
                    id.clone(),
                    deps.iter().filter(|d| usable(d, &infos)).cloned().collect(),
                )
            })
            .collect(),
    )
    .unwrap_or_default();

    // Extension points from usable plugins.
    let mut points: Vec<ExtensionPointInfo> = kernel_points();
    let mut schemas: HashMap<String, Schema> = HashMap::new();
    for id in &order {
        let m = &manifests[id];
        for (name, def) in &m.extension_points {
            let point = format!("{id}/{name}");
            // A string is a path inside the package.
            let resolved = match &def.schema {
                Some(Value::String(path)) => match package_json(dirs.get(id), path) {
                    Ok(v) => Some(v),
                    Err(e) => {
                        infos
                            .get_mut(id)
                            .unwrap()
                            .warnings
                            .push(format!("{point}: {e}; contributions are not validated"));
                        None
                    }
                },
                other => other.clone(),
            };
            if let Some(schema) = &resolved {
                match Schema::compile(schema) {
                    Ok(s) => {
                        schemas.insert(point.clone(), s);
                    }
                    Err(e) => infos
                        .get_mut(id)
                        .unwrap()
                        .warnings
                        .push(format!("{point}: invalid schema: {e}")),
                }
            }
            points.push(ExtensionPointInfo {
                id: point,
                owner: Some(id.clone()),
                description: def.description.clone(),
                cardinality: def.cardinality,
                resolution: def.resolution,
            });
        }
    }
    let point_ids: BTreeSet<&str> = points.iter().map(|p| p.id.as_str()).collect();

    // Contributions are validated against the owner's schema; an invalid
    // contribution invalidates its plugin.
    let mut invalidated: Vec<(String, String)> = Vec::new();
    for id in &order {
        let m = &manifests[id];
        for (point, value) in &m.contributes {
            if !point_ids.contains(point.as_str()) {
                continue;
            }
            if let Some(schema) = schemas.get(point) {
                if let Err(e) = schema.validate(value) {
                    invalidated.push((id.clone(), format!("contributes.{point}: {e}")));
                }
            }
        }
    }
    for (id, err) in &invalidated {
        let info = infos.get_mut(id).unwrap();
        info.state = PluginState::Invalid;
        info.error = Some(err.clone());
    }

    let order: Vec<String> = order.into_iter().filter(|id| usable(id, &infos)).collect();
    let mut contributions: BTreeMap<String, Vec<Contribution>> = BTreeMap::new();
    let mut commands = Vec::new();
    let mut settings = BTreeMap::new();
    for id in &order {
        let m = &manifests[id];
        for (point, value) in &m.contributes {
            if !point_ids.contains(point.as_str()) {
                // Owner absent or disabled: inert, a warning not an error.
                infos.get_mut(id).unwrap().warnings.push(format!(
                    "contribution to `{point}` is inert: no such extension point"
                ));
                continue;
            }
            contributions
                .entry(point.clone())
                .or_default()
                .push(Contribution {
                    plugin: id.clone(),
                    value: value.clone(),
                });
        }
        for decl in m.commands() {
            let half = decl.handler.unwrap_or_else(|| m.default_handler());
            if let Some(args) = &decl.args {
                match Schema::compile(args) {
                    Ok(s) => {
                        schemas.insert(format!("command:{}", decl.id), s);
                    }
                    Err(e) => infos
                        .get_mut(id)
                        .unwrap()
                        .warnings
                        .push(format!("command `{}`: invalid args schema: {e}", decl.id)),
                }
            }
            commands.push(CommandInfo {
                decl,
                plugin: id.clone(),
                half,
            });
        }
        for (key, schema) in m.settings() {
            let default = schema.get("default").cloned().unwrap_or(Value::Null);
            match Schema::compile(&schema) {
                Ok(s) => {
                    schemas.insert(format!("setting:{key}"), s);
                }
                Err(e) => infos
                    .get_mut(id)
                    .unwrap()
                    .warnings
                    .push(format!("setting `{key}`: invalid schema: {e}")),
            }
            settings.insert(
                key,
                SettingInfo {
                    plugin: id.clone(),
                    schema,
                    default,
                },
            );
        }
    }

    // Usable plugins first, in activation order, then everything else by ID.
    let mut plugins: Vec<PluginInfo> = order.iter().map(|id| infos[id].clone()).collect();
    plugins.extend(infos.values().filter(|i| !order.contains(&i.id)).cloned());

    Built {
        snapshot: RegistrySnapshot {
            hash: format!("{:016x}", hasher.finish()),
            plugins,
            extension_points: points,
            contributions,
            commands,
            settings,
        },
        manifests: manifests.into_iter().collect(),
        schemas,
    }
}

/// Read a JSON file from a plugin package, refusing paths that leave it.
fn package_json(dir: Option<&std::path::PathBuf>, path: &str) -> Result<Value, String> {
    let dir = dir.ok_or_else(|| format!("schema path `{path}` needs a package directory"))?;
    let rel = std::path::Path::new(path);
    if rel.is_absolute()
        || rel
            .components()
            .any(|c| !matches!(c, std::path::Component::Normal(_)))
    {
        return Err(format!("schema path `{path}` must stay inside the package"));
    }
    let text = std::fs::read_to_string(dir.join(rel)).map_err(|e| format!("`{path}`: {e}"))?;
    serde_json::from_str(&text).map_err(|e| format!("`{path}`: {e}"))
}

/// Activation events implied by contributions, plus declared ones.
fn activation_events(m: &Manifest) -> Vec<String> {
    let mut events: BTreeSet<String> = m.activation_events.iter().cloned().collect();
    for c in m.commands() {
        events.insert(format!("onCommand:{}", c.id));
    }
    for s in &m.services.provides {
        events.insert(format!("onService:{}", s.id));
    }
    events.into_iter().collect()
}

/// Kahn's algorithm with a sorted ready set: dependencies first, ties by ID, so
/// the order never depends on install order. `Err` lists the plugins on cycles.
fn topo_order(edges: &BTreeMap<String, BTreeSet<String>>) -> Result<Vec<String>, Vec<String>> {
    let mut remaining: BTreeMap<&str, usize> = edges
        .iter()
        .map(|(id, deps)| (id.as_str(), deps.len()))
        .collect();
    let mut dependents: HashMap<&str, Vec<&str>> = HashMap::new();
    for (id, deps) in edges {
        for d in deps {
            dependents.entry(d.as_str()).or_default().push(id.as_str());
        }
    }
    let mut ready: BTreeSet<&str> = remaining
        .iter()
        .filter(|(_, n)| **n == 0)
        .map(|(id, _)| *id)
        .collect();
    let mut order = Vec::with_capacity(edges.len());
    while let Some(id) = ready.pop_first() {
        remaining.remove(id);
        order.push(id.to_owned());
        for dep in dependents.get(id).into_iter().flatten() {
            if let Some(n) = remaining.get_mut(dep) {
                *n -= 1;
                if *n == 0 {
                    ready.insert(dep);
                }
            }
        }
    }
    if remaining.is_empty() {
        Ok(order)
    } else {
        Err(remaining.keys().map(|s| s.to_string()).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn manifest(id: &str, extra: Value) -> Input {
        let mut m = json!({
            "manifestVersion": 1, "id": id, "version": "1.0.0", "displayName": id,
            "description": "", "engines": { "atomo": "^0.1.0" }
        });
        m.as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        Input {
            source: Manifest::parse(&m.to_string()).map_err(|e| e.to_string()),
            fallback_id: id.into(),
            tier: Tier::Core,
            backend_runnable: false,
            dir: None,
            held: None,
        }
    }

    fn state(b: &Built, id: &str) -> PluginState {
        b.snapshot.plugin(id).unwrap().state
    }

    #[test]
    fn dependency_order_is_deterministic() {
        let b = build(
            vec![
                manifest("t.c", json!({ "dependencies": { "t.b": "^1" } })),
                manifest("t.b", json!({ "dependencies": { "t.a": "^1" } })),
                manifest("t.a", json!({})),
                manifest("t.z", json!({})),
            ],
            &BTreeSet::new(),
        );
        let ids: Vec<_> = b.snapshot.plugins.iter().map(|p| p.id.as_str()).collect();
        assert_eq!(ids, ["t.a", "t.b", "t.c", "t.z"]);
    }

    #[test]
    fn missing_and_mismatched_dependencies() {
        let b = build(
            vec![
                manifest("t.a", json!({ "dependencies": { "t.missing": "^1" } })),
                manifest("t.b", json!({ "dependencies": { "t.a": "^1" } })),
                manifest("t.c", json!({ "dependencies": { "t.d": "^2" } })),
                manifest("t.d", json!({})),
            ],
            &BTreeSet::new(),
        );
        assert_eq!(state(&b, "t.a"), PluginState::Unresolved);
        assert_eq!(state(&b, "t.b"), PluginState::Unresolved, "propagates");
        assert_eq!(state(&b, "t.c"), PluginState::Unresolved);
        assert_eq!(state(&b, "t.d"), PluginState::Resolved);
    }

    #[test]
    fn cycles_are_rejected() {
        let b = build(
            vec![
                manifest("t.a", json!({ "dependencies": { "t.b": "^1" } })),
                manifest("t.b", json!({ "dependencies": { "t.a": "^1" } })),
            ],
            &BTreeSet::new(),
        );
        assert_eq!(state(&b, "t.a"), PluginState::Invalid);
        assert_eq!(state(&b, "t.b"), PluginState::Invalid);
    }

    #[test]
    fn contributions_validated_and_inert() {
        let owner = manifest(
            "t.owner",
            json!({ "extensionPoints": { "things": {
                "description": "d", "resolution": "all",
                "schema": { "type": "array", "items": { "type": "object", "required": ["id"] } }
            }}}),
        );
        let good = manifest(
            "t.good",
            json!({ "contributes": { "t.owner/things": [{ "id": "x" }] } }),
        );
        let bad = manifest(
            "t.bad",
            json!({ "contributes": { "t.owner/things": [{ "nope": 1 }] } }),
        );
        let inert = manifest("t.inert", json!({ "contributes": { "t.gone/things": [] } }));
        let b = build(vec![owner, good, bad, inert], &BTreeSet::new());
        assert_eq!(b.snapshot.contributions("t.owner/things").len(), 1);
        assert_eq!(state(&b, "t.bad"), PluginState::Invalid);
        assert_eq!(state(&b, "t.inert"), PluginState::Resolved);
        assert_eq!(b.snapshot.plugin("t.inert").unwrap().warnings.len(), 1);
    }

    #[test]
    fn disabled_owner_makes_contributions_inert() {
        let owner = manifest(
            "t.owner",
            json!({ "extensionPoints": { "things": { "description": "d", "resolution": "all" } } }),
        );
        let user = manifest(
            "t.user",
            json!({ "contributes": { "t.owner/things": [1] } }),
        );
        let b = build(vec![owner, user], &BTreeSet::from(["t.owner".to_string()]));
        assert_eq!(state(&b, "t.owner"), PluginState::Disabled);
        assert_eq!(state(&b, "t.user"), PluginState::Resolved);
        assert!(b.snapshot.contributions("t.owner/things").is_empty());
    }

    #[test]
    fn tiers_and_engines() {
        let mut community = manifest("t.native", json!({ "backend": { "runtime": "native" } }));
        community.tier = Tier::Community;
        let future = manifest("t.future", json!({ "engines": { "atomo": "^9" } }));
        let b = build(vec![community, future], &BTreeSet::new());
        assert_eq!(state(&b, "t.native"), PluginState::Invalid);
        assert_eq!(state(&b, "t.future"), PluginState::Invalid);
    }

    #[test]
    fn held_plugins_are_disabled_and_their_dependents_unresolved() {
        let mut held = manifest("t.held", json!({}));
        held.held = Some("review its permissions".into());
        let user = manifest("t.user", json!({ "dependencies": { "t.held": "^1" } }));
        let b = build(vec![held, user], &BTreeSet::new());
        let info = b.snapshot.plugin("t.held").unwrap();
        assert_eq!(info.state, PluginState::Disabled);
        assert!(info.needs_consent);
        assert_eq!(state(&b, "t.user"), PluginState::Unresolved);
    }

    #[test]
    fn commands_and_settings() {
        let b = build(
            vec![manifest(
                "t.a",
                json!({
                    "frontend": { "runtime": "in-realm" },
                    "contributes": {
                        "commands": [{ "id": "t.a.go", "title": "Go" }],
                        "settings": { "t.a.size": { "type": "integer", "default": 3 } }
                    }
                }),
            )],
            &BTreeSet::new(),
        );
        let cmd = b.snapshot.command("t.a.go").unwrap();
        assert_eq!(cmd.half, Half::Frontend);
        assert_eq!(b.snapshot.settings["t.a.size"].default, json!(3));
        assert!(b
            .snapshot
            .plugin("t.a")
            .unwrap()
            .activation_events
            .contains(&"onCommand:t.a.go".to_string()));
    }
}
