//! Plain-language permission summaries generated from a manifest: the install
//! and update consent dialogs and the Plugins page show the same text.
//!
//! "Needs no permissions" is a positive signal: it rewards authors who stay
//! pure. Risk levels steer the dialog's emphasis, never its outcome.

use std::collections::BTreeSet;

use atomo_manifest::Manifest;
use serde::Serialize;
use serde_json::Value;
use ts_rs::TS;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export, rename = "PermissionRisk")]
pub enum Risk {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export, rename = "PermissionKind")]
pub enum LineKind {
    /// Access the user hands over with a gesture (intent grants).
    Intent,
    /// A standing grant the plugin needs to work.
    Required,
    /// A standing grant the plugin may ask for in context.
    Optional,
}

/// One line of a permission summary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export, rename = "PermissionLine")]
pub struct SummaryLine {
    pub text: String,
    pub kind: LineKind,
    /// The right (`fs.read`, `net`…) or the access token (`selection:read`).
    pub right: String,
    pub risk: Risk,
    /// The author's `reason`, shown as the "why".
    #[serde(skip_serializing_if = "Option::is_none")]
    #[ts(optional)]
    pub reason: Option<String>,
}

/// `~/…` for paths under the home directory.
pub fn display_path(path: &str) -> String {
    let path = path
        .strip_prefix("file://")
        .map(|p| p.trim_start_matches("localhost"))
        .unwrap_or(path);
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .unwrap_or_default()
        .replace('\\', "/");
    let path = path.replace('\\', "/");
    if !home.is_empty() && home != "/" {
        if let Some(rest) = path.strip_prefix(&home) {
            if rest.is_empty() || rest.starts_with('/') {
                return format!("~{rest}");
            }
        }
    }
    path
}

fn list(items: &[String]) -> String {
    match items {
        [] => String::new(),
        [one] => one.clone(),
        [a, b] => format!("{a} and {b}"),
        [rest @ .., last] => format!("{} and {last}", rest.join(", ")),
    }
}

fn strings(p: &Value, key: &str) -> Vec<String> {
    p.get(key)
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

/// A raw IP address (v4, or bracketed / colon-separated v6), maybe with a port.
pub fn is_raw_ip(host: &str) -> bool {
    let h = host.trim_start_matches('[');
    let h = h.split(']').next().unwrap_or(h);
    let h = if h.matches(':').count() == 1 {
        h.split(':').next().unwrap_or(h)
    } else {
        h
    };
    h.parse::<std::net::IpAddr>().is_ok()
}

/// Lines for one standing permission entry (`{id, paths|hosts|binaries, reason}`).
pub fn describe_permission(p: &Value, kind: LineKind) -> SummaryLine {
    let right = p
        .get("id")
        .and_then(Value::as_str)
        .unwrap_or("?")
        .to_owned();
    let reason = p.get("reason").and_then(Value::as_str).map(str::to_owned);
    let paths: Vec<String> = strings(p, "paths")
        .iter()
        .map(|s| display_path(s))
        .collect();
    let hosts = strings(p, "hosts");
    let binaries = strings(p, "binaries");
    let where_ = |verb: &str| {
        if paths.is_empty() {
            format!("{verb} any of your files")
        } else {
            format!("{verb} files in {}", list(&paths))
        }
    };
    let broad = paths.is_empty()
        || paths
            .iter()
            .any(|p| p == "~" || p == "/" || p.starts_with("~/**") || p == "/**");
    let (text, risk) = match right.as_str() {
        "fs.read" => (
            where_("Reads"),
            if broad { Risk::High } else { Risk::Medium },
        ),
        "fs.write" => (
            where_("Changes"),
            if broad { Risk::High } else { Risk::Medium },
        ),
        "fs.create" => (where_("Creates"), Risk::Medium),
        "net" => {
            let insecure = hosts
                .iter()
                .any(|h| h.starts_with("http:") || is_raw_ip(h.trim_start_matches("https://")));
            if hosts.is_empty() {
                ("Connects to any server".to_owned(), Risk::High)
            } else if insecure {
                (
                    format!(
                        "Connects to {} (unencrypted or a raw IP address)",
                        list(&hosts)
                    ),
                    Risk::High,
                )
            } else {
                (format!("Connects to {}", list(&hosts)), Risk::Medium)
            }
        }
        // The programs run with the user's own authority, outside every
        // other check: say so.
        "exec" => {
            if binaries.is_empty() {
                (
                    "Can run programs with your full user permissions".to_owned(),
                    Risk::High,
                )
            } else {
                (
                    format!(
                        "Can run {} with your full user permissions",
                        list(&binaries)
                    ),
                    Risk::High,
                )
            }
        }
        "secrets" => (
            "Keeps its own passwords and tokens in your keychain".to_owned(),
            Risk::Low,
        ),
        other => (format!("Uses the `{other}` permission"), Risk::Medium),
    };
    let text = if kind == LineKind::Optional {
        format!("May ask to: {}{}", text[..1].to_lowercase(), &text[1..])
    } else {
        text
    };
    SummaryLine {
        text,
        kind,
        right,
        risk,
        reason,
    }
}

/// The line for an intent-access token.
pub fn describe_access(token: &str) -> SummaryLine {
    let (text, risk) = match token {
        "selection:read" => ("Reads files you select", Risk::Low),
        "selection:write" => ("Changes files you select", Risk::Medium),
        "selection:create-siblings" => ("Creates files next to the ones you select", Risk::Low),
        "picked:read" => ("Reads files you pick", Risk::Low),
        "picked:write" => ("Changes files you pick", Risk::Medium),
        "dropped:read" => ("Reads files you drop on it", Risk::Low),
        "opened:read" => ("Reads files you open with it", Risk::Low),
        "opened:write" => ("Edits files you open with it", Risk::Medium),
        "location:read" => ("Reads the folder you are in", Risk::Low),
        "location:write" => ("Changes files in the folder you are in", Risk::Medium),
        t if t.starts_with("mount:") => ("Connects to servers you add", Risk::Medium),
        _ => ("Uses files you hand it", Risk::Low),
    };
    SummaryLine {
        text: text.to_owned(),
        kind: LineKind::Intent,
        right: token.to_owned(),
        risk,
        reason: None,
    }
}

/// Every `access` token a manifest declares: on commands, and on any
/// contributed object (actions, views…) that carries an `access` array.
pub fn access_tokens(m: &Manifest) -> BTreeSet<String> {
    fn walk(v: &Value, out: &mut BTreeSet<String>, depth: usize) {
        match v {
            Value::Object(o) => {
                if let Some(Value::Array(a)) = o.get("access") {
                    out.extend(a.iter().filter_map(Value::as_str).map(str::to_owned));
                }
                if depth < 3 {
                    o.values().for_each(|x| walk(x, out, depth + 1));
                }
            }
            Value::Array(a) if depth < 3 => a.iter().for_each(|x| walk(x, out, depth + 1)),
            _ => {}
        }
    }
    let mut out = BTreeSet::new();
    for (point, value) in &m.contributes {
        if point != "settings" {
            walk(value, &mut out, 0);
        }
    }
    out.retain(|t| atomo_manifest::is_valid_access(t));
    out
}

/// The whole summary of a manifest: intent access, then required, then
/// optional permissions. Empty means "Needs no permissions".
pub fn summarize(m: &Manifest) -> Vec<SummaryLine> {
    let mut lines: Vec<SummaryLine> = Vec::new();
    for t in access_tokens(m) {
        let line = describe_access(&t);
        if !lines.iter().any(|l| l.text == line.text) {
            lines.push(line);
        }
    }
    lines.extend(
        m.permissions
            .required
            .iter()
            .map(|p| describe_permission(p, LineKind::Required)),
    );
    lines.extend(
        m.permissions
            .optional
            .iter()
            .map(|p| describe_permission(p, LineKind::Optional)),
    );
    lines
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn manifest(extra: Value) -> Manifest {
        let mut m = json!({
            "manifestVersion": 1, "id": "acme.tool", "version": "1.0.0", "displayName": "Tool",
            "description": "", "engines": { "atomo": "^0.1.0" },
            "frontend": { "runtime": "sandbox" }
        });
        m.as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        Manifest::parse(&m.to_string()).unwrap()
    }

    #[test]
    fn pure_plugins_need_nothing() {
        let m = manifest(json!({}));
        assert!(summarize(&m).is_empty());
    }

    #[test]
    fn lines_in_plain_language() {
        let m = manifest(json!({
            "contributes": { "commands": [{ "id": "acme.tool.go", "title": "Go", "access": ["selection:read"] }] },
            "permissions": {
                "required": [
                    { "id": "net", "hosts": ["api.example.com"], "reason": "to sync" },
                    { "id": "exec", "binaries": ["/opt/homebrew/bin/ffmpeg"] },
                    { "id": "net", "hosts": ["10.0.0.1"] }
                ],
                "optional": [{ "id": "fs.read", "paths": ["/srv/data"] }]
            }
        }));
        let lines = summarize(&m);
        assert_eq!(lines[1].reason.as_deref(), Some("to sync"));
        let texts: Vec<String> = lines.into_iter().map(|l| l.text).collect();
        assert_eq!(
            texts,
            [
                "Reads files you select",
                "Connects to api.example.com",
                "Can run /opt/homebrew/bin/ffmpeg with your full user permissions",
                "Connects to 10.0.0.1 (unencrypted or a raw IP address)",
                "May ask to: reads files in /srv/data",
            ]
        );
    }

    #[test]
    fn home_is_shortened() {
        let home = std::env::var("HOME").unwrap_or_default();
        if !home.is_empty() && home != "/" {
            assert_eq!(display_path(&format!("{home}/Documents")), "~/Documents");
        }
        assert!(is_raw_ip("[::1]:8080") && is_raw_ip("1.2.3.4:80") && !is_raw_ip("a.b"));
    }
}
