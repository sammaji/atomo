//! Consent prompts: a request the shell's trusted UI answers, or that times
//! out as "deny".

use serde_json::{json, Value};
use tokio::sync::oneshot;

use super::summary::{self, LineKind};
use super::{
    forbidden, now_ms, Binding, Broker, Grant, GrantKind, Principal, PromptDecision, PromptRequest,
    Scope, ONCE_TTL,
};
use crate::{KernelError, KernelResult};

impl Broker {
    pub(super) async fn prompt(
        &self,
        principal: &Principal,
        right: &str,
        resources: Vec<String>,
        sensitive: bool,
    ) -> KernelResult<()> {
        let plugin = principal.to_string();
        let facts = principal.plugin().and_then(|p| self.facts(p));
        let checker = self.checker(right);
        let declared = facts.as_ref().and_then(|f| {
            f.manifest
                .permissions
                .optional
                .iter()
                .find(|p| p.get("id").and_then(Value::as_str) == Some(right))
                .cloned()
        });
        let shown: Vec<String> = resources
            .iter()
            .map(|r| checker.as_ref().map_or(r.clone(), |c| c.display(right, r)))
            .collect();
        let text = summary::describe_permission(
            &json!({ "id": right, "paths": shown, "hosts": shown, "binaries": shown }),
            LineKind::Required,
        )
        .text;
        let text = match right {
            "fs.read" | "fs.write" | "fs.create" | "net" | "exec" => text,
            _ => summary::describe_permission(&json!({ "id": right }), LineKind::Required).text,
        };
        let id = self.next_id('p');
        let request = PromptRequest {
            prompt_id: id.clone(),
            plugin: plugin.clone(),
            display_name: facts
                .as_ref()
                .map_or(plugin.clone(), |f| f.manifest.display_name.clone()),
            tier: facts.as_ref().map(|f| f.tier),
            right: right.to_owned(),
            resources: resources.clone(),
            text,
            reason: declared
                .and_then(|p| p.get("reason").and_then(Value::as_str).map(str::to_owned)),
            sensitive,
            created_ms: now_ms(),
        };
        let (tx, rx) = oneshot::channel();
        self.0
            .prompts
            .lock()
            .insert(id.clone(), (request.clone(), tx));
        self.0.events.emit(
            "kernel",
            "broker.promptRequested",
            serde_json::to_value(&request).unwrap_or_default(),
        );
        let timeout = *self.0.prompt_timeout.read();
        let answer = tokio::time::timeout(timeout, rx).await;
        self.0.prompts.lock().remove(&id);
        let (decision, word) = match answer {
            Ok(Ok(d)) => (
                d,
                match d {
                    PromptDecision::Once => "allowOnce",
                    PromptDecision::Always => "allowAlways",
                    PromptDecision::Deny => "denied",
                },
            ),
            _ => (PromptDecision::Deny, "timeout"),
        };
        self.0.events.emit(
            "kernel",
            "broker.promptResolved",
            json!({ "promptId": id, "decision": word }),
        );
        for r in &resources {
            self.audit(&plugin, right, r, word, None, Some("prompt"));
        }
        match decision {
            PromptDecision::Deny => Err(forbidden(if word == "timeout" {
                format!("no answer to {plugin}'s request for `{right}`")
            } else {
                format!("the user denied {plugin} `{right}`")
            })),
            PromptDecision::Once => {
                let expires = now_ms() + ONCE_TTL.as_millis() as f64;
                let mut intents = self.0.intents.write();
                for r in &resources {
                    intents.push(Grant {
                        id: self.next_id('i'),
                        principal: plugin.clone(),
                        right: right.to_owned(),
                        scope: Scope::Exact(r.clone()),
                        kind: GrantKind::Intent,
                        source: "prompt".into(),
                        binding: Binding::Timed,
                        overrides_denylist: sensitive,
                        created_ms: now_ms(),
                        expires_ms: Some(expires),
                        reason: None,
                    });
                }
                drop(intents);
                self.grants_changed(&plugin);
                Ok(())
            }
            PromptDecision::Always => {
                for r in &resources {
                    let scope = checker
                        .as_ref()
                        .map_or(Scope::Exact(r.clone()), |c| c.remember_scope(right, r));
                    self.grant_standing(principal, right, scope, "prompt", sensitive)?;
                }
                Ok(())
            }
        }
    }

    /// Answer a pending prompt (only the shell's trusted UI calls this).
    pub fn respond(&self, prompt_id: &str, decision: PromptDecision) -> KernelResult<()> {
        let (_, tx) = self
            .0
            .prompts
            .lock()
            .remove(prompt_id)
            .ok_or_else(|| KernelError::not_found(format!("no pending prompt {prompt_id}")))?;
        let _ = tx.send(decision);
        Ok(())
    }

    /// Prompts waiting for an answer (for a consent UI that starts late).
    pub fn pending_prompts(&self) -> Vec<PromptRequest> {
        let mut out: Vec<PromptRequest> = self
            .0
            .prompts
            .lock()
            .values()
            .map(|(r, _)| r.clone())
            .collect();
        out.sort_by(|a, b| a.created_ms.total_cmp(&b.created_ms));
        out
    }
}
