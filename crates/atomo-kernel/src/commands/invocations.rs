//! Frontend command invocations. Frontend commands run in the shell (or a
//! sandbox), so the shell brackets a gesture-invoked one with begin/end and
//! the kernel holds its intent grants in between.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use parking_lot::Mutex;

use super::{Invocation, InvocationSource};
use crate::broker::GrantLease;
use crate::{Caller, Kernel, KernelError, KernelResult};

/// A frontend command invocation the shell never ends still releases its
/// grants after this long.
const FRONTEND_INVOCATION_TTL: Duration = Duration::from_secs(600);

#[derive(Default)]
pub(crate) struct Invocations {
    /// Numbers command invocations (intent-grant bindings).
    next: AtomicU64,
    /// Intent grants of frontend command invocations the shell runs itself.
    frontend: Mutex<HashMap<String, GrantLease>>,
}

impl Invocations {
    pub fn next_number(&self) -> u64 {
        self.next.fetch_add(1, Ordering::Relaxed)
    }
}

impl Kernel {
    /// Start a gesture-invoked frontend command: mint its declared access
    /// and mark its plugin as running a user invocation. Returns the
    /// invocation ID that ends it.
    pub(crate) fn begin_frontend_invocation(
        &self,
        caller: &Caller,
        command: &str,
        source: InvocationSource,
        resources: Vec<String>,
    ) -> KernelResult<String> {
        if *caller != Caller::Shell || !source.is_gesture() {
            return Err(KernelError::forbidden(
                "only the shell's trusted gestures mint intent grants",
            ));
        }
        let info = self
            .registry()
            .command(command)
            .cloned()
            .ok_or_else(|| KernelError::not_found(format!("no such command: {command}")))?;
        let invocation = Invocation {
            source,
            trusted_gesture: true,
            caller: "user".into(),
            window: None,
            resources,
        };
        let lease = self.intent_lease(&info.plugin, &info.decl.access, &invocation);
        let id = format!("fi{}", self.0.invocations.next_number());
        self.0.broker.begin_user_invocation(&id, &info.plugin);
        if let Some(lease) = lease {
            self.0.invocations.frontend.lock().insert(id.clone(), lease);
            let (kernel, id) = (self.clone(), id.clone());
            self.0.runtime.spawn(async move {
                tokio::time::sleep(FRONTEND_INVOCATION_TTL).await;
                kernel.0.invocations.frontend.lock().remove(&id);
            });
        }
        Ok(id)
    }

    pub(crate) fn end_frontend_invocation(&self, id: &str) {
        self.0.invocations.frontend.lock().remove(id);
        self.0.broker.end_user_invocation(id);
    }
}
