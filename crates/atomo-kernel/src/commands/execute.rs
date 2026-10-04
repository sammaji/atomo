//! Executing a command: who is invoking it, validating its arguments,
//! activating its plugin, and the intent grants its handler runs with.

use atomo_manifest::Half;
use serde_json::Value;

use super::{object_if_null, ExecuteParams, Invocation, InvocationSource};
use crate::broker::{Binding, GrantLease, Principal};
use crate::{Caller, ErrorCode, Kernel, KernelError, KernelResult, PluginState};

impl Kernel {
    /// Execute a command. `invocation.caller` is `user` or a plugin ID.
    pub async fn execute_command(
        &self,
        id: &str,
        args: Value,
        invocation: Invocation,
    ) -> KernelResult<Value> {
        let registry = self.0.registry.load_full();
        let declared = registry.snapshot.command(id);
        let access = declared.map(|c| c.decl.access.clone()).unwrap_or_default();
        let owner = match declared {
            Some(info) => {
                if info.half == Half::Frontend {
                    return Err(KernelError::new(
                        ErrorCode::FrontendCommand,
                        format!("`{id}` is implemented by a frontend half; the shell runs it"),
                    ));
                }
                if let Some(schema) = registry.schemas.get(&format!("command:{id}")) {
                    schema
                        .validate(&object_if_null(args.clone()))
                        .map_err(|e| KernelError::invalid_params(format!("{id}: {e}")))?;
                }
                info.plugin.clone()
            }
            None => {
                // Undeclared commands are private to their plugin.
                match self.0.registrations.command_owner(id) {
                    Some(p) if p == invocation.caller => p,
                    _ => return Err(KernelError::not_found(format!("no such command: {id}"))),
                }
            }
        };
        if self.plugin_state(&owner) != Some(PluginState::Active) {
            self.activate(&owner)?;
        }
        let handler = self.0.registrations.command_handler(id).ok_or_else(|| {
            KernelError::new(
                ErrorCode::NotRegistered,
                format!("`{owner}` declares `{id}` but registered no handler"),
            )
        })?;
        // Intent grants live exactly as long as the handler runs.
        let _lease = self.intent_lease(&owner, &access, &invocation);
        handler(invocation, args).await
    }

    /// Execute a command for a protocol caller. Only the shell's own
    /// invocations can be user gestures; a plugin caller is always attributed.
    pub(crate) async fn execute_for(
        &self,
        caller: &Caller,
        p: ExecuteParams,
    ) -> KernelResult<Value> {
        let (caller, source, trusted) = match (caller, &p.caller_plugin) {
            // The bridge's identity wins over anything the plugin claims.
            (Caller::Plugin(plugin), _) | (Caller::Shell, Some(plugin)) => {
                (plugin.clone(), InvocationSource::Plugin, false)
            }
            (Caller::Shell, None) => ("user".to_owned(), p.source, p.source.is_gesture()),
        };
        // No amplification: a plugin passes along only resources it already holds grants for.
        let principal = Principal::parse(&caller);
        if !principal.has_user_authority() {
            if let Some(r) = p
                .resources
                .iter()
                .find(|r| !self.0.broker.holds(&principal, r))
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
        self.execute_command(&p.id, p.args, invocation).await
    }

    /// The intent grants `owner`'s handler gets for `inv`: minted from a
    /// trusted user gesture, delegated from a plugin caller, otherwise none.
    pub(crate) fn intent_lease(
        &self,
        owner: &str,
        access: &[String],
        inv: &Invocation,
    ) -> Option<GrantLease> {
        if access.is_empty() || inv.resources.is_empty() {
            return None;
        }
        let broker = &self.0.broker;
        if broker.is_trusted(&Principal::Plugin(owner.to_owned())) {
            return None; // core-tier handlers act with the caller's principal
        }
        let n = self.0.invocations.next_number();
        let binding = Binding::Invocation(format!("{owner}#{n}"));
        let caller = Principal::parse(&inv.caller);
        if caller == Principal::User && inv.trusted_gesture {
            Some(broker.mint(owner, access, &inv.resources, binding, inv.source.as_str()))
        } else if !caller.has_user_authority() {
            Some(broker.delegate(&caller, owner, access, &inv.resources, binding))
        } else {
            None
        }
    }
}
