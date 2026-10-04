use std::future::Future;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use atomo_manifest::Half;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use ts_rs::TS;

use crate::broker::{Binding, GrantLease, Principal};
use crate::call::BoxFuture;
use crate::{ErrorCode, Kernel, KernelError, KernelResult, PluginState};

/// Where a command invocation came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export)]
pub enum InvocationSource {
    Menu,
    Keybinding,
    Palette,
    Toolbar,
    /// Double-click or drag-and-drop on an item.
    Pointer,
    Plugin,
}

impl InvocationSource {
    /// Sources that can carry a trusted user gesture (only when the shell says so).
    pub(crate) fn is_gesture(self) -> bool {
        matches!(
            self,
            Self::Menu | Self::Keybinding | Self::Palette | Self::Toolbar | Self::Pointer
        )
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Menu => "menu",
            Self::Keybinding => "keybinding",
            Self::Palette => "palette",
            Self::Toolbar => "toolbar",
            Self::Pointer => "pointer",
            Self::Plugin => "plugin",
        }
    }
}

/// What a command handler receives besides its arguments.
#[derive(Debug, Clone, Serialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export)]
pub struct Invocation {
    pub source: InvocationSource,
    /// True only for menus, keybindings, the palette, toolbars and pointer
    /// gestures, from the shell. Intent grants are minted from these and
    /// nothing else.
    pub trusted_gesture: bool,
    /// `user`, or the ID of the plugin that executed the command.
    pub caller: String,
    pub window: Option<String>,
    /// Canonical URIs in scope (usually the selection).
    pub resources: Vec<String>,
}

/// `commands.execute` (shell → kernel).
#[derive(Debug, Clone, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export)]
pub struct ExecuteParams {
    pub id: String,
    #[serde(default)]
    #[ts(type = "unknown")]
    pub args: Value,
    pub source: InvocationSource,
    #[serde(default)]
    pub resources: Vec<String>,
    #[serde(default)]
    pub window: Option<String>,
    /// Set when a frontend half (not the user) executes the command.
    #[serde(default)]
    pub caller_plugin: Option<String>,
}

pub(crate) type CommandHandler =
    Arc<dyn Fn(Invocation, Value) -> BoxFuture<KernelResult<Value>> + Send + Sync>;

pub(crate) struct CommandEntry {
    pub owner: String,
    pub handler: CommandHandler,
}

/// `null` arguments mean "no arguments", which schemas see as `{}`.
fn object_if_null(args: Value) -> Value {
    if args.is_null() {
        Value::Object(Default::default())
    } else {
        args
    }
}

pub(crate) fn typed_command<P, R, F, Fut>(handler: F) -> CommandHandler
where
    P: DeserializeOwned + Send + 'static,
    R: Serialize + 'static,
    F: Fn(Invocation, P) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = KernelResult<R>> + Send + 'static,
{
    let handler = Arc::new(handler);
    Arc::new(move |inv, args| {
        let handler = handler.clone();
        Box::pin(async move {
            let args: P = serde_json::from_value(object_if_null(args))
                .map_err(|e| KernelError::invalid_params(e.to_string()))?;
            let result = handler(inv, args).await?;
            serde_json::to_value(result).map_err(|e| KernelError::internal(e.to_string()))
        })
    })
}

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
                let owner = self.0.commands.read().get(id).map(|c| c.owner.clone());
                match owner {
                    Some(p) if p == invocation.caller => p,
                    _ => return Err(KernelError::not_found(format!("no such command: {id}"))),
                }
            }
        };
        if self.plugin_state(&owner) != Some(PluginState::Active) {
            self.activate(&owner)?;
        }
        let handler = self
            .0
            .commands
            .read()
            .get(id)
            .map(|c| c.handler.clone())
            .ok_or_else(|| {
                KernelError::new(
                    ErrorCode::NotRegistered,
                    format!("`{owner}` declares `{id}` but registered no handler"),
                )
            })?;
        // Intent grants live exactly as long as the handler runs.
        let _lease = self.intent_lease(&owner, &access, &invocation);
        handler(invocation, args).await
    }

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
        let n = self.0.next_invocation.fetch_add(1, Ordering::Relaxed);
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
