//! Commands: what an invocation carries, the handlers plugins bind, and
//! executing them with the right intent grants.

mod execute;
mod invocations;

use std::future::Future;
use std::sync::Arc;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use ts_rs::TS;

pub(crate) use invocations::Invocations;

use crate::protocol::BoxFuture;
use crate::{KernelError, KernelResult};

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
