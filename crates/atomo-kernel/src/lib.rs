//! The microkernel.
//!
//! It builds the registry from manifests, runs plugin lifecycles and hosts what
//! every plugin uses — services, protocol methods, commands, events, settings,
//! context keys, storage and the capability broker.

pub mod broker;
mod builder;
mod call;
mod command;
mod context;
mod error;
mod events;
mod kernel;
mod lifecycle;
mod methods;
mod plugin;
mod registry;
mod schema;
mod settings;
mod storage;
mod stream;

pub use atomo_manifest;
pub use broker::{
    AuditEntry, Binding, Broker, Decision, Grant, GrantKind, GrantLease, PermissionSummary,
    Principal, PromptDecision, PromptRequest, RightChecker, Scope, SecretStore,
};
pub use builder::KernelBuilder;
pub use call::{CallContext, Caller, EventSink, Visibility};
pub use command::{ExecuteParams, Invocation, InvocationSource};
pub use error::{ErrorCode, KernelError, KernelResult};
pub use events::{topic_matches, Event, EventBus, EventMessage, Subscription};
pub use kernel::{platform_os, Bootstrap, Kernel, KernelConfig};
pub use lifecycle::{PluginReloaded, ReloadReason};
pub use plugin::{ActivationContext, NativePlugin, RuntimeHost};
pub use registry::{
    CommandInfo, Contribution, ExtensionPointInfo, PluginInfo, PluginState, RegistrySnapshot,
    SettingInfo, Tier,
};
pub use schema::Schema;
pub use settings::{SaveSettingsParams, SaveSettingsResult};
pub use storage::PluginStorage;
pub use stream::CallCancellation;
pub use tokio;
pub use tokio_util;

#[cfg(test)]
mod tests;
