pub mod broker;

mod builder;
mod commands;
mod context;
mod error;
mod events;
mod kernel;
mod permissions;
mod plugins;
mod protocol;
mod registrations;
mod registry;
mod schema;
mod secrets;
mod settings;
mod storage;

pub use atomo_manifest;
pub use broker::{
    AuditEntry, Binding, Broker, Decision, Grant, GrantKind, GrantLease, PermissionSummary,
    Principal, PromptDecision, PromptRequest, RightChecker, Scope, SecretStore,
};
pub use builder::KernelBuilder;
pub use commands::{ExecuteParams, Invocation, InvocationSource};
pub use error::{ErrorCode, KernelError, KernelResult};
pub use events::{Event, EventBus, EventMessage, Subscription};
pub use kernel::{Bootstrap, Kernel, KernelConfig};
pub use plugins::{ActivationContext, NativePlugin, PluginReloaded, ReloadReason, RuntimeHost};
pub use protocol::{CallCancellation, CallContext, Caller, EventSink, Visibility};
pub use registry::{
    CommandInfo, Contribution, ExtensionPointInfo, PluginInfo, PluginState, RegistrySnapshot,
    SettingInfo, Tier,
};
pub use schema::Schema;
pub use settings::{SaveSettingsParams, SaveSettingsResult};
pub use storage::PluginStorage;

#[cfg(test)]
mod tests;
