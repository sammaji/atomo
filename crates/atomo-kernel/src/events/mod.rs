//! Events: the bus, publishing within a plugin's own namespace, and
//! subscription streams over the protocol.

mod bus;
mod subscriptions;

use serde_json::Value;

pub use bus::{Event, EventBus, EventMessage, Subscription};
pub(crate) use subscriptions::Subscriptions;

use crate::{Kernel, KernelError, KernelResult};

impl Kernel {
    /// Publish an event as `plugin`. Plugins may only publish in their own
    /// namespace (`<id>.*`, or `<short>.*` for first-party `atomo.<short>`).
    pub fn publish(&self, plugin: &str, topic: &str, payload: Value) -> KernelResult<()> {
        let owns = self
            .registry_state()
            .manifests
            .get(plugin)
            .is_some_and(|m| m.owns_name(topic));
        if !owns {
            return Err(KernelError::forbidden(format!(
                "`{plugin}` may not publish `{topic}`"
            )));
        }
        self.0.events.emit(plugin, topic, payload);
        Ok(())
    }

    pub(crate) fn emit_kernel(&self, topic: &str, payload: Value) {
        self.0.events.emit("kernel", topic, payload);
    }
}
