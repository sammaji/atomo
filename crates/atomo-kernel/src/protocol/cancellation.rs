//! Stopping long-running methods that stream progress to their caller.

use std::sync::{Arc, Weak};

use serde_json::json;
use tokio_util::sync::CancellationToken;

use super::CallContext;
use crate::kernel::Inner;
use crate::Kernel;

/// The cancellation of one streamed call. When the call has a sink, its
/// first message is `{ "type": "started", "subscriptionId" }` and
/// `events.unsubscribe { subscriptionId }` (by the same caller) cancels
/// [`CallCancellation::token`]. Dropping it (the call finished or its future
/// was dropped) cancels the token too and forgets the subscription.
pub struct CallCancellation {
    kernel: Weak<Inner>,
    id: Option<u32>,
    token: CancellationToken,
}

impl CallCancellation {
    pub fn token(&self) -> &CancellationToken {
        &self.token
    }
}

impl Drop for CallCancellation {
    fn drop(&mut self) {
        self.token.cancel();
        if let (Some(id), Some(inner)) = (self.id, self.kernel.upgrade()) {
            inner.subscriptions.forget(id);
        }
    }
}

impl Kernel {
    /// Make `call` cancellable by its caller (see [`CallCancellation`]).
    pub fn call_cancellation(&self, call: &CallContext) -> CallCancellation {
        let token = CancellationToken::new();
        let Some(sink) = &call.sink else {
            return CallCancellation {
                kernel: Weak::new(),
                id: None,
                token,
            };
        };
        let id = self.0.subscriptions.open(&call.caller, token.clone());
        sink(json!({ "type": "started", "subscriptionId": id }));
        CallCancellation {
            kernel: Arc::downgrade(&self.0),
            id: Some(id),
            token,
        }
    }
}
