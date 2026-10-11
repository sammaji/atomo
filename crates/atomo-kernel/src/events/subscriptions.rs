//! Event streams opened over the protocol (`events.subscribe`, and streamed
//! calls), each cancellable by the caller that opened it.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};

use parking_lot::Mutex;
use tokio_util::sync::CancellationToken;

use super::EventMessage;
use crate::broker::Principal;
use crate::{CallContext, Caller, Kernel, KernelError, KernelResult};

/// A live stream.
struct Entry {
    /// The plugin that opened it; `None` for the shell.
    owner: Option<String>,
    cancel: CancellationToken,
}

pub(crate) struct Subscriptions {
    entries: Mutex<HashMap<u32, Entry>>,
    next: AtomicU32,
}

impl Default for Subscriptions {
    fn default() -> Self {
        Subscriptions {
            entries: Default::default(),
            next: AtomicU32::new(1),
        }
    }
}

impl Subscriptions {
    /// Track a stream `caller` may cancel; returns its subscription ID.
    pub fn open(&self, caller: &Caller, cancel: CancellationToken) -> u32 {
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        self.entries.lock().insert(
            id,
            Entry {
                owner: caller.plugin().map(str::to_owned),
                cancel,
            },
        );
        id
    }

    pub fn forget(&self, id: u32) {
        self.entries.lock().remove(&id);
    }
}

impl Kernel {
    /// Stream events matching `topics` to the call's sink until the caller
    /// unsubscribes. What a plugin receives is filtered by its grants.
    pub(crate) fn subscribe_events(
        &self,
        call: CallContext,
        topics: Vec<String>,
    ) -> KernelResult<u32> {
        let sink = call
            .sink
            .ok_or_else(|| KernelError::invalid_params("events.subscribe needs a channel"))?;
        let cancel = CancellationToken::new();
        let id = self.0.subscriptions.open(&call.caller, cancel.clone());
        let mut sub = self.0.events.subscribe(topics);
        let filter = match &call.caller {
            Caller::Plugin(id) => Some((self.0.broker.clone(), Principal::Plugin(id.clone()))),
            _ => None,
        };
        self.0.runtime.spawn(async move {
            loop {
                tokio::select! {
                    msg = sub.recv() => match msg {
                        Some(EventMessage::Event { event }) => {
                            let event = match &filter {
                                Some((broker, who)) => broker.filter_event(who, &event),
                                None => Some(event),
                            };
                            if let Some(event) = event {
                                sink(serde_json::to_value(EventMessage::Event { event }).expect("events serialize"));
                            }
                        }
                        Some(msg) => sink(serde_json::to_value(msg).expect("events serialize")),
                        None => break,
                    },
                    _ = cancel.cancelled() => break,
                }
            }
        });
        Ok(id)
    }

    /// Cancel a stream. A plugin may only cancel its own streams; the shell
    /// may cancel any. An unknown ID is not an error.
    pub(crate) fn unsubscribe(&self, caller: &Caller, id: u32) -> KernelResult<()> {
        let mut entries = self.0.subscriptions.entries.lock();
        let allowed = match (entries.get(&id), caller.plugin()) {
            (Some(entry), Some(caller)) => entry.owner.as_deref() == Some(caller),
            (Some(_), None) => true,
            (None, _) => return Ok(()),
        };
        if !allowed {
            return Err(KernelError::forbidden("not your subscription"));
        }
        if let Some(entry) = entries.remove(&id) {
            entry.cancel.cancel();
        }
        Ok(())
    }
}
