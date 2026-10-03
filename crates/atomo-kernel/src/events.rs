//! The event bus, used to send notification.
//!
//! One bounded broadcast channel; subscribers filter by topic prefix. A slow
//! subscriber gets a `lagged` signal instead of an unbounded queue. Ownership of
//! topics is checked by [`crate::Kernel::publish`], not here.

use std::sync::Arc;

use serde::Serialize;
use serde_json::Value;
use tokio::sync::broadcast;
use ts_rs::TS;

const CAPACITY: usize = 1024;

#[derive(Debug, Clone, Serialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export)]
pub struct Event {
    pub topic: String,
    /// The plugin that published it (`kernel` for kernel topics).
    pub source: String,
    #[ts(type = "unknown")]
    pub payload: Value,
}

/// What a subscription Channel carries.
#[derive(Debug, Clone, Serialize, TS)]
#[serde(tag = "type", rename_all = "camelCase")]
#[ts(export)]
pub enum EventMessage {
    Event {
        event: Event,
    },
    /// Events were dropped because the subscriber fell behind.
    Lagged {
        missed: u64,
    },
}

#[derive(Clone)]
pub struct EventBus {
    tx: broadcast::Sender<Arc<Event>>,
}

impl Default for EventBus {
    fn default() -> Self {
        Self {
            tx: broadcast::channel(CAPACITY).0,
        }
    }
}

impl EventBus {
    pub(crate) fn emit(&self, source: &str, topic: &str, payload: Value) {
        // No receivers is fine.
        let _ = self.tx.send(Arc::new(Event {
            topic: topic.to_owned(),
            source: source.to_owned(),
            payload,
        }));
    }

    pub fn subscribe(&self, prefixes: Vec<String>) -> Subscription {
        Subscription {
            rx: self.tx.subscribe(),
            prefixes,
        }
    }
}

/// `true` if `topic` is `prefix` or starts with `prefix.`; `""` and `*` match everything.
pub fn topic_matches(prefix: &str, topic: &str) -> bool {
    prefix.is_empty() || prefix == "*" || atomo_manifest::has_prefix(topic, prefix)
}

pub struct Subscription {
    rx: broadcast::Receiver<Arc<Event>>,
    prefixes: Vec<String>,
}

impl Subscription {
    /// The next matching event or lag notice; `None` when the bus is gone.
    pub async fn recv(&mut self) -> Option<EventMessage> {
        loop {
            match self.rx.recv().await {
                Ok(event) => {
                    if self.prefixes.iter().any(|p| topic_matches(p, &event.topic)) {
                        return Some(EventMessage::Event {
                            event: (*event).clone(),
                        });
                    }
                }
                Err(broadcast::error::RecvError::Lagged(missed)) => {
                    return Some(EventMessage::Lagged { missed })
                }
                Err(broadcast::error::RecvError::Closed) => return None,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[tokio::test]
    async fn prefix_filtering() {
        let bus = EventBus::default();
        let mut sub = bus.subscribe(vec!["vfs".into()]);
        bus.emit("atomo.ops", "ops.completed", json!(1));
        bus.emit("atomo.vfs", "vfs.changed", json!(2));
        bus.emit("atomo.vfs", "vfsx.other", json!(3));
        match sub.recv().await.unwrap() {
            EventMessage::Event { event } => assert_eq!(event.payload, json!(2)),
            other => panic!("{other:?}"),
        }
        assert!(topic_matches("", "a.b"));
        assert!(!topic_matches("a.b", "a.bc"));
    }
}
