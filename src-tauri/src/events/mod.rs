use std::sync::Arc;
use std::time::Duration;

use tokio::sync::mpsc;

use crate::vfs::types::{FsEvent, FsEventKind};
use crate::vfs::uri::VfsUri;

/// time in ms we wait for another event before emitting a batch
/// this is to avoid emitting too many events at once
const COALESCE_WINDOW: Duration = Duration::from_millis(50);

/// max number of events in a batch
const MAX_BATCH_SIZE: usize = 500;

pub type EmitFn = Arc<dyn Fn(Vec<FsEvent>) + Send + Sync>;

/// Delivers `FsEvent`s to the webview, coalesced. Kept narrow (`emit_fs`) and
/// in its own module (not inside `vfs/`) since later milestones add more topics.
#[derive(Clone)]
pub struct EventBus {
    tx: mpsc::UnboundedSender<FsEvent>,
}

impl EventBus {
    /// `emit` is abstracted so tests can inject a collector instead of a real
    /// webview emitter.
    pub fn new(emit: EmitFn) -> Self {
        let (tx, mut rx) = mpsc::unbounded_channel::<FsEvent>();

        // `tauri::async_runtime::spawn` rather than `tokio::spawn`: this runs
        // before the Tauri app is built, when there is no ambient tokio
        // reactor yet (Tauri lazily owns its own runtime).
        tauri::async_runtime::spawn(async move {
            loop {
                let first = match rx.recv().await {
                    Some(e) => e,
                    None => break,
                };
                let mut batch = vec![first];
                let deadline = tokio::time::sleep(COALESCE_WINDOW);
                tokio::pin!(deadline);
                loop {
                    tokio::select! {
                        _ = &mut deadline => break,
                        maybe = rx.recv() => match maybe {
                            Some(e) => {
                                batch.push(e);
                                if batch.len() >= MAX_BATCH_SIZE * 2 {
                                    break;
                                }
                            }
                            None => break,
                        }
                    }
                }
                emit(coalesce(batch));
            }
        });
        EventBus { tx }
    }

    pub fn emit_fs(&self, event: FsEvent) {
        let _ = self.tx.send(event);
    }
}

fn coalesce(events: Vec<FsEvent>) -> Vec<FsEvent> {
    if events.len() > MAX_BATCH_SIZE {
        let mut roots: Vec<VfsUri> = Vec::new();
        for ev in &events {
            let root = ev.uri.parent().unwrap_or_else(|| ev.uri.clone());
            if !roots.contains(&root) {
                roots.push(root);
            }
        }
        return roots
            .into_iter()
            .map(|uri| FsEvent {
                kind: FsEventKind::Overflow,
                uri,
                renamed_to: None,
            })
            .collect();
    }

    let mut out: Vec<FsEvent> = Vec::new();
    for ev in events {
        let is_duplicate = out
            .iter()
            .any(|o| o.kind == ev.kind && o.uri == ev.uri && o.renamed_to == ev.renamed_to);
        if is_duplicate {
            continue;
        }
        if ev.kind == FsEventKind::Removed {
            if let Some(pos) = out
                .iter()
                .position(|o| o.kind == FsEventKind::Created && o.uri == ev.uri)
            {
                out.remove(pos);
            }
        }
        out.push(ev);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use std::time::Duration as StdDuration;

    fn collector() -> (EmitFn, Arc<Mutex<Vec<Vec<FsEvent>>>>) {
        let batches = Arc::new(Mutex::new(Vec::new()));
        let batches2 = batches.clone();
        let emit: EmitFn = Arc::new(move |b| batches2.lock().unwrap().push(b));
        (emit, batches)
    }

    fn uri(s: &str) -> VfsUri {
        VfsUri::parse(s).unwrap()
    }

    #[tokio::test]
    async fn dedupes_and_batches() {
        let (emit, batches) = collector();
        let bus = EventBus::new(emit);
        bus.emit_fs(FsEvent {
            kind: FsEventKind::Modified,
            uri: uri("file:///a"),
            renamed_to: None,
        });
        bus.emit_fs(FsEvent {
            kind: FsEventKind::Modified,
            uri: uri("file:///a"),
            renamed_to: None,
        });
        tokio::time::sleep(StdDuration::from_millis(150)).await;
        let got = batches.lock().unwrap().clone();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].len(), 1);
    }

    #[tokio::test]
    async fn created_then_removed_collapses_to_removed() {
        let (emit, batches) = collector();
        let bus = EventBus::new(emit);
        bus.emit_fs(FsEvent {
            kind: FsEventKind::Created,
            uri: uri("file:///a"),
            renamed_to: None,
        });
        bus.emit_fs(FsEvent {
            kind: FsEventKind::Removed,
            uri: uri("file:///a"),
            renamed_to: None,
        });
        tokio::time::sleep(StdDuration::from_millis(150)).await;
        let got = batches.lock().unwrap().clone();
        assert_eq!(got[0].len(), 1);
        assert_eq!(got[0][0].kind, FsEventKind::Removed);
    }
}
