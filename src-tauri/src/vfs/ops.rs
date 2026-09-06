use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use super::error::VfsError;
use super::types::OpProgress;
use super::uri::VfsUri;

/// Minimal precursor of the future job scheduler: tracks cancellation tokens
/// for in-flight ops, keyed by client-generated `op_id`.
#[derive(Clone)]
pub struct OpRegistry {
    inner: Arc<Mutex<HashMap<Uuid, CancellationToken>>>,
}

impl Default for OpRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl OpRegistry {
    pub fn new() -> Self {
        OpRegistry {
            inner: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Registers a new op and returns its cancellation token plus a guard
    /// that removes the registration on drop (so panics still clean up).
    pub fn start(&self, id: Uuid) -> (CancellationToken, OpGuard) {
        let ct = CancellationToken::new();
        self.inner.lock().unwrap().insert(id, ct.clone());
        (
            ct,
            OpGuard {
                id,
                registry: self.clone(),
            },
        )
    }

    /// Cancelling an unknown/finished op is a silent no-op.
    pub fn cancel(&self, id: Uuid) {
        if let Some(ct) = self.inner.lock().unwrap().get(&id) {
            ct.cancel();
        }
    }

    fn finish(&self, id: Uuid) {
        self.inner.lock().unwrap().remove(&id);
    }

    #[cfg(test)]
    pub fn contains(&self, id: Uuid) -> bool {
        self.inner.lock().unwrap().contains_key(&id)
    }
}

pub struct OpGuard {
    id: Uuid,
    registry: OpRegistry,
}

impl Drop for OpGuard {
    fn drop(&mut self) {
        self.registry.finish(self.id);
    }
}

const THROTTLE_MIN_MS: u128 = 100;
const THROTTLE_MIN_BYTES: u64 = 64 * 1024;

pub struct OpCtx {
    pub id: Uuid,
    pub ct: CancellationToken,
    progress: Box<dyn Fn(OpProgress) + Send + Sync>,
    last_emit: Mutex<(Instant, u64)>,
}

impl OpCtx {
    pub fn new(
        id: Uuid,
        ct: CancellationToken,
        progress: impl Fn(OpProgress) + Send + Sync + 'static,
    ) -> Self {
        OpCtx {
            id,
            ct,
            progress: Box::new(progress),
            last_emit: Mutex::new((Instant::now(), 0)),
        }
    }

    pub fn is_cancelled(&self) -> bool {
        self.ct.is_cancelled()
    }

    pub fn check_cancelled(&self) -> Result<(), VfsError> {
        if self.is_cancelled() {
            Err(VfsError::Cancelled)
        } else {
            Ok(())
        }
    }

    /// Throttled to ~30 msg/s: emits when >=100ms have passed, >=64KiB of new
    /// progress has accumulated, or the operation just completed.
    pub fn report(
        &self,
        done_bytes: u64,
        total_bytes: u64,
        done_files: u64,
        total_files: u64,
        current: Option<VfsUri>,
    ) {
        let mut last = self.last_emit.lock().unwrap();
        let elapsed_ms = last.0.elapsed().as_millis();
        let byte_delta = done_bytes.saturating_sub(last.1);
        let done = done_bytes >= total_bytes && done_files >= total_files;
        if elapsed_ms >= THROTTLE_MIN_MS || byte_delta >= THROTTLE_MIN_BYTES || done {
            (self.progress)(OpProgress {
                op_id: self.id,
                done_bytes,
                total_bytes,
                done_files,
                total_files,
                current,
            });
            *last = (Instant::now(), done_bytes);
        }
    }
}
