//! Which plugins are running a command the user just invoked: some acts
//! (signing in, which opens the browser) are allowed only then.

use std::time::{Duration, Instant};

use super::Broker;

/// An invocation the shell never ends stops counting after this long.
pub const USER_INVOCATION_TTL: Duration = Duration::from_secs(600);

impl Broker {
    /// A gesture-invoked command of `plugin` started (`id` ends it).
    pub(crate) fn begin_user_invocation(&self, id: &str, plugin: &str) {
        let mut live = self.0.user_invocations.lock();
        live.retain(|_, (_, started)| started.elapsed() < USER_INVOCATION_TTL);
        live.insert(id.to_owned(), (plugin.to_owned(), Instant::now()));
    }

    pub(crate) fn end_user_invocation(&self, id: &str) {
        self.0.user_invocations.lock().remove(id);
    }

    /// Is a command of `plugin` that the user invoked running right now?
    pub fn in_user_invocation(&self, plugin: &str) -> bool {
        self.0
            .user_invocations
            .lock()
            .values()
            .any(|(p, started)| p == plugin && started.elapsed() < USER_INVOCATION_TTL)
    }
}
