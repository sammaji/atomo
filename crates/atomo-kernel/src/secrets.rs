//! The secrets API: each plugin reads and writes only secrets under its own ID.

use crate::broker::Principal;
use crate::{Caller, Kernel, KernelError, KernelResult};

/// Whose secrets a call acts on: a bridged plugin's own, or the plugin the
/// shell names for an in-realm frontend.
fn secret_principal(caller: &Caller, claimed: Option<String>) -> KernelResult<Principal> {
    match (caller, claimed) {
        (Caller::Plugin(id), _) => Ok(Principal::Plugin(id.clone())),
        (_, Some(id)) => Ok(Principal::Plugin(id)),
        _ => Err(KernelError::invalid_params("missing `plugin`")),
    }
}

impl Kernel {
    pub(crate) fn secret_get(
        &self,
        caller: &Caller,
        plugin: Option<String>,
        key: &str,
    ) -> KernelResult<Option<String>> {
        let who = secret_principal(caller, plugin)?;
        self.0.broker.secret_get(&who, key)
    }

    pub(crate) fn secret_set(
        &self,
        caller: &Caller,
        plugin: Option<String>,
        key: &str,
        value: Option<String>,
    ) -> KernelResult<()> {
        let who = secret_principal(caller, plugin)?;
        let value = value.ok_or_else(|| KernelError::invalid_params("missing `value`"))?;
        self.0.broker.secret_set(&who, key, &value)
    }

    pub(crate) fn secret_delete(
        &self,
        caller: &Caller,
        plugin: Option<String>,
        key: &str,
    ) -> KernelResult<()> {
        let who = secret_principal(caller, plugin)?;
        self.0.broker.secret_delete(&who, key)
    }
}
