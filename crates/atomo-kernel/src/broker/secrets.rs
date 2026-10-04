//! Per-plugin secrets, kept in the OS keychain under `atomo/<plugin-id>` /
//! `<key>`. The broker binds the namespace to the caller's identity, so a
//! plugin can never name another plugin's secrets.

use std::collections::HashMap;
use std::sync::Arc;

use parking_lot::Mutex;

use super::{forbidden, Broker, Decision, Principal};
use crate::{ErrorCode, KernelError, KernelResult};

/// Where secrets are kept. Tests and in-memory kernels use [`MemorySecrets`].
pub trait SecretStore: Send + Sync + 'static {
    fn get(&self, service: &str, key: &str) -> KernelResult<Option<String>>;
    fn set(&self, service: &str, key: &str, value: &str) -> KernelResult<()>;
    /// Deleting a missing secret is not an error.
    fn delete(&self, service: &str, key: &str) -> KernelResult<()>;
}

/// The keychain service name of a plugin's secrets.
fn service_name(plugin: &str) -> String {
    format!("atomo/{plugin}")
}

/// Secret keys are short printable names chosen by the plugin.
fn validate_key(key: &str) -> KernelResult<()> {
    if key.is_empty() || key.len() > 256 || key.chars().any(char::is_control) {
        return Err(KernelError::invalid_params(
            "a secret key is 1–256 printable characters",
        ));
    }
    Ok(())
}

impl Broker {
    pub(super) fn secrets_for(
        &self,
        principal: &Principal,
    ) -> KernelResult<(String, Arc<dyn SecretStore>)> {
        let plugin = principal
            .plugin()
            .ok_or_else(|| forbidden("only plugins keep secrets"))?
            .to_owned();
        if let Decision::Deny(why) = self.decide(principal, "secrets", "*", Some("secrets")).0 {
            return Err(forbidden(why));
        }
        Ok((service_name(&plugin), self.0.secrets.read().clone()))
    }

    /// A secret in the principal's own namespace.
    pub fn secret_get(&self, principal: &Principal, key: &str) -> KernelResult<Option<String>> {
        validate_key(key)?;
        let (service, store) = self.secrets_for(principal)?;
        store.get(&service, key)
    }

    pub fn secret_set(&self, principal: &Principal, key: &str, value: &str) -> KernelResult<()> {
        validate_key(key)?;
        let (service, store) = self.secrets_for(principal)?;
        store.set(&service, key, value)
    }

    pub fn secret_delete(&self, principal: &Principal, key: &str) -> KernelResult<()> {
        validate_key(key)?;
        let (service, store) = self.secrets_for(principal)?;
        store.delete(&service, key)
    }

    /// `plugin`'s namespace (keychain service and store) for a core-tier
    /// service `by` that keeps secrets there on the plugin's behalf, such as
    /// its sign-in tokens: the plugin needs no `secrets` grant for that.
    pub fn secrets_on_behalf(
        &self,
        by: &Principal,
        plugin: &str,
    ) -> KernelResult<(String, Arc<dyn SecretStore>)> {
        if by.plugin().is_none() || !self.is_trusted(by) {
            return Err(forbidden(format!(
                "{by} may not keep secrets for other plugins"
            )));
        }
        Ok((service_name(plugin), self.0.secrets.read().clone()))
    }
}

#[derive(Default)]
pub struct MemorySecrets(Mutex<HashMap<(String, String), String>>);

impl SecretStore for MemorySecrets {
    fn get(&self, service: &str, key: &str) -> KernelResult<Option<String>> {
        Ok(self.0.lock().get(&(service.into(), key.into())).cloned())
    }
    fn set(&self, service: &str, key: &str, value: &str) -> KernelResult<()> {
        self.0
            .lock()
            .insert((service.into(), key.into()), value.into());
        Ok(())
    }
    fn delete(&self, service: &str, key: &str) -> KernelResult<()> {
        self.0.lock().remove(&(service.into(), key.into()));
        Ok(())
    }
}

/// The OS keychain (macOS Keychain, Windows Credential Manager, the Linux
/// kernel keyring) through the `keyring` crate.
#[derive(Default)]
pub struct KeychainSecrets;

#[cfg(any(target_os = "macos", windows, target_os = "linux"))]
mod keychain {
    use super::*;

    fn err(e: keyring::Error) -> KernelError {
        KernelError::new(ErrorCode::Secrets, e.to_string())
    }

    impl SecretStore for KeychainSecrets {
        fn get(&self, service: &str, key: &str) -> KernelResult<Option<String>> {
            match keyring::Entry::new(service, key)
                .map_err(err)?
                .get_password()
            {
                Ok(v) => Ok(Some(v)),
                Err(keyring::Error::NoEntry) => Ok(None),
                Err(e) => Err(err(e)),
            }
        }
        fn set(&self, service: &str, key: &str, value: &str) -> KernelResult<()> {
            keyring::Entry::new(service, key)
                .map_err(err)?
                .set_password(value)
                .map_err(err)
        }
        fn delete(&self, service: &str, key: &str) -> KernelResult<()> {
            match keyring::Entry::new(service, key)
                .map_err(err)?
                .delete_credential()
            {
                Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
                Err(e) => Err(err(e)),
            }
        }
    }
}

#[cfg(not(any(target_os = "macos", windows, target_os = "linux")))]
impl SecretStore for KeychainSecrets {
    fn get(&self, _: &str, _: &str) -> KernelResult<Option<String>> {
        Err(KernelError::new(
            "unsupported",
            "no keychain on this platform",
        ))
    }
    fn set(&self, _: &str, _: &str, _: &str) -> KernelResult<()> {
        Err(KernelError::new(
            "unsupported",
            "no keychain on this platform",
        ))
    }
    fn delete(&self, _: &str, _: &str) -> KernelResult<()> {
        Err(KernelError::new(
            "unsupported",
            "no keychain on this platform",
        ))
    }
}
