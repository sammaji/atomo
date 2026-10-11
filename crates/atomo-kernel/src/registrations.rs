use std::any::{Any, TypeId};
use std::collections::HashMap;
use std::sync::Arc;

use parking_lot::RwLock;
use tokio_util::sync::CancellationToken;

use crate::commands::{CommandEntry, CommandHandler};
use crate::protocol::{Method, MethodEntry};
use crate::{Kernel, Visibility};

type AnyService = Arc<dyn Any + Send + Sync>;

/// Registrations a plugin instance owns, disposed on deactivation.
#[derive(Default)]
pub(crate) struct Ledger {
    pub methods: Vec<String>,
    pub commands: Vec<String>,
    pub services: Vec<TypeId>,
    /// Whether it defined rights (`ActivationContext::define_rights`).
    pub rights: bool,
    pub cancel: CancellationToken,
}

#[derive(Default)]
pub(crate) struct Registrations {
    services: RwLock<HashMap<TypeId, (String, AnyService)>>,
    methods: RwLock<HashMap<String, MethodEntry>>,
    commands: RwLock<HashMap<String, CommandEntry>>,
}

impl Registrations {
    pub fn insert_service(&self, owner: &str, type_id: TypeId, service: AnyService) {
        self.services
            .write()
            .insert(type_id, (owner.to_owned(), service));
    }

    pub fn insert_method(&self, name: &str, visibility: Visibility, handler: Method) {
        let entry = MethodEntry {
            visibility,
            handler,
        };
        let previous = self.methods.write().insert(name.to_owned(), entry);
        assert!(previous.is_none(), "method {name} registered twice");
    }

    pub fn method(&self, name: &str) -> Option<(Visibility, Method)> {
        self.methods
            .read()
            .get(name)
            .map(|m| (m.visibility, m.handler.clone()))
    }

    pub fn insert_command(&self, id: &str, entry: CommandEntry) {
        self.commands.write().insert(id.to_owned(), entry);
    }

    pub fn command_owner(&self, id: &str) -> Option<String> {
        self.commands.read().get(id).map(|c| c.owner.clone())
    }

    pub fn command_handler(&self, id: &str) -> Option<CommandHandler> {
        self.commands.read().get(id).map(|c| c.handler.clone())
    }

    /// Remove everything listed in a plugin's ledger.
    pub fn remove(&self, ledger: &Ledger) {
        let mut methods = self.methods.write();
        for m in &ledger.methods {
            methods.remove(m);
        }
        let mut commands = self.commands.write();
        for c in &ledger.commands {
            commands.remove(c);
        }
        let mut services = self.services.write();
        for s in &ledger.services {
            services.remove(s);
        }
    }
}

impl Kernel {
    pub fn service<T: Send + Sync + 'static>(&self) -> Option<Arc<T>> {
        self.0
            .registrations
            .services
            .read()
            .get(&TypeId::of::<T>())
            .and_then(|(_, s)| s.clone().downcast::<T>().ok())
    }
}
