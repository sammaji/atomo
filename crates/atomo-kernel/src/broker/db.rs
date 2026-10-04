//! The broker's tables in `kernel.db`: standing grants, consent
//! records (what a plugin's user approved, for the update escalation check)
//! and the append-only audit log.

use rusqlite::{params, OptionalExtension};

use super::{AuditEntry, Binding, Grant, GrantKind, Scope};
use crate::storage::KernelDb;
use crate::KernelResult;

pub(super) fn init(db: &KernelDb) -> KernelResult<()> {
    db.with(|c| {
        c.execute_batch(
            "CREATE TABLE IF NOT EXISTS grants (
                 id TEXT PRIMARY KEY, principal TEXT NOT NULL, right_id TEXT NOT NULL,
                 scope TEXT NOT NULL, source TEXT NOT NULL, reason TEXT,
                 overrides INTEGER NOT NULL, created_ms INTEGER NOT NULL);
             CREATE TABLE IF NOT EXISTS consents (
                 plugin TEXT PRIMARY KEY, atoms TEXT NOT NULL, version TEXT NOT NULL,
                 decided_ms INTEGER NOT NULL);
             CREATE TABLE IF NOT EXISTS audit (
                 id INTEGER PRIMARY KEY AUTOINCREMENT, time_ms INTEGER NOT NULL,
                 principal TEXT NOT NULL, right_id TEXT NOT NULL, resource TEXT NOT NULL,
                 decision TEXT NOT NULL, reason TEXT, source TEXT);
             CREATE INDEX IF NOT EXISTS audit_principal ON audit (principal, id);
             CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit
                 BEGIN SELECT RAISE(ABORT, 'the audit log is append-only'); END;
             CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit
                 BEGIN SELECT RAISE(ABORT, 'the audit log is append-only'); END;",
        )
    })
}

pub(super) fn load_grants(db: &KernelDb) -> KernelResult<Vec<Grant>> {
    db.with(|c| {
        let mut stmt = c.prepare(
            "SELECT id, principal, right_id, scope, source, reason, overrides, created_ms
             FROM grants ORDER BY created_ms, id",
        )?;
        let rows = stmt.query_map([], |r| {
            let scope: String = r.get(3)?;
            Ok(Grant {
                id: r.get(0)?,
                principal: r.get(1)?,
                right: r.get(2)?,
                scope: serde_json::from_str(&scope).unwrap_or(Scope::Exact(String::new())),
                kind: GrantKind::Standing,
                source: r.get(4)?,
                binding: Binding::Persistent,
                overrides_denylist: r.get::<_, i64>(6)? != 0,
                created_ms: r.get::<_, i64>(7)? as f64,
                expires_ms: None,
                reason: r.get(5)?,
            })
        })?;
        rows.collect()
    })
}

pub(super) fn insert_grant(db: &KernelDb, g: &Grant) -> KernelResult<()> {
    db.with(|c| {
        c.execute(
            "INSERT OR REPLACE INTO grants
                 (id, principal, right_id, scope, source, reason, overrides, created_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                g.id,
                g.principal,
                g.right,
                serde_json::to_string(&g.scope).unwrap_or_default(),
                g.source,
                g.reason,
                g.overrides_denylist,
                g.created_ms as i64
            ],
        )
        .map(drop)
    })
}

pub(super) fn delete_grant(db: &KernelDb, id: &str) -> KernelResult<()> {
    db.with(|c| {
        c.execute("DELETE FROM grants WHERE id = ?1", params![id])
            .map(drop)
    })
}

pub(super) fn delete_grants_from(db: &KernelDb, principal: &str, source: &str) -> KernelResult<()> {
    db.with(|c| {
        c.execute(
            "DELETE FROM grants WHERE principal = ?1 AND source = ?2",
            params![principal, source],
        )
        .map(drop)
    })
}

/// The atoms (see `super::consent_atoms`) a plugin's user approved.
pub(super) fn consent(db: &KernelDb, plugin: &str) -> KernelResult<Option<Vec<String>>> {
    let text: Option<String> = db.with(|c| {
        c.query_row(
            "SELECT atoms FROM consents WHERE plugin = ?1",
            params![plugin],
            |r| r.get(0),
        )
        .optional()
    })?;
    Ok(text.and_then(|t| serde_json::from_str(&t).ok()))
}

pub(super) fn set_consent(
    db: &KernelDb,
    plugin: &str,
    atoms: &[String],
    version: &str,
    now: i64,
) -> KernelResult<()> {
    db.with(|c| {
        c.execute(
            "INSERT OR REPLACE INTO consents (plugin, atoms, version, decided_ms)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                plugin,
                serde_json::to_string(atoms).unwrap_or_default(),
                version,
                now
            ],
        )
        .map(drop)
    })
}

pub(super) fn append_audit(db: &KernelDb, e: &AuditEntry) -> KernelResult<()> {
    db.with(|c| {
        c.execute(
            "INSERT INTO audit (time_ms, principal, right_id, resource, decision, reason, source)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                e.time_ms as i64,
                e.principal,
                e.right,
                e.resource,
                e.decision,
                e.reason,
                e.source
            ],
        )
        .map(drop)
    })
}

pub(super) fn audit(
    db: &KernelDb,
    principal: Option<&str>,
    limit: u32,
) -> KernelResult<Vec<AuditEntry>> {
    db.with(|c| {
        let mut stmt = c.prepare(
            "SELECT id, time_ms, principal, right_id, resource, decision, reason, source
             FROM audit WHERE (?1 IS NULL OR principal = ?1) ORDER BY id DESC LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![principal, limit], |r| {
            Ok(AuditEntry {
                id: r.get::<_, i64>(0)? as f64,
                time_ms: r.get::<_, i64>(1)? as f64,
                principal: r.get(2)?,
                right: r.get(3)?,
                resource: r.get(4)?,
                decision: r.get(5)?,
                reason: r.get(6)?,
                source: r.get(7)?,
            })
        })?;
        rows.collect()
    })
}
