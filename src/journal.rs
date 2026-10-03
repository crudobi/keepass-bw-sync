//! Local SQLite sync journal.
//!
//! The journal holds no secrets — only identities, content hashes, watermarks,
//! tombstones, and the quarantine queue. It is what makes the engine's
//! conflict decisions possible without trusting either side's clocks.

use std::collections::HashSet;
use std::path::Path;

use anyhow::{Context, Result};
use rusqlite::{params, Connection};
use uuid::Uuid;

/// A journal mutation deferred by [`crate::sync::apply`] until the caller has
/// durably saved the KeePass database. Committing these before `save_vault()`
/// succeeds would let the journal claim KeePass mutations that never reached
/// disk — a mid-apply bail or crash then corrupts the next run's conflict
/// decisions (silent loss of foreign edits, or resurrection of deleted items).
#[derive(Debug)]
pub enum JournalOp {
    UpsertMapping {
        kp_uuid: Uuid,
        bw_id: String,
        hash: String,
    },
    RecordTombstone {
        kp_uuid: Uuid,
        bw_id: Option<String>,
        side: &'static str,
    },
    DeleteMappingByKp {
        kp_uuid: Uuid,
    },
    Quarantine {
        kind: &'static str,
        kp_uuid: Option<Uuid>,
        bw_id: Option<String>,
        title: String,
        detail: String,
    },
}

pub struct Journal {
    conn: Connection,
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

impl Journal {
    pub fn open(path: &Path) -> Result<Self> {
        let conn = Connection::open(path)
            .with_context(|| format!("open journal {}", path.display()))?;
        // The journal holds content hashes (offline-brute-forceable for weak
        // passwords): keep it owner-only. Skip for :memory: databases.
        #[cfg(unix)]
        if path != Path::new(":memory:") {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
                .with_context(|| format!("chmod 0600 {}", path.display()))?;
        }
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS mapping(
                 kp_uuid   TEXT PRIMARY KEY,
                 bw_id     TEXT NOT NULL,
                 last_hash TEXT NOT NULL,
                 last_sync INTEGER NOT NULL);
             CREATE TABLE IF NOT EXISTS tombstone(
                 kp_uuid TEXT PRIMARY KEY,
                 bw_id   TEXT,
                 side    TEXT NOT NULL,
                 at      INTEGER NOT NULL);
             CREATE TABLE IF NOT EXISTS quarantine(
                 id         INTEGER PRIMARY KEY,
                 kind       TEXT NOT NULL,
                 kp_uuid    TEXT,
                 bw_id      TEXT,
                 title      TEXT,
                 detail     TEXT NOT NULL,
                 created_at INTEGER NOT NULL,
                 resolved   INTEGER NOT NULL DEFAULT 0);",
        )
        .context("create journal schema")?;
        Ok(Journal { conn })
    }

    /// (bw_id, last_hash) for a KeePass UUID.
    pub fn mapping_by_kp(&self, kp_uuid: &Uuid) -> Result<Option<(String, String)>> {
        let mut st = self
            .conn
            .prepare("SELECT bw_id, last_hash FROM mapping WHERE kp_uuid = ?1")?;
        let mut rows = st.query(params![kp_uuid.to_string()])?;
        if let Some(r) = rows.next()? {
            Ok(Some((r.get(0)?, r.get(1)?)))
        } else {
            Ok(None)
        }
    }

    pub fn mapping_by_bw(&self, bw_id: &str) -> Result<Option<(Uuid, String)>> {
        let mut st = self
            .conn
            .prepare("SELECT kp_uuid, last_hash FROM mapping WHERE bw_id = ?1")?;
        let mut rows = st.query(params![bw_id])?;
        if let Some(r) = rows.next()? {
            let u: String = r.get(0)?;
            let h: String = r.get(1)?;
            match u.parse::<Uuid>() {
                Ok(uuid) => Ok(Some((uuid, h))),
                Err(_) => Ok(None), // corrupt row: treat as unmapped, never crash
            }
        } else {
            Ok(None)
        }
    }

    pub fn upsert_mapping(&self, kp_uuid: &Uuid, bw_id: &str, hash_hex: &str) -> Result<()> {
        self.conn.execute(
            "INSERT INTO mapping(kp_uuid, bw_id, last_hash, last_sync)
             VALUES(?1, ?2, ?3, ?4)
             ON CONFLICT(kp_uuid) DO UPDATE SET bw_id=excluded.bw_id,
               last_hash=excluded.last_hash, last_sync=excluded.last_sync",
            params![kp_uuid.to_string(), bw_id, hash_hex, now()],
        )?;
        Ok(())
    }

    pub fn delete_mapping_by_kp(&self, kp_uuid: &Uuid) -> Result<()> {
        self.conn
            .execute("DELETE FROM mapping WHERE kp_uuid = ?1", params![kp_uuid.to_string()])?;
        Ok(())
    }

    pub fn record_tombstone(&self, kp_uuid: &Uuid, bw_id: Option<&str>, side: &str) -> Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO tombstone(kp_uuid, bw_id, side, at) VALUES(?1, ?2, ?3, ?4)",
            params![kp_uuid.to_string(), bw_id, side, now()],
        )?;
        Ok(())
    }

    pub fn tombstoned(&self, kp_uuid: &Uuid) -> Result<bool> {
        let n: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM tombstone WHERE kp_uuid = ?1",
            params![kp_uuid.to_string()],
            |r| r.get(0),
        )?;
        Ok(n > 0)
    }

    /// Mappings not covered by a tombstone: the only ones whose Bitwarden
    /// item going missing from a listing counts as a delete.
    pub fn live_mapping_count(&self) -> Result<i64> {
        let n: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM mapping m WHERE NOT EXISTS (SELECT 1 FROM tombstone t WHERE t.kp_uuid = m.kp_uuid)",
            [],
            |r| r.get(0),
        )?;
        Ok(n)
    }

    /// bw_ids of live (non-tombstoned) mappings: the only ones whose
    /// Bitwarden item going missing from a listing counts as a delete.
    pub fn live_mapped_bw_ids(&self) -> Result<HashSet<String>> {
        let mut st = self.conn.prepare(
            "SELECT bw_id FROM mapping m WHERE NOT EXISTS
             (SELECT 1 FROM tombstone t WHERE t.kp_uuid = m.kp_uuid)",
        )?;
        let rows = st.query_map([], |r| r.get::<_, String>(0))?;
        rows.collect::<std::result::Result<HashSet<_>, _>>()
            .map_err(Into::into)
    }

    pub fn quarantine(
        &self,
        kind: &str,
        kp_uuid: Option<&Uuid>,
        bw_id: Option<&str>,
        title: &str,
        detail: &str,
    ) -> Result<()> {
        let kp = kp_uuid.map(|u| u.to_string());
        // Dedup: an unresolved row for the same (identity, kind) already
        // queues this case; don't pile up a duplicate every run.
        // (`IS` is the NULL-safe equality: NULL IS NULL is true.)
        let dup: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM quarantine WHERE resolved = 0 AND kind = ?1
             AND kp_uuid IS ?2 AND bw_id IS ?3",
            params![kind, kp, bw_id],
            |r| r.get(0),
        )?;
        if dup > 0 {
            return Ok(());
        }
        self.conn.execute(
            "INSERT INTO quarantine(kind, kp_uuid, bw_id, title, detail, created_at)
             VALUES(?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                kind,
                kp,
                bw_id,
                title,
                detail,
                now()
            ],
        )?;
        Ok(())
    }

    /// Mark a quarantine row resolved. Returns true when an open row existed.
    pub fn resolve_quarantine(&self, id: i64) -> Result<bool> {
        let n = self.conn.execute(
            "UPDATE quarantine SET resolved = 1 WHERE id = ?1 AND resolved = 0",
            params![id],
        )?;
        Ok(n > 0)
    }

    pub fn list_quarantine(&self) -> Result<Vec<(i64, String, Option<String>, Option<String>, String, String)>> {
        let mut st = self.conn.prepare(
            "SELECT id, kind, kp_uuid, bw_id, title, detail FROM quarantine
             WHERE resolved = 0 ORDER BY id",
        )?;
        let rows = st.query_map([], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, Option<String>>(2)?,
                r.get::<_, Option<String>>(3)?,
                r.get::<_, String>(4)?,
                r.get::<_, String>(5)?,
            ))
        })?;
        rows.collect::<std::result::Result<Vec<_>, _>>().map_err(Into::into)
    }

    /// Commit deferred [`JournalOp`]s. The caller must invoke this only after
    /// the KeePass database is durably saved: committing earlier would let
    /// the journal claim KeePass mutations that never reached disk.
    ///
    /// Commits atomically: the ops run inside a single transaction, so a
    /// mid-commit failure rolls back instead of leaving a partial op
    /// sequence. `&self` is enough — `execute_batch` runs the transaction
    /// statements on the same connection without needing `&mut`.
    pub fn apply_ops(&self, ops: &[JournalOp]) -> Result<()> {
        self.conn
            .execute_batch("BEGIN IMMEDIATE")
            .context("begin journal transaction")?;
        let mut r = Ok(());
        for op in ops {
            r = match op {
                JournalOp::UpsertMapping { kp_uuid, bw_id, hash } => {
                    self.upsert_mapping(kp_uuid, bw_id, hash)
                }
                JournalOp::RecordTombstone { kp_uuid, bw_id, side } => {
                    self.record_tombstone(kp_uuid, bw_id.as_deref(), side)
                }
                JournalOp::DeleteMappingByKp { kp_uuid } => {
                    self.delete_mapping_by_kp(kp_uuid)
                }
                JournalOp::Quarantine { kind, kp_uuid, bw_id, title, detail } => {
                    self.quarantine(kind, kp_uuid.as_ref(), bw_id.as_deref(), title, detail)
                }
            };
            if r.is_err() {
                break;
            }
        }
        match r {
            Ok(()) => self
                .conn
                .execute_batch("COMMIT")
                .context("commit journal transaction"),
            Err(e) => {
                let _ = self.conn.execute_batch("ROLLBACK");
                Err(e).context("apply journal ops")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mem_journal() -> Journal {
        Journal::open(Path::new(":memory:")).unwrap()
    }

    #[test]
    fn mem_journal_skips_chmod() {
        // :memory: must not trip the 0600 path; journal still works.
        let j = mem_journal();
        j.upsert_mapping(
            &Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap(),
            "bw-1",
            "h",
        )
        .unwrap();
        assert_eq!(j.live_mapping_count().unwrap(), 1);
    }

    #[test]
    fn quarantine_dedups_unresolved_rows() {
        let j = mem_journal();
        let u = Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap();
        j.quarantine("foreign-bw-edit", Some(&u), Some("bw-1"), "t", "d")
            .unwrap();
        // Same (identity, kind) while unresolved: no duplicate row.
        j.quarantine("foreign-bw-edit", Some(&u), Some("bw-1"), "t", "d")
            .unwrap();
        assert_eq!(j.list_quarantine().unwrap().len(), 1);
        // Different kind is a separate case.
        j.quarantine("concurrent-edit", Some(&u), Some("bw-1"), "t", "d")
            .unwrap();
        assert_eq!(j.list_quarantine().unwrap().len(), 2);
    }

    #[test]
    fn quarantine_resolve_closes_row() {
        let j = mem_journal();
        j.quarantine("k", None, Some("bw-9"), "t", "d").unwrap();
        let rows = j.list_quarantine().unwrap();
        assert_eq!(rows.len(), 1);
        assert!(j.resolve_quarantine(rows[0].0).unwrap());
        assert!(j.list_quarantine().unwrap().is_empty());
        // Resolving twice is a no-op.
        assert!(!j.resolve_quarantine(rows[0].0).unwrap());
        assert!(!j.resolve_quarantine(9999).unwrap());
    }

    #[test]
    fn apply_ops_commits_in_order() {
        let j = mem_journal();
        let u = Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap();
        j.apply_ops(&[
            JournalOp::UpsertMapping {
                kp_uuid: u,
                bw_id: "bw-1".into(),
                hash: "h".into(),
            },
            JournalOp::RecordTombstone {
                kp_uuid: u,
                bw_id: Some("bw-1".into()),
                side: "keepass",
            },
            JournalOp::DeleteMappingByKp { kp_uuid: u },
        ])
        .unwrap();
        assert!(j.tombstoned(&u).unwrap());
        assert!(j.mapping_by_kp(&u).unwrap().is_none());
        assert_eq!(j.live_mapping_count().unwrap(), 0);
        assert!(j.live_mapped_bw_ids().unwrap().is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn journal_file_is_owner_only() {
        // The journal holds identities (UUID <-> Bitwarden id). It must be
        // created 0600; a regression here would expose the mapping to other
        // local users.
        use std::os::unix::fs::PermissionsExt;
        let d = std::env::temp_dir().join(format!("kbs-perm-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        let p = d.join("sync.db");
        let _ = std::fs::remove_file(&p);
        let _j = Journal::open(&p).unwrap();
        let mode = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "journal must be 0600, got {:o}", mode);
        let _ = std::fs::remove_file(&p);
    }
}
