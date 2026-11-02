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
    /// Resolve open `unmapped-bw-item` rows for one Bitwarden item
    /// (adopt confirmation, or reconciliation of a stale row). Kind-scoped
    /// on purpose: other kinds still need human review.
    ResolveUnmappedForBw {
        bw_id: String,
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

/// One unresolved quarantine row:
/// (id, kind, kp_uuid, bw_id, title, detail).
pub type QuarantineRow = (i64, String, Option<String>, Option<String>, String, String);

/// Journal schema version, tracked in SQLite's `user_version` pragma.
/// v1 is the original schema (mapping / tombstone / quarantine). Journals
/// written before versioning existed report 0 and are adopted as v1 — the
/// schema is unchanged, only the stamp is new. v2 adds `missing_bw` (first
/// sightings of mapped items absent from a listing; see `note_missing`).
/// Future schema changes bump this and add a migration step in
/// [`Journal::open`]; a journal stamped newer than this build understands
/// is refused, never guessed at.
pub const SCHEMA_VERSION: i32 = 2;

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// In-memory journal for unit tests (no real file touched).
#[cfg(test)]
pub fn test_journal() -> Journal {
    Journal::open(Path::new(":memory:")).unwrap()
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
        // Schema version gate (see SCHEMA_VERSION). Migration scaffold:
        // any stored version up to SCHEMA_VERSION is accepted; the DDL
        // below is all CREATE TABLE IF NOT EXISTS, so opening an older
        // journal applies the missing tables, then the version is
        // stamped forward. v0 -> v1 was adoption only (identical schema);
        // v1 -> v2 adds `missing_bw`.
        let version: i32 = conn
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .context("read journal schema version")?;
        match version {
            v if (0..=SCHEMA_VERSION).contains(&v) => {}
            v if v > SCHEMA_VERSION => {
                anyhow::bail!(
                    "journal {} has schema version {v}, newer than this build supports ({SCHEMA_VERSION}); upgrade keepass-bw-sync",
                    path.display()
                );
            }
            v => {
                anyhow::bail!("journal {} has invalid schema version {v}", path.display());
            }
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
                 resolved   INTEGER NOT NULL DEFAULT 0);
             CREATE TABLE IF NOT EXISTS missing_bw(
                 bw_id      TEXT PRIMARY KEY,
                 kp_uuid    TEXT NOT NULL,
                 first_seen INTEGER NOT NULL);",
        )
        .context("create journal schema")?;
        if version != SCHEMA_VERSION {
            conn.execute_batch(&format!("PRAGMA user_version = {SCHEMA_VERSION}"))
                .context("stamp journal schema version")?;
        }
        Ok(Journal { conn })
    }

    /// The journal's schema version (see [`SCHEMA_VERSION`]).
    pub fn schema_version(&self) -> Result<i32> {
        let v: i32 = self
            .conn
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .context("read journal schema version")?;
        Ok(v)
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

    /// The recorded tombstone side for a KeePass UUID, if any. The side
    /// distinguishes *why* an entry was binned: `"keepass"` (user-binned),
    /// `"bitwarden"` (Bitwarden trash propagated into KeePass), and
    /// `"bitwarden-absence"` (recycled on a twice-confirmed Bitwarden
    /// listing absence — see `plan`'s missing-confirmation arm). The
    /// deleted branch consults this before trashing: an absence-recycle
    /// whose Bitwarden item reappeared must quarantine, never trash.
    pub fn tombstone_side(&self, kp_uuid: &Uuid) -> Result<Option<String>> {
        let mut st = self
            .conn
            .prepare("SELECT side FROM tombstone WHERE kp_uuid = ?1")?;
        let mut rows = st.query(params![kp_uuid.to_string()])?;
        if let Some(r) = rows.next()? {
            Ok(Some(r.get(0)?))
        } else {
            Ok(None)
        }
    }

    /// Delete a tombstone row. Used only to clear a stale plan-time
    /// `"bitwarden-absence"` record: when the entry is live and its
    /// Bitwarden item is present again, the recycle never landed and the
    /// record is stale evidence, not a completed delete.
    pub fn clear_tombstone(&self, kp_uuid: &Uuid) -> Result<()> {
        self.conn.execute(
            "DELETE FROM tombstone WHERE kp_uuid = ?1",
            params![kp_uuid.to_string()],
        )?;
        Ok(())
    }

    /// Record a first sighting of a mapped Bitwarden item absent from a
    /// listing. A single absence may be a transient listing glitch, not a
    /// delete, so `plan()` only recycles after a second, independent
    /// listing confirms it (see `was_missing`). Idempotent.
    pub fn note_missing(&self, bw_id: &str, kp_uuid: &Uuid) -> Result<()> {
        self.conn.execute(
            "INSERT OR IGNORE INTO missing_bw(bw_id, kp_uuid, first_seen) VALUES(?1, ?2, ?3)",
            params![bw_id, kp_uuid.to_string(), now()],
        )?;
        Ok(())
    }

    /// True when a previous plan already saw this item missing.
    pub fn was_missing(&self, bw_id: &str) -> Result<bool> {
        let n: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM missing_bw WHERE bw_id = ?1",
            params![bw_id],
            |r| r.get(0),
        )?;
        Ok(n > 0)
    }

    /// Clear the missing record: the item reappeared (glitch, not a
    /// delete), or the confirmed recycle was just planned. Clearing on
    /// plan rather than on apply is fail-safe: if apply then crashes
    /// before binning, the next run starts the two-listing clock over
    /// instead of recycling on stale evidence.
    pub fn clear_missing(&self, bw_id: &str) -> Result<()> {
        self.conn
            .execute("DELETE FROM missing_bw WHERE bw_id = ?1", params![bw_id])?;
        Ok(())
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

    /// Resolve open `unmapped-bw-item` rows for one Bitwarden item.
    /// Scoped to that kind on purpose: an unmapped item has no pair, so
    /// its open rows can only be unmapped-item rows in practice -- but
    /// if a row of another kind ever pointed at the same id, resolving
    /// it here would hide a real conflict, so the kind filter stays.
    /// Returns rows resolved.
    pub fn resolve_unmapped_for_bw(&self, bw_id: &str) -> Result<usize> {
        let n = self.conn.execute(
            "UPDATE quarantine SET resolved = 1 WHERE resolved = 0
             AND kind = 'unmapped-bw-item' AND bw_id = ?1",
            params![bw_id],
        )?;
        Ok(n)
    }

    /// Reconcile stale unmapped rows: an open `unmapped-bw-item` row whose
    /// item is now live-mapped (adopted, or mapped by any other path)
    /// states something false, so resolve it. Scoped narrowly to that
    /// kind plus live mappings (tombstoned pairs excluded, mirroring
    /// `live_mapped_bw_ids`): every other kind still needs human review
    /// even when the item is mapped. Returns rows resolved.
    pub fn reconcile_unmapped_rows(&self) -> Result<usize> {
        let n = self.conn.execute(
            "UPDATE quarantine SET resolved = 1 WHERE resolved = 0
             AND kind = 'unmapped-bw-item' AND bw_id IN
             (SELECT bw_id FROM mapping m WHERE NOT EXISTS
              (SELECT 1 FROM tombstone t WHERE t.kp_uuid = m.kp_uuid))",
            [],
        )?;
        Ok(n)
    }

    pub fn list_quarantine(&self) -> Result<Vec<QuarantineRow>> {
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

    /// Total unresolved quarantine rows: the authoritative "pending review"
    /// count. This is what the `quarantine` subcommand lists and what an
    /// operator compares against -- unlike the per-run sync summary's
    /// `quarantined` field, which counts only actions taken *this run*.
    /// An adopted item no longer leaves its row open: adopting resolves
    /// the item's `unmapped-bw-item` rows atomically with the mapping
    /// commit, and each sync reconciles stale unmapped rows for mapped
    /// items. Every other kind still needs an explicit `quarantine
    /// resolve`.
    pub fn unresolved_quarantine_count(&self) -> Result<i64> {
        let n: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM quarantine WHERE resolved = 0",
            [],
            |r| r.get(0),
        )?;
        Ok(n)
    }

    /// Commit deferred [`JournalOp`]s. The caller must invoke this only after
    /// the KeePass database is durably saved: committing earlier would let
    /// the journal claim KeePass mutations that never reached disk.
    ///
    /// Commits atomically: the ops run inside a single transaction, so a
    /// mid-commit failure rolls back instead of leaving a partial op
    /// sequence.
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
                JournalOp::ResolveUnmappedForBw { bw_id } => {
                    self.resolve_unmapped_for_bw(bw_id).map(|_| ())
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

    fn test_uuid() -> Uuid {
        Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap()
    }

    /// A fresh on-disk journal path in a per-test temp dir (any stale file
    /// from a previous run removed).
    fn temp_journal(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("kbs-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        let p = d.join("sync.db");
        let _ = std::fs::remove_file(&p);
        p
    }

    #[test]
    fn in_memory_journal_skips_chmod() {
        // :memory: must not trip the 0600 path; journal still works.
        let j = test_journal();
        j.upsert_mapping(&test_uuid(), "bw-1", "h")
        .unwrap();
        assert_eq!(j.live_mapping_count().unwrap(), 1);
    }

    #[test]
    fn quarantine_dedups_unresolved_rows() {
        let j = test_journal();
        let u = test_uuid();
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
    fn resolve_unmapped_for_bw_is_kind_scoped() {
        let j = test_journal();
        j.quarantine("unmapped-bw-item", None, Some("bw-1"), "t", "d")
            .unwrap();
        j.quarantine("foreign-bw-edit", None, Some("bw-1"), "t", "d")
            .unwrap();
        assert_eq!(j.resolve_unmapped_for_bw("bw-1").unwrap(), 1);
        let rows = j.list_quarantine().unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].1, "foreign-bw-edit");
    }

    #[test]
    fn reconcile_unmapped_rows_only_mapped_unmapped_kind() {
        let j = test_journal();
        let u = test_uuid();
        j.upsert_mapping(&u, "bw-1", "h").unwrap();
        // Stale: unmapped row for a now-mapped item -> resolved.
        j.quarantine("unmapped-bw-item", None, Some("bw-1"), "t", "d")
            .unwrap();
        // Other kind for the same mapped item -> stays open.
        j.quarantine("foreign-bw-edit", None, Some("bw-1"), "t", "d")
            .unwrap();
        // Unmapped row for a still-unmapped item -> stays open.
        j.quarantine("unmapped-bw-item", None, Some("bw-2"), "t", "d")
            .unwrap();
        // Tombstoned mapping does not count as mapped -> stays open.
        let u2 = Uuid::parse_str("22222222-2222-2222-2222-222222222222").unwrap();
        j.upsert_mapping(&u2, "bw-3", "h").unwrap();
        j.record_tombstone(&u2, Some("bw-3"), "keepass").unwrap();
        j.quarantine("unmapped-bw-item", None, Some("bw-3"), "t", "d")
            .unwrap();
        assert_eq!(j.reconcile_unmapped_rows().unwrap(), 1);
        let rows = j.list_quarantine().unwrap();
        assert_eq!(rows.len(), 3);
        assert!(rows.iter().any(|r| r.1 == "foreign-bw-edit"));
        assert!(rows.iter().any(|r| r.3.as_deref() == Some("bw-2")));
        assert!(rows.iter().any(|r| r.3.as_deref() == Some("bw-3")));
    }

    #[test]
    fn quarantine_resolve_closes_row() {
        let j = test_journal();
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
    fn unresolved_quarantine_count_counts_only_open_rows() {
        let j = test_journal();
        assert_eq!(j.unresolved_quarantine_count().unwrap(), 0);
        j.quarantine("k", None, Some("bw-1"), "t", "d").unwrap();
        // Same identity while unresolved: deduped, still 1.
        j.quarantine("k", None, Some("bw-1"), "t", "d").unwrap();
        j.quarantine("k", None, Some("bw-2"), "t", "d").unwrap();
        assert_eq!(j.unresolved_quarantine_count().unwrap(), 2);
        assert_eq!(j.list_quarantine().unwrap().len(), 2);
        let rows = j.list_quarantine().unwrap();
        assert!(j.resolve_quarantine(rows[0].0).unwrap());
        assert_eq!(j.unresolved_quarantine_count().unwrap(), 1);
    }

    #[test]
    fn apply_ops_commits_in_order() {
        let j = test_journal();
        let u = test_uuid();
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

    #[test]
    fn schema_version_stamped_on_open() {
        let j = test_journal();
        assert_eq!(j.schema_version().unwrap(), SCHEMA_VERSION);
    }

    #[test]
    fn v1_journal_migrates_to_v2_with_missing_bw() {
        // A v1-shaped journal (version 1, no missing_bw table) must open
        // cleanly, gain the table, and stamp forward to v2 — the
        // production journal upgrades in place on first run.
        let p = temp_journal("migrate");
        {
            let j = Journal::open(&p).unwrap();
            assert_eq!(j.schema_version().unwrap(), SCHEMA_VERSION);
        }
        {
            let conn = Connection::open(&p).unwrap();
            conn.execute_batch("PRAGMA user_version = 1; DROP TABLE missing_bw;")
                .unwrap();
        }
        let j = Journal::open(&p).unwrap();
        assert_eq!(j.schema_version().unwrap(), SCHEMA_VERSION);
        assert!(!j.was_missing("bw-9").unwrap());
        j.note_missing("bw-9", &test_uuid()).unwrap();
        assert!(j.was_missing("bw-9").unwrap());
        j.clear_missing("bw-9").unwrap();
        assert!(!j.was_missing("bw-9").unwrap());
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn newer_schema_version_is_refused() {
        // A journal stamped by a newer build must fail with a clear
        // error, not be misread by an older schema's assumptions.
        let p = temp_journal("schema");
        {
            let c = Connection::open(&p).unwrap();
            c.execute_batch("PRAGMA user_version = 99").unwrap();
        }
        let err = match Journal::open(&p) {
            Ok(_) => panic!("expected a newer-schema journal to be refused"),
            Err(e) => e.to_string(),
        };
        assert!(err.contains("newer"), "unexpected error: {err}");
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn legacy_unversioned_journal_is_adopted() {
        // Pre-versioning journals have user_version 0 and the v1 schema:
        // they open fine and get stamped.
        let p = temp_journal("legacy");
        {
            let c = Connection::open(&p).unwrap();
            c.execute_batch(
                "CREATE TABLE mapping(kp_uuid TEXT PRIMARY KEY, bw_id TEXT NOT NULL,
                     last_hash TEXT NOT NULL, last_sync INTEGER NOT NULL);",
            )
            .unwrap();
        }
        let j = Journal::open(&p).unwrap();
        assert_eq!(j.schema_version().unwrap(), SCHEMA_VERSION);
        let _ = std::fs::remove_file(&p);
    }

    #[cfg(unix)]
    #[test]
    fn journal_file_is_owner_only() {
        // The journal holds identities (UUID <-> Bitwarden id). It must be
        // created 0600; a regression here would expose the mapping to other
        // local users.
        use std::os::unix::fs::PermissionsExt;
        let p = temp_journal("perm");
        let _j = Journal::open(&p).unwrap();
        let mode = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "journal must be 0600, got {:o}", mode);
        let _ = std::fs::remove_file(&p);
    }
}
