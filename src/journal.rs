//! Local SQLite sync journal.
//!
//! The journal holds no secrets — only identities, content hashes, watermarks,
//! tombstones, and the quarantine queue. It is what makes the engine's
//! conflict decisions possible without trusting either side's clocks.

use std::path::Path;

use anyhow::{Context, Result};
use rusqlite::{params, Connection};
use uuid::Uuid;

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

    pub fn quarantine(
        &self,
        kind: &str,
        kp_uuid: Option<&Uuid>,
        bw_id: Option<&str>,
        title: &str,
        detail: &str,
    ) -> Result<()> {
        self.conn.execute(
            "INSERT INTO quarantine(kind, kp_uuid, bw_id, title, detail, created_at)
             VALUES(?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                kind,
                kp_uuid.map(|u| u.to_string()),
                bw_id,
                title,
                detail,
                now()
            ],
        )?;
        Ok(())
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
}
