//! KeePass .kdbx access: open, walk, extract, save.
//!
//! The database is decrypted strictly in RAM. Plaintext entries are projected
//! into [`CanonicalEntry`] and the `Database` is then available for write-back
//! mutations. Saves are crash-safe: build to `<name>.kdbx.tmp`, fsync, then
//! atomic rename over the original.

use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use keepass_rs::model::core::date::DateInstant;
use keepass_rs::model::core::node::NodeId;
use keepass_rs::model::core::security::ProtectedString;
use keepass_rs::model::db::composite_key::CompositeKey;
use keepass_rs::model::db::database::Database;
use keepass_rs::model::entry::Entry;
use keepass_rs::{open_database, save_database};
use uuid::Uuid;

use crate::canonical::CanonicalEntry;
use crate::secret::Secret;

pub struct KdbxVault {
    pub db: Database,
    key: CompositeKey,
    path: PathBuf,
}

/// Open and decrypt the .kdbx at `path`. Nothing plaintext touches disk.
pub fn open_vault(path: &Path, password: &Secret, keyfile: Option<&[u8]>) -> Result<KdbxVault> {
    let mut ck = CompositeKey::new().with_password(password.expose());
    if let Some(kf) = keyfile {
        ck = ck.with_key_file(kf);
    }
    let f = File::open(path).with_context(|| format!("open {}", path.display()))?;
    let db = open_database(f, &ck).context("decrypt .kdbx (wrong password/keyfile?)")?;
    Ok(KdbxVault {
        db,
        key: ck,
        path: path.to_path_buf(),
    })
}

fn ps_to_string(p: &ProtectedString) -> String {
    p.as_str().to_string()
}

fn child_to_parent(db: &Database) -> HashMap<NodeId, NodeId> {
    let mut m = HashMap::new();
    for (gid, g) in &db.groups {
        for c in &g.child_group_ids {
            m.insert(c.clone(), gid.clone());
        }
    }
    m
}

/// "Personal/Email" style path of the group holding `entry_id`, excluding root.
fn group_path(db: &Database, entry_id: &NodeId, c2p: &HashMap<NodeId, NodeId>) -> String {
    let mut parts: Vec<String> = Vec::new();
    let mut cur = db.find_parent_group_of_entry(entry_id);
    let root = db.root_group_id.clone();
    let mut guard = 0;
    while let Some(gid) = cur {
        guard += 1;
        if guard > 256 {
            break;
        }
        if Some(&gid) == root.as_ref() {
            break;
        }
        match db.groups.get(&gid) {
            Some(g) => {
                parts.push(g.title.clone());
                cur = c2p.get(&gid).cloned();
            }
            None => break,
        }
    }
    parts.reverse();
    parts.join("/")
}

fn ms(t: &DateInstant) -> i64 {
    t.as_millis().unwrap_or(0)
}

/// TOTP is carried as a plain custom field named "totp" (case-insensitive).
fn extract_totp(entry: &Entry) -> Option<String> {
    entry
        .custom_fields
        .iter()
        .find(|f| f.name.eq_ignore_ascii_case("totp"))
        .map(|f| ps_to_string(&f.value))
        .filter(|s| !s.is_empty())
}

fn entry_to_canonical(db: &Database, eid: &NodeId, entry: &Entry, c2p: &HashMap<NodeId, NodeId>) -> CanonicalEntry {
    let uuid = entry.id.as_uuid().cloned().unwrap_or_else(Uuid::nil);
    let recycle = db.recycle_bin_uuid.map(NodeId::from_uuid);
    let deleted = match db.find_parent_group_of_entry(eid) {
        Some(p) => Some(p) == recycle,
        None => false,
    };
    let custom: Vec<(String, String)> = entry
        .custom_fields
        .iter()
        .filter(|f| !f.name.eq_ignore_ascii_case("totp"))
        .map(|f| (f.name.clone(), ps_to_string(&f.value)))
        .collect();
    CanonicalEntry {
        uuid,
        title: entry.title.clone(),
        username: ps_to_string(&entry.username),
        password: Secret::from_str(entry.password.as_str()),
        url: entry.url.clone(),
        notes: ps_to_string(&entry.notes),
        totp: extract_totp(entry),
        custom,
        group_path: group_path(db, eid, c2p),
        last_modified_ms: ms(&entry.last_modification_time),
        deleted,
    }
}

/// Project every entry in the database into canonical form.
pub fn extract_entries(db: &Database) -> Vec<CanonicalEntry> {
    let c2p = child_to_parent(db);
    db.entries
        .iter()
        .map(|(eid, e)| entry_to_canonical(db, eid, e, &c2p))
        .collect()
}

/// UUIDs of entries permanently deleted (KDBX tombstones).
pub fn tombstoned_uuids(db: &Database) -> HashSet<Uuid> {
    db.deleted_objects
        .iter()
        .filter_map(|n| n.as_uuid().cloned())
        .collect()
}

/// Crash-safe save: write temp file, fsync, atomic rename, fsync parent dir.
pub fn save_vault(v: &KdbxVault) -> Result<()> {
    let tmp = v.path.with_extension("kdbx.tmp");
    {
        let mut f = File::create(&tmp).with_context(|| format!("create {}", tmp.display()))?;
        save_database(&mut f, &v.db, &v.key).context("serialize .kdbx")?;
        f.sync_all().context("fsync tmp")?;
    }
    std::fs::rename(&tmp, &v.path).context("atomic rename into place")?;
    if let Some(parent) = v.path.parent() {
        let d = File::open(parent).context("open parent dir")?;
        d.sync_all().context("fsync parent dir")?;
    }
    Ok(())
}

/// Build a fresh entry from Bitwarden-side content (adopt path).
pub fn bw_adopt_entry(item: &crate::bw::BwItem) -> Entry {
    use keepass_rs::model::core::security::ProtectedString as PS;
    let mut e = Entry::new(NodeId::new_uuid());
    e.title = item.name.clone();
    let login = item.login.clone().unwrap_or_default();
    e.username = PS::new_protected(&login.username.unwrap_or_default());
    e.password = PS::new_protected(&login.password.unwrap_or_default());
    e.url = login
        .uris
        .unwrap_or_default()
        .into_iter()
        .find_map(|u| u.uri)
        .unwrap_or_default();
    e.notes = PS::new_protected(item.notes.as_deref().unwrap_or_default());
    if let Some(t) = login.totp.filter(|s| !s.is_empty()) {
        e.custom_fields.push(keepass_rs::model::entry::EntryField {
            name: "totp".to_string(),
            value: PS::new_protected(&t),
            is_protected: true,
        });
    }
    e
}

/// Empty in-memory vault for unit tests (no real .kdbx touched).
#[cfg(test)]
pub fn test_vault() -> KdbxVault {
    use keepass_rs::model::db::database::{Database, DatabaseVersion};
    KdbxVault {
        db: Database::new(DatabaseVersion::KDBX4),
        key: CompositeKey::new(),
        path: PathBuf::from("test.kdbx"),
    }
}
