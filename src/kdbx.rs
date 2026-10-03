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
use keepass_rs::model::core::node::NodeId;
use keepass_rs::model::core::security::ProtectedString;
use keepass_rs::model::db::composite_key::CompositeKey;
use keepass_rs::model::db::database::Database;
use keepass_rs::model::entry::Entry;
use keepass_rs::{open_database, save_database};
use uuid::Uuid;

use crate::canonical::CanonicalEntry;
use crate::secret::Secret;
use crate::stamps::{SYNC_HASH_FIELD, SYNC_ID_FIELD};

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
///
/// Bitwarden custom fields ride along as KeePass custom fields (protected),
/// minus the sync stamps, which the adopt arm stamps back onto the Bitwarden
/// item instead of copying into KeePass. A field named "totp" (case
/// insensitive) is skipped when the item carries a real TOTP — KeePass
/// represents TOTP as its own field, and the collision would double-count in
/// [`CanonicalEntry::content_hash`].
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
    let totp = login.totp.clone().filter(|s| !s.is_empty());
    if let Some(t) = totp {
        e.custom_fields.push(keepass_rs::model::entry::EntryField {
            name: "totp".to_string(),
            value: PS::new_protected(&t),
            is_protected: true,
        });
    }
    // A field named "totp" collides with the real TOTP above and would
    // double-count in `CanonicalEntry::content_hash`; skip it then.
    let skip_totp = login.totp.map(|s| !s.is_empty()).unwrap_or(false);
    for f in &item.fields {
        if f.name == SYNC_ID_FIELD || f.name == SYNC_HASH_FIELD {
            continue;
        }
        if skip_totp && f.name.eq_ignore_ascii_case("totp") {
            continue;
        }
        e.custom_fields.push(keepass_rs::model::entry::EntryField {
            name: f.name.clone(),
            value: PS::new_protected(&f.value),
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

/// Look up a single entry by exact title and return one field value.
///
/// The field argument is one of: password (default), username, url, totp,
/// notes, or a custom-field name (matched case-insensitively). Zero matches
/// errors; multiple matches error listing each entry group path so the
/// caller can disambiguate.
///
/// The consumption path for automation: workers pull secrets from the local
/// .kdbx without touching the sync journal or Bitwarden.
pub fn get_entry_field(db: &Database, title: &str, field: &str) -> Result<Secret> {
    let c2p = child_to_parent(db);
    let mut hits: Vec<(&NodeId, &Entry)> = db
        .entries
        .iter()
        .filter(|(_, e)| e.title == title)
        .collect();
    hits.sort_by(|a, b| {
        group_path(db, a.0, &c2p)
            .cmp(&group_path(db, b.0, &c2p))
            .then(a.1.title.cmp(&b.1.title))
    });
    match hits.len() {
        0 => anyhow::bail!("no entry titled {:?}", title),
        1 => {
            let (_, e) = hits[0];
            Ok(Secret::new(entry_field_bytes(e, field)?))
        }
        _ => {
            let paths: Vec<String> = hits
                .iter()
                .map(|(eid, e)| {
                    let gp = group_path(db, eid, &c2p);
                    if gp.is_empty() {
                        e.title.clone()
                    } else {
                        format!("{}/{}", gp, e.title)
                    }
                })
                .collect();
            anyhow::bail!(
                "multiple entries titled {:?}:\n  {}",
                title,
                paths.join("\n  ")
            )
        }
    }
}

/// Raw bytes of one entry field. Custom fields are matched case-insensitively;
/// an unknown name errors listing the available field names.
fn entry_field_bytes(e: &Entry, field: &str) -> Result<Vec<u8>> {
    let lowered = field.to_ascii_lowercase();
    match lowered.as_str() {
        "password" => Ok(ps_bytes(&e.password)),
        "username" => Ok(ps_bytes(&e.username)),
        "url" => Ok(e.url.as_bytes().to_vec()),
        "totp" => Ok(extract_totp(e).unwrap_or_default().into_bytes()),
        "notes" => Ok(ps_bytes(&e.notes)),
        custom => match e
            .custom_fields
            .iter()
            .find(|f| f.name.eq_ignore_ascii_case(custom))
        {
            Some(f) => Ok(ps_bytes(&f.value)),
            None => {
                let mut names = vec!["password", "username", "url", "totp", "notes"];
                names.extend(e.custom_fields.iter().map(|f| f.name.as_str()));
                anyhow::bail!(
                    "no field {:?} on entry {:?}; available: {}",
                    field,
                    e.title,
                    names.join(", ")
                )
            }
        },
    }
}

fn ps_bytes(p: &ProtectedString) -> Vec<u8> {
    p.as_str().as_bytes().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use keepass_rs::model::core::node::NodeId;
    use keepass_rs::model::core::security::ProtectedString as PS;
    use keepass_rs::model::db::database::{Database, DatabaseVersion};
    use keepass_rs::model::entry::{Entry, EntryField};
    use keepass_rs::model::group::Group;

    fn add_group(db: &mut Database, title: &str, parent: &NodeId) -> NodeId {
        let id = NodeId::new_uuid();
        let mut g = Group::new(id.clone());
        g.title = title.to_string();
        assert!(db.add_group(g, parent), "add_group {}", title);
        id
    }

    /// "github" is unique and fully populated; "deploy key" exists twice
    /// (Ops and Misc) for the ambiguity test.
    fn fixture_db() -> Database {
        let mut db = Database::new(DatabaseVersion::KDBX4);
        let root_id = NodeId::new_uuid();
        let mut root = Group::new(root_id);
        root.title = "Root".to_string();
        assert!(db.add_group(root, &NodeId::new_uuid()));
        let root = db.root_group_id.clone().unwrap();

        let ops = add_group(&mut db, "Ops", &root);
        let misc = add_group(&mut db, "Misc", &root);

        let mut e = Entry::new(NodeId::new_uuid());
        e.title = "github".to_string();
        e.username = PS::new_protected("alice");
        e.password = PS::new_protected("s3cr3t-pw");
        e.url = "https://github.com".to_string();
        e.notes = PS::new_protected("some notes");
        e.custom_fields.push(EntryField {
            name: "totp".to_string(),
            value: PS::new_protected("JBSWY3DPEHPK3PXP"),
            is_protected: true,
        });
        e.custom_fields.push(EntryField {
            name: "API Key".to_string(),
            value: PS::new_protected("ak-123"),
            is_protected: true,
        });
        assert!(db.add_entry(e, &ops));

        for parent in [&ops, &misc] {
            let mut d = Entry::new(NodeId::new_uuid());
            d.title = "deploy key".to_string();
            d.username = PS::new_protected("deployer");
            d.password = PS::new_protected("key-pw");
            assert!(db.add_entry(d, parent));
        }
        db
    }

    fn get(db: &Database, title: &str, field: &str) -> String {
        let s = get_entry_field(db, title, field).map_err(|e| e.to_string()).unwrap();
        String::from_utf8_lossy(s.expose()).into_owned()
    }

    fn get_err(db: &Database, title: &str, field: &str) -> String {
        get_entry_field(db, title, field).map(|_| ()).unwrap_err().to_string()
    }

    #[test]
    fn get_returns_each_field() {
        let db = fixture_db();
        assert_eq!(get(&db, "github", "password"), "s3cr3t-pw");
        assert_eq!(get(&db, "github", "username"), "alice");
        assert_eq!(get(&db, "github", "url"), "https://github.com");
        assert_eq!(get(&db, "github", "totp"), "JBSWY3DPEHPK3PXP");
        assert_eq!(get(&db, "github", "notes"), "some notes");
        assert_eq!(get(&db, "github", "API Key"), "ak-123");
        // Custom-field names match case-insensitively.
        assert_eq!(get(&db, "github", "api key"), "ak-123");
    }

    #[test]
    fn get_unknown_title_errors() {
        let db = fixture_db();
        let msg = get_err(&db, "nope", "password");
        assert!(msg.contains("no entry titled"), "unexpected error: {msg}");
    }

    #[test]
    fn get_duplicate_title_errors_with_group_paths() {
        let db = fixture_db();
        let msg = get_err(&db, "deploy key", "password");
        assert!(msg.contains("multiple entries"), "unexpected error: {msg}");
        assert!(msg.contains("Ops"), "missing Ops path: {msg}");
        assert!(msg.contains("Misc"), "missing Misc path: {msg}");
    }

    #[test]
    fn get_unknown_field_errors_with_available_names() {
        let db = fixture_db();
        let msg = get_err(&db, "github", "bogus");
        assert!(msg.contains("no field"), "unexpected error: {msg}");
        assert!(msg.contains("API Key"), "missing custom name: {msg}");
    }
}
