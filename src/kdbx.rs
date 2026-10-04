//! KeePass .kdbx access: open, walk, extract, save.
//!
//! The database is decrypted strictly in RAM. Plaintext entries are projected
//! into [`CanonicalEntry`] and the `Database` is then available for write-back
//! mutations. Saves are crash-safe: build to `<name>.kdbx.tmp`, fsync, then
//! atomic rename over the original.

use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::IsTerminal;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use keepass_rs::model::core::node::NodeId;
use keepass_rs::model::core::security::ProtectedString;
use keepass_rs::model::db::composite_key::CompositeKey;
use keepass_rs::model::db::database::Database;
use keepass_rs::model::entry::Entry;
use keepass_rs::model::group::Group;
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
    fn put_spec(title: &str) -> NewEntrySpec {
        NewEntrySpec {
            title: title.to_string(),
            group: None,
            username: None,
            url: None,
            password: None,
            notes: None,
            update: false,
        }
    }

    #[test]
    fn put_creates_entry_with_all_fields() {
        let mut db = fixture_db();
        let mut spec = put_spec("newsvc");
        spec.group = Some("Ops".to_string());
        spec.username = Some(Secret::from_str("bob"));
        spec.url = Some("https://example.com".to_string());
        spec.password = Some(Secret::from_str("pw-1"));
        spec.notes = Some(Secret::from_str("hello"));
        assert!(matches!(put_entry(&mut db, spec), Ok(PutOutcome::Created)));
        assert_eq!(get(&db, "newsvc", "password"), "pw-1");
        assert_eq!(get(&db, "newsvc", "username"), "bob");
        assert_eq!(get(&db, "newsvc", "url"), "https://example.com");
        assert_eq!(get(&db, "newsvc", "notes"), "hello");
        let list = list_entries(&db);
        assert!(
            list.contains(&("Ops".to_string(), "newsvc".to_string())),
            "list: {list:?}"
        );
    }

    #[test]
    fn put_duplicate_without_update_errors() {
        let mut db = fixture_db();
        let msg = put_entry(&mut db, put_spec("github")).unwrap_err().to_string();
        assert!(msg.contains("already exists"), "unexpected error: {msg}");
        assert!(msg.contains("--update"), "unexpected error: {msg}");
    }

    #[test]
    fn put_update_replaces_only_provided_fields_and_never_moves() {
        let mut db = fixture_db();
        let mut spec = put_spec("github");
        spec.update = true;
        spec.group = Some("Misc".to_string()); // must be ignored on update
        spec.password = Some(Secret::from_str("new-pw"));
        assert!(matches!(put_entry(&mut db, spec), Ok(PutOutcome::Updated)));
        assert_eq!(get(&db, "github", "password"), "new-pw");
        // Untouched fields survive the merge.
        assert_eq!(get(&db, "github", "username"), "alice");
        assert_eq!(get(&db, "github", "notes"), "some notes");
        // Still in Ops, not moved to Misc.
        let list = list_entries(&db);
        assert!(list.contains(&("Ops".to_string(), "github".to_string())));
        assert!(!list.contains(&("Misc".to_string(), "github".to_string())));
    }

    #[test]
    fn put_creates_missing_group() {
        let mut db = fixture_db();
        let mut spec = put_spec("svc");
        spec.group = Some("BrandNew".to_string());
        spec.password = Some(Secret::from_str("x"));
        assert!(matches!(put_entry(&mut db, spec), Ok(PutOutcome::Created)));
        assert!(list_entries(&db).contains(&("BrandNew".to_string(), "svc".to_string())));
    }

    #[test]
    fn put_ambiguous_update_errors() {
        let mut db = fixture_db();
        let mut spec = put_spec("deploy key");
        spec.update = true;
        let msg = put_entry(&mut db, spec).unwrap_err().to_string();
        assert!(msg.contains("multiple entries"), "unexpected error: {msg}");
    }

    #[test]
    fn trim_one_newline_cases() {
        let t = |s: &[u8]| String::from_utf8(trim_one_newline(s.to_vec())).unwrap();
        assert_eq!(t(b"abc\n"), "abc");
        assert_eq!(t(b"abc\r\n"), "abc");
        assert_eq!(t(b"abc"), "abc");
        assert_eq!(t(b"abc\n\n"), "abc\n");
        assert_eq!(t(b""), "");
        assert_eq!(t(b"\n"), "");
        assert_eq!(t(b"\r\n"), "");
    }

    #[test]
    fn read_secret_input_from_file_trims_newline() {
        let dir = std::env::temp_dir();
        let tag = std::process::id();
        let p = dir.join(format!("kbs-put-test-{tag}.txt"));
        std::fs::write(&p, b"file-secret\n").unwrap();
        let s = read_secret_input("password", false, Some(p.as_path()))
            .unwrap()
            .expect("expected Some");
        assert_eq!(String::from_utf8_lossy(s.expose()), "file-secret");
        std::fs::remove_file(&p).ok();

        // No source -> None.
        assert!(read_secret_input("password", false, None).unwrap().is_none());

        // Both sources -> error.
        let p2 = dir.join(format!("kbs-put-test2-{tag}.txt"));
        std::fs::write(&p2, b"x").unwrap();
        let err = match read_secret_input("password", true, Some(p2.as_path())) {
            Err(e) => e.to_string(),
            Ok(_) => panic!("expected mutually-exclusive error"),
        };
        assert!(err.contains("mutually exclusive"), "unexpected error: {err}");
        std::fs::remove_file(&p2).ok();
    }

    #[test]
    fn list_entries_sorted_titles_only() {
        let mut db = fixture_db();
        let root = db.root_group_id.clone().unwrap();
        let mut e = Entry::new(NodeId::new_uuid());
        e.title = "zeta-root".to_string();
        assert!(db.add_entry(e, &root));
        assert_eq!(
            list_entries(&db),
            vec![
                ("".to_string(), "zeta-root".to_string()),
                ("Misc".to_string(), "deploy key".to_string()),
                ("Ops".to_string(), "deploy key".to_string()),
                ("Ops".to_string(), "github".to_string()),
            ]
        );
    }

    #[test]
    fn list_entries_excludes_recycle_bin() {
        let mut db = fixture_db();
        let root = db.root_group_id.clone().unwrap();
        let trash = add_group(&mut db, "Trash", &root);
        db.recycle_bin_uuid = trash.as_uuid().cloned();
        let mut e = Entry::new(NodeId::new_uuid());
        e.title = "old-secret".to_string();
        assert!(db.add_entry(e, &trash));
        let list = list_entries(&db);
        assert!(!list.iter().any(|(_, t)| t == "old-secret"), "list: {list:?}");
        assert!(list.iter().any(|(_, t)| t == "github"));
    }
}

// ---------------------------------------------------------------------------
// Local secret management: `put` (write) and `list` (titles-only inventory).
// These touch the .kdbx only — no journal, no Bitwarden, no lock.
// ---------------------------------------------------------------------------

/// Trim exactly one trailing newline (`\n` or `\r\n`) from secret input.
///
/// Documented CLI contract for `--password-stdin`, `--password-file`,
/// `--notes-stdin`, and `--notes-file`: one trailing newline is stripped so
/// `echo` output and editor-saved files work as-is; anything beyond that is
/// part of the secret.
pub fn trim_one_newline(mut v: Vec<u8>) -> Vec<u8> {
    if v.ends_with(b"\r\n") {
        v.truncate(v.len() - 2);
    } else if v.ends_with(b"\n") {
        v.truncate(v.len() - 1);
    }
    v
}

/// Read a secret for `put` from stdin or a file.
///
/// Secret material never comes from argv (visible in `ps`). At most one
/// source may be given; none means the field is left unset (`None`). Fails
/// closed when `--*-stdin` is requested but stdin is a terminal (nothing
/// piped in).
pub fn read_secret_input(
    kind: &str,
    from_stdin: bool,
    from_file: Option<&Path>,
) -> Result<Option<Secret>> {
    if from_stdin && from_file.is_some() {
        anyhow::bail!("--{kind}-stdin and --{kind}-file are mutually exclusive");
    }
    if from_stdin {
        if std::io::stdin().is_terminal() {
            anyhow::bail!(
                "--{kind}-stdin needs piped input, but stdin is a terminal; refusing to read a secret interactively"
            );
        }
        let mut v = Vec::new();
        std::io::Read::read_to_end(&mut std::io::stdin(), &mut v)
            .with_context(|| format!("read {kind} from stdin"))?;
        return Ok(Some(Secret::new(trim_one_newline(v))));
    }
    if let Some(f) = from_file {
        let v = std::fs::read(f).with_context(|| format!("read {kind} from {}", f.display()))?;
        return Ok(Some(Secret::new(trim_one_newline(v))));
    }
    Ok(None)
}

/// Fields for `put`. Secrets ride in the zeroizing [`Secret`] newtype; this
/// struct deliberately implements neither `Debug` nor `Display`. `None`
/// means "not provided": on create it becomes empty, on `--update` the
/// existing field is left untouched. `group` is honored on create only —
/// updates never move an entry between groups.
pub struct NewEntrySpec {
    pub title: String,
    pub group: Option<String>,
    pub username: Option<Secret>,
    pub url: Option<String>,
    pub password: Option<Secret>,
    pub notes: Option<Secret>,
    pub update: bool,
}

/// Outcome of [`put_entry`]. Carries no secret material, so `Debug` is safe.
#[derive(Debug, PartialEq, Eq)]
pub enum PutOutcome {
    Created,
    Updated,
}

/// Full "a/b/c" path of a group, including the group's own title, root excluded.
fn full_group_path(db: &Database, gid: &NodeId, c2p: &HashMap<NodeId, NodeId>) -> String {
    let mut parts: Vec<String> = Vec::new();
    let root = db.root_group_id.clone();
    let mut cur: Option<NodeId> = Some(gid.clone());
    let mut guard = 0;
    while let Some(id) = cur {
        guard += 1;
        if guard > 256 {
            break;
        }
        if Some(&id) == root.as_ref() {
            break;
        }
        match db.groups.get(&id) {
            Some(g) => {
                parts.push(g.title.clone());
                cur = c2p.get(&id).cloned();
            }
            None => break,
        }
    }
    parts.reverse();
    parts.join("/")
}

/// Find a group by exact title (deterministic: lowest full path wins), or
/// create it as a top-level group under root when missing.
fn find_or_create_group(db: &mut Database, name: &str) -> Result<NodeId> {
    let c2p = child_to_parent(db);
    let mut hits: Vec<NodeId> = db
        .groups
        .iter()
        .filter(|(_, g)| g.title == name)
        .map(|(gid, _)| gid.clone())
        .collect();
    hits.sort_by(|a, b| full_group_path(db, a, &c2p).cmp(&full_group_path(db, b, &c2p)));
    if let Some(gid) = hits.into_iter().next() {
        return Ok(gid);
    }
    let root = db
        .root_group_id
        .clone()
        .context("database has no root group")?;
    let id = NodeId::new_uuid();
    let mut g = Group::new(id.clone());
    g.title = name.to_string();
    if !db.add_group(g, &root) {
        anyhow::bail!("failed to create group {name:?}");
    }
    Ok(id)
}

fn secret_to_string(s: &Secret) -> String {
    String::from_utf8_lossy(s.expose()).into_owned()
}

/// Apply the provided spec fields onto an entry. `None` fields are skipped,
/// which gives `--update` its merge semantics.
fn apply_spec_fields(e: &mut Entry, spec: &NewEntrySpec) {
    if let Some(u) = spec.username.as_ref() {
        e.username = ProtectedString::new_protected(&secret_to_string(u));
    }
    if let Some(url) = spec.url.as_ref() {
        e.url = url.clone();
    }
    if let Some(p) = spec.password.as_ref() {
        e.password = ProtectedString::new_protected(&secret_to_string(p));
    }
    if let Some(n) = spec.notes.as_ref() {
        e.notes = ProtectedString::new_protected(&secret_to_string(n));
    }
}

/// Create or update an entry by exact title (matched globally, across groups).
///
/// * No match: create in `spec.group` (created when missing) or the root
///   group, applying every provided field. → [`PutOutcome::Created`]
/// * One match without `spec.update`: fail closed (duplicate title).
/// * One match with `spec.update`: overwrite the provided fields in place;
///   the entry is never moved between groups. → [`PutOutcome::Updated`]
/// * Several matches: fail closed listing each entry's group path.
pub fn put_entry(db: &mut Database, spec: NewEntrySpec) -> Result<PutOutcome> {
    let c2p = child_to_parent(db);
    let mut hits: Vec<NodeId> = db
        .entries
        .iter()
        .filter(|(_, e)| e.title == spec.title)
        .map(|(eid, _)| eid.clone())
        .collect();
    hits.sort_by(|a, b| group_path(db, a, &c2p).cmp(&group_path(db, b, &c2p)));
    match hits.len() {
        0 => {
            let gid = match spec.group {
                Some(ref name) => find_or_create_group(db, name)?,
                None => db
                    .root_group_id
                    .clone()
                    .context("database has no root group")?,
            };
            let mut e = Entry::new(NodeId::new_uuid());
            e.title = spec.title.clone();
            apply_spec_fields(&mut e, &spec);
            if !db.add_entry(e, &gid) {
                anyhow::bail!("failed to add entry {:?}", spec.title);
            }
            Ok(PutOutcome::Created)
        }
        1 => {
            if !spec.update {
                anyhow::bail!(
                    "an entry titled {:?} already exists; pass --update to replace it in place",
                    spec.title
                );
            }
            let e = db
                .entries
                .get_mut(&hits[0])
                .context("entry vanished mid-update")?;
            apply_spec_fields(e, &spec);
            Ok(PutOutcome::Updated)
        }
        _ => {
            let paths: Vec<String> = hits
                .iter()
                .map(|eid| {
                    let gp = group_path(db, eid, &c2p);
                    if gp.is_empty() {
                        spec.title.clone()
                    } else {
                        format!("{gp}/{}", spec.title)
                    }
                })
                .collect();
            anyhow::bail!(
                "multiple entries titled {:?}:\n  {}",
                spec.title,
                paths.join("\n  ")
            )
        }
    }
}

/// `(group_path, title)` for every live entry, sorted deterministically.
/// Entries in the recycle bin are excluded. Root-group entries carry an
/// empty group path. Titles only — field values are never exposed.
pub fn list_entries(db: &Database) -> Vec<(String, String)> {
    let c2p = child_to_parent(db);
    let recycle = db.recycle_bin_uuid.map(NodeId::from_uuid);
    let mut v: Vec<(String, String)> = db
        .entries
        .iter()
        .filter(|(eid, _)| match db.find_parent_group_of_entry(eid) {
            Some(p) => Some(p) != recycle,
            None => true,
        })
        .map(|(eid, e)| (group_path(db, eid, &c2p), e.title.clone()))
        .collect();
    v.sort();
    v
}
