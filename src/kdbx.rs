//! KeePass .kdbx access: open, walk, extract, save.
//!
//! The database is decrypted strictly in RAM. Plaintext entries are projected
//! into [`CanonicalEntry`] and the `Database` is then available for write-back
//! mutations. Saves are crash-safe: build to `<name>.kdbx.tmp`, fsync, then
//! atomic rename over the original.

use std::collections::HashSet;
use std::fs::File;
use std::io::IsTerminal;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use keepass::config::DatabaseVersion;
use keepass::db::{fields, Database, Entry, EntryId, GroupId, History};
use keepass::DatabaseKey;
use uuid::Uuid;

use crate::canonical::CanonicalEntry;
use crate::secret::Secret;
use crate::stamps::{SYNC_HASH_FIELD, SYNC_ID_FIELD};

pub struct KdbxVault {
    pub db: Database,
    password: Secret,
    keyfile: Option<Vec<u8>>,
    path: PathBuf,
}

fn build_key(password: &Secret, keyfile: Option<&[u8]>) -> Result<DatabaseKey> {
    let pw = std::str::from_utf8(password.expose()).context("master password is not UTF-8")?;
    let mut key = DatabaseKey::new().with_password(pw);
    if let Some(kf) = keyfile {
        let mut slice: &[u8] = kf;
        key = key
            .with_keyfile(&mut slice)
            .context("parse keyfile")?;
    }
    Ok(key)
}

/// Open and decrypt the .kdbx at `path`. Nothing plaintext touches disk.
pub fn open_vault(path: &Path, password: &Secret, keyfile: Option<&[u8]>) -> Result<KdbxVault> {
    let key = build_key(password, keyfile)?;
    let mut f = File::open(path).with_context(|| format!("open {}", path.display()))?;
    let mut db = Database::open(&mut f, key).context("decrypt .kdbx (wrong password/keyfile?)")?;
    // The keepass crate's writer emits KDBX 4.1 only (its dump path rejects
    // any other version). A KDBX 4.0 database (e.g. one last written by an
    // older KeePassXC) is therefore upgraded in memory at open: 4.1 is a
    // strict superset, every KeePassXC >= 2.7 reads it, and the first save
    // writes the vault back as 4.1.
    if db.config.version == DatabaseVersion::KDB4(0) {
        db.config.version = DatabaseVersion::KDB4(1);
    }
    Ok(KdbxVault {
        db,
        password: Secret::new(password.expose().to_vec()),
        keyfile: keyfile.map(|k| k.to_vec()),
        path: path.to_path_buf(),
    })
}

/// The standard KDBX field names. Anything else in an entry's field map is a
/// custom field.
fn is_standard_field(name: &str) -> bool {
    matches!(
        name,
        fields::TITLE | fields::USERNAME | fields::PASSWORD | fields::URL | fields::NOTES
    )
}

/// One entry found by the tree walk, with the context the old flat model
/// used to look up separately. The entry is cloned out of the tree: the
/// crate's `GroupRef` iterators tie child lifetimes to the parent handle,
/// which makes a borrowed recursive walk impossible; vaults here are small
/// and every consumer either sorts or projects the clone immediately.
struct WalkedEntry {
    id: EntryId,
    entry: Entry,
    group_path: String,
    parent: GroupId,
}

/// Walk the whole group tree once (explicit stack of group ids, so every
/// `GroupRef` is minted fresh from the database). Returns every entry (with
/// its group path excluding the root group) and every group as
/// (id, name, full path).
fn walk(db: &Database) -> (Vec<WalkedEntry>, Vec<(GroupId, String, String)>) {
    let mut entries = Vec::new();
    let mut groups = Vec::new();
    let mut stack: Vec<(GroupId, String)> = vec![(db.root().id(), String::new())];
    while let Some((gid, path)) = stack.pop() {
        let Some(group) = db.group(gid) else {
            continue;
        };
        groups.push((gid, group.name.clone(), path.clone()));
        for e in group.entries() {
            entries.push(WalkedEntry {
                id: e.id(),
                entry: (*e).clone(),
                group_path: path.clone(),
                parent: gid,
            });
        }
        for g in group.groups() {
            let child_path = if path.is_empty() {
                g.name.clone()
            } else {
                format!("{path}/{}", g.name)
            };
            stack.push((g.id(), child_path));
        }
    }
    (entries, groups)
}

/// TOTP is carried as a plain custom field named "totp" (case-insensitive).
fn extract_totp(entry: &Entry) -> Option<String> {
    entry
        .fields
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("totp"))
        .map(|(_, v)| v.get().clone())
        .filter(|s| !s.is_empty())
}

fn entry_to_canonical(db: &Database, w: &WalkedEntry) -> CanonicalEntry {
    let entry = &w.entry;
    let deleted = db.meta.recyclebin_uuid == Some(w.parent.uuid());
    let custom: Vec<(String, String)> = entry
        .fields
        .iter()
        .filter(|(name, _)| !is_standard_field(name) && !name.eq_ignore_ascii_case("totp"))
        .map(|(name, v)| (name.clone(), v.get().clone()))
        .collect();
    CanonicalEntry {
        uuid: w.id.uuid(),
        title: entry.get_title().unwrap_or_default().to_string(),
        username: entry.get_username().unwrap_or_default().to_string(),
        password: Secret::from_str(entry.get_password().unwrap_or_default()),
        url: entry.get_url().unwrap_or_default().to_string(),
        notes: entry.get(fields::NOTES).unwrap_or_default().to_string(),
        totp: extract_totp(entry),
        custom,
        group_path: w.group_path.clone(),
        deleted,
    }
}

/// Project every entry in the database into canonical form.
pub fn extract_entries(db: &Database) -> Vec<CanonicalEntry> {
    let (entries, _) = walk(db);
    entries.iter().map(|w| entry_to_canonical(db, w)).collect()
}

/// UUIDs of entries permanently deleted (KDBX tombstones).
pub fn tombstoned_uuids(db: &Database) -> HashSet<Uuid> {
    db.deleted_objects.keys().cloned().collect()
}

/// Crash-safe save: write temp file, fsync, atomic rename, fsync parent dir.
pub fn save_vault(v: &KdbxVault) -> Result<()> {
    let key = build_key(&v.password, v.keyfile.as_deref())?;
    let tmp = v.path.with_extension("kdbx.tmp");
    {
        let mut f = File::create(&tmp).with_context(|| format!("create {}", tmp.display()))?;
        v.db.save(&mut f, key).context("serialize .kdbx")?;
        f.sync_all().context("fsync tmp")?;
    }
    std::fs::rename(&tmp, &v.path).context("atomic rename into place")?;
    if let Some(parent) = v.path.parent() {
        let d = File::open(parent).context("open parent dir")?;
        d.sync_all().context("fsync parent dir")?;
    }
    Ok(())
}

/// Create a KeePass entry from Bitwarden-side content (adopt path), under the
/// root group. Returns the new entry's UUID.
///
/// Bitwarden custom fields ride along as KeePass custom fields (protected),
/// minus the sync stamps, which the adopt arm stamps back onto the Bitwarden
/// item instead of copying into KeePass. A field named "totp" (case
/// insensitive) is skipped when the item carries a real TOTP — KeePass
/// represents TOTP as its own field, and the collision would double-count in
/// [`CanonicalEntry::content_hash`].
pub fn adopt_bw_entry(db: &mut Database, item: &crate::bw::BwItem) -> Uuid {
    let mut root = db.root_mut();
    let mut e = root.add_entry();
    e.set_unprotected(fields::TITLE, item.name.clone());
    let login = item.login.clone().unwrap_or_default();
    e.set_protected(fields::USERNAME, login.username.unwrap_or_default());
    e.set_protected(fields::PASSWORD, login.password.unwrap_or_default());
    e.set_unprotected(
        fields::URL,
        login
            .uris
            .unwrap_or_default()
            .into_iter()
            .find_map(|u| u.uri)
            .unwrap_or_default(),
    );
    e.set_protected(fields::NOTES, item.notes.as_deref().unwrap_or_default());
    let totp = login.totp.clone().filter(|s| !s.is_empty());
    if let Some(t) = totp {
        e.set_protected("totp", t);
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
        e.set_protected(f.name.clone(), f.value.clone());
    }
    e.id().uuid()
}

/// Recycle one entry by UUID, mirroring the old `remove_entry(id, true)`:
/// move it into the recycle bin when the bin exists, otherwise permanently
/// remove it and record a KDBX tombstone. Returns false when no such entry.
pub fn recycle_entry(db: &mut Database, uuid: Uuid) -> bool {
    let eid = EntryId::from_uuid(uuid);
    if db.entry(eid).is_none() {
        return false;
    }
    if let Some(rb) = db.recycle_bin() {
        let rb_id = rb.id();
        drop(rb);
        if let Some(mut e) = db.entry_mut(eid) {
            return e.move_to(rb_id).is_ok();
        }
        return false;
    }
    if let Some(e) = db.entry_mut(eid) {
        e.remove();
        db.deleted_objects
            .insert(uuid, Some(chrono::Utc::now().naive_utc()));
        true
    } else {
        false
    }
}

/// Apply a Bitwarden edit into the KeePass entry with this UUID (writeback
/// path): the current state is preserved in entry history first. Returns
/// false when no such entry exists.
pub fn writeback_entry(db: &mut Database, uuid: Uuid, item: &crate::bw::BwItem) -> bool {
    let eid = EntryId::from_uuid(uuid);
    let Some(mut e) = db.entry_mut(eid) else {
        return false;
    };
    // Preserve the loser in entry history before overwriting.
    let snapshot: Entry = (*e).clone();
    match &mut e.history {
        Some(h) => h.add_entry(snapshot),
        None => {
            let mut h = History::default();
            h.add_entry(snapshot);
            e.history = Some(h);
        }
    }
    apply_bw_to_entry(&mut e, item);
    true
}

/// Overwrite a KeePass entry's syncable fields from a Bitwarden item.
pub fn apply_bw_to_entry(entry: &mut Entry, it: &crate::bw::BwItem) {
    let login = it.login.clone().unwrap_or_default();
    entry.set_unprotected(fields::TITLE, it.name.clone());
    entry.set_protected(fields::USERNAME, login.username.as_deref().unwrap_or_default());
    entry.set_protected(fields::PASSWORD, login.password.as_deref().unwrap_or_default());
    entry.set_unprotected(
        fields::URL,
        login
            .uris
            .as_ref()
            .and_then(|u| u.first())
            .and_then(|u| u.uri.clone())
            .unwrap_or_default(),
    );
    entry.set_protected(fields::NOTES, it.notes.as_deref().unwrap_or_default());
    // Replace non-stamp custom fields wholesale with the BW side's set.
    entry.fields.retain(|name, _| {
        is_standard_field(name) || name == SYNC_ID_FIELD || name == SYNC_HASH_FIELD
    });
    for f in &it.fields {
        if f.name == SYNC_ID_FIELD || f.name == SYNC_HASH_FIELD {
            continue;
        }
        entry.set_protected(f.name.clone(), f.value.clone());
    }
    if let Some(t) = login.totp.filter(|s| !s.is_empty()) {
        entry.fields.retain(|name, _| !name.eq_ignore_ascii_case("totp"));
        entry.set_protected("totp", t);
    }
    entry.times.last_modification = Some(chrono::Utc::now().naive_utc());
}

/// Empty in-memory vault for unit tests (no real .kdbx touched).
#[cfg(test)]
pub fn test_vault() -> KdbxVault {
    KdbxVault {
        db: Database::new(),
        password: Secret::new(Vec::new()),
        keyfile: None,
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
    let (entries, _) = walk(db);
    let mut hits: Vec<&WalkedEntry> = entries.iter().filter(|w| entry_title(&w.entry) == title).collect();
    hits.sort_by(|a, b| a.group_path.cmp(&b.group_path).then(entry_title(&a.entry).cmp(entry_title(&b.entry))));
    match hits.len() {
        0 => anyhow::bail!("no entry titled {:?}", title),
        1 => Ok(Secret::new(entry_field_bytes(&hits[0].entry, field)?)),
        _ => {
            let paths: Vec<String> = hits
                .iter()
                .map(|w| {
                    if w.group_path.is_empty() {
                        entry_title(&w.entry).to_string()
                    } else {
                        format!("{}/{}", w.group_path, entry_title(&w.entry))
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

fn entry_title(e: &Entry) -> &str {
    e.get_title().unwrap_or_default()
}

/// Raw bytes of one entry field. Custom fields are matched case-insensitively;
/// an unknown name errors listing the available field names.
fn entry_field_bytes(e: &Entry, field: &str) -> Result<Vec<u8>> {
    let lowered = field.to_ascii_lowercase();
    match lowered.as_str() {
        "password" => Ok(e.get_password().unwrap_or_default().as_bytes().to_vec()),
        "username" => Ok(e.get_username().unwrap_or_default().as_bytes().to_vec()),
        "url" => Ok(e.get_url().unwrap_or_default().as_bytes().to_vec()),
        "totp" => Ok(extract_totp(e).unwrap_or_default().into_bytes()),
        "notes" => Ok(e.get(fields::NOTES).unwrap_or_default().as_bytes().to_vec()),
        custom => match e
            .fields
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case(custom))
        {
            Some((_, v)) => Ok(v.get().as_bytes().to_vec()),
            None => {
                let mut names = vec!["password", "username", "url", "totp", "notes"];
                names.extend(
                    e.fields
                        .keys()
                        .filter(|k| !is_standard_field(k))
                        .map(|k| k.as_str()),
                );
                anyhow::bail!(
                    "no field {:?} on entry {:?}; available: {}",
                    field,
                    entry_title(e),
                    names.join(", ")
                )
            }
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn add_group(db: &mut Database, title: &str, parent: GroupId) -> GroupId {
        let mut parent = db.group_mut(parent).expect("parent group");
        let mut g = parent.add_group();
        g.name = title.to_string();
        g.id()
    }

    fn add_entry(db: &mut Database, parent: GroupId, title: &str) -> EntryId {
        let mut parent = db.group_mut(parent).expect("parent group");
        let mut e = parent.add_entry();
        e.set_unprotected(fields::TITLE, title);
        e.id()
    }

    /// "github" is unique and fully populated; "deploy key" exists twice
    /// (Ops and Misc) for the ambiguity test.
    fn fixture_db() -> Database {
        let mut db = Database::new();
        let root = db.root().id();
        let ops = add_group(&mut db, "Ops", root);
        let misc = add_group(&mut db, "Misc", root);

        {
            let mut g = db.group_mut(ops).unwrap();
            let mut e = g.add_entry();
            e.set_unprotected(fields::TITLE, "github");
            e.set_protected(fields::USERNAME, "alice");
            e.set_protected(fields::PASSWORD, "s3cr3t-pw");
            e.set_unprotected(fields::URL, "https://github.com");
            e.set_protected(fields::NOTES, "some notes");
            e.set_protected("totp", "JBSWY3DPEHPK3PXP");
            e.set_protected("API Key", "ak-123");
        }
        for parent in [ops, misc] {
            let mut g = db.group_mut(parent).unwrap();
            let mut d = g.add_entry();
            d.set_unprotected(fields::TITLE, "deploy key");
            d.set_protected(fields::USERNAME, "deployer");
            d.set_protected(fields::PASSWORD, "key-pw");
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
        let root = db.root().id();
        add_entry(&mut db, root, "zeta-root");
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
        let root = db.root().id();
        let trash = add_group(&mut db, "Trash", root);
        db.meta.recyclebin_uuid = Some(trash.uuid());
        add_entry(&mut db, trash, "old-secret");
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

/// Find a group by exact title (deterministic: lowest full path wins), or
/// create it as a top-level group under root when missing.
fn find_or_create_group(db: &mut Database, name: &str) -> Result<GroupId> {
    let (_, groups) = walk(db);
    // groups[i].2 is the group's own full path (root excluded), which is the
    // deterministic sort key the old implementation used.
    let mut hits: Vec<&(GroupId, String, String)> = groups
        .iter()
        .filter(|(_, gname, _)| gname == name)
        .collect();
    hits.sort_by(|a, b| a.2.cmp(&b.2));
    if let Some((gid, _, _)) = hits.into_iter().next() {
        return Ok(*gid);
    }
    let mut root = db.root_mut();
    let mut g = root.add_group();
    g.name = name.to_string();
    Ok(g.id())
}

fn secret_to_string(s: &Secret) -> String {
    String::from_utf8_lossy(s.expose()).into_owned()
}

/// Apply the provided spec fields onto an entry. `None` fields are skipped,
/// which gives `--update` its merge semantics.
fn apply_spec_fields(e: &mut Entry, spec: &NewEntrySpec) {
    if let Some(u) = spec.username.as_ref() {
        e.set_protected(fields::USERNAME, secret_to_string(u));
    }
    if let Some(url) = spec.url.as_ref() {
        e.set_unprotected(fields::URL, url.clone());
    }
    if let Some(p) = spec.password.as_ref() {
        e.set_protected(fields::PASSWORD, secret_to_string(p));
    }
    if let Some(n) = spec.notes.as_ref() {
        e.set_protected(fields::NOTES, secret_to_string(n));
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
    let (entries, _) = walk(db);
    let mut hits: Vec<(EntryId, String)> = entries
        .iter()
        .filter(|w| entry_title(&w.entry) == spec.title)
        .map(|w| (w.id, w.group_path.clone()))
        .collect();
    hits.sort_by(|a, b| a.1.cmp(&b.1));
    match hits.len() {
        0 => {
            let gid = match spec.group {
                Some(ref name) => find_or_create_group(db, name)?,
                None => db.root().id(),
            };
            let mut group = db.group_mut(gid).context("target group vanished")?;
            let mut e = group.add_entry();
            e.set_unprotected(fields::TITLE, spec.title.clone());
            apply_spec_fields(&mut e, &spec);
            Ok(PutOutcome::Created)
        }
        1 => {
            if !spec.update {
                anyhow::bail!(
                    "an entry titled {:?} already exists; pass --update to replace it in place",
                    spec.title
                );
            }
            let mut e = db.entry_mut(hits[0].0).context("entry vanished mid-update")?;
            apply_spec_fields(&mut e, &spec);
            Ok(PutOutcome::Updated)
        }
        _ => {
            let paths: Vec<String> = hits
                .iter()
                .map(|(_, gp)| {
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
    let (entries, _) = walk(db);
    let recycle = db.meta.recyclebin_uuid;
    let mut v: Vec<(String, String)> = entries
        .iter()
        .filter(|w| Some(w.parent.uuid()) != recycle)
        .map(|w| (w.group_path.clone(), entry_title(&w.entry).to_string()))
        .collect();
    v.sort();
    v
}
