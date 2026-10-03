//! End-to-end test against a stub `bw serve`.
//!
//! Builds a fixture .kdbx with keepass-rs, runs the real plan/apply pipeline
//! against a minimal in-process HTTP stub, and asserts idempotency,
//! quarantine-on-foreign-edit, and atomic save/reopen.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Mutex};

use keepass_bw_sync::bw::BwClient;
use keepass_bw_sync::journal::Journal;
use keepass_bw_sync::kdbx::{extract_entries, open_vault, save_vault, tombstoned_uuids};
use keepass_bw_sync::secret::Secret;
use keepass_bw_sync::sync::{apply, plan, Action, SyncOpts};

struct Stub {
    items: Vec<serde_json::Value>,
    next_id: u64,
}

fn handle(mut stream: std::net::TcpStream, state: &Arc<Mutex<Stub>>) {
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut request_line = String::new();
    if reader.read_line(&mut request_line).is_err() || request_line.trim().is_empty() {
        return;
    }
    let mut content_length = 0usize;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).is_err() {
            return;
        }
        let t = line.trim();
        if t.is_empty() {
            break;
        }
        // Header names arrive lowercase from reqwest; match case-insensitively.
        if let Some(v) = t.to_ascii_lowercase().strip_prefix("content-length:") {
            content_length = v.trim().parse().unwrap_or(0);
        }
    }
    let mut body = vec![0u8; content_length];
    if content_length > 0 && reader.read_exact(&mut body).is_err() {
        return;
    }
    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() < 2 {
        return;
    }
    let (method, path) = (parts[0], parts[1]);
    let mut st = state.lock().unwrap();
    let resp_body = match (method, path) {
        ("POST", "/sync") => serde_json::json!({"success": true, "data": {}}),
        ("GET", "/list/object/items") => serde_json::json!({"success": true, "data": {"object": "list", "data": st.items}}),
        ("GET", "/list/object/folders") => serde_json::json!({"success": true, "data": {"object": "list", "data": []}}),
        ("POST", "/object/folder") => {
            serde_json::json!({"success": true, "data": {"id": "folder-1"}})
        }
        ("POST", "/object/item") => {
            let mut v: serde_json::Value = serde_json::from_slice(&body).unwrap();
            st.next_id += 1;
            let id = format!("bw-{}", st.next_id);
            v["id"] = id.clone().into();
            v["revisionDate"] = "2026-10-03T00:00:00Z".into();
            st.items.push(v);
            serde_json::json!({"success": true, "data": {"id": id}})
        }
        _ if method == "GET" && path.starts_with("/object/item/") => {
            let id = path.trim_start_matches("/object/item/");
            let item = st
                .items
                .iter()
                .find(|i| i["id"] == id)
                .cloned()
                .unwrap_or(serde_json::json!({}));
            serde_json::json!({"success": true, "data": item})
        }
        _ if method == "PUT" && path.starts_with("/object/item/") => {
            let id = path.trim_start_matches("/object/item/");
            let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
            if let Some(item) = st.items.iter_mut().find(|i| i["id"] == id) {
                if let Some(obj) = v.as_object() {
                    for (k, val) in obj {
                        item[k] = val.clone();
                    }
                }
                item["revisionDate"] = "2026-10-03T00:00:01Z".into();
            }
            serde_json::json!({"success": true})
        }
        _ if method == "DELETE" && path.starts_with("/object/item/") => {
            let id = path.trim_start_matches("/object/item/");
            if let Some(item) = st.items.iter_mut().find(|i| i["id"] == id) {
                item["deletedDate"] = "2026-10-03T00:00:02Z".into();
            }
            serde_json::json!({"success": true})
        }
        _ => serde_json::json!({"success": false}),
    };
    let body = resp_body.to_string();
    let resp = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    let _ = stream.write_all(resp.as_bytes());
}

fn spawn_stub() -> (String, Arc<Mutex<Stub>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let state = Arc::new(Mutex::new(Stub {
        items: vec![],
        next_id: 0,
    }));
    let s2 = state.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            handle(stream, &s2);
        }
    });
    (format!("http://{}", addr), state)
}

fn fixture_kdbx(path: &std::path::Path) {
    use keepass_rs::model::core::node::NodeId;
    use keepass_rs::model::core::security::ProtectedString as PS;
    use keepass_rs::model::db::composite_key::CompositeKey;
    use keepass_rs::model::db::database::{Database, DatabaseVersion};
    use keepass_rs::model::entry::Entry;
    use keepass_rs::model::group::Group;

    let mut db = Database::new(DatabaseVersion::KDBX4);
    let root_id = NodeId::new_uuid();
    let mut root_group = Group::new(root_id);
    root_group.title = "Root".to_string();
    // Dummy parent (not in groups) + no root yet => accepted as the root group.
    assert!(db.add_group(root_group, &NodeId::new_uuid()));
    let root = db.root_group_id.clone().unwrap();
    for (title, user, pw) in [("github", "alice", "s3cret1"), ("bank", "bob", "s3cret2")] {
        let mut e = Entry::new(NodeId::new_uuid());
        e.title = title.into();
        e.username = PS::new_protected(user);
        e.password = PS::new_protected(pw);
        e.url = format!("https://{}.example.com", title);
        assert!(db.add_entry(e, &root));
    }
    let key = CompositeKey::new().with_password(b"test-password");
    let mut f = std::fs::File::create(path).unwrap();
    keepass_rs::save_database(&mut f, &db, &key).unwrap();
}

fn tmpdir() -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("kbs-test-{}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    d
}

#[test]
fn full_sync_flow_is_idempotent_and_quarantines_foreign_edits() {
    let dir = tmpdir();
    let kdbx = dir.join("test.kdbx");
    let journal_path = dir.join("sync.db");
    fixture_kdbx(&kdbx);

    let (base, state) = spawn_stub();
    let bw = BwClient::new(&base).unwrap();
    bw.sync().unwrap();

    let pw = Secret::from_str("test-password");
    let mut vault = open_vault(&kdbx, &pw, None).unwrap();
    let journal = Journal::open(&journal_path).unwrap();
    let opts = SyncOpts::default();

    // First run: two creates.
    let entries = extract_entries(&vault.db);
    assert_eq!(entries.len(), 2);
    let tombstones = tombstoned_uuids(&vault.db);
    let items = bw.list_items().unwrap();
    let p = plan(&entries, &tombstones, &items, &journal, &opts).unwrap();
    assert_eq!(p.actions.len(), 2);
    let mut folder_ids = HashMap::new();
    let folders = bw.list_folders().unwrap();
    let (r, ops) = apply(&p, &entries, &items, &bw, &mut vault, &mut folder_ids, &folders, &opts).unwrap();
    assert_eq!(r.created, 2);
    assert_eq!(r.quarantined, 0);
    // Journal ops are deferred: nothing is committed by apply itself.
    assert_eq!(journal.live_mapping_count().unwrap(), 0);
    journal.apply_ops(&ops).unwrap();
    assert_eq!(journal.live_mapping_count().unwrap(), 2);

    // Second run: fully idempotent, zero actions.
    let entries = extract_entries(&vault.db);
    let items = bw.list_items().unwrap();
    let p = plan(&entries, &tombstones, &items, &journal, &opts).unwrap();
    assert!(p.actions.is_empty(), "expected idempotent no-op, got {}", p.actions.len());

    // Foreign edit on the Bitwarden side: quarantine, never overwrite.
    {
        let mut st = state.lock().unwrap();
        st.items[0]["name"] = "github (edited in bitwarden)".into();
    }
    let entries = extract_entries(&vault.db);
    let items = bw.list_items().unwrap();
    let p = plan(&entries, &tombstones, &items, &journal, &opts).unwrap();
    assert_eq!(p.actions.len(), 1);
    let mut folder_ids = HashMap::new();
    let (r, ops) = apply(&p, &entries, &items, &bw, &mut vault, &mut folder_ids, &folders, &opts).unwrap();
    assert_eq!(r.quarantined, 1);
    assert_eq!(r.updated, 0);
    journal.apply_ops(&ops).unwrap();
    assert_eq!(journal.list_quarantine().unwrap().len(), 1);

    // Adopt path: an unstamped Bitwarden item becomes a KeePass entry, and
    // the KBS_SYNC_ID stamp is written back onto the Bitwarden item.
    {
        let mut st = state.lock().unwrap();
        st.items.push(serde_json::json!({
            "id": "bw-adopt-1", "name": "adopted", "notes": null, "favorite": false,
            "folderId": null,
            "login": {"username": "u", "password": "p", "totp": null, "uris": []},
            "fields": [],
            "revisionDate": "2026-10-03T00:00:00Z", "deletedDate": null,
        }));
    }
    let opts = SyncOpts { adopt: true, ..Default::default() };
    let entries = extract_entries(&vault.db);
    let items = bw.list_items().unwrap();
    let p = plan(&entries, &tombstones, &items, &journal, &opts).unwrap();
    assert!(
        p.actions.iter().any(|a| matches!(a, Action::AdoptBwNew { .. })),
        "expected an AdoptBwNew action, got {} actions",
        p.actions.len()
    );
    let mut folder_ids = HashMap::new();
    let (r, ops) = apply(&p, &entries, &items, &bw, &mut vault, &mut folder_ids, &folders, &opts).unwrap();
    assert_eq!(r.kp_adopted, 1);
    journal.apply_ops(&ops).unwrap();
    {
        let st = state.lock().unwrap();
        let it = st.items.iter().find(|i| i["id"] == "bw-adopt-1").unwrap();
        let fields = it["fields"].as_array().unwrap();
        assert!(
            fields.iter().any(|f| f["name"] == "KBS_SYNC_ID"),
            "adopted item must carry the KBS_SYNC_ID stamp"
        );
    }

    // Atomic save + reopen: entries intact (2 original + 1 adopted).
    save_vault(&vault).unwrap();
    let v2 = open_vault(&kdbx, &pw, None).unwrap();
    assert_eq!(extract_entries(&v2.db).len(), 3);
}
