//! End-to-end test against a stub `bw serve`.
//!
//! Builds a fixture .kdbx with the keepass crate, runs the real plan/apply pipeline
//! against a minimal in-process HTTP stub, and asserts idempotency,
//! quarantine-on-foreign-edit, and atomic save/reopen.

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
    // (status, body): the stub is intentionally dumb, but the PUT must have
    // replace semantics like the real serve's `toView` (the request body is
    // the new view, not a merge), and unknown items must 404 so client
    // error paths are actually exercised.
    let (status, resp_body) = match (method, path) {
        ("POST", "/sync") => (200, serde_json::json!({"success": true, "data": {}})),
        ("GET", "/list/object/items") => (200, serde_json::json!({"success": true, "data": {"object": "list", "data": st.items}})),
        ("GET", "/list/object/folders") => (200, serde_json::json!({"success": true, "data": {"object": "list", "data": []}})),
        ("POST", "/object/folder") => {
            (200, serde_json::json!({"success": true, "data": {"id": "folder-1"}}))
        }
        ("POST", "/object/item") => {
            let mut v: serde_json::Value = serde_json::from_slice(&body).unwrap();
            st.next_id += 1;
            let id = format!("bw-{}", st.next_id);
            v["id"] = id.clone().into();
            v["revisionDate"] = "2026-10-03T00:00:00Z".into();
            st.items.push(v);
            (200, serde_json::json!({"success": true, "data": {"id": id}}))
        }
        _ if method == "GET" && path.starts_with("/object/item/") => {
            let id = path.trim_start_matches("/object/item/");
            match st.items.iter().find(|i| i["id"] == id).cloned() {
                Some(item) => (200, serde_json::json!({"success": true, "data": item})),
                None => (404, serde_json::json!({"success": false, "message": "not found"})),
            }
        }
        _ if method == "PUT" && path.starts_with("/object/item/") => {
            let id = path.trim_start_matches("/object/item/");
            let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
            if let Some(item) = st.items.iter_mut().find(|i| i["id"] == id) {
                // Replace semantics: the request body is the new view. Only
                // the view keys travel; id/revisionDate are server-managed.
                for k in ["type", "name", "notes", "favorite", "folderId", "reprompt", "fields", "login"] {
                    if let Some(val) = v.get(k) {
                        item[k] = val.clone();
                    }
                }
                item["revisionDate"] = "2026-10-03T00:00:01Z".into();
            }
            (200, serde_json::json!({"success": true}))
        }
        _ if method == "DELETE" && path.starts_with("/object/item/") => {
            let id = path.trim_start_matches("/object/item/");
            if let Some(item) = st.items.iter_mut().find(|i| i["id"] == id) {
                item["deletedDate"] = "2026-10-03T00:00:02Z".into();
            }
            (200, serde_json::json!({"success": true}))
        }
        _ => (200, serde_json::json!({"success": false})),
    };
    let body = resp_body.to_string();
    let reason = match status {
        200 => "OK",
        404 => "Not Found",
        _ => "Error",
    };
    let resp = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
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
    use keepass::db::fields;

    let mut db = keepass::Database::new();
    {
        let mut root = db.root_mut();
        root.name = "Root".into();
        for (title, user, pw) in [("github", "alice", "s3cret1"), ("bank", "bob", "s3cret2")] {
            let mut e = root.add_entry();
            e.set_unprotected(fields::TITLE, title);
            e.set_protected(fields::USERNAME, user);
            e.set_protected(fields::PASSWORD, pw);
            e.set_unprotected(fields::URL, format!("https://{}.example.com", title));
        }
    }
    let key = keepass::DatabaseKey::new().with_password("test-password");
    let mut f = std::fs::File::create(path).unwrap();
    db.save(&mut f, key).unwrap();
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
    let folders = bw.list_folders().unwrap();
    let p = plan(&entries, &tombstones, &items, &folders, &journal, &opts).unwrap();
    assert_eq!(p.actions.len(), 2);
    let (r, ops) = apply(&p, &entries, &items, &bw, &mut vault, &folders).unwrap();
    assert_eq!(r.created, 2);
    assert_eq!(r.quarantined, 0);
    // Journal ops are deferred: nothing is committed by apply itself.
    assert_eq!(journal.live_mapping_count().unwrap(), 0);
    journal.apply_ops(&ops).unwrap();
    assert_eq!(journal.live_mapping_count().unwrap(), 2);

    // Second run: fully idempotent, zero actions.
    let entries = extract_entries(&vault.db);
    let items = bw.list_items().unwrap();
    let p = plan(&entries, &tombstones, &items, &folders, &journal, &opts).unwrap();
    assert!(p.actions.is_empty(), "expected idempotent no-op, got {}", p.actions.len());

    // Foreign edit on the Bitwarden side: quarantine, never overwrite.
    {
        let mut st = state.lock().unwrap();
        st.items[0]["name"] = "github (edited in bitwarden)".into();
    }
    let entries = extract_entries(&vault.db);
    let items = bw.list_items().unwrap();
    let p = plan(&entries, &tombstones, &items, &folders, &journal, &opts).unwrap();
    assert_eq!(p.actions.len(), 1);
    let (r, ops) = apply(&p, &entries, &items, &bw, &mut vault, &folders).unwrap();
    assert_eq!(r.quarantined, 1);
    assert_eq!(r.updated, 0);
    journal.apply_ops(&ops).unwrap();
    assert_eq!(journal.list_quarantine().unwrap().len(), 1);

    // Adopt path: an unstamped login with custom fields becomes a KeePass
    // entry WITH those fields (regression: adopt used to drop them, and the
    // next sync's UpdateBw then wiped them server-side). A secure note must
    // NOT be adopted: it quarantines for human review, item untouched.
    {
        let mut st = state.lock().unwrap();
        st.items.push(serde_json::json!({
            "id": "bw-adopt-1", "name": "adopted", "notes": null, "favorite": false,
            "folderId": null, "type": 1, "reprompt": 0,
            "login": {"username": "u", "password": "p", "totp": null,
                      "uris": [{"uri": "https://adopted.example.com", "match": null}]},
            "fields": [{"name": "API key", "value": "abc123", "type": 0}],
            "revisionDate": "2026-10-03T00:00:00Z", "deletedDate": null,
        }));
        st.items.push(serde_json::json!({
            "id": "bw-note-1", "name": "a secure note", "notes": "secret text",
            "favorite": false, "folderId": null, "type": 2, "reprompt": 0,
            "secureNote": {"type": 0},
            "fields": [],
            "revisionDate": "2026-10-03T00:00:00Z", "deletedDate": null,
        }));
    }
    let opts = SyncOpts { adopt: true, ..Default::default() };
    let entries = extract_entries(&vault.db);
    let items = bw.list_items().unwrap();
    let p = plan(&entries, &tombstones, &items, &folders, &journal, &opts).unwrap();
    assert!(
        p.actions.iter().any(|a| matches!(a, Action::AdoptBwNew { .. })),
        "expected an AdoptBwNew action, got {} actions",
        p.actions.len()
    );
    assert!(
        p.actions.iter().any(|a| matches!(a, Action::Quarantine(q) if q.kind == "unsupported_bw_type")),
        "expected the secure note to quarantine, got {} actions",
        p.actions.len()
    );
    let (r, ops) = apply(&p, &entries, &items, &bw, &mut vault, &folders).unwrap();
    assert_eq!(r.kp_adopted, 1);
    // Two quarantines: the secure note (new) plus the foreign edit on bw-1
    // re-reported (pre-existing behavior; the journal dedups it at commit).
    assert_eq!(r.quarantined, 2);
    let qkinds: Vec<&str> = ops
        .iter()
        .filter_map(|op| match op {
            keepass_bw_sync::journal::JournalOp::Quarantine { kind, .. } => Some(*kind),
            _ => None,
        })
        .collect();
    assert!(qkinds.contains(&"unsupported_bw_type"));
    assert!(qkinds.contains(&"foreign-bw-edit"));
    journal.apply_ops(&ops).unwrap();
    {
        let st = state.lock().unwrap();
        let it = st.items.iter().find(|i| i["id"] == "bw-adopt-1").unwrap();
        let fields = it["fields"].as_array().unwrap();
        assert!(
            fields.iter().any(|f| f["name"] == "KBS_SYNC_ID"),
            "adopted item must carry the KBS_SYNC_ID stamp"
        );
        assert!(
            fields.iter().any(|f| f["name"] == "API key" && f["value"] == "abc123"),
            "adopt must not wipe the item's custom fields"
        );
        // Secure note: quarantined, but its server-side shape is intact.
        let note = st.items.iter().find(|i| i["id"] == "bw-note-1").unwrap();
        assert_eq!(note["type"], 2, "secure note must keep its type");
        assert_eq!(note["notes"], "secret text");
    }

    // Second sync after adopt: the adopted entry round-tripped cleanly —
    // no UpdateBw for it (that would wipe its custom fields server-side).
    // The only actions are the two expected re-quarantines (the foreign
    // edit on bw-1 and the un-adoptable secure note re-report every run).
    let entries = extract_entries(&vault.db);
    let items = bw.list_items().unwrap();
    let p = plan(&entries, &tombstones, &items, &folders, &journal, &opts).unwrap();
    assert_eq!(
        p.actions.len(),
        2,
        "expected only the two re-quarantines after adopt"
    );
    assert!(
        p.actions
            .iter()
            .all(|a| matches!(a, Action::Quarantine(_))),
        "adopted entry must not plan any write after adopt"
    );

    // Atomic save + reopen: entries intact (2 original + 1 adopted), and the
    // adopted entry kept its Bitwarden custom fields through the save.
    save_vault(&vault).unwrap();
    let v2 = open_vault(&kdbx, &pw, None).unwrap();
    let entries = extract_entries(&v2.db);
    assert_eq!(entries.len(), 3);
    let adopted = entries.iter().find(|e| e.title == "adopted").unwrap();
    assert!(
        adopted.custom.iter().any(|(k, v, _)| k == "API key" && v == "abc123"),
        "adopted entry must carry the Bitwarden custom field after save/reopen, got {:?}",
        adopted.custom
    );
}
