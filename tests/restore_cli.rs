//! CLI-level restore tests against a stub `bw serve`.
//!
//! Runs the real binary: restore must create a vault + journal from the
//! stub's items (one download-only POST /sync, then the GET list calls),
//! keep stamp UUIDs, skip trashed items, and
//! then refuse a second restore into the now non-empty vault without
//! touching it. A restore without `KBS_MASTER_PASSWORD` fails closed.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};

fn tmpdir(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("kbs-restore-cli-{tag}-{}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn bin() -> std::path::PathBuf {
    // Cargo sets CARGO_BIN_EXE_<name> for integration tests; the exact
    // spelling (dashes preserved vs underscored) varies, so try both,
    // then the sibling of the deps/ dir holding this test binary.
    for var in [
        "CARGO_BIN_EXE_keepass-bw-sync",
        "CARGO_BIN_EXE_keepass_bw_sync",
    ] {
        if let Ok(p) = std::env::var(var) {
            let pb = std::path::PathBuf::from(p);
            if pb.exists() {
                return pb;
            }
        }
    }
    let exe = std::env::current_exe().unwrap();
    let cand = exe
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("keepass-bw-sync");
    if cand.exists() {
        return cand;
    }
    panic!("could not locate the keepass-bw-sync binary (tried CARGO_BIN_EXE_* and {cand:?})");
}

/// Stub `bw serve` that serves one fixed items/folders listing and records
/// every request method + path. Handles requests inline, one connection at
/// a time (the CLI issues them sequentially).
fn spawn_stub(methods: Arc<Mutex<Vec<String>>>) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let mut stream = stream;
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut request_line = String::new();
            if reader.read_line(&mut request_line).is_err() || request_line.trim().is_empty() {
                continue;
            }
            let mut content_length = 0usize;
            loop {
                let mut line = String::new();
                if reader.read_line(&mut line).is_err() {
                    break;
                }
                let t = line.trim();
                if t.is_empty() {
                    break;
                }
                if let Some(v) = t.to_ascii_lowercase().strip_prefix("content-length:") {
                    content_length = v.trim().parse().unwrap_or(0);
                }
            }
            let mut body = vec![0u8; content_length];
            if content_length > 0 {
                let _ = reader.read_exact(&mut body);
            }
            let parts: Vec<&str> = request_line.split_whitespace().collect();
            if parts.len() < 2 {
                continue;
            }
            methods
                .lock()
                .unwrap()
                .push(format!("{} {}", parts[0], parts[1]));
            let resp_body = match (parts[0], parts[1]) {
                ("POST", "/sync") => serde_json::json!({"success": true}),
                ("GET", "/list/object/items") => serde_json::json!({
                    "success": true,
                    "data": {"object": "list", "data": [
                        {
                            "id": "bw-1", "name": "stamped", "notes": null,
                            "favorite": false, "folderId": "f-ops", "type": 1,
                            "reprompt": 0,
                            "login": {"username": "alice", "password": "s3cr3t",
                                      "totp": null, "uris": []},
                            "fields": [
                                {"name": "KBS_SYNC_ID",
                                 "value": "11111111-1111-1111-1111-111111111111", "type": 0},
                                {"name": "KBS_SYNC_HASH", "value": "h", "type": 0}
                            ],
                            "revisionDate": "r1", "deletedDate": null
                        },
                        {
                            "id": "bw-2", "name": "fresh", "notes": null,
                            "favorite": false, "folderId": null, "type": 1,
                            "reprompt": 0,
                            "login": {"username": "bob", "password": "pw2",
                                      "totp": null, "uris": []},
                            "fields": [],
                            "revisionDate": "r1", "deletedDate": null
                        },
                        {
                            "id": "bw-3", "name": "trashed", "notes": null,
                            "favorite": false, "folderId": null, "type": 1,
                            "reprompt": 0,
                            "login": {"username": "x", "password": "y",
                                      "totp": null, "uris": []},
                            "fields": [],
                            "revisionDate": "r1",
                            "deletedDate": "2026-10-03T00:00:00Z"
                        }
                    ]}
                }),
                ("GET", "/list/object/folders") => serde_json::json!({
                    "success": true,
                    "data": {"object": "list", "data": [
                        {"id": "f-ops", "name": "Ops"}
                    ]}
                }),
                _ => serde_json::json!({"success": false, "message": "unexpected"}),
            }
            .to_string();
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                resp_body.len(),
                resp_body
            );
            let _ = stream.write_all(resp.as_bytes());
        }
    });
    format!("http://{addr}")
}

fn restore_cmd(kdbx: &std::path::Path, journal: &std::path::Path, bw_url: &str) -> Command {
    let mut c = Command::new(bin());
    c.arg("restore")
        .arg("--kdbx")
        .arg(kdbx)
        .arg("--journal")
        .arg(journal)
        .arg("--bw-url")
        .arg(bw_url)
        .env("KBS_MASTER_PASSWORD", "restore-test-password")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    c
}

#[test]
fn restore_creates_vault_then_refuses_nonempty_target() {
    let dir = tmpdir("creates");
    let kdbx = dir.join("restored.kdbx");
    let journal = dir.join("sync.db");
    let methods = Arc::new(Mutex::new(Vec::new()));
    let base = spawn_stub(methods.clone());

    let out = restore_cmd(&kdbx, &journal, &base).output().unwrap();
    assert!(
        out.status.success(),
        "restore failed: stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("restored stamped=1 unstamped=1 skipped_trashed=1"),
        "stdout: {stdout}"
    );
    // One download-only POST /sync first, then the two GET list calls;
    // no server-mutating POST/PUT/DELETE ever reaches the stub.
    assert_eq!(
        *methods.lock().unwrap(),
        vec![
            "POST /sync".to_string(),
            "GET /list/object/items".to_string(),
            "GET /list/object/folders".to_string()
        ],
        "restore must sync (download-only) before listing, and issue no server writes"
    );

    // The restored vault reopens with the stub password, the stamped
    // entry kept its stamp UUID, the fresh entry is in the root group,
    // and the trashed item is absent. The journal maps both live items.
    {
        use keepass_bw_sync::journal::Journal;
        use keepass_bw_sync::kdbx::{extract_entries, open_vault};
        use keepass_bw_sync::secret::Secret;
        let pw = Secret::from_str("restore-test-password");
        let vault = open_vault(&kdbx, &pw, None).unwrap();
        let entries = extract_entries(&vault.db);
        assert_eq!(
            entries.len(),
            2,
            "entries: {:?}",
            entries.iter().map(|e| &e.title).collect::<Vec<_>>()
        );
        let stamped = entries.iter().find(|e| e.title == "stamped").unwrap();
        assert_eq!(
            stamped.uuid.to_string(),
            "11111111-1111-1111-1111-111111111111"
        );
        assert_eq!(stamped.group_path, "Ops");
        let fresh = entries.iter().find(|e| e.title == "fresh").unwrap();
        assert_eq!(fresh.group_path, "");
        assert!(entries.iter().all(|e| e.title != "trashed"));
        let j = Journal::open(&journal).unwrap();
        assert_eq!(j.live_mapping_count().unwrap(), 2);
        assert_eq!(j.mapping_by_kp(&stamped.uuid).unwrap().unwrap().0, "bw-1");
    }

    // Second restore into the same (now non-empty) vault: refuses, and
    // the vault bytes are untouched. No stub is even needed — the target
    // check runs before any Bitwarden traffic (dead URL proves it).
    let before = std::fs::read(&kdbx).unwrap();
    let out = restore_cmd(&kdbx, &journal, "http://127.0.0.1:1")
        .output()
        .unwrap();
    assert!(!out.status.success(), "second restore must refuse");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("non-empty"),
        "stderr should name the refusal: {stderr}"
    );
    assert_eq!(
        std::fs::read(&kdbx).unwrap(),
        before,
        "refused restore must not touch the vault"
    );
    // And it issued no Bitwarden traffic at all (no stub, dead URL, yet
    // the failure is the target refusal, not a connection error).
    assert!(
        !stderr.contains("Connection refused") && !stderr.contains("bw list"),
        "refusal must precede Bitwarden traffic: {stderr}"
    );
}

#[test]
fn restore_fails_closed_without_password() {
    let dir = tmpdir("nopw");
    let kdbx = dir.join("restored.kdbx");
    let journal = dir.join("sync.db");
    let mut c = Command::new(bin());
    c.arg("restore")
        .arg("--kdbx")
        .arg(&kdbx)
        .arg("--journal")
        .arg(&journal)
        .arg("--bw-url")
        .arg("http://127.0.0.1:1")
        .env_remove("KBS_MASTER_PASSWORD")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let out = c.output().unwrap();
    assert!(
        !out.status.success(),
        "restore without a password must fail"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("KBS_MASTER_PASSWORD"),
        "error must name the missing env var: {stderr}"
    );
    assert!(
        !kdbx.exists(),
        "failed restore must not create a vault file"
    );
}

#[test]
fn restore_syncs_before_listing() {
    // Regression (2026-11-01 review): restore read a possibly stale
    // `bw serve` cache because it never called `bw.sync()`, so it could
    // silently under-restore while reporting success. The listing step
    // must be preceded by the download-only sync POST.
    let dir = tmpdir("sync-first");
    let kdbx = dir.join("restored.kdbx");
    let journal = dir.join("sync.db");
    let methods = Arc::new(Mutex::new(Vec::new()));
    let base = spawn_stub(methods.clone());

    let out = restore_cmd(&kdbx, &journal, &base).output().unwrap();
    assert!(
        out.status.success(),
        "restore failed: stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        *methods.lock().unwrap(),
        vec![
            "POST /sync".to_string(),
            "GET /list/object/items".to_string(),
            "GET /list/object/folders".to_string()
        ],
        "restore must sync (download-only) before listing"
    );
}

#[test]
fn restore_ignores_proxy_env() {
    // Regression (2026-11-01 review): without `.no_proxy()`, proxy env
    // vars route loopback plaintext through the proxy. The child runs
    // with a dead proxy set (and NO_PROXY removed, so a proxy-respecting
    // client would actually use it) and must still reach the stub.
    let dir = tmpdir("no-proxy");
    let kdbx = dir.join("restored.kdbx");
    let journal = dir.join("sync.db");
    let methods = Arc::new(Mutex::new(Vec::new()));
    let base = spawn_stub(methods.clone());

    let mut c = restore_cmd(&kdbx, &journal, &base);
    for v in [
        "HTTP_PROXY",
        "http_proxy",
        "HTTPS_PROXY",
        "https_proxy",
        "ALL_PROXY",
        "all_proxy",
    ] {
        c.env(v, "http://127.0.0.1:1");
    }
    c.env_remove("NO_PROXY");
    c.env_remove("no_proxy");
    let out = c.output().unwrap();
    assert!(
        out.status.success(),
        "restore behind a dead proxy failed: stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        *methods.lock().unwrap(),
        vec![
            "POST /sync".to_string(),
            "GET /list/object/items".to_string(),
            "GET /list/object/folders".to_string()
        ],
        "restore must reach the stub directly despite proxy env"
    );
}
