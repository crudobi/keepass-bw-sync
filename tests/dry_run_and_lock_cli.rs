//! CLI-level tests for `--dry-run` and journal-lock contention.
//!
//! Runs the real binary against a stub `bw serve`:
//! - dry run prints the planned actions and leaves the journal bytes and
//!   the vault bytes bit-identical, with zero Bitwarden writes;
//! - `--dry-run` on a command where it does not apply is rejected by
//!   clap instead of silently ignored;
//! - a second process attempting the journal lock while it is held fails
//!   cleanly instead of blocking or corrupting.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};

fn tmpdir(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("kbs-cli-{tag}-{}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn bin() -> std::path::PathBuf {
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

/// Stub `bw serve` serving one fixed listing and recording every request
/// method + path, so the dry-run test can prove zero Bitwarden writes.
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
            if content_length > 0 {
                let mut body = vec![0u8; content_length];
                let _ = reader.read_exact(&mut body);
            }
            let parts: Vec<&str> = request_line.split_whitespace().collect();
            if parts.len() < 2 {
                continue;
            }
            let (method, path) = (parts[0], parts[1]);
            methods.lock().unwrap().push(format!("{method} {path}"));
            let (status, resp_body) = match (method, path) {
                ("POST", "/sync") => (200, serde_json::json!({"success": true, "data": {}})),
                ("GET", "/list/object/items") => (
                    200,
                    serde_json::json!({"success": true, "data": {"object": "list", "data": [{
                        "id": "bw-unmapped", "name": "unmapped", "notes": null,
                        "favorite": false, "folderId": null, "type": 1, "reprompt": 0,
                        "login": {"username": "u", "password": "p", "totp": null, "uris": []},
                        "fields": [],
                        "revisionDate": "2026-10-03T00:00:00Z", "deletedDate": null,
                    }]}}),
                ),
                ("GET", "/list/object/folders") => (
                    200,
                    serde_json::json!({"success": true, "data": {"object": "list", "data": []}}),
                ),
                _ => (200, serde_json::json!({"success": false})),
            };
            let body = resp_body.to_string();
            let reason = if status == 200 { "OK" } else { "Error" };
            let resp = format!(
                "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = stream.write_all(resp.as_bytes());
        }
    });
    format!("http://{addr}")
}

fn fixture_kdbx(path: &std::path::Path) {
    use keepass::db::fields;
    let mut db = keepass::Database::new();
    {
        let mut root = db.root_mut();
        root.name = "Root".into();
        let mut e = root.add_entry();
        e.set_unprotected(fields::TITLE, "local-only");
        e.set_protected(fields::USERNAME, "alice");
        e.set_protected(fields::PASSWORD, "s3cret1");
        e.set_unprotected(fields::URL, "https://local.example.com");
    }
    let key = keepass::DatabaseKey::new().with_password("test-password");
    let mut f = std::fs::File::create(path).unwrap();
    db.save(&mut f, key).unwrap();
}

#[test]
fn dry_run_lists_actions_and_mutates_nothing() {
    let dir = tmpdir("dryrun");
    let kdbx = dir.join("test.kdbx");
    let journal_path = dir.join("sync.db");
    fixture_kdbx(&kdbx);
    // Create the journal through the library so a real pre-existing
    // journal (with bytes to compare) is what the dry run must not touch.
    drop(keepass_bw_sync::journal::Journal::open(&journal_path).unwrap());
    let journal_before = std::fs::read(&journal_path).unwrap();
    let vault_before = std::fs::read(&kdbx).unwrap();

    let methods = Arc::new(Mutex::new(Vec::new()));
    let base = spawn_stub(methods.clone());
    let out = Command::new(bin())
        .args([
            "sync",
            "--kdbx",
            kdbx.to_str().unwrap(),
            "--journal",
            journal_path.to_str().unwrap(),
            "--bw-url",
            &base,
            "--dry-run",
        ])
        .env("KBS_MASTER_PASSWORD", "test-password")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "dry run must exit 0, stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    // One line per planned action: the new local entry's create, and the
    // unmapped Bitwarden item's quarantine.
    assert!(stdout.contains("CreateBw"), "stdout:\n{stdout}");
    assert!(stdout.contains("local-only"), "stdout:\n{stdout}");
    assert!(stdout.contains("Quarantine"), "stdout:\n{stdout}");
    assert!(stdout.contains("unmapped"), "stdout:\n{stdout}");
    assert!(stdout.contains("dry run"), "stdout:\n{stdout}");
    // Bit-identical journal + vault: plan ran against a temp copy only.
    assert_eq!(
        std::fs::read(&journal_path).unwrap(),
        journal_before,
        "dry run must not mutate the journal"
    );
    assert_eq!(
        std::fs::read(&kdbx).unwrap(),
        vault_before,
        "dry run must not mutate the vault"
    );
    // Zero Bitwarden writes: only the download-only sync + GET listings.
    let methods = methods.lock().unwrap();
    assert!(
        methods
            .iter()
            .all(|m| m.starts_with("POST /sync") || m.starts_with("GET ")),
        "dry run must issue no Bitwarden writes, saw: {methods:?}"
    );
}

#[test]
fn dry_run_flag_is_rejected_on_other_commands() {
    let dir = tmpdir("dryrun-reject");
    let kdbx = dir.join("test.kdbx");
    fixture_kdbx(&kdbx);
    let out = Command::new(bin())
        .args(["list", "--kdbx", kdbx.to_str().unwrap(), "--dry-run"])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(!out.status.success(), "list --dry-run must be rejected");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("unexpected argument"),
        "expected a clap rejection, got: {stderr}"
    );
}

#[test]
fn journal_lock_contention_fails_cleanly() {
    // The test process holds the journal lock (same fs2 advisory flock
    // the binary uses); the binary's sync must fail fast with the lock
    // error instead of blocking or corrupting, and must proceed past
    // the lock once it is released.
    use fs2::FileExt;
    let dir = tmpdir("lock");
    let journal_path = dir.join("sync.db");
    let lock_path = {
        let mut p = journal_path.as_os_str().to_owned();
        p.push(".lock");
        std::path::PathBuf::from(p)
    };
    let lock_file = std::fs::File::create(&lock_path).unwrap();
    lock_file.try_lock_exclusive().unwrap();

    let run_sync = || {
        Command::new(bin())
            .args([
                "sync",
                "--kdbx",
                dir.join("nonexistent.kdbx").to_str().unwrap(),
                "--journal",
                journal_path.to_str().unwrap(),
                "--bw-url",
                "http://127.0.0.1:1",
            ])
            .env("KBS_MASTER_PASSWORD", "test-password")
            .stdin(Stdio::null())
            .output()
            .unwrap()
    };
    let out = run_sync();
    assert!(!out.status.success(), "contended sync must fail");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("journal lock"),
        "expected a clean lock error, got: {stderr}"
    );

    drop(lock_file);
    let out = run_sync();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains("journal lock"),
        "after release the run must get past the lock, got: {stderr}"
    );
}
