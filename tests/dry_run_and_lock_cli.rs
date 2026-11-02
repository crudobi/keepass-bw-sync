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

#[test]
fn put_does_not_hold_lock_while_waiting_on_stdin() {
    // The reorder proof: spawn put with stdin piped but unwritten, so
    // it blocks on the stdin read. After a settle delay (long past
    // process startup, so an old-order put would already hold the
    // lock), the journal lock must be acquirable while the child is
    // still alive and waiting. If put held the lock first, every
    // attempt here would fail.
    use fs2::FileExt;
    let dir = tmpdir("put-lock-order");
    let kdbx = dir.join("test.kdbx");
    let journal_path = dir.join("sync.db");
    fixture_kdbx(&kdbx);
    let lock_path = {
        let mut p = journal_path.as_os_str().to_owned();
        p.push(".lock");
        std::path::PathBuf::from(p)
    };
    let mut child = Command::new(bin())
        .args([
            "put",
            "--kdbx",
            kdbx.to_str().unwrap(),
            "--journal",
            journal_path.to_str().unwrap(),
            "--title",
            "put-lock-test",
            "--password-stdin",
        ])
        .env("KBS_MASTER_PASSWORD", "test-password")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    // Settle: startup is milliseconds; after this, an old-order put
    // would already hold the lock while waiting on stdin.
    std::thread::sleep(std::time::Duration::from_secs(1));
    let mut lock_free = false;
    for _ in 0..25 {
        // A dead child would free the lock trivially -- the proof
        // requires the child to be alive when the lock proves free.
        if child.try_wait().unwrap().is_some() {
            break;
        }
        {
            let f = std::fs::File::create(&lock_path).unwrap();
            if f.try_lock_exclusive().is_ok() {
                lock_free = true;
                break;
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
    assert!(
        lock_free,
        "journal lock must be free while put waits on stdin"
    );
    assert!(
        child.try_wait().unwrap().is_none(),
        "put must still be waiting on stdin when the lock proves free"
    );
    let mut stdin = child.stdin.take().unwrap();
    stdin.write_all(b"put-secret\n").unwrap();
    drop(stdin);
    let out = child.wait_with_output().unwrap();
    assert!(
        out.status.success(),
        "put must succeed after stdin, stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("created"),
        "expected created output, got: {}",
        String::from_utf8_lossy(&out.stdout)
    );
}

#[test]
fn quarantine_acknowledge_cli() {
    // Acknowledge through the real binary: build a scratch journal with
    // the library, acknowledge the row via the CLI, and prove the list
    // marks it and the pending count drops to zero.
    let dir = tmpdir("ack");
    let journal = dir.join("sync.db");
    {
        use keepass_bw_sync::journal::Journal;
        let j = Journal::open(&journal).unwrap();
        j.quarantine("org-item", None, Some("bw-1"), "t", "d")
            .unwrap();
        j.quarantine("has-attachments", None, Some("bw-2"), "t", "d")
            .unwrap();
        assert_eq!(j.unresolved_quarantine_count().unwrap(), 2);
    }
    let qcmd = |args: &[&str]| {
        let mut c = Command::new(bin());
        c.arg("quarantine").arg("--journal").arg(&journal);
        for a in args {
            c.arg(a);
        }
        c.stdout(Stdio::piped()).stderr(Stdio::piped());
        c.output().unwrap()
    };
    let out = qcmd(&["acknowledge", "1"]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("acknowledged quarantine row #1"),
        "stdout: {stdout}"
    );
    let out = qcmd(&[]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("[org-item] [acknowledged]"),
        "list must mark the acknowledged row: {stdout}"
    );
    assert!(
        !stdout.contains("[has-attachments] [acknowledged]"),
        "unacknowledged row must stay unmarked: {stdout}"
    );
    {
        use keepass_bw_sync::journal::Journal;
        let j = Journal::open(&journal).unwrap();
        assert_eq!(j.unresolved_quarantine_count().unwrap(), 1);
    }
    // Resolve output states the re-queue rule and points to acknowledge.
    let out = qcmd(&["resolve", "2"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("resolved quarantine row #2"),
        "stdout: {stdout}"
    );
    assert!(
        stdout.contains("re-queues it") && stdout.contains("acknowledge"),
        "resolve output must state the re-queue rule: {stdout}"
    );
}

#[test]
fn dry_run_copy_ignores_planted_symlink_at_predictable_name() {
    // The old construction used the predictable name
    // kbs-dry-run-{pid}.db with truncate + symlink-following: a planted
    // link there would receive journal bytes. The new construction uses
    // O_EXCL under a random suffix, so the planted link must be untouched
    // and the copy must land elsewhere, byte-identical and 0600.
    use std::os::unix::fs::symlink;
    let dir = tmpdir("dryrun-copy");
    let journal_path = dir.join("sync.db");
    drop(keepass_bw_sync::journal::Journal::open(&journal_path).unwrap());
    let scratch = dir.join("tmp");
    std::fs::create_dir_all(&scratch).unwrap();
    let canary = dir.join("canary");
    std::fs::write(&canary, b"canary").unwrap();
    let predictable = scratch.join(format!("kbs-dry-run-{}.db", std::process::id()));
    symlink(&canary, &predictable).unwrap();
    let p = keepass_bw_sync::journal::create_dry_run_copy(&journal_path, &scratch).unwrap();
    assert_ne!(p, predictable, "copy must not use the predictable name");
    assert_eq!(
        std::fs::read(&canary).unwrap(),
        b"canary",
        "planted link target must be untouched"
    );
    assert_eq!(
        std::fs::read(&p).unwrap(),
        std::fs::read(&journal_path).unwrap(),
        "copy must hold the journal bytes"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&p).unwrap().permissions().mode() & 0o777,
            0o600,
            "copy must be 0600"
        );
    }
    let _ = std::fs::remove_file(&p);
    let _ = std::fs::remove_dir_all(&dir);
}

/// Stub whose /sync succeeds but whose item listing fails: proves the
/// sync arm's list calls carry the same daemon hint as restore's.
fn spawn_failing_list_stub() -> String {
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
            let (status, resp_body) = match (method, path) {
                ("POST", "/sync") => (200, serde_json::json!({"success": true, "data": {}})),
                ("GET", "/list/object/items") => (
                    500,
                    serde_json::json!({"success": false, "message": "boom"}),
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

#[test]
fn sync_list_failure_names_the_daemon() {
    let dir = tmpdir("sync-list-hint");
    let kdbx = dir.join("test.kdbx");
    let journal_path = dir.join("sync.db");
    fixture_kdbx(&kdbx);
    let base = spawn_failing_list_stub();
    let out = Command::new(bin())
        .args([
            "sync",
            "--kdbx",
            kdbx.to_str().unwrap(),
            "--journal",
            journal_path.to_str().unwrap(),
            "--bw-url",
            &base,
        ])
        .env("KBS_MASTER_PASSWORD", "test-password")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(
        !out.status.success(),
        "sync with a failing item listing must fail"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("is `bw serve` running and unlocked?"),
        "expected the daemon hint, got: {stderr}"
    );
}

#[test]
fn quarantine_help_documents_the_bare_list() {
    let out = Command::new(bin())
        .args(["quarantine", "--help"])
        .output()
        .unwrap();
    assert!(out.status.success(), "quarantine --help must exit 0");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("lists open rows"),
        "help must document the bare list, got:\n{stdout}"
    );
}

#[test]
fn sync_journal_defaults_to_sibling_of_vault() {
    // Hold the sibling journal's lock: a sync without --journal must
    // fail fast on that lock, proving it resolved to the sibling path;
    // an explicit --journal elsewhere must get past it (and fail later
    // on the dead daemon, not on the lock).
    use fs2::FileExt;
    let dir = tmpdir("sync-journal-default");
    let kdbx = dir.join("test.kdbx");
    let sibling = dir.join("sync.db");
    fixture_kdbx(&kdbx);
    let lock_path = {
        let mut p = sibling.as_os_str().to_owned();
        p.push(".lock");
        std::path::PathBuf::from(p)
    };
    let lock_file = std::fs::File::create(&lock_path).unwrap();
    lock_file.try_lock_exclusive().unwrap();
    let run = |extra: &[&str]| {
        let mut args = vec![
            "sync",
            "--kdbx",
            kdbx.to_str().unwrap(),
            "--bw-url",
            "http://127.0.0.1:1",
        ];
        args.extend_from_slice(extra);
        Command::new(bin())
            .args(&args)
            .env("KBS_MASTER_PASSWORD", "test-password")
            .stdin(Stdio::null())
            .output()
            .unwrap()
    };
    let out = run(&[]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !out.status.success() && stderr.contains("journal lock"),
        "sync without --journal must hit the sibling lock, got: {stderr}"
    );
    let other = dir.join("other.db");
    let out = run(&["--journal", other.to_str().unwrap()]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains("journal lock"),
        "explicit --journal must bypass the sibling lock, got: {stderr}"
    );
}

#[test]
fn restore_journal_defaults_to_sibling_of_vault() {
    // Same lock trick as the sync default: restore without --journal
    // must fail fast on the sibling journal's lock (the lock is taken
    // before any vault or daemon work).
    use fs2::FileExt;
    let dir = tmpdir("restore-journal-default");
    let kdbx = dir.join("restored.kdbx");
    let sibling = dir.join("sync.db");
    let lock_path = {
        let mut p = sibling.as_os_str().to_owned();
        p.push(".lock");
        std::path::PathBuf::from(p)
    };
    let lock_file = std::fs::File::create(&lock_path).unwrap();
    lock_file.try_lock_exclusive().unwrap();
    let out = Command::new(bin())
        .args([
            "restore",
            "--kdbx",
            kdbx.to_str().unwrap(),
            "--bw-url",
            "http://127.0.0.1:1",
        ])
        .env("KBS_MASTER_PASSWORD", "new-vault-password")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("journal lock"),
        "restore without --journal must hit the sibling lock, got: {stderr}"
    );
}

#[test]
fn put_master_password_prompt_runs_before_lock() {
    // Order proof without a TTY: hold the journal lock, spawn put via
    // setsid (no controlling terminal) with piped stdin secrets and NO
    // env password. New order: stdin secrets read, then the prompt
    // fails (no TTY) BEFORE the lock is attempted — so the error must
    // NOT be a lock error. Control: with the env password set, the same
    // setup MUST fail on the lock, proving the lock still gates.
    use fs2::FileExt;
    let dir = tmpdir("put-prompt-order");
    let kdbx = dir.join("test.kdbx");
    let journal_path = dir.join("sync.db");
    fixture_kdbx(&kdbx);
    let lock_path = {
        let mut p = journal_path.as_os_str().to_owned();
        p.push(".lock");
        std::path::PathBuf::from(p)
    };
    let lock_file = std::fs::File::create(&lock_path).unwrap();
    lock_file.try_lock_exclusive().unwrap();
    let run = |env_pw: bool| {
        let mut cmd = Command::new("setsid");
        cmd.args([
            "--wait",
            bin().to_str().unwrap(),
            "put",
            "--kdbx",
            kdbx.to_str().unwrap(),
            "--journal",
            journal_path.to_str().unwrap(),
            "--title",
            "put-prompt-test",
            "--password-stdin",
        ]);
        if env_pw {
            cmd.env("KBS_MASTER_PASSWORD", "test-password");
        } else {
            cmd.env_remove("KBS_MASTER_PASSWORD");
        }
        let mut child = cmd
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut stdin = child.stdin.take().unwrap();
        stdin.write_all(b"put-secret\n").unwrap();
        drop(stdin);
        child.wait_with_output().unwrap()
    };
    let out = run(false);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !out.status.success() && !stderr.contains("journal lock"),
        "without env password the prompt must fail before the lock, got: {stderr}"
    );
    let out = run(true);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !out.status.success() && stderr.contains("journal lock"),
        "with env password the held lock must still gate, got: {stderr}"
    );
}
