use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use fs2::FileExt;
use keepass_bw_sync::bw::{BwClient, BwItem};
use keepass_bw_sync::canonical::CanonicalEntry;
use keepass_bw_sync::journal::Journal;
use keepass_bw_sync::kdbx::{
    display_path, extract_entries, get_entry_field, list_entries, new_vault, open_vault, put_entry,
    read_secret_input, save_vault, tombstoned_uuids, KdbxVault, NewEntrySpec, PutOutcome,
};
use keepass_bw_sync::restore::{check_target_empty, restore_into};
use keepass_bw_sync::secret::Secret;
use keepass_bw_sync::sync::{apply, plan, Action, SyncOpts};

#[derive(Parser)]
#[command(name = "keepass-bw-sync", about = "Bidirectional KeePass2 <-> Bitwarden sync engine")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run one sync pass. The local .kdbx is the source of truth.
    Sync {
        /// Path to the KeePass2 database.
        #[arg(long)]
        kdbx: PathBuf,
        /// Path to a KeePass keyfile (or set KBS_KEYFILE).
        #[arg(long, env = "KBS_KEYFILE")]
        keyfile: Option<PathBuf>,
        /// Path to the SQLite sync journal (created if missing).
        #[arg(long)]
        journal: PathBuf,
        /// Base URL of a running, unlocked `bw serve`.
        #[arg(long, default_value = "http://127.0.0.1:8087")]
        bw_url: String,
        /// Apply foreign Bitwarden edits into KeePass (else quarantine).
        #[arg(long)]
        writeback: bool,
        /// KeePass unconditionally overwrites foreign Bitwarden edits.
        #[arg(long)]
        force: bool,
        /// Create KeePass entries for unmapped Bitwarden items.
        #[arg(long)]
        adopt: bool,
        /// Preview only: print the planned actions and exit without
        /// applying anything and without mutating the journal or the
        /// vault. Sync-only: other subcommands reject this flag.
        #[arg(long)]
        dry_run: bool,
        /// Allow a non-loopback bw serve URL. The transport is plaintext
        /// HTTP with no auth: a remote URL exfiltrates vault secrets.
        #[arg(long)]
        insecure_remote_url: bool,
    },
    /// Rebuild a KeePass vault from Bitwarden. NEVER writes to the
    /// Bitwarden server vault: a download-only `bw.sync()` refreshes
    /// serve's cache, then only the two GET list calls run; stamped
    /// items keep their stamp
    /// UUIDs, unstamped items are adopted under fresh UUIDs (and NOT
    /// stamped back), trashed items are skipped. Refuses to restore into
    /// an existing non-empty vault. The new vault's password comes from
    /// KBS_MASTER_PASSWORD (fail closed when unset); --keyfile is
    /// supported like the other commands.
    Restore {
        /// Path to the KeePass database to create (or an empty vault file).
        #[arg(long)]
        kdbx: PathBuf,
        /// Path to a KeePass keyfile (or set KBS_KEYFILE).
        #[arg(long, env = "KBS_KEYFILE")]
        keyfile: Option<PathBuf>,
        /// Path to the SQLite sync journal to create (created if missing).
        #[arg(long)]
        journal: PathBuf,
        /// Base URL of a running, unlocked `bw serve`.
        #[arg(long, default_value = "http://127.0.0.1:8087")]
        bw_url: String,
        /// Allow a non-loopback bw serve URL. The transport is plaintext
        /// HTTP with no auth: a remote URL exfiltrates vault secrets.
        #[arg(long)]
        insecure_remote_url: bool,
    },
    /// Manage the quarantine queue.
    Quarantine {
        #[arg(long)]
        journal: PathBuf,
        #[command(subcommand)]
        action: Option<QuarantineCmd>,
    },
    /// Manage the sync journal.
    Journal {
        #[command(subcommand)]
        action: JournalCmd,
    },
    /// Print one entry field to stdout with no trailing newline (scripting).
    /// Reads the local .kdbx only: no journal, no Bitwarden, no lock.
    Get {
        /// Path to the KeePass2 database.
        #[arg(long)]
        kdbx: PathBuf,
        /// Path to a KeePass keyfile (or set KBS_KEYFILE).
        #[arg(long, env = "KBS_KEYFILE")]
        keyfile: Option<PathBuf>,
        /// Exact entry title.
        #[arg(long)]
        title: String,
        /// Field: password (default), username, url, totp, notes, or a
        /// custom-field name (case-insensitive).
        #[arg(long, default_value = "password")]
        field: String,
    },
    /// Write an entry into the local .kdbx (create, or replace in place
    /// with --update). Secret material comes only from stdin or a file,
    /// never argv (argv is visible in `ps`). Reads/writes the local .kdbx
    /// only: no journal writes, no Bitwarden. The journal flock is held
    /// for the modify-save only (stdin is read before the lock) so an
    /// interactive put waiting on stdin cannot block the hourly sync;
    /// put and sync still cannot race the vault save.
    Put {
        /// Path to the KeePass2 database.
        #[arg(long)]
        kdbx: PathBuf,
        /// Path to a KeePass keyfile (or set KBS_KEYFILE).
        #[arg(long, env = "KBS_KEYFILE")]
        keyfile: Option<PathBuf>,
        /// Sync journal whose `.lock` file serializes put against sync
        /// runs. Only the lock file is used; the journal itself is never
        /// opened. Defaults to `sync.db` next to the vault — pass the same
        /// journal your sync runs use when it lives elsewhere.
        #[arg(long)]
        journal: Option<PathBuf>,
        /// Exact entry title.
        #[arg(long)]
        title: String,
        /// Group name; created as a top-level group when missing. Ignored
        /// with --update (entries are never moved between groups).
        #[arg(long)]
        group: Option<String>,
        /// Username (not secret on its own; argv is fine).
        #[arg(long)]
        username: Option<String>,
        /// URL (argv is fine).
        #[arg(long)]
        url: Option<String>,
        /// Read the password from stdin (must be piped, not a terminal).
        #[arg(long)]
        password_stdin: bool,
        /// Read the password from a file. Exactly one trailing newline
        /// (`\n` or `\r\n`) is trimmed.
        #[arg(long)]
        password_file: Option<PathBuf>,
        /// Read notes from stdin (must be piped, not a terminal).
        #[arg(long)]
        notes_stdin: bool,
        /// Read notes from a file. Exactly one trailing newline is trimmed.
        #[arg(long)]
        notes_file: Option<PathBuf>,
        /// Replace the existing entry's fields in place instead of failing
        /// on a duplicate title. Only provided fields are overwritten;
        /// everything else is left untouched.
        #[arg(long)]
        update: bool,
    },
    /// List entry titles as `group/title` (root entries as bare `title`),
    /// one per line, sorted. Never prints field values. Reads the local
    /// .kdbx only: no journal, no Bitwarden.
    List {
        /// Path to the KeePass2 database.
        #[arg(long)]
        kdbx: PathBuf,
        /// Path to a KeePass keyfile (or set KBS_KEYFILE).
        #[arg(long, env = "KBS_KEYFILE")]
        keyfile: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum QuarantineCmd {
    /// Mark a quarantine row resolved.
    Resolve {
        /// Row id from the quarantine listing.
        id: i64,
    },
    /// Acknowledge a quarantine row: it stays listed (marked) and its
    /// item stays untouched, but it no longer counts as pending or
    /// triggers the sync nag. For persistent conditions you have
    /// accepted (an org item, an item with attachments). If the
    /// condition later clears, the row auto-resolves on the next sync.
    /// Resolving a persistent row only clears it until the next sync
    /// re-queues it; acknowledge is the silence path, not a bypass.
    Acknowledge {
        /// Row id from the quarantine listing.
        id: i64,
    },
}

#[derive(Subcommand)]
enum JournalCmd {
    /// Archive the current journal to a timestamped backup and start fresh.
    /// This is the escape hatch the listing guard's bail message points at:
    /// after a genuine mass Bitwarden delete, reset here and the next sync
    /// rebuilds every mapping from the KBS_SYNC_ID stamps. The backup keeps
    /// quarantine history and tombstones for forensics.
    Reset {
        /// Path to the SQLite sync journal.
        #[arg(long)]
        journal: PathBuf,
    },
}

/// Exclusive advisory lock on `<journal>.lock`, held for the whole run.
/// Concurrent runs share one `.kdbx.tmp` path and would diverge the journal.
fn acquire_journal_lock(journal: &std::path::Path) -> Result<std::fs::File> {
    let lock_path = {
        let mut p = journal.as_os_str().to_owned();
        p.push(".lock");
        PathBuf::from(p)
    };
    let lock_file = std::fs::File::create(&lock_path)
        .with_context(|| format!("create lock {}", lock_path.display()))?;
    lock_file.try_lock_exclusive().context(
        "another sync run holds the journal lock; refusing to run concurrently",
    )?;
    Ok(lock_file)
}

/// Load keyfile bytes for a vault open, when a keyfile was given (CLI
/// `--keyfile` or the `KBS_KEYFILE` env var). The bytes live only in
/// memory for the duration of the open.
fn load_keyfile(path: &Option<PathBuf>) -> Result<Option<Vec<u8>>> {
    match path {
        Some(p) => Ok(Some(
            std::fs::read(p).with_context(|| format!("read keyfile {}", p.display()))?,
        )),
        None => Ok(None),
    }
}

/// Open the vault for a CLI command: get the master password, load any
/// keyfile bytes, decrypt. The master password is dropped before this
/// returns, so it leaves scope before any network IO or output in every
/// caller.
fn open_cli_vault(kdbx: &std::path::Path, keyfile: &Option<PathBuf>) -> Result<KdbxVault> {
    let pw = master_password()?;
    let kf = load_keyfile(keyfile)?;
    let vault = open_vault(kdbx, &pw, kf.as_deref())?;
    drop(pw);
    Ok(vault)
}

/// Restore's vault password: `KBS_MASTER_PASSWORD` only, fail closed
/// when unset. Unlike the other commands, restore never falls back to an
/// interactive prompt: a restore creates a *new* vault, and a mistyped or
/// defaulted password would lock the user out of the recovery they just
/// made (or, worse, silently reuse a terminal-entered password they did
/// not intend as the new vault's password).
fn restore_master_password() -> Result<Secret> {
    match std::env::var("KBS_MASTER_PASSWORD") {
        Ok(pw) if !pw.is_empty() => {
            let pw = zeroize::Zeroizing::new(pw);
            Ok(Secret::from_str(pw.as_str()))
        }
        _ => anyhow::bail!(
            "KBS_MASTER_PASSWORD is not set (or is empty); restore refuses to invent a vault \
             password — set it to the new vault's master password and re-run"
        ),
    }
}

fn master_password() -> Result<Secret> {
    // Zeroizing wrapper: the intermediate String is wiped on drop instead of
    // lingering in allocator memory.
    if let Ok(pw) = std::env::var("KBS_MASTER_PASSWORD") {
        let pw = zeroize::Zeroizing::new(pw);
        return Ok(Secret::from_str(pw.as_str()));
    }
    let pw = zeroize::Zeroizing::new(rpassword::prompt_password("KeePass master password: ")?);
    Ok(Secret::from_str(pw.as_str()))
}

/// One human-readable line per planned action: kind + title + ids.
/// Titles resolve from the plan's own inputs; a TrashBw planned from a
/// KeePass tombstone (no live entry) falls back to the Bitwarden id.
fn describe_action(a: &Action, entries: &[CanonicalEntry], items: &[BwItem]) -> String {
    let entry_title = |uuid: &uuid::Uuid| {
        entries
            .iter()
            .find(|e| &e.uuid == uuid)
            .map(|e| e.title.clone())
    };
    match a {
        Action::CreateBw { entry_idx } => {
            let e = &entries[*entry_idx];
            format!("CreateBw title={:?} kp={}", e.title, e.uuid)
        }
        Action::UpdateBw { bw_id, entry_idx, .. } => {
            let e = &entries[*entry_idx];
            format!("UpdateBw title={:?} bw={bw_id} kp={}", e.title, e.uuid)
        }
        Action::TrashBw { bw_id, kp_uuid, .. } => {
            let title = entry_title(kp_uuid).unwrap_or_else(|| bw_id.clone());
            format!("TrashBw title={title:?} bw={bw_id} kp={kp_uuid}")
        }
        Action::RecycleKp { kp_uuid, bw_id, .. } => {
            let title = entry_title(kp_uuid).unwrap_or_else(|| bw_id.clone());
            format!("RecycleKp title={title:?} bw={bw_id} kp={kp_uuid}")
        }
        Action::AdoptBwNew { item_idx } => {
            let it = &items[*item_idx];
            format!("AdoptBwNew title={:?} bw={}", it.name, it.id)
        }
        Action::WritebackEdit { bw_id, kp_uuid, item_idx } => {
            let title = items
                .get(*item_idx)
                .map(|it| it.name.clone())
                .or_else(|| entry_title(kp_uuid))
                .unwrap_or_else(|| bw_id.clone());
            format!("WritebackEdit title={title:?} bw={bw_id} kp={kp_uuid}")
        }
        Action::Quarantine(q) => {
            format!(
                "Quarantine kind={} title={:?} kp={:?} bw={:?} detail={:?}",
                q.kind, q.title, q.kp_uuid, q.bw_id, q.detail
            )
        }
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Sync {
            kdbx,
            keyfile,
            journal,
            bw_url,
            writeback,
            force,
            adopt,
            dry_run,
            insecure_remote_url,
        } => {
            let _lock = acquire_journal_lock(&journal)?;

            let opts = SyncOpts {
                writeback,
                force,
                adopt,
            };
            let mut vault = open_cli_vault(&kdbx, &keyfile)?;
            // Fail fast on read-only vault formats (KDBX3) BEFORE any
            // Bitwarden write or stamp — the write would otherwise land
            // server-side and only fail at save time.
            vault.require_writable()?;
            let entries = extract_entries(&vault.db);
            let tombstones = tombstoned_uuids(&vault.db);

            let bw = BwClient::new_with_remote(&bw_url, insecure_remote_url)?;
            bw.sync()
                .context("bw sync failed — is `bw serve` running and unlocked?")?;
            let items = bw.list_items()?;
            // Fail closed: a transient folder-list failure must not silently
            // duplicate server folders (the CreateBw path creates them).
            let folders = bw.list_folders().context("list bitwarden folders")?;
            // Dry run: plan against a throwaway copy of the journal, so
            // plan()'s immediate bookkeeping (mapping rebuild, missing
            // notes, watermark refresh) can never touch the real journal.
            // The vault is never saved and apply() never runs, so the
            // vault bytes are untouched too. (The journal lock is still
            // held, and `bw.sync()` still refreshes serve's cache — a
            // download-only refresh, not a vault or journal mutation.)
            // The guard removes the throwaway copy on ALL exits, not just
            // the success path: a plan error returns via `?` before the
            // explicit remove below, and a leaked copy would otherwise
            // linger in the temp dir.
            struct RemoveOnDrop(Option<PathBuf>);
            impl Drop for RemoveOnDrop {
                fn drop(&mut self) {
                    if let Some(p) = self.0.take() {
                        let _ = std::fs::remove_file(p);
                    }
                }
            }
            let tmp_journal: Option<PathBuf> = if dry_run {
                let p = std::env::temp_dir()
                    .join(format!("kbs-dry-run-{}.db", std::process::id()));
                if journal.exists() {
                    std::fs::copy(&journal, &p).context("copy journal for dry run")?;
                    // The journal holds hashes and titles, not secrets —
                    // but a 0644 copy in a shared temp dir is still wider
                    // than the 0600 the real journal carries, so narrow it
                    // immediately (Journal::open re-chmods on open anyway).
                    #[cfg(unix)]
                    std::fs::set_permissions(
                        &p,
                        std::os::unix::fs::PermissionsExt::from_mode(0o600),
                    )
                    .context("chmod dry-run journal copy")?;
                }
                Some(p)
            } else {
                None
            };
            let _dry_run_guard = tmp_journal
                .as_ref()
                .map(|p| RemoveOnDrop(Some(p.clone())));
            let journal_path = tmp_journal.as_ref().unwrap_or(&journal);
            let journal = Journal::open(journal_path)?;

            let plan = plan(&entries, &tombstones, &items, &folders, &journal, &opts)?;
            println!(
                "plan: {} actions ({} keepass entries, {} bitwarden items)",
                plan.actions.len(),
                entries.len(),
                items.len()
            );
            if dry_run {
                for a in &plan.actions {
                    println!("  {}", describe_action(a, &entries, &items));
                }
                println!(
                    "dry run: {} actions, no changes made (journal and vault untouched)",
                    plan.actions.len()
                );
                if let Some(p) = &tmp_journal {
                    let _ = std::fs::remove_file(p);
                }
                return Ok(());
            }
            let (report, journal_ops) =
                apply(&plan, &entries, &items, &bw, &mut vault, &folders)?;
            println!(
                "created={} updated={} trashed={} kp_recycled={} kp_adopted={} writeback={} quarantined={}",
                report.created,
                report.updated,
                report.trashed,
                report.kp_recycled,
                report.kp_adopted,
                report.writeback_applied,
                report.quarantined
            );
            if report.kp_recycled + report.kp_adopted + report.writeback_applied > 0 {
                save_vault(&vault)?;
                println!("keepass database saved (atomic temp+rename)");
            }
            // Journal ops commit only after the KeePass side is durable: a
            // failed save bails above, so the journal can never claim
            // KeePass mutations that never reached disk.
            journal
                .apply_ops(&journal_ops)
                .context("commit journal ops")?;
            let quarantine_pending = journal.unresolved_quarantine_count()?;
            println!("quarantine_pending={quarantine_pending}");
            if report.quarantined > 0 || quarantine_pending > 0 {
                println!("review: keepass-bw-sync quarantine --journal <path>");
            }
        }
        Cmd::Restore {
            kdbx,
            keyfile,
            journal,
            bw_url,
            insecure_remote_url,
        } => {
            let _lock = acquire_journal_lock(&journal)?;

            let pw = restore_master_password()?;
            let kf = load_keyfile(&keyfile)?;
            // Target safety BEFORE any Bitwarden traffic or journal write:
            // a nonexistent path or a zero-byte file becomes a brand-new
            // vault; an existing vault must be empty, else refuse.
            let mut vault = if std::fs::metadata(&kdbx).map(|m| m.len()).unwrap_or(0) == 0 {
                new_vault(&kdbx, &pw, kf.as_deref())
            } else {
                open_vault(&kdbx, &pw, kf.as_deref())?
            };
            drop(pw);
            vault.require_writable()?;
            check_target_empty(&vault.db)?;

            // Refresh serve's local cache first: without `bw.sync()`, a
            // stale cache can miss recently added items or still list
            // server-deleted ones, and restore would silently
            // under-restore while reporting success. `bw.sync()` is a
            // download-only POST — it mutates no server vault — so the
            // no-server-writes guarantee below still holds. The restore
            // module takes only the fetched slices — it has no client
            // handle, so no Bitwarden write can originate from it.
            let bw = BwClient::new_with_remote(&bw_url, insecure_remote_url)?;
            bw.sync()
                .context("bw sync failed — is `bw serve` running and unlocked?")?;
            let items = bw
                .list_items()
                .context("bw list items failed — is `bw serve` running and unlocked?")?;
            let folders = bw.list_folders().context("list bitwarden folders")?;
            let (report, journal_ops) = restore_into(&mut vault.db, &items, &folders)?;
            // Journal opens (creating it when missing) only after the
            // restore computed cleanly in memory; the vault saves before
            // the journal commits, same ordering as sync.
            let journal = Journal::open(&journal)?;
            save_vault(&vault)?;
            println!("keepass database saved (atomic temp+rename)");
            journal
                .apply_ops(&journal_ops)
                .context("commit journal ops")?;
            println!(
                "restored stamped={} unstamped={} skipped_trashed={} skipped_org={} restored_without_blobs={}",
                report.stamped,
                report.unstamped,
                report.skipped_trashed,
                report.skipped_org,
                report.restored_without_blobs
            );
            if report.restored_without_blobs > 0 {
                // Prominent, not buried: a restore that reports success
                // while entries lack their blobs must say so loudly —
                // the blobs survive server-side, but this vault does not
                // have them, and the next sync will quarantine these
                // items as `has-attachments` until blobs sync.
                println!(
                    "warning: {} restored entries are missing their attachment blobs (not synced); the blobs still exist in Bitwarden",
                    report.restored_without_blobs
                );
                for t in &report.restored_without_blobs_titles {
                    println!("    - {t}");
                }
            }
            if report.skipped_org > 0 {
                println!(
                    "warning: {} org-owned items were skipped (never copied into a personal vault)",
                    report.skipped_org
                );
                for t in &report.skipped_org_titles {
                    println!("    - {t}");
                }
            }
        }
        Cmd::Quarantine { journal, action } => {
            let j = Journal::open(&journal)?;
            match action {
                Some(QuarantineCmd::Resolve { id }) => {
                    if j.resolve_quarantine(id)? {
                        println!("resolved quarantine row #{id}");
                        println!("note: if its condition persists (e.g. org ownership, attachments), the next sync re-queues it; use `quarantine acknowledge {id}` for a condition you have accepted");
                    } else {
                        println!("no unresolved quarantine row #{id}");
                    }
                }
                Some(QuarantineCmd::Acknowledge { id }) => {
                    if j.acknowledge_quarantine(id)? {
                        println!("acknowledged quarantine row #{id} (it stays listed, its item stays untouched, and it no longer counts as pending)");
                    } else {
                        println!("no unresolved quarantine row #{id}");
                    }
                }
                None => {
                    let rows = j.list_quarantine()?;
                    if rows.is_empty() {
                        println!("quarantine is empty");
                    }
                    for (id, kind, kp, bw_id, title, detail, ack) in rows {
                        let mark = if ack { " [acknowledged]" } else { "" };
                        println!(
                            "#{id} [{kind}]{mark} {title} kp={kp:?} bw={bw_id:?}\n    {detail}"
                        );
                    }
                }
            }
        }
        Cmd::Journal { action } => match action {
            JournalCmd::Reset { journal } => {
                // Take the lock first: resetting while a sync holds it
                // would orphan that run's mappings.
                let _lock = acquire_journal_lock(&journal)?;
                if journal.exists() {
                    let ts = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .context("system clock before epoch")?
                        .as_secs();
                    let backup = journal.with_extension(format!("bak-{ts}"));
                    std::fs::rename(&journal, &backup).with_context(|| {
                        format!(
                            "archive journal {} to {}",
                            journal.display(),
                            backup.display()
                        )
                    })?;
                    println!("archived journal to {}", backup.display());
                }
                Journal::open(&journal)?;
                println!("created fresh journal at {}", journal.display());
            }
        },
        Cmd::Get { kdbx, keyfile, title, field } => {
            let vault = open_cli_vault(&kdbx, &keyfile)?;
            let value = get_entry_field(&vault.db, &title, &field)?;
            {
                use std::io::Write as _;
                std::io::stdout()
                    .write_all(value.expose())
                    .context("write field value to stdout")?;
            }
        }
        Cmd::Put {
            kdbx,
            keyfile,
            journal,
            title,
            group,
            username,
            url,
            password_stdin,
            password_file,
            notes_stdin,
            notes_file,
            update,
        } => {
            // Same flock discipline as sync, held for the whole
            // read-modify-save: put and sync share the vault file and its
            // .kdbx.tmp path, and a racing sync save used to silently
            // erase a put entry (its older in-memory DB renamed over the
            // put, with nothing anywhere detecting the loss). The lock
            // is taken AFTER reading stdin: an interactive put waiting
            // on stdin must not block the hourly sync (which fails fast
            // on a contended lock) -- only the read-modify-save itself
            // needs the lock.
            let journal_path = journal.unwrap_or_else(|| kdbx.with_file_name("sync.db"));

            let password =
                read_secret_input("password", password_stdin, password_file.as_deref())?;
            let notes = read_secret_input("notes", notes_stdin, notes_file.as_deref())?;
            let _lock = acquire_journal_lock(&journal_path)?;
            let mut vault = open_cli_vault(&kdbx, &keyfile)?;
            // KDBX3 is read-only for this tool: refuse before mutating.
            vault.require_writable()?;
            let title_msg = title.clone();
            let spec = NewEntrySpec {
                title,
                group,
                username: username.map(|u| Secret::from_str(&u)),
                url,
                password,
                notes,
                update,
            };
            let outcome = put_entry(&mut vault.db, spec)?;
            save_vault(&vault)?;
            match outcome {
                PutOutcome::Created => println!("created {title_msg:?}"),
                PutOutcome::Updated => println!("updated {title_msg:?}"),
            }
        }
        Cmd::List { kdbx, keyfile } => {
            let vault = open_cli_vault(&kdbx, &keyfile)?;
            for (gp, t) in list_entries(&vault.db) {
                println!("{}", display_path(&gp, &t));
            }
        }
    }
    Ok(())
}
