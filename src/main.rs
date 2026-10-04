use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use fs2::FileExt;
use keepass_bw_sync::bw::BwClient;
use keepass_bw_sync::journal::Journal;
use keepass_bw_sync::kdbx::{
    extract_entries, get_entry_field, list_entries, open_vault, put_entry, read_secret_input,
    save_vault, tombstoned_uuids, NewEntrySpec, PutOutcome,
};
use keepass_bw_sync::secret::Secret;
use keepass_bw_sync::sync::{apply, plan, SyncOpts};

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
    /// only: no journal, no Bitwarden.
    Put {
        /// Path to the KeePass2 database.
        #[arg(long)]
        kdbx: PathBuf,
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
    },
}

#[derive(Subcommand)]
enum QuarantineCmd {
    /// Mark a quarantine row resolved.
    Resolve {
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

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Sync {
            kdbx,
            journal,
            bw_url,
            writeback,
            force,
            adopt,
            insecure_remote_url,
        } => {
            // Single-writer: an exclusive flock on <journal>.lock for the
            // whole run. Fail closed when another sync holds it — concurrent
            // runs share one .kdbx.tmp path and would diverge the journal.
            let _lock = acquire_journal_lock(&journal)?;

            let opts = SyncOpts {
                writeback,
                force,
                adopt,
            };
            let pw = master_password()?;
            let mut vault = open_vault(&kdbx, &pw, None)?;
            drop(pw); // master password leaves scope before any network IO
            let entries = extract_entries(&vault.db);
            let tombstones = tombstoned_uuids(&vault.db);

            let bw = BwClient::new_with_remote(&bw_url, insecure_remote_url)?;
            bw.sync()
                .context("bw sync failed — is `bw serve` running and unlocked?")?;
            let items = bw.list_items()?;
            // Fail closed: a transient folder-list failure must not silently
            // duplicate server folders (the CreateBw path creates them).
            let folders = bw.list_folders().context("list bitwarden folders")?;
            let journal = Journal::open(&journal)?;

            let plan = plan(&entries, &tombstones, &items, &journal, &opts)?;
            println!(
                "plan: {} actions ({} keepass entries, {} bitwarden items)",
                plan.actions.len(),
                entries.len(),
                items.len()
            );
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
            if report.quarantined > 0 {
                println!("review: keepass-bw-sync quarantine --journal <path>");
            }
        }
        Cmd::Quarantine { journal, action } => {
            let j = Journal::open(&journal)?;
            match action {
                Some(QuarantineCmd::Resolve { id }) => {
                    if j.resolve_quarantine(id)? {
                        println!("resolved quarantine row #{id}");
                    } else {
                        println!("no unresolved quarantine row #{id}");
                    }
                }
                None => {
                    let rows = j.list_quarantine()?;
                    if rows.is_empty() {
                        println!("quarantine is empty");
                    }
                    for (id, kind, kp, bw_id, title, detail) in rows {
                        println!("#{id} [{kind}] {title} kp={kp:?} bw={bw_id:?}\n    {detail}");
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
        Cmd::Get { kdbx, title, field } => {
            let pw = master_password()?;
            let vault = open_vault(&kdbx, &pw, None)?;
            drop(pw); // master password leaves scope before any output
            let value = get_entry_field(&vault.db, &title, &field)?;
            {
                use std::io::Write as _;
                std::io::stdout()
                    .write_all(value.expose())
                    .context("write field value to stdout")?;
            }
            // The returned Secret zeroizes its bytes on drop.
        }
        Cmd::Put {
            kdbx,
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
            let password =
                read_secret_input("password", password_stdin, password_file.as_deref())?;
            let notes = read_secret_input("notes", notes_stdin, notes_file.as_deref())?;
            let pw = master_password()?;
            let mut vault = open_vault(&kdbx, &pw, None)?;
            drop(pw); // master password leaves scope before mutation
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
        Cmd::List { kdbx } => {
            let pw = master_password()?;
            let vault = open_vault(&kdbx, &pw, None)?;
            drop(pw); // master password leaves scope before any output
            for (gp, t) in list_entries(&vault.db) {
                if gp.is_empty() {
                    println!("{t}");
                } else {
                    println!("{gp}/{t}");
                }
            }
        }
    }
    Ok(())
}
