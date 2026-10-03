use std::collections::HashMap;
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use keepass_bw_sync::bw::BwClient;
use keepass_bw_sync::journal::Journal;
use keepass_bw_sync::kdbx::{extract_entries, open_vault, save_vault, tombstoned_uuids};
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
    },
    /// List unresolved quarantine cases.
    Quarantine {
        #[arg(long)]
        journal: PathBuf,
    },
}

fn master_password() -> Result<Secret> {
    if let Ok(pw) = std::env::var("KBS_MASTER_PASSWORD") {
        return Ok(Secret::from_str(&pw));
    }
    Ok(Secret::from_str(&rpassword::prompt_password(
        "KeePass master password: ",
    )?))
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
        } => {
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

            let bw = BwClient::new(&bw_url);
            bw.sync()
                .context("bw sync failed — is `bw serve` running and unlocked?")?;
            let items = bw.list_items()?;
            let folders = bw.list_folders().unwrap_or_default();
            let journal = Journal::open(&journal)?;

            let plan = plan(&entries, &tombstones, &items, &journal, &opts)?;
            println!(
                "plan: {} actions ({} keepass entries, {} bitwarden items)",
                plan.actions.len(),
                entries.len(),
                items.len()
            );
            let mut folder_ids = HashMap::new();
            let report = apply(
                &plan,
                &entries,
                &items,
                &bw,
                &mut vault,
                &journal,
                &mut folder_ids,
                &folders,
                &opts,
            )?;
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
            if report.quarantined > 0 {
                println!("review: keepass-bw-sync quarantine --journal <path>");
            }
        }
        Cmd::Quarantine { journal } => {
            let j = Journal::open(&journal)?;
            let rows = j.list_quarantine()?;
            if rows.is_empty() {
                println!("quarantine is empty");
            }
            for (id, kind, kp, bw_id, title, detail) in rows {
                println!("#{id} [{kind}] {title} kp={kp:?} bw={bw_id:?}\n    {detail}");
            }
        }
    }
    Ok(())
}
