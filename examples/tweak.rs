//! Mutate one entry in a test KeePass2 database (for E2E sync testing).
//!
//! Usage: KBS_MASTER_PASSWORD=... cargo run --example tweak -- <db.kdbx> <entry-title> <new-password>
//!
//! Finds the entry by title, replaces its password, and saves atomically.
//! Test tooling only.

use keepass_bw_sync::kdbx::{open_vault, save_vault};
use keepass_bw_sync::secret::Secret;
use keepass_rs::model::core::security::ProtectedString;

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let path = args.get(1).expect("usage: tweak <db.kdbx> <title> <new-password>");
    let title = args.get(2).expect("usage: tweak <db.kdbx> <title> <new-password>");
    let new_pw = args.get(3).expect("usage: tweak <db.kdbx> <title> <new-password>");
    let pw = std::env::var("KBS_MASTER_PASSWORD").expect("KBS_MASTER_PASSWORD required");
    let secret = Secret::from_str(&pw);

    let mut vault = open_vault(std::path::Path::new(path), &secret, None)?;
    let mut found = false;
    for (_id, e) in vault.db.entries.iter_mut() {
        if e.title == *title {
            e.password = ProtectedString::new_protected(new_pw);
            found = true;
            break;
        }
    }
    anyhow::ensure!(found, "entry not found: {title}");
    save_vault(&vault)?;
    println!("tweaked '{title}'");
    Ok(())
}
