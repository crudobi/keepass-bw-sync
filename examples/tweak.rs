//! Mutate one entry in a test KeePass2 database (for E2E sync testing).
//!
//! Usage: KBS_MASTER_PASSWORD=<redacted>
//!
//! Finds the entry by title, replaces its password, and saves atomically.
//! Test tooling only.

use keepass::db::{fields, EntryId};
use keepass_bw_sync::kdbx::{extract_entries, open_vault, save_vault};
use keepass_bw_sync::secret::Secret;

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let path = args.get(1).expect("usage: tweak <db.kdbx> <title> <new-password>");
    let title = args.get(2).expect("usage: tweak <db.kdbx> <title> <new-password>");
    let new_pw = args.get(3).expect("usage: tweak <db.kdbx> <title> <new-password>");
    let pw = std::env::var("KBS_MASTER_PASSWORD").expect("KBS_MASTER_PASSWORD required");
    let secret = Secret::from_str(&pw);

    let mut vault = open_vault(std::path::Path::new(path), &secret, None)?;
    let target = extract_entries(&vault.db)
        .into_iter()
        .find(|e| e.title == *title);
    let Some(target) = target else {
        anyhow::bail!("entry not found: {title}");
    };
    {
        let mut e = vault
            .db
            .entry_mut(EntryId::from_uuid(target.uuid))
            .expect("entry vanished");
        e.set_protected(fields::PASSWORD, new_pw.as_str());
    }
    save_vault(&vault)?;
    println!("tweaked '{title}'");
    Ok(())
}
