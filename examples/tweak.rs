//! Mutate one entry in a test KeePass2 database (for E2E sync testing).
//!
//! Usage: printf '%s' "$NEW_PW" | KBS_MASTER_PASSWORD=... tweak <db.kdbx> <title>
//!
//! Finds the entry by title, replaces its password, and saves atomically.
//! The new password comes from stdin — never argv, per the project's
//! no-argv rule (argv is visible in `ps`). Test tooling only.

use std::io::{IsTerminal, Read};

use keepass::db::{fields, EntryId};
use keepass_bw_sync::kdbx::{extract_entries, open_vault, save_vault};
use keepass_bw_sync::secret::Secret;

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let path = args.get(1).expect("usage: tweak <db.kdbx> <title>");
    let title = args.get(2).expect("usage: tweak <db.kdbx> <title>");
    if std::io::stdin().is_terminal() {
        anyhow::bail!("new password must come from stdin (piped), not a terminal");
    }
    let mut new_pw = String::new();
    std::io::stdin().read_to_string(&mut new_pw)?;
    // Trim rule (same as `put`): exactly one trailing newline is stripped,
    // so `echo` output and editor-saved files work as-is.
    if new_pw.ends_with('\n') {
        new_pw.pop();
        if new_pw.ends_with('\r') {
            new_pw.pop();
        }
    }
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
