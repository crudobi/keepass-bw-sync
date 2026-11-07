//! One-off init tool: create an empty KDBX4 vault for production use.
//!
//! Usage: KBS_MASTER_PASSWORD must be set in the environment, then
//!   cargo run --example mkvault -- $SECRETS_DIR/vault.kdbx
//!
//! Fails closed when KBS_MASTER_PASSWORD is unset or empty; the password is
//! zeroized after use. Documented as a one-off: the production password lives
//! sealed in $SECRETS_DIR/vault.env.cred (TPM2; see README "TPM sealing"),
//! never printed, never committed.

#[cfg(not(unix))]
use std::fs::File;

use zeroize::Zeroizing;

fn main() {
    let out = std::env::args()
        .nth(1)
        .expect("usage: mkvault <out.kdbx>");
    let pw = Zeroizing::new(
        std::env::var("KBS_MASTER_PASSWORD")
            .expect("KBS_MASTER_PASSWORD must be set in the environment"),
    );
    assert!(
        !pw.is_empty(),
        "KBS_MASTER_PASSWORD is empty; refusing to create a vault with an empty password"
    );

    let mut db = keepass::Database::new();
    db.root_mut().name = "Root".to_string();

    let key = keepass::DatabaseKey::new().with_password(pw.as_str());
    // The vault file itself must be owner-only from creation: File::create
    // would leave umask defaults (typically 0644) until a later chmod.
    #[cfg(unix)]
    let mut f = {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&out)
            .expect("create output file")
    };
    #[cfg(not(unix))]
    let mut f = File::create(&out).expect("create output file");
    db.save(&mut f, key).expect("save database");
    println!("created empty KDBX4 vault at {out}");
}
