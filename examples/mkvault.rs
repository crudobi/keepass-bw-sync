//! One-off init tool: create an empty KDBX4 vault for production use.
//!
//! Usage: KBS_MASTER_PASSWORD must be set in the environment, then
//!   cargo run --offline --example mkvault -- $SECRETS_DIR/vault.kdbx
//!
//! Fails closed when KBS_MASTER_PASSWORD is unset or empty; the password is
//! zeroized after use. Documented as a one-off: the production password lives
//! in $SECRETS_DIR/vault.env (0600, never printed, never committed).

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
    let mut f = File::create(&out).expect("create output file");
    db.save(&mut f, key).expect("save database");
    println!("created empty KDBX4 vault at {out}");
}
