//! One-off init tool: create an empty KDBX4 vault for production use.
//!
//! Usage: KBS_MASTER_PASSWORD must be set in the environment, then
//!   cargo run --offline --example mkvault -- /store/muscle/secrets/vault.kdbx
//!
//! Fails closed when KBS_MASTER_PASSWORD is unset or empty; the password is
//! zeroized after use. Documented as a one-off: the production password lives
//! in /store/muscle/secrets/vault.env (0600, never printed, never committed).

use std::fs::File;

use keepass_rs::model::core::node::NodeId;
use keepass_rs::model::db::composite_key::CompositeKey;
use keepass_rs::model::db::database::{Database, DatabaseVersion};
use keepass_rs::model::group::Group;
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

    let mut db = Database::new(DatabaseVersion::KDBX4);
    let mut root = Group::new(NodeId::new_uuid());
    root.title = "Root".to_string();
    assert!(db.add_group(root, &NodeId::new_uuid()));

    let key = CompositeKey::new().with_password(pw.as_bytes());
    let mut f = File::create(&out).expect("create output file");
    keepass_rs::save_database(&mut f, &db, &key).expect("save database");
    println!("created empty KDBX4 vault at {out}");
}
