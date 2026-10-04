//! Build a test KeePass2 database for end-to-end sync testing.
//!
//! Usage: cargo run --example mkdb -- <out.kdbx> <password>
//!
//! Creates groups (Email, Finance, nested Email/Social) and a handful of
//! entries, including one with TOTP and a custom field. Test data only.

use keepass_rs::model::core::node::NodeId;
use keepass_rs::model::core::security::ProtectedString as PS;
use keepass_rs::model::db::composite_key::CompositeKey;
use keepass_rs::model::db::database::{Database, DatabaseVersion};
use keepass_rs::model::entry::{Entry, EntryField};
use keepass_rs::model::group::Group;

fn add_group(db: &mut Database, title: &str, parent: &NodeId) -> NodeId {
    let id = NodeId::new_uuid();
    let mut g = Group::new(id.clone());
    g.title = title.to_string();
    assert!(db.add_group(g, parent), "add_group {}", title);
    id
}

fn add_entry(
    db: &mut Database,
    parent: &NodeId,
    title: &str,
    user: &str,
    pw: &str,
    url: &str,
    notes: &str,
) {
    let mut e = Entry::new(NodeId::new_uuid());
    e.title = title.to_string();
    e.username = PS::new_protected(user);
    e.password = PS::new_protected(pw);
    e.url = url.to_string();
    e.notes = PS::new_protected(notes);
    assert!(db.add_entry(e, parent), "add_entry {}", title);
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let out = args.get(1).expect("usage: mkdb <out.kdbx> <password>");
    let password = args.get(2).expect("usage: mkdb <out.kdbx> <password>");

    let mut db = Database::new(DatabaseVersion::KDBX4);
    let mut rg = Group::new(NodeId::new_uuid());
    rg.title = "Root".to_string();
    assert!(db.add_group(rg, &NodeId::new_uuid()));
    let root = db.root_group_id.clone().unwrap();

    let email = add_group(&mut db, "Email", &root);
    let finance = add_group(&mut db, "Finance", &root);
    let social = add_group(&mut db, "Social", &email);

    add_entry(
        &mut db,
        &email,
        "ExampleMail",
        "alice@example.com",
        "test-pw-alice-1",
        "https://example.com",
        "e2e test entry",
    );
    add_entry(
        &mut db,
        &finance,
        "Test Bank",
        "e2e-tester",
        "test-pw-bank-2",
        "https://bank.example.com",
        "",
    );
    add_entry(
        &mut db,
        &social,
        "Test Social",
        "e2e-social",
        "test-pw-social-3",
        "https://social.example.com",
        "nested group entry",
    );

    // Entry exercising TOTP + custom fields.
    let mut e = Entry::new(NodeId::new_uuid());
    e.title = "With Extras".to_string();
    e.username = PS::new_protected("extra-user");
    e.password = PS::new_protected("test-pw-extra-4");
    e.url = "https://extra.example.com".to_string();
    e.custom_fields.push(EntryField {
        name: "totp".to_string(),
        value: PS::new_protected("JBSWY3DPEHPK3PXP"),
        is_protected: true,
    });
    e.custom_fields.push(EntryField {
        name: "API key".to_string(),
        value: PS::new_protected("e2e-api-key-abc123"),
        is_protected: false,
    });
    let misc = add_group(&mut db, "Misc", &root);
    assert!(db.add_entry(e, &misc));

    let key = CompositeKey::new().with_password(password.as_bytes());
    let mut f = std::fs::File::create(out).expect("create output");
    keepass_rs::save_database(&mut f, &db, &key).expect("save database");
    println!("wrote {} entries to {}", db.entry_count(), out);
}
