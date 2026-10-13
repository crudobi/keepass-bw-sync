//! Build a test KeePass2 database for end-to-end sync testing.
//!
//! Usage: cargo run --example mkdb -- <out.kdbx> <password>
//!
//! Creates groups (Email, Finance, nested Email/Social) and a handful of
//! entries, including one with TOTP and a custom field. Test data only.

use keepass::db::{fields, Database, GroupId, GroupRef};

fn add_group(db: &mut Database, title: &str, parent: GroupId) -> GroupId {
    let mut p = db.group_mut(parent).expect("parent group");
    let mut g = p.add_group();
    g.name = title.to_string();
    g.id()
}

fn add_entry(
    db: &mut Database,
    parent: GroupId,
    title: &str,
    user: &str,
    pw: &str,
    url: &str,
    notes: &str,
) {
    let mut p = db.group_mut(parent).expect("parent group");
    let mut e = p.add_entry();
    e.set_unprotected(fields::TITLE, title);
    e.set_protected(fields::USERNAME, user);
    e.set_protected(fields::PASSWORD, pw);
    e.set_unprotected(fields::URL, url);
    e.set_protected(fields::NOTES, notes);
}

fn count_entries(group: GroupRef) -> usize {
    group.entries().count() + group.groups().map(count_entries).sum::<usize>()
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let out = args.get(1).expect("usage: mkdb <out.kdbx> <password>");
    let password = args.get(2).expect("usage: mkdb <out.kdbx> <password>");

    let mut db = Database::new();
    db.root_mut().name = "Root".to_string();
    let root = db.root().id();

    let email = add_group(&mut db, "Email", root);
    let finance = add_group(&mut db, "Finance", root);
    let social = add_group(&mut db, "Social", email);

    add_entry(
        &mut db,
        email,
        "ExampleMail",
        "alice@example.com",
        "test-pw-alice-1",
        "https://example.com",
        "e2e test entry",
    );
    add_entry(
        &mut db,
        finance,
        "Test Bank",
        "e2e-tester",
        "test-pw-bank-2",
        "https://bank.example.com",
        "",
    );
    add_entry(
        &mut db,
        social,
        "Test Social",
        "e2e-social",
        "test-pw-social-3",
        "https://social.example.com",
        "nested group entry",
    );

    // Entry exercising TOTP + custom fields.
    let misc = add_group(&mut db, "Misc", root);
    {
        let mut p = db.group_mut(misc).expect("parent group");
        let mut e = p.add_entry();
        e.set_unprotected(fields::TITLE, "With Extras");
        e.set_protected(fields::USERNAME, "extra-user");
        e.set_protected(fields::PASSWORD, "test-pw-extra-4");
        e.set_unprotected(fields::URL, "https://extra.example.com");
        e.set_protected("totp", "JBSWY3DPEHPK3PXP");
        e.set_unprotected("API key", "e2e-api-key-abc123");
    }

    let key = keepass::DatabaseKey::new().with_password(password);
    let mut f = std::fs::File::create(out).expect("create output");
    db.save(&mut f, key).expect("save database");
    println!("wrote {} entries to {}", count_entries(db.root()), out);
}
