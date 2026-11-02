//! Rebuild a KeePass vault from Bitwarden (`restore` subcommand).
//!
//! RESTORE NEVER WRITES TO THE BITWARDEN SERVER VAULT. This module is
//! the structural guarantee: it takes already-fetched `&[BwItem]` /
//! `&[BwFolder]` slices and a `&mut Database` — it has no `BwClient`,
//! no HTTP, and no way to issue a Bitwarden write. The CLI arm that
//! calls it first refreshes serve's local cache with `bw.sync()` — a
//! download-only POST that mutates no server vault — then performs only
//! the two GET list calls (`list_items`, `list_folders`); it never calls
//! `create_*`, `edit_item`, `trash_item`, or `stamp_item`. In
//! particular, unstamped items are NOT stamped back:
//! stamping would be a Bitwarden write, and restore must not mutate the
//! source it is recovering from.
//!
//! Identity rules (see `restore_into`):
//! - Stamped items are restored under their `KBS_SYNC_ID` stamp UUID —
//!   that UUID is the entry's true identity, and the next `sync` matches
//!   it instead of quarantining it as `orphan_bw_stamp`.
//! - Unstamped items are adopted too (dropping Bitwarden-only items
//!   would make the restore incomplete), but under fresh minted UUIDs,
//!   and they are NOT stamped back. Consequence, stated not silent: if
//!   the new journal is later lost, those items are orphans again — a
//!   later `sync --adopt` would re-adopt them under yet another UUID
//!   rather than matching them. Stamped items do not have this problem:
//!   their identity survives in the Bitwarden stamp itself.
//! - Trashed Bitwarden items (`deletedDate` set) are NOT restored.
//! - Org-owned items (non-empty `collectionIds`) are NOT restored either:
//!   copying org credentials into a personal vault would evade org
//!   control, so they are skipped and counted in `skipped_org`, mirroring
//!   the sync gate.
//! - Items with attachments ARE restored, but without their blobs (this
//!   engine does not transfer blobs) and counted in
//!   `restored_without_blobs`, so a restore never reports silent success
//!   while incomplete. The blobs survive server-side; the next `sync`
//!   quarantines these items as `has-attachments` until blobs sync.
//! - Journal baseline follows the M1 rule: the `KBS_SYNC_HASH` stamp
//!   when present, else the item's live content hash. A restored vault
//!   plus its new journal plus the same Bitwarden state therefore plans
//!   zero sync actions (both sides agree; at most the watermark refreshes
//!   when the stamp baseline is stale).
//!
//! Non-login Bitwarden items (secure notes, cards, identities) are
//! adopted as login-shaped entries, unlike `sync --adopt`, which
//! quarantines them. For a restore, dropping them would silently lose
//! data the user is recovering; reshaping is the lesser loss, and the
//! item's title, notes, and custom fields all survive. The one
//! projection gap to know about: KeePass has no boolean custom fields,
//! so a Bitwarden boolean field lands protected and projects back as
//! hidden — the first `sync` after restoring such an item plans a single
//! `UpdateBw` that rewrites the field as hidden, after which it is
//! stable. Content itself is never lost.
//!
//! This module never saves anything: it mutates the in-memory database
//! and returns deferred [`JournalOp`]s, exactly like `sync::apply`. The
//! caller saves the vault atomically first and only then commits the
//! journal ops, so a failed save can never leave a journal claiming
//! entries that never reached disk.

use std::collections::HashSet;

use anyhow::{Context, Result};
use keepass::db::Database;
use uuid::Uuid;

use crate::bw::{BwFolder, BwItem};
use crate::journal::JournalOp;
use crate::kdbx::{adopt_bw_entry, adopt_bw_entry_with_uuid, extract_entries};

/// Counts reported by `restore` on completion. Carries no secret material.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct RestoreReport {
    /// Items restored under their `KBS_SYNC_ID` stamp UUID.
    pub stamped: usize,
    /// Items restored under freshly minted UUIDs (unstamped in Bitwarden).
    pub unstamped: usize,
    /// Bitwarden items skipped because they are in the trash.
    pub skipped_trashed: usize,
    /// Bitwarden items skipped because they are owned by an organization
    /// (non-empty `collectionIds`): restore never copies org items into
    /// a personal vault, mirroring the sync gate.
    pub skipped_org: usize,
    /// Titles of the skipped org-owned items, in listing order.
    pub skipped_org_titles: Vec<String>,
    /// Items restored without their attachment blobs: the entry itself
    /// is restored, but this engine does not transfer blobs, so the
    /// restore is incomplete for these items by exactly that much.
    pub restored_without_blobs: usize,
    /// Titles of the items restored without their attachment blobs, in
    /// listing order.
    pub restored_without_blobs_titles: Vec<String>,
}

/// Fail closed when a restore target already holds entries: restoring
/// into a live vault would merge two vaults' worth of entries under one
/// journal and could duplicate or shadow the user's real entries. The
/// caller checks this before any Bitwarden traffic or journal write.
pub fn check_target_empty(db: &Database) -> Result<()> {
    let entries = extract_entries(db);
    if entries.is_empty() {
        Ok(())
    } else {
        anyhow::bail!(
            "refusing to restore into an existing non-empty vault ({} entries); \
             choose a new --kdbx path, or an empty vault file",
            entries.len()
        )
    }
}

/// Rebuild `db` from the fetched Bitwarden items.
///
/// Precondition (checked by the caller via [`check_target_empty`]): `db`
/// holds no entries, so every UUID restored here is fresh to the vault.
/// Fails before returning — with `db` still mutated in memory, but the
/// caller only saves on success, so a failure here writes nothing to
/// disk and commits no journal ops.
///
/// The returned ops are the new journal's mappings, one per restored
/// item: uuid → bw_id with the stamp hash as baseline when present,
/// else the live content hash.
pub fn restore_into(
    db: &mut Database,
    items: &[BwItem],
    folders: &[BwFolder],
) -> Result<(RestoreReport, Vec<JournalOp>)> {
    let mut report = RestoreReport::default();
    let mut journal_ops = Vec::new();
    // UUIDs already in the vault (empty by precondition, but checked
    // anyway so a caller slip can never mint a duplicate identity) plus
    // every UUID restored in this run.
    let mut seen_uuids: HashSet<Uuid> = extract_entries(db).iter().map(|e| e.uuid).collect();
    let mut seen_bw_ids: HashSet<&str> = HashSet::new();

    for it in items {
        if it.trashed() {
            report.skipped_trashed += 1;
            continue;
        }
        if !seen_bw_ids.insert(it.id.as_str()) {
            anyhow::bail!(
                "refusing to restore: duplicate Bitwarden item id {:?} in the listing",
                it.id
            );
        }
        // Org gate, mirroring sync: never copy org credentials into a
        // personal vault. Skipped, counted, no entry, no mapping.
        if it.org_owned() {
            report.skipped_org += 1;
            report.skipped_org_titles.push(it.name.clone());
            continue;
        }
        let folder_name = it
            .folder_id
            .as_deref()
            .and_then(|id| folders.iter().find(|f| f.id == id))
            .map(|f| f.name.as_str());
        let (stamp_id, stamp_hash) = it.stamps();
        let (uuid, baseline, stamped) = match stamp_id {
            Some(s) => {
                let uuid: Uuid = s.parse().with_context(|| {
                    format!(
                        "Bitwarden item {:?} carries an invalid KBS_SYNC_ID stamp; refusing to restore it under a guessed identity",
                        it.name
                    )
                })?;
                if seen_uuids.contains(&uuid) {
                    anyhow::bail!(
                        "refusing to restore: two Bitwarden items claim KeePass UUID {uuid} (item {:?})",
                        it.name
                    );
                }
                let restored = adopt_bw_entry_with_uuid(db, it, folder_name, Some(uuid))?;
                debug_assert_eq!(restored, uuid);
                let baseline = stamp_hash
                    .filter(|h| !h.is_empty())
                    .unwrap_or_else(|| it.content_hash_hex());
                (restored, baseline, true)
            }
            None => {
                let restored = adopt_bw_entry(db, it, folder_name)?;
                if seen_uuids.contains(&restored) {
                    anyhow::bail!(
                        "refusing to restore: minted UUID {restored} collided with an existing entry; nothing was saved"
                    );
                }
                let baseline = it.content_hash_hex();
                (restored, baseline, false)
            }
        };
        seen_uuids.insert(uuid);
        if stamped {
            report.stamped += 1;
        } else {
            report.unstamped += 1;
        }
        // Attachments ride no transfer: the entry is restored, but its
        // blobs are not, and the report must say so (see module docs).
        if it.has_attachments() {
            report.restored_without_blobs += 1;
            report.restored_without_blobs_titles.push(it.name.clone());
        }
        journal_ops.push(JournalOp::UpsertMapping {
            kp_uuid: uuid,
            bw_id: it.id.clone(),
            hash: baseline,
        });
    }
    Ok((report, journal_ops))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bw::{BwAttachment, BwField, BwLogin, BwUri};
    use crate::journal::test_journal;
    use crate::kdbx::test_vault;
    use crate::stamps::{SYNC_HASH_FIELD, SYNC_ID_FIELD};
    use crate::sync::{plan, SyncOpts};

    const STAMP_UUID: &str = "11111111-1111-1111-1111-111111111111";

    fn bw_item(id: &str, name: &str, stamp: Option<&str>, trashed: bool) -> BwItem {
        let mut fields = vec![BwField {
            name: "API key".into(),
            value: "abc123".into(),
            field_type: 1,
        }];
        if let Some(u) = stamp {
            fields.push(BwField {
                name: SYNC_ID_FIELD.into(),
                value: u.into(),
                field_type: 0,
            });
            fields.push(BwField {
                name: SYNC_HASH_FIELD.into(),
                value: "stale-stamp-hash".into(),
                field_type: 0,
            });
        }
        BwItem {
            id: id.into(),
            name: name.into(),
            notes: Some("some notes".into()),
            favorite: false,
            folder_id: Some("f-ops".into()),
            login: Some(BwLogin {
                username: Some("alice".into()),
                password: Some("s3cr3t".into()),
                totp: Some("JBSWY3DPEHPK3PXP".into()),
                uris: Some(vec![
                    BwUri {
                        uri: Some("https://example.com".into()),
                        match_: None,
                    },
                    BwUri {
                        uri: Some("https://second.example.com".into()),
                        match_: None,
                    },
                ]),
            }),
            fields,
            revision_date: "r1".into(),
            deleted_date: trashed.then_some("2026-10-03T00:00:00Z".into()),
            item_type: 1,
            reprompt: None,
            collection_ids: vec![],
            organization_id: None,
            attachments: vec![],
        }
    }

    fn folders() -> Vec<BwFolder> {
        vec![BwFolder {
            id: "f-ops".into(),
            name: "Ops".into(),
        }]
    }

    #[test]
    fn stamped_restore_keeps_stamp_uuid_and_stamp_baseline() {
        let mut vault = test_vault();
        let items = vec![bw_item("bw-1", "stamped", Some(STAMP_UUID), false)];
        let (report, ops) = restore_into(&mut vault.db, &items, &folders()).unwrap();
        assert_eq!(
            report,
            RestoreReport {
                stamped: 1,
                unstamped: 0,
                skipped_trashed: 0,
                skipped_org: 0,
                skipped_org_titles: vec![],
                restored_without_blobs: 0,
                restored_without_blobs_titles: vec![],
            }
        );
        let entries = extract_entries(&vault.db);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].uuid.to_string(), STAMP_UUID);
        assert_eq!(entries[0].group_path, "Ops");
        assert_eq!(entries[0].title, "stamped");
        // Field mapping rides along: TOTP, both URIs, custom field.
        assert_eq!(entries[0].totp.as_deref(), Some("JBSWY3DPEHPK3PXP"));
        assert_eq!(
            entries[0].uris,
            vec![
                "https://example.com".to_string(),
                "https://second.example.com".to_string()
            ]
        );
        assert!(
            entries[0]
                .custom
                .iter()
                .any(|(k, v, _)| k == "API key" && v == "abc123"),
            "custom: {:?}",
            entries[0].custom
        );
        // M1 rule: the journal baseline is the stamp hash, not live content.
        assert_eq!(ops.len(), 1);
        assert!(matches!(
            &ops[0],
            JournalOp::UpsertMapping { kp_uuid, bw_id, hash }
                if kp_uuid.to_string() == STAMP_UUID && bw_id == "bw-1" && hash == "stale-stamp-hash"
        ));
    }

    #[test]
    fn unstamped_restore_mints_fresh_uuid_with_live_baseline() {
        let mut vault = test_vault();
        let items = vec![bw_item("bw-2", "fresh", None, false)];
        let (report, ops) = restore_into(&mut vault.db, &items, &folders()).unwrap();
        assert_eq!(report.unstamped, 1);
        assert_eq!(report.stamped, 0);
        let entries = extract_entries(&vault.db);
        assert_eq!(entries.len(), 1);
        // Minted, not the stamped UUID, and not nil.
        assert_ne!(entries[0].uuid.to_string(), STAMP_UUID);
        assert_ne!(entries[0].uuid, Uuid::nil());
        // No stamp hash exists, so the baseline is the live content hash.
        let live = items[0].content_hash_hex();
        assert!(matches!(
            &ops[0],
            JournalOp::UpsertMapping { hash, .. } if hash == &live
        ));
    }

    #[test]
    fn restore_report_names_skipped_org_and_blob_less_titles() {
        let mut vault = test_vault();
        let mut org = bw_item("bw-org", "org-one", None, false);
        org.collection_ids = vec!["coll-1".into()];
        let mut blobs = bw_item("bw-blob", "blob-one", None, false);
        blobs.attachments = vec![BwAttachment {
            id: Some("att-1".into()),
            file_name: Some("scan.pdf".into()),
            size: Some(10),
        }];
        let plain = bw_item("bw-plain", "plain-one", None, false);
        let (report, _) = restore_into(&mut vault.db, &[org, blobs, plain], &folders()).unwrap();
        assert_eq!(report.skipped_org, 1);
        assert_eq!(report.skipped_org_titles, vec!["org-one".to_string()]);
        assert_eq!(report.restored_without_blobs, 1);
        assert_eq!(
            report.restored_without_blobs_titles,
            vec!["blob-one".to_string()]
        );
        assert_eq!(report.unstamped, 2);
    }

    #[test]
    fn trashed_items_are_skipped_stamped_or_not() {
        let mut vault = test_vault();
        let items = vec![
            bw_item("bw-1", "trashed-stamped", Some(STAMP_UUID), true),
            bw_item("bw-2", "trashed-fresh", None, true),
            bw_item("bw-3", "live", None, false),
        ];
        let (report, ops) = restore_into(&mut vault.db, &items, &folders()).unwrap();
        assert_eq!(report.skipped_trashed, 2);
        assert_eq!(report.unstamped, 1);
        assert_eq!(ops.len(), 1);
        assert_eq!(extract_entries(&vault.db).len(), 1);
    }

    #[test]
    fn duplicate_stamp_uuid_bails_before_any_mapping() {
        let mut vault = test_vault();
        let items = vec![
            bw_item("bw-1", "first", Some(STAMP_UUID), false),
            bw_item("bw-2", "second", Some(STAMP_UUID), false),
        ];
        let err = restore_into(&mut vault.db, &items, &folders())
            .unwrap_err()
            .to_string();
        assert!(err.contains("two Bitwarden items"), "unexpected error: {err}");
    }

    #[test]
    fn invalid_stamp_uuid_bails() {
        let mut vault = test_vault();
        let items = vec![bw_item("bw-1", "bad-stamp", Some("not-a-uuid"), false)];
        let err = restore_into(&mut vault.db, &items, &folders())
            .unwrap_err()
            .to_string();
        assert!(err.contains("invalid KBS_SYNC_ID"), "unexpected error: {err}");
    }

    #[test]
    fn target_guard_refuses_nonempty_vault() {
        let mut vault = test_vault();
        let items = vec![bw_item("bw-1", "one", None, false)];
        restore_into(&mut vault.db, &items, &folders()).unwrap();
        let err = check_target_empty(&vault.db).unwrap_err().to_string();
        assert!(err.contains("non-empty"), "unexpected error: {err}");

        let empty = test_vault();
        assert!(check_target_empty(&empty.db).is_ok());
    }

    #[test]
    fn restore_traffic_is_gets_only() {
        // The restore path's only Bitwarden traffic is the two GET list
        // calls: restore_into itself takes no client at all, so no PUT,
        // POST, or DELETE can originate from it.
        let stamped = serde_json::json!({
            "id": "bw-1", "name": "stamped", "notes": null, "favorite": false,
            "folderId": "f-ops", "type": 1, "reprompt": 0,
            "login": {"username": "u", "password": "p", "totp": null, "uris": []},
            "fields": [
                {"name": SYNC_ID_FIELD, "value": STAMP_UUID, "type": 0},
                {"name": SYNC_HASH_FIELD, "value": "h", "type": 0}
            ],
            "revisionDate": "r1", "deletedDate": null
        });
        let items_body = serde_json::json!({
            "success": true,
            "data": {"object": "list", "data": [stamped]}
        })
        .to_string();
        let folders_body = serde_json::json!({
            "success": true,
            "data": {"object": "list", "data": [{"id": "f-ops", "name": "Ops"}]}
        })
        .to_string();
        let (base, captured) = crate::bw::tests::stub_server_capturing(vec![
            ("GET /list/object/items ".into(), 200, items_body),
            ("GET /list/object/folders ".into(), 200, folders_body),
        ]);
        let bw = crate::bw::BwClient::new(&base).unwrap();
        let items = bw.list_items().unwrap();
        let folders = bw.list_folders().unwrap();
        let mut vault = test_vault();
        let (report, _) = restore_into(&mut vault.db, &items, &folders).unwrap();
        assert_eq!(report.stamped, 1);
        let requests = captured.lock().unwrap();
        assert_eq!(requests.len(), 2, "requests: {requests:?}");
        assert!(
            requests.iter().all(|(line, _)| line.starts_with("GET ")),
            "restore must issue only GETs, got: {requests:?}"
        );
    }

    #[test]
    fn restore_then_plan_is_zero_actions() {
        // The acceptance invariant: restore, commit the new journal, then
        // plan a sync against the restored vault + new journal + the same
        // Bitwarden state. No actions, no quarantines.
        let items = vec![
            bw_item("bw-1", "stamped", Some(STAMP_UUID), false),
            bw_item("bw-2", "fresh", None, false),
            bw_item("bw-3", "trashed", None, true),
        ];
        let folders = folders();
        let mut vault = test_vault();
        let (report, ops) = restore_into(&mut vault.db, &items, &folders).unwrap();
        assert_eq!(report.stamped, 1);
        assert_eq!(report.unstamped, 1);
        assert_eq!(report.skipped_trashed, 1);
        let journal = test_journal();
        journal.apply_ops(&ops).unwrap();
        assert_eq!(journal.live_mapping_count().unwrap(), 2);

        let entries = extract_entries(&vault.db);
        let tombstones = std::collections::HashSet::new();
        let live: Vec<BwItem> = items.into_iter().filter(|i| !i.trashed()).collect();
        // The trashed item stays in the listing (deletedDate set), as the
        // real serve returns it; plan must still be a no-op for it: its
        // KeePass entry does not exist and it is not unmapped-live, so
        // the unmapped loop skips it (trashed) and the pair loop never
        // sees it.
        let mut listed = live.clone();
        listed.push(bw_item("bw-3", "trashed", None, true));
        let p = plan(
            &entries,
            &tombstones,
            &listed,
            &folders,
            &journal,
            &SyncOpts::default(),
        )
        .unwrap();
        assert!(
            p.actions.is_empty(),
            "expected 0 actions after restore, got {} actions",
            p.actions.len()
        );
        assert_eq!(journal.unresolved_quarantine_count().unwrap(), 0);
    }

    #[test]
    fn org_items_are_skipped_and_counted_never_adopted() {
        let mut vault = test_vault();
        let mut org = bw_item("bw-org", "org-owned", None, false);
        org.collection_ids = vec!["coll-1".into()];
        let items = vec![org, bw_item("bw-1", "plain", None, false)];
        let (report, ops) = restore_into(&mut vault.db, &items, &folders()).unwrap();
        assert_eq!(report.skipped_org, 1);
        assert_eq!(report.unstamped, 1);
        assert_eq!(ops.len(), 1);
        let entries = extract_entries(&vault.db);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].title, "plain");
    }

    #[test]
    fn attached_items_restore_without_blobs_and_are_counted() {
        let mut vault = test_vault();
        let mut att = bw_item("bw-att", "with-blob", None, false);
        att.attachments = vec![BwAttachment {
            id: Some("att-1".into()),
            file_name: Some("scan.pdf".into()),
            size: Some(1234),
        }];
        let items = vec![att];
        let (report, ops) = restore_into(&mut vault.db, &items, &folders()).unwrap();
        assert_eq!(report.restored_without_blobs, 1);
        assert_eq!(report.unstamped, 1);
        assert_eq!(ops.len(), 1);
        // The entry itself restores; only its blobs are missing.
        assert_eq!(extract_entries(&vault.db).len(), 1);
    }
}
