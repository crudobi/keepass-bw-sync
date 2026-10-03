//! The sync engine.
//!
//! Policy (KeePass is the source of truth):
//! - New/changed KeePass entries flow to Bitwarden idempotently.
//! - Bitwarden-side edits the engine did not make are **quarantined**, never
//!   silently overwritten — unless `--force` (KeePass wins) or `--writeback`
//!   (apply the Bitwarden edit into KeePass, preserving the loser in entry
//!   history).
//! - Deletes propagate only into the other side's *recoverable* bin, never as
//!   hard deletes, and never auto-resurrect (no delete/recreate loops).
//! - Genuine concurrent edits (both sides changed since last sync) always
//!   quarantine: there is no safe automatic merge for secrets.

use std::collections::{HashMap, HashSet};

use anyhow::{Context, Result};
use uuid::Uuid;

use crate::bw::{BwClient, BwFolder, BwItem, BwLogin};
use crate::canonical::CanonicalEntry;
use crate::journal::Journal;
use crate::kdbx::{bw_adopt_entry, KdbxVault};
use crate::secret::Secret;

#[derive(Debug, Clone, Default)]
pub struct SyncOpts {
    /// Apply foreign Bitwarden edits into KeePass instead of quarantining.
    pub writeback: bool,
    /// KeePass unconditionally overwrites foreign Bitwarden edits.
    pub force: bool,
    /// Create KeePass entries for unmapped Bitwarden items.
    pub adopt: bool,
}

#[derive(Debug)]
pub enum Action {
    CreateBw { entry_idx: usize },
    UpdateBw { bw_id: String, entry_idx: usize, expected_revision: String },
    TrashBw { bw_id: String, kp_uuid: Uuid },
    /// Bitwarden trashed the item and KeePass did not change it: recycle in KP.
    RecycleKp { kp_uuid: Uuid, bw_id: String },
    /// KeePass entry is in recycle bin and BW is unchanged: trash in BW.
    AdoptBwNew { item_idx: usize },
    /// Foreign BW edit applied into KeePass (only with --writeback).
    WritebackEdit { bw_id: String, kp_uuid: Uuid, item_idx: usize },
    Quarantine(QuarantineCase),
}

#[derive(Debug)]
pub struct QuarantineCase {
    pub kind: &'static str,
    pub kp_uuid: Option<Uuid>,
    pub bw_id: Option<String>,
    pub title: String,
    pub detail: String,
}

pub struct Plan {
    pub actions: Vec<Action>,
}

fn stamp_uuid(item: &BwItem) -> Option<Uuid> {
    let (id, _) = item.stamps();
    id.and_then(|s| s.parse().ok())
}

/// Build the sync plan. Pure apart from journal reads for identity mapping.
pub fn plan(
    kp_entries: &[CanonicalEntry],
    kp_tombstones: &HashSet<Uuid>,
    bw_items: &[BwItem],
    journal: &Journal,
    opts: &SyncOpts,
) -> Result<Plan> {
    let mut actions = Vec::new();
    let kp_by_uuid: HashMap<Uuid, usize> =
        kp_entries.iter().enumerate().map(|(i, e)| (e.uuid, i)).collect();
    let bw_by_id: HashMap<&str, usize> = bw_items
        .iter()
        .enumerate()
        .map(|(i, it)| (it.id.as_str(), i))
        .collect();

    // Adopt stamped-but-unmapped items into the journal first (identity lives
    // in the custom field, so any host can rebuild the map).
    for it in bw_items {
        if let Some(u) = stamp_uuid(it) {
            if journal.mapping_by_kp(&u)?.is_none() {
                journal.upsert_mapping(&u, &it.id, &it.content_hash_hex())?;
            }
        }
    }

    for (idx, e) in kp_entries.iter().enumerate() {
        if e.deleted {
            // In KeePass recycle bin: propagate a soft delete to BW when BW is
            // unchanged since last sync; otherwise it's a delete-vs-edit race.
            if let Some((bw_id, last_hash)) = journal.mapping_by_kp(&e.uuid)? {
                if let Some(&bi) = bw_by_id.get(bw_id.as_str()) {
                    let it = &bw_items[bi];
                    if it.trashed() {
                        continue; // already trashed on both sides
                    }
                    if it.content_hash_hex() == last_hash {
                        actions.push(Action::TrashBw { bw_id, kp_uuid: e.uuid });
                    } else {
                        actions.push(Action::Quarantine(QuarantineCase {
                            kind: "delete-vs-edit",
                            kp_uuid: Some(e.uuid),
                            bw_id: Some(bw_id),
                            title: e.title.clone(),
                            detail: "entry is in the KeePass recycle bin but the Bitwarden item changed since last sync".into(),
                        }));
                    }
                }
            }
            continue;
        }

        match journal.mapping_by_kp(&e.uuid)? {
            None => {
                // Brand-new KeePass entry.
                actions.push(Action::CreateBw { entry_idx: idx });
            }
            Some((bw_id, last_hash)) => match bw_by_id.get(bw_id.as_str()) {
                None => {
                    // Mapped BW item is gone. Tombstoned = already handled.
                    // Otherwise the user permanently deleted it in Bitwarden:
                    // move the KP entry to the recycle bin (recoverable).
                    if journal.tombstoned(&e.uuid)? {
                        continue;
                    }
                    if kp_tombstones.contains(&e.uuid) {
                        // Permanently deleted in KeePass too: both sides agree.
                        journal.record_tombstone(&e.uuid, Some(&bw_id), "both")?;
                        journal.delete_mapping_by_kp(&e.uuid)?;
                        continue;
                    }
                    actions.push(Action::RecycleKp { kp_uuid: e.uuid, bw_id: bw_id.clone() });
                }
                Some(&bi) => {
                    let it = &bw_items[bi];
                    let h_kp = e.content_hash_hex();
                    let h_bw = it.content_hash_hex();
                    let kp_changed = h_kp != last_hash;
                    let bw_changed = h_bw != last_hash;

                    if it.trashed() {
                        if !kp_changed {
                            actions.push(Action::RecycleKp { kp_uuid: e.uuid, bw_id: bw_id.clone() });
                        } else {
                            actions.push(Action::Quarantine(QuarantineCase {
                                kind: "delete-vs-edit",
                                kp_uuid: Some(e.uuid),
                                bw_id: Some(bw_id),
                                title: e.title.clone(),
                                detail: "item is in the Bitwarden trash but the KeePass entry changed since last sync".into(),
                            }));
                        }
                        continue;
                    }

                    match (kp_changed, bw_changed) {
                        (false, false) => {}
                        (true, false) => actions.push(Action::UpdateBw {
                            bw_id,
                            entry_idx: idx,
                            expected_revision: it.revision_date.clone(),
                        }),
                        (false, true) => {
                            // Foreign Bitwarden edit.
                            if opts.writeback {
                                actions.push(Action::WritebackEdit {
                                    bw_id,
                                    kp_uuid: e.uuid,
                                    item_idx: bi,
                                });
                            } else if opts.force {
                                actions.push(Action::UpdateBw {
                                    bw_id,
                                    entry_idx: idx,
                                    expected_revision: it.revision_date.clone(),
                                });
                            } else {
                                actions.push(Action::Quarantine(QuarantineCase {
                                    kind: "foreign-bw-edit",
                                    kp_uuid: Some(e.uuid),
                                    bw_id: Some(bw_id),
                                    title: e.title.clone(),
                                    detail: "Bitwarden item changed outside the engine; kept as-is pending review".into(),
                                }));
                            }
                        }
                        (true, true) => {
                            actions.push(Action::Quarantine(QuarantineCase {
                                kind: "concurrent-edit",
                                kp_uuid: Some(e.uuid),
                                bw_id: Some(bw_id),
                                title: e.title.clone(),
                                detail: "both sides changed since last sync; no automatic merge for secrets".into(),
                            }));
                        }
                    }
                }
            },
        }
    }

    // KeePass tombstones with no live entry: propagate soft delete to BW.
    for u in kp_tombstones {
        if kp_by_uuid.contains_key(u) {
            continue;
        }
        if journal.tombstoned(u)? {
            continue;
        }
        if let Some((bw_id, _)) = journal.mapping_by_kp(u)? {
            if let Some(&bi) = bw_by_id.get(bw_id.as_str()) {
                if !bw_items[bi].trashed() {
                    actions.push(Action::TrashBw { bw_id: bw_id.clone(), kp_uuid: *u });
                }
            }
            journal.record_tombstone(u, Some(&bw_id), "keepass")?;
        }
    }

    // Unmapped, unstamped, live Bitwarden items: new on the BW side.
    for (idx, it) in bw_items.iter().enumerate() {
        if it.trashed() || stamp_uuid(it).is_some() {
            continue;
        }
        if journal.mapping_by_bw(&it.id)?.is_some() {
            continue;
        }
        if opts.adopt {
            actions.push(Action::AdoptBwNew { item_idx: idx });
        } else {
            actions.push(Action::Quarantine(QuarantineCase {
                kind: "unmapped-bw-item",
                kp_uuid: None,
                bw_id: Some(it.id.clone()),
                title: it.name.clone(),
                detail: "Bitwarden item has no sync stamp; adopt explicitly or ignore".into(),
            }));
        }
    }

    Ok(Plan { actions })
}

#[derive(Debug, Default)]
pub struct ApplyReport {
    pub created: usize,
    pub updated: usize,
    pub trashed: usize,
    pub kp_recycled: usize,
    pub kp_adopted: usize,
    pub writeback_applied: usize,
    pub quarantined: usize,
}

/// Execute the plan. KeePass mutations are applied to the in-memory database;
/// the caller saves atomically afterwards.
pub fn apply(
    plan: &Plan,
    kp_entries: &[CanonicalEntry],
    bw_items: &[BwItem],
    bw: &BwClient,
    vault: &mut KdbxVault,
    journal: &Journal,
    folder_ids: &mut HashMap<String, String>,
    folders: &[BwFolder],
    opts: &SyncOpts,
) -> Result<ApplyReport> {
    let _ = opts;
    let mut folder_cache: HashMap<String, String> = folders
        .iter()
        .map(|f| (f.name.clone(), f.id.clone()))
        .collect();
    let mut report = ApplyReport::default();

    let mut folder_for = |path: &str, bw: &BwClient| -> Result<Option<String>> {
        if path.is_empty() {
            return Ok(None);
        }
        if let Some(id) = folder_cache.get(path) {
            return Ok(Some(id.clone()));
        }
        let id = bw.create_folder(path)?;
        folder_cache.insert(path.to_string(), id.clone());
        folder_ids.insert(path.to_string(), id.clone());
        Ok(Some(id))
    };

    for a in &plan.actions {
        match a {
            Action::CreateBw { entry_idx } => {
                let e = &kp_entries[*entry_idx];
                let fid = folder_for(&e.group_path, bw)?;
                let bw_id = bw.create_item(e, fid.as_deref())?;
                journal.upsert_mapping(&e.uuid, &bw_id, &e.content_hash_hex())?;
                report.created += 1;
            }
            Action::UpdateBw { bw_id, entry_idx, expected_revision } => {
                let e = &kp_entries[*entry_idx];
                let fid = folder_for(&e.group_path, bw)?;
                bw.edit_item(bw_id, e, fid.as_deref(), expected_revision)
                    .with_context(|| format!("update bw item {}", bw_id))?;
                journal.upsert_mapping(&e.uuid, bw_id, &e.content_hash_hex())?;
                report.updated += 1;
            }
            Action::TrashBw { bw_id, kp_uuid } => {
                bw.trash_item(bw_id)?;
                journal.record_tombstone(kp_uuid, Some(bw_id), "keepass")?;
                journal.delete_mapping_by_kp(kp_uuid)?;
                report.trashed += 1;
            }
            Action::RecycleKp { kp_uuid, bw_id } => {
                let nid = keepass_rs::model::core::node::NodeId::from_uuid(*kp_uuid);
                if vault.db.remove_entry(&nid, true).is_some() {
                    journal.record_tombstone(kp_uuid, Some(bw_id), "bitwarden")?;
                    journal.delete_mapping_by_kp(kp_uuid)?;
                    report.kp_recycled += 1;
                }
            }
            Action::AdoptBwNew { item_idx } => {
                let it = &bw_items[*item_idx];
                let entry = bw_adopt_entry(it);
                let uuid = entry.id.as_uuid().cloned().unwrap_or_default();
                let root = vault
                    .db
                    .root_group_id
                    .clone()
                    .context("no root group")?;
                if vault.db.add_entry(entry, &root) {
                    journal.upsert_mapping(&uuid, &it.id, &it.content_hash_hex())?;
                    report.kp_adopted += 1;
                }
            }
            Action::WritebackEdit { bw_id, kp_uuid, item_idx } => {
                let it = &bw_items[*item_idx];
                let nid = keepass_rs::model::core::node::NodeId::from_uuid(*kp_uuid);
                if let Some(entry) = vault.db.entries.get_mut(&nid) {
                    // Preserve the loser in entry history before overwriting.
                    let snapshot = entry.clone();
                    entry.history.push(snapshot);
                    apply_bw_to_entry(entry, it);
                    journal.upsert_mapping(kp_uuid, bw_id, &it.content_hash_hex())?;
                    report.writeback_applied += 1;
                }
            }
            Action::Quarantine(q) => {
                journal.quarantine(&q.kind, q.kp_uuid.as_ref(), q.bw_id.as_deref(), &q.title, &q.detail)?;
                report.quarantined += 1;
            }
        }
    }
    Ok(report)
}

/// Overwrite a KeePass entry's syncable fields from a Bitwarden item.
fn apply_bw_to_entry(
    entry: &mut keepass_rs::model::entry::Entry,
    it: &BwItem,
) {
    use keepass_rs::model::core::security::ProtectedString as PS;
    use keepass_rs::model::core::date::DateInstant;
    let login = it.login.clone().unwrap_or_default();
    entry.title = it.name.clone();
    entry.username = PS::new_protected(login.username.as_deref().unwrap_or_default());
    entry.password = PS::new_protected(login.password.as_deref().unwrap_or_default());
    entry.url = login
        .uris
        .as_ref()
        .and_then(|u| u.first())
        .and_then(|u| u.uri.clone())
        .unwrap_or_default();
    entry.notes = PS::new_protected(it.notes.as_deref().unwrap_or_default());
    // Replace non-stamp custom fields wholesale with the BW side's set.
    entry.custom_fields.retain(|f| {
        f.name == crate::stamps::SYNC_ID_FIELD || f.name == crate::stamps::SYNC_HASH_FIELD
    });
    for f in &it.fields {
        if f.name == crate::stamps::SYNC_ID_FIELD || f.name == crate::stamps::SYNC_HASH_FIELD {
            continue;
        }
        entry.custom_fields.push(keepass_rs::model::entry::EntryField {
            name: f.name.clone(),
            value: PS::new_protected(&f.value),
            is_protected: false,
        });
    }
    if let Some(t) = login.totp.filter(|s| !s.is_empty()) {
        entry.custom_fields.retain(|f| !f.name.eq_ignore_ascii_case("totp"));
        entry.custom_fields.push(keepass_rs::model::entry::EntryField {
            name: "totp".to_string(),
            value: PS::new_protected(&t),
            is_protected: true,
        });
    }
    entry.last_modification_time = DateInstant::now();
}

/// Build a [`Secret`] for tests without touching real credentials.
#[doc(hidden)]
pub fn test_secret(s: &str) -> Secret {
    Secret::from_str(s)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canonical::CanonicalEntry;
    use crate::secret::Secret;

    fn entry(uuid: &str) -> CanonicalEntry {
        CanonicalEntry {
            uuid: uuid.parse().unwrap(),
            title: "t".into(),
            username: "u".into(),
            password: Secret::from_str("p"),
            url: "".into(),
            notes: "".into(),
            totp: None,
            custom: vec![],
            group_path: "".into(),
            last_modified_ms: 0,
            deleted: false,
        }
    }

    fn bw_item(id: &str, kp_uuid: Option<&str>, rev: &str) -> BwItem {
        let mut fields = vec![];
        if let Some(u) = kp_uuid {
            fields.push(crate::bw::BwField {
                name: crate::stamps::SYNC_ID_FIELD.into(),
                value: u.into(),
            });
            fields.push(crate::bw::BwField {
                name: crate::stamps::SYNC_HASH_FIELD.into(),
                value: "oldhash".into(),
            });
        }
        BwItem {
            id: id.into(),
            name: "t".into(),
            notes: None,
            favorite: false,
            folder_id: None,
            login: Some(BwLogin {
                username: Some("u".into()),
                password: Some("p".into()),
                totp: None,
                uris: None,
            }),
            fields,
            revision_date: rev.into(),
            deleted_date: None,
        }
    }

    fn mem_journal() -> Journal {
        Journal::open(Path::new(":memory:")).unwrap()
    }

    use std::path::Path;

    #[test]
    fn new_kp_entry_plans_create() {
        let j = mem_journal();
        let kp = vec![entry("11111111-1111-1111-1111-111111111111")];
        let p = plan(&kp, &HashSet::new(), &[], &j, &SyncOpts::default()).unwrap();
        assert_eq!(p.actions.len(), 1);
        assert!(matches!(p.actions[0], Action::CreateBw { .. }));
    }

    #[test]
    fn unchanged_pair_plans_nothing() {
        let j = mem_journal();
        let kp = vec![entry("11111111-1111-1111-1111-111111111111")];
        let h = kp[0].content_hash_hex();
        j.upsert_mapping(&kp[0].uuid, "bw-1", &h).unwrap();
        let mut bi = bw_item("bw-1", Some("11111111-1111-1111-1111-111111111111"), "r1");
        // make the BW content hash match: stamp hash must equal live hash
        bi.fields.iter_mut().find(|f| f.name == crate::stamps::SYNC_HASH_FIELD).unwrap().value = bi.content_hash_hex();
        j.upsert_mapping(&kp[0].uuid, "bw-1", &bi.content_hash_hex()).unwrap();
        let p = plan(&kp, &HashSet::new(), &[bi], &j, &SyncOpts::default()).unwrap();
        assert!(p.actions.is_empty(), "expected no actions, got {:?}", p.actions.len());
    }

    #[test]
    fn kp_change_plans_update() {
        let j = mem_journal();
        let mut kp = vec![entry("11111111-1111-1111-1111-111111111111")];
        let bi = bw_item("bw-1", Some("11111111-1111-1111-1111-111111111111"), "r1");
        j.upsert_mapping(&kp[0].uuid, "bw-1", &bi.content_hash_hex())
            .unwrap();
        kp[0].title = "changed".into();
        let p = plan(&kp, &HashSet::new(), &[bi], &j, &SyncOpts::default()).unwrap();
        assert_eq!(p.actions.len(), 1);
        assert!(matches!(p.actions[0], Action::UpdateBw { .. }));
    }

    #[test]
    fn foreign_bw_edit_quarantines_by_default() {
        let j = mem_journal();
        let kp = vec![entry("11111111-1111-1111-1111-111111111111")];
        let h = kp[0].content_hash_hex();
        j.upsert_mapping(&kp[0].uuid, "bw-1", &h).unwrap();
        let mut bi = bw_item("bw-1", Some("11111111-1111-1111-1111-111111111111"), "r2");
        bi.name = "someone edited me".into(); // foreign edit
        let p = plan(&kp, &HashSet::new(), &[bi], &j, &SyncOpts::default()).unwrap();
        assert!(matches!(p.actions[0], Action::Quarantine(_)));
    }

    #[test]
    fn force_overwrites_foreign_bw_edit() {
        let j = mem_journal();
        let kp = vec![entry("11111111-1111-1111-1111-111111111111")];
        let h = kp[0].content_hash_hex();
        j.upsert_mapping(&kp[0].uuid, "bw-1", &h).unwrap();
        let mut bi = bw_item("bw-1", Some("11111111-1111-1111-1111-111111111111"), "r2");
        bi.name = "someone edited me".into();
        let opts = SyncOpts { force: true, ..Default::default() };
        let p = plan(&kp, &HashSet::new(), &[bi], &j, &opts).unwrap();
        assert!(matches!(p.actions[0], Action::UpdateBw { .. }));
    }

    #[test]
    fn bw_trash_with_unchanged_kp_recycles() {
        let j = mem_journal();
        let kp = vec![entry("11111111-1111-1111-1111-111111111111")];
        let h = kp[0].content_hash_hex();
        j.upsert_mapping(&kp[0].uuid, "bw-1", &h).unwrap();
        let mut bi = bw_item("bw-1", Some("11111111-1111-1111-1111-111111111111"), "r2");
        bi.deleted_date = Some("2026-10-03T00:00:00Z".into());
        let p = plan(&kp, &HashSet::new(), &[bi], &j, &SyncOpts::default()).unwrap();
        assert!(matches!(p.actions[0], Action::RecycleKp { .. }));
    }

    #[test]
    fn permanently_deleted_bw_item_is_not_resurrected() {
        let j = mem_journal();
        let kp = vec![entry("11111111-1111-1111-1111-111111111111")];
        j.upsert_mapping(&kp[0].uuid, "bw-1", "h").unwrap();
        j.record_tombstone(&kp[0].uuid, Some("bw-1"), "bitwarden").unwrap();
        // BW item gone entirely; tombstone exists -> no action (no resurrect)
        let p = plan(&kp, &HashSet::new(), &[], &j, &SyncOpts::default()).unwrap();
        assert!(p.actions.is_empty());
    }
}
