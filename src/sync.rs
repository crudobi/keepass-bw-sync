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
//! - Genuine concurrent edits (both sides changed to *different* content)
//!   quarantine by default — there is no safe automatic merge for secrets —
//!   but `--force`/`--writeback` resolve them. Both sides holding identical
//!   new content is agreement, not conflict: the journal watermark simply
//!   refreshes (that is the post-crash recovery state).

use std::collections::{HashMap, HashSet};

use anyhow::{Context, Result};
use uuid::Uuid;

use crate::bw::{BwClient, BwFolder, BwItem, EditOutcome, TrashOutcome};
use crate::canonical::CanonicalEntry;
use crate::journal::{Journal, JournalOp};
use crate::kdbx::{adopt_bw_entry, recycle_entry, writeback_entry, KdbxVault};

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
    /// New KeePass entry: create the Bitwarden item.
    CreateBw { entry_idx: usize },
    /// KeePass entry changed: update the Bitwarden item (revision-guarded).
    UpdateBw { bw_id: String, entry_idx: usize, expected_revision: String },
    /// KeePass entry is in the recycle bin and Bitwarden is unchanged:
    /// soft-delete the Bitwarden item (revision-guarded).
    TrashBw { bw_id: String, kp_uuid: Uuid, expected_revision: String },
    /// Bitwarden trashed the item and KeePass did not change it: recycle in KP.
    RecycleKp { kp_uuid: Uuid, bw_id: String },
    /// Unmapped, unstamped Bitwarden item: adopt as a new KeePass entry
    /// (only with --adopt), then stamp KBS_SYNC_ID back onto the BW item.
    AdoptBwNew { item_idx: usize },
    /// Foreign BW edit applied into KeePass (only with --writeback).
    WritebackEdit { bw_id: String, kp_uuid: Uuid, item_idx: usize },
    /// Genuine conflict or unmappable item: queue for human review.
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

impl From<&QuarantineCase> for JournalOp {
    fn from(q: &QuarantineCase) -> Self {
        JournalOp::Quarantine {
            kind: q.kind,
            kp_uuid: q.kp_uuid,
            bw_id: q.bw_id.clone(),
            title: q.title.clone(),
            detail: q.detail.clone(),
        }
    }
}

pub struct Plan {
    pub actions: Vec<Action>,
}

fn stamp_uuid(item: &BwItem) -> Option<Uuid> {
    let (id, _) = item.stamps();
    id.and_then(|s| s.parse().ok())
}

/// The flat placement model: an entry's top-level KeePass group name
/// corresponds to a Bitwarden folder of the same name. Root-group entries
/// (and items with no folder) map to "".
fn top_group(group_path: &str) -> &str {
    group_path.split('/').next().unwrap_or("")
}

/// Build the sync plan.
///
/// Not pure: it performs idempotent journal writes for identity recovery
/// (stamped-but-unmapped Bitwarden items get their mapping upserted) and
/// terminal bookkeeping (both-sides-deleted pairs). All per-action journal
/// mutations are deferred — [`apply`] returns them as [`JournalOp`]s and the
/// caller commits them via [`Journal::apply_ops`] only after the KeePass
/// database is durably saved, so the journal can never claim KeePass
/// mutations that never reached disk.
pub fn plan(
    kp_entries: &[CanonicalEntry],
    kp_tombstones: &HashSet<Uuid>,
    bw_items: &[BwItem],
    folders: &[BwFolder],
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
    let folder_name_by_id: HashMap<&str, &str> = folders
        .iter()
        .map(|f| (f.id.as_str(), f.name.as_str()))
        .collect();
    // The Bitwarden folder name an item sits in ("" when folderless or
    // the folder id is unknown to the listing).
    let bw_folder_name = |it: &BwItem| -> &str {
        it.folder_id
            .as_deref()
            .and_then(|id| folder_name_by_id.get(id).copied())
            .unwrap_or("")
    };

    // Fail-closed on transport failures. An empty Bitwarden listing while the
    // journal holds live mappings is almost certainly a sync failure, not
    // "the user deleted everything" (2026-10-03: this once recycled a whole
    // test database) — and a *partial* listing is the same failure class in
    // a different shape. Refuse instead; genuine mass Bitwarden deletes need
    // an explicit journal reset. (Trashed items stay in the listing with
    // deletedDate set, so a real mass-trash does not trip this guard.)
    let live_ids = journal.live_mapped_bw_ids()?;
    if bw_items.is_empty() {
        if !live_ids.is_empty() {
            anyhow::bail!(
                "refusing to sync: Bitwarden listed 0 items but the journal holds {} live mappings (probable sync failure); no changes made. If you genuinely deleted everything server-side, run `keepass-bw-sync journal reset --journal <path>`",
                live_ids.len()
            );
        }
    } else {
        let present: HashSet<&str> = bw_items.iter().map(|it| it.id.as_str()).collect();
        let missing = live_ids.iter().filter(|id| !present.contains(id.as_str())).count();
        if !live_ids.is_empty() && missing * 2 > live_ids.len() {
            anyhow::bail!(
                "refusing to sync: Bitwarden listing is missing {}/{} mapped items (probable partial listing); no changes made. If you genuinely deleted most of your vault server-side, run `keepass-bw-sync journal reset --journal <path>`",
                missing,
                live_ids.len()
            );
        }
    }

    // Clear stale missing records for items present in this listing: a
    // reappearance means the earlier absence was a glitch, not a delete,
    // so the two-listing clock resets (see the missing arm below).
    for it in bw_items {
        journal.clear_missing(&it.id)?;
    }

    // Rebuild journal mappings from stamps (identity lives in the custom
    // field, so any host can rebuild the map). A stamp whose UUID matches no
    // KeePass entry is an orphan — most likely an interrupted adopt whose
    // KeePass entry was never written. Upserting a mapping for it would mint
    // a phantom identity (the pair would then compare hashes against a
    // non-existent entry and TrashBw its Bitwarden item); quarantine it for
    // human re-adopt instead. Stamps that ride a KeePass tombstone keep
    // their mapping: that is the delete-propagation path, not an orphan.
    //
    // The rebuilt baseline is the KBS_SYNC_HASH stamp — the hash the engine
    // last wrote — NEVER the item's live content hash. Adopting live state
    // as the baseline (the old behavior) silently blessed every foreign
    // edit made since the last engine write: after a `journal reset`, the
    // next sync would overwrite them from KeePass without a trace. With
    // the stamped baseline, the pair loop below classifies a live/stamp
    // mismatch as what it is: a foreign edit (quarantine by default;
    // --writeback/--force still apply). Items stamped before KBS_SYNC_HASH
    // existed have no stamp hash; only those fall back to the live hash.
    for it in bw_items {
        if let Some(u) = stamp_uuid(it) {
            if journal.mapping_by_kp(&u)?.is_none() {
                let kp_has = kp_by_uuid.contains_key(&u)
                    || kp_tombstones.contains(&u)
                    || journal.tombstoned(&u)?;
                if kp_has {
                    let baseline = it
                        .stamps()
                        .1
                        .filter(|x| !x.is_empty())
                        .unwrap_or_else(|| it.content_hash_hex());
                    journal.upsert_mapping(&u, &it.id, &baseline)?;
                } else {
                    actions.push(Action::Quarantine(QuarantineCase {
                        kind: "orphan_bw_stamp",
                        kp_uuid: Some(u),
                        bw_id: Some(it.id.clone()),
                        title: it.name.clone(),
                        detail: "Bitwarden item carries a sync stamp for a KeePass entry that does not exist (interrupted adopt?); not adopting a phantom mapping. Remove the KBS_SYNC_ID/KBS_SYNC_HASH fields to re-adopt, or resolve if intentional".into(),
                    }));
                }
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
                        // Already trashed on both sides: nothing to
                        // propagate, but the tombstone bookkeeping still
                        // completes — otherwise the mapping lingers forever
                        // (a crash between an applied TrashBw and the
                        // journal commit used to leak exactly this).
                        journal.record_tombstone(&e.uuid, Some(&bw_id), "keepass")?;
                        journal.delete_mapping_by_kp(&e.uuid)?;
                        continue;
                    }
                    if it.content_hash_hex() == last_hash {
                        actions.push(Action::TrashBw {
                            bw_id,
                            kp_uuid: e.uuid,
                            expected_revision: it.revision_date.clone(),
                        });
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
                    // A single absence may be a transient listing glitch,
                    // not a delete: the 2026-11-01 review showed a one-run
                    // recycle followed by a reappearing item cascading into
                    // TrashBw, deleting a live entry on both sides. Only
                    // recycle once a second, independent listing confirms
                    // the absence; the first sighting just records it.
                    // (A genuinely trashed BW item still recycles
                    // immediately — that arm sees the item
                    // present-but-trashed, not missing.)
                    if journal.was_missing(&bw_id)? {
                        journal.clear_missing(&bw_id)?;
                        // Mirror the present-but-trashed arm: a KeePass
                        // edit since the watermark turns a confirmed
                        // absence into delete-vs-edit, not a recycle —
                        // otherwise a live edit would land in the bin
                        // on the strength of a listing absence alone.
                        if e.content_hash_hex() != last_hash {
                            actions.push(Action::Quarantine(QuarantineCase {
                                kind: "delete-vs-edit",
                                kp_uuid: Some(e.uuid),
                                bw_id: Some(bw_id),
                                title: e.title.clone(),
                                detail: "item is absent from the Bitwarden listing but the KeePass entry changed since last sync".into(),
                            }));
                        } else {
                            actions.push(Action::RecycleKp { kp_uuid: e.uuid, bw_id: bw_id.clone() });
                        }
                    } else {
                        journal.note_missing(&bw_id, &e.uuid)?;
                    }
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

                    if h_kp == h_bw {
                        // The two sides AGREE with each other; only the
                        // journal watermark is behind. This is the
                        // post-crash state (a Bitwarden write landed but
                        // the deferred journal commit did not) and the
                        // one-time state after a hash-format change:
                        // agreement, not conflict. Refresh the watermark
                        // to the common hash — never quarantine two
                        // agreeing copies. (Idempotent journal write,
                        // like the rebuild above.)
                        if kp_changed {
                            journal.upsert_mapping(&e.uuid, &bw_id, &h_kp)?;
                        }
                        // Placement still reconciles: a move is not
                        // content, so it rides an UpdateBw whose payload
                        // carries the folder (flat model: top-level
                        // group name <-> folder name).
                        if top_group(&e.group_path) != bw_folder_name(it) {
                            actions.push(Action::UpdateBw {
                                bw_id,
                                entry_idx: idx,
                                expected_revision: it.revision_date.clone(),
                            });
                        }
                    } else {
                        // A Bitwarden-side change to resolve: --writeback
                        // applies it into KeePass, --force overwrites it
                        // from KeePass, otherwise it quarantines. The two
                        // arms below differ only in quarantine kind/detail
                        // (foreign edit vs genuine divergence).
                        let bw_change = |kind: &'static str, detail: &str, bw_id: &str| -> Action {
                            if opts.writeback {
                                Action::WritebackEdit {
                                    bw_id: bw_id.to_string(),
                                    kp_uuid: e.uuid,
                                    item_idx: bi,
                                }
                            } else if opts.force {
                                Action::UpdateBw {
                                    bw_id: bw_id.to_string(),
                                    entry_idx: idx,
                                    expected_revision: it.revision_date.clone(),
                                }
                            } else {
                                Action::Quarantine(QuarantineCase {
                                    kind,
                                    kp_uuid: Some(e.uuid),
                                    bw_id: Some(bw_id.to_string()),
                                    title: e.title.clone(),
                                    detail: detail.into(),
                                })
                            }
                        };
                        match (kp_changed, bw_changed) {
                            (false, false) => {}
                            (true, false) => actions.push(Action::UpdateBw {
                                bw_id,
                                entry_idx: idx,
                                expected_revision: it.revision_date.clone(),
                            }),
                            (false, true) => {
                                // Foreign Bitwarden edit.
                                actions.push(bw_change(
                                    "foreign-bw-edit",
                                    "Bitwarden item changed outside the engine; kept as-is pending review",
                                    &bw_id,
                                ));
                            }
                            (true, true) => {
                                // Genuine divergence: both sides changed
                                // to DIFFERENT content. Same resolution as
                                // a foreign edit — the flags must apply
                                // here too, or crash-recovery quarantines
                                // would be unresolvable through the tool.
                                actions.push(bw_change(
                                    "concurrent-edit",
                                    "both sides changed since last sync; no automatic merge for secrets",
                                    &bw_id,
                                ));
                            }
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
            match bw_by_id.get(bw_id.as_str()) {
                Some(&bi) if !bw_items[bi].trashed() => {
                    actions.push(Action::TrashBw {
                        bw_id: bw_id.clone(),
                        kp_uuid: *u,
                        expected_revision: bw_items[bi].revision_date.clone(),
                    });
                    // No plan-time tombstone for this arm: the TrashBw
                    // apply arm records it as a deferred JournalOp, only
                    // when the trash is applied.
                }
                _ => {
                    // The Bitwarden item is already trashed (a crash
                    // between the applied trash and the journal commit
                    // used to leak this mapping forever) or permanently
                    // gone: both sides agree the entry is deleted, so the
                    // bookkeeping completes now — tombstone recorded,
                    // mapping removed — with no action to apply.
                    journal.record_tombstone(u, Some(&bw_id), "keepass")?;
                    journal.delete_mapping_by_kp(u)?;
                }
            }
        }
    }

    // Unmapped, unstamped, live Bitwarden items: new on the BW side.
    // Only type-1 (login) items are adopted: KeePass has no card/identity
    // model, and silently reshaping a secure note into a login-shaped entry
    // would corrupt the user's data. Other types quarantine for human review.
    for (idx, it) in bw_items.iter().enumerate() {
        if it.trashed() || stamp_uuid(it).is_some() {
            continue;
        }
        if journal.mapping_by_bw(&it.id)?.is_some() {
            continue;
        }
        if it.item_type != 1 {
            actions.push(Action::Quarantine(QuarantineCase {
                kind: "unsupported_bw_type",
                kp_uuid: None,
                bw_id: Some(it.id.clone()),
                title: it.name.clone(),
                detail: format!(
                    "Bitwarden item is type {} (not a login); refusing to adopt into a login-shaped KeePass entry. Item left untouched",
                    it.item_type
                ),
            }));
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

/// Execute the plan.
///
/// Bitwarden-side writes happen immediately; KeePass mutations are applied
/// to the in-memory database (the caller saves atomically afterwards).
/// Journal mutations are NOT performed here — they are returned as
/// [`JournalOp`]s for the caller to commit via [`Journal::apply_ops`] only
/// after `save_vault()` succeeds, so a mid-apply bail can never leave the
/// journal claiming KeePass mutations that never reached disk.
/// Journal op for the plan/apply race: the Bitwarden item changed
/// between plan and apply, so the action (`what`: "update" / "trash") is
/// skipped and the case queues for review — instead of aborting the run
/// and discarding every other action's journal commit.
fn revision_changed_op(kp_uuid: Uuid, bw_id: &str, title: String, what: &str) -> JournalOp {
    JournalOp::from(&QuarantineCase {
        kind: "bw_revision_changed",
        kp_uuid: Some(kp_uuid),
        bw_id: Some(bw_id.to_string()),
        title,
        detail: format!(
            "Bitwarden item changed between plan and apply; {what} skipped pending review"
        ),
    })
}

pub fn apply(
    plan: &Plan,
    kp_entries: &[CanonicalEntry],
    bw_items: &[BwItem],
    bw: &BwClient,
    vault: &mut KdbxVault,
    folders: &[BwFolder],
) -> Result<(ApplyReport, Vec<JournalOp>)> {
    let mut folder_cache: HashMap<String, String> = folders
        .iter()
        .map(|f| (f.name.clone(), f.id.clone()))
        .collect();
    let mut report = ApplyReport::default();
    let mut journal_ops: Vec<JournalOp> = Vec::new();

    // Flat placement model: only the TOP-LEVEL group name maps to a
    // Bitwarden folder ("" = root = no folder). Nested groups share their
    // top-level ancestor's folder.
    let mut folder_for = |group_path: &str, bw: &BwClient| -> Result<Option<String>> {
        let name = top_group(group_path);
        if name.is_empty() {
            return Ok(None);
        }
        if let Some(id) = folder_cache.get(name) {
            return Ok(Some(id.clone()));
        }
        let id = bw.create_folder(name)?;
        folder_cache.insert(name.to_string(), id.clone());
        Ok(Some(id))
    };

    for a in &plan.actions {
        match a {
            Action::CreateBw { entry_idx } => {
                let e = &kp_entries[*entry_idx];
                let fid = folder_for(&e.group_path, bw)?;
                let bw_id = bw.create_item(e, fid.as_deref())?;
                journal_ops.push(JournalOp::UpsertMapping {
                    kp_uuid: e.uuid,
                    bw_id,
                    hash: e.content_hash_hex(),
                });
                report.created += 1;
            }
            Action::UpdateBw { bw_id, entry_idx, expected_revision } => {
                let e = &kp_entries[*entry_idx];
                let fid = folder_for(&e.group_path, bw)?;
                match bw
                    .edit_item(bw_id, e, fid.as_deref(), expected_revision)
                    .with_context(|| format!("update bw item {}", bw_id))?
                {
                    EditOutcome::Updated => {
                        journal_ops.push(JournalOp::UpsertMapping {
                            kp_uuid: e.uuid,
                            bw_id: bw_id.clone(),
                            hash: e.content_hash_hex(),
                        });
                        report.updated += 1;
                    }
                    EditOutcome::RevisionChanged => {
                        journal_ops.push(revision_changed_op(
                            e.uuid,
                            bw_id,
                            e.title.clone(),
                            "update",
                        ));
                        report.quarantined += 1;
                    }
                }
            }
            Action::TrashBw { bw_id, kp_uuid, expected_revision } => {
                match bw
                    .trash_item(bw_id, Some(expected_revision))
                    .with_context(|| format!("trash bw item {}", bw_id))?
                {
                    TrashOutcome::Trashed => {
                        // Tombstone first, mapping delete second: the ordering
                        // that blocks delete/recreate resurrection loops.
                        journal_ops.push(JournalOp::RecordTombstone {
                            kp_uuid: *kp_uuid,
                            bw_id: Some(bw_id.clone()),
                            side: "keepass",
                        });
                        journal_ops.push(JournalOp::DeleteMappingByKp { kp_uuid: *kp_uuid });
                        report.trashed += 1;
                    }
                    TrashOutcome::RevisionChanged => {
                        let title = kp_entries
                            .iter()
                            .find(|e| e.uuid == *kp_uuid)
                            .map(|e| e.title.clone())
                            .unwrap_or_else(|| bw_id.clone());
                        journal_ops.push(revision_changed_op(*kp_uuid, bw_id, title, "trash"));
                        report.quarantined += 1;
                    }
                }
            }
            Action::RecycleKp { kp_uuid, bw_id } => {
                eprintln!(
                    "warning: Bitwarden item {bw_id} missing from listing; moving KeePass entry to recycle bin (recoverable)"
                );
                if recycle_entry(&mut vault.db, *kp_uuid) {
                    journal_ops.push(JournalOp::RecordTombstone {
                        kp_uuid: *kp_uuid,
                        bw_id: Some(bw_id.clone()),
                        side: "bitwarden",
                    });
                    journal_ops.push(JournalOp::DeleteMappingByKp { kp_uuid: *kp_uuid });
                    report.kp_recycled += 1;
                }
            }
            Action::AdoptBwNew { item_idx } => {
                let it = &bw_items[*item_idx];
                // Placement: the KeePass entry lands in the group named
                // by the item's Bitwarden folder (flat model).
                let folder_name = it
                    .folder_id
                    .as_deref()
                    .and_then(|id| folders.iter().find(|f| f.id == id))
                    .map(|f| f.name.as_str());
                let uuid = adopt_bw_entry(&mut vault.db, it, folder_name)?;
                let hash = it.content_hash_hex();
                // Write the identity stamp back so the hybrid identity
                // holds in both directions on future runs.
                bw.stamp_item(&it.id, &uuid, &hash)
                    .with_context(|| format!("stamp adopted item {}", it.id))?;
                journal_ops.push(JournalOp::UpsertMapping {
                    kp_uuid: uuid,
                    bw_id: it.id.clone(),
                    hash,
                });
                report.kp_adopted += 1;
            }
            Action::WritebackEdit { bw_id, kp_uuid, item_idx } => {
                let it = &bw_items[*item_idx];
                if writeback_entry(&mut vault.db, *kp_uuid, it) {
                    journal_ops.push(JournalOp::UpsertMapping {
                        kp_uuid: *kp_uuid,
                        bw_id: bw_id.clone(),
                        hash: it.content_hash_hex(),
                    });
                    report.writeback_applied += 1;
                }
            }
            Action::Quarantine(q) => {
                journal_ops.push(JournalOp::from(q));
                report.quarantined += 1;
            }
        }
    }
    Ok((report, journal_ops))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bw::{BwClient, BwLogin};
    use crate::journal::test_journal;
    use crate::canonical::CanonicalEntry;
    use crate::secret::Secret;

    fn entry(uuid: &str) -> CanonicalEntry {
        CanonicalEntry {
            uuid: uuid.parse().unwrap(),
            title: "t".into(),
            username: "u".into(),
            password: Secret::from_str("p"),
            url: "".into(),
            uris: vec![],
            notes: "".into(),
            totp: None,
            custom: vec![],
            group_path: "".into(),
            deleted: false,
        }
    }

    fn bw_item(id: &str, kp_uuid: Option<&str>, rev: &str) -> BwItem {
        let mut fields = vec![];
        if let Some(u) = kp_uuid {
            fields.push(crate::bw::BwField {
                name: crate::stamps::SYNC_ID_FIELD.into(),
                value: u.into(),
                field_type: 0,
            });
            fields.push(crate::bw::BwField {
                name: crate::stamps::SYNC_HASH_FIELD.into(),
                value: "oldhash".into(),
                field_type: 0,
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
            item_type: 1,
            reprompt: None,
        }
    }

    #[test]
    fn new_kp_entry_plans_create() {
        let j = test_journal();
        let kp = vec![entry("11111111-1111-1111-1111-111111111111")];
        let p = plan(&kp, &HashSet::new(), &[], &[], &j, &SyncOpts::default()).unwrap();
        assert_eq!(p.actions.len(), 1);
        assert!(matches!(p.actions[0], Action::CreateBw { .. }));
    }

    #[test]
    fn unchanged_pair_plans_nothing() {
        let j = test_journal();
        let kp = vec![entry("11111111-1111-1111-1111-111111111111")];
        let h = kp[0].content_hash_hex();
        j.upsert_mapping(&kp[0].uuid, "bw-1", &h).unwrap();
        let mut bi = bw_item("bw-1", Some("11111111-1111-1111-1111-111111111111"), "r1");
        // make the BW content hash match: stamp hash must equal live hash
        bi.fields.iter_mut().find(|f| f.name == crate::stamps::SYNC_HASH_FIELD).unwrap().value = bi.content_hash_hex();
        j.upsert_mapping(&kp[0].uuid, "bw-1", &bi.content_hash_hex()).unwrap();
        let p = plan(&kp, &HashSet::new(), &[bi], &[], &j, &SyncOpts::default()).unwrap();
        assert!(p.actions.is_empty(), "expected no actions, got {:?}", p.actions.len());
    }

    #[test]
    fn kp_change_plans_update() {
        let j = test_journal();
        let mut kp = vec![entry("11111111-1111-1111-1111-111111111111")];
        let bi = bw_item("bw-1", Some("11111111-1111-1111-1111-111111111111"), "r1");
        j.upsert_mapping(&kp[0].uuid, "bw-1", &bi.content_hash_hex())
            .unwrap();
        kp[0].title = "changed".into();
        let p = plan(&kp, &HashSet::new(), &[bi], &[], &j, &SyncOpts::default()).unwrap();
        assert_eq!(p.actions.len(), 1);
        assert!(matches!(p.actions[0], Action::UpdateBw { .. }));
    }

    #[test]
    fn foreign_bw_edit_quarantines_by_default() {
        let j = test_journal();
        let kp = vec![entry("11111111-1111-1111-1111-111111111111")];
        let h = kp[0].content_hash_hex();
        j.upsert_mapping(&kp[0].uuid, "bw-1", &h).unwrap();
        let mut bi = bw_item("bw-1", Some("11111111-1111-1111-1111-111111111111"), "r2");
        bi.name = "someone edited me".into(); // foreign edit
        let p = plan(&kp, &HashSet::new(), &[bi], &[], &j, &SyncOpts::default()).unwrap();
        assert!(matches!(p.actions[0], Action::Quarantine(_)));
    }

    #[test]
    fn force_overwrites_foreign_bw_edit() {
        let j = test_journal();
        let kp = vec![entry("11111111-1111-1111-1111-111111111111")];
        let h = kp[0].content_hash_hex();
        j.upsert_mapping(&kp[0].uuid, "bw-1", &h).unwrap();
        let mut bi = bw_item("bw-1", Some("11111111-1111-1111-1111-111111111111"), "r2");
        bi.name = "someone edited me".into();
        let opts = SyncOpts { force: true, ..Default::default() };
        let p = plan(&kp, &HashSet::new(), &[bi], &[], &j, &opts).unwrap();
        assert!(matches!(p.actions[0], Action::UpdateBw { .. }));
    }

    #[test]
    fn bw_trash_with_unchanged_kp_recycles() {
        let j = test_journal();
        let kp = vec![entry("11111111-1111-1111-1111-111111111111")];
        let h = kp[0].content_hash_hex();
        j.upsert_mapping(&kp[0].uuid, "bw-1", &h).unwrap();
        let mut bi = bw_item("bw-1", Some("11111111-1111-1111-1111-111111111111"), "r2");
        bi.deleted_date = Some("2026-10-03T00:00:00Z".into());
        let p = plan(&kp, &HashSet::new(), &[bi], &[], &j, &SyncOpts::default()).unwrap();
        assert!(matches!(p.actions[0], Action::RecycleKp { .. }));
    }

    #[test]
    fn permanently_deleted_bw_item_is_not_resurrected() {
        let j = test_journal();
        let kp = vec![entry("11111111-1111-1111-1111-111111111111")];
        j.upsert_mapping(&kp[0].uuid, "bw-1", "h").unwrap();
        j.record_tombstone(&kp[0].uuid, Some("bw-1"), "bitwarden").unwrap();
        // BW item gone entirely; tombstone exists -> no action (no resurrect)
        let p = plan(&kp, &HashSet::new(), &[], &[], &j, &SyncOpts::default()).unwrap();
        assert!(p.actions.is_empty());
    }

    #[test]
    fn empty_bw_list_with_live_mappings_bails() {
        // Regression (2026-10-03): a transient empty listing once recycled a
        // whole test database. Fail closed instead of treating it as a
        // mass Bitwarden delete.
        let j = test_journal();
        let kp = vec![entry("11111111-1111-1111-1111-111111111111")];
        let h = kp[0].content_hash_hex();
        j.upsert_mapping(&kp[0].uuid, "bw-1", &h).unwrap();
        let r = plan(&kp, &HashSet::new(), &[], &[], &j, &SyncOpts::default());
        assert!(r.is_err(), "expected plan to bail on empty listing with live mappings");
    }

    fn mapped_pair(j: &Journal, i: u8) -> (CanonicalEntry, BwItem) {
        let e = entry(&format!("11111111-1111-1111-1111-11111111111{i}"));
        let id = format!("bw-{i}");
        let bi = bw_item(&id, Some(&format!("11111111-1111-1111-1111-11111111111{i}")), "r1");
        // entry() and bw_item() agree on content, so both sides hash equal.
        let h = bi.content_hash_hex();
        assert_eq!(e.content_hash_hex(), h);
        j.upsert_mapping(&e.uuid, &id, &h).unwrap();
        (e, bi)
    }

    #[test]
    fn partial_listing_missing_majority_bails() {
        // Only a fully-empty listing used to trip the fail-closed guard; a
        // truncated listing walked into mass RecycleKp. Bail when more than
        // half of the live-mapped items are missing from the listing.
        let j = test_journal();
        let mut kp = vec![];
        let mut items = vec![];
        for i in 1..=4u8 {
            let (e, bi) = mapped_pair(&j, i);
            kp.push(e);
            items.push(bi);
        }
        let listed = vec![items[0].clone()]; // 3/4 missing > 1/2
        let r = plan(&kp, &HashSet::new(), &listed, &[], &j, &SyncOpts::default());
        assert!(r.is_err(), "expected bail on partial listing missing the majority");
    }

    #[test]
    fn partial_listing_missing_minority_records_first_then_recycles() {
        // 1 of 4 missing is no longer recycled on first sighting: a single
        // absence may be a transient listing glitch. The first partial
        // listing records the absence (no action); a second, independent
        // partial listing confirms it and plans the one recycle.
        let j = test_journal();
        let mut kp = vec![];
        let mut items = vec![];
        for i in 1..=4u8 {
            let (e, bi) = mapped_pair(&j, i);
            kp.push(e);
            items.push(bi);
        }
        let listed: Vec<BwItem> = items[..3].to_vec();
        let p = plan(&kp, &HashSet::new(), &listed, &[], &j, &SyncOpts::default()).unwrap();
        assert!(p.actions.is_empty(), "first sighting must not recycle");
        assert!(j.was_missing("bw-4").unwrap());
        let p = plan(&kp, &HashSet::new(), &listed, &[], &j, &SyncOpts::default()).unwrap();
        assert_eq!(p.actions.len(), 1);
        assert!(matches!(p.actions[0], Action::RecycleKp { .. }));
    }

    #[test]
    fn partial_listing_missing_with_kp_edit_quarantines() {
        // Mirror of the trashed arm's delete-vs-edit: a KeePass edit
        // since the watermark plus a second confirmed absence must
        // quarantine, not recycle — the edit is live data, and a
        // listing absence alone is not proof of a delete.
        let j = test_journal();
        let mut kp = vec![];
        let mut items = vec![];
        for i in 1..=4u8 {
            let (e, bi) = mapped_pair(&j, i);
            kp.push(e);
            items.push(bi);
        }
        let listed: Vec<BwItem> = items[..3].to_vec();
        let p = plan(&kp, &HashSet::new(), &listed, &[], &j, &SyncOpts::default()).unwrap();
        assert!(p.actions.is_empty(), "first sighting must not recycle");
        assert!(j.was_missing("bw-4").unwrap());
        kp[3].title = "edited locally".into();
        let p = plan(&kp, &HashSet::new(), &listed, &[], &j, &SyncOpts::default()).unwrap();
        assert_eq!(p.actions.len(), 1);
        assert!(
            matches!(&p.actions[0], Action::Quarantine(q) if q.kind == "delete-vs-edit"),
            "expected delete-vs-edit quarantine, got {:?}", p.actions[0]
        );
        assert!(
            !j.was_missing("bw-4").unwrap(),
            "missing record must clear so the case does not churn"
        );
    }

    #[test]
    fn partial_listing_then_full_listing_recycles_nothing() {
        // Regression (2026-11-01 review): a transient partial listing used
        // to recycle the missing entry, and the reappearing item then
        // trashed its Bitwarden copy too — a live entry deleted on both
        // sides by a glitch. Now the glitch run records only, and the
        // full listing clears the record: no RecycleKp, no TrashBw,
        // entry intact on both sides.
        let j = test_journal();
        let mut kp = vec![];
        let mut items = vec![];
        for i in 1..=4u8 {
            let (e, bi) = mapped_pair(&j, i);
            kp.push(e);
            items.push(bi);
        }
        let partial: Vec<BwItem> = items[..3].to_vec();
        let p = plan(&kp, &HashSet::new(), &partial, &[], &j, &SyncOpts::default()).unwrap();
        assert!(p.actions.is_empty());
        assert!(j.was_missing("bw-4").unwrap());
        let p = plan(&kp, &HashSet::new(), &items, &[], &j, &SyncOpts::default()).unwrap();
        assert!(
            p.actions.is_empty(),
            "reappearance must clear the glitch, got {:?}",
            p.actions.len()
        );
        assert!(!j.was_missing("bw-4").unwrap());
    }

    #[test]
    fn trash_plan_carries_expected_revision() {
        let j = test_journal();
        let mut kp = vec![entry("11111111-1111-1111-1111-111111111111")];
        kp[0].deleted = true; // in the KeePass recycle bin
        let bi = bw_item("bw-1", Some("11111111-1111-1111-1111-111111111111"), "r42");
        let h = bi.content_hash_hex();
        j.upsert_mapping(&kp[0].uuid, "bw-1", &h).unwrap();
        let p = plan(&kp, &HashSet::new(), &[bi], &[], &j, &SyncOpts::default()).unwrap();
        assert!(
            matches!(&p.actions[0], Action::TrashBw { expected_revision, .. } if expected_revision == "r42"),
            "TrashBw must carry the plan-time revision for the apply-time guard"
        );
    }

    #[test]
    fn apply_error_leaves_journal_untouched() {
        // Regression: journal writes used to happen inside apply(), so a
        // mid-apply bail (e.g. a 503 on a later action) left the journal
        // claiming KeePass mutations that never reached disk. Ops are now
        // collected and only committed via Journal::apply_ops.
        let j = test_journal();
        let kp = vec![entry("11111111-1111-1111-1111-111111111111")];
        let p = Plan {
            actions: vec![
                Action::Quarantine(QuarantineCase {
                    kind: "test-kind",
                    kp_uuid: Some(kp[0].uuid),
                    bw_id: None,
                    title: "t".into(),
                    detail: "d".into(),
                }),
                // Dead URL (connection refused): this action fails.
                Action::CreateBw { entry_idx: 0 },
            ],
        };
        let bw = BwClient::new("http://127.0.0.1:1").unwrap();
        let mut vault = crate::kdbx::test_vault();
        let r = apply(&p, &kp, &[], &bw, &mut vault, &[]);
        assert!(r.is_err(), "expected apply to fail on the dead URL");
        assert!(
            j.list_quarantine().unwrap().is_empty(),
            "journal must be untouched when apply bails partway"
        );
        assert_eq!(j.live_mapping_count().unwrap(), 0);
    }

    #[test]
    fn journal_ops_commit_only_via_apply_ops() {
        let j = test_journal();
        let kp = vec![entry("11111111-1111-1111-1111-111111111111")];
        let p = Plan {
            actions: vec![Action::Quarantine(QuarantineCase {
                kind: "test-kind",
                kp_uuid: Some(kp[0].uuid),
                bw_id: None,
                title: "t".into(),
                detail: "d".into(),
            })],
        };
        let bw = BwClient::new("http://127.0.0.1:1").unwrap();
        let mut vault = crate::kdbx::test_vault();
        let (report, ops) = apply(&p, &kp, &[], &bw, &mut vault, &[]).unwrap();
        assert_eq!(report.quarantined, 1);
        assert_eq!(ops.len(), 1);
        assert!(
            j.list_quarantine().unwrap().is_empty(),
            "apply itself must not commit journal ops"
        );
        j.apply_ops(&ops).unwrap();
        assert_eq!(j.list_quarantine().unwrap().len(), 1);
    }

    #[test]
    fn adopt_quarantines_non_login_types() {
        // A secure note must never be reshaped into a login-shaped KeePass
        // entry: it quarantines for human review, item untouched.
        let j = test_journal();
        let mut note = bw_item("bw-9", None, "r1");
        note.item_type = 2; // secure note
        let opts = SyncOpts {
            adopt: true,
            ..Default::default()
        };
        let p = plan(&[], &HashSet::new(), &[note], &[], &j, &opts).unwrap();
        assert_eq!(p.actions.len(), 1);
        assert!(matches!(&p.actions[0], Action::Quarantine(q) if q.kind == "unsupported_bw_type"));
    }

    #[test]
    fn orphan_bw_stamp_quarantines_instead_of_mapping_phantom() {
        // Stamped, unmapped, but the KeePass entry does not exist (interrupted
        // adopt): upserting a mapping would mint a phantom identity, so the
        // item quarantines for human re-adopt instead.
        let j = test_journal();
        let orphan = bw_item("bw-9", Some("22222222-2222-2222-2222-222222222222"), "r1");
        let p = plan(&[], &HashSet::new(), &[orphan], &[], &j, &SyncOpts::default()).unwrap();
        assert_eq!(p.actions.len(), 1);
        assert!(matches!(&p.actions[0], Action::Quarantine(q) if q.kind == "orphan_bw_stamp"));
        assert_eq!(
            j.live_mapping_count().unwrap(),
            0,
            "no phantom mapping may be rebuilt"
        );
    }

    #[test]
    fn stamped_item_with_kp_entry_rebuilds_mapping() {
        // Positive control for the orphan gate: when the stamped UUID matches
        // a real KeePass entry, the mapping is rebuilt and the in-sync pair
        // is a no-op.
        let j = test_journal();
        let kp = vec![entry("11111111-1111-1111-1111-111111111111")];
        let bi = bw_item("bw-9", Some("11111111-1111-1111-1111-111111111111"), "r1");
        let p = plan(&kp, &HashSet::new(), &[bi], &[], &j, &SyncOpts::default()).unwrap();
        assert!(
            p.actions.is_empty(),
            "rebuilt in-sync pair must be a no-op, got {} actions",
            p.actions.len()
        );
        assert_eq!(
            j.mapping_by_kp(&kp[0].uuid)
                .unwrap()
                .map(|(id, _hash)| id)
                .as_deref(),
            Some("bw-9")
        );
    }

    #[test]
    fn apply_quarantines_on_revision_change_inside_apply() {
        // TrashBw's revision guard lives inside apply(): the plan saw r1 but
        // the re-read at apply time sees r2 — the item changed under us, so
        // the trash is skipped and the case quarantines for human review.
        let revved = crate::bw::tests::item_json("r2");
        let base = crate::bw::tests::stub_server(vec![(
            "GET /object/item/bw-1 ".into(),
            200,
            revved,
        )]);
        let bw = BwClient::new(&base).unwrap();
        let p = Plan {
            actions: vec![Action::TrashBw {
                bw_id: "bw-1".into(),
                kp_uuid: uuid::Uuid::nil(),
                expected_revision: "r1".into(),
            }],
        };
        let mut vault = crate::kdbx::test_vault();
        let (report, ops) = apply(&p, &[], &[], &bw, &mut vault, &[]).unwrap();
        assert_eq!(report.quarantined, 1);
        assert_eq!(report.trashed, 0);
        assert_eq!(ops.len(), 1);
        assert!(matches!(
            &ops[0],
            crate::journal::JournalOp::Quarantine { kind, .. } if *kind == "bw_revision_changed"
        ));
    }

    #[test]
    fn writeback_marks_custom_fields_protected() {
        // Foreign content applied into KeePass must land in protected
        // custom fields, never plaintext.
        use keepass::db::{fields, Value};
        let mut db = keepass::Database::new();
        let mut root = db.root_mut();
        let mut e = root.add_entry();
        let mut bi = bw_item("bw-1", None, "r1");
        bi.fields = vec![crate::bw::BwField {
            name: "API key".into(),
            value: "abc".into(),
            field_type: 1, // hidden -> protected in KeePass
        }];
        bi.login.as_mut().unwrap().totp = Some("totpseed".into());
        crate::kdbx::apply_bw_to_entry(&mut e, &bi);
        let custom: Vec<(&String, &Value<String>)> = e
            .fields
            .iter()
            .filter(|(name, _)| {
                ![
                    fields::TITLE,
                    fields::USERNAME,
                    fields::PASSWORD,
                    fields::URL,
                    fields::NOTES,
                ]
                .contains(&name.as_str())
            })
            .collect();
        assert!(!custom.is_empty(), "writeback must copy custom fields");
        assert!(
            custom.iter().all(|(_, v)| v.is_protected()),
            "writeback custom fields must be protected"
        );
        assert!(custom.iter().any(|(name, _)| *name == "API key"));
        assert!(custom.iter().any(|(name, _)| *name == "totp"));
    }

    #[test]
    fn post_crash_replan_refreshes_watermark_without_quarantine() {
        // H1 regression: the engine wrote the new content to Bitwarden,
        // then crashed before the deferred journal commit. Both sides now
        // hold identical NEW content; only the watermark is behind. The
        // old planner read this as (changed, changed) and quarantined two
        // agreeing copies — permanently, since the resolution flags were
        // ignored for that arm.
        let j = test_journal();
        let kp = vec![entry("11111111-1111-1111-1111-111111111111")];
        let bi = bw_item("bw-1", Some("11111111-1111-1111-1111-111111111111"), "r2");
        j.upsert_mapping(&kp[0].uuid, "bw-1", "pre-crash-watermark")
            .unwrap();
        let p = plan(&kp, &HashSet::new(), &[bi], &[], &j, &SyncOpts::default()).unwrap();
        assert!(
            p.actions.is_empty(),
            "agreeing copies must not quarantine, got {} actions",
            p.actions.len()
        );
        let (_, watermark) = j.mapping_by_kp(&kp[0].uuid).unwrap().unwrap();
        assert_eq!(watermark, kp[0].content_hash_hex());
    }

    #[test]
    fn concurrent_edit_honors_force_and_writeback() {
        // Genuine divergence (both sides changed to different content):
        // quarantine by default, but the resolution flags apply.
        let setup = |j: &Journal| -> (Vec<CanonicalEntry>, BwItem) {
            let mut kp = vec![entry("11111111-1111-1111-1111-111111111111")];
            let mut bi = bw_item("bw-1", Some("11111111-1111-1111-1111-111111111111"), "r2");
            // Watermark: the original shared content (the plain pair).
            let w = bi.content_hash_hex();
            j.upsert_mapping(&kp[0].uuid, "bw-1", &w).unwrap();
            kp[0].title = "kp-side edit".into();
            bi.name = "bw-side edit".into();
            (kp, bi)
        };

        let j = test_journal();
        let (kp, bi) = setup(&j);
        let p = plan(&kp, &HashSet::new(), &[bi], &[], &j, &SyncOpts::default()).unwrap();
        assert!(matches!(&p.actions[0], Action::Quarantine(q) if q.kind == "concurrent-edit"));

        let j = test_journal();
        let (kp, bi) = setup(&j);
        let opts = SyncOpts { force: true, ..Default::default() };
        let p = plan(&kp, &HashSet::new(), &[bi], &[], &j, &opts).unwrap();
        assert!(matches!(p.actions[0], Action::UpdateBw { .. }));

        let j = test_journal();
        let (kp, bi) = setup(&j);
        let opts = SyncOpts { writeback: true, ..Default::default() };
        let p = plan(&kp, &HashSet::new(), &[bi], &[], &j, &opts).unwrap();
        assert!(matches!(p.actions[0], Action::WritebackEdit { .. }));
    }

    #[test]
    fn rebuild_with_matching_stamp_is_quiet() {
        // M1, match branch: the stamp hash equals the item's live hash —
        // the rebuild adopts the stamped baseline and the pair is a no-op.
        let j = test_journal();
        let kp = vec![entry("11111111-1111-1111-1111-111111111111")];
        let mut bi = bw_item("bw-1", Some("11111111-1111-1111-1111-111111111111"), "r1");
        let live = bi.content_hash_hex();
        bi.fields
            .iter_mut()
            .find(|f| f.name == crate::stamps::SYNC_HASH_FIELD)
            .unwrap()
            .value = live.clone();
        let p = plan(&kp, &HashSet::new(), &[bi], &[], &j, &SyncOpts::default()).unwrap();
        assert!(p.actions.is_empty(), "got {} actions", p.actions.len());
        let (_, watermark) = j.mapping_by_kp(&kp[0].uuid).unwrap().unwrap();
        assert_eq!(watermark, live);
    }

    #[test]
    fn rebuild_with_stale_stamp_quarantines_foreign_edit() {
        // M1, mismatch branch: the journal is gone (reset) but the stamp
        // survives. Since the engine last wrote, someone edited the
        // Bitwarden item. The rebuild must NOT adopt the live state as
        // the baseline: the pair classifies as a foreign edit, and the
        // watermark is the stamped (pre-edit) hash.
        let j = test_journal();
        let kp = vec![entry("11111111-1111-1111-1111-111111111111")]; // pre-edit content
        let stamped = kp[0].content_hash_hex();
        let mut bi = bw_item("bw-1", Some("11111111-1111-1111-1111-111111111111"), "r2");
        bi.fields
            .iter_mut()
            .find(|f| f.name == crate::stamps::SYNC_HASH_FIELD)
            .unwrap()
            .value = stamped.clone();
        bi.name = "edited outside the engine".into(); // the foreign edit
        let p = plan(&kp, &HashSet::new(), &[bi], &[], &j, &SyncOpts::default()).unwrap();
        assert_eq!(p.actions.len(), 1);
        assert!(
            matches!(&p.actions[0], Action::Quarantine(q) if q.kind == "foreign-bw-edit"),
            "expected foreign-bw-edit quarantine"
        );
        let (_, watermark) = j.mapping_by_kp(&kp[0].uuid).unwrap().unwrap();
        assert_eq!(watermark, stamped, "baseline must be the stamp, not live state");
    }

    #[test]
    fn group_move_plans_folder_update() {
        // M5: content is in sync, but the entry moved groups in KeePass —
        // plan a Bitwarden folder update (an UpdateBw with identical
        // content; only the payload's folderId changes).
        let j = test_journal();
        let mut kp = vec![entry("11111111-1111-1111-1111-111111111111")];
        kp[0].group_path = "Ops".into();
        let mut bi = bw_item("bw-1", Some("11111111-1111-1111-1111-111111111111"), "r1");
        bi.folder_id = Some("f-misc".into());
        let h = bi.content_hash_hex();
        j.upsert_mapping(&kp[0].uuid, "bw-1", &h).unwrap();
        let folders = vec![crate::bw::BwFolder {
            id: "f-misc".into(),
            name: "Misc".into(),
        }];
        let p = plan(&kp, &HashSet::new(), &[bi], &folders, &j, &SyncOpts::default()).unwrap();
        assert_eq!(p.actions.len(), 1);
        assert!(matches!(p.actions[0], Action::UpdateBw { .. }));

        // Same folder name: no action.
        let j = test_journal();
        let mut bi = bw_item("bw-1", Some("11111111-1111-1111-1111-111111111111"), "r1");
        bi.folder_id = Some("f-ops".into());
        let h = bi.content_hash_hex();
        j.upsert_mapping(&kp[0].uuid, "bw-1", &h).unwrap();
        let folders = vec![crate::bw::BwFolder {
            id: "f-ops".into(),
            name: "Ops".into(),
        }];
        let p = plan(&kp, &HashSet::new(), &[bi], &folders, &j, &SyncOpts::default()).unwrap();
        assert!(p.actions.is_empty(), "got {} actions", p.actions.len());

        // Nested KeePass group: the TOP-LEVEL name is the folder.
        let j = test_journal();
        let mut kp = vec![entry("11111111-1111-1111-1111-111111111111")];
        kp[0].group_path = "Ops/Servers".into();
        let mut bi = bw_item("bw-1", Some("11111111-1111-1111-1111-111111111111"), "r1");
        bi.folder_id = Some("f-ops".into());
        let h = bi.content_hash_hex();
        j.upsert_mapping(&kp[0].uuid, "bw-1", &h).unwrap();
        let folders = vec![crate::bw::BwFolder {
            id: "f-ops".into(),
            name: "Ops".into(),
        }];
        let p = plan(&kp, &HashSet::new(), &[bi], &folders, &j, &SyncOpts::default()).unwrap();
        assert!(p.actions.is_empty(), "nested group must map to its top-level folder");
    }

    #[test]
    fn tombstone_cleanup_completes_when_bw_already_trashed() {
        // L8: a prior run trashed the Bitwarden item but crashed before
        // the journal commit. The tombstone bookkeeping must still
        // complete: tombstone recorded, mapping removed, no action.
        let j = test_journal();
        let u: Uuid = "11111111-1111-1111-1111-111111111111".parse().unwrap();
        j.upsert_mapping(&u, "bw-1", "h").unwrap();
        let mut bi = bw_item("bw-1", Some("11111111-1111-1111-1111-111111111111"), "r2");
        bi.deleted_date = Some("2026-10-03T00:00:00Z".into());
        let tombs: HashSet<Uuid> = [u].into_iter().collect();
        let p = plan(&[], &tombs, &[bi], &[], &j, &SyncOpts::default()).unwrap();
        assert!(p.actions.is_empty(), "got {} actions", p.actions.len());
        assert!(j.tombstoned(&u).unwrap());
        assert!(j.mapping_by_kp(&u).unwrap().is_none());
    }

    #[test]
    fn apply_quarantines_update_on_revision_change_inside_apply() {
        // L1: the UpdateBw revision guard lives inside apply (via
        // edit_item's outcome): plan saw r1, the apply-time re-read sees
        // r2 — skip just this edit and quarantine, don't abort the run.
        let revved = crate::bw::tests::item_json("r2");
        let base = crate::bw::tests::stub_server(vec![(
            "GET /object/item/bw-1 ".into(),
            200,
            revved,
        )]);
        let bw = BwClient::new(&base).unwrap();
        let kp = vec![entry("11111111-1111-1111-1111-111111111111")];
        let p = Plan {
            actions: vec![Action::UpdateBw {
                bw_id: "bw-1".into(),
                entry_idx: 0,
                expected_revision: "r1".into(),
            }],
        };
        let mut vault = crate::kdbx::test_vault();
        let (report, ops) = apply(&p, &kp, &[], &bw, &mut vault, &[]).unwrap();
        assert_eq!(report.updated, 0);
        assert_eq!(report.quarantined, 1);
        assert_eq!(ops.len(), 1);
        assert!(matches!(
            &ops[0],
            crate::journal::JournalOp::Quarantine { kind, .. } if *kind == "bw_revision_changed"
        ));
    }

    #[test]
    fn apply_adopt_places_entry_in_folder_group() {
        // M5 adopt: the item sits in Bitwarden folder "Ops", so the
        // adopted KeePass entry lands in a top-level "Ops" group.
        let item = serde_json::json!({
            "success": true,
            "data": {
                "id": "bw-1", "name": "adopted", "notes": null, "favorite": false,
                "folderId": "f-ops", "type": 1, "reprompt": 0,
                "login": {"username": "u", "password": "p", "totp": null,
                          "uris": [{"uri": "https://x.example.com", "match": null}]},
                "fields": [],
                "revisionDate": "r1", "deletedDate": null
            }
        })
        .to_string();
        let base = crate::bw::tests::stub_server(vec![
            ("GET /object/item/bw-1 ".into(), 200, item),
            (
                "PUT /object/item/bw-1 ".into(),
                200,
                r#"{"success":true}"#.into(),
            ),
        ]);
        let bw = BwClient::new(&base).unwrap();
        let mut bi = bw_item("bw-1", None, "r1");
        bi.name = "adopted".into();
        bi.folder_id = Some("f-ops".into());
        bi.login = Some(crate::bw::BwLogin {
            username: Some("u".into()),
            password: Some("p".into()),
            totp: None,
            uris: Some(vec![crate::bw::BwUri {
                uri: Some("https://x.example.com".into()),
                match_: None,
            }]),
        });
        let folders = vec![crate::bw::BwFolder {
            id: "f-ops".into(),
            name: "Ops".into(),
        }];
        let p = Plan {
            actions: vec![Action::AdoptBwNew { item_idx: 0 }],
        };
        let mut vault = crate::kdbx::test_vault();
        let (report, _ops) = apply(&p, &[], &[bi], &bw, &mut vault, &folders).unwrap();
        assert_eq!(report.kp_adopted, 1);
        let entries = crate::kdbx::extract_entries(&vault.db);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].group_path, "Ops");
    }
}
