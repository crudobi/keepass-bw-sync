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
//!
//! Naming notes (two lookalike pairs that have confused reviewers):
//! - `adopt_bw_entry` (kdbx.rs) *creates* a new KeePass entry from a
//!   Bitwarden item; `apply_bw_to_entry` *overwrites* an existing entry's
//!   fields in place (the writeback path, which snapshots history first).
//! - `BwClient::sync()` (bw.rs) is just the `POST /sync` cache refresh
//!   against `bw serve`; the sync *engine* is this module (`plan`/`apply`).
//!   Calling one does not run the other.

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
    /// `from_absence` is true only for the missing-confirmation arm (the
    /// item was absent from two independent listings, not seen trashed):
    /// the apply arm records that reason in the tombstone side
    /// (`"bitwarden-absence"`), so the deleted branch can tell an
    /// absence-recycle whose item reappeared from a genuine user bin.
    /// A trashed-arm recycle records side `"bitwarden-trash"` (legacy
    /// spelling `"bitwarden"`) for the same reason: an item the user
    /// untrashes unchanged must quarantine, never re-trash.
    RecycleKp { kp_uuid: Uuid, bw_id: String, from_absence: bool },
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

/// Tombstone sides the engine itself records for recycles it initiated.
/// These are NON-completions, unlike a user bin: a binned entry whose
/// item reappeared must quarantine, never trash, and a permanently
/// deleted entry whose item is live must still propagate its delete.
/// `"bitwarden"` is the legacy spelling of `"bitwarden-trash"`,
/// recorded by trashed-arm recycles before the rename; readers treat
/// both identically. Completed propagations are `"keepass"` (user bin
/// trashed, or tombstone-arm completion) and `"both"` (both sides
/// deleted); only those skip the tombstone arm.
fn is_engine_recycle_side(side: Option<&str>) -> bool {
    matches!(
        side,
        Some("bitwarden-absence") | Some("bitwarden-trash") | Some("bitwarden")
    )
}

/// First custom-field name that appears twice on a Bitwarden item, if
/// any. KeePass fields are name-keyed, so a duplicated name would
/// silently drop the non-last value on writeback -- the plan gate
/// quarantines instead.
fn duplicate_field_name(it: &BwItem) -> Option<&str> {
    let mut seen: HashSet<&str> = HashSet::new();
    it.fields.iter().find_map(|f| {
        if seen.contains(f.name.as_str()) {
            Some(f.name.as_str())
        } else {
            seen.insert(f.name.as_str());
            None
        }
    })
}

/// Build the sync plan.
///
/// Not pure — and deliberately so (see the purity note below). `plan()`
/// performs these journal writes *immediately*, in this order:
/// - `clear_missing` for every item present in this listing (a reappearance
///   means the earlier absence was a glitch, so the two-listing clock
///   resets);
/// - mapping rebuild: stamped-but-unmapped Bitwarden items whose UUID
///   matches a KeePass entry, tombstone, or journal tombstone get their
///   mapping upserted (baseline = the `KBS_SYNC_HASH` stamp, falling back
///   to the live hash only for pre-stamp-hash items);
/// - watermark refresh: a pair whose two sides agree on new content gets
///   its mapping upserted to the common hash (post-crash agreement);
/// - `missing_bw` bookkeeping: a first sighting of a mapped item absent
///   from the listing is recorded (`note_missing`); a second, independent
///   listing confirming the absence clears the record (`clear_missing`)
///   and plans the recycle;
/// - absence-recycle reason: when the missing-confirmation arm plans a
///   recycle, the tombstone is recorded *at plan time* with side
///   `"bitwarden-absence"` (distinguishable from a user bin, side
///   `"keepass"`), so a crash between vault save and journal commit
///   cannot turn the reappeared item's next run into a `TrashBw`;
/// - trash-recycle reason: a trashed-arm recycle records side
///   `"bitwarden-trash"` at apply time (legacy `"bitwarden"`), so
///   an item the user untrashes unchanged quarantines as
///   `trash-recycle-reappeared` instead of being re-trashed; and the
///   tombstone arm skips only completed propagations (`"keepass"` /
///   `"both"`), so a permanently deleted entry with a live item
///   still propagates its delete even on an engine-recycle side;
/// - terminal bookkeeping: both-sides-deleted pairs and already-trashed
///   Bitwarden items complete immediately (`record_tombstone` +
///   `delete_mapping_by_kp`).
/// - quarantine reconciliation: open `unmapped-bw-item` rows for
///   live-mapped items are resolved (their premise is false once the
///   item is mapped). The only quarantine-table write plan makes, and
///   it only ever resolves -- plan never *creates* rows.
///
/// Purity note [WILL NOT IMPLEMENT, user decision 2026-11-01]: a
/// pure move — plan returns its journal writes as a delta for the caller
/// to apply — was stopped, not attempted halfway. Later reads inside
/// `plan()` observe its own earlier writes (the rebuild upsert feeds the
/// pair classification; `clear_missing`/`note_missing` drive the
/// two-listing clock; terminal tombstones feed the tombstone-loop skip),
/// so a delta without an in-plan overlay would change planned actions,
/// and the only semantics-preserving shape (caller applies the delta
/// immediately after plan) still needs that overlay plus new `JournalOp`
/// variants for the `missing_bw`/tombstone bookkeeping — a second source
/// of journal truth for zero behavior change. Deferring the delta to the
/// post-save commit instead would change crash semantics (a run that
/// bails mid-apply would lose first-sighting missing notes and
/// stamp-rebuild mappings). Behavior is therefore kept, and this
/// inventory is the contract.
///
/// All *per-action* journal mutations are still deferred — [`apply`]
/// returns them as [`JournalOp`]s and the caller commits them via
/// [`Journal::apply_ops`] only after the KeePass database is durably
/// saved, so the journal can never claim KeePass mutations that never
/// reached disk. Quarantine rows are per-action too: `plan()` only
/// returns `Quarantine` actions, it never creates quarantine rows itself
/// (the reconciliation above only resolves stale unmapped rows).
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

    // Folder-listing guard, the analogue of the items guard above: a
    // folder listing that came back empty while items reference folders
    // is a partial listing, not a folderless vault -- and `folder_for`
    // would then create duplicate same-named folders server-side on
    // apply. A genuinely folderless vault (empty folder list, no item
    // referencing a folder) syncs fine.
    let folder_refs = bw_items
        .iter()
        .filter(|it| it.folder_id.as_deref().is_some_and(|f| !f.is_empty()))
        .count();
    if folders.is_empty() && folder_refs > 0 {
        anyhow::bail!(
            "refusing to sync: Bitwarden listed 0 folders but {folder_refs} item(s) reference a folder (probable partial listing); no changes made"
        );
    }

    // Partial-folder-listing guard: the empty-list guard above covers
    // only total failure. A truncated non-empty listing still passes
    // it, and `folder_for` (apply) would then create duplicate
    // same-named folders for any placement decision made against the
    // truncated list. Bail when a non-blocked, non-trashed item
    // references a folder id absent from the listing AND its mapped
    // live pair would carry a folderId: an agreeing pair whose top
    // group differs from the (unknown) folder name plans a move, a
    // KeePass-only change plans an UpdateBw, and --force plans one for
    // any divergence. Adopt-path items (no mapping) use the root-group
    // fallback and create no folder, so they never trip; trashed items
    // recycle or quarantine without placement, so neither do they; and
    // root-group pairs resolve to no folder either way.
    {
        let known_folder_ids: HashSet<&str> = folders.iter().map(|f| f.id.as_str()).collect();
        for it in bw_items {
            // The gates loop below has not run yet (it must stay after
            // reconcile/clear_missing, so a refused sync changes
            // nothing), so the blocked check is mirrored inline here
            // instead of reading `blocked_bw`: org-owned, attached,
            // TOTP-source-named, or duplicate-named. Keep in sync with
            // the gates loop.
            let gate_blocked = it.org_owned()
                || it.has_attachments()
                || it
                    .fields
                    .iter()
                    .any(|f| crate::kdbx::is_totp_source_field(&f.name))
                || duplicate_field_name(it).is_some();
            if gate_blocked || it.trashed() {
                continue;
            }
            let Some(fid) = it.folder_id.as_deref().filter(|f| !f.is_empty()) else {
                continue;
            };
            if known_folder_ids.contains(fid) {
                continue;
            }
            let Some((kp_uuid, last_hash)) = journal.mapping_by_bw(&it.id)? else {
                continue;
            };
            let Some(&ei) = kp_by_uuid.get(&kp_uuid) else {
                continue;
            };
            let e = &kp_entries[ei];
            if e.deleted || top_group(&e.group_path).is_empty() {
                continue;
            }
            let h_kp = e.content_hash_hex();
            let h_bw = it.content_hash_hex();
            let kp_changed = h_kp != last_hash;
            let bw_changed = h_bw != last_hash;
            let needs_placement =
                (h_kp == h_bw) || (kp_changed && !bw_changed) || (opts.force && h_kp != h_bw);
            if needs_placement {
                anyhow::bail!(
                    "refusing to sync: Bitwarden folder listing is missing folder id {fid} referenced by item {:?}, and its pair needs a placement decision (probable partial listing); no changes made",
                    it.name
                );
            }
        }
    }

    // Reconcile stale unmapped rows: an open `unmapped-bw-item` row whose
    // item is now live-mapped states something false, so resolve it.
    // After the listing guard on purpose: a refused sync makes no changes.
    // Scoped to that kind only -- every other kind still needs human
    // review even when the item is mapped. This is plan-time bookkeeping
    // like `clear_missing` below, and it only ever resolves: plan never
    // *creates* quarantine rows (those stay per-action, via `apply`).
    journal.reconcile_unmapped_rows()?;

    // Clear stale missing records for items present in this listing: a
    // reappearance means the earlier absence was a glitch, not a delete,
    // so the two-listing clock resets (see the missing arm below).
    for it in bw_items {
        journal.clear_missing(&it.id)?;
    }

    // Fail-closed gates that fire BEFORE any other action for the item,
    // in default mode and under --writeback/--force alike (those flags
    // resolve conflicts; they never override a do-not-touch): org-owned
    // items (non-empty `collectionIds`), items with attachments, BW
    // items carrying a TOTP-source custom-field name, and BW items with
    // duplicate custom-field names. Each
    // blocked item gets exactly one quarantine here; every later loop
    // skips blocked ids, so the engine never creates, edits, stamps, or
    // trashes one.
    let mut blocked_bw: HashSet<&str> = HashSet::new();
    for it in bw_items {
        if it.org_owned() {
            blocked_bw.insert(it.id.as_str());
            actions.push(Action::Quarantine(QuarantineCase {
                kind: "org-item",
                kp_uuid: stamp_uuid(it),
                bw_id: Some(it.id.clone()),
                title: it.name.clone(),
                detail: format!(
                    "Bitwarden item {:?} is owned by an organization (collections: {:?}); org items are not synced — skipped, no data changed",
                    it.name, it.collection_ids
                ),
            }));
        } else if it.has_attachments() {
            blocked_bw.insert(it.id.as_str());
            actions.push(Action::Quarantine(QuarantineCase {
                kind: "has-attachments",
                kp_uuid: stamp_uuid(it),
                bw_id: Some(it.id.clone()),
                title: it.name.clone(),
                detail: "has attachments, which this engine does not sync — skipped, no data changed".into(),
            }));
        } else if let Some(field) = it
            .fields
            .iter()
            .find(|f| crate::kdbx::is_totp_source_field(&f.name))
        {
            // KeePass excludes TOTP-source names from its custom set, so
            // a Bitwarden custom field with one of those names can never
            // converge: the two sides hash it differently forever.
            // Quarantine instead of silently dropping or renaming it.
            blocked_bw.insert(it.id.as_str());
            actions.push(Action::Quarantine(QuarantineCase {
                kind: "totp-name-collision",
                kp_uuid: stamp_uuid(it),
                bw_id: Some(it.id.clone()),
                title: it.name.clone(),
                detail: format!(
                    "Bitwarden item {:?} carries a custom field named {:?}, which is a TOTP-source name on the KeePass side -- the two sides can never converge on it, so it is quarantined instead of synced",
                    it.name, field.name
                ),
            }));
        } else if let Some(dup) = duplicate_field_name(it) {
            // KeePass fields are name-keyed, so a duplicated Bitwarden
            // name would silently drop the non-last value on writeback.
            blocked_bw.insert(it.id.as_str());
            actions.push(Action::Quarantine(QuarantineCase {
                kind: "duplicate-field-name",
                kp_uuid: stamp_uuid(it),
                bw_id: Some(it.id.clone()),
                title: it.name.clone(),
                detail: format!(
                    "Bitwarden item {:?} carries duplicate custom-field name {:?}; KeePass fields are name-keyed, so syncing it would silently drop a value -- quarantined instead",
                    it.name, dup
                ),
            }));
        }
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
        if blocked_bw.contains(it.id.as_str()) {
            continue;
        }
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
        // KeePass-side attachments quarantine before anything else for
        // this entry — no CreateBw, UpdateBw, TrashBw, or WritebackEdit.
        // When the mapped Bitwarden item is itself blocked (org/attached),
        // its early quarantine already covers the pair: stay silent here
        // so the pair reports exactly one quarantine, not two.
        if e.has_attachments {
            let mapped_id = journal
                .mapping_by_kp(&e.uuid)?
                .map(|(bw_id, _)| bw_id);
            let mapped_blocked = mapped_id
                .as_deref()
                .map(|id| blocked_bw.contains(id))
                .unwrap_or(false);
            if !mapped_blocked {
                actions.push(Action::Quarantine(QuarantineCase {
                    kind: "has-attachments",
                    kp_uuid: Some(e.uuid),
                    bw_id: mapped_id,
                    title: e.title.clone(),
                    detail: "has attachments, which this engine does not sync — skipped, no data changed".into(),
                }));
            }
            continue;
        }
        if e.deleted {
            // In KeePass recycle bin: propagate a soft delete to BW when BW is
            // unchanged since last sync; otherwise it's a delete-vs-edit race.
            if let Some((bw_id, last_hash)) = journal.mapping_by_kp(&e.uuid)? {
                if let Some(&bi) = bw_by_id.get(bw_id.as_str()) {
                    // Blocked (org/attached) items never trash: the early
                    // quarantine already covers this pair.
                    if blocked_bw.contains(bw_id.as_str()) {
                        continue;
                    }
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
                        // Engine-recycle window: this entry was binned
                        // by the engine — two listings confirmed its
                        // Bitwarden item absent, or Bitwarden trashed it
                        // — but the item has reappeared unchanged (vault
                        // saved, journal commit lost, or the user
                        // untrashed it). Trashing it now would delete a
                        // live item on both sides on the strength of
                        // stale recycle evidence — quarantine for human
                        // review instead. A genuine user bin carries a
                        // completed side (`"keepass"`) or no tombstone
                        // and still trashes in one run.
                        match journal.tombstone_side(&e.uuid)?.as_deref() {
                            Some(side) if is_engine_recycle_side(Some(side)) => {
                                let (kind, cause) = if side == "bitwarden-absence" {
                                    (
                                        "absence-recycle-reappeared",
                                        "a confirmed Bitwarden listing absence",
                                    )
                                } else {
                                    ("trash-recycle-reappeared", "its Bitwarden trash state")
                                };
                                actions.push(Action::Quarantine(QuarantineCase {
                                    kind,
                                    kp_uuid: Some(e.uuid),
                                    bw_id: Some(bw_id),
                                    title: e.title.clone(),
                                    detail: format!(
                                        "entry was recycled after {cause}, but the Bitwarden item reappeared unchanged; refusing to trash a live item on stale recycle evidence. Clear it by restoring the entry from the KeePass recycle bin, or by deleting the Bitwarden item"
                                    ),
                                }));
                            }
                            _ => {
                                actions.push(Action::TrashBw {
                                    bw_id,
                                    kp_uuid: e.uuid,
                                    expected_revision: it.revision_date.clone(),
                                });
                            }
                        }
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
                    // Mapped BW item is gone. Tombstoned = already handled
                    // — EXCEPT a plan-time "bitwarden-absence" record,
                    // which means a recycle was planned but its apply
                    // never committed (crash window): the two-listing
                    // clock must re-run, not stall forever on
                    // uncommitted evidence. Otherwise the user
                    // permanently deleted it in Bitwarden: move the KP
                    // entry to the recycle bin (recoverable).
                    // Completed-side orphan cleanup (same crash window
                    // as the tombstone arm): a completed (`"keepass"` /
                    // `"both"`) tombstone alongside a lingering mapping
                    // means plan crashed between `record_tombstone` and
                    // `delete_mapping_by_kp`. The pair is terminally
                    // handled, so drop the mapping instead of skipping
                    // past it forever: a binned entry then rests closed,
                    // and an entry later restored from the bin syncs as
                    // brand-new instead of being skipped by a stale row.
                    // Engine-recycle sides keep their existing behavior
                    // (absence re-runs the two-listing clock; trash
                    // keeps its skip).
                    if journal.tombstoned(&e.uuid)?
                        && matches!(
                            journal.tombstone_side(&e.uuid)?.as_deref(),
                            Some("keepass") | Some("both")
                        )
                    {
                        journal.delete_mapping_by_kp(&e.uuid)?;
                        continue;
                    }
                    if journal.tombstoned(&e.uuid)?
                        && journal.tombstone_side(&e.uuid)?.as_deref()
                            != Some("bitwarden-absence")
                    {
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
                            // Record the reason durably NOW, at plan
                            // time: if apply crashes after the vault
                            // save but before the journal commit, the
                            // next run's deleted branch sees this side
                            // and quarantines instead of trashing the
                            // reappeared item.
                            journal.record_tombstone(
                                &e.uuid,
                                Some(&bw_id),
                                "bitwarden-absence",
                            )?;
                            actions.push(Action::RecycleKp {
                                kp_uuid: e.uuid,
                                bw_id: bw_id.clone(),
                                from_absence: true,
                            });
                        }
                    } else {
                        journal.note_missing(&bw_id, &e.uuid)?;
                    }
                }
                Some(&bi) => {
                    // Blocked items never reach pair handling: the early
                    // quarantine is the only action for them.
                    if blocked_bw.contains(bw_id.as_str()) {
                        continue;
                    }
                    let it = &bw_items[bi];
                    // Stale engine-recycle record: the entry is live
                    // and its item is present, so the bin decision is
                    // moot — the planned recycle never landed (crash
                    // before save), or the user restored the entry from
                    // the bin. Clear the record so it stops shadowing
                    // this mapping. (A committed recycle deletes the
                    // mapping, so this arm can only ever see a plan-time
                    // record or a restored-from-bin one.)
                    if is_engine_recycle_side(journal.tombstone_side(&e.uuid)?.as_deref()) {
                        journal.clear_tombstone(&e.uuid)?;
                    }
                    let h_kp = e.content_hash_hex();
                    let h_bw = it.content_hash_hex();
                    let kp_changed = h_kp != last_hash;
                    let bw_changed = h_bw != last_hash;

                    if it.trashed() {
                        if !kp_changed {
                            actions.push(Action::RecycleKp {
                                kp_uuid: e.uuid,
                                bw_id: bw_id.clone(),
                                from_absence: false,
                            });
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
    // A permanently deleted entry is confirmed delete intent, so only
    // COMPLETED propagations skip here (`"keepass"` / `"both"`). An
    // engine-recycle side means the binning was the engine's doing, not
    // the user's — the delete must still propagate to a live item
    // below instead of lingering forever on a skipped tombstone.
    for u in kp_tombstones {
        if kp_by_uuid.contains_key(u) {
            continue;
        }
        if journal.tombstoned(u)?
            && matches!(
                journal.tombstone_side(u)?.as_deref(),
                Some("keepass") | Some("both")
            )
        {
            // Completed-propagation orphan check (2026-11-01 review):
            // `record_tombstone` + `delete_mapping_by_kp` are separate
            // autocommits in the completion branches below, so a crash
            // between them leaves a mapping alongside a completed-side
            // tombstone — and the old skip-before-mapping-check then hid
            // the pair forever: the pair loop never iterates tombstones,
            // the adopt loop skips stamped items, and the rebuild loop
            // re-upserts the mapping for a tombstoned stamp, so merely
            // deleting the mapping would oscillate without ever making
            // the item visible. Resolve by outcome instead:
            // - live, non-blocked item: quarantine (`tombstone-
            //   reappeared`) — never trash on a stale record, never
            //   ignore. The mapping is kept, so the row stays single
            //   (dedupe) and the user can acknowledge it if intentional.
            // - trashed or listing-absent item: genuinely complete —
            //   drop the lingering mapping, no action.
            // - blocked item: the early gate already quarantined it;
            //   skip without double-reporting.
            if let Some((bw_id, _)) = journal.mapping_by_kp(u)? {
                if blocked_bw.contains(bw_id.as_str()) {
                    continue;
                }
                match bw_by_id.get(bw_id.as_str()) {
                    Some(&bi) if !bw_items[bi].trashed() => {
                        actions.push(Action::Quarantine(QuarantineCase {
                            kind: "tombstone-reappeared",
                            kp_uuid: Some(*u),
                            bw_id: Some(bw_id),
                            title: bw_items[bi].name.clone(),
                            detail: "KeePass entry is permanently deleted and its Bitwarden delete was recorded complete, but the Bitwarden item is live again (untrashed after completion, or a crash orphan); refusing to trash it or ignore it. Clear it by deleting the Bitwarden item, or acknowledge the row if the live item is intentional".into(),
                        }));
                    }
                    _ => {
                        journal.delete_mapping_by_kp(u)?;
                    }
                }
            }
            continue;
        }
        if let Some((bw_id, _)) = journal.mapping_by_kp(u)? {
            // Blocked items never trash, even from the tombstone arm.
            if blocked_bw.contains(bw_id.as_str()) {
                continue;
            }
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
        // Already quarantined by the early gate; never adopt or re-report.
        if blocked_bw.contains(it.id.as_str()) {
            continue;
        }
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

    // Expire acknowledged rows whose condition cleared: an acknowledged
    // row is re-emitted by plan every run while its condition persists
    // (the insert dedupes on unresolved rows, so the single row
    // survives), so an acknowledged row NOT among this plan's quarantine
    // actions states something false — the item left the org, dropped
    // its attachments, got adopted, or vanished — and resolves. Rows
    // for conditions that persist stay acknowledged and silent.
    // Apply-only rows (e.g. `bw_revision_changed`) are not plan-emitted:
    // if their conflict reappears under a new kind, the old row expires
    // here and the new kind's row takes over the nag — acknowledge is
    // per row (kind + identity), not per item. This runs after every
    // successful plan; the bail paths above return before it, so a
    // refused sync still changes nothing.
    let emitted: HashSet<(&str, Option<String>, Option<String>)> = actions
        .iter()
        .filter_map(|a| match a {
            Action::Quarantine(q) => {
                Some((q.kind, q.kp_uuid.map(|u| u.to_string()), q.bw_id.clone()))
            }
            _ => None,
        })
        .collect();
    journal.resolve_stale_acknowledged(&emitted)?;

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
            Action::RecycleKp { kp_uuid, bw_id, from_absence } => {
                eprintln!(
                    "warning: Bitwarden item {bw_id} missing from listing; moving KeePass entry to recycle bin (recoverable)"
                );
                if recycle_entry(&mut vault.db, *kp_uuid) {
                    journal_ops.push(JournalOp::RecordTombstone {
                        kp_uuid: *kp_uuid,
                        bw_id: Some(bw_id.clone()),
                        side: if *from_absence {
                            "bitwarden-absence"
                        } else {
                            "bitwarden-trash"
                        },
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
                // Adopting is the confirmation: resolve the item's open
                // unmapped rows in the same journal transaction as the
                // mapping, so a confirmed item can never stay pending.
                // (Deferred like every other op: if the vault save fails,
                // neither the mapping nor the resolution commits.)
                journal_ops.push(JournalOp::ResolveUnmappedForBw {
                    bw_id: it.id.clone(),
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
            has_attachments: false,
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
            collection_ids: vec![],
            organization_id: None,
            attachments: vec![],
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
    fn plan_reconciles_stale_unmapped_row_for_mapped_pair() {
        // TapPlastics shape: the item was quarantined as unmapped in one
        // run and adopted in a later one; the next sync must resolve the
        // stale row with no other action for the item.
        let j = test_journal();
        let kp = vec![entry("11111111-1111-1111-1111-111111111111")];
        let h = kp[0].content_hash_hex();
        j.upsert_mapping(&kp[0].uuid, "bw-1", &h).unwrap();
        let mut bi = bw_item("bw-1", Some("11111111-1111-1111-1111-111111111111"), "r1");
        // make the BW content hash match: stamp hash must equal live hash
        bi.fields.iter_mut().find(|f| f.name == crate::stamps::SYNC_HASH_FIELD).unwrap().value = bi.content_hash_hex();
        j.upsert_mapping(&kp[0].uuid, "bw-1", &bi.content_hash_hex()).unwrap();
        j.quarantine("unmapped-bw-item", None, Some("bw-1"), "t", "d")
            .unwrap();
        // Other kind for the same mapped pair -> stays open.
        j.quarantine("foreign-bw-edit", None, Some("bw-1"), "t", "d")
            .unwrap();
        assert_eq!(j.unresolved_quarantine_count().unwrap(), 2);
        let p = plan(&kp, &HashSet::new(), &[bi], &[], &j, &SyncOpts::default()).unwrap();
        assert!(p.actions.is_empty(), "expected no actions, got {:?}", p.actions);
        let rows = j.list_quarantine().unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].1, "foreign-bw-edit");
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
    fn folder_guard_bails_on_empty_folder_listing_with_references() {
        let j = test_journal();
        let mut item = bw_item("bw-1", None, "r1");
        item.folder_id = Some("folder-1".into());
        let err = match plan(&[], &HashSet::new(), &[item], &[], &j, &SyncOpts::default()) {
            Err(e) => e,
            Ok(_) => panic!("folder guard must bail on empty folder listing with references"),
        };
        assert!(
            err.to_string().contains("0 folders"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn folderless_vault_with_empty_folder_listing_syncs() {
        // Empty folder list + no item referencing a folder is a
        // genuinely folderless vault, not a partial listing.
        let j = test_journal();
        let item = bw_item("bw-1", None, "r1");
        let p =
            plan(&[], &HashSet::new(), &[item], &[], &j, &SyncOpts::default()).unwrap();
        assert_eq!(p.actions.len(), 1);
        assert!(
            matches!(&p.actions[0], Action::Quarantine(q) if q.kind == "unmapped-bw-item"),
            "expected unmapped quarantine, got {:?}", p.actions[0]
        );
    }

    #[test]
    fn totp_name_collision_quarantines_under_all_modes() {
        let mut item = bw_item("bw-1", None, "r1");
        item.fields.push(crate::bw::BwField {
            name: "TOTP Seed".into(),
            value: "JBSWY3DPEHPK3PXP".into(),
            field_type: 0,
        });
        for opts in [
            SyncOpts::default(),
            SyncOpts { writeback: true, force: false, adopt: false },
            SyncOpts { writeback: false, force: true, adopt: false },
        ] {
            let j = test_journal();
            let p =
                plan(&[], &HashSet::new(), &[item.clone()], &[], &j, &opts).unwrap();
            assert_eq!(p.actions.len(), 1);
            assert!(
                matches!(&p.actions[0], Action::Quarantine(q) if q.kind == "totp-name-collision"),
                "expected totp-name-collision, got {:?}", p.actions[0]
            );
        }
    }

    #[test]
    fn totp_collision_does_not_block_other_items() {
        let mut colliding = bw_item("bw-1", None, "r1");
        colliding.fields.push(crate::bw::BwField {
            name: "totp".into(),
            value: "x".into(),
            field_type: 0,
        });
        let kp = vec![entry("11111111-1111-1111-1111-111111111111")];
        let p = plan(
            &kp,
            &HashSet::new(),
            &[colliding],
            &[],
            &test_journal(),
            &SyncOpts::default(),
        )
        .unwrap();
        // The new KeePass entry still plans its create; the colliding
        // item gets exactly its quarantine.
        assert!(p.actions.iter().any(|a| matches!(a, Action::CreateBw { .. })));
        assert!(p.actions.iter().any(
            |a| matches!(a, Action::Quarantine(q) if q.kind == "totp-name-collision")
        ));
        assert_eq!(p.actions.len(), 2);
    }

    #[test]
    fn duplicate_field_name_quarantines() {
        let mut item = bw_item("bw-1", None, "r1");
        item.fields.push(crate::bw::BwField {
            name: "api-key".into(),
            value: "first".into(),
            field_type: 0,
        });
        item.fields.push(crate::bw::BwField {
            name: "api-key".into(),
            value: "second".into(),
            field_type: 0,
        });
        let p = plan(
            &[],
            &HashSet::new(),
            &[item],
            &[],
            &test_journal(),
            &SyncOpts::default(),
        )
        .unwrap();
        assert_eq!(p.actions.len(), 1);
        assert!(
            matches!(&p.actions[0], Action::Quarantine(q) if q.kind == "duplicate-field-name"),
            "expected duplicate-field-name, got {:?}", p.actions[0]
        );
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

    #[test]
    fn apply_adopt_resolves_unmapped_quarantine_row() {
        // Adopting is the confirmation: the adopt op must resolve the
        // item's open unmapped row in the same journal transaction as
        // the mapping (same stub/item shape as the folder test above,
        // minus the folder).
        let item = serde_json::json!({
            "success": true,
            "data": {
                "id": "bw-1", "name": "adopted", "notes": null, "favorite": false,
                "folderId": null, "type": 1, "reprompt": 0,
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
        bi.login = Some(crate::bw::BwLogin {
            username: Some("u".into()),
            password: Some("p".into()),
            totp: None,
            uris: Some(vec![crate::bw::BwUri {
                uri: Some("https://x.example.com".into()),
                match_: None,
            }]),
        });
        let p = Plan {
            actions: vec![Action::AdoptBwNew { item_idx: 0 }],
        };
        let mut vault = crate::kdbx::test_vault();
        let j = test_journal();
        j.quarantine("unmapped-bw-item", None, Some("bw-1"), "adopted", "d")
            .unwrap();
        assert_eq!(j.unresolved_quarantine_count().unwrap(), 1);
        let (report, ops) = apply(&p, &[], &[bi], &bw, &mut vault, &[]).unwrap();
        assert_eq!(report.kp_adopted, 1);
        assert!(ops.iter().any(|op| matches!(op,
            crate::journal::JournalOp::ResolveUnmappedForBw { bw_id }
            if bw_id == "bw-1")));
        j.apply_ops(&ops).unwrap();
        assert_eq!(j.unresolved_quarantine_count().unwrap(), 0);
        assert!(j.mapping_by_bw("bw-1").unwrap().is_some());
    }

    fn org_item(id: &str, kp_uuid: Option<&str>, rev: &str) -> BwItem {
        let mut it = bw_item(id, kp_uuid, rev);
        it.collection_ids = vec!["coll-1".into()];
        it
    }

    fn attached_item(id: &str, kp_uuid: Option<&str>, rev: &str) -> BwItem {
        let mut it = bw_item(id, kp_uuid, rev);
        it.attachments = vec![crate::bw::BwAttachment {
            id: Some("att-1".into()),
            file_name: Some("scan.pdf".into()),
            size: Some(1234),
        }];
        it
    }

    /// Any action that would write to Bitwarden (or bin in KeePass) for
    /// the given item id. Quarantines are the only permitted action.
    fn writes_for(actions: &[Action], bw_id: &str) -> Vec<String> {
        actions
            .iter()
            .filter_map(|a| match a {
                Action::CreateBw { .. } => None,
                Action::UpdateBw { bw_id: id, .. } if id == bw_id => Some("UpdateBw"),
                Action::TrashBw { bw_id: id, .. } if id == bw_id => Some("TrashBw"),
                Action::RecycleKp { bw_id: id, .. } if id == bw_id => Some("RecycleKp"),
                Action::AdoptBwNew { .. } => None,
                Action::WritebackEdit { bw_id: id, .. } if id == bw_id => {
                    Some("WritebackEdit")
                }
                _ => None,
            })
            .map(|s| s.to_string())
            .collect()
    }

    #[test]
    fn org_item_quarantines_once_and_personal_item_still_syncs() {
        // An org-owned item in a listing gets exactly one org quarantine
        // and zero BW writes for it; a personal item in the same listing
        // still plans its create. The flags must not override this:
        // --writeback/--force resolve conflicts, never a do-not-touch.
        for opts in [
            SyncOpts::default(),
            SyncOpts { writeback: true, ..Default::default() },
            SyncOpts { force: true, ..Default::default() },
        ] {
            let j = test_journal();
            let kp = vec![entry("11111111-1111-1111-1111-111111111111")];
            let org = org_item("bw-org", None, "r1");
            let listed = vec![org];
            let p = plan(&kp, &HashSet::new(), &listed, &[], &j, &opts).unwrap();
            let org_q: Vec<&Action> = p
                .actions
                .iter()
                .filter(|a| {
                    matches!(a, Action::Quarantine(q) if q.kind == "org-item")
                })
                .collect();
            assert_eq!(
                org_q.len(),
                1,
                "expected exactly one org quarantine, got {}",
                org_q.len()
            );
            if let Action::Quarantine(q) = org_q[0] {
                assert!(q.detail.contains("org items are not synced"), "detail: {}", q.detail);
                assert_eq!(q.bw_id.as_deref(), Some("bw-org"));
            }
            assert!(
                writes_for(&p.actions, "bw-org").is_empty(),
                "org item must have zero BW writes, got {:?}", p.actions
            );
            // The personal KeePass entry still plans its create.
            assert!(
                p.actions.iter().any(|a| matches!(a, Action::CreateBw { .. })),
                "personal entry must still sync, got {:?}", p.actions
            );
        }
    }

    #[test]
    fn org_item_blocks_update_and_trash() {
        // A mapped org item must not be edited even when KeePass changed,
        // and a binned KeePass entry mapped to an org item must not trash
        // it — both quarantine instead, under every flag combination.
        for opts in [
            SyncOpts::default(),
            SyncOpts { writeback: true, ..Default::default() },
            SyncOpts { force: true, ..Default::default() },
        ] {
            // Changed KP entry, mapped org item: quarantine, no UpdateBw.
            let j = test_journal();
            let mut kp = vec![entry("11111111-1111-1111-1111-111111111111")];
            let mut org = org_item("bw-org", Some("11111111-1111-1111-1111-111111111111"), "r1");
            j.upsert_mapping(&kp[0].uuid, "bw-org", &org.content_hash_hex()).unwrap();
            kp[0].title = "edited locally".into();
            let p = plan(&kp, &HashSet::new(), &[org.clone()], &[], &j, &opts).unwrap();
            assert_eq!(p.actions.len(), 1, "got {:?}", p.actions);
            assert!(matches!(&p.actions[0], Action::Quarantine(q) if q.kind == "org-item"));
            assert!(writes_for(&p.actions, "bw-org").is_empty());

            // Binned KP entry, mapped org item: quarantine, no TrashBw.
            let j = test_journal();
            let mut kp = vec![entry("11111111-1111-1111-1111-111111111111")];
            kp[0].deleted = true;
            org.fields.iter_mut().find(|f| f.name == crate::stamps::SYNC_HASH_FIELD).unwrap().value =
                org.content_hash_hex();
            j.upsert_mapping(&kp[0].uuid, "bw-org", &org.content_hash_hex()).unwrap();
            let p = plan(&kp, &HashSet::new(), &[org], &[], &j, &opts).unwrap();
            assert_eq!(p.actions.len(), 1, "got {:?}", p.actions);
            assert!(matches!(&p.actions[0], Action::Quarantine(q) if q.kind == "org-item"));
            assert!(writes_for(&p.actions, "bw-org").is_empty());
        }
    }

    #[test]
    fn bw_item_with_attachments_quarantines_and_is_never_adopted() {
        // BW-side attachments: unmapped item quarantines (never adopted,
        // even with --adopt), and a mapped item never updates.
        let j = test_journal();
        let attached = attached_item("bw-att", None, "r1");
        let opts = SyncOpts { adopt: true, ..Default::default() };
        let p = plan(&[], &HashSet::new(), &[attached], &[], &j, &opts).unwrap();
        assert_eq!(p.actions.len(), 1, "got {:?}", p.actions);
        assert!(
            matches!(&p.actions[0], Action::Quarantine(q) if q.kind == "has-attachments" && q.detail.contains("has attachments, which this engine does not sync")),
            "got {:?}", p.actions[0]
        );

        let j = test_journal();
        let mut kp = vec![entry("11111111-1111-1111-1111-111111111111")];
        let attached = attached_item("bw-att", Some("11111111-1111-1111-1111-111111111111"), "r1");
        j.upsert_mapping(&kp[0].uuid, "bw-att", &attached.content_hash_hex()).unwrap();
        kp[0].title = "edited locally".into();
        let p = plan(&kp, &HashSet::new(), &[attached], &[], &j, &SyncOpts::default()).unwrap();
        assert_eq!(p.actions.len(), 1, "got {:?}", p.actions);
        assert!(matches!(&p.actions[0], Action::Quarantine(q) if q.kind == "has-attachments"));
        assert!(writes_for(&p.actions, "bw-att").is_empty());
    }

    #[test]
    fn kp_entry_with_attachments_quarantines_instead_of_syncing() {
        // KeePass-side attachments: a new entry never creates, a changed
        // mapped entry never updates, and a binned entry never trashes.
        // Each case plans exactly one has-attachments quarantine whose
        // detail states the engine does not sync attachments.
        let assert_quarantine_only = |p: Plan| {
            assert_eq!(p.actions.len(), 1, "got {:?}", p.actions);
            assert!(
                matches!(&p.actions[0], Action::Quarantine(q) if q.kind == "has-attachments" && q.detail == "has attachments, which this engine does not sync — skipped, no data changed"),
                "got {:?}", p.actions[0]
            );
        };
        // New entry with attachments: no CreateBw.
        let mut e = entry("11111111-1111-1111-1111-111111111111");
        e.has_attachments = true;
        let j = test_journal();
        let p = plan(&[e], &HashSet::new(), &[], &[], &j, &SyncOpts::default()).unwrap();
        assert_quarantine_only(p);
        // Changed mapped entry with attachments: no UpdateBw.
        let j = test_journal();
        let mut e = entry("11111111-1111-1111-1111-111111111111");
        e.has_attachments = true;
        e.title = "edited locally".into();
        let bi = bw_item("bw-1", Some("11111111-1111-1111-1111-111111111111"), "r1");
        j.upsert_mapping(&e.uuid, "bw-1", &bi.content_hash_hex()).unwrap();
        let p = plan(&[e], &HashSet::new(), &[bi], &[], &j, &SyncOpts::default()).unwrap();
        assert_quarantine_only(p);
        // Binned entry with attachments: no TrashBw.
        let j = test_journal();
        let mut e = entry("11111111-1111-1111-1111-111111111111");
        e.has_attachments = true;
        e.deleted = true;
        let bi = bw_item("bw-1", Some("11111111-1111-1111-1111-111111111111"), "r1");
        j.upsert_mapping(&e.uuid, "bw-1", &bi.content_hash_hex()).unwrap();
        let p = plan(&[e], &HashSet::new(), &[bi], &[], &j, &SyncOpts::default()).unwrap();
        assert_quarantine_only(p);
    }

    #[test]
    fn absence_recycle_reappeared_quarantines_instead_of_trashing() {
        // The double-bin window, simulated end to end at the plan/apply
        // seam: (1) two listings confirm the absence and plan the
        // recycle — the plan-time tombstone records the absence reason;
        // (2) apply bins the KeePass entry and saves the vault, but the
        // journal commit is LOST (crash: ops discarded); (3) the next
        // run sees the binned entry and the reappeared, unchanged BW
        // item — it must quarantine, never TrashBw, and the BW item
        // stays intact (no trash action exists to apply).
        let j = test_journal();
        let mut kp = vec![];
        let mut items = vec![];
        for i in 1..=4u8 {
            let (e, bi) = mapped_pair(&j, i);
            kp.push(e);
            items.push(bi);
        }
        // The pair under test is bw-4 / uuid ...1114.
        let target_uuid: Uuid = "11111111-1111-1111-1111-111111111114".parse().unwrap();
        let partial: Vec<BwItem> = items[..3].to_vec();
        let p = plan(&kp, &HashSet::new(), &partial, &[], &j, &SyncOpts::default()).unwrap();
        assert!(p.actions.is_empty(), "first sighting must not recycle");
        let p = plan(&kp, &HashSet::new(), &partial, &[], &j, &SyncOpts::default()).unwrap();
        assert_eq!(p.actions.len(), 1, "got {:?}", p.actions);
        assert!(
            matches!(&p.actions[0], Action::RecycleKp { from_absence: true, .. }),
            "expected an absence recycle, got {:?}", p.actions[0]
        );
        assert_eq!(
            j.tombstone_side(&target_uuid).unwrap().as_deref(),
            Some("bitwarden-absence"),
            "plan must record the absence reason durably"
        );
        // Apply bins the entry (in-memory vault with a real recycle bin)
        // — then the journal commit is lost: ops are discarded, exactly
        // the crash window.
        let mut vault = crate::kdbx::test_vault();
        {
            use keepass::db::fields;
            let mut root = vault.db.root_mut();
            let mut e = root
                .add_entry_with_id(keepass::db::EntryId::from_uuid(target_uuid))
                .unwrap();
            e.set_unprotected(fields::TITLE, "t");
            e.set_protected(fields::USERNAME, "u");
            e.set_protected(fields::PASSWORD, "p");
        }
        let bin_uuid = {
            let mut root = vault.db.root_mut();
            let mut bin = root.add_group();
            bin.name = "Recycle Bin".to_string();
            bin.id().uuid()
        };
        vault.db.meta.recyclebin_uuid = Some(bin_uuid);
        let bw = BwClient::new("http://127.0.0.1:1").unwrap();
        let (report, _discarded_ops) =
            apply(&p, &kp, &items, &bw, &mut vault, &[]).unwrap();
        assert_eq!(report.kp_recycled, 1);
        assert!(
            j.mapping_by_kp(&target_uuid).unwrap().is_some(),
            "crash: the mapping must still be there (commit lost)"
        );
        // Next run: the entry is binned, the BW item reappeared unchanged.
        let mut entries = crate::kdbx::extract_entries(&vault.db);
        // The vault holds only the target entry; re-add the other three
        // live entries so the listing guards (majority-present) pass.
        entries.extend(kp.into_iter().filter(|e| e.uuid != target_uuid));
        let binned = entries.iter().find(|e| e.uuid == target_uuid).unwrap();
        assert!(binned.deleted, "applied recycle must have binned the entry");
        let p = plan(&entries, &HashSet::new(), &items, &[], &j, &SyncOpts::default()).unwrap();
        assert!(
            p.actions.iter().all(|a| !matches!(a, Action::TrashBw { .. })),
            "no TrashBw may fire on a reappeared item, got {:?}", p.actions
        );
        assert!(
            p.actions.iter().any(|a| matches!(a, Action::Quarantine(q) if q.kind == "absence-recycle-reappeared")),
            "expected an absence-recycle-reappeared quarantine, got {:?}", p.actions
        );
    }

    #[test]
    fn user_binned_entry_still_trashes_in_one_run() {
        // Positive control for the absence guard: a genuine user bin
        // (no absence tombstone) still plans TrashBw immediately, with
        // no quarantine in the way.
        let j = test_journal();
        let mut kp = vec![entry("11111111-1111-1111-1111-111111111111")];
        kp[0].deleted = true;
        let bi = bw_item("bw-1", Some("11111111-1111-1111-1111-111111111111"), "r1");
        j.upsert_mapping(&kp[0].uuid, "bw-1", &bi.content_hash_hex()).unwrap();
        let p = plan(&kp, &HashSet::new(), &[bi], &[], &j, &SyncOpts::default()).unwrap();
        assert_eq!(p.actions.len(), 1, "got {:?}", p.actions);
        assert!(matches!(&p.actions[0], Action::TrashBw { .. }));
        assert_eq!(
            j.tombstone_side(&kp[0].uuid).unwrap(),
            None,
            "a user bin must not carry an absence tombstone"
        );
    }

    #[test]
    fn trash_recycle_reappeared_quarantines_instead_of_retrashing() {
        // Mirror of the absence test, for the trashed arm: (1) BW
        // trashes the item and plan recycles it; (2) apply bins the
        // entry and the journal commit LANDS, recording side
        // "bitwarden-trash"; (3) the user untrashes the BW item
        // unchanged — the next run must quarantine, never TrashBw.
        let j = test_journal();
        let mut kp = vec![];
        let mut items = vec![];
        for i in 1..=4u8 {
            let (e, bi) = mapped_pair(&j, i);
            kp.push(e);
            items.push(bi);
        }
        // Production stamps carry the last-synced hash; the fixture's
        // "oldhash" stamp would disagree with live content after a
        // rebuild, so point bw-4's stamp hash at its live hash (content
        // hashes exclude stamps, so this does not change it).
        let live = items[3].content_hash_hex();
        for f in items[3].fields.iter_mut() {
            if f.name == crate::stamps::SYNC_HASH_FIELD {
                f.value = live.clone();
            }
        }
        let target_uuid: Uuid = "11111111-1111-1111-1111-111111111114".parse().unwrap();
        let mut trashed = items.clone();
        trashed[3].deleted_date = Some("2026-10-03T00:00:00Z".into());
        let p = plan(
            &kp,
            &HashSet::new(),
            &trashed,
            &[],
            &j,
            &SyncOpts::default(),
        )
        .unwrap();
        assert_eq!(p.actions.len(), 1, "got {:?}", p.actions);
        assert!(
            matches!(
                &p.actions[0],
                Action::RecycleKp {
                    from_absence: false,
                    ..
                }
            ),
            "expected a trashed-arm recycle, got {:?}",
            p.actions[0]
        );
        // Apply bins the entry (in-memory vault with a real recycle bin)
        // and the journal commit lands this time.
        let mut vault = crate::kdbx::test_vault();
        {
            use keepass::db::fields;
            let mut root = vault.db.root_mut();
            let mut e = root
                .add_entry_with_id(keepass::db::EntryId::from_uuid(target_uuid))
                .unwrap();
            e.set_unprotected(fields::TITLE, "t");
            e.set_protected(fields::USERNAME, "u");
            e.set_protected(fields::PASSWORD, "p");
        }
        let bin_uuid = {
            let mut root = vault.db.root_mut();
            let mut bin = root.add_group();
            bin.name = "Recycle Bin".to_string();
            bin.id().uuid()
        };
        vault.db.meta.recyclebin_uuid = Some(bin_uuid);
        let bw = BwClient::new("http://127.0.0.1:1").unwrap();
        let (report, ops) = apply(&p, &kp, &trashed, &bw, &mut vault, &[]).unwrap();
        assert_eq!(report.kp_recycled, 1);
        j.apply_ops(&ops).unwrap();
        assert_eq!(
            j.tombstone_side(&target_uuid).unwrap().as_deref(),
            Some("bitwarden-trash"),
            "trashed-arm recycle must record its own side"
        );
        assert!(
            j.mapping_by_kp(&target_uuid).unwrap().is_none(),
            "committed recycle deletes the mapping"
        );
        // Next run: the entry is binned, the BW item untrashed unchanged.
        let mut entries = crate::kdbx::extract_entries(&vault.db);
        entries.extend(kp.into_iter().filter(|e| e.uuid != target_uuid));
        let binned = entries.iter().find(|e| e.uuid == target_uuid).unwrap();
        assert!(binned.deleted, "applied recycle must have binned the entry");
        let p = plan(
            &entries,
            &HashSet::new(),
            &items,
            &[],
            &j,
            &SyncOpts::default(),
        )
        .unwrap();
        assert_eq!(p.actions.len(), 1, "got {:?}", p.actions);
        assert!(
            p.actions
                .iter()
                .all(|a| !matches!(a, Action::TrashBw { .. })),
            "no TrashBw may fire on an untrashed item, got {:?}",
            p.actions
        );
        assert!(
            p.actions.iter().any(
                |a| matches!(a, Action::Quarantine(q) if q.kind == "trash-recycle-reappeared")
            ),
            "expected a trash-recycle-reappeared quarantine, got {:?}",
            p.actions
        );
        // The new detail states its clearing path (round-3 finding 12
        // for the absence kind, mirrored here).
        assert!(
            p.actions
                .iter()
                .any(|a| matches!(a, Action::Quarantine(q) if q.detail.contains("recycle bin"))),
            "detail must state the clearing path, got {:?}",
            p.actions
        );
    }

    #[test]
    fn tombstone_arm_propagates_delete_for_engine_recycle_sides() {
        // Engine-recycle tombstones are not completions: a permanently
        // deleted KeePass entry (bin emptied) with a live Bitwarden item
        // must still propagate its delete, for every engine side
        // including the legacy "bitwarden" spelling.
        for side in ["bitwarden-absence", "bitwarden-trash", "bitwarden"] {
            let j = test_journal();
            let uuid: Uuid = "11111111-1111-1111-1111-111111111111".parse().unwrap();
            let bi = bw_item("bw-1", Some("11111111-1111-1111-1111-111111111111"), "r1");
            j.upsert_mapping(&uuid, "bw-1", &bi.content_hash_hex())
                .unwrap();
            j.record_tombstone(&uuid, Some("bw-1"), side).unwrap();
            let mut tombs = HashSet::new();
            tombs.insert(uuid);
            let p = plan(&[], &tombs, &[bi], &[], &j, &SyncOpts::default()).unwrap();
            assert_eq!(p.actions.len(), 1, "side {side}: got {:?}", p.actions);
            assert!(
                matches!(&p.actions[0], Action::TrashBw { .. }),
                "side {side}: expected TrashBw, got {:?}",
                p.actions[0]
            );
        }
    }

    #[test]
    fn tombstone_arm_skips_completed_propagations_without_mapping() {
        // The skip rule survives where it still applies: a completed
        // propagation with NO lingering mapping and NO live item still
        // skips. (A live item would not skip: a stamped one rebuilds
        // its mapping first and lands in the orphan case below, and an
        // unstamped one reaches the adopt loop's unmapped quarantine.)
        for side in ["keepass", "both"] {
            let j = test_journal();
            let uuid: Uuid = "11111111-1111-1111-1111-111111111111".parse().unwrap();
            j.record_tombstone(&uuid, Some("bw-1"), side).unwrap();
            let mut tombs = HashSet::new();
            tombs.insert(uuid);
            let p = plan(&[], &tombs, &[], &[], &j, &SyncOpts::default()).unwrap();
            assert!(p.actions.is_empty(), "side {side}: got {:?}", p.actions);
        }
    }

    #[test]
    fn tombstone_completed_orphan_with_live_item_quarantines() {
        // Crash orphan: mapping + completed-side tombstone + live item.
        // Old behavior skipped it forever (never synced, never
        // quarantined, no error). New behavior quarantines it visibly
        // and never trashes on a stale record; the mapping is kept so
        // the row stays single (dedupe).
        for side in ["keepass", "both"] {
            let j = test_journal();
            let uuid: Uuid = "11111111-1111-1111-1111-111111111111".parse().unwrap();
            let bi = bw_item("bw-1", Some("11111111-1111-1111-1111-111111111111"), "r1");
            j.upsert_mapping(&uuid, "bw-1", &bi.content_hash_hex())
                .unwrap();
            j.record_tombstone(&uuid, Some("bw-1"), side).unwrap();
            let mut tombs = HashSet::new();
            tombs.insert(uuid);
            let p = plan(&[], &tombs, &[bi], &[], &j, &SyncOpts::default()).unwrap();
            assert_eq!(p.actions.len(), 1, "side {side}: got {:?}", p.actions);
            assert!(
                matches!(&p.actions[0], Action::Quarantine(q) if q.kind == "tombstone-reappeared" && q.bw_id.as_deref() == Some("bw-1")),
                "side {side}: expected tombstone-reappeared, got {:?}",
                p.actions[0]
            );
            assert!(
                j.mapping_by_kp(&uuid).unwrap().is_some(),
                "side {side}: mapping must be kept while quarantined"
            );
        }
    }

    #[test]
    fn tombstone_completed_orphan_with_trashed_item_cleans_mapping() {
        // Same orphan, but the item is trashed: genuinely complete, so
        // the lingering mapping is dropped and no action is needed.
        let j = test_journal();
        let uuid: Uuid = "11111111-1111-1111-1111-111111111111".parse().unwrap();
        let mut bi = bw_item("bw-1", Some("11111111-1111-1111-1111-111111111111"), "r1");
        bi.deleted_date = Some("2026-10-03T00:00:00Z".into());
        j.upsert_mapping(&uuid, "bw-1", &bi.content_hash_hex())
            .unwrap();
        j.record_tombstone(&uuid, Some("bw-1"), "keepass").unwrap();
        let mut tombs = HashSet::new();
        tombs.insert(uuid);
        let p = plan(&[], &tombs, &[bi], &[], &j, &SyncOpts::default()).unwrap();
        assert!(p.actions.is_empty(), "got {:?}", p.actions);
        assert_eq!(j.mapping_by_kp(&uuid).unwrap(), None);
    }

    #[test]
    fn deleted_branch_completed_orphan_cleans_mapping() {
        // Same crash window in the deleted branch's item-absent arm: a
        // completed-side tombstone plus a lingering mapping used to skip
        // forever. Now the mapping is dropped: the pair rests closed,
        // and an entry later restored from the bin syncs as brand-new.
        let j = test_journal();
        let uuid: Uuid = "11111111-1111-1111-1111-111111111111".parse().unwrap();
        let kp = vec![entry("11111111-1111-1111-1111-111111111111")];
        j.upsert_mapping(&uuid, "bw-1", "h").unwrap();
        j.record_tombstone(&uuid, Some("bw-1"), "keepass").unwrap();
        let p = plan(&kp, &HashSet::new(), &[], &[], &j, &SyncOpts::default()).unwrap();
        assert!(p.actions.is_empty(), "got {:?}", p.actions);
        assert_eq!(j.mapping_by_kp(&uuid).unwrap(), None);
        // Second plan: live entry, no mapping, no item -> brand-new.
        let p = plan(&kp, &HashSet::new(), &[], &[], &j, &SyncOpts::default()).unwrap();
        assert!(
            matches!(&p.actions[0], Action::CreateBw { .. }),
            "expected CreateBw, got {:?}",
            p.actions
        );
    }

    fn folder_guard_fixtures() -> (
        crate::journal::Journal,
        Vec<CanonicalEntry>,
        BwItem,
        Vec<crate::bw::BwFolder>,
    ) {
        // Mapped pair: KeePass entry in group "X", Bitwarden item in an
        // unknown folder. The folder list knows only "f-known".
        let j = test_journal();
        let uuid: Uuid = "11111111-1111-1111-1111-111111111111".parse().unwrap();
        let mut kp = vec![entry("11111111-1111-1111-1111-111111111111")];
        kp[0].group_path = "X".into();
        let mut bi = bw_item("bw-1", Some("11111111-1111-1111-1111-111111111111"), "r1");
        bi.folder_id = Some("f-unknown".into());
        let folders = vec![crate::bw::BwFolder {
            id: "f-known".into(),
            name: "Known".into(),
        }];
        j.upsert_mapping(&uuid, "bw-1", &kp[0].content_hash_hex())
            .unwrap();
        (j, kp, bi, folders)
    }

    #[test]
    fn partial_folder_listing_bails_for_placement_pairs() {
        // KeePass-only change -> UpdateBw carrying a folderId, resolved
        // against a truncated list -> bail, and the bail changes
        // nothing (a stale unmapped row seeded beforehand stays open:
        // reconcile never ran).
        let (j, mut kp, bi, folders) = folder_guard_fixtures();
        j.quarantine("unmapped-bw-item", None, Some("bw-1"), "t", "d")
            .unwrap();
        kp[0].title = "changed".into();
        let err = match plan(
            &kp,
            &HashSet::new(),
            &[bi],
            &folders,
            &j,
            &SyncOpts::default(),
        ) {
            Ok(p) => panic!("expected bail, got {:?}", p.actions),
            Err(e) => e,
        };
        assert!(
            err.to_string().contains("partial listing"),
            "unexpected error: {err}"
        );
        assert_eq!(j.unresolved_quarantine_count().unwrap(), 1);
        assert_eq!(j.list_quarantine().unwrap().len(), 1);
    }

    #[test]
    fn partial_folder_listing_bails_for_agreeing_mismatched_pair() {
        // Agreeing pair (hashes equal) whose top group differs from the
        // unknown folder name -> a move UpdateBw -> bail.
        let (j, kp, mut bi, folders) = folder_guard_fixtures();
        // Helpers align: same title/username/password, empty notes/uris,
        // stamps excluded from the hash.
        bi.notes = Some("".into());
        if let Some(l) = bi.login.as_mut() {
            l.uris = Some(vec![]);
        }
        assert_eq!(
            kp[0].content_hash_hex(),
            bi.content_hash_hex(),
            "fixture must agree for the move case"
        );
        j.upsert_mapping(&kp[0].uuid, "bw-1", &bi.content_hash_hex())
            .unwrap();
        let err = match plan(
            &kp,
            &HashSet::new(),
            &[bi],
            &folders,
            &j,
            &SyncOpts::default(),
        ) {
            Ok(p) => panic!("expected bail, got {:?}", p.actions),
            Err(e) => e,
        };
        assert!(
            err.to_string().contains("partial listing"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn partial_folder_listing_does_not_trip_non_placement_pairs() {
        // Adopt path: unmapped item, unknown folder -> root fallback, no
        // folder creation, no bail.
        let j = test_journal();
        let mut bi = bw_item("bw-9", None, "r1");
        bi.folder_id = Some("f-unknown".into());
        let folders = vec![crate::bw::BwFolder {
            id: "f-known".into(),
            name: "Known".into(),
        }];
        let p = plan(
            &[],
            &HashSet::new(),
            &[bi],
            &folders,
            &j,
            &SyncOpts::default(),
        )
        .unwrap();
        assert!(
            p.actions
                .iter()
                .any(|a| matches!(a, Action::Quarantine(q) if q.kind == "unmapped-bw-item")),
            "adopt path must quarantine, not bail: {:?}",
            p.actions
        );
        // Foreign edit, default mode: quarantine carries no folderId,
        // so no bail even though the folder is unknown.
        let (j, kp, mut bi, folders) = folder_guard_fixtures();
        bi.name = "t (edited in bitwarden)".into();
        let p = plan(
            &kp,
            &HashSet::new(),
            std::slice::from_ref(&bi),
            &folders,
            &j,
            &SyncOpts::default(),
        )
        .unwrap();
        assert!(
            p.actions
                .iter()
                .any(|a| matches!(a, Action::Quarantine(q) if q.kind == "foreign-bw-edit")),
            "foreign edit must quarantine, not bail: {:?}",
            p.actions
        );
        // Same foreign edit under --force: UpdateBw -> bail.
        let err = match plan(
            &kp,
            &HashSet::new(),
            &[bi],
            &folders,
            &j,
            &SyncOpts {
                force: true,
                ..SyncOpts::default()
            },
        ) {
            Ok(p) => panic!("expected bail, got {:?}", p.actions),
            Err(e) => e,
        };
        assert!(
            err.to_string().contains("partial listing"),
            "force + foreign edit must bail: {err}"
        );
        // Root-group pair: UpdateBw resolves to no folder -> no bail.
        let (j, mut kp, bi, folders) = folder_guard_fixtures();
        kp[0].group_path = "".into();
        kp[0].title = "changed".into();
        let p = plan(
            &kp,
            &HashSet::new(),
            &[bi],
            &folders,
            &j,
            &SyncOpts::default(),
        )
        .unwrap();
        assert!(
            p.actions
                .iter()
                .any(|a| matches!(a, Action::UpdateBw { .. })),
            "root-group update must plan, not bail: {:?}",
            p.actions
        );
        // Trashed item: recycle/quarantine carries no folderId -> no bail.
        let (j, kp, mut bi, folders) = folder_guard_fixtures();
        bi.deleted_date = Some("2026-10-03T00:00:00Z".into());
        let p = plan(
            &kp,
            &HashSet::new(),
            &[bi],
            &folders,
            &j,
            &SyncOpts::default(),
        )
        .unwrap();
        assert!(
            p.actions
                .iter()
                .any(|a| matches!(a, Action::RecycleKp { .. })),
            "trashed item must recycle, not bail: {:?}",
            p.actions
        );
    }

    #[test]
    fn acknowledged_gate_row_stays_silent_but_blocked() {
        // Acknowledge is silence, not bypass: the org row re-fires every
        // run, stays listed and marked, stops counting as pending, and
        // the item still gets no sync action.
        let j = test_journal();
        let bi = org_item("bw-1", None, "r1");
        let p = plan(
            &[],
            &HashSet::new(),
            std::slice::from_ref(&bi),
            &[],
            &j,
            &SyncOpts::default(),
        )
        .unwrap();
        assert!(
            p.actions
                .iter()
                .any(|a| matches!(a, Action::Quarantine(q) if q.kind == "org-item")),
            "expected org-item quarantine: {:?}",
            p.actions
        );
        j.quarantine("org-item", None, Some("bw-1"), "t", "d")
            .unwrap();
        let rows = j.list_quarantine().unwrap();
        assert_eq!(rows.len(), 1);
        assert!(j.acknowledge_quarantine(rows[0].0).unwrap());
        assert_eq!(j.unresolved_quarantine_count().unwrap(), 0);
        // Second plan re-fires the gate: still blocked, still silent.
        let p = plan(&[], &HashSet::new(), &[bi], &[], &j, &SyncOpts::default()).unwrap();
        assert!(
            p.actions.iter().all(|a| matches!(a, Action::Quarantine(_))),
            "acknowledged item must get no sync action: {:?}",
            p.actions
        );
        assert_eq!(j.unresolved_quarantine_count().unwrap(), 0);
        let rows = j.list_quarantine().unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].1, "org-item");
        assert!(rows[0].6, "row must stay listed and marked acknowledged");
    }

    #[test]
    fn acknowledged_row_resolves_when_condition_clears() {
        // The org row is acknowledged; then the item leaves the org.
        // Plan no longer emits org-item for it, so the row resolves —
        // and the item is no longer blocked (it reaches the adopt loop).
        let j = test_journal();
        let bi = org_item("bw-1", None, "r1");
        j.quarantine("org-item", None, Some("bw-1"), "t", "d")
            .unwrap();
        let rows = j.list_quarantine().unwrap();
        assert!(j.acknowledge_quarantine(rows[0].0).unwrap());
        let mut deorged = bi.clone();
        deorged.collection_ids = vec![];
        let p = plan(
            &[],
            &HashSet::new(),
            &[deorged],
            &[],
            &j,
            &SyncOpts::default(),
        )
        .unwrap();
        assert!(
            p.actions
                .iter()
                .any(|a| matches!(a, Action::Quarantine(q) if q.kind == "unmapped-bw-item")),
            "de-orged item must reach the adopt loop: {:?}",
            p.actions
        );
        assert!(
            !p.actions
                .iter()
                .any(|a| matches!(a, Action::Quarantine(q) if q.kind == "org-item")),
            "org-item must stop firing: {:?}",
            p.actions
        );
        assert!(
            j.list_quarantine().unwrap().is_empty(),
            "acknowledged row must resolve when its condition clears"
        );
    }
}
