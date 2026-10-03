//! Sync identity stamps stored as Bitwarden custom fields.
//!
//! `KBS_SYNC_ID` carries the KeePass entry UUID (durable cross-system
//! identity, survives export/import). `KBS_SYNC_HASH` carries the hex content
//! hash the engine last wrote, so foreign (non-engine) edits are detectable:
//! a live item whose hash differs from its stamp was touched outside the
//! engine and must quarantine, never silently overwrite.

pub const SYNC_ID_FIELD: &str = "KBS_SYNC_ID";
pub const SYNC_HASH_FIELD: &str = "KBS_SYNC_HASH";
