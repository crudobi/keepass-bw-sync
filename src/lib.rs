//! keepass-bw-sync: bidirectional KeePass2 <-> Bitwarden sync engine.
//!
//! Design: local .kdbx is the source of truth. Identity is a hybrid of a
//! Bitwarden custom-field stamp (KBS_SYNC_ID) and a local SQLite journal
//! (watermarks, content hashes, tombstones). Conflicts quarantine for human
//! review; secrets live in zeroized memory only.

pub mod secret;
pub mod stamps;
pub mod canonical;
pub mod kdbx;
pub mod bw;
pub mod journal;
pub mod sync;
