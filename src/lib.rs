//! keepass-bw-sync: bidirectional KeePass2 <-> Bitwarden sync engine.
//!
//! Design: local .kdbx is the source of truth. Identity is a hybrid of a
//! Bitwarden custom-field stamp (KBS_SYNC_ID) and a local SQLite journal
//! (watermarks, content hashes, tombstones). Conflicts quarantine for human
//! review. KeePass-side secrets are held in zeroizing containers; the
//! Bitwarden side necessarily materializes plaintext JSON in memory at the
//! `bw serve` boundary (loopback only) — the client wipes the copies it
//! controls, but the payload structures themselves are plain.

pub mod secret;
pub mod stamps;
pub mod canonical;
pub mod kdbx;
pub mod bw;
pub mod journal;
pub mod sync;
