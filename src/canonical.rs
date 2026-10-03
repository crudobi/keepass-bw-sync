//! Canonical entry model shared by both sides of the sync.
//!
//! Both the KeePass entry and the Bitwarden item are projected into the same
//! field set so a single stable content hash detects changes on either side.
//! Sync-stamp fields are excluded from the hash; group/folder placement is
//! excluded too (moves are placement decisions, not content conflicts).

use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::secret::Secret;
use crate::stamps::{SYNC_HASH_FIELD, SYNC_ID_FIELD};

pub struct CanonicalEntry {
    pub uuid: Uuid,
    pub title: String,
    pub username: String,
    pub password: Secret,
    pub url: String,
    pub notes: String,
    pub totp: Option<String>,
    /// (name, value) pairs; order normalized at hash time.
    pub custom: Vec<(String, String)>,
    pub group_path: String,
    pub last_modified_ms: i64,
    /// True when the entry lives in the KeePass recycle bin.
    pub deleted: bool,
}

fn write_field(h: &mut Sha256, tag: &str, data: &[u8]) {
    h.update(tag.as_bytes());
    h.update([0u8]);
    h.update(&(data.len() as u64).to_le_bytes());
    h.update(data);
}

/// Stable content hash over the syncable fields of an entry.
pub fn hash_fields(
    title: &str,
    username: &str,
    password: &[u8],
    url: &str,
    notes: &str,
    totp: Option<&str>,
    custom: &[(String, String)],
) -> [u8; 32] {
    let mut h = Sha256::new();
    write_field(&mut h, "title", title.as_bytes());
    write_field(&mut h, "username", username.as_bytes());
    write_field(&mut h, "password", password);
    write_field(&mut h, "url", url.as_bytes());
    write_field(&mut h, "notes", notes.as_bytes());
    if let Some(t) = totp {
        write_field(&mut h, "totp", t.as_bytes());
    }
    let mut sorted: Vec<&(String, String)> = custom.iter().collect();
    sorted.sort_by(|a, b| a.0.cmp(&b.0));
    for (k, v) in sorted {
        if k == SYNC_ID_FIELD || k == SYNC_HASH_FIELD {
            continue;
        }
        write_field(&mut h, "custom-name", k.as_bytes());
        write_field(&mut h, "custom-value", v.as_bytes());
    }
    h.finalize().into()
}

impl CanonicalEntry {
    pub fn content_hash(&self) -> [u8; 32] {
        hash_fields(
            &self.title,
            &self.username,
            self.password.expose(),
            &self.url,
            &self.notes,
            self.totp.as_deref(),
            &self.custom,
        )
    }

    pub fn content_hash_hex(&self) -> String {
        hex::encode(self.content_hash())
    }
}
