//! Canonical entry model shared by both sides of the sync.
//!
//! Both the KeePass entry and the Bitwarden item are projected into the same
//! field set so a single stable content hash detects changes on either side.
//! Sync-stamp fields are excluded from the hash. Group/folder placement is
//! excluded from the *content* hash too (moves are placement decisions, not
//! content conflicts) — placement is reconciled separately by the plan
//! (flat model: top-level KeePass group name <-> Bitwarden folder name).

use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::secret::Secret;
use crate::stamps::{SYNC_HASH_FIELD, SYNC_ID_FIELD};

pub struct CanonicalEntry {
    pub uuid: Uuid,
    pub title: String,
    pub username: String,
    pub password: Secret,
    /// The primary URL: always the first of [`CanonicalEntry::uris`]
    /// (empty when the entry has no URIs). Kept as a separate field for
    /// single-URL consumers.
    pub url: String,
    /// All URIs, in order. KeePass has a single URL field, so URIs beyond
    /// the first round-trip through `URL <n>` custom fields (see kdbx.rs).
    pub uris: Vec<String>,
    pub notes: String,
    pub totp: Option<String>,
    /// (name, value, field type) triples; order normalized at hash time.
    /// Field types are Bitwarden's: 0 = text, 1 = hidden, 2 = boolean.
    /// KeePass has no field-type concept: protected values project as
    /// hidden (1), unprotected values as text (0).
    pub custom: Vec<(String, String, i32)>,
    pub group_path: String,
    /// True when the entry lives in the KeePass recycle bin.
    pub deleted: bool,
}

fn write_field(h: &mut Sha256, tag: &str, data: &[u8]) {
    h.update(tag.as_bytes());
    h.update([0u8]);
    h.update((data.len() as u64).to_le_bytes());
    h.update(data);
}

/// Stable content hash over the syncable fields of an entry.
///
/// The Bitwarden URI `match` strategy is deliberately NOT hashed: KeePass
/// has no per-URI match concept, so hashing it would make every adopted
/// item with an explicit non-null match permanently disagree with its
/// KeePass twin (adopt → spurious UpdateBw → false foreign-edit
/// quarantine, forever). The engine echoes `match` back on PUTs instead,
/// so it is never silently reset — it just isn't change-detected.
///
/// Format (locked by the golden-vector tests below): each field is
/// `tag || 0x00 || len_le64 || bytes`. The first URL is hashed under
/// "url" (so single-URL entries hash as they always have); additional
/// URIs follow under "uri". Custom fields hash name, value, and type.
pub fn hash_fields(
    title: &str,
    username: &str,
    password: &[u8],
    urls: &[String],
    notes: &str,
    totp: Option<&str>,
    custom: &[(String, String, i32)],
) -> [u8; 32] {
    let mut h = Sha256::new();
    write_field(&mut h, "title", title.as_bytes());
    write_field(&mut h, "username", username.as_bytes());
    write_field(&mut h, "password", password);
    write_field(
        &mut h,
        "url",
        urls.first().map(|s| s.as_bytes()).unwrap_or(&[]),
    );
    for extra in urls.iter().skip(1) {
        write_field(&mut h, "uri", extra.as_bytes());
    }
    write_field(&mut h, "notes", notes.as_bytes());
    if let Some(t) = totp {
        write_field(&mut h, "totp", t.as_bytes());
    }
    let mut sorted: Vec<&(String, String, i32)> = custom.iter().collect();
    sorted.sort_by(|a, b| a.0.cmp(&b.0));
    for (k, v, t) in sorted {
        if k == SYNC_ID_FIELD || k == SYNC_HASH_FIELD {
            continue;
        }
        write_field(&mut h, "custom-name", k.as_bytes());
        write_field(&mut h, "custom-value", v.as_bytes());
        write_field(&mut h, "custom-type", &t.to_le_bytes());
    }
    h.finalize().into()
}

impl CanonicalEntry {
    pub fn content_hash(&self) -> [u8; 32] {
        hash_fields(
            &self.title,
            &self.username,
            self.password.expose(),
            &self.uris,
            &self.notes,
            self.totp.as_deref(),
            &self.custom,
        )
    }

    pub fn content_hash_hex(&self) -> String {
        hex::encode(self.content_hash())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Golden vectors: these hex values ARE the hash format. If a change
    /// alters any of them, every journal watermark and KBS_SYNC_HASH stamp
    /// in the field invalidates at once (mass quarantines on next sync) —
    /// such a change must be deliberate, versioned, and announced, never
    /// accidental. Regenerate only with that understood.
    #[test]
    fn golden_hash_vectors() {
        // Minimal entry: no URLs, no TOTP, no custom fields.
        let h = hash_fields("t", "u", b"p", &[], "", None, &[]);
        assert_eq!(
            hex::encode(h),
            "48349868faebca0abcb3ee2a8e123218547fbeeef87aeb42270fa9048b4340d9"
        );

        // Full entry: two URIs, TOTP, typed custom fields (given unsorted;
        // hashing sorts by name).
        let urls = vec![
            "https://a.example.com".to_string(),
            "https://b.example.com".to_string(),
        ];
        let custom = vec![
            ("Plain".to_string(), "x".to_string(), 0),
            ("API Key".to_string(), "abc".to_string(), 1),
        ];
        let h = hash_fields("title", "user", b"pw", &urls, "notes", Some("OTPSEED"), &custom);
        assert_eq!(
            hex::encode(h),
            "c181bb71659104ebede1b1f17a14e93456028c54c9068a77fb761d0422bb8bfa"
        );
    }

    #[test]
    fn hash_is_order_insensitive_for_custom_fields() {
        let urls = vec!["https://a.example.com".to_string()];
        let a = vec![
            ("B".to_string(), "2".to_string(), 0),
            ("A".to_string(), "1".to_string(), 1),
        ];
        let b = vec![
            ("A".to_string(), "1".to_string(), 1),
            ("B".to_string(), "2".to_string(), 0),
        ];
        assert_eq!(
            hash_fields("t", "u", b"p", &urls, "", None, &a),
            hash_fields("t", "u", b"p", &urls, "", None, &b)
        );
    }

    #[test]
    fn hash_excludes_sync_stamps() {
        let urls: Vec<String> = vec![];
        let plain = vec![("A".to_string(), "1".to_string(), 0)];
        let stamped = vec![
            ("A".to_string(), "1".to_string(), 0),
            (SYNC_ID_FIELD.to_string(), "some-uuid".to_string(), 0),
            (SYNC_HASH_FIELD.to_string(), "some-hash".to_string(), 0),
        ];
        assert_eq!(
            hash_fields("t", "u", b"p", &urls, "", None, &plain),
            hash_fields("t", "u", b"p", &urls, "", None, &stamped)
        );
    }

    #[test]
    fn hash_detects_uri_and_type_changes() {
        let one = vec!["https://a.example.com".to_string()];
        let two = vec![
            "https://a.example.com".to_string(),
            "https://b.example.com".to_string(),
        ];
        assert_ne!(
            hash_fields("t", "u", b"p", &one, "", None, &[]),
            hash_fields("t", "u", b"p", &two, "", None, &[])
        );
        let text = vec![("A".to_string(), "1".to_string(), 0)];
        let hidden = vec![("A".to_string(), "1".to_string(), 1)];
        assert_ne!(
            hash_fields("t", "u", b"p", &one, "", None, &text),
            hash_fields("t", "u", b"p", &one, "", None, &hidden)
        );
    }
}
