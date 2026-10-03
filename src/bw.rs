//! Bitwarden client over a local `bw serve` HTTP API.
//!
//! Assumes `bw serve` is already running and unlocked on loopback. All vault
//! crypto stays client-side (zero-knowledge); this transport only ever sees
//! ciphertext on the wire to the real server. On a multi-user box, prefer a
//! Unix-socket front or seal payloads, since `bw serve` is plaintext HTTP.
//!
//! Writes use optimistic concurrency: [`BwClient::edit_item`] re-reads the
//! item's `revisionDate` and aborts when it moved under us.

use std::time::Duration;

use anyhow::{bail, Context, Result};
use reqwest::blocking::Client;
use serde::Deserialize;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::canonical::{hash_fields, CanonicalEntry};
use crate::stamps::{SYNC_HASH_FIELD, SYNC_ID_FIELD};

#[derive(Debug, Clone, Deserialize, Default)]
pub struct BwUri {
    pub uri: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct BwLogin {
    pub username: Option<String>,
    pub password: Option<String>,
    pub totp: Option<String>,
    pub uris: Option<Vec<BwUri>>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct BwField {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct BwItem {
    pub id: String,
    pub name: String,
    pub notes: Option<String>,
    pub favorite: bool,
    #[serde(rename = "folderId")]
    pub folder_id: Option<String>,
    pub login: Option<BwLogin>,
    #[serde(default)]
    pub fields: Vec<BwField>,
    #[serde(rename = "revisionDate")]
    pub revision_date: String,
    #[serde(rename = "deletedDate")]
    pub deleted_date: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct BwFolder {
    pub id: String,
    pub name: String,
}

impl BwItem {
    /// (sync_id, sync_hash) stamps, when present.
    pub fn stamps(&self) -> (Option<String>, Option<String>) {
        let mut id = None;
        let mut hash = None;
        for f in &self.fields {
            if f.name == SYNC_ID_FIELD {
                id = Some(f.value.clone());
            } else if f.name == SYNC_HASH_FIELD {
                hash = Some(f.value.clone());
            }
        }
        (id, hash)
    }

    /// Content hash in the same space as [`CanonicalEntry::content_hash`].
    pub fn content_hash(&self) -> [u8; 32] {
        let login = self.login.clone().unwrap_or_default();
        let url = login
            .uris
            .as_ref()
            .and_then(|u| u.first())
            .and_then(|u| u.uri.clone())
            .unwrap_or_default();
        let custom: Vec<(String, String)> = self
            .fields
            .iter()
            .filter(|f| f.name != SYNC_ID_FIELD && f.name != SYNC_HASH_FIELD)
            .map(|f| (f.name.clone(), f.value.clone()))
            .collect();
        hash_fields(
            &self.name,
            login.username.as_deref().unwrap_or_default(),
            login.password.as_deref().unwrap_or_default().as_bytes(),
            &url,
            self.notes.as_deref().unwrap_or_default(),
            login.totp.as_deref(),
            &custom,
        )
    }

    pub fn content_hash_hex(&self) -> String {
        hex::encode(self.content_hash())
    }

    pub fn trashed(&self) -> bool {
        self.deleted_date.is_some()
    }
}

pub struct BwClient {
    base: String,
    http: Client,
}

/// Outcome of [`BwClient::trash_item`].
#[derive(Debug, PartialEq, Eq)]
pub enum TrashOutcome {
    /// The item was moved to the Bitwarden trash.
    Trashed,
    /// The item's revision changed between plan and apply: the delete was
    /// skipped so the caller can quarantine instead.
    RevisionChanged,
}

/// The serve `message` field, or a placeholder — never the full response
/// body, which a future `bw serve` version could fill with echoed request
/// objects (secret material in logs).
fn serve_message(v: &serde_json::Value) -> &str {
    v.get("message").and_then(|m| m.as_str()).unwrap_or("(no message)")
}

/// Host part of an http(s):// URL, without port or brackets.
fn url_host(base: &str) -> Option<String> {
    let authority = base.split("://").nth(1)?.split('/').next()?;
    let authority = authority.rsplit('@').next()?; // strip userinfo
    if let Some(inner) = authority.strip_prefix('[') {
        return inner.split(']').next().map(str::to_string); // IPv6 literal
    }
    authority.split(':').next().map(str::to_string)
}

fn is_loopback_host(host: &str) -> bool {
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    host.parse::<std::net::IpAddr>()
        .map(|ip| ip.is_loopback()) // 127.0.0.0/8 and ::1
        .unwrap_or(false)
}

impl BwClient {
    /// Connect to a `bw serve` base URL. Rejects non-loopback hosts: the
    /// transport is plaintext HTTP with no auth, so a remote URL would
    /// exfiltrate vault secrets.
    pub fn new(base: &str) -> Result<Self> {
        Self::new_with_remote(base, false)
    }

    /// Like [`BwClient::new`], but permits non-loopback hosts when the caller
    /// explicitly opts in (CLI `--insecure-remote-url`).
    pub fn new_with_remote(base: &str, allow_remote: bool) -> Result<Self> {
        let host = url_host(base).unwrap_or_default();
        if !allow_remote && !is_loopback_host(&host) {
            bail!(
                "refusing non-loopback bw serve URL {base:?}: plaintext HTTP would exfiltrate vault secrets; pass --insecure-remote-url to override"
            );
        }
        let http = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .context("build reqwest client")?;
        Ok(BwClient {
            base: base.trim_end_matches('/').to_string(),
            http,
        })
    }

    /// Unwrap `{"success":true,"data":...}` envelopes; tolerate raw bodies.
    fn unwrap<T: for<'de> Deserialize<'de>>(&self, resp: reqwest::blocking::Response) -> Result<T> {
        let status = resp.status();
        let v: serde_json::Value = resp.json().context("parse bw serve response")?;
        if !status.is_success() {
            bail!("bw serve HTTP {}: {}", status, serve_message(&v));
        }
        if let Some(data) = v.get("data") {
            // list endpoints nest once more: {"object":"list","data":[...]}
            if let Some(inner) = data.get("data") {
                return Ok(serde_json::from_value(inner.clone()).context("parse bw list data")?);
            }
            return Ok(serde_json::from_value(data.clone()).context("parse bw data")?);
        }
        Ok(serde_json::from_value(v).context("parse bw body")?)
    }

    pub fn sync(&self) -> Result<()> {
        let resp = self
            .http
            .post(format!("{}/sync", self.base))
            .send()
            .context("POST /sync")?;
        let status = resp.status();
        let v: serde_json::Value = resp.json().context("parse /sync")?;
        if !status.is_success() {
            bail!("bw sync HTTP {}: {}", status, serve_message(&v));
        }
        if v.get("success").and_then(|s| s.as_bool()) == Some(false) {
            bail!("bw sync reported failure: {}", serve_message(&v));
        }
        Ok(())
    }

    pub fn list_items(&self) -> Result<Vec<BwItem>> {
        let resp = self
            .http
            .get(format!("{}/list/object/items", self.base))
            .send()
            .context("GET items")?;
        self.unwrap(resp)
    }

    pub fn get_item(&self, id: &str) -> Result<BwItem> {
        let resp = self
            .http
            .get(format!("{}/object/item/{}", self.base, id))
            .send()
            .with_context(|| format!("GET item {}", id))?;
        self.unwrap(resp)
    }

    pub fn list_folders(&self) -> Result<Vec<BwFolder>> {
        let resp = self
            .http
            .get(format!("{}/list/object/folders", self.base))
            .send()
            .context("GET folders")?;
        self.unwrap(resp)
    }

    pub fn create_folder(&self, name: &str) -> Result<String> {
        #[derive(Deserialize)]
        struct Created {
            id: String,
        }
        let resp = self
            .http
            .post(format!("{}/object/folder", self.base))
            .json(&serde_json::json!({ "name": name }))
            .send()
            .context("POST folder")?;
        Ok(self.unwrap::<Created>(resp)?.id)
    }

    /// Build the `bw create/edit item` payload. The password is copied into a
    /// `Zeroizing<String>` so the transient plaintext is wiped after use.
    pub fn item_payload(
        entry: &CanonicalEntry,
        folder_id: Option<&str>,
        sync_hash_hex: &str,
    ) -> serde_json::Value {
        let pw: Zeroizing<String> =
            Zeroizing::new(String::from_utf8_lossy(entry.password.expose()).into_owned());
        let mut fields = vec![
            serde_json::json!({"name": SYNC_ID_FIELD, "value": entry.uuid.to_string(), "type": 0}),
            serde_json::json!({"name": SYNC_HASH_FIELD, "value": sync_hash_hex, "type": 0}),
        ];
        for (k, v) in &entry.custom {
            fields.push(serde_json::json!({"name": k, "value": v, "type": 0}));
        }
        let mut uris = vec![];
        if !entry.url.is_empty() {
            uris.push(serde_json::json!({"uri": entry.url}));
        }
        serde_json::json!({
            "type": 1,
            "name": entry.title,
            "notes": entry.notes,
            "favorite": false,
            "folderId": folder_id,
            "fields": fields,
            "login": {
                "username": entry.username,
                "password": pw.as_str(),
                "totp": entry.totp,
                "uris": uris,
            }
        })
    }

    pub fn create_item(
        &self,
        entry: &CanonicalEntry,
        folder_id: Option<&str>,
    ) -> Result<String> {
        #[derive(Deserialize)]
        struct Created {
            id: String,
        }
        let hash = entry.content_hash_hex();
        let payload = Self::item_payload(entry, folder_id, &hash);
        let resp = self
            .http
            .post(format!("{}/object/item", self.base))
            .json(&payload)
            .send()
            .context("POST item")?;
        Ok(self.unwrap::<Created>(resp)?.id)
    }

    /// Optimistic-concurrency edit: abort when `revisionDate` moved.
    pub fn edit_item(
        &self,
        id: &str,
        entry: &CanonicalEntry,
        folder_id: Option<&str>,
        expected_revision: &str,
    ) -> Result<()> {
        let cur = self.get_item(id)?;
        if cur.revision_date != expected_revision {
            bail!(
                "stale write on {}: revision {} != expected {}",
                id,
                cur.revision_date,
                expected_revision
            );
        }
        let hash = entry.content_hash_hex();
        let payload = Self::item_payload(entry, folder_id, &hash);
        let resp = self
            .http
            .put(format!("{}/object/item/{}", self.base, id))
            .json(&payload)
            .send()
            .with_context(|| format!("PUT item {}", id))?;
        let status = resp.status();
        let v: serde_json::Value = resp.json().context("parse PUT item")?;
        if !status.is_success() {
            bail!("bw edit HTTP {}: {}", status, serve_message(&v));
        }
        if v.get("success").and_then(|s| s.as_bool()) == Some(false) {
            bail!("bw edit reported failure: {}", serve_message(&v));
        }
        Ok(())
    }

    /// Soft delete (moves to trash). With `expected_revision`, re-reads the
    /// item first and refuses to delete when it changed under us, returning
    /// [`TrashOutcome::RevisionChanged`] so the caller can quarantine instead.
    pub fn trash_item(&self, id: &str, expected_revision: Option<&str>) -> Result<TrashOutcome> {
        if let Some(exp) = expected_revision {
            let cur = self.get_item(id)?;
            if cur.revision_date != exp {
                return Ok(TrashOutcome::RevisionChanged);
            }
        }
        let resp = self
            .http
            .delete(format!("{}/object/item/{}", self.base, id))
            .send()
            .with_context(|| format!("DELETE item {}", id))?;
        let status = resp.status();
        let v: serde_json::Value = resp.json().context("parse DELETE item")?;
        if !status.is_success() {
            bail!("bw delete HTTP {}: {}", status, serve_message(&v));
        }
        if v.get("success").and_then(|s| s.as_bool()) == Some(false) {
            bail!("bw delete reported failure: {}", serve_message(&v));
        }
        Ok(TrashOutcome::Trashed)
    }

    /// Stamp `KBS_SYNC_ID` / `KBS_SYNC_HASH` onto an existing item (adopt
    /// path: the item predates the engine). Skips when already stamped.
    /// Operates on a fresh read; the PUT carries the full item plus the two
    /// stamp fields. Content hashes exclude the stamps, so the journal hash
    /// recorded at adopt time stays valid.
    pub fn stamp_item(&self, id: &str, kp_uuid: &Uuid, hash_hex: &str) -> Result<()> {
        let it = self.get_item(id)?;
        if it.stamps().0.is_some() {
            return Ok(()); // already stamped
        }
        let mut fields: Vec<serde_json::Value> = it
            .fields
            .iter()
            .map(|f| serde_json::json!({"name": f.name, "value": f.value, "type": 0}))
            .collect();
        fields.push(
            serde_json::json!({"name": SYNC_ID_FIELD, "value": kp_uuid.to_string(), "type": 0}),
        );
        fields.push(
            serde_json::json!({"name": SYNC_HASH_FIELD, "value": hash_hex, "type": 0}),
        );
        let login = it.login.clone().unwrap_or_default();
        let uris: Vec<serde_json::Value> = login
            .uris
            .unwrap_or_default()
            .iter()
            .map(|u| serde_json::json!({"uri": u.uri}))
            .collect();
        let payload = serde_json::json!({
            "type": 1,
            "name": it.name,
            "notes": it.notes,
            "favorite": it.favorite,
            "folderId": it.folder_id,
            "fields": fields,
            "login": {
                "username": login.username,
                "password": login.password,
                "totp": login.totp,
                "uris": uris,
            },
        });
        let resp = self
            .http
            .put(format!("{}/object/item/{}", self.base, id))
            .json(&payload)
            .send()
            .with_context(|| format!("PUT stamp item {}", id))?;
        let status = resp.status();
        let v: serde_json::Value = resp.json().context("parse PUT stamp item")?;
        if !status.is_success() {
            bail!("bw stamp HTTP {}: {}", status, serve_message(&v));
        }
        if v.get("success").and_then(|s| s.as_bool()) == Some(false) {
            bail!("bw stamp reported failure: {}", serve_message(&v));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal canned-response HTTP stub. Serves `handlers` in order, one
    /// connection per request; asserts each request line starts with the
    /// expected prefix.
    fn stub_server(handlers: Vec<(String, u16, String)>) -> String {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            use std::io::{Read, Write};
            for (prefix, status, body) in handlers {
                let (mut stream, _) = listener.accept().unwrap();
                let mut req = Vec::new();
                let mut buf = [0u8; 1024];
                loop {
                    let n = stream.read(&mut buf).unwrap();
                    if n == 0 {
                        break;
                    }
                    req.extend_from_slice(&buf[..n]);
                    if req.windows(4).any(|w| w == b"\r\n\r\n") {
                        break;
                    }
                }
                let req = String::from_utf8_lossy(&req);
                let line = req.lines().next().unwrap_or("");
                assert!(
                    line.starts_with(prefix.as_str()),
                    "unexpected request line: {line}"
                );
                let reason = if status == 200 { "OK" } else { "Error" };
                let resp = format!(
                    "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(resp.as_bytes());
            }
        });
        format!("http://{addr}")
    }

    fn item_json(rev: &str) -> String {
        serde_json::json!({
            "success": true,
            "data": {
                "id": "bw-1", "name": "t", "notes": null, "favorite": false,
                "folderId": null, "login": null, "fields": [],
                "revisionDate": rev, "deletedDate": null
            }
        })
        .to_string()
    }

    #[test]
    fn trash_item_skips_on_revision_change() {
        // GET returns r2 while the plan saw r1: the item changed under us.
        // No DELETE may be issued; the caller quarantines instead.
        let base = stub_server(vec![("GET /object/item/bw-1 ".into(), 200, item_json("r2"))]);
        let bw = BwClient::new(&base).unwrap();
        let out = bw.trash_item("bw-1", Some("r1")).unwrap();
        assert_eq!(out, TrashOutcome::RevisionChanged);
    }

    #[test]
    fn trash_item_trashes_on_matching_revision() {
        let base = stub_server(vec![
            ("GET /object/item/bw-1 ".into(), 200, item_json("r1")),
            (
                "DELETE /object/item/bw-1 ".into(),
                200,
                r#"{"success":true,"data":{}}"#.into(),
            ),
        ]);
        let bw = BwClient::new(&base).unwrap();
        let out = bw.trash_item("bw-1", Some("r1")).unwrap();
        assert_eq!(out, TrashOutcome::Trashed);
    }

    #[test]
    fn trash_item_without_expected_revision_skips_guard() {
        let base = stub_server(vec![(
            "DELETE /object/item/bw-1 ".into(),
            200,
            r#"{"success":true,"data":{}}"#.into(),
        )]);
        let bw = BwClient::new(&base).unwrap();
        let out = bw.trash_item("bw-1", None).unwrap();
        assert_eq!(out, TrashOutcome::Trashed);
    }

    #[test]
    fn sync_rejects_http_error_without_success_field() {
        // A 503 whose body lacks "success" used to be treated as success.
        let base = stub_server(vec![(
            "POST /sync ".into(),
            503,
            r#"{"message":"upstream unavailable"}"#.into(),
        )]);
        let bw = BwClient::new(&base).unwrap();
        let err = bw.sync().unwrap_err();
        assert!(err.to_string().contains("503"), "unexpected error: {err}");
    }

    #[test]
    fn edit_rejects_http_error() {
        let base = stub_server(vec![
            ("GET /object/item/bw-1 ".into(), 200, item_json("r1")),
            (
                "PUT /object/item/bw-1 ".into(),
                500,
                r#"{"message":"boom"}"#.into(),
            ),
        ]);
        let bw = BwClient::new(&base).unwrap();
        let entry = crate::canonical::CanonicalEntry {
            uuid: uuid::Uuid::nil(),
            title: "t".into(),
            username: "u".into(),
            password: crate::secret::Secret::from_str("p"),
            url: "".into(),
            notes: "".into(),
            totp: None,
            custom: vec![],
            group_path: "".into(),
            last_modified_ms: 0,
            deleted: false,
        };
        let err = bw.edit_item("bw-1", &entry, None, "r1").unwrap_err();
        assert!(err.to_string().contains("500"), "unexpected error: {err}");
    }

    #[test]
    fn new_rejects_non_loopback_urls() {
        assert!(BwClient::new("http://192.168.1.5:8087").is_err());
        assert!(BwClient::new("http://example.com:8087").is_err());
        assert!(BwClient::new("http://[2001:db8::1]:8087").is_err());
        assert!(BwClient::new("http://127.0.0.1:8087").is_ok());
        assert!(BwClient::new("http://127.1.2.3:8087").is_ok());
        assert!(BwClient::new("http://[::1]:8087").is_ok());
        assert!(BwClient::new("http://localhost:8087").is_ok());
        // Explicit opt-in bypasses the check.
        assert!(BwClient::new_with_remote("http://192.168.1.5:8087", true).is_ok());
        assert!(BwClient::new_with_remote("http://127.0.0.1:8087", true).is_ok());
    }
}
