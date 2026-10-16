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
    /// Bitwarden URI match strategy (0=default … 6=never). Echoed back on
    /// PUTs so engine edits never silently reset it. Deliberately excluded
    /// from the content hash (see `hash_fields`): KeePass cannot represent
    /// it, so hashing it would permanently disagree on adopted items.
    #[serde(rename = "match", default)]
    pub match_: Option<i32>,
}

#[derive(Clone, Deserialize, Default)]
pub struct BwLogin {
    pub username: Option<String>,
    pub password: Option<String>,
    pub totp: Option<String>,
    pub uris: Option<Vec<BwUri>>,
}

// Redacting Debug: this struct holds plaintext secrets; one stray `{:?}`
// must never land them in a log.
impl std::fmt::Debug for BwLogin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BwLogin")
            .field("username", &self.username)
            .field("password", &self.password.as_ref().map(|_| "<redacted>"))
            .field("totp", &self.totp.as_ref().map(|_| "<redacted>"))
            .field("uris", &self.uris)
            .finish()
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct BwField {
    pub name: String,
    pub value: String,
    /// Bitwarden field type: 0 = text, 1 = hidden, 2 = boolean. Carried
    /// end-to-end so an engine edit never flattens a hidden field into a
    /// visible text field. Defaults to 0 for payloads that omit it.
    #[serde(rename = "type", default)]
    pub field_type: i32,
}

#[derive(Clone, Deserialize)]
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
    /// Bitwarden item type: 1=login, 2=secure note, 3=card, 4=identity.
    /// The engine only manages logins; other types quarantine on adopt.
    #[serde(rename = "type", default)]
    pub item_type: i32,
    /// Master-password reprompt policy. Echoed back on PUTs (the real serve
    /// resets it to None when omitted); excluded from the content hash —
    /// it is a policy flag, not content.
    #[serde(default)]
    pub reprompt: Option<i32>,
}

// Redacting Debug: custom-field values can hold secrets (API keys, …);
// show field names only, never values.
impl std::fmt::Debug for BwItem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BwItem")
            .field("id", &self.id)
            .field("name", &self.name)
            .field("notes", &self.notes.as_ref().map(|_| "<redacted>"))
            .field("favorite", &self.favorite)
            .field("folder_id", &self.folder_id)
            .field("login", &self.login)
            .field(
                "fields",
                &self
                    .fields
                    .iter()
                    .map(|x| &x.name)
                    .collect::<Vec<_>>(),
            )
            .field("revision_date", &self.revision_date)
            .field("deleted_date", &self.deleted_date)
            .field("item_type", &self.item_type)
            .field("reprompt", &self.reprompt)
            .finish()
    }
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
        // All URIs hash, in order (first under "url", rest under "uri") —
        // the same projection the KeePass side builds.
        let urls: Vec<String> = login
            .uris
            .as_ref()
            .map(|us| {
                us.iter()
                    .filter_map(|u| u.uri.clone())
                    .collect::<Vec<String>>()
            })
            .unwrap_or_default();
        let custom: Vec<(String, String, i32)> = self
            .fields
            .iter()
            .filter(|f| f.name != SYNC_ID_FIELD && f.name != SYNC_HASH_FIELD)
            .map(|f| (f.name.clone(), f.value.clone(), f.field_type))
            .collect();
        hash_fields(
            &self.name,
            login.username.as_deref().unwrap_or_default(),
            login.password.as_deref().unwrap_or_default().as_bytes(),
            &urls,
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

/// Outcome of [`BwClient::edit_item`].
#[derive(Debug, PartialEq, Eq)]
pub enum EditOutcome {
    /// The item was updated.
    Updated,
    /// The item's revision changed between plan and apply: the edit was
    /// skipped so the caller can quarantine instead of aborting the run.
    RevisionChanged,
}

/// The serve `message` field, or a placeholder — never the full response
/// body, which a future `bw serve` version could fill with echoed request
/// objects (secret material in logs).
fn serve_message(v: &serde_json::Value) -> &str {
    v.get("message").and_then(|m| m.as_str()).unwrap_or("(no message)")
}

fn is_loopback_host(host: &str) -> bool {
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    host.parse::<std::net::IpAddr>()
        .map(|ip| ip.is_loopback()) // 127.0.0.0/8 and ::1
        .unwrap_or(false)
}

/// Validate a `bw serve` base URL with a real URL parser. The previous
/// hand-rolled host extraction had a parser differential:
/// `http://example.com#@127.0.0.1:8087/` read as loopback (the `#` fragment
/// confused the split logic) while reqwest connected to example.com.
/// Parsing with the same URL implementation the HTTP client uses removes
/// the whole class: scheme must be http, the parsed host must be
/// 127.0.0.0/8, ::1, or localhost, and userinfo is refused outright (it
/// has no legitimate use here and only serves parser confusion).
fn validate_loopback_url(base: &str) -> Result<()> {
    let url = reqwest::Url::parse(base)
        .map_err(|e| anyhow::anyhow!("invalid bw serve URL {base:?}: {e}"))?;
    if url.scheme() != "http" {
        bail!(
            "refusing bw serve URL {base:?}: scheme must be http (bw serve is plaintext loopback HTTP)"
        );
    }
    if !url.username().is_empty() || url.password().is_some() {
        bail!("refusing bw serve URL {base:?}: userinfo is not allowed");
    }
    // host_str serializes IPv6 hosts bracketed ("[::1]"); unbracket
    // before the loopback check.
    let host = url.host_str().unwrap_or_default();
    let host = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    if !is_loopback_host(host) {
        bail!(
            "refusing non-loopback bw serve URL {base:?}: plaintext HTTP would exfiltrate vault secrets; pass --insecure-remote-url to override"
        );
    }
    Ok(())
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
        if !allow_remote {
            validate_loopback_url(base)?;
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
                return serde_json::from_value(inner.clone()).context("parse bw list data");
            }
            return serde_json::from_value(data.clone()).context("parse bw data");
        }
        serde_json::from_value(v).context("parse bw body")
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
    ///
    /// `echo_src` is the current server-side item (present on edit): its
    /// `type`, `reprompt`, and the URI `match` of the synced URL are echoed
    /// back, because the real serve applies `toView` replace semantics —
    /// omitting them would silently reset the URI match strategy and disable
    /// master-password reprompt. Creates have no source item (type 1, no
    /// reprompt, no match).
    pub fn item_payload(
        entry: &CanonicalEntry,
        folder_id: Option<&str>,
        sync_hash_hex: &str,
        echo_src: Option<&BwItem>,
    ) -> serde_json::Value {
        let pw: Zeroizing<String> =
            Zeroizing::new(String::from_utf8_lossy(entry.password.expose()).into_owned());
        let mut fields = vec![
            serde_json::json!({"name": SYNC_ID_FIELD, "value": entry.uuid.to_string(), "type": 0}),
            serde_json::json!({"name": SYNC_HASH_FIELD, "value": sync_hash_hex, "type": 0}),
        ];
        for (k, v, t) in &entry.custom {
            fields.push(serde_json::json!({"name": k, "value": v, "type": t}));
        }
        // Every URI is written, not just the first: truncating to one
        // silently destroyed additional URIs on multi-URI items. Each URI
        // echoes the match strategy of the same URI on the source item
        // when there is one; the engine's KeePass-side model has no
        // per-URI match of its own, so there is nothing else to compare
        // against.
        let src_uris = echo_src
            .and_then(|s| s.login.as_ref())
            .and_then(|l| l.uris.as_ref());
        let mut uris = vec![];
        for u in &entry.uris {
            let m = src_uris
                .and_then(|us| us.iter().find(|x| x.uri.as_deref() == Some(u.as_str())))
                .and_then(|x| x.match_);
            uris.push(serde_json::json!({"uri": u, "match": m}));
        }
        serde_json::json!({
            "type": echo_src.map(|s| s.item_type).unwrap_or(1),
            "name": entry.title,
            "notes": entry.notes,
            // Preserve the item's favorite flag on edit; creates start
            // unfavorited. (Edits used to silently un-favorite.)
            "favorite": echo_src.map(|s| s.favorite).unwrap_or(false),
            "folderId": folder_id,
            "reprompt": echo_src.and_then(|s| s.reprompt),
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
        let payload = Self::item_payload(entry, folder_id, &hash, None);
        let resp = self
            .http
            .post(format!("{}/object/item", self.base))
            .json(&payload)
            .send()
            .context("POST item")?;
        Ok(self.unwrap::<Created>(resp)?.id)
    }

    /// Optimistic-concurrency edit: when `revisionDate` moved between plan
    /// and apply, the edit is skipped and [`EditOutcome::RevisionChanged`]
    /// is returned so the caller can quarantine just that item — the same
    /// graceful handling `trash_item` has always had — instead of aborting
    /// the whole run and discarding every other action's journal commit.
    pub fn edit_item(
        &self,
        id: &str,
        entry: &CanonicalEntry,
        folder_id: Option<&str>,
        expected_revision: &str,
    ) -> Result<EditOutcome> {
        let cur = self.get_item(id)?;
        if cur.revision_date != expected_revision {
            return Ok(EditOutcome::RevisionChanged);
        }
        let hash = entry.content_hash_hex();
        let payload = Self::item_payload(entry, folder_id, &hash, Some(&cur));
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
        Ok(EditOutcome::Updated)
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
    /// stamp fields, echoing back `type`, `reprompt`, and URI `match` —
    /// the real serve applies `toView` replace semantics, so omitting them
    /// would silently reset them. Content hashes exclude the stamps, so the
    /// journal hash recorded at adopt time stays valid.
    pub fn stamp_item(&self, id: &str, kp_uuid: &Uuid, hash_hex: &str) -> Result<()> {
        let it = self.get_item(id)?;
        if it.stamps().0.is_some() {
            return Ok(()); // already stamped
        }
        let mut fields: Vec<serde_json::Value> = it
            .fields
            .iter()
            .map(|f| serde_json::json!({"name": f.name, "value": f.value, "type": f.field_type}))
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
            .map(|u| serde_json::json!({"uri": u.uri, "match": u.match_}))
            .collect();
        let payload = serde_json::json!({
            "type": it.item_type,
            "name": it.name,
            "notes": it.notes,
            "favorite": it.favorite,
            "folderId": it.folder_id,
            "reprompt": it.reprompt,
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
pub(crate) mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    /// (expected request-line prefix, HTTP status, response body)
    type Handlers = Vec<(String, u16, String)>;
    /// Recorded (request line, body) pairs from a capturing stub.
    type CapturedRequests = Arc<Mutex<Vec<(String, Vec<u8>)>>>;

    /// Minimal canned-response HTTP stub. Serves `handlers` in order, one
    /// connection per request; asserts each request line starts with the
    /// expected prefix.
    pub(crate) fn stub_server(handlers: Handlers) -> String {
        stub_server_inner(handlers, None)
    }

    /// Like [`stub_server`], but also records each request's request line
    /// and body, so tests can assert on the exact PUT/POST payload.
    pub(crate) fn stub_server_capturing(handlers: Handlers) -> (String, CapturedRequests) {
        let captured = Arc::new(Mutex::new(Vec::new()));
        let base = stub_server_inner(handlers, Some(captured.clone()));
        (base, captured)
    }

    fn stub_server_inner(handlers: Handlers, captured: Option<CapturedRequests>) -> String {
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
                // Consume the body too, so capturing sees full PUT/POST
                // payloads.
                let header_end = req
                    .windows(4)
                    .position(|w| w == b"\r\n\r\n")
                    .map(|p| p + 4)
                    .unwrap_or(req.len());
                let mut content_length = 0usize;
                for line in String::from_utf8_lossy(&req[..header_end]).lines().skip(1) {
                    if let Some(v) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                        content_length = v.trim().parse().unwrap_or(0);
                    }
                }
                let mut body_bytes = req[header_end..].to_vec();
                while body_bytes.len() < content_length {
                    let n = stream.read(&mut buf).unwrap();
                    if n == 0 {
                        break;
                    }
                    body_bytes.extend_from_slice(&buf[..n]);
                }
                let req_str = String::from_utf8_lossy(&req);
                let line = req_str.lines().next().unwrap_or("").to_string();
                assert!(
                    line.starts_with(prefix.as_str()),
                    "unexpected request line: {line}"
                );
                if let Some(c) = &captured {
                    c.lock().unwrap().push((line, body_bytes));
                }
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

    pub(crate) fn item_json(rev: &str) -> String {
        serde_json::json!({
            "success": true,
            "data": {
                "id": "bw-1", "name": "t", "notes": null, "favorite": false,
                "folderId": null, "type": 1, "reprompt": 0,
                "login": null, "fields": [],
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
            uris: vec![],
            notes: "".into(),
            totp: None,
            custom: vec![],
            group_path: "".into(),
            deleted: false,
        };
        let err = bw.edit_item("bw-1", &entry, None, "r1").unwrap_err();
        assert!(err.to_string().contains("500"), "unexpected error: {err}");
    }

    #[test]
    fn edit_item_skips_on_revision_change() {
        // GET returns r2 while the plan saw r1: no PUT may be issued; the
        // caller quarantines just this item instead of aborting the run.
        let base = stub_server(vec![("GET /object/item/bw-1 ".into(), 200, item_json("r2"))]);
        let bw = BwClient::new(&base).unwrap();
        let entry = crate::canonical::CanonicalEntry {
            uuid: uuid::Uuid::nil(),
            title: "t".into(),
            username: "u".into(),
            password: crate::secret::Secret::from_str("p"),
            url: "".into(),
            uris: vec![],
            notes: "".into(),
            totp: None,
            custom: vec![],
            group_path: "".into(),
            deleted: false,
        };
        let out = bw.edit_item("bw-1", &entry, None, "r1").unwrap();
        assert_eq!(out, EditOutcome::RevisionChanged);
    }

    #[test]
    fn item_payload_preserves_favorite_types_and_all_uris() {
        // One payload must carry: the source item's favorite flag, each
        // custom field's Bitwarden type (hidden stays hidden), and every
        // URI with its echoed match strategy.
        let src: BwItem = serde_json::from_value(serde_json::json!({
            "id": "bw-1", "name": "t", "notes": null, "favorite": true,
            "folderId": null, "type": 1, "reprompt": 0,
            "login": {
                "username": "u", "password": "p", "totp": null,
                "uris": [
                    {"uri": "https://a.example.com", "match": 3},
                    {"uri": "https://b.example.com", "match": null}
                ]
            },
            "fields": [],
            "revisionDate": "r1", "deletedDate": null
        }))
        .unwrap();
        let entry = crate::canonical::CanonicalEntry {
            uuid: uuid::Uuid::nil(),
            title: "t".into(),
            username: "u".into(),
            password: crate::secret::Secret::from_str("p"),
            url: "https://a.example.com".into(),
            uris: vec![
                "https://a.example.com".into(),
                "https://b.example.com".into(),
            ],
            notes: "".into(),
            totp: None,
            custom: vec![
                ("Visible".into(), "v".into(), 0),
                ("Secret Q".into(), "s".into(), 1),
                ("Flag".into(), "true".into(), 2),
            ],
            group_path: "".into(),
            deleted: false,
        };
        let payload = BwClient::item_payload(&entry, None, "hashhex", Some(&src));
        assert_eq!(payload["favorite"], true);
        let fields = payload["fields"].as_array().unwrap();
        let ty = |n: &str| {
            fields
                .iter()
                .find(|f| f["name"] == n)
                .map(|f| f["type"].as_i64().unwrap())
        };
        assert_eq!(ty("Visible"), Some(0));
        assert_eq!(ty("Secret Q"), Some(1));
        assert_eq!(ty("Flag"), Some(2));
        let uris = payload["login"]["uris"].as_array().unwrap();
        assert_eq!(uris.len(), 2);
        assert_eq!(uris[0]["uri"], "https://a.example.com");
        assert_eq!(uris[0]["match"], 3);
        assert_eq!(uris[1]["uri"], "https://b.example.com");
        assert!(uris[1]["match"].is_null());
    }

    #[test]
    fn stamp_item_echoes_type_reprompt_match_and_stamps() {
        // The PUT must carry the stamps plus the echoed type/reprompt/match
        // (replace semantics); content must otherwise be untouched.
        let item = serde_json::json!({
            "success": true,
            "data": {
                "id": "bw-1", "name": "t", "notes": "n", "favorite": true,
                "folderId": null, "type": 1, "reprompt": 1,
                "login": {
                    "username": "u", "password": "p", "totp": null,
                    "uris": [{"uri": "https://example.com", "match": 2}]
                },
                "fields": [
                    {"name": "API key", "value": "abc", "type": 0},
                    {"name": "Secret Q", "value": "shh", "type": 1}
                ],
                "revisionDate": "r1", "deletedDate": null
            }
        })
        .to_string();
        let (base, captured) = stub_server_capturing(vec![
            ("GET /object/item/bw-1 ".into(), 200, item.clone()),
            ("PUT /object/item/bw-1 ".into(), 200, r#"{"success":true}"#.into()),
        ]);
        let bw = BwClient::new(&base).unwrap();
        bw.stamp_item("bw-1", &uuid::Uuid::nil(), "deadbeef").unwrap();

        let captured = captured.lock().unwrap();
        assert_eq!(captured.len(), 2);
        let put = serde_json::from_slice::<serde_json::Value>(&captured[1].1).unwrap();
        // Echoed policy/type fields.
        assert_eq!(put["type"], 1);
        assert_eq!(put["reprompt"], 1);
        assert_eq!(put["login"]["uris"][0]["match"], 2);
        // Stamps appended; existing content intact.
        let names: Vec<&str> = put["fields"]
            .as_array()
            .unwrap()
            .iter()
            .map(|f| f["name"].as_str().unwrap())
            .collect();
        assert!(names.contains(&"API key"));
        assert!(names.contains(&"KBS_SYNC_ID"));
        assert!(names.contains(&"KBS_SYNC_HASH"));
        // Field types ride through stamping: hidden stays hidden.
        let secret_q = put["fields"]
            .as_array()
            .unwrap()
            .iter()
            .find(|f| f["name"] == "Secret Q")
            .unwrap();
        assert_eq!(secret_q["type"], 1);
        assert_eq!(put["login"]["username"], "u");
        assert_eq!(put["login"]["password"], "p");
        assert_eq!(put["notes"], "n");
        assert_eq!(put["favorite"], true);
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

    #[test]
    fn new_rejects_url_parser_differentials() {
        // The old hand-rolled host parser read this as loopback (text
        // after '#' looked like the authority to it) while reqwest
        // connected to example.com. The real parser must reject it.
        assert!(BwClient::new("http://example.com#@127.0.0.1:8087/").is_err());
        // Userinfo is refused even on a loopback host.
        assert!(BwClient::new("http://user@127.0.0.1:8087").is_err());
        assert!(BwClient::new("http://user:pass@127.0.0.1:8087").is_err());
        // Scheme must be http: bw serve has no TLS, and an https URL here
        // would be a different service entirely.
        assert!(BwClient::new("https://127.0.0.1:8087").is_err());
        assert!(BwClient::new("ftp://127.0.0.1:8087").is_err());
        // A fragment after a genuine loopback authority is harmless: the
        // connection really does go to 127.0.0.1.
        assert!(BwClient::new("http://127.0.0.1:8087/#frag").is_ok());
        // Garbage is garbage.
        assert!(BwClient::new("not a url").is_err());
        assert!(BwClient::new("127.0.0.1:8087").is_err());
    }
}
