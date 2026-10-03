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

impl BwClient {
    pub fn new(base: &str) -> Self {
        let http = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .expect("reqwest client");
        BwClient {
            base: base.trim_end_matches('/').to_string(),
            http,
        }
    }

    /// Unwrap `{"success":true,"data":...}` envelopes; tolerate raw bodies.
    fn unwrap<T: for<'de> Deserialize<'de>>(&self, resp: reqwest::blocking::Response) -> Result<T> {
        let status = resp.status();
        let v: serde_json::Value = resp.json().context("parse bw serve response")?;
        if !status.is_success() {
            bail!("bw serve HTTP {}: {}", status, v);
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
        let v: serde_json::Value = resp.json().context("parse /sync")?;
        if v.get("success").and_then(|s| s.as_bool()) == Some(false) {
            bail!("bw sync reported failure: {}", v);
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
        let v: serde_json::Value = resp.json().context("parse PUT item")?;
        if v.get("success").and_then(|s| s.as_bool()) == Some(false) {
            bail!("bw edit reported failure: {}", v);
        }
        Ok(())
    }

    /// Soft delete (moves to trash).
    pub fn trash_item(&self, id: &str) -> Result<()> {
        let resp = self
            .http
            .delete(format!("{}/object/item/{}", self.base, id))
            .send()
            .with_context(|| format!("DELETE item {}", id))?;
        let v: serde_json::Value = resp.json().context("parse DELETE item")?;
        if v.get("success").and_then(|s| s.as_bool()) == Some(false) {
            bail!("bw delete reported failure: {}", v);
        }
        Ok(())
    }
}
