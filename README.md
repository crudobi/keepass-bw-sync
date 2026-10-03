# keepass-bw-sync

Bidirectional KeePass2 ↔ Bitwarden sync engine in Rust. The local `.kdbx`
on this box is the **source of truth**; the Bitwarden vault syncs to it.

## Threat model (honest)

True perfect forward secrecy is **not** achievable for data at rest: both
vaults have persistent master keys, so a compromised master secret decrypts
everything ever encrypted under it. What this engine does instead:

- Both vaults are decrypted **strictly in RAM**; secrets live in `Secret`,
  a `Vec<u8>` newtype that is zeroized on drop and implements no
  `Debug`/`Display`/`Clone`/`Serialize`.
- Transient plaintext at the Bitwarden JSON boundary uses
  `zeroize::Zeroizing<String>`.
- The SQLite journal stores **hashes and identities only** — never secrets.
- No plaintext is ever written to disk: `.kdbx` saves go through
  temp-file + fsync + atomic rename; `bw export --format json` is never used.
- Sync runs are short-lived: unlock → sync → wipe. `BW_SESSION` is never
  persisted by this tool.

Known limitations: `reqwest`/`serde_json` make their own in-RAM copies of
request bodies that we cannot zeroize; the `bw serve` leg is plaintext HTTP
on loopback (fine single-user; seal or socket it on multi-user boxes).

## How it works

- **Identity (hybrid):** the KeePass entry UUID is stamped into a Bitwarden
  custom field `KBS_SYNC_ID` (durable, survives export/import); the local
  SQLite journal maps UUID ↔ Bitwarden id plus last-synced content hashes,
  watermarks, and tombstones.
- **Change detection:** SHA-256 over canonical fields (title, username,
  password, url, notes, totp, custom fields). Never file-byte hashes:
  KDBX rotates seeds/IVs/KDF salt on every save.
- **Conflicts:** KeePass-wins by policy. Foreign Bitwarden edits (hash ≠
  `KBS_SYNC_HASH` stamp) **quarantine** for human review — never silently
  overwritten. `--writeback` applies them into KeePass (loser preserved in
  entry history); `--force` lets KeePass overwrite them. Concurrent edits on
  both sides always quarantine: no automatic merge for secrets.
- **Deletes:** propagate only into the other side's *recoverable* bin
  (Bitwarden trash ↔ KeePass recycle bin). KDBX `DeletedObject` tombstones
  are honored; nothing auto-resurrects, so deletes stay deleted.
- **Writes to Bitwarden** are optimistic-concurrency: the item's
  `revisionDate` is re-read and the write aborts on mismatch.

## Usage

```sh
# bw serve must be running and unlocked:
bw serve --port 8087 &

keepass-bw-sync sync \
  --kdbx /path/to/vault.kdbx \
  --journal /path/to/sync.db

# review what the engine refused to touch:
keepass-bw-sync quarantine --journal /path/to/sync.db
```

Master password comes from `KBS_MASTER_PASSWORD` or an interactive prompt.

## Recovering from the listing guard

A sync refuses to run when the Bitwarden listing looks wrong (empty or
missing most mapped items) — that pattern is usually a `bw serve` hiccup,
not a real delete. If you genuinely deleted most of your vault server-side,
reset the journal; the next sync rebuilds every mapping from the
`KBS_SYNC_ID` stamps:

```sh
keepass-bw-sync journal reset --journal /path/to/sync.db
```

The old journal is archived to `sync.bak-<unix-timestamp>` (quarantine
history and tombstones preserved for forensics).

## Dev-loop secrets integration (phase 1)

The local `.kdbx` is the source of truth for machine secrets; Bitwarden is
the encrypted offsite copy ("survival offsite"). Workers consume secrets
with `get` — they never need the sync journal or Bitwarden access.

```sh
# print one field to stdout with no trailing newline (script-safe):
keepass-bw-sync get --kdbx /store/muscle/secrets/vault.kdbx \
  --title "Deploy Key" --field password
# field: password (default) | username | url | totp | notes | <custom name>
```

Exact title match; duplicates error listing each entry's group path so you
can disambiguate. Unknown fields error listing the available names.

### Layout on waflurgiooh

- `/store/muscle/secrets/vault.kdbx` — production vault (0600)
- `/store/muscle/secrets/vault.env` — `KBS_MASTER_PASSWORD=...` (0600, never printed)
- `/store/muscle/secrets/sync.db` — sync journal (created on first sync)
- `/store/muscle/secrets/bw.env` — `BW_PASSWORD=...` (0600) — DOES NOT EXIST YET

### systemd units (installed, NOT enabled)

`deploy/systemd/` holds the unit sources. They are installed to
`/etc/systemd/system/` and `/usr/local/bin/` (`systemd-analyze verify`
clean) but deliberately left disabled — the Bitwarden account is not
hardened yet (see checklist).

- `bw-serve.service` — supervised `bw serve` via `/usr/local/bin/bw-serve.sh`
  (`Restart=always`; fails closed when `BW_PASSWORD` is unset; the
  `EnvironmentFile=-...` is optional until the account is hardened).
- `kbs-sync.service` — oneshot sync with default safe flags
  (no `--force` / `--adopt` / `--writeback`; foreign Bitwarden edits
  quarantine for human review). `Requires=bw-serve.service`.
- `kbs-sync.timer` — hourly, `Persistent=true`, `RandomizedDelaySec=600`.

The release binary is installed at `/usr/local/bin/keepass-bw-sync`.

### Account-hardening checklist (unblocks enabling the timer)

1. Rotate the Bitwarden master password (the test password is compromised —
   it appeared in a chat transcript).
2. Enable 2FA on the Bitwarden account.
3. Create `/store/muscle/secrets/bw.env` (0600) with `BW_PASSWORD=...`
   (or `BW_CLIENTID` / `BW_CLIENTSECRET` for API-key login, which bypasses
   2FA for headless use).
4. `sudo systemctl enable --now bw-serve.service kbs-sync.timer`
5. Migrate secrets into the vault one by one, verifying each with
   `keepass-bw-sync get`.
6. Run a restore drill: fresh host, `bw` login, export, rebuild — before
   trusting the offsite copy.

### One-off vault init

`examples/mkvault.rs` creates an empty KDBX4 vault. It reads
`KBS_MASTER_PASSWORD` from the environment and fails closed when unset:

```sh
set -a; source /store/muscle/secrets/vault.env; set +a
cargo run --offline --example mkvault -- /store/muscle/secrets/vault.kdbx
chmod 600 /store/muscle/secrets/vault.kdbx
```

## Layout

- `src/secret.rs` — zeroized secret newtype
- `src/canonical.rs` — canonical entry model + content hashing
- `src/kdbx.rs` — open/walk/save .kdbx (keepass-rs)
- `src/bw.rs` — `bw serve` client with revision guards
- `src/journal.rs` — SQLite mappings, tombstones, quarantine
- `src/sync.rs` — plan/apply engine + unit tests
- `tests/integration.rs` — end-to-end vs a stub `bw serve`

## Roadmap

- Sealed-box (X25519 ephemeral) transport for any multi-process deployment
- Attachment sync via content-hash identity
- Passkey (`KPEX_PASSKEY_*` ↔ `fido2Credentials`) round-trip
- `systemd --user` timer unit for scheduled runs
