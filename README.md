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
