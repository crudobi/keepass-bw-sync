# keepass-bw-sync

Bidirectional KeePass2 ↔ Bitwarden sync engine in Rust. The local `.kdbx`
is the **source of truth**; the Bitwarden vault is the encrypted offsite copy.

## Prerequisites

- **Bitwarden CLI** `bw` on `PATH` (tested with `bw` 2026.9.1) plus a
  Bitwarden account. The engine talks to `bw serve`'s local HTTP API; it
  never contacts bitwarden.com directly.
- **Rust** stable toolchain (`cargo`, `rustc`), MSRV 1.89 (set by the
  `keepass` crate; declared as `rust-version` in `Cargo.toml`). Install
  with rustup if needed:
  ```sh
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
  source "$HOME/.cargo/env"
  ```
  Note: in a non-interactive SSH session `~/.cargo/bin` is not on `PATH`
  by default — export it or source the env file above.
- Linux for the `deploy/systemd/` units (optional — the binary itself is
  portable).

## Install

```sh
cargo build --release
# or: cargo install --path .
```

Put the release binary on `PATH` (e.g. `/usr/local/bin/keepass-bw-sync`),
then run an unlocked `bw serve` on loopback and point `sync` at your vault
and journal — see [Deployment example](#deployment-example).

## Threat model (honest)

True perfect forward secrecy is **not** achievable for data at rest: both
vaults have persistent master keys, so a compromised master secret decrypts
everything ever encrypted under it. What this engine does instead:

- Both vaults are decrypted **strictly in RAM**; only entry passwords and the master password live in `Secret`,
  a `Vec<u8>` newtype that is zeroized on drop and implements no
  `Debug`/`Display`/`Clone`/`Serialize`; TOTP seeds, notes,
  custom-field values, and keyfile bytes are plain in RAM.
- Transient plaintext at the Bitwarden JSON boundary uses
  `zeroize::Zeroizing<String>`.
- The SQLite journal stores **hashes and identities only** — never secrets —
  but the hashes are unsalted SHA-256, so a weak password is
  offline-brute-forceable from a stolen journal.
- No plaintext is ever written to disk: `.kdbx` saves go through
  temp-file + fsync + atomic rename; `bw export --format json` is never used.
- The shipped `bw-serve.service` runs `bw serve` permanently unlocked on
  loopback (`Restart=always`) — the daemon form of this tool is NOT
  short-lived unlock → sync → wipe. Its confinement is the loopback-only
  bind, `User=crudobi`, `NoNewPrivileges`, and `PrivateTmp` — but `bw
  serve` has NO peer authentication on loopback TCP, so without a
  further boundary any local UID could dump, create, edit, and trash
  vault items through the API. Those mitigations confine the daemon
  process, not its API peers. Low severity on a true single-user box;
  on a multi-user box this needs a real boundary. The author's
  deployment has one: ufw `before.rules` ACCEPTs loopback TCP to port
  8087 only for uid 0 and uid 1001, then DROPs every other local UID
  (probed: an unprivileged UID times out). The shipped units do NOT
  include those rules — a multi-user install must add its own boundary
  (ufw owner-match, Unix socket, nftables owner-match, or auth proxy).
  Manual runs are short-lived by contrast, and `BW_SESSION` is never
  persisted by this tool.

Known limitations: `reqwest`/`serde_json` make their own in-RAM copies of
request bodies that we cannot zeroize; the `bw serve` leg is plaintext HTTP
on loopback with no peer authentication in the daemon itself — the
author's deployment seals it with ufw owner-match rules (loopback TCP
to port 8087 only for uid 0 and uid 1001), but the shipped units do
not include them, so a multi-user install must add its own boundary.

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
  entry history); `--force` lets KeePass overwrite them. Genuine concurrent
  edits (both sides changed to *different* content) quarantine by default
  and honor the same two flags; when both sides changed to the *same*
  content — e.g. after a crash between a Bitwarden write and the journal
  commit — the watermark simply refreshes instead of quarantining two
  agreeing copies.
- **Deletes:** propagate only into the other side's *recoverable* bin
  (Bitwarden trash ↔ KeePass recycle bin). KDBX `DeletedObject` tombstones
  are honored; nothing auto-resurrects, so deletes stay deleted.
- **Writes to Bitwarden** are optimistic-concurrency: the item's
  `revisionDate` is re-read and the write aborts on mismatch.
- **Fidelity:** placement syncs both ways (top-level KeePass group ↔
  Bitwarden folder; adopted entries land in the group named by their
  folder). Custom-field types ride through (hidden stays hidden), every
  URI round-trips (first in the URL field, the rest in `URL <n>` fields),
  and the favorite flag and URI match strategies survive edits.
- **Rate limits** are retried, not fatal: HTTP 429 — including 400s that
  embed an upstream 429 — backs off (parsed `Try again in Ns` hint, else
  exponential 1s→30s, max 5 attempts). Creates, folders, and deletes
  re-check server state before re-issuing, so a retry can never duplicate
  an item or delete twice; a limit that survives all attempts fails the
  run without committing anything, and the next run reconciles.

## Usage

```sh
# bw serve must be running and unlocked:
bw serve --port 8087 &

keepass-bw-sync sync \
  --kdbx /path/to/vault.kdbx \
  --journal /path/to/sync.db

`--journal` defaults to `sync.db` next to the vault when omitted (same
default as `put`; `restore`'s new journal defaults the same way).

# preview only: prints the planned actions and exits without applying
# anything and without mutating the journal or the vault:
keepass-bw-sync sync --dry-run \
  --kdbx /path/to/vault.kdbx \
  --journal /path/to/sync.db

# review what the engine refused to touch, and clear a row once you
# have dealt with it:
keepass-bw-sync quarantine --journal /path/to/sync.db
keepass-bw-sync quarantine --journal /path/to/sync.db resolve <id>
keepass-bw-sync quarantine --journal /path/to/sync.db acknowledge <id>
```

Master password comes from `KBS_MASTER_PASSWORD` or an interactive prompt (except `restore`, which takes its password from `KBS_MASTER_PASSWORD` only — see `restore` below).

Quarantine kinds you may see: `org-item` (owned by an organization —
never synced), `has-attachments` (carries files this engine does not
sync), `unmapped-bw-item` (Bitwarden-only; adopt it with `sync
--adopt`), `foreign-bw-edit` / `concurrent-edit` (Bitwarden changed
since last sync), `delete-vs-edit`, `absence-recycle-reappeared` /
`trash-recycle-reappeared` (an engine-recycled entry whose Bitwarden
item came back unchanged — restore the entry from the KeePass recycle
bin, or delete the Bitwarden item, to clear it), `totp-name-collision`
(a Bitwarden custom field named like a TOTP source — rename the field
to clear it), `duplicate-field-name` (two Bitwarden custom fields
sharing a name — rename one to clear it), `orphan_bw_stamp` (a
Bitwarden item stamped for a KeePass entry that does not exist —
remove the stamp fields to re-adopt, or resolve if intentional), `tombstone-reappeared` (a completed delete whose Bitwarden item is live again — delete the Bitwarden item, or acknowledge if intentional).
Resolving a row whose condition persists only clears it until the next
sync, which re-queues it: for a condition you have accepted (an org
item you will not sync, an item with attachments), use `quarantine
acknowledge <id>` instead — the row stays listed and marked, its item
stays untouched, and it no longer counts as pending; if the condition
later clears, the row auto-resolves on the next sync. Adopting an item with
`sync --adopt` resolves its `unmapped-bw-item` rows in the same journal
transaction as the mapping, and each sync reconciles stale unmapped
rows for already-mapped items; every other kind still needs an explicit
`quarantine resolve` (or `acknowledge`, for a persistent condition you
have accepted).

### Bitwarden CLI setup (one time)

The engine only ever talks to a local `bw serve`; it never contacts
bitwarden.com directly. Get that server running first.

Install `bw` if it is not already present: the native binary from
bitwarden.com/download, or `npm install -g @bitwarden/cli`.

```sh
bw login            # interactive: email + password, then 2FA if enabled
bw unlock --raw     # prints only the session key; capture it cleanly
export BW_SESSION=<key from bw unlock>
bw serve --port 8087 &
```

Headless / 2FA accounts: log in with an API key instead. Create the key
in the web vault (Settings → Security → Keys), then:

```sh
export BW_CLIENTID=<client_id> BW_CLIENTSECRET=<client_secret>
bw login --apikey   # reads the pair from those env vars, no prompt
bw unlock --raw
export BW_SESSION=<key from bw unlock>
bw serve --port 8087 &
```

Notes: an API-key login authenticates but does not unlock — you still
unlock with the master password. Interactive 2FA is `bw login --method
<method> --code <code>` (see `bw login --help` for method values).
`--raw` on both `login` and `unlock` prints only the session key, so
`export BW_SESSION=$(bw unlock --raw)` captures it without parsing.

For unattended use, `deploy/systemd/bw-serve.service` automates this
(headless re-login via API key, 2FA-safe) — see
[Deployment example](#deployment-example).

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

## Restoring from Bitwarden

When the local vault is gone, rebuild it from Bitwarden with `restore`.
It reuses the proven adoption code (`adopt_bw_entry`: folder → group,
TOTP, all URIs, typed custom fields), and it writes a fresh journal so
the restored vault syncs cleanly afterwards.

```sh
KBS_MASTER_PASSWORD='...' keepass-bw-sync restore \
  --kdbx /path/to/restored.kdbx \
  --journal /path/to/restored-sync.db
# --bw-url http://127.0.0.1:8087 (default) and --keyfile are supported
# like the other commands; --insecure-remote-url opts out of the
# loopback guard, same as for sync.
```

What it restores:

- **Stamped items** (engine-managed, carrying `KBS_SYNC_ID`) under their
  stamp UUID — that UUID is the entry's true identity, so the next sync
  matches them instead of quarantining them as `orphan_bw_stamp`.
- **Unstamped items** (Bitwarden-only) too, under freshly minted UUIDs —
  a restore that dropped them would be incomplete.
- **Trashed items are NOT restored** (`deletedDate` set in Bitwarden).
- **Org-owned items are NOT restored** (non-empty `collectionIds`) —
  restore never copies org credentials into a personal vault, mirroring
  the sync gate. They are counted as `skipped_org` in the report.
- **Items with attachments ARE restored, but without their blobs** —
  this engine does not transfer blobs. They are counted as
  `restored_without_blobs` and the CLI warns loudly about them, so a
  restore never reports silent success while incomplete. The blobs
  survive server-side; the next `sync` quarantines these items as
  `has-attachments` until blobs sync.
- The new journal maps uuid → Bitwarden id with the `KBS_SYNC_HASH`
  stamp as baseline when present, else the live content hash (the M1
  rule). A subsequent `sync` against the restored vault + new journal +
  the same Bitwarden state plans **0 actions**.

No-server-writes guarantee: restore first refreshes serve's local
cache with a download-only `bw.sync()` (it mutates no server vault —
without it, a stale cache could silently under-restore), then issues
only the two GET list calls (`list_items`, `list_folders`) — no
creates, edits, trash, or stamps. Unstamped items are deliberately NOT
stamped back: stamping would be a Bitwarden write, and restore must
not mutate the source it is recovering from.

Unstamped-orphan caveat (stated, not silent): because unstamped items
are not stamped back, their only identity record is the new journal. If
that journal is later lost, those items are orphans again — a later
`sync --adopt` would re-adopt them under yet another UUID rather than
matching them. Stamped items do not have this problem: their identity
survives in the Bitwarden stamp itself. Back up the journal with the
vault.

Target safety: the normal case is a brand-new vault at a nonexistent
path; restoring into an explicitly empty vault file is also allowed.
Restore **refuses** an existing non-empty vault (fail closed, clear
error) — it never merges into a live vault. The new vault's password
comes from `KBS_MASTER_PASSWORD` only; restore fails closed when it is
unset and never falls back to an interactive prompt, so a mistyped
password cannot silently lock you out of the recovery you just made.

Verification steps after a restore:

1. `keepass-bw-sync list --kdbx /path/to/restored.kdbx` shows the
   expected `group/title` inventory (titles only, no values).
2. Open the restored vault in KeePassXC with the password from
   `KBS_MASTER_PASSWORD` and spot-check an entry's fields.
3. `keepass-bw-sync sync --kdbx /path/to/restored.kdbx --journal
   /path/to/restored-sync.db` plans 0 actions against unchanged
   Bitwarden state.
4. Confirm Bitwarden itself is untouched: its revision state is
   identical before and after (restore performs no writes there).

Background: a 2026-11-01 restore drill proved the data round-trips
before this subcommand existed — 25/25 live items restored, 24/24
production titles present (the one extra was a Bitwarden-only item),
121/121 field-value hashes matched, KeePassXC opened the restored
vault, zero Bitwarden writes. Note that `sync --adopt` is still NOT a
restore path: a stamped item whose KeePass entry is missing quarantines
as `orphan_bw_stamp` by design (adopting it would mint a phantom
identity), and `--adopt` stamps unstamped items back onto Bitwarden (a
write). Use `restore` for recovery; use `sync --adopt` only for
adopting new Bitwarden items into an existing, live vault.

## Deployment example

One proven layout: the local `.kdbx` is the source of truth for machine
secrets; Bitwarden is the encrypted offsite copy. Consumers read secrets
with `get` — they never need the sync journal or Bitwarden access.

The examples below use `$SECRETS_DIR` for the directory holding your vault
files (keep the files 0600 inside a 0700 directory).

```sh
# print one field to stdout with no trailing newline (script-safe):
keepass-bw-sync get --kdbx "$SECRETS_DIR/vault.kdbx" \
  --title "Deploy Key" --field password
# field: password (default) | username | url | totp | notes | <custom name>
```

Exact title match; duplicates error listing each entry's group path so you
can disambiguate. Unknown fields error listing the available names.

### Writing entries: `put`

```sh
# create (group is created when missing):
printf '%s' "$PW" | keepass-bw-sync put --kdbx vault.kdbx \
  --title "Deploy Key" --group "Ops" --username deploy \
  --url https://example.com --password-stdin
# replace the existing entry's fields in place (only provided fields change):
printf '%s' "$NEWPW" | keepass-bw-sync put --kdbx vault.kdbx \
  --title "Deploy Key" --password-stdin --update
# inventory without exposing values:
keepass-bw-sync list --kdbx vault.kdbx
```

**No-argv rule:** secret material comes only from `--password-stdin` /
`--password-file` (and the `--notes-*` variants) — never from argv, which
is visible in `ps`. `--*-stdin` fails closed when stdin is a terminal
(nothing piped). `--username` / `--url` are argv-safe (not secret alone).

**Trim rule:** exactly one trailing newline (`\n` or `\r\n`) is stripped
from stdin/file input, so `echo` output and editor-saved files work as-is;
anything beyond that is part of the secret.

Duplicate titles fail closed unless `--update` (matched by exact title
globally; `--update` never moves an entry between groups, and `--group`
is ignored then). `list` prints one `group/title` per line, sorted;
root-group entries print as bare titles; recycle-bin entries are excluded.
`put` saves the database atomically after mutation. Neither `put` nor
`list` touches Bitwarden; `put` holds the sync journal lock (via
`--journal`, defaulting to `sync.db` next to the vault) for its whole
read-modify-save, so it serializes safely against the hourly `kbs-sync`
run.

**Keyfiles:** vaults protected with a keyfile work via `--keyfile <path>`
(or the `KBS_KEYFILE` env var) on every command.

### Files

- `$SECRETS_DIR/vault.kdbx` — the vault (0600)
- `$SECRETS_DIR/vault.env.cred` — `KBS_MASTER_PASSWORD`, sealed with
  `systemd-creds` (TPM2, 0600). The plaintext `vault.env` exists only
  transiently while sealing — see "TPM sealing" — and must not stay on disk.
- `$SECRETS_DIR/sync.db` — sync journal (created on first sync)
- `$SECRETS_DIR/bw.env.cred` — `BW_PASSWORD` (and/or `BW_CLIENTID` /
  `BW_CLIENTSECRET`), sealed the same way.

(The author's machine uses `/store/muscle/secrets` for `$SECRETS_DIR`.)

### systemd units

`deploy/systemd/` holds the unit sources. Install them to
`/etc/systemd/system/` and `/usr/local/bin/` (`systemd-analyze verify`
clean), then work through the `# EDIT:` markers at the top of each file for
your username and paths. Leave them disabled until the Bitwarden account is
hardened (see checklist). Also copy `deploy/systemd/kbs-tpm-wrapper.py`
to `/usr/local/bin/` and `chmod 0755` it — both units exec through it
(see "TPM sealing").

- `bw-serve.service` — supervised `bw serve` via `bw-serve.sh`
  (`Restart=always`; fails closed when the sealed `bw.env` credential is
  missing or unsealable, and when `BW_PASSWORD` is unset).
- `kbs-sync.service` — oneshot sync with default safe flags
  (no `--force` / `--adopt` / `--writeback`; foreign Bitwarden edits
  quarantine for human review). `Requires=bw-serve.service`.
- `kbs-sync.timer` — hourly, `Persistent=true`, `RandomizedDelaySec=600`.

### TPM sealing

On a machine with TPM2, the master passwords never live on disk as
plaintext. Create each env file once (0600), seal it, then delete the
plaintext:

```sh
# vault.env holds KBS_MASTER_PASSWORD=<password>; bw.env holds
# BW_PASSWORD=<password> (and/or BW_CLIENTID / BW_CLIENTSECRET).
# Type the values at a prompt rather than sourcing a password file.
sudo systemd-creds encrypt --with-key=tpm2 --tpm2-pcrs=0+7 \
  --name=vault.env "$SECRETS_DIR/vault.env" "$SECRETS_DIR/vault.env.cred"
sudo systemd-creds encrypt --with-key=tpm2 --tpm2-pcrs=0+7 \
  --name=bw.env "$SECRETS_DIR/bw.env" "$SECRETS_DIR/bw.env.cred"
sudo chmod 0600 "$SECRETS_DIR/vault.env.cred" "$SECRETS_DIR/bw.env.cred"
rm "$SECRETS_DIR/vault.env" "$SECRETS_DIR/bw.env"
```

Details that matter:

- `--with-key=tpm2` seals to the TPM only (not `auto`, which would also
  require the host key — an extra on-disk dependency with no gain against
  disk theft). `--tpm2-pcrs=0+7` binds the seal to firmware (PCR 0) and
  Secure Boot policy (PCR 7); no PIN, so unattended sync keeps working.
  On a box with Secure Boot disabled the PCR 7 half is weak and PCR 0
  does the real work.
- **The credential name is bound.** `systemd-creds` embeds a name in the
  blob, and PID1 refuses a credential whose embedded name differs from
  the name declared in `LoadCredentialEncrypted=` (exit 243). The name
  comes from `--name=` — it must be `vault.env` / `bw.env`, matching the
  unit files; the blob filename alone does not set it. `decrypt` needs
  `--name=` too when the file name differs.
- **Why the wrapper exists.** `EnvironmentFile=` cannot consume a
  credential: PID1 reads env files before the per-service credentials
  directory is set up, so both `%d` and the literal
  `/run/credentials/<unit>/<name>` fail with "Failed to load environment
  files" (systemd 257, verified). The sanctioned pattern is for the
  process itself to read `$CREDENTIALS_DIRECTORY/<name>` at runtime —
  that is what `kbs-tpm-wrapper.py` (Python stdlib only) does: it parses
  the decrypted file as env-file syntax, exports the variables, and
  execs the command. It never prints values.
- **What sealing does and does not do.** It protects the disk: a stolen
  disk, a backup copy, or any process that can read the files gets
  ciphertext that only this machine's TPM can open. It does NOT protect
  against live root on the running machine — the password still has to
  be in RAM while the tool decrypts the vault, and nothing can change
  that.
- **Rotation.** A firmware update (PCR 0) or Secure Boot policy change
  (PCR 7) breaks unseal: `bw-serve` enters a restart loop and syncs
  fail. Re-encrypt with the same commands above — from the
  human-supplied password, since the old blob can no longer be opened —
  then restart the services. TPM or board death breaks automation the
  same way; the vault itself is unaffected.
- **Break-glass is the human passwords.** Once the plaintext files are
  deleted, the only way back is the passwords you know (plus the sealed
  blobs while the PCRs hold). Do not delete the plaintext until both
  services have been verified running on the sealed blobs.

Machines without TPM2 use the plaintext-env fallback instead: keep
`vault.env` / `bw.env` (0600 in a 0700 directory) and put
`EnvironmentFile=` back in the units in place of
`LoadCredentialEncrypted=` + the wrapper. That is strictly less secure —
anyone who can read the disk can read the passwords — so prefer sealing
whenever the hardware allows it.

### Account-hardening checklist (unblocks enabling the timer)

1. Rotate the Bitwarden master password if it was ever exposed.
2. Enable 2FA on the Bitwarden account.
3. Seal both env files (see "TPM sealing"): create `vault.env` (0600)
   with `KBS_MASTER_PASSWORD=...` and `bw.env` (0600) with
   `BW_PASSWORD=...` (or `BW_CLIENTID` / `BW_CLIENTSECRET` for API-key
   login, which bypasses 2FA for headless use), encrypt both with
   `systemd-creds`, then delete the plaintext files.
4. `sudo systemctl enable --now bw-serve.service kbs-sync.timer`
5. Migrate secrets into the vault one by one, verifying each with
   `keepass-bw-sync get`.
6. Run a restore drill ([Restoring from Bitwarden](#restoring-from-bitwarden)) before trusting the offsite copy.

### One-off vault init

`examples/mkvault.rs` creates an empty KDBX4 vault. It reads
`KBS_MASTER_PASSWORD` from the environment and fails closed when unset:

`mkvault` creates the vault 0600 itself. Type the password at a
prompt rather than sourcing a password file — sourcing breaks on
shell-significant characters:

```sh
read -rsp "vault password: " KBS_MASTER_PASSWORD; echo
export KBS_MASTER_PASSWORD
cargo run --example mkvault -- "$SECRETS_DIR/vault.kdbx"
```

## Limitations

- **No attachment sync** (see Roadmap): large secrets such as SSH private
  keys are stored as text in notes fields. It works, but it is clunky for
  many or large files.
- **Sustained Bitwarden rate limits** still fail a run after 5 backoff
  attempts — safely (nothing commits, the next run reconciles) — but a
  bulk first-sync against a throttled account may need a second run.
- **`bw serve` is loopback-only plaintext HTTP by design.**
  `--insecure-remote-url` exists for exotic setups, but a remote URL
  exfiltrates vault secrets — only ever point it at hosts you fully trust.
- The `deploy/systemd/` units are Linux-specific; the Rust binary itself is
  portable.

## Layout

- `src/main.rs` — CLI (`sync`/`restore`/`quarantine`/`journal`/`get`/`put`/`list`)
- `src/secret.rs` — zeroized secret newtype
- `src/canonical.rs` — canonical entry model + content hashing
- `src/kdbx.rs` — open/walk/save .kdbx (keepass 0.15)
- `src/bw.rs` — `bw serve` client with revision guards
- `src/journal.rs` — SQLite mappings, tombstones, quarantine
- `src/sync.rs` — plan/apply engine + unit tests
- `src/restore.rs` — rebuild a vault from Bitwarden (download-only)
- `src/stamps.rs` — `KBS_SYNC_ID` / `KBS_SYNC_HASH` field names
- `tests/integration.rs` — end-to-end vs a stub `bw serve`
- `tests/restore_cli.rs` — CLI-level restore tests vs a stub `bw serve`
- `examples/mkvault.rs` — one-off empty-vault creator (0600)
- `examples/mkdb.rs` — fixture-vault builder for tests/drills
- `examples/tweak.rs` — one-off entry editor (password via stdin)

## Roadmap

- Sealed-box (X25519 ephemeral) transport for any multi-process deployment
- Attachment sync via content-hash identity
- Passkey (`KPEX_PASSKEY_*` ↔ `fido2Credentials`) round-trip
- `systemd --user` timer unit for scheduled runs
