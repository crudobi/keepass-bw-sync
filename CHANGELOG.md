# Changelog

## Unreleased

- **Restore now honors the sync gates, and delete propagation no longer
  undoes a user's restore.** `restore` skips org-owned items (counted
  as `skipped_org`) and counts entries restored without their blobs
  (`restored_without_blobs`, warned loudly on the CLI) instead of
  reporting silent success while incomplete. Trashed-arm recycles now
  record side `bitwarden-trash`, so an item the user untrashes
  unchanged quarantines as `trash-recycle-reappeared` instead of being
  re-trashed; the tombstone arm skips only completed propagations
  (`keepass`/`both`), so a permanently deleted entry with a live item
  still propagates its delete. `Quarantine` dry-run lines now include
  the reason inline. `BwUri` Debug redacts credential-bearing URIs, the
  dry-run journal copy is 0600 and removed on all exits, and the README
  documents `--dry-run`, `--adopt` auto-resolve, the quarantine kinds,
  and `quarantine resolve` (plus restore-gate bullets and an honest
  threat model for the shipped daemon).

- **Adopting a quarantined item now clears its quarantine row.**
  `sync --adopt` resolves the item's `unmapped-bw-item` rows in the
  same journal transaction as the mapping, and each sync reconciles
  stale unmapped rows for already-mapped items -- so an adopted item
  can no longer stay `quarantine_pending` forever. Other quarantine
  kinds still need an explicit `quarantine resolve`.

- **Dry-run mode, org/attachment quarantine, body cap, and crash-path
  tests.** `sync --dry-run` plans against a throwaway journal copy and
  exits before apply or any vault save (journal and vault bytes
  bit-identical in test). Items with non-empty `collectionIds` quarantine
  as `org-item` and items with attachments as `has-attachments` before
  any other action, under default, `--writeback`, and `--force` alike,
  so full-replace PUTs can never strip org membership. Response bodies
  are capped at 32 MiB inside the JSON-envelope path (a future streaming
  attachment download bypasses it by design). The RecycleKp re-verify
  residual closed via the durable `bitwarden-absence` tombstone side,
  and crash-path integration tests cover post-save journal-commit loss
  and flock contention. The `plan()` purity refactor stopped with cause
  documented; its docstring now inventories every plan-time write.

- **Restore refreshes the Bitwarden cache, missing-arm edit check, and
  proxy hardening.** The restore arm calls `bw.sync()` (a download-only
  POST, so the no-server-writes guarantee survives) before listing, so a
  stale cache can no longer silently under-restore. The
  missing-confirmation arm mirrors the trashed arm: a KeePass edit since
  the watermark turns a confirmed absence into a `delete-vs-edit`
  quarantine instead of a recycle. The client sets `.no_proxy()` (proxy
  env vars can no longer route loopback plaintext through a proxy),
  the `mkvault` doc comment no longer shows the stale `--offline` form,
  and the README `bw` walkthrough covers install paths, `--apikey`
  with `BW_CLIENTID`/`BW_CLIENTSECRET`, interactive 2FA, and `--raw`.

- **Writeback no longer destroys KeePassXC TOTP.** `apply_bw_to_entry`
  retains all TOTP-source fields (`totp`, `otp`, `TOTP Seed`,
  `TOTP Settings`) when the Bitwarden item carries no TOTP; previously
  only `totp` survived the wholesale field replace, so a writeback
  silently deleted a KeePassXC second factor with no quarantine ever
  firing. When the Bitwarden item does carry a TOTP it supersedes the
  old fields, as before.
- **Listing glitches can no longer delete entries on both sides.** A
  mapped Bitwarden item absent from a listing is only recycled after a
  second, independent listing confirms the absence (new `missing_bw`
  journal table, schema v2 with in-place migration); the first sighting
  just records it, and a reappearance clears the record. A genuinely
  trashed Bitwarden item still recycles in one run, and a KeePass-binned
  entry still trashes its Bitwarden copy in one run.
- **No redirects, ever.** The `bw serve` client now refuses redirects
  (`Policy::none`); previously a 307 from an impersonated server would
  have re-sent full secret payloads to another host.
- **Installability:** `rust-version = "1.89"` declared (the real MSRV,
  set by the `keepass` crate); README Prerequisites gain rustup install
  lines; the vault-init command no longer passes `--offline` (it failed
  on an empty cargo cache); a minimal `bw login` → `unlock` → `serve`
  walkthrough; `examples/tweak.rs` reads its new password from stdin
  instead of argv, per the project's no-argv rule.

## 0.1.0 — 2026-11-01 (unreleased on crates.io; private repo)

- `restore` subcommand: rebuild a KeePass vault from Bitwarden, read
  only — it never writes to the Bitwarden server vault (enforced
  structurally: the refresh is a download-only POST /sync, then only
  GET list calls).
  Stamped items keep their stamp UUIDs; unstamped items are adopted
  under fresh UUIDs without stamping back; trashed items skipped.
- 429 retry with create-safety: direct and wrapped-400 rate limits
  back off (hint-capped 30s, else exponential, max 5 attempts); creates
  re-list for the stamp before re-issuing, so a retry never duplicates.
- README documents placement sync, field-type preservation, multi-URI
  round-trip, and the restore procedure (drill-proven: 25/25 items,
  121/121 field hashes, KeePassXC-opened, zero Bitwarden writes).
- Writeback now retains KeePassXC `TOTP Seed`/`TOTP Settings` and
  KeePass2 `otp` when the Bitwarden item carries no TOTP (correction:
  the 2026-10-15 entry overstated this as full writeback TOTP retention;
  that batch kept only the literal `totp` field).

## 2026-10-15

- Full review pass: agreement-refresh instead of quarantining agreeing
  copies, `--force`/`--writeback` honored for genuine concurrent edits,
  KDBX3 fail-fast on write paths, `KBS_SYNC_HASH` as the rebuild
  baseline, vault save permission preservation, `put` holds the journal
  flock, recycle-bin exclusion for `get`/`put`, placement sync
  (top-level group ↔ Bitwarden folder, both directions), stale-revision
  skip-and-quarantine, KeePassXC/KeePass2 TOTP recognition, `--keyfile`,
  field-type and favorite and multi-URI preservation, loopback guard via
  real URL parsing, tombstone bookkeeping for already-trashed items,
  journal schema versioning, writeback retention of only the literal
  `totp` field (full Seed/Settings retention is the 2026-11-01 batch).
- Hygiene pass: shared response gate, URI projection, path formatting,
  vault-open, and test fixtures deduplicated; narrative comments
  trimmed; dead `Secret::is_empty` removed. No behavior change.

## 2026-10-13

- KDBX layer ported from keepass-rs 0.2 to keepass 0.15 (KDBX4.0→4.1
  upgrade shim at open).

## 2026-10-03 – 2026-10-06

- Initial bidirectional KeePass2 ↔ Bitwarden sync engine (v0.1.0):
  local `.kdbx` as source of truth, `KBS_SYNC_ID`/`KBS_SYNC_HASH`
  stamps, SQLite journal (mappings, hashes, tombstones, quarantine),
  KeePass-wins conflicts with quarantine-first handling, revisionDate
  optimistic-concurrency guards, atomic temp+rename saves, zeroized
  in-memory secrets, `get`/`put`/`list`/`sync`/`quarantine`/`journal`
  subcommands, systemd units, headless `bw serve` re-login via API key.
- Tri-persona review fixes: deferred journal commit, listing guards,
  trash revision guard, flock, 0600 perms, quarantine dedup/resolve,
  adopt stamp-back, journal reset.
- Publish prep: MIT license, package metadata, de-personalized docs
  and examples.

## Open-items batch (2026-11-01)

- Plan-to-apply org race closed: edit and stamp payloads echo
  collectionIds from the re-read item when non-empty; the next
  sync plan gate quarantining as org-item is the backstop.
- put reads stdin before taking the journal flock, so an
  interactive put no longer blocks the hourly sync.
- Folder-listing guard: an empty folder listing with
  folder-referencing items fails closed, no changes made.
- New plan gates (all flag modes, before any mutation):
  totp-name-collision and duplicate-field-name quarantines.
- Otpauth label percent-encoded per RFC 3986.
- missing_bw rows are deleted with their mapping.
- bw-serve.sh unlock stderr now goes to a 0600 mktemp file,
  removed on exit (takes effect on next service restart).

## Round-4 top batch (2026-11-01)

- Org-membership echo now carries `organizationId` alongside
  `collectionIds`; stub PUT proves both keys through. Claim kept
  honest: payload preservation, not end-to-end membership proof.
- Tombstone crash orphan closed: a completed-side tombstone with
  a lingering mapping quarantines a live item as
  `tombstone-reappeared` instead of hiding it forever.
- Partial folder listings now fail closed when a placement
  decision needs an unknown folder id.
- `quarantine acknowledge <id>`: accepted persistent conditions
  stop nagging (and stop counting as pending) without bypassing
  any gate; journal schema v3 (additive `acknowledged` column,
  migrates on open).
- Restore warnings now name the skipped-org and blob-less items.
- README kinds list completed; zeroization and daemon
  threat-model docs corrected to what the code actually does.
