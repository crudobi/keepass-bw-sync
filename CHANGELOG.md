# Changelog

## Unreleased

- **Adopting a quarantined item now clears its quarantine row.**
  `sync --adopt` resolves the item's `unmapped-bw-item` rows in the
  same journal transaction as the mapping, and each sync reconciles
  stale unmapped rows for already-mapped items -- so an adopted item
  can no longer stay `quarantine_pending` forever. Other quarantine
  kinds still need an explicit `quarantine resolve`.

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
  only — it never writes to Bitwarden (GETs only, enforced structurally).
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
