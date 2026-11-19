# Fork divergence from upstream

This is a first-party fork of `keepass-rs`. Branch `transformed-key` adds the
ability to capture and re-supply the post-KDF **transformed key** so a caller
can skip the (expensive) Argon2id KDF on a repeat open of the same on-disk
database state. Keep this diff minimal and reviewed; track upstream.

## What changed

- **`src/transformed_key.rs`** (new): `TransformedKey`, a 32-byte newtype. The
  bytes live in `shrouded` secure memory (mlock, guard pages, `MADV_DONTDUMP`,
  zeroize-on-drop). No `Clone`, no `Display`.
- **`Database::open_capturing_key`** (`src/db/open.rs`): a normal open that, for
  KDBX4, also returns the `TransformedKey` it derived (`None` for KDBX3/KDB).
- **`Database::open_with_transformed_key`** (`src/db/open.rs`): open a KDBX4
  database from a supplied `TransformedKey`, skipping the KDF. The key is
  combined with the file's master seed and verified by the header HMAC, so a
  stale/wrong key fails and never decrypts (fails closed).
- **`Database::save_capturing_key`** (`src/db/save.rs`): like `save`, returning
  the transformed key derived under the freshly-rotated KDF seed.
- **`src/format/kdbx4/{parse,dump}.rs`**: the decrypt path is refactored so the
  transformed key is obtained either by running the KDF or from a supplied
  value (`Kdbx4KeySource`); everything after — master-key combine, HMAC verify,
  decrypt — is shared, so the supplied-key path is identical to a normal open
  except for skipping the KDF.

## New dependency

- **`shrouded`** (crates.io): secure-memory backing for `TransformedKey`.
  Upstream may not want this; it is intentional for our use case (the
  transformed key is a vault-password-equivalent and must not sit in plain,
  swappable, dumpable memory).

Tests: `tests/transformed_key.rs` (round-trip, wrong-key HMAC rejection, save
returns a usable key, key bound to the rotating salt).

## Timestamps: jiff, not chrono

Every public timestamp is a `jiff::civil::DateTime` here, where upstream
uses chrono's `NaiveDateTime`. RustSec marks chrono unmaintained
(RUSTSEC-2026-0543). The change is a single commit,
`feat!: replace chrono with jiff`, that touches no fork-only file and
applies to upstream's master as of 26cb076. Drop this section if
upstream moves off chrono.
