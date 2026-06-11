# Changelog

All notable changes to revvault are documented here. Follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) conventions; versions follow [SemVer 2.0.0](https://semver.org/).

## [0.3.0] — 2026-06-11

### Fixed

- **`sync vercel --apply` no longer downgrades Vercel `sensitive` env vars to
  `encrypted` on re-create.** `create_env_var` previously hardcoded
  `type=encrypted`; re-creating a var that existed as `sensitive` (after an
  external delete, or when the surviving rows sit on non-synced targets)
  silently made the credential revealable in the Vercel UI — observed
  2026-06-10 when a sync apply re-created Stripe + signing secrets as
  `encrypted`. Creates now preserve sensitivity: if any remote row with the
  same key is `sensitive`, the new row is created `sensitive`. Updates were
  already safe (the value-only PATCH never touches type).

### Added

- **`sensitive = true` per-var manifest marker.** `[projects.<slug>.vars]`
  inline tables accept `sensitive = true` to request Vercel type `sensitive`
  on create: `KEY = { path = "...", sensitive = true }`. The inline table's
  `shape` is now optional (defaults to `any`). Unknown keys in a var entry
  are rejected at parse time so a typo'd marker fails loudly instead of
  silently leaving a credential downgradable. (`revvault doctor` tolerates
  and ignores the marker — it validates vault values, not Vercel types.)
- **`sensitive` flag on rotation sync targets.** `[[providers.<name>.sync.vercel.env_vars]]`
  entries accept `sensitive = true` so the rotation chain's create-fallback
  also requests type `sensitive`.
- **Type visibility.** Push diffs annotate creates that will request
  `sensitive` and warn on type drift (manifest wants `sensitive` but the
  remote row is not — updates preserve type, so flipping requires delete +
  re-create). The JSONL audit log records `var_type` on create entries.
- **Loud type rejection.** If Vercel rejects the requested type, the create
  fails naming that type — there is no silent fallback to `encrypted`.

### Changed

- The sync audit log now writes to the `.revvault/` directory of the store
  the sync actually used, instead of re-resolving configuration.

## [0.2.0] — 2026-05-14

### Breaking changes

- **`--pull` removed from `revvault sync vercel`** (closes incident-2026-05-11). The
  inverted-direction primitive (Vercel → vault) is gone. `revvault` is the
  canonical age-encrypted store; Vercel is a downstream copy. Any invocation
  that passed `--pull` will now error with a migration message pointing at
  `docs/bootstrap-from-vercel.md`. See the spec at
  `docs/specs/revvault-sync-durable-redesign.md` for the full rationale.

### Added

- **`revvault doctor [--manifest <path>] [--json]`** — vault-only health check.
  Reads every var declared in a sync manifest, fetches the vault value, and
  validates it against the declared shape. Never touches Vercel. Exit code `0`
  when all entries pass; `1` when any entry fails or is missing. Use before any
  push, after any vault mutation (set / edit / rotate / migrate / restore).

- **`crates/core/src/sync/shape.rs`** — new shape-validation module. Provides
  `Shape` (13 variants: `any`, `postgres-url`, `https-url`, `stripe-key`,
  `stripe-key-live-only`, `stripe-webhook`, `stripe-resource`, `pem-private-key`,
  `pem-public-key`, `hex32`, `hex64`, `email`, `flag`), `ShapeViolation`, and
  `check`/`classify` functions. All checks are prefix-match + length +
  character-class predicates — no regex.

- **Shape validation on push** — `revvault sync vercel --apply` now validates
  every vault value against its declared shape before calling the Vercel API.
  Values that fail the check (empty, null-literal, Vercel v2 envelope, or
  declared-shape mismatch) are logged as `drop-shape` audit entries and skipped;
  the push continues for the remaining entries.

- **Shape validation in rotation sync hook** — `push_to_vercel` in
  `crates/core/src/rotation/sync_hook.rs` applies the same universal structural
  checks (empty / null / envelope) to the fresh rotation outcome before making
  any Vercel API call. A misbehaving rotation provider (e.g., one that returns
  an empty body) can no longer poison Vercel.

- **Rotation provider `output_shape`** — optional field on
  `[providers.<name>]` in `rotation.toml`. When declared, the executor validates
  the fresh rotation outcome against the shape **before** writing to the vault.
  A mismatch aborts the rotation and leaves the old key in place.

- **MATCH skip on push** — `revvault sync vercel --apply` now attempts to fetch
  decrypted remote values via `decrypt=true` (requires `env:read:decrypted` scope
  on the Vercel token). When vault and Vercel values match, the API call is
  skipped and a `match` audit entry is recorded. Falls back gracefully to
  assume-drift (current behavior) when the token lacks the scope (403).

- **`value_shape` in audit log** — every audit entry now includes a
  `value_shape` field (e.g., `"postgres-url"`, `"stripe-key"`, `"empty"`,
  `"vercel-envelope"`) so log review surfaces corruption without needing to
  re-read the vault. Applies to both the sync audit log and the rotation sync
  hook's `SyncLogEntry`.

- **Manifest per-var shape declarations** — `[projects.<slug>.vars]` now
  accepts an inline-table form:
  ```toml
  POSTGRES_URL = { path = "revealui/prod/db/postgres-url", shape = "postgres-url" }
  ```
  Bare-string entries (`POSTGRES_URL = "revealui/prod/db/postgres-url"`) continue
  to work unchanged (shape defaults to `any`). Existing manifests require no
  changes.

- **`list_env_vars_with_values`** on `VercelClient` — fetches env vars with
  `decrypt=true` for MATCH detection. Returns `Ok(None)` on 403 (scope missing)
  so callers can fall back safely.

### Removed

- `pull_mode` function in `crates/cli/src/commands/sync.rs`
- `detect_path_collisions` function (was only used to gate pull)
- `pull: bool` field from `SyncArgs`

## [0.1.0] — initial release

First working version. Age-encrypted vault, CLI, Tauri desktop app, rotation
providers, and the bidirectional `sync vercel` command (now superseded in 0.2.0
by the push-only redesign).
