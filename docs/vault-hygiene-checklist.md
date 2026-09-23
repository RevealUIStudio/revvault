# Vault hygiene marks (GAP-263)

Annotated inventory of vault paths and namespaces already described in this repo. Each item is marked from in-repo evidence. An owner ruling below overrides an earlier proposal.

This document does not delete, move, or rewrite vault entries. A **RETIRE** mark is a proposal until an owner ruling records **RETIRE APPROVED**. Approval is still not permission to delete a leaf. Deletes wait for a later execute-approved step, with Joshua OK per item if needed. A **CONSOLIDATE** mark names the target path. It is not permission to move a leaf.

Test-only paths (`misc/empty`, `credentials/test-key`, and the other fixtures under `crates/cli/tests/` and `crates/core/tests/`) are not store leaves and are not items below.

## Owner rulings

### 2026-09-23

Joshua:

- `credentials/resend/*` — **RETIRE APPROVED** (2026-09-23). Do not delete `.age` files or vault entries in this change.
- leftover `revealcoin/*` — **RETIRE APPROVED** (2026-09-23). Do not delete `.age` files or vault entries in this change.
- `credentials/huggingface/*` — **KEEP**. Do not retire.

## Sources

| Inventory | Where |
|---|---|
| Canonical path table and store tree | `README.md` |
| Path conventions, storage layout, sync manifest, compose table | `docs/MASTER_SPEC.md` |
| Stream namespace bundles | `docs/STREAM-SAFE.md` |
| Legacy license leaves | `docs/examples/rotation-license-signing.toml`, `docs/rotation-dual-slot-verify.md` |
| Import categorization (including removal notes) | `crates/core/src/import/plaintext.rs` |
| Built-in namespaces | `crates/core/src/namespace.rs` |
| Env-bundle paths | `crates/cli/src/commands/run.rs` |
| Store and identity resolution | `crates/core/src/config.rs` |
| Placeholder examples in the copied fleet rule | `.claude/rules/secrets.md` |

## KEEP

These are the current contract. Code still resolves them, the canonical docs name them with no in-repo removal note, or an owner ruling says KEEP.

| Item | Rationale |
|---|---|
| Namespace `revealui/` | Built-in in `Namespace::builtins()` (`crates/core/src/namespace.rs`). |
| Namespace `credentials/` | Same builtins list. README lists it as a built-in namespace. |
| Namespace `ssh/` | Same builtins list. README store tree includes `ssh/github.age`. |
| Namespace `misc/` | Same builtins list. Import sends uncategorized files here (`plaintext.rs`). |
| `revealui/dev/electric/service-url` | README canonical table and store tree. |
| `revealui/dev/electric/secret` | `docs/MASTER_SPEC.md` path conventions. No second path for this leaf. |
| `revealui/dev/admin-session-cookie` | README canonical table. Spec storage layout shows the same leaf. |
| `revealui/dev/stripe/secret-key` | README `revvault run` example and `docs/STREAM-SAFE.md`. Dev counterpart of the prod Stripe key, not a duplicate of it. |
| `revealui/prod/neon/postgres-url` | README canonical table, spec path conventions, spec sync manifest `DATABASE_URL`, and `docs/STREAM-SAFE.md`. |
| `revealui/prod/stripe/secret-key` | README canonical table, spec path conventions, and spec sync manifest `STRIPE_SECRET_KEY`. |
| `revealui/prod/stripe/webhook-secret` | README canonical table and spec sync manifest `STRIPE_WEBHOOK_SECRET`. |
| `revealui/prod/storage/r2/access-key-id` | README canonical table. No conflicting path in code or docs. |
| `revdev/license-signing-private-key` | README canonical example. `docs/examples/rotation-license-signing.toml` sets `secret_path` to this leaf. |
| `revdev/license-signing-public-key` | Same example toml, `settings.public_key_path`. |
| `revealui/env/<ns>` bundles `revealui/env/stripe` and `revealui/env/neon` | `docs/STREAM-SAFE.md` tells operators to `revvault set` those two files. `run.rs` loads `revealui/env/{ns}`. |
| `revealui/env/license` | `run.rs` maps namespace `license` here. `export_env.rs` documents it as the public-only path. |
| `revealui/env/license-signing` | `run.rs` maps namespace `license-signing` here and refuses it unless `REVVAULT_ALLOW_PRIVATE=1`. |
| Dual-slot suffixes `{path}-next`, `{path}-previous`, `{path}-next-id` | Rotation protocol in `crates/core/src/rotation/executor.rs` and `docs/rotation-dual-slot-verify.md`. Not spare copies of unrelated secrets. |
| `credentials/github/personal-token` | README canonical example under `credentials/<system>/<name>`. |
| `credentials/anthropic/api-key` | README canonical example. Import still files Anthropic and Claude names under `credentials/anthropic`. The import comment says Joshua still holds Anthropic keys (`plaintext.rs`). |
| `credentials/openai/*` | Import comment (2026-04-05): BYOK is no longer a customer path, and the heuristic stays because Joshua personally holds OpenAI keys. Not a delete candidate on that evidence. |
| `credentials/huggingface/*` | Owner ruling 2026-09-23: **KEEP**. Do not retire. |
| `credentials/vercel/*`, `credentials/supabase/*`, `credentials/vultr/*`, `credentials/namecheap/*`, `credentials/redis/*`, `credentials/npm/*`, `credentials/aws/*` | Import heuristics only. No in-repo note says these providers were removed. |
| `ssh/<host>/<key-name>` (example `ssh/github`) | Spec path conventions plus the README store tree. Import files SSH key names under `ssh`. |
| `forge/customers/<slug>/*` | `docs/MASTER_SPEC.md` compose table calls this the live per-customer prefix. Rotation re-mint comments use `forge/customers/*/license-key` (`executor.rs`, `docs/rotation-dual-slot-verify.md`, example toml). |
| Store `~/.revealui/passage-store` | Default in `Config::resolve_store_dir` (`config.rs`) and the README config table. |
| `REVVAULT_STORE` | Same resolver. Wins over `PASSAGE_DIR`. |
| `PASSAGE_DIR` | Still accepted in `config.rs` as the backwards-compat alias. Not a leaf, and still live code, so not a retire. |
| Identity `~/.config/age/keys.txt` | Checked first in `config.rs` and the README. |
| Identity `~/.age-identity/keys.txt` | Still the fallback in `config.rs` when the XDG file is absent. Removing it would break decrypt on machines that only have this file. |
| WSL candidates under `/mnt/c/Users/$WINDOWS_USERNAME/.revealui/passage-store` and `.age-identity/keys.txt` | Extra candidates in `config.rs` when `WINDOWS_USERNAME` is set on Linux. |

## RETIRE APPROVED (2026-09-23)

Joshua approved retirement of these families on 2026-09-23. Still do not delete `.age` files or vault entries until an execute-approved step, with Joshua OK per item if needed.

| Item | Rationale |
|---|---|
| `credentials/resend/*` | **RETIRE APPROVED** (2026-09-23). `plaintext.rs` says Resend left the RevealUI stack on 2026-04-09 in favor of Gmail API. The heuristic remains only so older plaintext dumps still categorize. Resend is absent from the README canonical table. Not deleted. |
| leftover `revealcoin/*` | **RETIRE APPROVED** (2026-09-23). `docs/MASTER_SPEC.md` compose table: RevealCoin was cancelled 2026-05-29, its keypair files were destroyed, and it is no longer a vault consumer. No `revealcoin` path remains in code. Not deleted. |

## CONSOLIDATE (target named)

Name the surviving path. Do not move leaves in this PR.

| Item | Target | Rationale |
|---|---|---|
| `revealui/prod/db/postgres-url` | `revealui/prod/neon/postgres-url` | Sync command comments, `doctor.rs` fixtures, and the CHANGELOG manifest example use the `db` path. The README canonical table, spec path list, spec sync manifest, and `docs/STREAM-SAFE.md` use the `neon` path for the Postgres URL. |
| `credentials/stripe/*` (import bucket and CLI examples such as `credentials/stripe/secret-key`) | `revealui/prod/stripe/<name>` | `plaintext.rs` returns `credentials/stripe`. `get.rs`, `set.rs`, and the spec CLI table use `credentials/stripe/secret-key`. The README canonical leaf is `revealui/prod/stripe/secret-key`. |
| `credentials/neon/*` | `revealui/prod/neon/<name>` | Import returns `credentials/neon`. Canonical Postgres and Neon examples live under `revealui/prod/neon/`. |
| `credentials/database/*` | `revealui/prod/neon/<name>` | Import sends filenames containing `database`, `postgres`, or `db_` to `credentials/database`. The canonical Postgres URL is `revealui/prod/neon/postgres-url`. |
| `credentials/github/token` | `credentials/github/personal-token` | `.claude/rules/secrets.md` example is `credentials/github/token`. README canonical example is `credentials/github/personal-token`. |
| `credentials/github/joshua` | `credentials/github/personal-token` | Spec storage layout shows `credentials/github/joshua.age`. README canonical example is `credentials/github/personal-token`. |
| `revdev/license-signing-key` | `revdev/license-signing-private-key` | Example toml `legacy_private_paths` and the `executor.rs` promote comment. Promote still mirrors the live private key onto this legacy leaf. Joshua approves before that mirror is dropped or the leaf is deleted. |
| `revdev/license-public-key` | `revdev/license-signing-public-key` | Example toml `legacy_public_paths` and the same promote comment. Same mirror rule as the private legacy leaf. |
| `revforge/customers/<slug>/<name>` | `forge/customers/<slug>/*` | README canonical table and store tree use `revforge/customers/...` (CHANGELOG 0.5.0 only marks that example operator/private). The spec compose table calls `forge/customers/<slug>/*` the live prefix, and the rotation re-mint comments use `forge/customers/*/license-key`. |
| `revealui/vercel/<slug>` prefixes in sync comments (`revealui/vercel/admin`, `revealui/vercel/api`) | `revealui/prod/` | Those prefixes appear as `vault_prefix` examples in `crates/cli/src/commands/sync.rs`. The spec manifest example uses `vault_prefix = "revealui/prod/"`. Not listed in the README canonical table. |
| `myapp/dev/database/url`, `myapp/prod/stripe/secret-key`, `myapp/prod/stripe/webhook-secret` | `revealui/dev/...` and `revealui/prod/stripe/...` | Placeholder examples in `.claude/rules/secrets.md` only. No other revvault file uses a `myapp/` namespace. Not evidence of live leaves. |

## Out of scope

- No `revvault delete`, `set`, or store rewrite.
- No edit to `~/.revealui/passage-store` or any `.age` file. RETIRE APPROVED rows stay on disk.
- Import heuristics and promote's legacy-path mirror stay in code until a later change that Joshua has approved.
