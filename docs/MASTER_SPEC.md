---
type: master-spec
repo: revvault
last-updated: 2026-05-10
owner: RevealUI Studio
staleness-status: FRESH
---

# RevVault — Master Spec

**Last Updated:** 2026-05-10
**Status:** Pre-1.0 — production-grade for studio internal use; surface area stable
**Repo:** [RevealUIStudio/revvault](https://github.com/RevealUIStudio/revvault)

> Surface area, architecture, contracts. Companion to [`MASTER_PLAN.md`](./MASTER_PLAN.md) (status + roadmap).

---

## Mission

Age-encrypted secret vault for RevFleet. Source of truth for every secret per the fleet-wide secrets rule. CLI + Tauri 2 desktop app. 100% [passage](https://github.com/FiloSottile/passage)-compatible.

The trust story compresses to one sentence: *Secrets live in RevVault, encrypted by an age identity that doesn't leave the developer's machine.*

---

## Repository structure

```
revvault/
├── Cargo.toml                # workspace root
├── crates/
│   ├── core/                 # vault primitives — age encryption, path validation, namespace logic
│   ├── cli/                  # binary `revvault` — get/set/list/search/delete/edit/export-env/generate/sync
│   └── tauri-app/            # Tauri 2 backend (Rust commands) for the desktop UI
├── frontend/                 # React 19 desktop UI (consumes tauri-app commands)
├── scripts/                  # support scripts (test fixtures, dev helpers)
├── flake.nix                 # Nix dev shell
├── rust-toolchain.toml       # pinned Rust version
└── deny.toml                 # cargo-deny rules
```

### Crate boundaries

| Crate | Responsibility | Dependencies |
|---|---|---|
| `core` | age encryption/decryption, path validation, namespace parsing, vault traversal, manifest parsing | `age`, `serde`, `toml` |
| `cli` | argv parsing, command dispatch, terminal IO (clipboard, prompts), shell-friendly output | `core`, `clap`, `dialoguer` |
| `tauri-app` | Tauri command handlers wrapping `core` for the desktop UI | `core`, `tauri` |

The frontend never touches `core` directly — it goes through `tauri-app` IPC. This boundary keeps secret handling in Rust and out of the JS heap.

---

## CLI surface

| Command | Purpose | Example |
|---|---|---|
| `revvault get <path>` | Decrypt + print one secret to stdout (or clipboard via `--clip`) | `revvault get credentials/stripe/secret-key` |
| `revvault get --json <path>` | JSON output (path + value) — use this in non-TTY contexts; bare `get` returns empty in `$()` (per memory `feedback_revvault_get_silent_in_subshell`) | `revvault --json get credentials/stripe/secret-key \| jq -r .value` |
| `revvault set <path>` | Encrypt + store from stdin or interactive prompt | `echo "sk_live_..." \| revvault set credentials/stripe/secret-key` |
| `revvault list [<prefix>]` | List secret paths, optionally namespace-filtered | `revvault list credentials/` |
| `revvault search <query>` | Fuzzy search across paths | `revvault search stripe` |
| `revvault delete <path>` | Remove a secret | `revvault delete credentials/old-key` |
| `revvault edit <path>` | Decrypt → open in `$EDITOR` → re-encrypt on save | `revvault edit credentials/stripe/secret-key` |
| `revvault export-env [<prefix>]` | Materialize `.env`-shaped output for direnv | `revvault export-env revealui/dev/ > .envrc.secret` |
| `revvault generate` | Generate a strong password (CSPRNG) | `revvault generate \| revvault set credentials/new` |
| `revvault sync vercel [--manifest <path>]` | Show diff between vault + Vercel env vars (default = dry-run; manifest defaults to `revvault-vercel.toml`) | `revvault sync vercel --manifest revvault-vercel.toml` |
| `revvault sync vercel --apply [--manifest <path>]` | Push vault values to Vercel; shape-validates each value before the API call | `revvault sync vercel --apply` |
| `revvault sync vercel --token <token> ...` | Override Vercel API token (or set `VERCEL_TOKEN` env var) | `revvault sync vercel --apply --token $VERCEL_TOKEN` |
| `revvault doctor [--manifest <path>] [--json]` | **0.2.0+** Vault-only health check — validates every manifest entry against its declared shape; exit 0 = all pass, exit 1 = failures found. Never touches Vercel. | `revvault doctor --manifest revvault-vercel.toml` |

### Path conventions

Paths are lower-kebab, grouped by repo/product, then subsystem:

```
<project>/<subsystem>/<name>
```

Examples:

```
revealui/dev/electric/service-url
revealui/dev/electric/secret
revealui/prod/neon/postgres-url
revealui/prod/stripe/secret-key
revealui/prod/stripe/webhook-secret
revealcoin/mint-authority.json
revdev/license-signing-key
credentials/github/<account>
credentials/anthropic/<account>
ssh/<host>/<key-name>
```

The first path segment is the **namespace**; commands accept namespace prefixes for `list`/`export-env`/`sync`.

---

## Storage layout

```
$HOME/.revealui/passage-store/             # default vault root
├── revealui/
│   ├── dev/
│   │   ├── electric/
│   │   │   ├── service-url.age
│   │   │   └── secret.age
│   │   └── admin-session-cookie.age
│   └── prod/...
├── revealcoin/
│   └── mint-authority.json.age
├── credentials/
│   └── github/joshua.age
└── ...
```

Each `.age` file is the encrypted secret. Filenames preserve the secret's logical extension (`.json`, `.pem`, etc.) ahead of `.age`.

### Identity

The age identity is read from `~/.age-identity/keys.txt` by default (override via `--identity <path>`). This file should never leave the developer's machine — that's the encryption boundary.

---

## Tauri desktop UI

Built on Tauri 2 + React 19. Surface mirrors the CLI plus richer browse/search:

| UI surface | Backed by |
|---|---|
| Search bar (fuzzy) | `core::search` via `tauri-app::search_secrets` |
| Tree browser (namespaces) | `core::list` via `tauri-app::list_secrets` |
| Detail pane (reveal/copy/delete/edit) | `core::{get,set,delete}` via tauri commands |
| Add new secret | `core::set` via `tauri-app::create_secret` |
| Import flow | `core::import` (categorizes by path heuristic) |

The desktop app is currently used internally; public release is **Phase 2** in `MASTER_PLAN.md` (notarization + auto-update pipeline pending).

---

## Sync surface

### Vercel sync manifest

Per the internal agent-memory entry `reference_revvault_sync_schema_prefix_with_override` (developer-local):

```toml
# revvault-vercel.toml — schema per crates/cli/src/commands/sync.rs ProjectSync
team_id = "team_abc123"  # optional; for personal accounts omit

[projects.revealui-prod]
project_id = "prj_xyz789"          # Vercel project ID (required)
vault_prefix = "revealui/prod/"    # secrets under this prefix sync as-is (required)
targets = ["production"]           # env targets list (default: ["production", "preview", "development"])
skip = ["VERCEL_AUTOMATION_TOKEN"] # var names to skip (integration-managed, etc.)

# per-var overrides — feature shipped via feat/sync-per-var-path-override
# Maps a Vercel var name to an absolute vault path; bypasses <vault_prefix>/<NAME> default
[projects.revealui-prod.vars]
DATABASE_URL = "revealui/prod/neon/postgres-url"
STRIPE_SECRET_KEY = "revealui/prod/stripe/secret-key"
```

The default behavior maps every `<vault_prefix>/<name>` to env var `NAME` for each target in `targets`. The per-var `[projects.<slug>.vars]` table maps a Vercel var name to a literal vault path, overriding the default prefix-based naming.

### Sync semantics

- `value-only PATCH` to Vercel API to preserve env-var type + target on update (`aa5ebf5`)
- `remote_map` filtered by `target` to avoid multi-environment ID collision (`b571920`)
- Manifest schema enforced via `serde` deserialization
- Dry-run prints unified diff between vault state and remote state

---

## Rotation surface

Per `da6ea01` (#37):

- Rotation hooks: `[rotation.<name>]` blocks in manifest define `pre-rotate` + `post-rotate` shell hooks
- Strict verify: every rotation re-fetches the new value to confirm encryption + retrieval round-trip
- Local generator: `revvault generate --shape <type>` produces shape-aware values (URL-safe random, alnum, digits-only, etc.)

Per-credential-type rotation runbook lives at [`revealui:docs/CREDENTIAL-ROTATION-RUNBOOK`](https://github.com/RevealUIStudio/revealui/blob/main/docs/CREDENTIAL-ROTATION-RUNBOOK).

---

## Security posture

- **Encryption boundary:** the age identity at `~/.age-identity/keys.txt`. Never copied to remote, never embedded in CI secrets, never logged.
- **Path validation:** directory traversal (`..`), null bytes, shell metacharacters rejected at the API layer in `core::path::validate`.
- **No plaintext on disk** outside a tmpfs-backed restore directory zeroized on command exit.
- **No logging of values** — debug logs reference paths, never decrypted bodies.
- **CI:** SHA-pinned 37 actions (`60c2912`); Tauri cross-platform build workflow (`9e54c1d`); cargo-deny (`deny.toml`); rust-toolchain pinned (`rust-toolchain.toml`); `gitleaks` scanned.

---

## Versioning

Pre-1.0 per the fleet versioning convention (RevealUI Studio internal). Cargo workspace crates use independent SemVer. Promotion to 1.0.0 gated on real external consumers + stable contract across at least one release cycle.

---

## Compose / coexistence

| Other product | Relationship |
|---|---|
| **RevealUI** | Consumer — every secret in RevealUI's `.env`/CI/runbook lives in RevVault per `secrets.md` rule |
| **RevealCoin** | Consumer — keypair files (`revealcoin/mint-authority.json`, etc.) stored as `.age` files |
| **RevDev** | Consumer — license signing keys |
| **RevForge** | Consumer — per-customer secrets at `forge/customers/<slug>/*` paths in vault |
| **RevKit** | Sets up the age-identity mount path RevVault expects (`~/.age-identity/keys.txt`) |
| **RevCon** | Independent — RevCon manages editor configs, doesn't touch secrets |
| **RevSkills** | Independent |

No reverse dependency: RevVault has no awareness of consumer products. The contract is the encrypted-file-on-disk format + the CLI surface.

---

## See also

- [`docs/MASTER_PLAN.md`](./MASTER_PLAN.md) — current status, phases, owner actions
- [`README.md`](../README.md) — quick start + setup
- Fleet master index (`MASTER_INDEX.md` in the RevealUI Studio internal coordination hub) — fleet-level navigation
- [`revealui:.claude/rules/secrets.md`](https://github.com/RevealUIStudio/revealui/blob/main/.claude/rules/secrets.md) — fleet-wide RevVault-first secrets rule
