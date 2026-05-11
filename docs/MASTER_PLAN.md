---
type: master-plan
repo: revvault
last-updated: 2026-05-10
owner: RevealUI Studio
staleness-status: FRESH
---

# RevVault — Master Plan

**Last Updated:** 2026-05-10
**Status:** Active — production-grade for studio internal use; commercial offering wraps RevealUI Pro tier
**Owner:** RevealUI Studio (`founder@revealui.com`)
**Repo:** [RevealUIStudio/revvault](https://github.com/RevealUIStudio/revvault)
**Fleet master index:** RevealUI Studio internal coordination hub (`MASTER_INDEX.md`, private).

> Fleet-level cross-cutting plans live in the internal coordination hub's `MASTER_PLAN.md`. This file is RevVault-scoped only.

---

## Current Reality (2026-05-10)

### What exists

- **Cargo workspace** with 3 crates: `cli`, `core`, `tauri-app`
- **Frontend** (Tauri 2 + React 19) at `frontend/`
- **Encryption**: age x25519 keys via the user's `~/.age-identity/keys.txt`; secrets stored as `.age` files
- **CLI commands**: `get`, `set`, `list`, `search`, `delete`, `edit`, `export-env`, `generate` (added 2026-04-x via #26)
- **Sync**: Vercel sync surface; per-var vault-path overrides land via `feat/sync-per-var-path-override`
- **Rotation**: post-rotate hooks + strict verify + local generator (#37 merged)
- **CI**: SHA-pinned 37 actions (#34); Tauri cross-platform build workflow (#35)
- **Path validation**: directory traversal + injection attacks blocked at the API layer

### What works (verified by code + commit history)

| Capability | Status | Confidence |
|---|---|---|
| `revvault get/set/list/delete` (file-based age vault) | Built | High — production-grade for studio internal use |
| Fuzzy search over secret paths | Built | High |
| `export-env` materialization for direnv | Built | High |
| Tauri desktop UI (search, browse, reveal, copy, delete) | Built | Medium — used internally; not packaged for external customers yet |
| Vercel sync (manifest-driven, per-var path overrides) | Active | Medium — new path-override feature on `feat/sync-per-var-path-override` |
| Rotation engine + post-rotate hooks | Built | Medium — shipped via #37 |
| Path validation (traversal/injection) | Built | High |
| `generate` subcommand for strong passwords | Built | High — shipped via #26 |

### What does not exist yet

- Public Tauri desktop releases (no signed/notarized auto-update pipeline cutting public releases)
- Cross-machine sync over a server (vault is single-machine; Vercel sync is one-way write to deployment env)
- Multi-identity vaults (single age identity per machine; team-shared identities not yet modeled)
- Audit log for `get`/`set` operations
- `revvault status` cross-check against revealui's `.env.example` (drift warning)

---

## Composition with the rest of RevFleet

RevVault is the **source of truth for every secret** in RevFleet per [`revealui:.claude/rules/secrets.md`](https://github.com/RevealUIStudio/revealui/blob/main/.claude/rules/secrets.md). One sentence trust story:

> Secrets live in RevVault, encrypted by an age identity that doesn't leave the developer's machine.

- **Local dev**: `revvault export-env` materializes `.env`-shaped output that direnv loads at session start
- **CI**: GitHub Actions secrets are mirrored from RevVault by a publish step, never hand-typed
- **Rotation**: per-credential-type runbook; rotation updates RevVault first, downstream re-reads from the same source

The Pro-tier commercial offering wraps the RevealUI license: RevealUI Pro unlocks the **RevVault desktop app** + **rotation engine** as Pro features. The CLI and core crate are MIT and free for any tier.

---

## Active Work

### `feat/sync-per-var-path-override` (current branch)

Per-variable vault-path overrides for Vercel sync. Manifest schema gains `[projects.<slug>.vars]` table for case-by-case overrides where the default `[projects.<slug>] vault_prefix` is wrong. Surfacing reference: internal agent-memory entry `reference_revvault_sync_schema_prefix_with_override` (developer-local).

**In scope:** schema parsing, conflict resolution between `vault_prefix` and per-var overrides, sync logic.
**Out of scope:** UI for editing overrides, rotation hooks for overridden vars (defer to follow-on).

### Recently shipped (last ~30 days, descending)

- `fd306fd` chore(docs): rename `~/suite/` → `~/revfleet/` in CLAUDE.md (#39)
- `cc43830` fix(core): escape brackets in `update_env_var` doc comment
- `aa5ebf5` fix(sync): `update_env_var` sends value-only PATCH to preserve type + target
- `b571920` fix(sync): filter `remote_map` by target to avoid multi-environment ID collision
- `20d55a3` feat(sync): per-var vault path overrides for Vercel sync (PR open as `feat/sync-per-var-path-override`)
- `da6ea01` feat(rotation): post-rotate hooks + strict verify + local generator (#37)
- `9e54c1d` ci: add `tauri-build` workflow for revvault-tauri cross-platform compile validation (#35)
- `60c2912` chore(ci): SHA-pin all 37 actions in revvault `ci.yml` (#34)
- `4c7cbe3` feat(cli): add `generate` subcommand for strong passwords (#26)

---

## Roadmap

Pre-1.0 (per the fleet versioning convention, RevealUI Studio internal). Promotion to 1.0.0 requires real external consumers + stable contract across one release cycle.

### Phase 0 — Studio internal use (DONE)

CLI feature-complete for daily studio workflow: get/set/list/edit/delete/export-env/search/generate; age encryption; namespaces; fuzzy search; path validation.

### Phase 1 — Vercel sync (IN FLIGHT)

Per-var vault-path overrides; multi-environment target filtering; post-rotate hooks. Surface: `revvault sync vercel` against a `[projects.<slug>]` manifest.

**Owner action items:** none currently — agent-driven.

### Phase 2 — Public Tauri release (NOT STARTED)

Signed + notarized desktop binary for macOS/Windows; auto-update pipeline; public download page (likely on `revealui.com/revvault` or a dedicated subdomain).

**Owner action items:** Apple notarization cert; Windows code-signing cert; auto-update server hosting decision.

### Phase 3 — Audit log + drift detection (NOT STARTED)

`revvault audit log` for `get`/`set` history; `revvault status` cross-check against RevealUI's `.env.example` to surface drift between expected and stored secrets.

### Phase 4 — Multi-identity / team vaults (NOT STARTED)

Multi-identity vault model (single age recipient list per vault, multiple consumers). Defers to a future "team plan" of RevealUI Pro.

---

## Owner Action Queue

| Item | Unblocks |
|---|---|
| Decide Tauri public-release distribution channel (revealui.com subpath vs separate domain vs GitHub releases only) | Phase 2 |
| Procure Apple notarization + Windows code-signing certs | Phase 2 |

---

## See also

- [`docs/MASTER_SPEC.md`](./MASTER_SPEC.md) — surface area + architecture
- [`README.md`](../README.md) — quick start + CLI command reference
- Fleet master index (`MASTER_INDEX.md` in the RevealUI Studio internal coordination hub) — fleet-level navigation
- [`revealui:.claude/rules/secrets.md`](https://github.com/RevealUIStudio/revealui/blob/main/.claude/rules/secrets.md) — fleet-wide secrets convention (RevVault as source of truth)
