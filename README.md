# RevVault

> The canonical secret store for the entire RevFleet. Age-encrypted vault with CLI and Tauri desktop app. 100% [passage](https://github.com/FiloSottile/passage)-compatible.

Per the fleet-wide [secrets rule](https://github.com/RevealUIStudio/revealui/blob/main/.claude/rules/secrets.md), every secret RevealUI depends on lives here — API keys, database URLs, webhook secrets, JWT/session keys, Solana keypairs, license keys, OAuth client secrets, age identities, SSH keys, anything else. One encryption boundary (the age identity) gates the whole fleet; rotation updates one store and downstream systems (CI secrets, Vercel envelopes) re-read from the same source.

## Features

- **Encrypted at rest** — `.age` files using x25519 key exchange
- **CLI** — `revvault get`, `set`, `list`, `search`, `delete`, `edit`, `export-env`, plus `--json` for structured output
- **Desktop app** — Tauri 2 + React 19 with search, browse, create, reveal, copy, delete
- **Namespaces** — secrets organized by first path segment (`revealui/`, `revealcoin/`, `revforge/`, `credentials/`, `ssh/`)
- **Fuzzy search** — find secrets by partial path match
- **Import** — migrate plaintext secret files with automatic categorization
- **Rotation** — `crates/core` includes rotation helpers for high-frequency rotation paths
- **Path validation** — directory traversal and injection attacks blocked
- **Downstream sync** — propagates to GitHub Actions secrets + Vercel encrypted envelopes via `scripts/sync/revvault-vercel.toml` in the RevealUI repo (downstream mirror, not source of truth)

## Quick Start

### Prerequisites

- [Nix](https://nixos.org/download/) with flakes enabled
- An age identity at `~/.age-identity/keys.txt`

### Build

```bash
cd ~/revfleet/revvault
direnv allow  # or: nix develop
cargo build --workspace
```

### CLI Usage

```bash
# Store a secret
echo "sk_live_abc123" | revvault set revealui/prod/stripe/secret-key

# Retrieve it
revvault get revealui/prod/stripe/secret-key

# Structured output (use --json in scripts — bare `revvault get` is silent in $(...))
revvault --json get revealui/prod/stripe/secret-key | jq -r .value

# Copy to clipboard
revvault get revealui/prod/stripe/secret-key --clip

# List
revvault list
revvault list --tree

# Fuzzy search
revvault search stripe

# Edit in $EDITOR
revvault edit revealui/prod/stripe/secret-key

# Export as KEY=VALUE for shell eval
eval "$(revvault export-env revealui/prod/stripe/secret-key)"

# Delete
revvault delete revealui/prod/stripe/secret-key

# Shell completions
revvault completions bash >> ~/.bashrc
```

### Desktop App

```bash
nix develop
cargo tauri dev
```

## Canonical paths

Paths are lower-kebab, grouped by repo or product, then by subsystem:

| Pattern | Example |
|---|---|
| `revealui/dev/<subsystem>/<name>` | `revealui/dev/electric/service-url`, `revealui/dev/admin-session-cookie` |
| `revealui/prod/<subsystem>/<name>` | `revealui/prod/neon/postgres-url`, `revealui/prod/stripe/secret-key`, `revealui/prod/stripe/webhook-secret` |
| `revealui/prod/storage/r2/<name>` | `revealui/prod/storage/r2/access-key-id` |
| `revealcoin/<keypair>` | `revealcoin/mint-authority.json` |
| `revforge/customers/<slug>/<name>` | `revforge/customers/allevia/admin-password` |
| `revdev/<name>` | `revdev/license-signing-key` |
| `credentials/<system>/<name>` | `credentials/github/personal-token`, `credentials/anthropic/api-key` |

New paths get a `docs/SECRETS.md` entry in the relevant repo. Mirroring to CI is a publish step, never hand-typed.

## Architecture

```
crates/core       — shared library (store, crypto, identity, config, namespaces, import, rotation)
crates/cli        — revvault CLI binary (clap)
crates/tauri-app  — Tauri 2 desktop backend
frontend/         — React 19 + TypeScript + Tailwind CSS v4 (Vite)
```

Workspace at version `0.2.0` (pre-1.0 per fleet versioning).

## Store Format

Secrets live in a directory hierarchy as `.age` files:

```
~/.revealui/passage-store/
├── .age-recipients
├── revealui/
│   ├── dev/
│   │   └── electric/service-url.age
│   └── prod/
│       ├── neon/postgres-url.age
│       └── stripe/secret-key.age
├── revealcoin/
│   └── mint-authority.json.age
├── revforge/
│   └── customers/
│       └── allevia/admin-password.age
├── credentials/
│   └── github/personal-token.age
└── ssh/
    └── github.age
```

Override the store location with `REVVAULT_STORE`. Override the identity file with `REVVAULT_IDENTITY`.

## Development

```bash
# Enter dev shell
direnv allow  # or: nix develop

# Run all CI checks (fmt, clippy, tests, frontend build)
bash scripts/ci.sh

# Run tests
cargo test --workspace

# Run specific crate tests
cargo test -p revvault-core
cargo test -p revvault-cli
```

Library errors use `thiserror`; binary errors use `anyhow`. Decrypted values are wrapped in `secrecy::SecretString` and never logged. All encryption goes through the `age` crate — no custom crypto.

## License

MIT.
