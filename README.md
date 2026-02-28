# Revvault

Age-encrypted secret vault with CLI and Tauri desktop app. 100% [passage](https://github.com/FiloSottile/passage)-compatible.

## Features

- **Encrypted at rest** — secrets stored as `.age` files using x25519 key exchange
- **CLI** — `revvault get`, `set`, `list`, `search`, `delete`, `edit`, `export-env`
- **Desktop app** — Tauri 2 + React 19 with search, browse, create, reveal, copy, delete
- **Namespaces** — secrets organized by first path segment (credentials, ssh, misc, etc.)
- **Fuzzy search** — find secrets by partial path match
- **Import** — migrate plaintext secret files with automatic categorization
- **Path validation** — directory traversal and injection attacks blocked

## Quick Start

### Prerequisites

- [Nix](https://nixos.org/download/) with flakes enabled
- An age identity at `~/.age-identity/keys.txt`

### Build

```bash
cd /path/to/revault
nix develop
cargo build --workspace
```

### CLI Usage

```bash
# Store a secret
echo "sk_live_abc123" | revvault set credentials/stripe/secret-key

# Retrieve it
revvault get credentials/stripe/secret-key

# Copy to clipboard
revvault get credentials/stripe/secret-key --clip

# List all secrets
revvault list
revvault list --tree

# Fuzzy search
revvault search stripe

# Edit in $EDITOR
revvault edit credentials/stripe/secret-key

# Export as KEY=VALUE for shell eval
eval "$(revvault export-env credentials/stripe/secret-key)"

# Delete
revvault delete credentials/stripe/secret-key

# Shell completions
revvault completions bash >> ~/.bashrc
```

### Desktop App

```bash
nix develop
cargo tauri dev
```

## Architecture

```
crates/core       — shared library (store, crypto, identity, config, namespaces)
crates/cli        — revvault CLI binary (clap)
crates/tauri-app  — Tauri 2 desktop backend
frontend/         — React 19 + TypeScript + Tailwind CSS v4 (Vite)
```

## Store Format

Secrets live in a directory hierarchy as `.age` files:

```
~/.revealui/passage-store/
├── .age-recipients
├── credentials/
│   └── stripe/
│       ├── secret-key.age
│       └── publishable-key.age
├── ssh/
│   └── github.age
└── misc/
    └── note.age
```

Override the store location with `REVVAULT_STORE` env var.
Override the identity file with `REVVAULT_IDENTITY` env var.

## Development

```bash
# Enter dev shell
nix develop

# Run all CI checks (fmt, clippy, tests, frontend build)
bash scripts/ci.sh

# Run tests
cargo test --workspace

# Run specific crate tests
cargo test -p revvault-core
cargo test -p revvault-cli
```

## License

MIT
