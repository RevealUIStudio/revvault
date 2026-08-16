# Dual-slot rotation verify (GAP-261 residual)

Operator helper for crown-jewel **ed25519-keypair** dual-slot rotations.
Complements `rotate` + `rotation-promote`; does **not** replace promote soak.

## What it checks

```bash
revvault rotation-verify <provider>
```

For a `[providers.<name>]` block with `dual_slot = true` and
`settings.public_key_path`:

| Check | Detail |
|-------|--------|
| next-id present | leaf `{secret_path}-next-id` exists and is non-empty |
| next public present | leaf `{public_key_path}-next` exists |
| kid match | `computeKeyId(next public PEM)` equals stored next-id |

Uses the same `compute_key_id` as the keypair provider (first 8 hex of
SHA-256 over public PEM UTF-8 bytes; aligned with revealui `computeKeyId`).

## What it never does

- Does **not** print PEMs, private keys, or other secret values (kids and paths only)
- Does **not** run `rotate` or `rotation-promote`
- Does **not** write vault leaves or edit `rotation.toml`
- Does **not** use shell `$(revvault get …)` (opens the store in-process)

## Operator flow

1. **Owner** (store edit, not this PR): copy
   [`docs/examples/rotation-license-signing.toml`](examples/rotation-license-signing.toml)
   into `<store>/.revvault/rotation.toml` (or merge the block). Live path on
   Studio machines is typically `~/.revealui/passage-store/.revvault/rotation.toml`.
2. `revvault rotate license-signing --dry-run`
3. `revvault rotate license-signing` (writes `*-next` / `*-previous` only)
4. `revvault rotation-verify license-signing` (also configured as `verify =` in the example)
5. Soak the printed **NEXT kid** on hosted multi-key license verify (GAP-259)
6. **Owner** runs `revvault rotation-promote license-signing` (overwrites live signing key)
7. Customer re-mint (`forge/customers/*/license-key`) remains a separate
   `post_rotate` / revforge script step until a later promote-subsume PR

## Example `verify` gate

```toml
verify = "revvault rotation-verify license-signing"
```

Do not use weak shell presence checks such as
`test -n "$(revvault get …-next-id)"` — that shape is stream-unsafe when
expanded in argv and only proves the leaf is non-empty.

## Exit codes

- `0` — next-id present, next public present, kids match; checklist printed
- non-zero — missing leaf, empty next-id, missing `public_key_path`, or kid mismatch
