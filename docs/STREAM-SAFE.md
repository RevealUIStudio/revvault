# Stream-safe secrets

**ADR:** `.jv` `docs/decisions/2026-08-05-stream-safe-secrets.md`  
**Gap:** GAP-468

## Goal

Secret **values** never appear in:

- command argv (`pnpm` / `ps` / OBS)
- agent tool transcripts
- a screenshare-captured TTY

Paths and namespaces are fine to show and say on stream.

## Stream (default on camera)

```bash
stream-safe   # STREAM_SAFE=1; prompt shows "stream"

# Prefer namespaces (revealui/env/*)
with-secrets stripe neon -- pnpm billing:catalog:sync -- --mode test

# Or explicit path → env map
revvault run \
  --env STRIPE_SECRET_KEY=revealui/dev/stripe/secret-key \
  --env NEON_DATABASE_URL=revealui/prod/neon/postgres-url \
  -- pnpm billing:catalog:sync -- --mode test
```

Under `STREAM_SAFE=1`, `revvault get` / `--clip` refuse without break-glass.
Piped use (scripts, `passenv`) still works when stdout is not a TTY.

## Vault-private (OBS window excluded)

```bash
vault-private   # REVVAULT_ALLOW_PRINT=1; prompt shows "VAULT"

revvault get --full revealui/prod/…
revvault get --clip revealui/prod/…
```

Clear the clipboard after paste. Close the window before ending a stream.

## Forbidden

```bash
# Never — expands onto argv
pnpm … -- --database-url "$(revvault get --full …)"
export X="$(revvault get --full …)" && tool --token "$X"
```

Agents: PreToolUse blocks those shapes (claude-config / Grok compat).

## Namespaces

| Namespace | Typical keys |
|-----------|----------------|
| `stripe` | `STRIPE_SECRET_KEY`, meter + overage price ids |
| `neon` | `NEON_DATABASE_URL`, `POSTGRES_URL`, `DATABASE_URL` |

Update bundles:

```bash
# KEY=VALUE file, then:
revvault set --force revealui/env/stripe < stripe.env
revvault set --force revealui/env/neon < neon.env
```
