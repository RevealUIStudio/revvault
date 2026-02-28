#!/usr/bin/env bash
set -euo pipefail

# Revvault local CI — runs the same checks as a CI pipeline would.
# Usage: nix develop --command bash scripts/ci.sh
#   or:  ./scripts/ci.sh  (if already inside nix develop)

RED='\033[0;31m'
GREEN='\033[0;32m'
BOLD='\033[1m'
RESET='\033[0m'

pass=0
fail=0

run_step() {
  local name="$1"
  shift
  printf "${BOLD}▶ %s${RESET}\n" "$name"
  if "$@"; then
    printf "${GREEN}  ✓ %s${RESET}\n\n" "$name"
    ((pass++))
  else
    printf "${RED}  ✗ %s${RESET}\n\n" "$name"
    ((fail++))
  fi
}

cd "$(git rev-parse --show-toplevel)"

echo ""
printf "${BOLD}Running Revvault CI checks...${RESET}\n\n"

# Rust checks
run_step "cargo fmt --check" cargo fmt --check --all
run_step "cargo clippy"      cargo clippy --workspace -- -D warnings
run_step "cargo test (core)" cargo test -p revvault-core
run_step "cargo test (cli)"  cargo test -p revvault-cli

# Frontend checks
run_step "pnpm install" bash -c "cd frontend && CI=true pnpm install --frozen-lockfile"
run_step "frontend build (tsc + vite)" bash -c "cd frontend && pnpm build"

# Summary
echo ""
printf "${BOLD}Results: ${GREEN}%d passed${RESET}" "$pass"
if [ "$fail" -gt 0 ]; then
  printf ", ${RED}%d failed${RESET}" "$fail"
fi
echo ""

if [ "$fail" -gt 0 ]; then
  exit 1
fi
