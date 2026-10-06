#!/usr/bin/env bash
# check-client-leaks.sh
#
# Scans the repo for any reference to a specific RevealUI Studio client,
# prospect, or warm-intro contact. Customer/prospect names belong in the
# private internal repo only, never in this public surface.
#
# Exit 0 on clean. Exit 1 on any violation. Exit 2 on tool/setup error.
#
# Usage:
#   bash scripts/check-client-leaks.sh                     # scan repo root
#   bash scripts/check-client-leaks.sh <path> [<path>...]  # scan specific paths
#   LEAK_JSON=1 bash scripts/check-client-leaks.sh         # machine-readable
#
# CI wiring: .github/workflows/check-client-leaks.yml
# REQUIRED status check on `test` and `main` branch protection.
#
# Adding a new client / prospect / contact:
#   Add one line to the CLIENT_LEAK_PATTERNS org Actions secret
#   (format: tag|literal-string|reason). Never commit the line to a file
#   in this repo. CI refuses to merge any tracked file that contains the
#   literal. There is no .leakignore for this scanner.
#
# Pattern source:
#   1. CLIENT_LEAK_PATTERNS (multiline, one pattern per line). Required when
#      CI=true or GITHUB_ACTIONS=true. Empty or missing fails closed.
#   2. Local only: gitignored .client-name-watchlist.local at the repo root,
#      used when the env var is empty. If neither source is present, the
#      script warns and exits 2 so a missing list is not a clean scan.

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCAN_PATHS=("$@")
[[ ${#SCAN_PATHS[@]} -eq 0 ]] && SCAN_PATHS=("$REPO_ROOT")

for _path in "${SCAN_PATHS[@]}"; do
  if [[ ! -e "$_path" ]]; then
    echo "[client-leak] error: scan path not found: $_path" >&2
    exit 2
  fi
done
unset _path

# --- Patterns: tag | literal-string | reason ---
#
# REGEX-CONFIG-BOUNDARY: the strings consumed by grep -F (fixed strings),
# so each pattern is a literal substring. No metacharacter handling.
# No regex authored.
#
# Loaded at runtime from CLIENT_LEAK_PATTERNS or, locally, from
# .client-name-watchlist.local. Do not add literals to this file.

in_ci() {
  [[ "${CI:-}" == "true" || "${GITHUB_ACTIONS:-}" == "true" ]]
}

fail_closed_missing_patterns() {
  if in_ci; then
    echo "[client-leak] error: CLIENT_LEAK_PATTERNS is empty or unset." >&2
    echo "[client-leak] CI fails closed until the org Actions secret CLIENT_LEAK_PATTERNS is set and visible to this repo." >&2
    echo "[client-leak] Add pattern lines to that secret, never to a committed file." >&2
  else
    echo "[client-leak] warning: no client-leak pattern list is available." >&2
    echo "[client-leak] Set CLIENT_LEAK_PATTERNS or add gitignored .client-name-watchlist.local at the repo root." >&2
    echo "[client-leak] Add pattern lines to the CLIENT_LEAK_PATTERNS org secret, never to a committed file." >&2
    echo "[client-leak] This is not a clean scan." >&2
  fi
  exit 2
}

# Append tag|literal|reason lines from one source. Exits 2 on a malformed line
# without echoing the line. Blank lines and '#' comments are ignored.
append_pattern_lines() {
  local source_name="$1"
  local source_text="$2"
  local line tag rest pattern reason
  while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line%$'\r'}"
    line="${line#"${line%%[![:space:]]*}"}"
    line="${line%"${line##*[![:space:]]}"}"
    [[ -z "$line" || "$line" == \#* ]] && continue
    if [[ "$line" == \"*\" && "$line" == *\" ]]; then
      line="${line:1:${#line}-2}"
    fi
    tag="${line%%|*}"
    rest="${line#*|}"
    if [[ "$rest" == "$line" || "$rest" != *"|"* ]]; then
      echo "[client-leak] error: malformed pattern line in ${source_name} (expected tag|literal|reason)." >&2
      exit 2
    fi
    pattern="${rest%%|*}"
    reason="${rest#*|}"
    if [[ -z "$tag" || -z "$pattern" || -z "$reason" ]]; then
      echo "[client-leak] error: malformed pattern line in ${source_name} (empty field)." >&2
      exit 2
    fi
    PATTERNS+=("$line")
  done <<< "$source_text"
}

WATCHLIST_FILE="$REPO_ROOT/.client-name-watchlist.local"
if command -v git >/dev/null 2>&1 && git -C "$REPO_ROOT" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  if git -C "$REPO_ROOT" ls-files --error-unmatch -- .client-name-watchlist.local >/dev/null 2>&1; then
    echo "[client-leak] error: .client-name-watchlist.local is tracked." >&2
    echo "[client-leak] Add pattern lines to the CLIENT_LEAK_PATTERNS org secret, never to a committed file." >&2
    exit 2
  fi
fi

PATTERNS=()
if [[ -n "${CLIENT_LEAK_PATTERNS:-}" ]]; then
  append_pattern_lines "CLIENT_LEAK_PATTERNS" "$CLIENT_LEAK_PATTERNS"
fi

if [[ ${#PATTERNS[@]} -eq 0 ]]; then
  if in_ci; then
    fail_closed_missing_patterns
  elif [[ -f "$WATCHLIST_FILE" ]]; then
    append_pattern_lines ".client-name-watchlist.local" "$(cat "$WATCHLIST_FILE")"
    if [[ ${#PATTERNS[@]} -eq 0 ]]; then
      fail_closed_missing_patterns
    fi
  else
    fail_closed_missing_patterns
  fi
fi

# Directories / file globs to skip.
# The local watchlist is the pattern source itself. It is gitignored, and a
# tracked copy is refused above, so excluding the basename cannot hide a
# committed list.
EXCLUDE_DIRS=(node_modules .git dist build .next .turbo .pnpm coverage target .direnv .nyc_output playwright-report test-results)
EXCLUDE_FILES=(
  pnpm-lock.yaml package-lock.json yarn.lock Cargo.lock
  .client-name-watchlist.local
  CHANGELOG.md
  '*.png' '*.jpg' '*.jpeg' '*.gif' '*.webp' '*.pdf' '*.zip' '*.tar.gz' '*.tgz'
  '*.ico' '*.woff' '*.woff2' '*.ttf' '*.otf'
  '*.har' '*.snap'
)

if ! command -v grep >/dev/null 2>&1; then
  echo "[client-leak] error: grep not found on PATH" >&2
  exit 2
fi

grep_excludes=()
for d in "${EXCLUDE_DIRS[@]}"; do
  grep_excludes+=(--exclude-dir="$d")
done
for f in "${EXCLUDE_FILES[@]}"; do
  grep_excludes+=(--exclude="$f")
done

violations=0
json_entries=()

for entry in "${PATTERNS[@]}"; do
  tag="${entry%%|*}"
  rest="${entry#*|}"
  pattern="${rest%%|*}"
  reason="${rest#*|}"

  while IFS= read -r hit; do
    [[ -z "$hit" ]] && continue
    file="${hit%%:*}"
    rest_="${hit#*:}"
    line="${rest_%%:*}"
    content="${rest_#*:}"

    if [[ -n "${LEAK_JSON:-}" ]]; then
      if command -v jq >/dev/null 2>&1; then
        json_entries+=("$(jq -cn --arg tag "$tag" --arg file "$file" --arg line "$line" --arg reason "$reason" --arg content "$content" \
          '{tag:$tag, file:$file, line:($line|tonumber), reason:$reason, content:$content}')")
      else
        safe="${content//\\/\\\\}"
        safe="${safe//\"/\\\"}"
        safe="${safe//$'\n'/\\n}"
        safe="${safe//$'\t'/\\t}"
        sreason="${reason//\\/\\\\}"
        sreason="${sreason//\"/\\\"}"
        json_entries+=("{\"tag\":\"$tag\",\"file\":\"$file\",\"line\":$line,\"reason\":\"$sreason\",\"content\":\"$safe\"}")
      fi
    else
      printf '[CLIENT-LEAK:%s] %s:%s %s\n  %s\n' "$tag" "$file" "$line" "$reason" "$content"
    fi
    violations=$((violations+1))
  done < <(grep -rFIn "${grep_excludes[@]}" -- "$pattern" "${SCAN_PATHS[@]}" 2>/dev/null || true)
done

if [[ -n "${LEAK_JSON:-}" ]]; then
  printf '{"violations":%d,"entries":[%s]}\n' "$violations" "$(IFS=,; echo "${json_entries[*]:-}")"
fi

if (( violations > 0 )); then
  if [[ -z "${LEAK_JSON:-}" ]]; then
    echo "" >&2
    echo "[client-leak] FAIL: $violations violation(s)." >&2
    echo "" >&2
    echo "Customer / prospect names must NEVER appear in this public-facing repo." >&2
    echo "Move the content to the private internal repo (or genericize with a" >&2
    echo "placeholder like 'Acme Corp' / 'acme' / 'first customer')." >&2
    echo "" >&2
    echo "If a new client onboards and their name needs scanner coverage, add" >&2
    echo "the pattern line to the CLIENT_LEAK_PATTERNS org secret, never to a" >&2
    echo "committed file." >&2
  fi
  exit 1
fi

[[ -z "${LEAK_JSON:-}" ]] && echo "[client-leak] OK: no client/prospect names detected across: ${SCAN_PATHS[*]}"
exit 0
