#!/usr/bin/env bash
set -euo pipefail

mode="${1:---staged}"
root="$(git rev-parse --show-toplevel)"
cd "$root"

secret_pattern='(BEGIN (RSA |DSA |EC |OPENSSH )?PRIVATE KEY|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}|[A-Za-z0-9_]*(SECRET|TOKEN|PASSWORD|PASSWD|API[_-]?KEY|VAULT[_-]?KEY|FERNET)[A-Za-z0-9_]*[[:space:]]*[:=][[:space:]]*["'\''"]?[A-Za-z0-9_./+=:@-]{4,})'
local_path_pattern='(^|/)(\.env($|\.)|\.playwright-mcp/|playwright-report/|test-results/|blob-report/|storageState.*\.json$|.*\.(log|har|db|sqlite|sqlite3|pcap|pcapng)$|reports?/|scan-output/|scan-results/|scanner-state/|captures?/|artifacts?/|screenshots?/|[^/]+\.png$)'
private_target_pattern='(10\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|192\.168\.[0-9]{1,3}\.[0-9]{1,3}|172\.(1[6-9]|2[0-9]|3[0-1])\.[0-9]{1,3}\.[0-9]{1,3}|/home/[A-Za-z0-9._-]+|/Users/[A-Za-z0-9._-]+)'

fail=0

report() {
  printf '%s\n' "$1" >&2
  fail=1
}

scan_with_gitleaks_if_available() {
  if command -v gitleaks >/dev/null 2>&1; then
    gitleaks protect --staged --redact --verbose
  else
    printf 'gitleaks not installed; using ScanR built-in checks only.\n' >&2
  fi
}

check_staged_paths() {
  local matches
  matches="$(git diff --cached --name-only --diff-filter=ACMR | rg "$local_path_pattern" | rg -v '^docs/screenshots/[^/]+\.png$' || true)"
  if [ -n "$matches" ]; then
    report "Blocked staged local/generated files:"
    printf '%s\n' "$matches" >&2
  fi
}

check_staged_content() {
  local matches
  matches="$(git grep --cached -n -I -E "$secret_pattern" -- \
    ':!.env.example' \
    ':!README.md' \
    ':!DEVELOPMENT.md' \
    ':!CONTRIBUTING.md' \
    ':!backend/tests/**' \
    ':!frontend/package-lock.json' \
    2>/dev/null || true)"
  matches="$(printf '%s\n' "$matches" | rg -v '(SCANR_TOKEN=sk_agent_\.\.\.|BEGIN RSA PRIVATE KEY|_TOKEN_URL)' || true)"
  if [ -n "$matches" ]; then
    report "Potential staged secret content (review and remove before commit):"
    printf '%s\n' "$matches" | sed -E 's/((SECRET|TOKEN|PASSWORD|PASSWD|API[_-]?KEY|VAULT[_-]?KEY|FERNET)[A-Za-z0-9_]*[[:space:]]*[:=][[:space:]]*)[^[:space:]]+/\1<redacted>/Ig' >&2
  fi

  matches="$(git grep --cached -n -I -E "$private_target_pattern" -- \
    '.playwright-mcp/**' 'reports/**' 'scan-output/**' 'scan-results/**' 'scanner-state/**' 'captures/**' 'artifacts/**' 'screenshots/**' \
    2>/dev/null || true)"
  if [ -n "$matches" ]; then
    report "Private targets found in staged generated output:"
    printf '%s\n' "$matches" >&2
  fi
}

check_worktree() {
  local matches
  matches="$(rg -n -I --with-filename --hidden --no-ignore \
    --glob '!.git/**' \
    --glob '!.claude/**' \
    --glob '!frontend/node_modules/**' \
    --glob '!frontend/dist/**' \
    --glob '!backend/.venv/**' \
    --glob '!node_modules/**' \
    --glob '!frontend/package-lock.json' \
    --glob '!.env.example' \
    --glob '!scripts/secret-scan.sh' \
    "$secret_pattern" . || true)"
  matches="$(printf '%s\n' "$matches" | rg -v '(SCANR_TOKEN=sk_agent_\.\.\.|BEGIN RSA PRIVATE KEY|_TOKEN_URL)' || true)"
  if [ -n "$matches" ]; then
    report "Potential secrets in working tree:"
    printf '%s\n' "$matches" | sed -E 's/((SECRET|TOKEN|PASSWORD|PASSWD|API[_-]?KEY|VAULT[_-]?KEY|FERNET)[A-Za-z0-9_]*[[:space:]]*[:=][[:space:]]*)[^[:space:]]+/\1<redacted>/Ig' >&2
  fi
}

check_history() {
  if command -v gitleaks >/dev/null 2>&1; then
    gitleaks detect --redact --source .
  else
    printf 'gitleaks not installed; running limited git-history checks.\n' >&2
  fi

  local paths
  paths="$(git log --all --name-only --pretty=format: | sort -u | rg "$local_path_pattern" | rg -v '^(\.env\.example|docs/screenshots/)' || true)"
  if [ -n "$paths" ]; then
    report "Sensitive/generated paths exist in git history:"
    printf '%s\n' "$paths" >&2
  fi

  local matches
  matches="$(git grep -l -I -E '(BEGIN (RSA |DSA |EC |OPENSSH )?PRIVATE KEY|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})' $(git rev-list --all) -- 2>/dev/null | rg -v ':(frontend/src/pages/Credentials\.tsx|scripts/secret-scan\.sh)$' || true)"
  if [ -n "$matches" ]; then
    report "High-confidence secret patterns exist in git history:"
    printf '%s\n' "$matches" >&2
  fi
}

case "$mode" in
  --staged)
    scan_with_gitleaks_if_available
    check_staged_paths
    check_staged_content
    ;;
  --all)
    check_staged_paths
    check_staged_content
    check_worktree
    ;;
  --history)
    check_history
    ;;
  *)
    printf 'usage: %s [--staged|--all|--history]\n' "$0" >&2
    exit 2
    ;;
esac

if [ "$fail" -ne 0 ]; then
  exit 1
fi

printf 'Secret scan passed (%s).\n' "$mode"
