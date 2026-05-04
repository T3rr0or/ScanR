#!/usr/bin/env bash
# ScanR release script — bump version, tag, push, create GitHub Release.
# Usage: ./scripts/release.sh <new_version> [notes_file]
# Example: ./scripts/release.sh 0.9.2
set -euo pipefail

NEW_VERSION="${1:?Usage: scripts/release.sh <version> [notes_file]}"
NOTES_FILE="${2:-/dev/stdin}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# ── Validate version format ───────────────────────────────────────────
if ! echo "$NEW_VERSION" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+$'; then
    echo "ERROR: version must be semver (X.Y.Z)" >&2
    exit 1
fi

# ── Ensure we are on master and clean ──────────────────────────────────
CURRENT_BRANCH="$(git branch --show-current)"
if [ "$CURRENT_BRANCH" != "master" ]; then
    echo "ERROR: must be on master branch (current: $CURRENT_BRANCH)" >&2
    exit 1
fi
if ! git diff --quiet || ! git diff --staged --quiet; then
    echo "ERROR: working tree is dirty — commit or stash changes first" >&2
    exit 1
fi

# Check no pending tag
if git tag -l "v$NEW_VERSION" | grep -q "v$NEW_VERSION"; then
    echo "ERROR: tag v$NEW_VERSION already exists" >&2
    exit 1
fi

# ── Get previous version ───────────────────────────────────────────────
OLD_VERSION="$(grep '^version = ' "$REPO_ROOT/backend/pyproject.toml" | head -1 | sed 's/version = "\(.*\)"/\1/')"

# ── Bump versions ──────────────────────────────────────────────────────
sed -i "s/^version = \".*\"/version = \"$NEW_VERSION\"/" "$REPO_ROOT/backend/pyproject.toml"
sed -i "s/app_version: str = \".*\"/app_version: str = \"$NEW_VERSION\"/" "$REPO_ROOT/backend/scanr/config.py"

# ── Commit & tag ───────────────────────────────────────────────────────
git add "$REPO_ROOT/backend/pyproject.toml" "$REPO_ROOT/backend/scanr/config.py"
git commit -m "chore: release $NEW_VERSION"
git tag "v$NEW_VERSION"

echo ""
echo "  Version bumped: $OLD_VERSION → $NEW_VERSION"
echo "  Tag created:    v$NEW_VERSION"
echo ""

# ── Push ───────────────────────────────────────────────────────────────
echo "Pushing master and tag…"
git push origin master --tags

# ── Create GitHub Release ──────────────────────────────────────────────
echo ""
echo "Creating GitHub Release…"

RELEASE_NOTES=""
if [ -f "$NOTES_FILE" ]; then
    RELEASE_NOTES="$(cat "$NOTES_FILE")"
elif [ ! -t 0 ]; then
    RELEASE_NOTES="$(cat)"
fi

if [ -z "$RELEASE_NOTES" ]; then
    # Generate changelog from commits since last tag
    LAST_TAG="$(git describe --tags --abbrev=0 HEAD^ 2>/dev/null || echo "")"
    if [ -n "$LAST_TAG" ]; then
        RELEASE_NOTES="## Commits since $LAST_TAG

$(git log "$LAST_TAG..HEAD" --oneline --no-merges)"
    else
        RELEASE_NOTES="## Commits

$(git log --oneline --no-merges -20)"
    fi
fi

gh release create "v$NEW_VERSION" \
    --title "ScanR v$NEW_VERSION" \
    --notes "$RELEASE_NOTES"

echo ""
echo "Release v$NEW_VERSION published."
echo "GitHub Actions will build + push Docker images to GHCR."
