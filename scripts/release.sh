#!/usr/bin/env bash
# Usage: ./scripts/release.sh <version> ["release notes"]
# Example: ./scripts/release.sh 0.7.0 "Add external webapp scanning, CVE feed refresh"
set -euo pipefail

VERSION="${1:?Usage: $0 <version> [\"release notes\"]}"
NOTES="${2:-}"
TAG="v${VERSION}"

# Ensure clean working tree
if ! git diff --quiet || ! git diff --cached --quiet; then
  echo "Error: uncommitted changes. Commit or stash first." >&2
  exit 1
fi

echo "→ Bumping version to ${VERSION}..."

# backend/scanr/config.py
sed -i "s/app_version: str = \".*\"/app_version: str = \"${VERSION}\"/" backend/scanr/config.py

# backend/pyproject.toml
sed -i "s/^version = \".*\"/version = \"${VERSION}\"/" backend/pyproject.toml

# frontend/package.json
sed -i "s/\"version\": \".*\"/\"version\": \"${VERSION}\"/" frontend/package.json

echo "→ Committing version bump..."
git add backend/scanr/config.py backend/pyproject.toml frontend/package.json
git commit -m "chore: bump version to ${VERSION}"

echo "→ Creating tag ${TAG}..."
git tag "${TAG}"

echo "→ Pushing commit and tag..."
git push origin master
git push origin "${TAG}"

echo "→ Creating GitHub release..."
if [ -n "${NOTES}" ]; then
  gh release create "${TAG}" \
    --title "ScanR ${TAG}" \
    --notes "${NOTES}"
else
  gh release create "${TAG}" \
    --title "ScanR ${TAG}" \
    --generate-notes
fi

echo ""
echo "✓ Released ${TAG}"
echo "  https://github.com/T3rr0or/ScanR/releases/tag/${TAG}"
