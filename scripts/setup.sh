#!/usr/bin/env bash
# ScanR one-shot setup — generates .env with all required secrets.
# Run once after cloning: ./scripts/setup.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "ScanR setup"
echo "==========="
echo ""

if [ -f "$REPO_ROOT/.env" ]; then
    echo ".env already exists — skipping generation."
    echo "Delete it first if you want a fresh setup: rm .env"
    exit 0
fi

# Copy template
cp "$REPO_ROOT/.env.example" "$REPO_ROOT/.env"

# Generate secrets
SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")
POSTGRES_PASSWORD=$(python3 -c "import secrets; print(secrets.token_urlsafe(24))")
ADMIN_PASSWORD=$(python3 -c "import secrets; print(secrets.token_urlsafe(16))")
SANDBOX_TOKEN=$(openssl rand -hex 32 2>/dev/null || python3 -c "import secrets; print(secrets.token_hex(32))")

# Replace placeholders
sed -i "s/^SECRET_KEY=$/SECRET_KEY=$SECRET_KEY/" "$REPO_ROOT/.env"
sed -i "s/^POSTGRES_PASSWORD=$/POSTGRES_PASSWORD=$POSTGRES_PASSWORD/" "$REPO_ROOT/.env"
sed -i "s/^ADMIN_PASSWORD=$/ADMIN_PASSWORD=$ADMIN_PASSWORD/" "$REPO_ROOT/.env"
sed -i "s/^SANDBOX_TOKEN=$/SANDBOX_TOKEN=$SANDBOX_TOKEN/" "$REPO_ROOT/.env"

echo "✓ .env created with generated secrets"
echo ""
echo "  Admin login:  admin@example.com"
echo "  Password:     $ADMIN_PASSWORD"
echo ""
echo "Next:  docker compose up -d"
echo ""
echo "Secrets are in .env (gitignored). Regenerate SANDBOX_TOKEN for production."
