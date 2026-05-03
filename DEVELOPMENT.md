# ScanR — Development Reference

## Releasing a new version

Release from a clean working tree.

```bash
# Update the version in:
# - backend/scanr/config.py
# - backend/pyproject.toml
# - frontend/package.json
# - frontend/package-lock.json

git add backend/scanr/config.py backend/pyproject.toml frontend/package.json frontend/package-lock.json
git commit -m "chore: release v0.7.0"
git tag -a v0.7.0 -m "ScanR v0.7.0"
git push origin master --tags
gh release create v0.7.0 --title "ScanR v0.7.0" --generate-notes
```

**Requires:** `gh` CLI authenticated (`gh auth login`)

---

## Local dev loop

```bash
# Start all services
docker compose up -d --build

# Watch API logs
docker compose logs -f api

# Watch worker logs
docker compose logs -f worker

# Restart after backend change (no rebuild needed for .py changes if using volumes)
docker compose restart api worker

# Full rebuild after dependency changes
docker compose up -d --build
```

---

## Sensitive data

ScanR handles credentials, target lists, scanner logs, screenshots, and reports. Never commit `.env`, local network target details, private credentials, scanner output, generated reports, Playwright/browser state, debug logs, local database files, or temporary screenshots. Documentation screenshots belong under `docs/screenshots/`; root-level screenshots are ignored as local artifacts.

---

## Environment

All secrets live in `.env` (gitignored). Copy from `.env.example` on a fresh clone:

```bash
cp .env.example .env
# Fill in SECRET_KEY, VAULT_KEY, POSTGRES_PASSWORD, ADMIN_PASSWORD
```

Generate keys:
```bash
# SECRET_KEY
python3 -c "import secrets; print(secrets.token_urlsafe(32))"

# VAULT_KEY
python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

---

## Adding a plugin

1. Create `backend/scanr/plugins/<category>/<name>.py`
2. Extend `PluginBase`, set `id`, `name`, `category`, `severity`, `ports`
3. Implement `async def check(self, context, host) -> list[FindingData]`
4. Plugin auto-discovered on next worker restart — no registration needed

Compliance/MITRE tags: add entry in `backend/scanr/core/compliance.py` and `backend/scanr/core/mitre.py`.

---

## Version locations

When bumping manually (instead of using the release script):

| File | Field |
|---|---|
| `backend/scanr/config.py` | `app_version: str = "x.y.z"` |
| `backend/pyproject.toml` | `version = "x.y.z"` |
| `frontend/package.json` | `"version": "x.y.z"` |
