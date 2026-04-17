# ScanR — Development Reference

## Releasing a new version

One command does everything: bumps version in all files, commits, tags, pushes, creates GitHub release.

```bash
./scripts/release.sh 0.7.0 "Add external webapp scanning, CVE feed refresh"
```

What it does:
1. Checks working tree is clean (aborts if uncommitted changes)
2. Bumps version in `backend/scanr/config.py`, `backend/pyproject.toml`, `frontend/package.json`
3. Commits the version bump
4. Creates and pushes git tag `v0.7.0`
5. Creates GitHub release via `gh` CLI (auto-generates notes from commits if no message given)

**Requires:** `gh` CLI authenticated (`gh auth login`)

If you omit the release notes argument, GitHub auto-generates them from commit messages since the last tag — usually good enough.

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
