# Contributing to ScanR

Thank you for your interest in contributing.

## Ground rules

- Only submit code you have the right to license under MIT.
- All scan/test code must target systems you own or have explicit written permission to test.
- Do not add features that facilitate unauthorized access or evasion of detection systems.
- Never commit credentials, local network details, scanner output, screenshots of private targets, generated reports, Playwright/browser state, or local machine paths.

## How to contribute

1. Fork the repository and create a branch from `main`.
2. Make your changes. Keep commits focused — one logical change per commit.
3. Test your changes locally with `docker compose up -d --build`.
4. Run the local secret checks before committing:

```bash
scripts/secret-scan.sh --staged
scripts/secret-scan.sh --history
```

5. Open a pull request with a clear description of what changed and why.

## Secret and local-state checks

ScanR is a security-sensitive project. Treat scanner output as potentially sensitive, even when it only contains private IPs, hostnames, screenshots, request logs, or generated reports.

Install the optional pre-commit hook:

```bash
pipx install pre-commit
pre-commit install
```

The pre-commit hook runs `scripts/secret-scan.sh --staged`. If `gitleaks` is installed, the same script also runs `gitleaks protect --staged --redact --verbose`.

Before opening a PR, also run the history check:

```bash
scripts/secret-scan.sh --history
```

Do not commit:
- `.env` or `.env.*` files other than `.env.example`
- API keys, JWTs, `SECRET_KEY`, `VAULT_KEY`, Fernet keys, database passwords, or admin passwords
- `.playwright-mcp`, Playwright reports, browser storage state, traces, HAR files, or debug logs
- local scanner state, generated reports, database files, captures, or root-level temporary screenshots
- local filesystem paths or private network details from real environments

## Reporting security vulnerabilities

Do **not** open a public issue for security bugs. Email the maintainer directly instead. Include reproduction steps and impact assessment.

## Plugin contributions

New plugins must:
- Extend `PluginBase` and implement `check(context, host) -> list[FindingData]`
- Include a docstring describing what the plugin tests
- Set an accurate default severity
- Only test conditions that are clearly misconfigured or vulnerable — no false-positive-prone heuristics
- Be placed in the correct category subdirectory under `backend/scanr/plugins/`

## Code style

- Python: follow existing patterns, no new dependencies without discussion
- TypeScript: strict mode, no `as any`
- Keep PRs small and reviewable
