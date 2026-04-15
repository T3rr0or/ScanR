# Contributing to ScanR

Thank you for your interest in contributing.

## Ground rules

- Only submit code you have the right to license under MIT.
- All scan/test code must target systems you own or have explicit written permission to test.
- Do not add features that facilitate unauthorized access or evasion of detection systems.

## How to contribute

1. Fork the repository and create a branch from `main`.
2. Make your changes. Keep commits focused — one logical change per commit.
3. Test your changes locally with `docker compose up -d --build`.
4. Open a pull request with a clear description of what changed and why.

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
