# Contributing

Keep changes small, reviewable, and safe for endpoint operations.

## Baseline rules

- Never commit secrets, tokens, credentials, or private keys.
- Prefer behavior-preserving refactors unless the PR explicitly documents a breaking change.
- For remediation scripts, verify `ShouldProcess` semantics (`-WhatIf`/`-Confirm`) before merge.
- Use shared `lib/` modules instead of adding new inline helper duplicates.

## Development flow

1. Create a branch.
2. Implement focused changes.
3. Run local checks.
4. Open a PR with scope, risks, and validation evidence.

Keep PRs scoped to one behavior change or documentation cleanup. If a change
touches orchestration, profile parsing, remediation, or runner integrity, call
that out explicitly in the PR summary and include a focused regression test.

## Required local checks

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\tools\verify.ps1 -SkipAnalyzer
pwsh -NoProfile -ExecutionPolicy Bypass -File .\tools\verify.ps1
pwsh -NoProfile -ExecutionPolicy Bypass -File .\tools\secret-scan.ps1
pwsh -NoProfile -Command "Invoke-Pester -Path .\tests -Output Detailed"
```

Or run:

```bash
./scripts/ci-local.sh
```

## Documentation policy

Root docs are intentionally minimal:

- `README.md`
- `CONTRIBUTING.md`
- `SECURITY.md`
- `CHANGELOG.md`

Move implementation plans and experiments to PR descriptions.
Do not commit generated evidence, local audit ledgers, remediation scratch
plans, deprecated docs, or machine-specific harness state.

## Security reporting

See [SECURITY.md](SECURITY.md).
