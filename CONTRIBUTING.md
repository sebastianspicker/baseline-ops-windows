# Contributing

Keep changes small, reviewable, and safe for endpoint operations.

## Baseline Rules

- Never commit secrets, tokens, credentials, private keys, or generated evidence.
- Prefer behavior-preserving refactors unless the PR explicitly documents a breaking change.
- For remediation scripts, verify `ShouldProcess` semantics through `-WhatIf` and `-Confirm`.
- Use shared `lib/` modules instead of adding inline helper duplicates.
- Treat profile JSON as untrusted run input.

## Development Flow

1. Create a branch.
2. Implement one focused change.
3. Run the relevant local checks.
4. Open a PR with scope, risk, and validation evidence.

If a change touches orchestration, profile parsing, remediation, or runner integrity, call that out in the PR summary and include a focused regression test.

## Required Local Checks

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\tools\verify.ps1 -SkipAnalyzer
pwsh -NoProfile -ExecutionPolicy Bypass -File .\tools\verify.ps1
pwsh -NoProfile -ExecutionPolicy Bypass -File .\tools\secret-scan.ps1
pwsh -NoProfile -Command "Invoke-Pester -Path .\tests -CI -Output Detailed"
npm ci
npm test
```

Run the PowerShell gates together with:

```bash
./scripts/ci-local.sh
```

## Documentation Policy

Root docs are intentionally minimal:

- `README.md`
- `CONTRIBUTING.md`
- `SECURITY.md`
- `CHANGELOG.md`

Keep implementation plans, experiments, audit ledgers, remediation scratch plans, deprecated docs, agent instructions, and machine-specific workspace state out of commits.

Only `docs/README.md` and `docs/launcher-gui.md` are currently allowlisted under
`docs/`. Add any new durable public document to the index, `.gitignore` allowlist,
and public-surface verifier in the same change. Keep private or generated
material in ignored local lanes; never force-add it.

## Security Reporting

Use [SECURITY.md](SECURITY.md) for vulnerability reporting.
