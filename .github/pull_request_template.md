## Summary
- 

## Scope and risk
- [ ] Audit-only / read-only behavior
- [ ] Remediation or state-changing behavior
- [ ] Orchestration/profile behavior
- [ ] Docs, tests, or GitHub metadata only

Risk notes:
-

## Validation
- [ ] Tested on a lab VM
- [ ] PowerShell version(s):
- [ ] Windows version(s):
- [ ] `pwsh -NoProfile -File .\tools\verify.ps1 -RootPath . -SkipAnalyzer`
- [ ] `pwsh -NoProfile -File .\tools\verify.ps1 -RootPath .`
- [ ] `pwsh -NoProfile -File .\tools\secret-scan.ps1 -RootPath .`
- [ ] `pwsh -NoProfile -Command "Invoke-Pester -Path .\tests -CI -Output Detailed"`

Skipped checks and reason:
-

## Safety checklist
- [ ] Script changes keep audit-first defaults where possible
- [ ] State-changing paths use `SupportsShouldProcess`, `-WhatIf`, and `-Confirm`
- [ ] Profile input cannot override runner-owned path, integrity, or confirmation controls
- [ ] Generated evidence, logs, local audit notes, and secrets are not committed
- [ ] Public docs or examples were updated when behavior changed
