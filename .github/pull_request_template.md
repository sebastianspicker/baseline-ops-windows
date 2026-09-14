# Summary

<!-- Explain the problem and what a user or contributor will see after this change. -->

## Scope and risk

- [ ] Audit-only / read-only behavior
- [ ] Remediation or state-changing behavior
- [ ] Orchestration/profile behavior
- [ ] Docs, tests, or GitHub metadata only

## Release impact

- [ ] No changes to shipped behavior or documentation
- [ ] User-visible behavior, examples, or limitations changed
- [ ] Packaging, provenance, or GitHub release automation changed

Target version or release note: <!-- Use "none" when not applicable. -->

### Risk notes

<!-- Describe security, privacy, compatibility, or operational risks. -->

## Validation

- [ ] Tested on a lab VM
- [ ] PowerShell version(s):
- [ ] Windows version(s):
- [ ] `pwsh -NoProfile -File .\tools\verify.ps1 -RootPath . -SkipAnalyzer`
- [ ] `pwsh -NoProfile -Command "Import-Module PSScriptAnalyzer -RequiredVersion 1.25.0 -Force; & .\tools\verify.ps1 -RootPath ."`
- [ ] `pwsh -NoProfile -File .\tools\secret-scan.ps1 -RootPath .`
- [ ] `pwsh -NoProfile -File .\tools\Test-Documentation.ps1 -RootPath .`
- [ ] `pwsh -NoProfile -Command "Import-Module Pester -RequiredVersion 5.8.0 -Force; Invoke-Pester -Path .\tests -CI -Output Detailed"`
- [ ] Relevant code-quality and Rust checks from `CONTRIBUTING.md`
- [ ] Native Windows validation completed where behavior requires it

### Skipped checks and reason

<!-- List checks you could not run and why, including any Windows-only checks. -->

## Safety checklist

- [ ] Script changes keep Audit as the default where possible
- [ ] State-changing paths use `SupportsShouldProcess`, `-WhatIf`, and `-Confirm`
- [ ] Profile input cannot override runner-owned path, integrity, or
      confirmation controls
- [ ] Generated evidence, logs, local audit notes, and secrets are not committed
- [ ] Public docs or examples were updated when behavior changed
