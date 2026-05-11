# Dry-Run Findings and Fix Proposals

Date: 2026-05-11

## Environment

| Item | Result |
| --- | --- |
| Repository | `win-mdm-security-hardening-kit` |
| Host OS | Microsoft Windows 10.0.28000 |
| PowerShell | 7.6.1, Core, Win32NT |
| Elevation | Non-elevated shell |
| Windows Sandbox | Not directly callable from this shell; `WindowsSandbox.exe` was not discoverable and checking `Containers-DisposableClientVM` required elevation. |
| Disposable fallback sandbox | `C:\Users\sebastian\AppData\Local\Temp\win-mdm-dryrun-sandbox-db5504491e694122838bb664600eb4e5`, copied without `.git`. |
| Pester | Initially only 3.4.0 was available; Pester 5.7.1 is now available from `C:\Users\sebastian\Documents\PowerShell\Modules\Pester\5.7.1\Pester.psd1`. |
| PSScriptAnalyzer | Available during the final disposable-copy sandbox run; `tools/verify.ps1` completed analyzer checks successfully. |

Windows Sandbox was the intended safe environment, but it was not available to this non-elevated automation session. The final runs below therefore used a disposable copy of the repository without `.git`, local safe checks, orchestration `-WhatIf`, profile validation, secret scanning, and a small no-write audit subset. No destructive remediation was run.

## Command Matrix

| Area | Command | Exit | Result |
| --- | --- | ---: | --- |
| Static parse | `pwsh -NoProfile -ExecutionPolicy Bypass -File .\tools\verify.ps1 -SkipAnalyzer` | 0 | Parsed 79 PowerShell files successfully. |
| Static parse + analyzer gate | `pwsh -NoProfile -ExecutionPolicy Bypass -File .\tools\verify.ps1` | 0 | Parsed 79 PowerShell files; PSScriptAnalyzer completed successfully. |
| Secret scan | `pwsh -NoProfile -ExecutionPolicy Bypass -File .\tools\secret-scan.ps1` | 0 | Fixed: non-git sandbox copy falls back to recursive scan; no matches found. |
| Pester, full test suite | `pwsh -NoProfile -Command "Invoke-Pester -Path .\tests -Output Detailed"` | 0 | Passed with Pester 5.7.1: 730 passed, 9 skipped. |
| Batch dry-run | `pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\00-Run-Batch.ps1 -Category All -Mode Audit -OutputFormat None -WhatIf -Confirm:$false` | 0 | Skipped execution through `ShouldProcess`; no child scripts ran. |

All sample profiles under `examples/profiles` passed validation:

| Profile | Validate Exit | Profile `-WhatIf` Exit | Observation |
| --- | ---: | ---: | --- |
| `baseline-audit.json` | 0 | 0 | Steps skipped by `-WhatIf`; runner now exits successfully when no real failures occur. |
| `compliance-full.json` | 0 | 0 | Steps skipped by `-WhatIf`; runner now exits successfully when no real failures occur. |
| `endpoint-health-check.json` | 0 | 0 | Steps skipped by `-WhatIf`; runner now exits successfully when no real failures occur. |
| `full-audit.json` | 0 | 0 | Steps skipped by `-WhatIf`; runner now exits successfully when no real failures occur. |
| `hardening-remediate.json` | 0 | 0 | Steps skipped by `-WhatIf`; runner now exits successfully when no real failures occur. |
| `incident-response.json` | 0 | 0 | Steps skipped by `-WhatIf`; runner now exits successfully when no real failures occur. |
| `rapid-triage.json` | 0 | 0 | Steps skipped by `-WhatIf`; runner now exits successfully when no real failures occur. |

Representative direct audit checks were limited to scripts that do not appear to write files by default, plus Defender health as a common audit entrypoint:

| Script | Command Shape | Exit | Observation |
| --- | --- | ---: | --- |
| `46-SecureBoot-UEFI-Audit.ps1` | `-OutputFormat None -PassThru` | 0 | Completed. |
| `47-WDAG-Readiness-Audit.ps1` | `-OutputFormat None -PassThru` | 0 | Fixed: filtered finding counts now force array semantics. |
| `48-ExploitProtection-Audit.ps1` | `-OutputFormat None -PassThru` | 0 | Completed. |
| `49-DriverSigning-Integrity-Audit.ps1` | `-OutputFormat None -PassThru` | 0 | Fixed: filtered finding counts now force array semantics. |
| `50-AMSI-Audit.ps1` | `-OutputFormat None -PassThru` | 0 | Completed. |
| `51-AppLocker-Audit.ps1` | `-OutputFormat None -PassThru` | 0 | Completed. |
| `52-DoH-Audit.ps1` | `-OutputFormat None -PassThru` | 0 | Completed. |
| `27-Defender-Health-Audit.ps1` | `-OutputFormat None -PassThru -SkipAdminCheck` | 0 | Fixed: omitted settings path is accepted; array conversion for findings is stable on PowerShell 7.6. |

## Issues and Fix Proposals

| Severity | Area | Issue | Proposed Fix |
| --- | --- | --- | --- |
| Medium | Tooling | The documented Pester command expects Pester 5, but the host has Pester 3.4.0. | Add a local bootstrap check, or document/install Pester 5 before test execution. The CI workflow already installs Pester 5.7.1, so mirror that in `scripts/ci-local.sh` for Windows shells or add a PowerShell-native setup helper. |
| Medium | Tooling | `tools/verify.ps1` exits 0 when `PSScriptAnalyzer` is missing, so local "full" verification may silently skip analyzer coverage. | Keep the current soft-skip for developer convenience, but add a clear command or switch for strict analyzer enforcement, for example `-RequireAnalyzer`, and use it in CI or release validation. |
| Low | Orchestration | `00-Run-Profile.ps1 -WhatIf` marks every step as skipped and exits 2. This is internally consistent but awkward for dry-run smoke checks where "all skipped by WhatIf" is expected success. | Consider treating `-WhatIf` skips as exit 0 when no real failures occur, or add a runner switch such as `-AllowWhatIfSkipExitZero` for CI/smoke scenarios. Preserve normal dependency-skip warning behavior outside `-WhatIf`. |
| Medium | Script contract | `47-WDAG-Readiness-Audit.ps1` and `49-DriverSigning-Integrity-Audit.ps1` call `.Count` on filtered pipeline output. When exactly one object is returned, the result can be scalar and has no `Count` property. | Wrap filtered results in array subexpressions before counting, for example `@($Findings \| Where-Object { $_.Severity -eq 'High' }).Count`. Apply the same pattern to medium-severity counts. |
| Medium | Script contract | `27-Defender-Health-Audit.ps1` calls `Try-LoadJsonConfig -Path $SettingsJsonPath` while `$SettingsJsonPath` can be empty, but the function parameter is mandatory and does not allow empty strings. | Either call `Try-LoadJsonConfig` only when the path is non-empty, or add `[AllowEmptyString()]` and remove mandatory binding friction from the function parameter. |
| Low | Script contracts | Some audit-only scripts declare `[ValidateSet('Audit')]` rather than the shared `Audit|Remediate` v2 mode shape. This is safe for direct use, but it means contract inventory needs to distinguish audit-only scripts. | Keep audit-only behavior, but update contract tests/docs to explicitly accept `[ValidateSet('Audit')]` for non-remediation scripts or standardize all scripts on the same mode parameter with explicit remediation rejection. |
| Low | Module hygiene | Several imports emit unapproved verb warnings from `Common`, `Registry`, and `External`. | Rename exported helper functions to approved verbs over time, or suppress expected warnings in operator-facing runs where the warnings reduce signal. |
| Low | Tooling | `tools/secret-scan.ps1` originally assumed a Git worktree. In a copied sandbox without `.git`, `git ls-files` failed and left a stale native exit code. | Detect whether the root is inside a Git worktree before using tracked files. Fall back to a recursive filtered scan for copied directories and reset native exit-code state after a failed Git probe. |
| Low | Windows Sandbox | Sandbox availability could not be checked or launched without elevation from this session. | Add a repeatable sandbox runbook or helper `.wsb` template that maps the repo read-only and writes logs to a mapped output folder. Run it from an elevated interactive session when validating Windows-only behaviors. |

## Fix Status

| Area | Status |
| --- | --- |
| Pester 5 local bootstrap | Fixed in `scripts/ci-local.sh` by installing Pester 5.7.1 when tests are enabled. |
| Strict analyzer enforcement | Fixed in `tools/verify.ps1` with `-RequireAnalyzer`; default behavior still soft-skips for developer convenience. |
| Profile `-WhatIf` exit code | Fixed in `00-Run-Profile.ps1`; `-WhatIf` exits 0 when no real failures occur. |
| Filtered finding counts | Fixed in `47-WDAG-Readiness-Audit.ps1` and `49-DriverSigning-Integrity-Audit.ps1`. |
| Defender empty settings path | Fixed in `27-Defender-Health-Audit.ps1`; also suppresses helper return output and avoids PowerShell 7.6 collection binding failures. |
| Import warning noise | Fixed by adding `-DisableNameChecking` to imports of `Common.psm1`, `Registry.psm1`, and `External.psm1` in script/test entrypoints. |
| Secret scan in copied sandbox | Fixed in `tools/secret-scan.ps1`; it now supports non-git directory scans and includes a Pester regression test. |
| Windows Sandbox | Still environment-blocked from this non-elevated session. |

## Suggested Next Sandbox Pass

When Windows Sandbox is available, run these commands inside the disposable VM from the repo root:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\tools\secret-scan.ps1
pwsh -NoProfile -ExecutionPolicy Bypass -File .\tools\verify.ps1 -SkipAnalyzer
pwsh -NoProfile -ExecutionPolicy Bypass -File .\tools\verify.ps1
pwsh -NoProfile -Command "Invoke-Pester -Path .\tests -Output Detailed"
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\00-Run-Batch.ps1 -Category All -Mode Audit -OutputFormat None -WhatIf -Confirm:$false
```

For direct script-body checks, prefer:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\<script>.ps1 -Mode Audit -OutputFormat None -PassThru -Confirm:$false
```

For remediation-capable scripts, use only:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\<script>.ps1 -Mode Remediate -WhatIf -Confirm:$false
```

Do not run remediation without `-WhatIf` during sandbox smoke testing unless the test case explicitly requires observing the resulting system state and the sandbox will be discarded immediately after capture.

## Acceptance Notes

- The follow-up pass fixed the documented script, tooling, and orchestration issues that could be addressed locally.
- The disposable-copy sandbox pass also found and fixed a copied-directory `secret-scan` failure that was not visible in the original Git worktree.
- No profile schema changes were made.
- Windows Sandbox validation still requires an elevated interactive environment where Sandbox is installed/enabled.

## Follow-Up Remediation Pass

Date: 2026-05-11

Additional safe-environment checks used a fresh disposable repository copy at:

`C:\Users\sebastian\AppData\Local\Temp\win-mdm-dryrun-sandbox-838d375304fb4fc9b125c60d1e615bda\repo`

### Additional Issues Fixed

| Severity | Area | Finding | Fix |
| --- | --- | --- | --- |
| High | Module contract | `Results.psm1` used `Get-CallerValue` without owning or importing it, so direct `Add-Finding` calls could fail in module scope. | Added a private `Get-CallerValue` helper to `Results.psm1`. |
| High | Module contract | `Config.psm1` initially imported `Common.psm1` internally to use path sanitization; with `-Force`, this could hide previously imported `Common` commands from script scope. | Replaced that import with a private `Sanitize-ConfigPath` helper. |
| High | PowerShell 7.6 compatibility | Generic lists and `[System.Collections.ArrayList]@(...)` caused binder/conversion failures in direct script runs. | Added `ConvertTo-ArrayList` and `ConvertTo-ObjectArray`; normalized findings before result serialization. |
| High | Findings contract | Some direct audit paths still relied on implicit caller-scope finding discovery. | Made `Add-Finding` calls explicit with `-FindingList` across the touched scripts and helper modules. |
| Medium | UI helper compatibility | Several scripts used existing call shapes such as `Write-KeyValue -Style`, `Write-KeyValue -Level`, positional color arguments, and `Write-UiList -Header`; the shared helper did not accept all of them. | Extended `Output.psm1` aliases and list handling to match existing script usage, including empty-list no-op behavior. |
| Medium | Direct audit defaults | Several scripts had null default proof/config/evidence paths that failed only when run directly outside a profile. | Added safe temp defaults and empty-path guards for Scheduled Tasks Hygiene, Support Bundle, IOC Sweep, Remote Access Guardrails, Missing Patch Notification, LAPS, LSASS/VBS, and Join Identity. |
| Medium | Native output handling | Sysmon drift probing parsed failed `wevtutil` output as XML. | Checked native success before XML parsing and records channel absence as an audit finding instead of a conversion error. |
| Medium | WEF readiness | `Add-Finding` emitted list objects into helper output, turning expected PSCustomObjects into arrays. | Suppressed helper `Add-Finding` output and guarded returned indicator property access. |
| Medium | Orchestration confirmation | `00-Run-Batch.ps1` could enter an unsafe confirmation prompt path during direct runs. | Lowered `ConfirmImpact` so non-remediation audit orchestration does not trip the null confirmation path. |
| Medium | Direct audit defaults | `04`, `15`, and `19` still used placeholder proof/state paths such as `PATH/TO/PROOF...`, which could create generated artifacts under the repository during direct runs. | Replaced runtime defaults with temp-directory paths and confirmed no `PATH/` artifact is recreated. |

### Final Local Verification

| Check | Command | Result |
| --- | --- | --- |
| Static + analyzer | `pwsh -NoProfile -ExecutionPolicy Bypass -File .\tools\verify.ps1 -RequireAnalyzer` | Pass: 79 PowerShell files parsed, PSScriptAnalyzer OK. |
| Secret scan | `pwsh -NoProfile -ExecutionPolicy Bypass -File .\tools\secret-scan.ps1` | Pass: no matches. |
| Pester | `pwsh -NoProfile -Command "Invoke-Pester -Path .\tests -Output Detailed"` | Pass: 730 passed, 0 failed, 9 skipped. |
| Whitespace | `git diff --check` | Pass; only Git line-ending normalization warnings were reported. |
| Profiles | all `examples/profiles/*.json` via validate + profile `-WhatIf` | Pass: validate exit 0 and profile `-WhatIf` exit 0 for every profile. |
| Batch `-WhatIf` | `.\scripts\00-Run-Batch.ps1 -Category All -Mode Audit -OutputFormat None -WhatIf -Confirm:$false` | Pass: exit 0. |

### Final Direct Audit Sweep

The apparent long-running direct audit issues were retested with stdout/stderr redirected to files instead of held in an unread process pipe. The earlier timeout behavior was caused by the smoke harness blocking on verbose output, not by the scripts hanging.

| Script Set | Result |
| --- | --- |
| `04`, `05`, `14`, `19`, `29`, `30` | Completed within the 180-second cap with no exception patterns when output was redirected to files. Non-zero exits were audit/drift outcomes where applicable. |
| `11-IOC-Sweep-Defender.ps1 -ScanType None` | Completed with exit 0 and no exception patterns. Full Defender scan remains intentionally operator-controlled because it can take a long time by design. |
| `46` through `52` | Completed with exit 0 and no exception patterns when invoked with their audit-only parameter contract. The earlier `-Confirm` failures were harness misuse, not script defects. |

### Residual Limits

- Real Windows Sandbox could not be launched from this non-elevated session because `WindowsSandbox.exe` was not available and feature inspection required elevation.
- Some scripts exit non-zero for expected host state, missing elevation, unavailable Windows features, or detected drift. Those are audit results, not script crashes.
