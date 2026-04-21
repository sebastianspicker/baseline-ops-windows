# Changelog

All notable changes to this project are documented in this file.

## [2.2.0] - 2026-04-18

### Added

- **v2 UnsupportedHost platform guard** added to all 49 numbered scripts
  (`01`–`49`). Every script now returns `Result=OK` with
  `Metadata.UnsupportedHost=true` when executed on a non-Windows host,
  preventing orchestration crashes during cross-platform CI smoke tests.
  Scripts 31 and 43 already had the guard; the remaining 47 are addressed
  in this release.
- **`scripts/private/` helper layer**: extracted helper functions from
  three large scripts into dedicated dot-sourced files:
  `04-OfficeBrowser-Hardening-Proof.helpers.ps1` (~530 lines),
  `09-SupportBundle.helpers.ps1` (~577 lines),
  `12-Suspicious-Artifact-Grabber.helpers.ps1` (~677 lines).
  All three parent scripts are now well under the 800-line budget.
- **`tests/scripts/PrivateHelpers.Tests.ps1`**: 35 Pester unit tests
  covering the three new helper files (pure functions, constructor
  helpers, symbol-export checks). All 35 pass.
- **`tests/scripts/ScriptLineBudget.Tests.ps1`**: enforces an 800-line
  ceiling on all `scripts/NN-*.ps1` numbered scripts.
- **3 new security audit scripts** (scripts 50–52):
  - `50-AMSI-Audit.ps1`: audits AMSI provider registration, detects known
    bypass artifacts, checks PowerShell Script Block Logging, and reports
    Windows Script Host AMSI integration status.
  - `51-AppLocker-Audit.ps1`: enumerates AppLocker effective policy per
    rule collection (Exe/Script/MSI/DLL/Appx), checks enforcement vs.
    AuditOnly mode, verifies Application Identity service state.
  - `52-DoH-Audit.ps1`: audits Windows DNS client DoH configuration
    (`EnableAutoDoh`), validates configured resolvers against known
    DoH-capable servers, and reports plaintext DNS fallback posture.
  All three follow the full v2 contract and pass V2Contract.Tests.ps1.
- **`tests/lib/Sanitization.Tests.ps1`**: proper Pester test file
  converted from the standalone `tests/Verify-Sanitization.ps1` script.
  8 tests covering `Sanitize-Path`, `Read-ConfigWithDefaults`, and
  `ConvertTo-Hashtable` are now automatically discovered by `Invoke-Pester`.
- Scripts 50–52 added to `examples/profiles/full-audit.json`.

### Changed

- **`#Requires -RunAsAdministrator`** added to scripts 24, 32, 38, 39,
  40, and 44. These scripts already called `Require-Admin` at runtime;
  the directive makes the elevation requirement explicit at invocation and
  consistent with the rest of the elevated-script set (18, 22, 23, 31, 33).
- **CI branch trigger** (`ci.yml`) extended to also cover `feat/**`
  branches (previously only `fix/**` feature branches triggered CI).
- **`scripts/README.md`** audit table expanded: scripts 03, 04, 06, 13,
  14, 16, 18, and 22 added to the Audit table (they were listed only
  under Remediation despite supporting both modes). New `Private Helpers`
  section added. Scripts 50–52 added to catalog.
- **Root `README.md`** script catalog updated (52 scripts, rows 50–52 added).
- **`scripts/TODO-future-scripts.md`**: AMSI, AppLocker, and DoH items
  marked as completed (implemented in scripts 50–52).
- **Doc-comment whitespace** cleaned up in scripts 02, 06–08, 10–11,
  14, 16–18: redundant blank lines between `.PARAMETER` entries removed.
- **Switch parameter defaults** cleaned up: removed redundant `= $false`
  defaults from `[switch]$EmitObject` in `09-SupportBundle.ps1` and
  `[switch]$ShowOkInConsole` in `18-Firewall-Baseline.ps1`
  (`PSAvoidDefaultValueSwitchParameter` compliance).

### Fixed

- Stale `# TODO: This script exceeds 800 lines` markers removed from
  scripts 04, 09, and 12 (helpers already extracted; budget met).
- Missing `## [2.1.0] - 2026-04-11` version header added to CHANGELOG
  (the 2.1.0 content was present but had no version marker).

## [2.1.0] - 2026-04-11

### Added

- **4 new security audit scripts**: `46-SecureBoot-UEFI-Audit.ps1` (Secure Boot
  and UEFI firmware verification), `47-WDAG-Readiness-Audit.ps1` (Application
  Guard prerequisites), `48-ExploitProtection-Audit.ps1` (system/process
  exploit mitigations and ASR rules), `49-DriverSigning-Integrity-Audit.ps1`
  (driver signing enforcement and HVCI status). All follow v2 contract with
  C10 findings pattern.
- **4 new execution profiles**: `full-audit.json` (all 49 audit scripts),
  `endpoint-health-check.json` (health-focused subset),
  `incident-response.json` (IR triage with DependsOn ordering),
  `compliance-full.json` (compliance-focused audit battery).
- **`New-SafeFileName`** function in `lib/Common.psm1` for sanitizing file
  names by replacing invalid characters.
- **`CustomFields` parameter** in `Write-ConsoleSummary` (`lib/Console.psm1`)
  for injecting domain-specific key-value lines into summary output.

### Changed

- **Batch categories expanded**: 17 scripts added to Audit category
  (03, 04, 06, 07, 11, 13, 14, 18, 20, 22, 24, 31, 32, 34, 38, 39, 40, 41),
  6 scripts added to Remediation category (06, 07, 08, 25, 32, 38).
  3 orphan scripts (07, 24, 41) now included in appropriate categories.
- **13 scripts migrated to C10 findings pattern** (`New-FindingsList`/`Add-Finding`):
  6 moderate (06, 10, 20, 24, 25, 29) and 6 hard (04, 05, 07, 14, 15, 16)
  conversions plus 1 easy fix (33). C10 compliance rose from 47% to 82%.
- **7 scripts migrated to lib `Write-ConsoleSummary`**: scripts 08, 27, 31, 33,
  34, 36, 41 replaced local Write-ConsoleSummary implementations with the
  canonical `lib/Console.psm1` version using `CustomFields`. ~330 lines removed.
- **9 local `Save-Json` variants consolidated**: scripts 04, 05, 06, 07, 11,
  12, 15, 17, 20 replaced local JSON-write functions with canonical
  `lib/Serialization.psm1:Save-Json`. ~110 lines removed; all writes now
  include path-traversal guards.
- **`Get-StatusColor` 'Note' mapping added** to `lib/Console.psm1` regex
  normalizer, enabling drop-in replacement in script 08.

### Fixed

- **3 orphan scripts** (07-ScheduledTasks-Hygiene, 24-Cert-AutoEnrollment-Health,
  41-NTLM-Audit-Client) added to batch categories in `00-Run-Batch.ps1`.

## [2.0.2] - 2026-03-21

### Fixed

- **Security hardening (Phase 2.1, S6-S17)**: auditpol subcategory input validation,
  registry key path allowlist enforcement, firewall RulePrefix validation, direct
  wevtutil calls replaced with `Invoke-Wevtutil` wrapper, driveId CIM filter escaping,
  dangerous winget `ExtraArgs` filtering, hardcoded WinRM CIM filter safety comment,
  SupportBundle wevtutil refactored to wrapper, `Export-ScheduledTask` path traversal
  check, environment variable expansion before traversal check in `Evidence.psm1`,
  `New-MdmScheduledTask` TaskName input validation, Sysmon drift sensor ScriptPath validation.
- **Static analysis fixes (Phase 2.2)**: added `Set-StrictMode -Version Latest` to
  3 scripts missing it, fixed `$null` ordering (`$LASTEXITCODE -eq $null` to
  `$null -eq $LASTEXITCODE`), removed unused variable assignments (`$eventLogReady`,
  `$canEventLog`), guarded `$InformationPreference = 'Continue'` override behind
  `$Quiet` check, removed 20 local function redefinitions replaced by lib imports.
- **Error handling standardization (Phase 4.2)**: 94 empty catch blocks annotated
  with `<# best-effort #>` across 19 scripts, 9 bare `throw` statements converted
  to `Add-Finding` + v2 FAIL result + `exit 1`, 3 silent catches in IOC-Sweep
  converted to `Write-Warning`, 4 bare re-throws replaced with v2 FAIL output.
- **Path traversal guards (Phase 4.3)**: added `Assert-NoPathTraversal` for
  config-driven output paths in `09-SupportBundle.ps1` and `12-Suspicious-Artifact-Grabber.ps1`.

### Changed

- **Convention alignment (Phase 2.3)**: `ErrorActionPreference = 'Stop'` added to
  10 scripts (now 100%), `exit 0` added to 40 scripts (now 100%), v2 output contract
  (`New-V2ResultObject` + `Write-ResultObject`) added to 44 scripts (94% coverage),
  1 script converted to `New-FindingsList`/`Add-Finding` pattern.
- **Lib deduplication (Phase 4.1)**: removed `Read-JsonConfig` from `Common.psm1`
  (sole caller migrated to `Read-JsonFileSafe`), removed `Write-JsonToFile` from
  `JsonCatalog.psm1` (consolidated on `Save-Json` with path-traversal guard),
  removed 8 local function copies across scripts (`Try-LoadJsonFile`, `Load-JsonFile`,
  `Read-Json`, `Read-JsonFile`, `Expand-Env`, `Ensure-Directory`).
- **Hardcoded paths replaced with env variables (Phase 4.3)**: `C:\Windows\` to
  `$env:SystemRoot`, `C:\Program Files\` to `$env:ProgramFiles`,
  `C:\Program Files (x86)\` to `${env:ProgramFiles(x86)}` across scripts 07, 08, 16.
- **Write-Rule name collision resolved (Phase 4.3)**: renamed `Console.psm1`'s
  `Write-Rule` to `Write-DecorativeRule`; updated all internal and script callers.
- **Invoke-Git collision resolved (Phase 4.3)**: renamed local `Invoke-Git` in
  `00-Copy-Local.ps1` to `Invoke-GitCommand` to avoid collision with `External.psm1`.
- **Has-Property extracted to `Common.psm1` (Phase 4.3)**: removed duplicate local
  definitions from `00-Run-Profile.ps1` and `00-Validate-Profile.ps1`.
- **Set-RegString shadow removed (Phase 4.3)**: removed local `Set-RegString` from
  `31-PowerShell-Logging-Baseline.ps1`; lib `Registry.psm1` version already imported.
- **Style tokens (Phase 4.3)**: replaced `DarkCyan`/`DarkYellow`/`DarkGray`
  `-ForegroundColor` calls with semantic `-Style` tokens (`Header`, `Warning`,
  `Muted`, `Accent`) in 6 scripts.

### Added

- **176 new Pester tests (329 to 505)**: 7 new test files for previously untested
  lib modules (`Config`, `Results`, `JsonCatalog`, `Evidence`, `EventLog`,
  `External`, `Output`), 99 tests added to 6 existing test files (`Execution`,
  `Validation`, `Common`, `Console`, `Serialization`, `Registry`), 18 orchestration
  integration tests for `00-Validate-Profile`, `00-Run-Batch`, `00-Report-Aggregate`.
- **Path traversal guards** on config-driven output paths (`Assert-NoPathTraversal`).
- **Has-Property** extracted to `lib/Common.psm1` as a shared utility.

## [2.0.1] - 2026-03-17

### Fixed

- **Invoke-NativeProcess deadlock** (`lib/Execution.psm1`): stdout/stderr
  `ReadToEnd()` was called after `WaitForExit()`, causing a classic pipe-buffer
  deadlock for child processes that emit more than ~64 KB. Fixed with async reads
  started before `WaitForExit()`.
- **WQL injection** (`scripts/02-LAPS-Hygiene.ps1`, `scripts/11-IOC-Sweep-Defender.ps1`):
  account name and service name values from registry/JSON config were interpolated
  directly into CIM filter strings without escaping single quotes. Fixed with
  `$value -replace "'", "''"` before filter construction.
- **PowerShell code injection via scheduled task** (`scripts/21-EmergencyKillSwitch.ps1`):
  `$TaskName` and `$RuleNames` from config JSON were embedded in a PowerShell
  heredoc that is base64-encoded and run elevated. Added input validation in
  `Schedule-AutoRollback` (TaskName must match `[a-zA-Z0-9\-_\\]+`; RuleNames
  must not contain single quotes) before heredoc construction.
- **schtasks invocation hardened** (`scripts/21-EmergencyKillSwitch.ps1`):
  converted bare-token schtasks call to array-based invocation.
- **Runtime bugs in Output aliases** (`lib/Output.psm1`, scripts): `Write-Ui -BlankLine`
  and `Write-Ui -Text` callers used parameters the wrapper did not expose; fixed
  to canonical `Write-BlankLine` and `Write-UiLine -Text`.
- **CI: Pester exit code** (`.github/workflows/ci.yml`): `Invoke-Pester` was
  called without `-CI`, so Pester 5 returned exit code 0 even when tests failed —
  test failures silently passed CI. Added `-CI` flag.
- **CI: Scorecard permissions** (`.github/workflows/scorecard.yml`): replaced
  overly broad `permissions: read-all` with minimal `permissions: { contents: read }`;
  job-level write scopes already set correctly.

### Changed

- **Alias cleanup — Output.psm1**: removed 16 alias wrapper functions
  (`Write-ConsoleKV`, `Write-UiKV`, `Write-UiKv`, `Write-UiKeyValue`,
  `Write-KV`, `Write-KvLine`, `Write-ConsoleKeyValue`, `Write-PrettyKeyValue`,
  `Write-ColorValue`, `Write-PrettyLine`, `Write-ColoredLine`, `Write-PrettyHeader`,
  `Write-Console`, `Write-HostLine`, `Write-Ui`, and one kept as `Write-Kv`).
  ~330 call-sites across 8 scripts updated to canonical names.
- **Alias cleanup — Common.psm1**: removed 5 alias functions (`Is-Admin`,
  `Test-IsAdministrator`, `Ensure-Dir`, `Ensure-Folder`, `Ensure-FolderForFile`).
  All call-sites updated to canonical names.
- **Dead parameter removal — EventLog.psm1**: removed `$EventLogReady` /
  `$CanEventLog` compatibility parameters from `Write-HealthEvent`; removed
  redundant `[Parameter(Mandatory = $false)]` annotations from `Ensure-EventSource`.
- **Null-splat guard removed** (`lib/Execution.psm1`): simplified `Invoke-ScriptWithTiming`
  to `& $ScriptPath @Arguments` (empty array splat is a no-op).
- **Export-ModuleMember formatted** (`lib/Output.psm1`): reformatted from a
  single 714-char line to a multi-line backtick-continued list.
- **lib/README.md**: removed stale alias reference for `Is-Admin`/`Ensure-Folder`.
- **CI: Pester version pinned** (`.github/workflows/ci.yml`): added
  `PESTER_VERSION: '5.7.1'` env, module cache step, and explicit install step
  to `test-windows` job (mirrors `verify` job's PSScriptAnalyzer pattern).
- **Alias cleanup — Registry.psm1**: removed `Get-RegValueSafe` forwarding
  wrapper; updated 3 call-sites in `scripts/34-TimeSync-Health.ps1` to
  `Get-RegValue`.
- **Test coverage**: added tests for `Assert-NoPathTraversal`, `Test-SafeUrl`,
  and `Test-PathUnderRoot` in `tests/lib/Validation.Tests.ps1`.

## [2.0.0] - 2026-02-27

### Added

- New orchestration layer:
  - `scripts/00-Validate-Profile.ps1`
  - `scripts/00-Run-Profile.ps1`
  - `scripts/00-Run-Batch.ps1`
  - `scripts/00-Report-Aggregate.ps1`
- New shared modules:
  - `lib/Validation.psm1`
  - `lib/Execution.psm1`
  - `lib/Serialization.psm1`
- Example profiles under `examples/profiles/`.
- New module and orchestration tests.

### Changed

- Root documentation cleaned up to core docs only.
- One-off migration helpers moved from `tools/` to `scripts/dev/`.
- Launcher GUI expanded for profile execution and output export.
- CI extended with Pester test jobs.
- Hard-cutover on script mode contract:
  - `AuditOnly` removed from `Mode` validate sets.
  - legacy top-level `-Remediate` script parameter removed in productive scripts.
  - remediation guarded via `-Mode Remediate` + `SupportsShouldProcess`.

### Fixed

- `Get-FindingStats` now handles empty findings collections.
- Pester suite stabilized for non-Windows environments via OS-aware skips.

## [1.x]

- Historical changes were tracked in prior planning and patch documents.
