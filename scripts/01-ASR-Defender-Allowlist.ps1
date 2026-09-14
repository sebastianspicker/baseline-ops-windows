#requires -version 5.1
<#
.SYNOPSIS
  Synchronizes Microsoft Defender Antivirus exclusions, Attack Surface Reduction (ASR) Only Exclusions, and Controlled Folder Access (CFA) allowlists from a JSON definition.

.DESCRIPTION
  This script enforces a desired allowlist state for Microsoft Defender-related settings by comparing the local configuration with a JSON definition and then:
  - Reporting drift (differences) without changing the system (default behavior).
  - Optionally remediating drift by adding/removing entries to match the desired state.

  The script is designed to be:
  - Safe and idempotent: running it multiple times results in the same final configuration.
  - Defensive: risky allowlist entries (for example wildcards, UNC paths, device paths, or overly broad system paths) are rejected and reported.
  - Auditable: a structured result object can be emitted to the pipeline, and an audit JSON file can be written to disk.
  - Operator-friendly: a human-readable console summary is printed at the end.

  Data sources:
  - Desired state: JSON allowlist file (primary) or a baseline mode (fallback).
  - Current state: local Defender preferences retrieved at runtime.

.PARAMETER ConfigPath
  Path to an optional configuration JSON file that can contain the path to the allowlist JSON.
  This is a convenience input for centralized deployments.

.PARAMETER ExceptionsPath
  Path to the allowlist JSON file that defines the desired state.
  If provided, it takes precedence over any path discovered via -ConfigPath.

.PARAMETER AuditPath
  Path to a JSON file that will receive an audit record of the run.
  If the directory does not exist, it is created.

.PARAMETER PassThru
  If specified, outputs exactly one structured object to the pipeline containing:
  - Metadata about the run (time, computer, mode, JSON source)
  - Per-category diffs (current/desired/add/remove/rejected)
  - Remediation results and errors (if remediation was requested)

  If omitted, nothing is written to the pipeline (console output only).

.PARAMETER StrictJson
  If specified, the script fails if the allowlist JSON cannot be loaded or parsed.
  If omitted, the script falls back to the selected -BaselineMode.

.PARAMETER BaselineMode
  Determines the fallback behavior when the allowlist JSON is missing, empty, or invalid (and -StrictJson is not set):
  - Current : Desired state is set to the current local configuration (no drift, no changes).
  - Minimum : Desired state is set to a minimal baseline intended to avoid broad exclusions by default.

  The baseline mode used is shown in the console summary and included in the structured output.


.PARAMETER Mode
  Execution mode. 'Audit' reports only; 'Remediate' applies changes.

.PARAMETER OutputFormat
  Output format: Console, Json, Csv, or None.

.PARAMETER OutputPath
  File path for Json/Csv output.

.PARAMETER Strict
  Treat warnings as failures.

.PARAMETER Quiet
  Suppress console output.

.PARAMETER NoColor
  Disable colored output.

.OUTPUTS
  None by default.

  When -PassThru is used:
  - A single PSCustomObject with properties such as:
    Timestamp, ComputerName, Remediate, SourceJson, AuditPath,
    JsonLoaded, JsonError, BaselineUsed, Notes,
    TotalAdd, TotalRemove, TotalRejected, TotalErrors, Result,
    Diffs, Results, ErrorsFlat, PerCategory

.INPUTS
  None. This script does not accept pipeline input.

.EXAMPLE
  # Audit-only: show drift (no changes applied)
  .\scripts\01-ASR-Defender-Allowlist.ps1 -ExceptionsPath .\examples\configs\asr-defender-allowlist.json

.EXAMPLE
  # Remediate: apply the diff to match the JSON allowlist
  .\scripts\01-ASR-Defender-Allowlist.ps1 -ExceptionsPath .\examples\configs\asr-defender-allowlist.json -Mode Remediate

.EXAMPLE
  # Audit with the minimum fallback and no external JSON
  .\scripts\01-ASR-Defender-Allowlist.ps1 -BaselineMode Minimum

.EXAMPLE
  # Enforce strict JSON loading (fail if JSON is missing/invalid)
  .\scripts\01-ASR-Defender-Allowlist.ps1 -ExceptionsPath .\examples\configs\asr-defender-allowlist.json -StrictJson

.EXAMPLE
  # Emit structured output for reporting
  .\scripts\01-ASR-Defender-Allowlist.ps1 -ExceptionsPath .\examples\configs\asr-defender-allowlist.json -PassThru | ConvertTo-Json -Depth 6

.EXAMPLE
  # Emit structured output and export a compact report
  .\scripts\01-ASR-Defender-Allowlist.ps1 -ExceptionsPath .\examples\configs\asr-defender-allowlist.json -PassThru |
    Select-Object Timestamp,ComputerName,Result,TotalAdd,TotalRemove,TotalRejected,TotalErrors,SourceJson |
    Export-Csv -NoTypeInformation -Path .\asr-defender-allowlist.csv

.NOTES
  Safety and behavior notes:
  - Entries flagged as risky are excluded from remediation and counted as Rejected.
  - In audit-only mode the script reports drift but performs no system changes.
  - A console summary is always printed; it is intended for humans and is not written to the pipeline.
  - The pipeline output (when enabled) is always a single structured object to support downstream automation.

  Operational considerations:
  - Changing Defender/ASR/CFA settings typically requires elevated permissions.
  - Tamper protection or organizational policy may prevent changes; such failures are captured in the results/errors.
#>


[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(

  # Optional config paths - use $null to skip, or provide actual paths
  [string]$ConfigPath,
  [string]$ExceptionsPath,
  [string]$AuditPath,

  [switch]$PassThru,
  [switch]$StrictJson,

  [ValidateSet('Current','Minimum')]
  [string]$BaselineMode = 'Minimum'

,
  [ValidateSet('Audit','Remediate')][string]$Mode = 'Audit',
  [ValidateSet('Console','Json','Csv','None')][string]$OutputFormat = 'Console',
  [string]$OutputPath,
  [switch]$Strict,
  [switch]$Quiet,
  [switch]$NoColor
)

. (Join-Path $PSScriptRoot '_lib/Bootstrap.ps1')
Import-Module (Join-Path $script:LibPath 'Output.psm1') -Force
Import-Module (Join-Path $script:LibPath 'EventLog.psm1') -Force
Import-Module (Join-Path $script:LibPath 'Common.psm1') -Force -DisableNameChecking
Import-Module (Join-Path $script:LibPath 'Results.psm1') -Force
Import-Module (Join-Path $script:LibPath 'Console.psm1') -Force
Import-Module (Join-Path $script:LibPath Serialization.psm1) -Force


Set-StrictMode -Version Latest
function Initialize-AllowlistMode {
if ($script:__V2Context.Quiet) { $InformationPreference = 'SilentlyContinue'; $VerbosePreference = 'SilentlyContinue' }
$script:NoColor = [bool]$script:__V2Context.NoColor
$ErrorActionPreference = 'Stop'
return [bool]$script:__V2Context.Remediate
}

$script:__V2Context = Initialize-V2Context -ScriptName '01-ASR-Defender-Allowlist.ps1' -BoundParameters $PSBoundParameters `
  -Values @{ Mode = $Mode; ConfigPath = $ConfigPath; OutputFormat = $OutputFormat; OutputPath = $OutputPath; PassThru = $PassThru; Strict = $Strict; Quiet = $Quiet; NoColor = $NoColor; DeriveRemediate = $true }
$Remediate = . Initialize-AllowlistMode

function Get-AllowlistUnsupportedSummary {
  return [pscustomobject]@{
    ComputerName = $env:COMPUTERNAME
    Timestamp    = Get-Date
    Mode         = $Mode
    Supported    = $false
    Notes        = @('Skipped: this script is only supported on Windows hosts.')
  }
}

if ($env:OS -ne 'Windows_NT') {
  $summary = Get-AllowlistUnsupportedSummary
  $unsupportedResult = if ($Strict) { 'FAIL' } else { 'WARN' }
  $result = Get-V2ResultObject -ScriptName '01-ASR-Defender-Allowlist.ps1' -Mode $Mode -Result $unsupportedResult -Findings @() -Summary $summary -Metadata @{ UnsupportedHost = $true }
  Write-ResultObject -ResultObject $result -OutputFormat $OutputFormat -OutputPath $OutputPath
  if ($PassThru) { $result }
  exit (Get-V2ExitCode -Result $unsupportedResult)
}

# ----------------------------- Helpers --------------------------------------------

function Get-AllowlistTerminalToken {
  param($Summary)
$resultToken = if ($Summary.Result -eq 'FAILED') { 'FAIL' } elseif ($script:Findings.Count -gt 0) { 'WARN' } else { 'OK' }
if ($Strict -and $resultToken -eq 'WARN') { $resultToken = 'FAIL' }
  return $resultToken
}

. (Join-Path $PSScriptRoot 'internal/01-ASR-Defender-Allowlist.helpers.ps1')

# ----------------------------- Main ------------------------------------------------
$script:Findings = Get-FindingsList
$runState = New-AllowlistRunState -Inputs @{ ConfigPath = $ConfigPath; ExceptionsPath = $ExceptionsPath; AuditPath = $AuditPath; StrictJson = $StrictJson; BaselineMode = $BaselineMode; Remediate = $Remediate }
Initialize-AllowlistEventSource

if ($env:OS -ne 'Windows_NT') {
  . Write-AllowlistUnsupported -RunState $runState
  exit (Get-V2ExitCode -Result $unsupportedResult)
}


. Invoke-AllowlistRun -RunState $runState

# V2 output contract
$resultToken = Get-AllowlistTerminalToken -Summary $runState.final
$v2Result = Get-V2ResultObject -ScriptName '01-ASR-Defender-Allowlist.ps1' -Mode $Mode -Result $resultToken -Findings (ConvertTo-ObjectArray -InputObject $script:Findings) -Summary $runState.final -Metadata @{}
Write-ResultObject -ResultObject $v2Result -OutputFormat $OutputFormat -OutputPath $OutputPath
if ($PassThru) { $v2Result }
exit (Get-V2ExitCode -Result $resultToken)
