#requires -version 5.1
<#
.SYNOPSIS
  Audits Windows Scheduled Tasks for health and security hygiene, optionally remediates issues, and produces evidence.
.DESCRIPTION
  This script performs a full inventory of Scheduled Tasks and evaluates them against a rule catalog (JSON) or built-in defaults.
  It focuses on two goals:
  1) Reliability: Ensure defined "critical" tasks exist and are enabled (optionally re-enable them).
  2) Security hygiene: Detect potentially risky tasks based on common persistence patterns (locations, command lines, privilege level, signature/publisher, triggers).
  Evidence and reporting:
  - Writes an evidence record to Windows Event Log (Application log, configurable source).
  - Writes an evidence JSON file ("proof") containing summary + findings.
  - Prints a human-readable summary to the console with highlighted status.
  - Emits exactly one structured proof object to the pipeline (for automation/export).
  Catalog input sources (highest precedence first):
  - -CatalogPath: explicit catalog JSON.
  - -ConfigPath: config JSON that can contain TasksHygiene.CatalogPath.
  - Built-in defaults (safe baseline) if no JSON can be loaded.
.PARAMETER CatalogPath
  Path to a catalog JSON that defines the hygiene rules.
  If explicitly provided, the file must exist and parse successfully; otherwise the run fails before inventory or remediation.
  Expected catalog fields (all optional; missing fields are filled with defaults):
  - CriticalTasks: Array of regex patterns matching FullPath (e.g. "\\Microsoft\\Windows\\...").
  - AllowTaskExact: Array of regex patterns for tasks that should be excluded from "risky" classification.
  - AllowActionPathPrefixes: Array of allowed executable path prefixes (string starts-with checks).
  - DenyActionPathRegex: Array of regex patterns for denied executable/working directory locations.
  - DenyCommandLineRegex: Array of regex patterns considered suspicious in command lines.
  - AllowPublisherOrgRegex: Array of regex patterns matched against certificate subject to allow trusted publishers.
  - PurgeUnapproved: Boolean; when true, risky tasks are quarantined (export XML + disable) but only in Remediate mode.
  - QuarantineDir: Directory used to store exported task XML during quarantine.
  - Proof.OutFile: Path to the evidence JSON file.
.PARAMETER Strict
  Controls compliance interpretation.
  When set, any drift (missing critical tasks, disabled critical tasks, quarantine errors, or other detected issues) is treated as a failure state.
  When not set, drift is still reported, but the overall run is considered informational unless errors occurred.
.PARAMETER ConfigPath
  Path to a configuration JSON that may contain a nested property TasksHygiene.CatalogPath.
  This allows central configuration to point to the catalog JSON without passing -CatalogPath explicitly.
  If explicitly provided, the file must exist and parse successfully. A valid config without a TasksHygiene catalog reference uses defaults.
.INPUTS
  None. This script does not accept pipeline input.
.PARAMETER Mode
  Execution mode. 'Audit' reports only; 'Remediate' applies changes.
  In Remediate mode, the script may enable disabled critical tasks and quarantine risky tasks
  only when the catalog property PurgeUnapproved is true.
.PARAMETER OutputFormat
  Output format: Console, Json, Csv, or None.
.PARAMETER OutputPath
  File path for Json/Csv output.
.PARAMETER PassThru
  Emit structured v2 result object to pipeline.
.PARAMETER Quiet
  Suppress console output.
.PARAMETER NoColor
  Disable colored output.
.OUTPUTS
  System.Management.Automation.PSCustomObject
  The script returns exactly one "proof" object to the pipeline, suitable for:
  - ConvertTo-Json
  - Export-Csv (with prior flattening if needed)
  - Where-Object filtering
  Proof object shape (high-level):
  - Time, Hostname
  - Summary: TotalTasks, CriticalKnown, RiskyDetected, Remediate, PurgeEnabled, Strict, ProofOutFile, QuarantineDir, IsAdmin
  - Critical: array of critical task records (FullPath, Enabled, LastRun, NextRun)
  - Risky: array of risky task records (FullPath, reasons, action details, signature info, triggers, etc.)
  - Actions: array of remediation actions performed (strings)
  - Notes/Drift: informational and drift messages (strings)
.EXAMPLE
  PS> .\07-ScheduledTasks-Hygiene.ps1
  Runs an audit using built-in defaults (or configured JSON if available via ConfigPath).
  Writes event log + proof JSON, prints summary, returns a proof object to the pipeline.
.EXAMPLE
  PS> .\07-ScheduledTasks-Hygiene.ps1 -CatalogPath $CatalogPath
  Runs an audit using an explicit catalog JSON.
.EXAMPLE
  PS> .\07-ScheduledTasks-Hygiene.ps1 -Mode Remediate
  Runs with remediation enabled:
  - Attempts to enable critical tasks that are disabled.
  - Quarantine occurs only if the loaded catalog sets PurgeUnapproved = true.
.EXAMPLE
  PS> .\07-ScheduledTasks-Hygiene.ps1 -Mode Remediate -WhatIf
  Simulates remediation actions. Shows what would be changed without making any changes.
.EXAMPLE
  PS> $proof = .\07-ScheduledTasks-Hygiene.ps1
  PS> $proof.Risky | ConvertTo-Json -Depth 6
  Captures the proof object and inspects risky findings as JSON.
.EXAMPLE
  PS> .\07-ScheduledTasks-Hygiene.ps1 | ConvertTo-Json -Depth 8 | Out-File .\proof.json
  Uses the pipeline output to generate an additional JSON artifact (separate from the built-in proof file).
.NOTES
  Permissions:
  - Reading tasks generally works without elevation.
  - Remediation (enabling/disabling tasks, creating an event source, writing quarantine/proof files) may require administrative rights.
  Safety:
  - Quarantine exports a task's XML definition before disabling it, so it can be recreated if needed.
  - Review the catalog patterns carefully; overly broad deny/allow rules can create false positives/negatives.
  Observability:
  - Console output is intended for humans (colored status and sections).
  - Automation should consume the single returned proof object and/or the proof JSON file.
#>
[CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
param(
  [string]$CatalogPath,
  [switch]$Strict,
  [string]$ConfigPath
,
  [ValidateSet('Audit','Remediate')][string]$Mode = 'Audit',
  [ValidateSet('Console','Json','Csv','None')][string]$OutputFormat = 'Console',
  [string]$OutputPath,
  [switch]$PassThru,
  [switch]$Quiet,
  [switch]$NoColor
)
. (Join-Path $PSScriptRoot '_lib/Bootstrap.ps1')
function Import-ScheduledTaskHygieneServices {
  Import-Module (Join-Path $script:LibPath 'Common.psm1') -Force -DisableNameChecking
  Import-Module (Join-Path $script:LibPath 'Output.psm1') -Force
  Import-Module (Join-Path $script:LibPath 'EventLog.psm1') -Force
  Import-Module (Join-Path $script:LibPath 'JsonCatalog.psm1') -Force
  Import-Module (Join-Path $script:LibPath 'Results.psm1') -Force
  Import-Module (Join-Path $script:LibPath Serialization.psm1) -Force
}
. Import-ScheduledTaskHygieneServices
Set-StrictMode -Version Latest
function Get-ScheduledTaskHygieneV2Context {
  param($BoundParameters)
  return Initialize-V2Context -ScriptName '07-ScheduledTasks-Hygiene.ps1' -BoundParameters $BoundParameters `
    -Values @{ Mode = $Mode; ConfigPath = $ConfigPath; OutputFormat = $OutputFormat; OutputPath = $OutputPath; PassThru = $PassThru; Strict = $Strict; Quiet = $Quiet; NoColor = $NoColor; DeriveRemediate = $true }
}
$script:__V2Context = Get-ScheduledTaskHygieneV2Context -BoundParameters $PSBoundParameters
$Remediate = [bool]$script:__V2Context.Remediate
if ($script:__V2Context.Quiet) { $InformationPreference = 'SilentlyContinue'; $VerbosePreference = 'SilentlyContinue' }
$script:NoColor = [bool]$script:__V2Context.NoColor
$ErrorActionPreference = 'Stop'

$isWindowsHost = ($env:OS -eq 'Windows_NT')
function Write-ScheduledTaskHygieneUnsupportedResult {
  param([string]$UnsupportedResult)
  $summary = [pscustomobject]@{
    ComputerName = $env:COMPUTERNAME
    Timestamp = Get-Date
    Mode = $Mode
    Supported = $false
    Notes = @('Skipped: this script is only supported on Windows hosts.')
  }
  $result = Get-V2ResultObject -ScriptName '07-ScheduledTasks-Hygiene.ps1' -Mode $Mode -Result $UnsupportedResult -Findings @() -Summary $summary -Metadata @{ UnsupportedHost = $true }
  Write-ResultObject -ResultObject $result -OutputFormat $OutputFormat -OutputPath $OutputPath
  if ($PassThru) { $result }
}
if (-not $isWindowsHost) {
  $unsupportedResult = if ($Strict) { 'FAIL' } else { 'WARN' }
  Write-ScheduledTaskHygieneUnsupportedResult -UnsupportedResult $unsupportedResult
  exit (Get-V2ExitCode -Result $unsupportedResult)
}

$script:Findings = Get-FindingsList
# Capability-private catalog, observation, and remediation helpers.
. (Join-Path $PSScriptRoot 'internal/07-ScheduledTasks-Hygiene.helpers.ps1')
. (Join-Path $PSScriptRoot 'internal/07-ScheduledTasks-Hygiene.catalog.ps1')
. (Join-Path $PSScriptRoot 'internal/07-ScheduledTasks-Hygiene.observations.ps1')
. (Join-Path $PSScriptRoot 'internal/07-ScheduledTasks-Hygiene.actions.ps1')





# =========================
# Catalog (safe defaults)
# =========================



# =========================
# Task inspection / actions
# =========================









# Run orchestration and evidence projection.
. (Join-Path $PSScriptRoot 'internal/07-ScheduledTasks-Hygiene.runtime.ps1')
$inputs = New-ScheduledTaskHygieneInputs -CatalogPath $CatalogPath -ConfigPath $ConfigPath `
  -Remediate $Remediate -Strict $Strict
$runState = New-ScheduledTaskHygieneState -Inputs $inputs
Invoke-ScheduledTaskHygiene -RunState $runState
$resultToken = if ($runState.ErrorMessage) { 'FAIL' } elseif ($script:Findings.Count -gt 0) { 'WARN' } else { 'OK' }
$v2Summary = Get-ScheduledTaskHygieneV2Summary -RunState $runState
$v2Result = Get-V2ResultObject -ScriptName '07-ScheduledTasks-Hygiene.ps1' -Mode $Mode -Result $resultToken -Findings $script:Findings.ToArray() -Summary $v2Summary -Metadata @{}
Write-ResultObject -ResultObject $v2Result -OutputFormat $OutputFormat -OutputPath $OutputPath
if ($PassThru) { $v2Result }
exit (Get-V2ExitCode -Result $resultToken)
