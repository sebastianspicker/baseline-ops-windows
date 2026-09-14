#requires -version 5.1
<#
.SYNOPSIS
  Checks Local Administrator Password Solution (LAPS) health on a Windows device and optionally triggers a Windows LAPS password rotation.
.DESCRIPTION
  This script inspects the local device to determine whether Windows LAPS or Legacy Microsoft LAPS (AdmPwd) is configured and active.
  It identifies the managed local administrator account (from policy if available, otherwise falls back to the built-in RID-500 account),
  reads the account state (exists/enabled) and the last password set timestamp, then evaluates whether the password is due for rotation
  based on the effective policy age and an optional early-rotation offset.
  The script is designed for automation:
  - Pipeline output is exactly one structured object (PSCustomObject) for easy filtering and exporting.
  - Human-readable console output is printed separately (not via pipeline), with optional color formatting.
  - Optional event log writing can be enabled/disabled via JSON configuration.
.PARAMETER MinDaysBeforeRotate
  Rotates earlier than the policy-defined maximum password age by this many days.
  Example: PolicyAge=30 and MinDaysBeforeRotate=5 => rotation becomes due at day 25.
  Default: 0 (rotate only when the configured maximum age is reached).
.PARAMETER ConfigPath
  Path to an optional JSON configuration file.
  If the file is missing, empty, or invalid JSON, the script continues with built-in safe defaults.
  The JSON can override selected settings such as event log writing, console formatting, and remediation behavior.
.INPUTS
  None. This script does not accept pipeline input.
.PARAMETER Mode
  Execution mode. 'Audit' reports only; 'Remediate' applies changes.
  In Remediate mode, Windows LAPS password rotation is triggered when rotation is due.
  If Windows LAPS is not active (Legacy LAPS or no policy), remediation is not performed.
.PARAMETER OutputFormat
  Output format: Console, Json, Csv, or None.
.PARAMETER OutputPath
  File path for Json/Csv output.
.PARAMETER PassThru
  Emit structured v2 result object to pipeline.
.PARAMETER Strict
  Treat warnings as failures.
.PARAMETER Quiet
  Suppress console output.
.PARAMETER NoColor
  Disable colored output.
.OUTPUTS
  System.Management.Automation.PSCustomObject
  The script returns exactly one object with (typical) properties:
  - TimestampUtc (DateTime): Execution time in UTC.
  - Remediate (bool): Whether remediation mode was requested.
  - MinDaysBeforeRotate (int): Early-rotation offset used for evaluation.
  - PolicyType (string): 'WindowsLAPS', 'LegacyLAPS', or 'None'.
  - PolicyMechanism (string): Policy source indicator (for example 'CSP', 'GPO', 'Local', or 'n/a').
  - PolicyRoot (string): Registry root path used to read policy settings (or 'n/a').
  - ManagedAccount (string): The local account name considered managed by LAPS.
  - ManagedAccountExists (bool): Whether the account exists locally.
  - ManagedAccountEnabled (bool): Whether the account is enabled.
  - PasswordLastSet (DateTime/null): Last password set timestamp when available; otherwise null.
  - PasswordAgeDays (int/null): Calculated password age in days when PasswordLastSet is known; otherwise null.
  - PolicyPasswordAgeDays (int): Effective policy password age in days (includes fallback defaults when not readable).
  - ThresholdDays (int/null): The effective rotation threshold after MinDaysBeforeRotate is applied.
  - PasswordComplexity (int/null): Complexity value when available from policy; otherwise null.
  - BackupDirectoryRaw (int/null): Raw Windows LAPS backup target value (Windows LAPS only).
  - BackupDirectory (string): Human-readable backup target text (Windows LAPS only).
  - AADJoined (bool): Whether the device is Azure AD joined (best-effort).
  - ADJoined (bool): Whether the device is Active Directory domain joined (best-effort).
  - NeedsRotate (bool): Whether rotation is considered due based on current findings.
  - Rotated (bool): Whether a rotation attempt succeeded (only when Remediate is used and Windows LAPS is active).
  - RotationMethod (string): The method used (or the failure context).
  - RotationError (string/null): Error details when rotation fails.
  - DiagnosticsCollected (bool): Whether diagnostics were collected after a failed rotation attempt.
  - DiagnosticsInfo (string/null): Diagnostics summary or error message.
  - OkOverall (bool): Final overall compliance verdict.
  - Reasons (string[]): List of reasons explaining non-compliance or notable findings.
.EXAMPLE
  .\02-LAPS-Hygiene.ps1
  Runs the hygiene check using defaults.
  Returns one structured result object and prints a readable console summary.
.EXAMPLE
  .\02-LAPS-Hygiene.ps1 -MinDaysBeforeRotate 7
  Checks compliance but treats rotation as due 7 days earlier than the policy maximum age.
.EXAMPLE
  .\02-LAPS-Hygiene.ps1 -Mode Remediate
  Checks compliance and triggers Windows LAPS password rotation if rotation is due.
  If Windows LAPS is not active, the script will not attempt remediation.
.EXAMPLE
  .\02-LAPS-Hygiene.ps1 -ConfigPath $ConfigPath
  Uses the specified JSON file to override selected defaults (for example event log, console, remediation options).
.EXAMPLE
  # Automation-friendly usage (export pipeline object)
  .\02-LAPS-Hygiene.ps1 -Mode Remediate -MinDaysBeforeRotate 3 | ConvertTo-Json -Depth 6
  Runs in remediation mode and exports the single result object as JSON.
.EXAMPLE
  # CI/MDM-style check (exit code indicates health)
  powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\02-LAPS-Hygiene.ps1
  if ($LASTEXITCODE -ne 0) { 'NOT OK' } else { 'OK' }
  Uses the script exit code (0 = OK, 2 = WARN, 1 = FAIL) for simple integration checks.
.NOTES
  Behavior and design decisions:
  - The pipeline output is always exactly one object; console formatting is written separately.
  - Event log writing is best-effort: if permissions or source registration prevent writing, the script continues.
  - Remediation is intentionally limited to Windows LAPS; Legacy LAPS remediation is not implemented.
  - Device join detection and some account properties are best-effort and may vary by OS and available modules.
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
  [int]$MinDaysBeforeRotate = 0,
  [string]$ConfigPath
,
  [ValidateSet('Audit','Remediate')][string]$Mode = 'Audit',
  [ValidateSet('Console','Json','Csv','None')][string]$OutputFormat = 'Console',
  [string]$OutputPath,
  [switch]$PassThru,
  [switch]$Strict,
  [switch]$Quiet,
  [switch]$NoColor
)
. (Join-Path $PSScriptRoot '_lib/Bootstrap.ps1')
Import-Module (Join-Path $script:LibPath 'Output.psm1') -Force
Import-Module (Join-Path $script:LibPath 'EventLog.psm1') -Force
Import-Module (Join-Path $script:LibPath 'Common.psm1') -Force -DisableNameChecking
Import-Module (Join-Path $script:LibPath 'Results.psm1') -Force
Import-Module (Join-Path $script:LibPath Serialization.psm1) -Force
Set-StrictMode -Version Latest
$script:__V2Context = Initialize-V2Context -ScriptName '02-LAPS-Hygiene.ps1' -BoundParameters $PSBoundParameters `
  -Values @{ Mode = $Mode; ConfigPath = $ConfigPath; OutputFormat = $OutputFormat; OutputPath = $OutputPath; PassThru = $PassThru; Strict = $Strict; Quiet = $Quiet; NoColor = $NoColor; DeriveRemediate = $true }
$Remediate = [bool]$script:__V2Context.Remediate
if ($script:__V2Context.Quiet) { $InformationPreference = 'SilentlyContinue'; $VerbosePreference = 'SilentlyContinue' }
$script:NoColor = [bool]$script:__V2Context.NoColor
$ErrorActionPreference = 'Stop'

function Get-LapsUnsupportedSummary {
  return [pscustomobject]@{
    ComputerName = $env:COMPUTERNAME
    Timestamp    = Get-Date
    Mode         = $Mode
    Supported    = $false
    Notes        = @('Skipped: this script is only supported on Windows hosts.')
  }
}

if ($env:OS -ne 'Windows_NT') {
  $summary = Get-LapsUnsupportedSummary
  $unsupportedResult = if ($Strict) { 'FAIL' } else { 'WARN' }
  $result = Get-V2ResultObject -ScriptName '02-LAPS-Hygiene.ps1' -Mode $Mode -Result $unsupportedResult -Findings @() -Summary $summary -Metadata @{ UnsupportedHost = $true }
  Write-ResultObject -ResultObject $result -OutputFormat $OutputFormat -OutputPath $OutputPath
  if ($PassThru) { $result }
  exit (Get-V2ExitCode -Result $unsupportedResult)
}

# --------------------------- Defaults / Config -------------------------------------
function Get-LapsTerminalToken {
  param($Summary)
$resultToken = if (-not $Summary.OkOverall) { 'FAIL' } elseif ($script:Findings.Count -gt 0) { 'WARN' } else { 'OK' }
if ($Strict -and $resultToken -eq 'WARN') { $resultToken = 'FAIL' }
  return $resultToken
}

. (Join-Path $PSScriptRoot 'internal/02-LAPS-Hygiene.helpers.ps1')
$runState = New-LapsRunState -Inputs @{ Remediate = $Remediate; MinDaysBeforeRotate = $MinDaysBeforeRotate; ConfigPath = $ConfigPath }
. Initialize-LapsConfiguration -RunState $runState
. Invoke-LapsHygiene -RunState $runState

# V2 output contract
$resultToken = Get-LapsTerminalToken -Summary $runState.result
$v2Result = Get-V2ResultObject -ScriptName '02-LAPS-Hygiene.ps1' -Mode $Mode -Result $resultToken -Findings (ConvertTo-ObjectArray -InputObject $script:Findings) -Summary $runState.result -Metadata @{}
Write-ResultObject -ResultObject $v2Result -OutputFormat $OutputFormat -OutputPath $OutputPath
if ($PassThru) { $v2Result }
exit (Get-V2ExitCode -Result $resultToken)
