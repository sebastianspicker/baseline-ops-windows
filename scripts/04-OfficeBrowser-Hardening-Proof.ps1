#requires -version 5.1
<#
.SYNOPSIS
  Evaluates and (optionally) enforces a hardened baseline for Microsoft Office, Microsoft Edge, and Mozilla Firefox, with drift detection and proof generation.

.DESCRIPTION
  This script validates a set of security-relevant configuration items for Office, Edge, and Firefox against an expected baseline ("catalog").
  It can run in two modes:
  - Audit mode (default): Detects drift and reports compliance without changing the system.
  - Remediation mode (-Mode Remediate): Applies the baseline settings (idempotent) and then re-checks compliance.

  The script produces two kinds of output:
  - Human-readable console output (status blocks, warnings, and a final summary).
  - Machine-readable pipeline output: a list of structured objects (one object per check) suitable for Export-Csv, ConvertTo-Json, filtering, etc.

  A proof JSON file is written at the end, containing:
  - Execution metadata (time, host, mode flags).
  - A summary (total checks, non-compliant checks, changed items).
  - The full per-check result list (expected/actual/compliant/changed/message).

  Catalog loading behavior:
  - If -CatalogPath is provided, it is used as the catalog source.
  - Otherwise, the script tries to read -ConfigPath and uses OfficeBrowser.CatalogPath if present.
  - If no catalog can be loaded or parsing fails, embedded defaults are used.
  - Missing sections (Office/Edge/Firefox/Proof) are automatically filled with embedded defaults.

  Permissions / scope:
  - Office settings are written under HKCU (current user).
  - Edge settings are written under HKLM (system-wide).
  - Firefox policies are written to a policies.json under the Firefox distribution directory (usually under Program Files).
  When not running elevated, write operations for system-wide locations may fail; audit mode still works.

.PARAMETER CatalogPath
  Path to the catalog JSON file that defines the desired baseline (Office/Edge/Firefox settings and optional proof output path).
  If the file is missing or invalid, embedded defaults are used.

.PARAMETER ConfigPath
  Path to an optional configuration JSON.
  If present, the script looks for:
    { "OfficeBrowser": { "CatalogPath": "[configured path]" } }
  If the config file is missing or invalid, it is ignored and embedded defaults are used.

.PARAMETER Strict
  Switch. Enables strict compliance evaluation.


.PARAMETER Mode
  Execution mode. 'Audit' reports only; 'Remediate' applies changes.

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

  One output object per check is written to the pipeline at the end of the script.
  Each object contains these core fields:
  - Time: Timestamp (ISO-like string).
  - Product: 'Office', 'Edge', or 'Firefox'.
  - Area: Sub-area / component (for grouping).
  - Policy: Logical policy name.
  - Target: Registry path or file path.
  - Name: Registry value name or file name.
  - Type: 'DWord', 'String', or 'File'.
  - Expected: Expected value (or expected file state).
  - Actual: Detected value (or detected file state).
  - Compliant: True if actual matches expected after evaluation (and remediation if enabled).
  - Changed: True if the script changed something during this run.
  - Message: Optional human-readable status (e.g. drift detected, write failed, set applied).

.NOTES
  Proof file location:
  - Default: $env:TEMP\OfficeBrowser-Hardening-Proof.json
  - Can be overridden via the catalog field: Proof.OutFile

  Exit codes:
  - 0 = OK, 2 = WARN, 1 = FAIL.

  Recommended usage:
  - Use audit mode for continuous compliance checks (e.g., scheduled task).
  - Use remediation mode for controlled baseline enforcement (e.g., during provisioning).
  - Consume the pipeline objects for reporting (CSV/JSON) and automation.

.EXAMPLE
  .\04-OfficeBrowser-Hardening-Proof.ps1

  Runs in audit mode using the embedded defaults (or a catalog resolved via ConfigPath if available).
  Writes a proof JSON file and outputs per-check objects to the pipeline.

.EXAMPLE
  .\04-OfficeBrowser-Hardening-Proof.ps1 -CatalogPath $CatalogPath

  Runs audit mode using the specified catalog JSON as the baseline source.

.EXAMPLE
  .\04-OfficeBrowser-Hardening-Proof.ps1 -Mode Remediate

  Runs remediation mode: applies the baseline settings and re-checks compliance.
  Returns a V2 result and its corresponding process exit code.

.EXAMPLE
  .\04-OfficeBrowser-Hardening-Proof.ps1 -Mode Remediate -Strict; exit $LASTEXITCODE

  Runs remediation mode with strict compliance evaluation.
  Useful for CI-style compliance enforcement.

.EXAMPLE
  $results = .\04-OfficeBrowser-Hardening-Proof.ps1
  $results | Where-Object { -not $_.Compliant } | Format-Table -AutoSize

  Runs the script and filters the pipeline output for non-compliant items.

.EXAMPLE
  .\04-OfficeBrowser-Hardening-Proof.ps1 | Export-Csv -NoTypeInformation -Path $OutputPath

  Runs the script and exports the per-check results to CSV for reporting.
#>


[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
  [string]$CatalogPath,
  [switch]$Strict,
  [string]$ConfigPath

  ,
  [ValidateSet('Audit', 'Remediate')][string]$Mode = 'Audit',
  [ValidateSet('Console', 'Json', 'Csv', 'None')][string]$OutputFormat = 'Console',
  [string]$OutputPath,
  [switch]$PassThru,
  [switch]$Quiet,
  [switch]$NoColor
)

. (Join-Path $PSScriptRoot '_lib/Bootstrap.ps1')
function Import-OfficeBrowserServices {
Import-Module (Join-Path $script:LibPath 'Output.psm1') -Force
Import-Module (Join-Path $script:LibPath 'Common.psm1') -Force -DisableNameChecking
Import-Module (Join-Path $script:LibPath 'Registry.psm1') -Force -DisableNameChecking
Import-Module (Join-Path $script:LibPath 'EventLog.psm1') -Force
Import-Module (Join-Path $script:LibPath 'Console.psm1') -Force
Import-Module (Join-Path $script:LibPath 'Results.psm1') -Force
Import-Module (Join-Path $script:LibPath Serialization.psm1) -Force


}
. Import-OfficeBrowserServices

Set-StrictMode -Version Latest
function Get-OfficeBrowserV2Context {
  param($BoundParameters)
  return Initialize-V2Context -ScriptName '04-OfficeBrowser-Hardening-Proof.ps1' -BoundParameters $BoundParameters `
    -Values @{ Mode = $Mode
    ConfigPath = $ConfigPath
    OutputFormat = $OutputFormat
    OutputPath = $OutputPath
    PassThru = $PassThru
    Strict = $Strict
    Quiet = $Quiet
    NoColor = $NoColor
    DeriveRemediate = $true
  }
}
$script:__V2Context = Get-OfficeBrowserV2Context -BoundParameters $PSBoundParameters
$Remediate = [bool]$script:__V2Context.Remediate
if ($script:__V2Context.Quiet) {
  $InformationPreference = 'SilentlyContinue'
  $VerbosePreference = 'SilentlyContinue'
}
$script:NoColor = [bool]$script:__V2Context.NoColor
$ErrorActionPreference = 'Stop'

function Get-OfficeBrowserUnsupportedSummary {
  return [pscustomobject]@{
    ComputerName = $env:COMPUTERNAME
    Timestamp = Get-Date
    Mode = $Mode
    Supported = $false
    Notes = @('Skipped: this script is only supported on Windows hosts.')
  }
}

function Write-OfficeBrowserUnsupportedResult {
  param([string]$UnsupportedResult)
  $summary = Get-OfficeBrowserUnsupportedSummary
  $result = Get-V2ResultObject -ScriptName '04-OfficeBrowser-Hardening-Proof.ps1' -Mode $Mode -Result $unsupportedResult -Findings @() -Summary $summary -Metadata @{ UnsupportedHost = $true }
  Write-ResultObject -ResultObject $result -OutputFormat $OutputFormat -OutputPath $OutputPath
  if ($PassThru) {
    $result
  }
}

$isWindowsHost = ($env:OS -eq 'Windows_NT')
if (-not $isWindowsHost) {
  $unsupportedResult = if ($Strict) {
    'FAIL'
  }
  else {
    'WARN'
  }
  Write-OfficeBrowserUnsupportedResult -UnsupportedResult $unsupportedResult
  exit (Get-V2ExitCode -Result $unsupportedResult)
}

if (-not $Quiet) {
  $InformationPreference = 'Continue'
}   # Information stream shown by default

$script:Findings = Get-FindingsList

function Get-OfficeBrowserResultToken {
  param($RunState)
  $resultToken = if (-not $RunState.overallOk) {
    'FAIL'
  }
  elseif ($script:Findings.Count -gt 0) {
    'WARN'
  }
  else {
    'OK'
  }
  return $resultToken
}

function Write-OfficeBrowserV2Result {
  param($RunState, [string]$ResultToken)
  $v2Result = Get-V2ResultObject -ScriptName '04-OfficeBrowser-Hardening-Proof.ps1' -Mode $Mode -Result $resultToken -Findings (ConvertTo-ObjectArray -InputObject $script:Findings) -Summary ([pscustomobject]@{ ComputerName = $env:COMPUTERNAME
      OverallOk = $runState.overallOk
      Timestamp = Get-Date
    }) -Metadata @{ Notes = @($runState.globalNotes) }
  Write-ResultObject -ResultObject $v2Result -OutputFormat $OutputFormat -OutputPath $OutputPath
  if ($PassThru) {
    $v2Result
  }
}

. (Join-Path $PSScriptRoot 'internal/04-OfficeBrowser-Hardening-Proof.helpers.ps1')
$runState = New-OfficeBrowserRunState -Inputs @{ CatalogPath = $CatalogPath
  ConfigPath = $ConfigPath
  Remediate = $Remediate
  Strict = $Strict
}
Invoke-OfficeBrowserProof -RunState $runState

# V2 output contract
$resultToken = Get-OfficeBrowserResultToken -RunState $runState
Write-OfficeBrowserV2Result -RunState $runState -ResultToken $resultToken

exit (Get-V2ExitCode -Result $resultToken)
