#requires -version 5.1
<#
.SYNOPSIS
Fast event log triage (Windows PowerShell 5.1) using Get-WinEvent -FilterHashtable.

.DESCRIPTION
Best-practice layout:
- Success output stream: structured objects only (safe for Export-Csv / ConvertTo-Json / Where-Object).
- Console output: blocks, separators, and colors use Write-UiLine / Write-Information only.

Features:
- Optional JSON config overrides loaded from $ConfigPath. Falls back to defaults if missing or invalid.
- Optional record de-duplication (true duplicates only).
- Optional "collapse" summary: groups similar events without removing records.
- Optional CSV export.

.PARAMETER ConfigPath
Optional path to JSON config supplied with $ConfigPath. If unreadable or invalid, defaults apply.

.PARAMETER Quiet
Suppresses console output (still returns objects).

.PARAMETER NoColor
Disables colored console output (still prints text).

.PARAMETER Collapse
Builds "similar event" groups for the summary (does not remove records).

.PARAMETER CollapseTop
Number of top similar groups shown in the summary.

.PARAMETER Deduplicate
Removes true duplicates from output (default: disabled). Uses RecordId when available.

.PARAMETER NormalizeMessage
If enabled, produces NormalizedMessage (single-line) and uses it for collapse grouping & CSV export.

.PARAMETER ExportPath
Optional CSV export path.

.PARAMETER Mode
  Execution mode. 'Audit' reports only; 'Remediate' applies changes.

.PARAMETER OutputFormat
  Output format: Console, Json, Csv, or None.

.PARAMETER OutputPath
  File path for Json/Csv output.

.PARAMETER PassThru
  Emit structured v2 result object to pipeline.

.PARAMETER Strict
  Treat warnings as failures.


.OUTPUTS
  None by default.
  When -PassThru is used, emits a PSCustomObject v2 result with Script, Mode, Result, Findings, Summary, and Metadata properties.

.EXAMPLE
  .\26-Get-WinEvent-FastTriage.ps1

#>


[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
  [Parameter()][string]$ConfigPath,

  [Parameter()][switch]$Quiet,

  [Parameter()][switch]$NoColor,

  [Parameter()][bool]$Collapse = $true,

  [Parameter()][ValidateRange(1, 50)]
  [int]$CollapseTop = 5,

  [Parameter()][bool]$Deduplicate = $false,

  [Parameter()][bool]$NormalizeMessage = $true,

  [Parameter()][ValidateNotNullOrEmpty()]
  [string]$LogName = 'System',

  [Parameter()][ValidateRange(1, 24*365)]
  [int]$HoursBack = 6,

  [Parameter()][ValidateSet(1,2,3,4,5)]
  [int[]]$Level = @(2,3),

  [Parameter()][string[]]$ProviderName,

  [Parameter()][int[]]$Id,

  [Parameter()][ValidateRange(1, 1000000)]
  [int]$MaxEvents = 500,

  [Parameter()][string]$ExportPath

,
  [ValidateSet('Audit','Remediate')][string]$Mode = 'Audit',
  [ValidateSet('Console','Json','Csv','None')][string]$OutputFormat = 'Console',
  [string]$OutputPath,
  [switch]$PassThru,
  [switch]$Strict
)

. (Join-Path $PSScriptRoot '_lib/Bootstrap.ps1')
function Initialize-Capability26Runtime {
  param($EntryBoundParameters)
  $RunState = @{

  }
Import-Module (Join-Path $script:LibPath 'Output.psm1') -Force
Import-Module (Join-Path $script:LibPath Serialization.psm1) -Force
Import-Module (Join-Path $script:LibPath 'Validation.psm1')


$script:Quiet = [bool]$Quiet
$script:NoColor = [bool]$NoColor


Set-StrictMode -Version Latest
$script:__V2Context = Initialize-V2Context -ScriptName '26-Get-WinEvent-FastTriage.ps1' -BoundParameters $EntryBoundParameters `
  -Values @{ Mode = $Mode; ConfigPath = $ConfigPath; OutputFormat = $OutputFormat; OutputPath = $OutputPath; PassThru = $PassThru; Strict = $Strict; Quiet = $Quiet; NoColor = $NoColor; DeriveRemediate = $false }
if ($script:__V2Context.Quiet) { $InformationPreference = 'SilentlyContinue'; $VerbosePreference = 'SilentlyContinue' }
$script:NoColor = [bool]$script:__V2Context.NoColor
$ErrorActionPreference = 'Stop'

$RunState.isWindowsHost = ($env:OS -eq 'Windows_NT')
  $script:RunState = $RunState
}

. Initialize-Capability26Runtime -EntryBoundParameters $PSBoundParameters
function Get-Capability26UnsupportedState {
  param([hashtable]$RunState)
$summary = [pscustomobject]@{
  ComputerName = $env:COMPUTERNAME
  Timestamp    = Get-Date
  Mode         = $Mode
  Supported    = $false
  Notes        = @('Skipped: this script is only supported on Windows hosts.')
}
$RunState.unsupportedResult = if ($Strict) { 'FAIL' } else { 'WARN' }
$RunState.result = Get-V2ResultObject -ScriptName '26-Get-WinEvent-FastTriage.ps1' -Mode $Mode -Result $RunState.unsupportedResult -Findings @() -Summary $summary -Metadata @{ UnsupportedHost = $true }
  [pscustomobject]@{ Result = $RunState.result; Token = $RunState.unsupportedResult }
}
function Set-Capability26UnsupportedState {
  param([hashtable]$RunState)
  $unsupportedState = Get-Capability26UnsupportedState -RunState $RunState
  $RunState.result = $unsupportedState.Result
  $RunState.unsupportedResult = $unsupportedState.Token
}
if (-not $RunState.isWindowsHost) {
  . Set-Capability26UnsupportedState -RunState $RunState
  Write-ResultObject -ResultObject $RunState.result -OutputFormat $OutputFormat -OutputPath $OutputPath
  if ($PassThru) { $RunState.result }
  exit (Get-V2ExitCode -Result $RunState.unsupportedResult)
}

# -------------------------
# Console helpers (no pipeline pollution)
# -------------------------



# -------------------------
# Config loading (optional) with safe defaults
# -------------------------
# -------------------------
# Data helpers
# -------------------------
# -------------------------
# Load config and apply defaults
# -------------------------
. (Join-Path $PSScriptRoot 'internal/26-Get-WinEvent-FastTriage.helpers.ps1')
. Invoke-Capability26Main -EntryBoundParameters $PSBoundParameters -EntryCmdlet $PSCmdlet -EntryInvocation $MyInvocation -RunState $RunState
$resultToken = Get-Capability26ResultToken -RunState $RunState
$v2Result = Get-V2ResultObject -ScriptName '26-Get-WinEvent-FastTriage.ps1' -Mode $Mode -Result $resultToken -Findings $findings -Summary $RunState.summary -Metadata @{}
Write-ResultObject -ResultObject $v2Result -OutputFormat $OutputFormat -OutputPath $OutputPath
if ($PassThru) { $v2Result }
exit (Get-V2ExitCode -Result $resultToken)
