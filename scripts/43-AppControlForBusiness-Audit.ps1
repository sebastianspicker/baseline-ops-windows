#requires -version 5.1
<#
.SYNOPSIS
Audit WDAC / App Control for Business indicators (best-effort).

.DESCRIPTION
- Reads Code Integrity Operational events (recent).
- Scans for deployed policy files in common OS and EFI locations (EFI best-effort).
- Supports optional JSON config overrides (safe defaults if missing/invalid).
- Optional CSV export.
- Prints a console summary at the end.

Pipeline output: structured objects only.
Console output: Write-UiLine (and optional Write-Information) only.

PowerShell: Windows PowerShell 5.1 compatible.

.PARAMETER HoursBack
How far back to query Code Integrity events.

.PARAMETER ExportPath
Optional CSV export path.

.PARAMETER ConfigJsonPath
Optional JSON config path for overrides.

.PARAMETER MaxEvents
Maximum number of CI events to read.

.PARAMETER RecurseMaxDepth
Maximum recursion depth when scanning policy locations.

.PARAMETER MaxPolicyFiles
Maximum policy files to enumerate.

.PARAMETER ExportEventsTop
Max number of events to include in export.


.PARAMETER Mode
  Execution mode. 'Audit' reports only; 'Remediate' applies changes.

.PARAMETER ConfigPath
  Path to JSON configuration file.

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
  None by default.
  When -PassThru is used, emits a PSCustomObject v2 result with Script, Mode, Result, Findings, Summary, and Metadata properties.

.EXAMPLE
  .\43-AppControlForBusiness-Audit.ps1

#>


[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
  [ValidateSet('Audit','Remediate')]
  [string]$Mode = 'Audit',

  [ValidateRange(1, 720)]
  [int]$HoursBack = 24,

  [string]$ExportPath,

  [string]$ConfigJsonPath = $null,

  [ValidateRange(1, 50000)]
  [int]$MaxEvents = 5000,

  [ValidateRange(0, 10)]
  [int]$RecurseMaxDepth = 4,

  [ValidateRange(1, 20000)]
  [int]$MaxPolicyFiles = 5000,

  [ValidateRange(1, 2000)]
  [int]$ExportEventsTop = 200,

  [ValidateSet('Console','Json','Csv','None')]
  [string]$OutputFormat = 'Console',

  [string]$OutputPath,

  [switch]$PassThru,
  [switch]$Strict,
  [switch]$Quiet,
  [switch]$NoColor

,
  [string]$ConfigPath
)

. (Join-Path $PSScriptRoot '_lib/Bootstrap.ps1')
function Initialize-Capability43Runtime {
  param($EntryBoundParameters)
  $RunState = @{

  }
Import-Module (Join-Path $script:LibPath 'Output.psm1') -Force
Import-Module (Join-Path $script:LibPath 'Console.psm1') -Force
Import-Module (Join-Path $script:LibPath 'Common.psm1') -Force -DisableNameChecking
Import-Module (Join-Path $script:LibPath 'Config.psm1') -Force
Import-Module (Join-Path $script:LibPath 'Results.psm1') -Force
Import-Module (Join-Path $script:LibPath 'Serialization.psm1') -Force


Set-StrictMode -Version Latest
$script:__V2Context = Initialize-V2Context -ScriptName '43-AppControlForBusiness-Audit.ps1' -BoundParameters $EntryBoundParameters `
  -Values @{ Mode = $Mode; ConfigPath = $ConfigPath; OutputFormat = $OutputFormat; OutputPath = $OutputPath; PassThru = $PassThru; Strict = $Strict; Quiet = $Quiet; NoColor = $NoColor; DeriveRemediate = $false }
if ($script:__V2Context.Quiet) { $InformationPreference = 'SilentlyContinue'; $VerbosePreference = 'SilentlyContinue' }
$script:NoColor = [bool]$script:__V2Context.NoColor
$ErrorActionPreference = 'Stop'

if ([string]::IsNullOrWhiteSpace($OutputPath) -and -not [string]::IsNullOrWhiteSpace($ExportPath)) {
  $OutputPath = $ExportPath
}

if ([string]::IsNullOrWhiteSpace($ConfigPath) -and -not [string]::IsNullOrWhiteSpace($ConfigJsonPath)) {
  $ConfigPath = $ConfigJsonPath
  $script:__V2Context.ConfigPath = $ConfigPath
}

# --------------------------
# Findings
# --------------------------
$script:Findings = Get-FindingsList
$Findings = $script:Findings
$RunState.strictModeEnabled = [bool]$Strict
$RunState.noColorEnabled = [bool]$NoColor

$RunState.isWindowsHost = ($env:OS -eq 'Windows_NT')
  $script:RunState = $RunState
}

. Initialize-Capability43Runtime -EntryBoundParameters $PSBoundParameters
function Get-Capability43UnsupportedState {
  param([hashtable]$RunState)
  $summary = [pscustomobject]@{
    ComputerName  = $env:COMPUTERNAME
    LikelyActive  = $false
    FindingsCount = 0
    Timestamp     = Get-Date
    Supported     = $false
    Notes         = @('Skipped: App Control for Business auditing is only supported on Windows hosts.')
  }

  $RunState.unsupportedResult = if ($Strict) { 'FAIL' } else { 'WARN' }
  $RunState.resultObject = Get-V2ResultObject `
    -ScriptName '43-AppControlForBusiness-Audit.ps1' `
    -Mode 'Audit' `
    -Result $RunState.unsupportedResult `
    -Findings @() `
    -Summary $summary `
    -Metadata @{ UnsupportedHost = $true; Indicators = $null; PolicyFiles = @(); RecentEvents = @() }
  [pscustomobject]@{ Result = $RunState.resultObject; Token = $RunState.unsupportedResult }
}
function Set-Capability43UnsupportedState {
  param([hashtable]$RunState)
  $unsupportedState = Get-Capability43UnsupportedState -RunState $RunState
  $RunState.resultObject = $unsupportedState.Result
  $RunState.unsupportedResult = $unsupportedState.Token
}
if (-not $RunState.isWindowsHost) {
  . Set-Capability43UnsupportedState -RunState $RunState
  Write-ResultObject -ResultObject $RunState.resultObject -OutputFormat $OutputFormat -OutputPath $OutputPath
  if ($PassThru) { $RunState.resultObject }
  exit (Get-V2ExitCode -Result $RunState.unsupportedResult)
}

if ($Mode -eq 'Remediate') {
  Add-Finding -FindingList $script:Findings -Code 'AC-ModeDowngradeToAudit' -Severity 'Warning' -Message 'Remediate mode is not supported by this script; running in audit behavior.'
}

# --------------------------
# Helpers
# --------------------------

# --------------------------
# Main
# --------------------------
function Invoke-Capability43MainPhase05Step01 {
  param([hashtable]$RunState)
Add-Finding -FindingList $script:Findings -Code 'AC-DisabledByConfig' -Severity 'Info' -Message 'Audit disabled by config; exiting.'

    $summary = [pscustomobject]@{
      ComputerName  = $env:COMPUTERNAME
      LikelyActive  = $null
      FindingsCount = $script:Findings.Count
      Timestamp     = Get-Date
    }

    $emptyIndicators = [pscustomobject]@{
      CodeIntegrityLogName = 'Microsoft-Windows-CodeIntegrity/Operational'
      LookbackHours        = $HoursBack
      RunningAsAdmin       = Test-IsAdmin
      CILogEnabled         = $null
      RecentCIEventsCount  = 0
      PolicyFilesCount     = 0
      LikelyActive         = $null
      ScannedRootsCount    = 0
    }

    $findingsAL = ConvertTo-ArrayList -InputObject $script:Findings.ToArray()

    if (-not $Quiet) {
      Write-ConsoleSummary -Summary $summary -Findings $findingsAL `
        -CustomFields ([ordered]@{
          RunningAsAdmin   = $emptyIndicators.RunningAsAdmin
          'CI Log Enabled' = $emptyIndicators.CILogEnabled
          'CI Events'      = $emptyIndicators.RecentCIEventsCount
          'Policies Found' = $emptyIndicators.PolicyFilesCount
          LikelyActive     = $summary.LikelyActive
        })
      if ($config.PreferWriteInformation) {
        Write-Information ("AppControl audit complete. LikelyActive={0}" -f $summary.LikelyActive) -InformationAction Continue
      }
    }

    $disabledFindings = @($script:Findings.ToArray())
    $disabledResultToken = if ($RunState.strictModeEnabled -and $disabledFindings.Count -gt 0) { 'FAIL' } elseif ($disabledFindings.Count -gt 0) { 'WARN' } else { 'OK' }
    $disabledResult = Get-V2ResultObject `
      -ScriptName '43-AppControlForBusiness-Audit.ps1' `
      -Mode 'Audit' `
      -Result $disabledResultToken `
      -Findings $disabledFindings `
      -Summary $summary `
      -Metadata @{ Indicators = $emptyIndicators; PolicyFiles = @(); RecentEvents = @() }

    Write-ResultObject -ResultObject $disabledResult -OutputFormat $OutputFormat -OutputPath $OutputPath
}

function Invoke-Capability43MainPhase05Step02 {
if ($PassThru) { $disabledResult }
    exit (Get-V2ExitCode -Result $disabledResultToken)
}

function Invoke-Capability43MainPhase05 {
  param([hashtable]$RunState)
  if (-not $config.Enabled) {
    . Invoke-Capability43MainPhase05Step01 -RunState $RunState
. Invoke-Capability43MainPhase05Step02
  }
}
. (Join-Path $PSScriptRoot 'internal/43-AppControlForBusiness-Audit.helpers.ps1')
. Invoke-Capability43Main -EntryBoundParameters $PSBoundParameters -EntryCmdlet $PSCmdlet -EntryInvocation $MyInvocation -RunState $RunState

$resultToken = Get-Capability43ResultToken -RunState $RunState
$RunState.resultObject = Get-V2ResultObject `
  -ScriptName '43-AppControlForBusiness-Audit.ps1' `
  -Mode 'Audit' `
  -Result $resultToken `
  -Findings $RunState.findingsArr `
  -Summary $RunState.summary `
  -Metadata @{ Indicators = $RunState.indicators; PolicyFiles = @($policyFiles); RecentEvents = @($RunState.events | Select-Object -First $ExportEventsTop); Strict = $RunState.strictModeEnabled; NoColor = $RunState.noColorEnabled }

Write-ResultObject -ResultObject $RunState.resultObject -OutputFormat $OutputFormat -OutputPath $OutputPath
if ($PassThru) { $RunState.resultObject }

exit (Get-V2ExitCode -Result $resultToken)
