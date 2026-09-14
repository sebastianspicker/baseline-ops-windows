#requires -version 5.1
<#
.SYNOPSIS
Create a Microsoft Defender health report (status, signatures, RTP, tamper protection, scan age).

.DESCRIPTION
Pipeline output is structured objects only (safe for Export-Csv / ConvertTo-Json / filtering).
All console formatting is written via Write-UiLine / Write-Information only.
Primary data source is Get-MpComputerStatus. [page:1]
Tamper protection can be checked via IsTamperProtected when present. [page:1]

.PARAMETER ExportPath
Optional. Export Summary as CSV.

.PARAMETER SettingsJsonPath
Optional. Path to JSON configuration supplied with $SettingsJsonPath.
If missing/unreadable/invalid, built-in defaults are used.

.PARAMETER WarnSignatureAgeDays
Warning threshold for AntivirusSignatureAge (days).

.PARAMETER WarnQuickScanAgeDays
Warning threshold for QuickScanAge (days).

.PARAMETER WarnFullScanAgeDays
Warning threshold for FullScanAge (days).

.PARAMETER SkipAdminCheck
Skip the admin check (useful in some automation contexts).

.PARAMETER NoConsoleSummary
Do not print the console summary.

.PARAMETER PassThru
Return the structured result object to the pipeline.


.PARAMETER Mode
  Execution mode. 'Audit' reports only; 'Remediate' applies changes.

.PARAMETER ConfigPath
  Path to JSON configuration file.

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
If -PassThru is used: PSCustomObject with Summary, Findings, EffectiveConfig.
Otherwise: no pipeline output (console summary only).
.EXAMPLE
  .\27-Defender-Health-Audit.ps1

#>


[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
  [Parameter(Mandatory = $false)]
  [ValidateNotNullOrEmpty()]
  [string]$ExportPath,

  [Parameter(Mandatory = $false)]
  [ValidateNotNullOrEmpty()]
  [string]$SettingsJsonPath,

  [Parameter(Mandatory = $false)]
  [ValidateRange(0, 3650)]
  [int]$WarnSignatureAgeDays = 3,

  [Parameter(Mandatory = $false)]
  [ValidateRange(0, 3650)]
  [int]$WarnQuickScanAgeDays = 14,

  [Parameter(Mandatory = $false)]
  [ValidateRange(0, 3650)]
  [int]$WarnFullScanAgeDays  = 30,

  [Parameter(Mandatory = $false)]
  [switch]$SkipAdminCheck,

  [Parameter(Mandatory = $false)]
  [switch]$NoConsoleSummary,

  [Parameter(Mandatory = $false)]
  [switch]$PassThru

,
  [ValidateSet('Audit','Remediate')][string]$Mode = 'Audit',
  [string]$ConfigPath,
  [ValidateSet('Console','Json','Csv','None')][string]$OutputFormat = 'Console',
  [string]$OutputPath,
  [switch]$Strict,
  [switch]$Quiet,
  [switch]$NoColor
)

. (Join-Path $PSScriptRoot '_lib/Bootstrap.ps1')
function Test-AllConditions {
  param([scriptblock[]]$Conditions)
  foreach ($condition in $Conditions) {
    if (-not (. $condition)) { return $false }
  }
  return $true
}
function Test-AnyCondition {
  param([scriptblock[]]$Conditions)
  foreach ($condition in $Conditions) {
    if (. $condition) { return $true }
  }
  return $false
}
function Initialize-Capability27Runtime {
  param($EntryBoundParameters)
  $RunState = @{

  }
Import-Module (Join-Path $script:LibPath 'Output.psm1') -Force
Import-Module (Join-Path $script:LibPath 'Common.psm1') -Force -DisableNameChecking
Import-Module (Join-Path $script:LibPath 'Console.psm1') -Force
Import-Module (Join-Path $script:LibPath 'Results.psm1') -Force
Import-Module (Join-Path $script:LibPath 'External.psm1') -Force -DisableNameChecking
Import-Module (Join-Path $script:LibPath Serialization.psm1) -Force


Set-StrictMode -Version Latest
$script:__V2Context = Initialize-V2Context -ScriptName '27-Defender-Health-Audit.ps1' -BoundParameters $EntryBoundParameters `
  -Values @{ Mode = $Mode; ConfigPath = $ConfigPath; OutputFormat = $OutputFormat; OutputPath = $OutputPath; PassThru = $PassThru; Strict = $Strict; Quiet = $Quiet; NoColor = $NoColor; DeriveRemediate = $false }
if ($script:__V2Context.Quiet) { $InformationPreference = 'SilentlyContinue'; $VerbosePreference = 'SilentlyContinue' }
$script:NoColor = [bool]$script:__V2Context.NoColor
$ErrorActionPreference = 'Stop'

$RunState.isWindowsHost = ($env:OS -eq 'Windows_NT')
  $script:RunState = $RunState
}

. Initialize-Capability27Runtime -EntryBoundParameters $PSBoundParameters
function Get-Capability27UnsupportedState {
  param([hashtable]$RunState)
$summary = [pscustomobject]@{
  ComputerName = $env:COMPUTERNAME
  Timestamp    = Get-Date
  Mode         = $Mode
  Supported    = $false
  Notes        = @('Skipped: this script is only supported on Windows hosts.')
}
$RunState.unsupportedResult = if ($Strict) { 'FAIL' } else { 'WARN' }
$RunState.result = Get-V2ResultObject -ScriptName '27-Defender-Health-Audit.ps1' -Mode $Mode -Result $RunState.unsupportedResult -Findings @() -Summary $summary -Metadata @{ UnsupportedHost = $true }
  [pscustomobject]@{ Result = $RunState.result; Token = $RunState.unsupportedResult }
}
function Set-Capability27UnsupportedState {
  param([hashtable]$RunState)
  $unsupportedState = Get-Capability27UnsupportedState -RunState $RunState
  $RunState.result = $unsupportedState.Result
  $RunState.unsupportedResult = $unsupportedState.Token
}
if (-not $RunState.isWindowsHost) {
  . Set-Capability27UnsupportedState -RunState $RunState
  Write-ResultObject -ResultObject $RunState.result -OutputFormat $OutputFormat -OutputPath $OutputPath
  if ($PassThru) { $RunState.result }
  exit (Get-V2ExitCode -Result $RunState.unsupportedResult)
}


# Ensure-Cmdlet imported from lib/External.psm1

function Get-DefaultConfig {
  param(
    [int]$WarnSignatureAgeDays,
    [int]$WarnQuickScanAgeDays,
    [int]$WarnFullScanAgeDays,
    [bool]$SkipAdminCheck,
    [string]$ExportPath,
    [string]$SettingsJsonPath
  )

  [pscustomobject]@{
    WarnSignatureAgeDays = $WarnSignatureAgeDays
    WarnQuickScanAgeDays = $WarnQuickScanAgeDays
    WarnFullScanAgeDays  = $WarnFullScanAgeDays
    SkipAdminCheck       = $SkipAdminCheck
    ExportPath           = $ExportPath
    SettingsJsonPath     = $SettingsJsonPath

    LoadedFromJson       = $false
    JsonLoadError        = $null
    JsonPathExists       = $false
  }
}

function Merge-Config {
  param(
    [Parameter(Mandatory = $true)]
    [pscustomobject]$Base,

    [Parameter(Mandatory = $true)]
    $Overlay
  )

  if ($null -eq $Overlay) { return $Base }

  foreach ($p in $Overlay.PSObject.Properties) {
    if (($Base.PSObject.Properties.Name -contains $p.Name) -and ($null -ne $p.Value)) {
      $Base.$($p.Name) = $p.Value
    }
  }

  $Base
}

function Try-LoadJsonConfig {
  param(
    [Parameter(Mandatory = $true)]
    [pscustomobject]$Config,

    [Parameter(Mandatory = $true)]
    [AllowEmptyString()]
    [string]$Path
  )

  if ([string]::IsNullOrWhiteSpace($Path)) { return $Config }

  $Config.JsonPathExists = (Test-Path -LiteralPath $Path)
  if (-not $Config.JsonPathExists) { return $Config }

  try {
    $raw = Get-BoundedUtf8FileContent -Path $Path -MaximumBytes 1048576
    if ([string]::IsNullOrWhiteSpace($raw)) { return $Config }

    $json = $raw | ConvertFrom-Json

    $overlay = $json
    if ($json -and ($json.PSObject.Properties.Name -contains 'Config')) {
      $overlay = $json.Config
    }

    $Config = Merge-Config -Base $Config -Overlay $overlay
    $Config.LoadedFromJson = $true
    $Config.JsonLoadError = $null
    return $Config
  }
  catch {
    $Config.LoadedFromJson = $false
    $Config.JsonLoadError  = $_.Exception.Message
    return $Config
  }
}

function Normalize-UInt32Age {
  param($Value)

  if ($null -eq $Value) { return $null }
  try { return [uint32]$Value } catch { return $null }
}

function Get-ScanAgeLabel {
  param([Nullable[UInt32]]$Age)

  if ($null -eq $Age) { return 'n/a' }
  if ($Age -eq [uint32]::MaxValue) { return 'never' }
  return [string]$Age
}

function Get-HighestSeverity {
  param([System.Collections.Generic.List[object]]$Findings)

  if ((Test-AnyCondition -Conditions @({ $null -eq $Findings }, { $Findings.Count -eq 0 }))) { return 'None' }

  $ranks = $Findings | ForEach-Object { Get-SeverityRank -Severity $_.Severity }
  $max = ($ranks | Measure-Object -Maximum).Maximum
  $labels = @('Info', 'Low', 'Medium', 'High', 'Critical')
  if ($max -lt 0 -or $max -ge $labels.Count) { return 'Unknown' }
  return $labels[[int]$max]
}

# Write-ConsoleSummary imported from lib/Console.psm1

# ----- Effective configuration (built-in defaults + optional JSON overlay)
function Invoke-Capability27MainPhase01 {
  $effective = Get-DefaultConfig `
    -WarnSignatureAgeDays $WarnSignatureAgeDays `
    -WarnQuickScanAgeDays $WarnQuickScanAgeDays `
    -WarnFullScanAgeDays  $WarnFullScanAgeDays `
    -SkipAdminCheck ([bool]$SkipAdminCheck) `
    -ExportPath $ExportPath `
    -SettingsJsonPath $SettingsJsonPath

  $effective = Try-LoadJsonConfig -Config $effective -Path $SettingsJsonPath

  # CLI parameters win over JSON (detect explicit use via PSBoundParameters).
  if ($script:__EntryBoundParameters.ContainsKey('WarnSignatureAgeDays')) { $effective.WarnSignatureAgeDays = $WarnSignatureAgeDays }
  if ($script:__EntryBoundParameters.ContainsKey('WarnQuickScanAgeDays')) { $effective.WarnQuickScanAgeDays = $WarnQuickScanAgeDays }
  if ($script:__EntryBoundParameters.ContainsKey('WarnFullScanAgeDays'))  { $effective.WarnFullScanAgeDays  = $WarnFullScanAgeDays }
  if ($script:__EntryBoundParameters.ContainsKey('ExportPath'))           { $effective.ExportPath           = $ExportPath }
  if ($script:__EntryBoundParameters.ContainsKey('SkipAdminCheck'))       { $effective.SkipAdminCheck       = [bool]$SkipAdminCheck }
}
function Invoke-Capability27MainPhase02 {
  if ($script:__EntryBoundParameters.ContainsKey('SettingsJsonPath'))     { $effective.SettingsJsonPath     = $SettingsJsonPath }

  # ----- Preconditions
  if (-not $effective.SkipAdminCheck -and -not (Test-IsAdmin)) {
    $msg = 'Administrative rights required. Use -SkipAdminCheck if your environment allows it.'
    Write-Warning $msg
    $v2Result = Get-V2ResultObject -ScriptName '27-Defender-Health-Audit.ps1' -Mode $Mode -Result 'FAIL' -Findings @() -Summary @{ Error = $msg } -Metadata @{}
    Write-ResultObject -ResultObject $v2Result -OutputFormat $OutputFormat -OutputPath $OutputPath
    if ($PassThru) { $v2Result }
    exit (Get-V2ExitCode -Result 'FAIL')
  }

  $null = Ensure-Cmdlet -Name 'Get-MpComputerStatus'  # Defender status cmdlet. [page:1]

  # ----- Data collection
  $Findings = Get-FindingsList
  $st = Get-MpComputerStatus  # Gets antimalware/Defender status. [page:1]

  # ----- Checks (based on Get-MpComputerStatus output properties). [page:1]
  if ($st.AMServiceEnabled -ne $true) {
    Add-Finding -FindingList $Findings -Code 'DEF-AMServiceDisabled' -Severity 'High' -Message 'Defender AM Service is not enabled.'
  }
}
function Invoke-Capability27MainPhase03 {
  param([hashtable]$RunState)
  if ($st.AntivirusEnabled -ne $true) {
    Add-Finding -FindingList $Findings -Code 'DEF-AntivirusDisabled' -Severity 'High' -Message 'AntivirusEnabled=False.'
  }
  if ($st.RealTimeProtectionEnabled -ne $true) {
    Add-Finding -FindingList $Findings -Code 'DEF-RTP-Disabled' -Severity 'High' -Message 'RealTimeProtectionEnabled=False.'
  }
  if ($st.DefenderSignaturesOutOfDate -eq $true) {
    Add-Finding -FindingList $Findings -Code 'DEF-SignaturesOutOfDate' -Severity 'Medium' -Message 'DefenderSignaturesOutOfDate=True.'
  }

  if ($null -ne $st.AntivirusSignatureAge -and $st.AntivirusSignatureAge -ge $effective.WarnSignatureAgeDays) {
    Add-Finding -FindingList $Findings -Code 'DEF-SignatureAgeHigh' -Severity 'Medium' -Message ("AntivirusSignatureAge={0} days (threshold {1})." -f $st.AntivirusSignatureAge, $effective.WarnSignatureAgeDays)
  }

  $RunState.quickAge = Normalize-UInt32Age $st.QuickScanAge
  $RunState.fullAge  = Normalize-UInt32Age $st.FullScanAge
}
function Invoke-Capability27MainPhase04 {
  param([hashtable]$RunState)
  if ($null -ne $RunState.quickAge -and $RunState.quickAge -ne [uint32]::MaxValue -and $RunState.quickAge -ge $effective.WarnQuickScanAgeDays) {
    Add-Finding -FindingList $Findings -Code 'DEF-QuickScanOld' -Severity 'Low' -Message ("QuickScanAge={0} days (threshold {1})." -f $RunState.quickAge, $effective.WarnQuickScanAgeDays)
  }
}
function Invoke-Capability27MainPhase05 {
  param([hashtable]$RunState)
  if ($null -ne $RunState.fullAge -and $RunState.fullAge -eq [uint32]::MaxValue) {
    Add-Finding -FindingList $Findings -Code 'DEF-FullScanNever' -Severity 'Info' -Message 'FullScanAge indicates "never ran" (max uint32).'
  }
  elseif ($null -ne $RunState.fullAge -and $RunState.fullAge -ne [uint32]::MaxValue -and $RunState.fullAge -ge $effective.WarnFullScanAgeDays) {
    Add-Finding -FindingList $Findings -Code 'DEF-FullScanOld' -Severity 'Low' -Message ("FullScanAge={0} days (threshold {1})." -f $RunState.fullAge, $effective.WarnFullScanAgeDays)
  }
}
function Invoke-Capability27MainPhase06 {
  param([hashtable]$RunState)
  if ($st.PSObject.Properties.Name -contains 'IsTamperProtected') {
    if ($st.IsTamperProtected -ne $true) {
      Add-Finding -FindingList $Findings -Code 'DEF-TamperProtectionOff' -Severity 'Medium' -Message 'IsTamperProtected=False (tamper protection appears off/unprotected).'
    }
  }

  # ----- Summary (CSV-friendly)
  $summary = [pscustomobject]@{
    ComputerName                  = $env:COMPUTERNAME
    AMRunningMode                 = $st.AMRunningMode
    AMServiceEnabled              = $st.AMServiceEnabled
    AntivirusEnabled              = $st.AntivirusEnabled
    AntispywareEnabled            = $st.AntispywareEnabled
    BehaviorMonitorEnabled        = $st.BehaviorMonitorEnabled
    RealTimeProtectionEnabled     = $st.RealTimeProtectionEnabled
    DefenderSignaturesOutOfDate   = $st.DefenderSignaturesOutOfDate
    AntivirusSignatureAge         = $st.AntivirusSignatureAge
    AntivirusSignatureLastUpdated = $st.AntivirusSignatureLastUpdated
    QuickScanAge                  = $st.QuickScanAge
    FullScanAge                   = $st.FullScanAge
    IsTamperProtected             = $st.IsTamperProtected
    RebootRequired                = $st.RebootRequired
    FindingsCount                 = $Findings.Count
    Timestamp                     = (Get-Date)
  }

  $RunState.result = [pscustomobject]@{
    Summary         = $summary
    Findings        = $Findings
    EffectiveConfig = $effective
  }

  # ----- Optional CSV export
  if ($effective.ExportPath) {
    $dir = Split-Path -Path $effective.ExportPath -Parent
    if ($dir -and -not (Test-Path -LiteralPath $dir)) {
      $null = New-Item -Path $dir -ItemType Directory -Force
    }
    $summary | Export-Csv -LiteralPath $effective.ExportPath -NoTypeInformation -Encoding UTF8
  }

  # ----- Formatted console summary (host only)
  $RunState.findingsAL = [System.Collections.ArrayList]::new()
}
function Invoke-Capability27MainPhase07 {
  param([hashtable]$RunState)
  foreach ($finding in $Findings) {
    [void]$RunState.findingsAL.Add($finding)
  }

  if (-not $NoConsoleSummary) {
    $highest = Get-HighestSeverity -Findings $Findings
    $qa = Get-ScanAgeLabel (Normalize-UInt32Age $summary.QuickScanAge)
    $fa = Get-ScanAgeLabel (Normalize-UInt32Age $summary.FullScanAge)

    $configSource = if ($effective.LoadedFromJson) { 'JSON: ' + $effective.SettingsJsonPath }
      elseif ($effective.JsonLoadError) { 'Defaults (JSON error: ' + $effective.JsonLoadError + ')' }
      elseif ($effective.JsonPathExists) { 'Defaults (JSON empty)' }
      else { 'Defaults (no JSON found: ' + $effective.SettingsJsonPath + ')' }

    $customFields = [ordered]@{
      'AMRunning'  = [string]$summary.AMRunningMode
      'AMService'  = [string]$summary.AMServiceEnabled
      'Antivirus'  = [string]$summary.AntivirusEnabled
      'RTP'        = [string]$summary.RealTimeProtectionEnabled
      'SigsStale'  = [string]$summary.DefenderSignaturesOutOfDate
      'SigAge'     = [string]$summary.AntivirusSignatureAge
      'QuickScan'  = ("{0} (warn >= {1})" -f $qa, $effective.WarnQuickScanAgeDays)
      'FullScan'   = ("{0} (warn >= {1})" -f $fa, $effective.WarnFullScanAgeDays)
      'Tamper'     = [string]$summary.IsTamperProtected
      'Severity'   = $highest
      'Config'     = $configSource
    }

    Write-ConsoleSummary -Summary $summary -Findings $RunState.findingsAL `
      -Title 'Microsoft Defender Health Audit' `
      -CustomFields $customFields
  }
}
function Invoke-Capability27Main {
  param($EntryBoundParameters, $EntryCmdlet, $EntryInvocation, [hashtable]$RunState)
  $script:__EntryBoundParameters = $EntryBoundParameters
  $script:__EntryCmdlet = $EntryCmdlet
  $script:__EntryInvocation = $EntryInvocation
  . Invoke-Capability27MainPhase01
  . Invoke-Capability27MainPhase02
  . Invoke-Capability27MainPhase03 -RunState $RunState
  . Invoke-Capability27MainPhase04 -RunState $RunState
  . Invoke-Capability27MainPhase05 -RunState $RunState
  . Invoke-Capability27MainPhase06 -RunState $RunState
  . Invoke-Capability27MainPhase07 -RunState $RunState
}
. Invoke-Capability27Main -EntryBoundParameters $PSBoundParameters -EntryCmdlet $PSCmdlet -EntryInvocation $MyInvocation -RunState $RunState

# V2 output contract
function Get-Capability27ResultToken {
  $resultToken = if ($Strict -and $Findings.Count -gt 0) { 'FAIL' } elseif ($Findings.Count -gt 0) { 'WARN' } else { 'OK' }
  return $resultToken
}
$resultToken = Get-Capability27ResultToken
$v2Result = Get-V2ResultObject -ScriptName '27-Defender-Health-Audit.ps1' -Mode $Mode -Result $resultToken -Findings (ConvertTo-ObjectArray -InputObject $Findings) -Summary $RunState.result.Summary -Metadata @{ EffectiveConfig = $RunState.result.EffectiveConfig }
Write-ResultObject -ResultObject $v2Result -OutputFormat $OutputFormat -OutputPath $OutputPath
if ($PassThru) { $v2Result }
exit (Get-V2ExitCode -Result $resultToken)
