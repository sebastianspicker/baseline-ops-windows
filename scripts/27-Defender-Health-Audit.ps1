#requires -version 5.1
<#
.SYNOPSIS
Create a Microsoft Defender health report (status, signatures, RTP, tamper protection, scan age).

.DESCRIPTION
Pipeline output is structured objects only (safe for Export-Csv / ConvertTo-Json / filtering).
All human-friendly formatting is written via Write-UiLine / Write-Information only.
Primary data source is Get-MpComputerStatus. [page:1]
Tamper protection can be checked via IsTamperProtected when present. [page:1]

.PARAMETER ExportPath
Optional. Export Summary as CSV.

.PARAMETER SettingsJsonPath
Optional. Path to JSON configuration (example: "PATH/TO/JSON/defender-audit.json").
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
Import-Module (Join-Path $script:LibPath 'Output.psm1') -Force
Import-Module (Join-Path $script:LibPath 'Common.psm1') -Force -DisableNameChecking
Import-Module (Join-Path $script:LibPath 'Console.psm1') -Force
Import-Module (Join-Path $script:LibPath 'Results.psm1') -Force
Import-Module (Join-Path $script:LibPath 'External.psm1') -Force -DisableNameChecking
Import-Module (Join-Path $script:LibPath Serialization.psm1) -Force


Set-StrictMode -Version Latest
# v2-init (migrated to Initialize-V2Context)
Initialize-V2Context -ScriptName '27-Defender-Health-Audit.ps1' -BoundParameters $PSBoundParameters
$ErrorActionPreference = 'Stop'

$isWindowsHost = ($env:OS -eq 'Windows_NT')
if (-not $isWindowsHost) {
  $summary = [pscustomobject]@{
    ComputerName = $env:COMPUTERNAME
    Timestamp    = Get-Date
    Mode         = $Mode
    Supported    = $false
    Notes        = @('Skipped: this script is only supported on Windows hosts.')
  }
  $result = Get-V2ResultObject -ScriptName '27-Defender-Health-Audit.ps1' -Mode $Mode -Result 'OK' -Findings @() -Summary $summary -Metadata @{ UnsupportedHost = $true }
  Write-ResultObject -ResultObject $result -OutputFormat $OutputFormat -OutputPath $OutputPath
  if ($PassThru) { $result }
  exit 0
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
    $raw = Get-Content -LiteralPath $Path -Raw -Encoding UTF8
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

  if ($null -eq $Findings -or $Findings.Count -eq 0) { return 'None' }

  $ranks = $Findings | ForEach-Object { Get-SeverityRank -Severity $_.Severity }
  $max = ($ranks | Measure-Object -Maximum).Maximum

  if ($max -ge 4) { return 'Critical' }
  if ($max -ge 3) { return 'High' }
  if ($max -ge 2) { return 'Medium' }
  if ($max -ge 1) { return 'Low' }
  if ($max -ge 0) { return 'Info' }
  return 'Unknown'
}

# Write-ConsoleSummary imported from lib/Console.psm1

# ----- Effective configuration (built-in defaults + optional JSON overlay)
$effective = Get-DefaultConfig `
  -WarnSignatureAgeDays $WarnSignatureAgeDays `
  -WarnQuickScanAgeDays $WarnQuickScanAgeDays `
  -WarnFullScanAgeDays  $WarnFullScanAgeDays `
  -SkipAdminCheck ([bool]$SkipAdminCheck) `
  -ExportPath $ExportPath `
  -SettingsJsonPath $SettingsJsonPath

$effective = Try-LoadJsonConfig -Config $effective -Path $SettingsJsonPath

# CLI parameters win over JSON (detect explicit use via PSBoundParameters).
if ($PSBoundParameters.ContainsKey('WarnSignatureAgeDays')) { $effective.WarnSignatureAgeDays = $WarnSignatureAgeDays }
if ($PSBoundParameters.ContainsKey('WarnQuickScanAgeDays')) { $effective.WarnQuickScanAgeDays = $WarnQuickScanAgeDays }
if ($PSBoundParameters.ContainsKey('WarnFullScanAgeDays'))  { $effective.WarnFullScanAgeDays  = $WarnFullScanAgeDays }
if ($PSBoundParameters.ContainsKey('ExportPath'))           { $effective.ExportPath           = $ExportPath }
if ($PSBoundParameters.ContainsKey('SkipAdminCheck'))       { $effective.SkipAdminCheck       = [bool]$SkipAdminCheck }
if ($PSBoundParameters.ContainsKey('SettingsJsonPath'))     { $effective.SettingsJsonPath     = $SettingsJsonPath }

# ----- Preconditions
if (-not $effective.SkipAdminCheck -and -not (Test-IsAdmin)) {
  $msg = 'Administrative rights required. Use -SkipAdminCheck if your environment allows it.'
  Write-Warning $msg
  $v2Result = Get-V2ResultObject -ScriptName '27-Defender-Health-Audit.ps1' -Mode $Mode -Result 'FAIL' -Findings @() -Summary @{ Error = $msg } -Metadata @{}
  Write-ResultObject -ResultObject $v2Result -OutputFormat $OutputFormat -OutputPath $OutputPath
  if ($PassThru) { $v2Result }
  exit 1
}

$null = Ensure-Cmdlet -Name 'Get-MpComputerStatus'  # Defender status cmdlet. [page:1]

# ----- Data collection
$Findings = Get-FindingsList
$st = Get-MpComputerStatus  # Gets antimalware/Defender status. [page:1]

# ----- Checks (based on Get-MpComputerStatus output properties). [page:1]
if ($st.AMServiceEnabled -ne $true) {
  Add-Finding -FindingList $Findings -Code 'DEF-AMServiceDisabled' -Severity 'High' -Message 'Defender AM Service is not enabled.'
}
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

$quickAge = Normalize-UInt32Age $st.QuickScanAge
$fullAge  = Normalize-UInt32Age $st.FullScanAge

# Get-MpComputerStatus commonly reports 4294967295 (max uint32) for "never ran". [page:1]
if ($null -ne $quickAge -and $quickAge -ne [uint32]::MaxValue -and $quickAge -ge $effective.WarnQuickScanAgeDays) {
  Add-Finding -FindingList $Findings -Code 'DEF-QuickScanOld' -Severity 'Low' -Message ("QuickScanAge={0} days (threshold {1})." -f $quickAge, $effective.WarnQuickScanAgeDays)
}

if ($null -ne $fullAge -and $fullAge -eq [uint32]::MaxValue) {
  Add-Finding -FindingList $Findings -Code 'DEF-FullScanNever' -Severity 'Info' -Message 'FullScanAge indicates "never ran" (max uint32).'
}
elseif ($null -ne $fullAge -and $fullAge -ne [uint32]::MaxValue -and $fullAge -ge $effective.WarnFullScanAgeDays) {
  Add-Finding -FindingList $Findings -Code 'DEF-FullScanOld' -Severity 'Low' -Message ("FullScanAge={0} days (threshold {1})." -f $fullAge, $effective.WarnFullScanAgeDays)
}

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

$result = [pscustomobject]@{
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

# ----- Console summary at the end (pretty, host-only)
$findingsAL = [System.Collections.ArrayList]::new()
foreach ($finding in $Findings) {
  [void]$findingsAL.Add($finding)
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

  Write-ConsoleSummary -Summary $summary -Findings $findingsAL `
    -Title 'Microsoft Defender Health Audit' `
    -CustomFields $customFields
}

# V2 output contract
$resultToken = if ($Strict -and $Findings.Count -gt 0) { 'FAIL' } elseif ($Findings.Count -gt 0) { 'WARN' } else { 'OK' }
$v2Result = Get-V2ResultObject -ScriptName '27-Defender-Health-Audit.ps1' -Mode $Mode -Result $resultToken -Findings (ConvertTo-ObjectArray -InputObject $Findings) -Summary $result.Summary -Metadata @{ EffectiveConfig = $result.EffectiveConfig }
Write-ResultObject -ResultObject $v2Result -OutputFormat $OutputFormat -OutputPath $OutputPath
if ($PassThru) { $v2Result }
exit 0
