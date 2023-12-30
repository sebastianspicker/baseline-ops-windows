#requires -version 5.1
<#
.SYNOPSIS
Create a Microsoft Defender health report (status, signatures, RTP, tamper protection, scan age).

.DESCRIPTION
Pipeline output is structured objects only (safe for Export-Csv / ConvertTo-Json / filtering).
All human-friendly formatting is written via Write-Host / Write-Information only.
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

.OUTPUTS
If -PassThru is used: PSCustomObject with Summary, Findings, EffectiveConfig.
Otherwise: no pipeline output (console summary only).
.EXAMPLE
  .\27-Defender-Health-Audit.ps1

#>


[CmdletBinding()]
param(
  [Parameter(Mandatory = $false)]
  [ValidateNotNullOrEmpty()]
  [string]$ExportPath,

  [Parameter(Mandatory = $false)]
  [ValidateNotNullOrEmpty()]
  [string]$SettingsJsonPath = 'PATH/TO/JSON/defender-audit.json',

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
)

$script:LibPath = Join-Path $PSScriptRoot 'lib'
Import-Module (Join-Path $script:LibPath 'Common.psm1') -Force
Import-Module (Join-Path $script:LibPath 'Results.psm1') -Force


Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'


function Ensure-Cmdlet {
  param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$Name
  )

  if (-not (Get-Command -Name $Name -ErrorAction SilentlyContinue)) {
    throw "Required cmdlet missing: $Name. Verify Microsoft Defender module/feature."
  }
}

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
    [string]$Path
  )

  if ([string]::IsNullOrWhiteSpace($Path)) { return $Config }

  $Config.JsonPathExists = (Test-Path -LiteralPath $Path)
  if (-not $Config.JsonPathExists) { return $Config }

  try {
    $raw = Get-Content -LiteralPath $Path -Raw
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

function Get-SeverityRank {
  param([string]$Severity)

  switch ($Severity) {
    'High'   { 1 }
    'Medium' { 2 }
    'Low'    { 3 }
    'Info'   { 4 }
    default  { 9 }
  }
}

function Get-HighestSeverity {
  param([System.Collections.Generic.List[object]]$Findings)

  if ($null -eq $Findings -or $Findings.Count -eq 0) { return 'None' }

  $ranks = $Findings | ForEach-Object { Get-SeverityRank $_.Severity }
  $min = ($ranks | Measure-Object -Minimum).Minimum

  switch ($min) {
    1 { 'High' }
    2 { 'Medium' }
    3 { 'Low' }
    4 { 'Info' }
    default { 'Unknown' }
  }
}

function Get-ColorForSeverity {
  param([string]$Severity)

  switch ($Severity) {
    'High'   { 'Red' }
    'Medium' { 'Yellow' }
    'Low'    { 'Cyan' }
    'Info'   { 'Gray' }
    'None'   { 'Green' }
    default  { 'White' }
  }
}

function Write-PrettyLine {
  param(
    [Parameter(Mandatory = $true)][string]$Label,
    [Parameter(Mandatory = $true)][string]$Value,
    [Parameter(Mandatory = $false)][string]$ValueColor = 'Gray',
    [Parameter(Mandatory = $false)][string]$LabelColor = 'DarkGray'
  )

  Write-Host ($Label.PadRight(28) + ': ') -NoNewline -ForegroundColor $LabelColor
  Write-Host $Value -ForegroundColor $ValueColor
}

function Write-ConsoleSummary {
  param(
    [Parameter(Mandatory = $true)]
    $Result
  )

  # Note: In Windows PowerShell 5.1, Write-Host writes to the Information stream. [page:0]
  # We keep all formatting in host output to preserve pipeline purity.

  $s = $Result.Summary
  $f = $Result.Findings
  $cfg = $Result.EffectiveConfig

  $highest = Get-HighestSeverity -Findings $f
  $highestColor = Get-ColorForSeverity $highest

  Write-Host ''
  Write-Host ('=' * 60) -ForegroundColor DarkGray
  Write-Host ' Microsoft Defender Health Audit ' -ForegroundColor White
  Write-Host ('=' * 60) -ForegroundColor DarkGray
  Write-Host ''

  Write-PrettyLine -Label 'ComputerName' -Value ([string]$s.ComputerName) -ValueColor White
  Write-PrettyLine -Label 'Timestamp' -Value ([string]$s.Timestamp) -ValueColor Gray

  Write-Host ''
  Write-Host 'Core status' -ForegroundColor White
  Write-Host ('-' * 60) -ForegroundColor DarkGray

  $boolColor = { param($b) if ($b -eq $true) { 'Green' } else { 'Red' } }

  Write-PrettyLine -Label 'AMRunningMode' -Value ([string]$s.AMRunningMode) -ValueColor Gray
  Write-PrettyLine -Label 'AMServiceEnabled' -Value ([string]$s.AMServiceEnabled) -ValueColor (& $boolColor $s.AMServiceEnabled)
  Write-PrettyLine -Label 'AntivirusEnabled' -Value ([string]$s.AntivirusEnabled) -ValueColor (& $boolColor $s.AntivirusEnabled)
  Write-PrettyLine -Label 'RealTimeProtection' -Value ([string]$s.RealTimeProtectionEnabled) -ValueColor (& $boolColor $s.RealTimeProtectionEnabled)

  $sigColor = if ($s.DefenderSignaturesOutOfDate -eq $true) { 'Red' } else { 'Green' }
  Write-PrettyLine -Label 'SignaturesOutOfDate' -Value ([string]$s.DefenderSignaturesOutOfDate) -ValueColor $sigColor

  Write-Host ''
  Write-Host 'Ages (days)' -ForegroundColor White
  Write-Host ('-' * 60) -ForegroundColor DarkGray

  $sigAgeColor = if (($null -ne $s.AntivirusSignatureAge) -and ($s.AntivirusSignatureAge -ge $cfg.WarnSignatureAgeDays)) { 'Yellow' } else { 'Green' }
  Write-PrettyLine -Label 'AntivirusSignatureAge' -Value ([string]$s.AntivirusSignatureAge) -ValueColor $sigAgeColor

  $qa = Get-ScanAgeLabel (Normalize-UInt32Age $s.QuickScanAge)
  $fa = Get-ScanAgeLabel (Normalize-UInt32Age $s.FullScanAge)

  $quickAgeColor = if ($qa -eq 'never') { 'Yellow' } elseif (($qa -as [int]) -ge $cfg.WarnQuickScanAgeDays) { 'Cyan' } else { 'Green' }
  $fullAgeColor  = if ($fa -eq 'never') { 'Yellow' } elseif (($fa -as [int]) -ge $cfg.WarnFullScanAgeDays) { 'Cyan' } else { 'Green' }

  Write-PrettyLine -Label 'QuickScanAge' -Value ("{0} (warn >= {1})" -f $qa, $cfg.WarnQuickScanAgeDays) -ValueColor $quickAgeColor
  Write-PrettyLine -Label 'FullScanAge'  -Value ("{0} (warn >= {1})" -f $fa, $cfg.WarnFullScanAgeDays) -ValueColor $fullAgeColor

  if ($s.PSObject.Properties.Name -contains 'IsTamperProtected') {
    $tpColor = if ($s.IsTamperProtected -eq $true) { 'Green' } else { 'Yellow' }
    Write-Host ''
    Write-Host 'Tamper protection' -ForegroundColor White
    Write-Host ('-' * 60) -ForegroundColor DarkGray
    Write-PrettyLine -Label 'IsTamperProtected' -Value ([string]$s.IsTamperProtected) -ValueColor $tpColor
  }

  Write-Host ''
  Write-Host 'Meta' -ForegroundColor White
  Write-Host ('-' * 60) -ForegroundColor DarkGray

  if ($cfg.LoadedFromJson) {
    Write-PrettyLine -Label 'ConfigSource' -Value ('JSON: ' + $cfg.SettingsJsonPath) -ValueColor Gray
  } elseif ($cfg.JsonLoadError) {
    Write-PrettyLine -Label 'ConfigSource' -Value ('Defaults (JSON error: ' + $cfg.JsonLoadError + ')') -ValueColor Yellow
  } elseif ($cfg.JsonPathExists) {
    Write-PrettyLine -Label 'ConfigSource' -Value ('Defaults (JSON empty)') -ValueColor Yellow
  } else {
    Write-PrettyLine -Label 'ConfigSource' -Value ('Defaults (no JSON found: ' + $cfg.SettingsJsonPath + ')') -ValueColor Gray
  }

  if ($cfg.ExportPath) {
    Write-PrettyLine -Label 'CsvExport' -Value $cfg.ExportPath -ValueColor Gray
  }

  Write-PrettyLine -Label 'FindingsCount' -Value ([string]$s.FindingsCount) -ValueColor $highestColor
  Write-PrettyLine -Label 'HighestSeverity' -Value $highest -ValueColor $highestColor

  Write-Host ''
  if ($f.Count -gt 0) {
    Write-Host 'Findings' -ForegroundColor White
    Write-Host ('-' * 60) -ForegroundColor DarkGray

    foreach ($item in ($f | Sort-Object @{ Expression = { Get-SeverityRank $_.Severity } }, Code)) {
      $c = Get-ColorForSeverity $item.Severity
      Write-Host ('[{0}] {1} - {2}' -f $item.Severity.ToUpper(), $item.Code, $item.Message) -ForegroundColor $c
    }
  }
  else {
    Write-Host 'No findings.' -ForegroundColor Green
  }

  Write-Host ''
}

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
  throw 'Administrative rights required. Use -SkipAdminCheck if your environment allows it.'
}

Ensure-Cmdlet -Name 'Get-MpComputerStatus'  # Defender status cmdlet. [page:1]

# ----- Data collection
$Findings = New-FindingsList
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
if (-not $NoConsoleSummary) {
  Write-ConsoleSummary -Result $result
}

# ----- Pipeline output (structured object only)
if ($PassThru) {
  $result
}
