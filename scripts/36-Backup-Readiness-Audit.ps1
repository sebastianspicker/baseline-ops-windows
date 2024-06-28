#requires -version 5.1
<#
.SYNOPSIS
Backup/Restore readiness baseline audit (no third-party tools).

.DESCRIPTION
Best-practice split:
- Pipeline output: only one structured object (Summary, Findings, Indicators, VssRaw).
- Console output: pretty, colorized human output using Write-Host / Write-Information only.

Checks:
- OS disk free space (rough signal).
- VSS writers state (common backup root cause).
- Windows Server Backup feature status (server only, if ServerManager is available).
- File History registry presence (client indicator).
- Optional JSON settings (safe defaults if missing/invalid).
- Optional export (CSV + VSS raw output).
- Console summary at the end.

.PARAMETER ExportPath
Optional path prefix for export files. Example: C:\Temp\36-Backup-Readiness-Audit.csv
Creates: *_summary.csv, *_findings.csv, *_indicators.csv, *_vss_writers.txt

.PARAMETER ConfigJsonPath
Optional JSON configuration path (e.g. "PATH/TO/JSON\backup-audit.json").
If missing or invalid JSON, defaults are used.

.OUTPUTS
PSCustomObject with Summary, Findings, Indicators, VssRaw.
.EXAMPLE
  .\36-Backup-Readiness-Audit.ps1

#>

[CmdletBinding()]
param(
  [Parameter(Mandatory = $false)]
  [string]$ExportPath,

  [Parameter(Mandatory = $false)]
  [string]$ConfigJsonPath
)

$script:LibPath = Join-Path $PSScriptRoot 'lib'
Import-Module (Join-Path $script:LibPath 'Results.psm1') -Force

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

$script:Findings = New-FindingsList

function Get-DefaultConfig {
  [CmdletBinding()]
  param()

  [pscustomobject]@{
    MinOsFreeGB               = 10
    TreatUnparsedVssAsFinding = $true

    VssFailedNoErrorSeverity  = 'Medium'
    VssFailedErrorSeverity    = 'High'

    ConsoleTopFindings        = 10
    ConsoleUseInformation     = $false  # If $true, prefer Write-Information; Write-Host used for colors anyway.
  }
}

function Normalize-Severity {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)] [string]$Severity,
    [string]$Fallback = 'Medium'
  )

  if ($Severity -in @('Info','Low','Medium','High')) { return $Severity }
  return $Fallback
}

function Get-Config {
  [CmdletBinding()]
  param(
    [string]$Path
  )

  $cfg = Get-DefaultConfig

  if ([string]::IsNullOrWhiteSpace($Path)) {
    return $cfg
  }

  if (-not (Test-Path -LiteralPath $Path)) {
    Add-Finding -Code 'BKP-ConfigJsonMissing' -Severity 'Info' `
      -Message 'Config JSON not found; using defaults.' `
      -Extra @{
        Evidence    = ("ConfigJsonPath={0}" -f $Path)
        Remediation = 'Provide a valid -ConfigJsonPath if customization is required.'
      }
    return $cfg
  }

  try {
    # PowerShell 5.1 ConvertFrom-Json errors on JSON comments; keep JSON strictly compliant. [web:64]
    $raw = Get-Content -LiteralPath $Path -Raw -ErrorAction Stop
    if ([string]::IsNullOrWhiteSpace($raw)) { throw "Config JSON is empty." }

    $user = $raw | ConvertFrom-Json -ErrorAction Stop

    if ($null -ne $user.MinOsFreeGB)               { $cfg.MinOsFreeGB = [int]$user.MinOsFreeGB }
    if ($null -ne $user.TreatUnparsedVssAsFinding) { $cfg.TreatUnparsedVssAsFinding = [bool]$user.TreatUnparsedVssAsFinding }
    if ($null -ne $user.VssFailedNoErrorSeverity)  { $cfg.VssFailedNoErrorSeverity = [string]$user.VssFailedNoErrorSeverity }
    if ($null -ne $user.VssFailedErrorSeverity)    { $cfg.VssFailedErrorSeverity = [string]$user.VssFailedErrorSeverity }
    if ($null -ne $user.ConsoleTopFindings)        { $cfg.ConsoleTopFindings = [int]$user.ConsoleTopFindings }
    if ($null -ne $user.ConsoleUseInformation)     { $cfg.ConsoleUseInformation = [bool]$user.ConsoleUseInformation }

    if ($cfg.MinOsFreeGB -lt 1) { $cfg.MinOsFreeGB = 1 }
    if ($cfg.ConsoleTopFindings -lt 1) { $cfg.ConsoleTopFindings = 1 }

    $cfg.VssFailedNoErrorSeverity = Normalize-Severity -Severity $cfg.VssFailedNoErrorSeverity -Fallback 'Medium'
    $cfg.VssFailedErrorSeverity   = Normalize-Severity -Severity $cfg.VssFailedErrorSeverity   -Fallback 'High'

    return $cfg
  }
  catch {
    Add-Finding -Code 'BKP-ConfigJsonInvalid' -Severity 'Low' `
      -Message 'Config JSON could not be loaded/parsed; using defaults.' `
      -Extra @{
        Evidence    = $_.Exception.Message
        Remediation = 'Validate JSON syntax/encoding; PowerShell 5.1 does not accept JSON comments.'
      }
    return $cfg
  }
}

function Get-OsDiskInfo {
  [CmdletBinding()]
  param()

  try {
    $driveId = $env:SystemDrive
    if ([string]::IsNullOrWhiteSpace($driveId)) { throw "SystemDrive is empty." }
    $driveId = $driveId.TrimEnd('\')

    $d = Get-CimInstance -ClassName Win32_LogicalDisk -Filter ("DeviceID='{0}'" -f $driveId) -ErrorAction Stop
    if (-not $d) { throw "Win32_LogicalDisk returned no result for $driveId" }

    [pscustomobject]@{
      DeviceID = $d.DeviceID
      FreeGB   = [math]::Round(($d.FreeSpace / 1GB), 2)
      SizeGB   = [math]::Round(($d.Size / 1GB), 2)
    }
  }
  catch {
    Add-Finding -Code 'BKP-OsDiskQueryFailed' -Severity 'Medium' `
      -Message 'OS disk could not be queried via CIM.' `
      -Extra @{
        Evidence    = $_.Exception.Message
        Remediation = 'Check CIM/WMI health and permissions; retry.'
      }
    return $null
  }
}

function Get-VssWriters {
  [CmdletBinding()]
  param()

  $raw = $null
  $writers = @()

  try {
    $raw = (& vssadmin.exe list writers 2>&1 | Out-String).Trim()
  }
  catch {
    $raw = $_.Exception.Message
  }

  if ($raw -match 'Writer name') {
    $blocks = ($raw -split "(?=Writer name:)") | Where-Object { $_.Trim() }
    foreach ($b in $blocks) {
      $name      = ([regex]::Match($b, "Writer name:\s*'([^']+)'")).Groups[1].Value
      $state     = ([regex]::Match($b, "State:\s*\[\d+\]\s*([A-Za-z ]+)")).Groups[1].Value.Trim()
      $lastError = ([regex]::Match($b, "Last error:\s*(.+)")).Groups[1].Value.Trim()

      if (-not [string]::IsNullOrWhiteSpace($name)) {
        $writers += [pscustomobject]@{
          Name      = $name
          State     = $state
          LastError = $lastError
          RawBlock  = $b.Trim()
        }
      }
    }
  }

  [pscustomobject]@{
    Raw     = $raw
    Writers = $writers
  }
}

function Get-WsbStatus {
  [CmdletBinding()]
  param()

  $status = 'Unknown'

  if (Get-Command -Name Get-WindowsFeature -ErrorAction SilentlyContinue) {
    try {
      $feat = Get-WindowsFeature -Name Windows-Server-Backup -ErrorAction Stop
      $status = if ($feat.Installed) { 'Installed' } else { 'NotInstalled' }
    }
    catch {
      $status = 'Unknown'
      Add-Finding -Code 'BKP-WSBQueryFailed' -Severity 'Low' `
        -Message 'Windows Server Backup feature status could not be determined.' `
        -Extra @{
          Evidence    = $_.Exception.Message
          Remediation = 'Ensure ServerManager module is available and permissions are sufficient.'
        }
    }
  }

  return $status
}

function Get-SeverityRank {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)] [ValidateSet('Info','Low','Medium','High')] [string]$Severity
  )

  switch ($Severity) {
    'High'   { 4 }
    'Medium' { 3 }
    'Low'    { 2 }
    'Info'   { 1 }
  }
}

function Get-SeverityColor {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)] [ValidateSet('Info','Low','Medium','High')] [string]$Severity
  )

  switch ($Severity) {
    'High'   { 'Red' }
    'Medium' { 'Yellow' }
    'Low'    { 'Cyan' }
    'Info'   { 'Gray' }
  }
}

function Write-PrettyLine {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)] [string]$Text,
    [ConsoleColor]$Color = [ConsoleColor]::Gray,
    [switch]$NoNewline
  )

  if ($NoNewline) {
    Write-Host $Text -ForegroundColor $Color -NoNewline
  }
  else {
    Write-Host $Text -ForegroundColor $Color
  }
}

function Write-ConsoleSummary {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)] $Summary,
    [Parameter(Mandatory)] $Indicators,
    [Parameter(Mandatory)] $Findings,
    [Parameter(Mandatory)] $Config
  )

  # Keep formatting off the success output stream (pipeline). [page:0]
  Write-Host ''
  Write-PrettyLine -Text ('=' * 46) -Color DarkGray
  Write-PrettyLine -Text ' Backup Readiness Audit (Baseline)' -Color White
  Write-PrettyLine -Text ('=' * 46) -Color DarkGray

  Write-PrettyLine -Text (" Computer : {0}" -f $Summary.ComputerName) -Color Gray
  Write-PrettyLine -Text (" Time     : {0}" -f $Summary.Timestamp) -Color Gray

  $badgeColor = if ($Summary.FindingsCount -gt 0) { 'Yellow' } else { 'Green' }
  Write-PrettyLine -Text (" Findings : {0}" -f $Summary.FindingsCount) -Color $badgeColor

  Write-Host ''
  Write-PrettyLine -Text ' Indicators' -Color White
  Write-PrettyLine -Text ('-' * 46) -Color DarkGray

  $osLine = if ($null -eq $Indicators.OsFreeGB -or $null -eq $Indicators.OsSizeGB) {
    ' OS Disk  : <unavailable>'
  } else {
    ' OS Disk  : {0}  Free {1} GB / {2} GB (Min {3} GB)' -f $Indicators.OsDrive, $Indicators.OsFreeGB, $Indicators.OsSizeGB, $Config.MinOsFreeGB
  }

  $osColor = 'Green'
  if ($null -eq $Indicators.OsFreeGB) { $osColor = 'Yellow' }
  elseif ($Indicators.OsFreeGB -lt $Config.MinOsFreeGB) { $osColor = 'Red' }
  Write-PrettyLine -Text $osLine -Color $osColor

  Write-PrettyLine -Text (" VSS      : Writers detected = {0}" -f $Indicators.VssWritersCount) -Color Gray

  $wsbColor = switch ($Indicators.WSBStatus) {
    'Installed'   { 'Green' }
    'NotInstalled'{ 'Yellow' }
    default       { 'Gray' }
  }
  Write-PrettyLine -Text (" WSB      : {0}" -f $Indicators.WSBStatus) -Color $wsbColor

  $fhColor = if ($Indicators.FileHistoryKey) { 'Green' } else { 'Gray' }
  Write-PrettyLine -Text (" FileHist : {0}" -f $Indicators.FileHistoryKey) -Color $fhColor

  Write-Host ''
  Write-PrettyLine -Text ' Findings' -Color White
  Write-PrettyLine -Text ('-' * 46) -Color DarkGray

  if ($Findings.Count -eq 0) {
    Write-PrettyLine -Text ' No findings.' -Color Green
    Write-Host ''
    return
  }

  $top = $Findings |
    Sort-Object `
      @{ Expression = { Get-SeverityRank -Severity $_.Severity }; Descending = $true }, `
      @{ Expression = 'Code'; Descending = $false } |
    Select-Object -First $Config.ConsoleTopFindings

  foreach ($f in $top) {
    $c = Get-SeverityColor -Severity $f.Severity
    Write-PrettyLine -Text (" [{0}] {1} - {2}" -f $f.Severity.ToUpper(), $f.Code, $f.Message) -Color $c

    if (-not [string]::IsNullOrWhiteSpace($f.Evidence)) {
      Write-PrettyLine -Text ("        Evidence   : {0}" -f $f.Evidence) -Color DarkGray
    }
    if (-not [string]::IsNullOrWhiteSpace($f.Remediation)) {
      Write-PrettyLine -Text ("        Remediate  : {0}" -f $f.Remediation) -Color DarkGray
    }
  }

  if ($Findings.Count -gt $Config.ConsoleTopFindings) {
    Write-Host ''
    Write-PrettyLine -Text (" Showing top {0} of {1} findings." -f $Config.ConsoleTopFindings, $Findings.Count) -Color DarkGray
  }

  Write-Host ''
}

function Invoke-Export {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)] [string]$ExportPath,
    [Parameter(Mandatory)] $Summary,
    [Parameter(Mandatory)] $Findings,
    [Parameter(Mandatory)] $Indicators,
    [Parameter(Mandatory)] [string]$VssRaw
  )

  try {
    $folder = Split-Path -Path $ExportPath -Parent
    if (-not $folder) { $folder = (Get-Location).Path }

    if (-not (Test-Path -LiteralPath $folder)) {
      New-Item -Path $folder -ItemType Directory -Force | Out-Null
    }

    $base = [IO.Path]::GetFileNameWithoutExtension($ExportPath)

    $Summary    | Export-Csv -Path (Join-Path $folder ($base + "_summary.csv"))     -NoTypeInformation -Encoding UTF8
    $Findings   | Export-Csv -Path (Join-Path $folder ($base + "_findings.csv"))    -NoTypeInformation -Encoding UTF8
    $Indicators | Export-Csv -Path (Join-Path $folder ($base + "_indicators.csv"))  -NoTypeInformation -Encoding UTF8
    Set-Content -Path (Join-Path $folder ($base + "_vss_writers.txt")) -Value $VssRaw -Encoding UTF8

    return $true
  }
  catch {
    Add-Finding -Code 'BKP-ExportFailed' -Severity 'Low' `
      -Message 'Export failed.' `
      -Extra @{
        Evidence    = $_.Exception.Message
        Remediation = 'Check path permissions and disk space, then retry.'
      }
    return $false
  }
}

# -------------------- Main (structured pipeline output only) --------------------
$cfg = Get-Config -Path $ConfigJsonPath

$osInfo = Get-OsDiskInfo
if ($osInfo) {
  if ($osInfo.FreeGB -lt $cfg.MinOsFreeGB) {
    Add-Finding -Code 'BKP-OsDiskLowFree' -Severity 'High' `
      -Message ("OS disk free space is low: {0}GB of {1}GB." -f $osInfo.FreeGB, $osInfo.SizeGB) `
      -Extra @{
        Evidence    = ("Drive={0}; ThresholdGB={1}" -f $osInfo.DeviceID, $cfg.MinOsFreeGB)
        Remediation = 'Free up space or extend the volume; backups and VSS require free space.'
      }
  }
}

$vssInfo = Get-VssWriters
if (-not $vssInfo.Writers -or $vssInfo.Writers.Count -eq 0) {
  if ($cfg.TreatUnparsedVssAsFinding) {
    Add-Finding -Code 'BKP-VSSWritersUnparsed' -Severity 'Low' `
      -Message 'VSS writer output could not be parsed (permissions or unexpected output).' `
      -Extra @{
        Evidence    = ($vssInfo.Raw | Select-Object -First 1)
        Remediation = 'Run elevated; verify "vssadmin list writers" manually.'
      }
  }
}
else {
  $failed = $vssInfo.Writers | Where-Object { $_.State -match '^Failed$' }
  foreach ($w in $failed) {
    $sev = $cfg.VssFailedNoErrorSeverity
    if ($w.LastError -and $w.LastError -notmatch '^No error$') {
      $sev = $cfg.VssFailedErrorSeverity
    }
    $sev = Normalize-Severity -Severity $sev -Fallback 'Medium'

    Add-Finding -Code 'BKP-VSSWriterFailed' -Severity $sev `
      -Message ("VSS writer state is Failed: {0}" -f $w.Name) `
      -Extra @{
        Evidence    = ("State={0}; LastError={1}" -f $w.State, $w.LastError)
        Remediation = 'Check related services and Event Logs (Application/System) for VSS/VolSnap errors.'
      }
  }
}

$wsbStatus = Get-WsbStatus
if ($wsbStatus -eq 'NotInstalled') {
  Add-Finding -Code 'BKP-WSBNotInstalled' -Severity 'Info' `
    -Message 'Windows Server Backup feature is not installed (only relevant if expected).' `
    -Extra @{
      Evidence    = 'Get-WindowsFeature Windows-Server-Backup'
      Remediation = 'Install the feature or validate the third-party backup solution.'
    }
}

$fileHistoryKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\FileHistory'
$fileHistoryPresent = $false
try { $fileHistoryPresent = Test-Path -Path $fileHistoryKey } catch { $fileHistoryPresent = $false }

if (-not $fileHistoryPresent -and $wsbStatus -ne 'Installed') {
  Add-Finding -Code 'BKP-NoNativeBackupIndicator' -Severity 'Info' `
    -Message 'No clear indicator of Windows Server Backup or File History (baseline only).' `
    -Extra @{
      Evidence    = ("WSBStatus={0}; FileHistoryKeyPresent={1}" -f $wsbStatus, $fileHistoryPresent)
      Remediation = 'Confirm a backup product exists and perform a restore test.'
    }
}

$summary = [pscustomobject]@{
  ComputerName  = $env:COMPUTERNAME
  FindingsCount = $script:Findings.Count
  Timestamp     = Get-Date
}

$indicators = [pscustomobject]@{
  ComputerName       = $env:COMPUTERNAME
  OsDrive            = $env:SystemDrive
  OsFreeGB           = if ($osInfo) { $osInfo.FreeGB } else { $null }
  OsSizeGB           = if ($osInfo) { $osInfo.SizeGB } else { $null }
  VssWritersCount    = ($vssInfo.Writers | Measure-Object).Count
  WSBStatus          = $wsbStatus
  FileHistoryKeyPath = $fileHistoryKey
  FileHistoryKey     = $fileHistoryPresent

  # Keep path as provided; documentation/examples should use placeholders.
  ConfigJsonPath     = if ([string]::IsNullOrWhiteSpace($ConfigJsonPath)) { $null } else { $ConfigJsonPath }

  MinOsFreeGB        = $cfg.MinOsFreeGB
}

$result = [pscustomobject]@{
  Summary    = $summary
  Findings   = $script:Findings
  Indicators = $indicators
  VssRaw     = $vssInfo.Raw
}

if ($ExportPath) {
  $null = Invoke-Export -ExportPath $ExportPath -Summary $summary -Findings $script:Findings -Indicators $indicators -VssRaw $vssInfo.Raw

  # Refresh counts in case export added a finding.
  $summary.FindingsCount = $script:Findings.Count
  $result.Summary = $summary
  $result.Findings = $script:Findings
}

Write-ConsoleSummary -Summary $summary -Indicators $indicators -Findings $script:Findings -Config $cfg

# Structured output only (success stream / pipeline). [web:63]
# $result
