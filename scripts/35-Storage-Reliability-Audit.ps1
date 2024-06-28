#requires -version 5.1
<#
.SYNOPSIS
Audits physical disks and (if available) storage reliability counters.

.DESCRIPTION
Best-practice output model (PowerShell 5.1):
- Pipeline output: structured objects only (safe for Export-Csv/ConvertTo-Json/Where-Object).
- Console output: all human-friendly formatting via Write-Host / Write-Information only.

Features:
- Lists PhysicalDisks (status, media, size, bus, identifiers).
- Optionally reads reliability counters (controller/stack dependent).
- Generates findings (health not healthy, operational not OK, counter issues).
- Optional CSV export.
- Optional JSON-driven thresholds; safe defaults if JSON is missing/invalid.
- Pretty, colorized console summary at the end.

.PARAMETER ExportPath
Optional: Base path/filename for CSV export (suffixes: _summary/_findings/_disks/_reliability).

.PARAMETER ConfigJsonPath
Optional: JSON config path (placeholder: "PATH/TO/JSON/storage-audit.json").

.PARAMETER PassThru
If set, writes a single structured result object to the pipeline.

.PARAMETER NoConsole
If set, suppresses console summary output.

.NOTES
Windows PowerShell 5.1 compatible (no ternary operator; avoid List+@() binder edge cases).
.EXAMPLE
  .\35-Storage-Reliability-Audit.ps1

#>

[CmdletBinding()]
param(
  [string]$ExportPath,
  [string]$ConfigJsonPath = "PATH/TO/JSON/storage-audit.json",
  [switch]$PassThru,
  [switch]$NoConsole
)

$script:LibPath = Join-Path $PSScriptRoot 'lib'
Import-Module (Join-Path $script:LibPath 'Results.psm1') -Force

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# region Helpers

function Test-CmdletAvailable {
  param([Parameter(Mandatory)][string]$Name)
  return [bool](Get-Command -Name $Name -ErrorAction SilentlyContinue)
}

function New-DefaultConfig {
  # Conservative defaults to reduce false positives.
  [pscustomobject]@{
    Thresholds = [pscustomobject]@{
      TemperatureWarnC          = 55
      TemperatureHighC          = 65
      WearWarnPercentRemaining  = 20
      UncorrectableErrorsHigh   = 1
      ReadErrorsWarn            = 1
      WriteErrorsWarn           = 1
    }
    Output = [pscustomobject]@{
      ConsoleSummaryTopFindings = 10
      ShowDiskTable             = $true
      UseWriteInformation        = $false
    }
  }
}


function Get-DiskKey {
  param([Parameter(Mandatory)]$Disk)

  if (-not [string]::IsNullOrWhiteSpace([string]$Disk.UniqueId))     { return "UniqueId:$($Disk.UniqueId)" }
  if ($null -ne $Disk.DeviceId -and "$($Disk.DeviceId)" -ne "")     { return "DeviceId:$($Disk.DeviceId)" }
  if (-not [string]::IsNullOrWhiteSpace([string]$Disk.SerialNumber)) { return "Serial:$($Disk.SerialNumber)" }
  return "Name:$($Disk.FriendlyName)"
}

function Load-Config {
  param([string]$Path)

  $cfg = New-DefaultConfig

  $pathDisplay = $Path
  if ([string]::IsNullOrWhiteSpace($pathDisplay)) { $pathDisplay = "<empty>" }

  if ([string]::IsNullOrWhiteSpace($Path) -or -not (Test-Path -Path $Path -PathType Leaf)) {
    Add-Finding -Code 'CFG-NotFound' -Severity 'Info' -Message ("Config JSON not found; using defaults. Path='{0}'." -f $pathDisplay) -TypeName 'StorageAudit.Finding'
    return $cfg
  }

  try {
    # ConvertFrom-Json can throw terminating errors; always use try/catch in PS 5.1.
    $raw = Get-Content -Path $Path -Raw -ErrorAction Stop
    $userCfg = $raw | ConvertFrom-Json

    if ($null -ne $userCfg.Thresholds) {
      foreach ($p in @('TemperatureWarnC','TemperatureHighC','WearWarnPercentRemaining','UncorrectableErrorsHigh','ReadErrorsWarn','WriteErrorsWarn')) {
        if ($null -ne $userCfg.Thresholds.$p) { $cfg.Thresholds.$p = $userCfg.Thresholds.$p }
      }
    }

    if ($null -ne $userCfg.Output) {
      foreach ($p in @('ConsoleSummaryTopFindings','ShowDiskTable','UseWriteInformation')) {
        if ($null -ne $userCfg.Output.$p) { $cfg.Output.$p = $userCfg.Output.$p }
      }
    }

    return $cfg
  }
  catch {
    Add-Finding -Code 'CFG-InvalidJson' -Severity 'Info' -Message ("Config JSON invalid/unreadable; using defaults. Path='{0}'. Error='{1}'." -f $Path, $_.Exception.Message) -TypeName 'StorageAudit.Finding'
    return $cfg
  }
}

function Resolve-PhysicalDisk {
  param([Parameter(Mandatory)][pscustomobject]$DiskRow)

  # DiskRow is projected; resolve to MSFT_PhysicalDisk for cmdlet parameter binding.
  try {
    if (-not [string]::IsNullOrWhiteSpace([string]$DiskRow.UniqueId)) {
      return Get-PhysicalDisk -UniqueId $DiskRow.UniqueId -ErrorAction Stop
    }
  } catch { }

  try {
    if ($null -ne $DiskRow.DeviceId -and "$($DiskRow.DeviceId)" -ne "") {
      $pd = Get-PhysicalDisk | Where-Object { $_.DeviceId -eq $DiskRow.DeviceId } | Select-Object -First 1
      if ($pd) { return $pd }
    }
  } catch { }

  try {
    if (-not [string]::IsNullOrWhiteSpace([string]$DiskRow.FriendlyName)) {
      return (Get-PhysicalDisk -FriendlyName $DiskRow.FriendlyName -ErrorAction Stop | Select-Object -First 1)
    }
  } catch { }

  throw "Unable to resolve PhysicalDisk object for '$($DiskRow.FriendlyName)'."
}

function Ensure-Folder {
  param([Parameter(Mandatory)][string]$Path)
  if (-not (Test-Path -Path $Path)) {
    New-Item -Path $Path -ItemType Directory -Force | Out-Null
  }
}

function Get-SeverityColor {
  param([Parameter(Mandatory)][ValidateSet('Info','Low','Medium','High')][string]$Severity)
  switch ($Severity) {
    'High'   { 'Red' }
    'Medium' { 'Yellow' }
    'Low'    { 'Cyan' }
    'Info'   { 'DarkGray' }
  }
}

function Write-Ui {
  param(
    [AllowEmptyString()][string]$Text,
    [ConsoleColor]$Color,
    [switch]$BlankLine
  )

  if ($BlankLine) {
    if ($script:UseWriteInformation) {
      Write-Information -MessageData "" -InformationAction Continue
    } else {
      Write-Host ""
    }
  }

  if ($PSBoundParameters.ContainsKey('Text')) {
    if ($script:UseWriteInformation) {
      Write-Information -MessageData $Text -InformationAction Continue
    } else {
      if ($PSBoundParameters.ContainsKey('Color')) {
        Write-Host $Text -ForegroundColor $Color
      } else {
        Write-Host $Text
      }
    }
  }
}

function Write-Rule {
  param(
    [Parameter(Mandatory)][string]$Title,
    [ConsoleColor]$Color = 'Gray'
  )
  $line = ('=' * 78)
  Write-Ui -BlankLine
  Write-Ui -Text $line -Color $Color
  Write-Ui -Text ("{0}" -f $Title) -Color $Color
  Write-Ui -Text $line -Color $Color
}

function Write-ConsoleSummary {
  param(
    [Parameter(Mandatory)]$Summary,
    [Parameter(Mandatory)][object[]]$Findings,
    [Parameter(Mandatory)][object[]]$Disks,
    [Parameter(Mandatory)][object[]]$Reliability,
    [Parameter(Mandatory)]$Config
  )

  $sevOrder = @{ High = 1; Medium = 2; Low = 3; Info = 4 }

  Write-Rule -Title "Storage Reliability Audit Summary" -Color 'Gray'

  Write-Ui -Text ("ComputerName  : {0}" -f $Summary.ComputerName) -Color 'Gray'
  Write-Ui -Text ("Timestamp     : {0}" -f $Summary.Timestamp) -Color 'Gray'
  Write-Ui -Text ("PhysicalDisks : {0}" -f $Summary.PhysicalDisks) -Color 'Gray'
  Write-Ui -Text ("Reliability   : {0}" -f $Summary.ReliabilityRead) -Color 'Gray'

  $findingsColor = 'Green'
  if ($Summary.FindingsCount -gt 0) { $findingsColor = 'Yellow' }
  if (($Findings | Where-Object { $_.Severity -eq 'High' } | Measure-Object).Count -gt 0) { $findingsColor = 'Red' }

  Write-Ui -Text ("Findings      : {0}" -f $Summary.FindingsCount) -Color $findingsColor

  if ($Findings.Count -gt 0) {
    $group = $Findings | Group-Object Severity | Sort-Object @{Expression={ $sevOrder[$_.Name] }}
    Write-Ui -BlankLine
    Write-Ui -Text "Findings by severity" -Color 'Gray'
    Write-Ui -Text (($group | Select-Object Name, Count | Format-Table -AutoSize | Out-String).TrimEnd()) -Color 'Gray'

    $topN = 10
    try { $topN = [int]$Config.Output.ConsoleSummaryTopFindings } catch { $topN = 10 }
    if ($topN -lt 1) { $topN = 10 }

    $top = $Findings | Sort-Object @{Expression={ $sevOrder[$_.Severity] }}, Code | Select-Object -First $topN

    Write-Ui -BlankLine
    Write-Ui -Text ("Top {0} findings" -f $topN) -Color 'Gray'

    foreach ($f in $top) {
      $c = Get-SeverityColor -Severity $f.Severity
      $dk = $f.DiskKey
      if ([string]::IsNullOrWhiteSpace($dk)) { $dk = '-' }
      Write-Ui -Text ("[{0}] {1} | {2} | {3}" -f $f.Severity.ToUpper(), $f.Code, $dk, $f.Message) -Color $c
    }
  }

  $showDiskTable = $true
  try { $showDiskTable = [bool]$Config.Output.ShowDiskTable } catch { $showDiskTable = $true }

  if ($showDiskTable -and $Disks -and $Disks.Count -gt 0) {
    Write-Rule -Title "Physical disks" -Color 'Gray'
    Write-Ui -Text ((($Disks | Select-Object FriendlyName, MediaType, BusType, HealthStatus, OperationalStatus, Size) |
        Format-Table -AutoSize | Out-String).TrimEnd()) -Color 'Gray'
  }

  if ($Reliability -and $Reliability.Count -gt 0) {
    Write-Rule -Title "Reliability counters (sample fields)" -Color 'Gray'
    Write-Ui -Text ((($Reliability | Select-Object FriendlyName, Temperature, Wear, UncorrectableErrors, ReadErrorsTotal, WriteErrorsTotal, PowerOnHours |
        Format-Table -AutoSize | Out-String).TrimEnd())) -Color 'Gray'
  }

  Write-Ui -BlankLine
}

# endregion Helpers

# region Main

$Findings = New-FindingsList

if (-not (Test-CmdletAvailable -Name 'Get-PhysicalDisk')) {
  throw "Required cmdlet missing: Get-PhysicalDisk (Storage module/OS)."
}

$hasReliability = Test-CmdletAvailable -Name 'Get-StorageReliabilityCounter'
if (-not $hasReliability) {
  Add-Finding -Code 'STO-ReliabilityCmdletMissing' -Severity 'Info' -Message 'Get-StorageReliabilityCounter is not available (OS/stack dependent).' -TypeName 'StorageAudit.Finding'
}

$Config = Load-Config -Path $ConfigJsonPath

$script:UseWriteInformation = $false
try { $script:UseWriteInformation = [bool]$Config.Output.UseWriteInformation } catch { $script:UseWriteInformation = $false }

$disks = Get-PhysicalDisk | Select-Object `
  FriendlyName, SerialNumber, UniqueId, DeviceId, MediaType, Size, HealthStatus, OperationalStatus, BusType

foreach ($d in $disks) {
  $diskKey = Get-DiskKey -Disk $d

  if ($null -ne $d.HealthStatus -and $d.HealthStatus -ne 'Healthy') {
    Add-Finding -Code 'STO-HealthNotHealthy' -Severity 'High' -Message ("Disk HealthStatus={0}." -f $d.HealthStatus) -TypeName 'StorageAudit.Finding' -Extra @{ DiskKey = $diskKey }
  }

  $op = @($d.OperationalStatus)
  if ($op.Count -gt 0 -and ($op -notcontains 'OK')) {
    Add-Finding -Code 'STO-OperationalNotOK' -Severity 'High' -Message ("Disk OperationalStatus={0}." -f ($op -join ',')) -TypeName 'StorageAudit.Finding' -Extra @{ DiskKey = $diskKey }
  }

  if ([string]::IsNullOrWhiteSpace([string]$d.SerialNumber)) {
    Add-Finding -Code 'STO-SerialMissing' -Severity 'Low' -Message 'Disk SerialNumber is empty (provider/controller dependent).' -TypeName 'StorageAudit.Finding' -Extra @{ DiskKey = $diskKey }
  }
}

$rel = @()
if ($hasReliability) {
  foreach ($d in $disks) {
    $diskKey = Get-DiskKey -Disk $d

    try {
      $pd = Resolve-PhysicalDisk -DiskRow $d
      $r = $pd | Get-StorageReliabilityCounter -ErrorAction Stop

      $rel += ($r | Select-Object `
        @{ n = 'PSTypeName'   ; e = { 'StorageAudit.Reliability' } }, `
        @{ n = 'FriendlyName' ; e = { $d.FriendlyName } }, `
        @{ n = 'SerialNumber' ; e = { $d.SerialNumber } }, `
        @{ n = 'UniqueId'     ; e = { $d.UniqueId } }, `
        @{ n = 'DeviceId'     ; e = { $d.DeviceId } }, `
        Wear, Temperature, ReadErrorsTotal, WriteErrorsTotal, UncorrectableErrors, PowerOnHours, StartStopCount)

      # Thresholds (robust parsing)
      $tWarn = 55; $tHigh = 65
      try { $tWarn = [int]$Config.Thresholds.TemperatureWarnC } catch { }
      try { $tHigh = [int]$Config.Thresholds.TemperatureHighC } catch { }
      if ($tHigh -lt $tWarn) { $tHigh = $tWarn + 10 }

      $thrUnc = 1; $thrRead = 1; $thrWrite = 1; $wearWarn = 20
      try { $thrUnc   = [int]$Config.Thresholds.UncorrectableErrorsHigh } catch { $thrUnc = 1 }
      try { $thrRead  = [int]$Config.Thresholds.ReadErrorsWarn } catch { $thrRead = 1 }
      try { $thrWrite = [int]$Config.Thresholds.WriteErrorsWarn } catch { $thrWrite = 1 }
      try { $wearWarn = [int]$Config.Thresholds.WearWarnPercentRemaining } catch { $wearWarn = 20 }

      if ($thrUnc -lt 1)   { $thrUnc = 1 }
      if ($thrRead -lt 1)  { $thrRead = 1 }
      if ($thrWrite -lt 1) { $thrWrite = 1 }
      if ($wearWarn -lt 1) { $wearWarn = 20 }

      if ($null -ne $r.Temperature) {
        if ($r.Temperature -ge $tHigh) {
          Add-Finding -Code 'STO-TempHigh' -Severity 'High' -Message ("Temperature={0}C (>= {1}C)." -f $r.Temperature, $tHigh) -TypeName 'StorageAudit.Finding' -Extra @{ DiskKey = $diskKey }
        }
        elseif ($r.Temperature -ge $tWarn) {
          Add-Finding -Code 'STO-TempWarn' -Severity 'Medium' -Message ("Temperature={0}C (>= {1}C)." -f $r.Temperature, $tWarn) -TypeName 'StorageAudit.Finding' -Extra @{ DiskKey = $diskKey }
        }
      }

      if ($null -ne $r.UncorrectableErrors -and $r.UncorrectableErrors -ge $thrUnc) {
        Add-Finding -Code 'STO-UncorrectableErrors' -Severity 'High' -Message ("UncorrectableErrors={0} (>= {1})." -f $r.UncorrectableErrors, $thrUnc) -TypeName 'StorageAudit.Finding' -Extra @{ DiskKey = $diskKey }
      }

      if ($null -ne $r.ReadErrorsTotal -and $r.ReadErrorsTotal -ge $thrRead) {
        Add-Finding -Code 'STO-ReadErrors' -Severity 'Medium' -Message ("ReadErrorsTotal={0} (>= {1})." -f $r.ReadErrorsTotal, $thrRead) -TypeName 'StorageAudit.Finding' -Extra @{ DiskKey = $diskKey }
      }

      if ($null -ne $r.WriteErrorsTotal -and $r.WriteErrorsTotal -ge $thrWrite) {
        Add-Finding -Code 'STO-WriteErrors' -Severity 'Medium' -Message ("WriteErrorsTotal={0} (>= {1})." -f $r.WriteErrorsTotal, $thrWrite) -TypeName 'StorageAudit.Finding' -Extra @{ DiskKey = $diskKey }
      }

      if ($null -ne $r.Wear -and $r.Wear -le $wearWarn) {
        Add-Finding -Code 'STO-WearWarn' -Severity 'Medium' -Message ("Wear={0} (<= {1}; provider-dependent semantics)." -f $r.Wear, $wearWarn) -TypeName 'StorageAudit.Finding' -Extra @{ DiskKey = $diskKey }
      }
    }
    catch {
      Add-Finding -Code 'STO-ReliabilityUnavailable' -Severity 'Info' -Message ("ReliabilityCounter unavailable: {0}" -f $_.Exception.Message) -TypeName 'StorageAudit.Finding' -Extra @{ DiskKey = $diskKey }
    }
  }
}

$summary = [pscustomobject]@{
  PSTypeName      = 'StorageAudit.Summary'
  ComputerName    = $env:COMPUTERNAME
  PhysicalDisks   = ($disks | Measure-Object).Count
  ReliabilityRead = ($rel   | Measure-Object).Count
  FindingsCount   = $Findings.Count
  Timestamp       = Get-Date
}

if ($ExportPath) {
  $folder = Split-Path -Path $ExportPath -Parent
  if (-not $folder) { $folder = (Get-Location).Path }
  Ensure-Folder -Path $folder

  $base = [IO.Path]::GetFileNameWithoutExtension($ExportPath)

  $summary            | Export-Csv -Path (Join-Path $folder ($base + "_summary.csv"))     -NoTypeInformation -Encoding UTF8
  $Findings.ToArray() | Export-Csv -Path (Join-Path $folder ($base + "_findings.csv"))    -NoTypeInformation -Encoding UTF8
  $disks              | Export-Csv -Path (Join-Path $folder ($base + "_disks.csv"))       -NoTypeInformation -Encoding UTF8
  $rel                | Export-Csv -Path (Join-Path $folder ($base + "_reliability.csv")) -NoTypeInformation -Encoding UTF8
}

if (-not $NoConsole) {
  Write-ConsoleSummary `
    -Summary $summary `
    -Findings ($Findings.ToArray()) `
    -Disks @($disks) `
    -Reliability @($rel) `
    -Config $Config
}

if ($PassThru) {
  [pscustomobject]@{
    PSTypeName  = 'StorageAudit.Result'
    Summary     = $summary
    Findings    = $Findings.ToArray()
    Disks       = @($disks)
    Reliability = @($rel)
    Config      = $Config
  }
}

# endregion Main
