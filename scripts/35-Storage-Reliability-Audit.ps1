#requires -version 5.1
<#
.SYNOPSIS
Audits physical disks and (if available) storage reliability counters.

.DESCRIPTION
Best-practice output model (PowerShell 5.1):
- Pipeline output: structured objects only (safe for Export-Csv/ConvertTo-Json/Where-Object).
- Console output: all human-friendly formatting via Write-UiLine / Write-Information only.

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
  None by default.
  When -PassThru is used, emits a PSCustomObject v2 result with Script, Mode, Result, Findings, Summary, and Metadata properties.

.EXAMPLE
  .\35-Storage-Reliability-Audit.ps1

#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
  [string]$ExportPath,
  [string]$ConfigJsonPath,
  [switch]$PassThru,
  [switch]$NoConsole

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
Import-Module (Join-Path $script:LibPath 'Common.psm1') -Force
Import-Module (Join-Path $script:LibPath 'Console.psm1') -Force
Import-Module (Join-Path $script:LibPath 'Results.psm1') -Force
Import-Module (Join-Path $script:LibPath Serialization.psm1) -Force

Set-StrictMode -Version Latest
# v2-init
$null = $Mode, $ConfigPath, $OutputFormat, $OutputPath, $PassThru, $Strict, $Quiet, $NoColor
$script:__V2Context = @{
  Mode = $Mode
  ConfigPath = $ConfigPath
  OutputFormat = $OutputFormat
  OutputPath = $OutputPath
  PassThru = [bool]$PassThru
  Strict = [bool]$Strict
  Quiet = [bool]$Quiet
  NoColor = [bool]$NoColor
}
if ($PSBoundParameters.ContainsKey('Mode')) {
  if (Get-Variable -Name Remediate -ErrorAction SilentlyContinue) {
    Set-Variable -Name Remediate -Scope Script -Value ($Mode -eq 'Remediate')
  }
}
if ($Quiet) {
  $InformationPreference = 'SilentlyContinue'
  $VerbosePreference = 'SilentlyContinue'
}
if ($NoColor) {
  $script:NoColor = $true
}
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
    $raw = Get-Content -Path $Path -Raw -Encoding UTF8 -ErrorAction Stop
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
  } catch { <# best-effort: UniqueId resolution may fail #> }

  try {
    if ($null -ne $DiskRow.DeviceId -and "$($DiskRow.DeviceId)" -ne "") {
      $pd = Get-PhysicalDisk | Where-Object { $_.DeviceId -eq $DiskRow.DeviceId } | Select-Object -First 1
      if ($pd) { return $pd }
    }
  } catch { <# best-effort: DeviceId resolution may fail #> }

  try {
    if (-not [string]::IsNullOrWhiteSpace([string]$DiskRow.FriendlyName)) {
      return (Get-PhysicalDisk -FriendlyName $DiskRow.FriendlyName -ErrorAction Stop | Select-Object -First 1)
    }
  } catch { <# best-effort: FriendlyName resolution may fail #> }

  throw "Unable to resolve PhysicalDisk object for '$($DiskRow.FriendlyName)'."
}

# Ensure-Directory imported from lib/Common.psm1

function Write-ConsoleSummary {
  param(
    [Parameter(Mandatory)]$Summary,
    [Parameter(Mandatory)][object[]]$Findings,
    [Parameter(Mandatory)][object[]]$Disks,
    [Parameter(Mandatory)][object[]]$Reliability,
    [Parameter(Mandatory)]$Config
  )

  $sevOrder = @{ High = 1; Medium = 2; Low = 3; Info = 4 }

  Write-DecorativeRule -Title "Storage Reliability Audit Summary" -Color 'Gray'

  Write-UiLine -Text ("ComputerName  : {0}" -f $Summary.ComputerName) -Color 'Gray'
  Write-UiLine -Text ("Timestamp     : {0}" -f $Summary.Timestamp) -Color 'Gray'
  Write-UiLine -Text ("PhysicalDisks : {0}" -f $Summary.PhysicalDisks) -Color 'Gray'
  Write-UiLine -Text ("Reliability   : {0}" -f $Summary.ReliabilityRead) -Color 'Gray'

  $findingsColor = 'Green'
  if ($Summary.FindingsCount -gt 0) { $findingsColor = 'Yellow' }
  if (($Findings | Where-Object { $_.Severity -eq 'High' } | Measure-Object).Count -gt 0) { $findingsColor = 'Red' }

  Write-UiLine -Text ("Findings      : {0}" -f $Summary.FindingsCount) -Color $findingsColor

  if ($Findings.Count -gt 0) {
    $group = $Findings | Group-Object Severity | Sort-Object @{Expression={ $sevOrder[$_.Name] }}
    Write-BlankLine
    Write-UiLine -Text "Findings by severity" -Color 'Gray'
    Write-UiLine -Text (($group | Select-Object Name, Count | Format-Table -AutoSize | Out-String).TrimEnd()) -Color 'Gray'

    $topN = 10
    try { $topN = [int]$Config.Output.ConsoleSummaryTopFindings } catch { <# best-effort: config property cast #> $topN = 10 }
    if ($topN -lt 1) { $topN = 10 }

    $top = $Findings | Sort-Object @{Expression={ $sevOrder[$_.Severity] }}, Code | Select-Object -First $topN

    Write-BlankLine
    Write-UiLine -Text ("Top {0} findings" -f $topN) -Color 'Gray'

    foreach ($f in $top) {
      $c = Get-SeverityColor -Severity $f.Severity
      $dk = $f.DiskKey
      if ([string]::IsNullOrWhiteSpace($dk)) { $dk = '-' }
      Write-UiLine -Text ("[{0}] {1} | {2} | {3}" -f $f.Severity.ToUpper(), $f.Code, $dk, $f.Message) -Color $c
    }
  }

  $showDiskTable = $true
  try { $showDiskTable = [bool]$Config.Output.ShowDiskTable } catch { <# best-effort: config property cast #> $showDiskTable = $true }

  if ($showDiskTable -and $Disks -and $Disks.Count -gt 0) {
    Write-DecorativeRule -Title "Physical disks" -Color 'Gray'
    Write-UiLine -Text ((($Disks | Select-Object FriendlyName, MediaType, BusType, HealthStatus, OperationalStatus, Size) |
        Format-Table -AutoSize | Out-String).TrimEnd()) -Color 'Gray'
  }

  if ($Reliability -and $Reliability.Count -gt 0) {
    Write-DecorativeRule -Title "Reliability counters (sample fields)" -Color 'Gray'
    Write-UiLine -Text ((($Reliability | Select-Object FriendlyName, Temperature, Wear, UncorrectableErrors, ReadErrorsTotal, WriteErrorsTotal, PowerOnHours |
        Format-Table -AutoSize | Out-String).TrimEnd())) -Color 'Gray'
  }

  Write-BlankLine
}

# endregion Helpers

# region Main

$Findings = New-FindingsList

if (-not (Test-CmdletAvailable -Name 'Get-PhysicalDisk')) {
  Add-Finding -FindingList $Findings -Code 'STO-CmdletMissing' -Severity 'Critical' -Message 'Required cmdlet missing: Get-PhysicalDisk (Storage module/OS).' -TypeName 'StorageAudit.Finding'
  $v2Result = New-V2ResultObject -ScriptName '35-Storage-Reliability-Audit.ps1' -Mode $Mode -Result 'FAIL' -Findings @($Findings.ToArray()) -Summary @{} -Metadata @{}
  Write-ResultObject -ResultObject $v2Result -OutputFormat $OutputFormat -OutputPath $OutputPath
  if ($PassThru) { $v2Result }
  exit 1
}

$hasReliability = Test-CmdletAvailable -Name 'Get-StorageReliabilityCounter'
if (-not $hasReliability) {
  Add-Finding -Code 'STO-ReliabilityCmdletMissing' -Severity 'Info' -Message 'Get-StorageReliabilityCounter is not available (OS/stack dependent).' -TypeName 'StorageAudit.Finding'
}

$Config = Load-Config -Path $ConfigJsonPath

$script:UseWriteInformation = $false
try { $script:UseWriteInformation = [bool]$Config.Output.UseWriteInformation } catch { <# best-effort: config property may not exist #> $script:UseWriteInformation = $false }

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
      try { $tWarn = [int]$Config.Thresholds.TemperatureWarnC } catch { <# best-effort: config threshold cast #> }
      try { $tHigh = [int]$Config.Thresholds.TemperatureHighC } catch { <# best-effort: config threshold cast #> }
      if ($tHigh -lt $tWarn) { $tHigh = $tWarn + 10 }

      $thrUnc = 1; $thrRead = 1; $thrWrite = 1; $wearWarn = 20
      try { $thrUnc   = [int]$Config.Thresholds.UncorrectableErrorsHigh } catch { <# best-effort: config threshold cast #> $thrUnc = 1 }
      try { $thrRead  = [int]$Config.Thresholds.ReadErrorsWarn } catch { <# best-effort: config threshold cast #> $thrRead = 1 }
      try { $thrWrite = [int]$Config.Thresholds.WriteErrorsWarn } catch { <# best-effort: config threshold cast #> $thrWrite = 1 }
      try { $wearWarn = [int]$Config.Thresholds.WearWarnPercentRemaining } catch { <# best-effort: config threshold cast #> $wearWarn = 20 }

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
  Ensure-Directory -Path $folder

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

# V2 output contract
$resultToken = if ($Strict -and $Findings.Count -gt 0) { 'FAIL' } elseif ($Findings.Count -gt 0) { 'WARN' } else { 'OK' }
$v2Result = New-V2ResultObject -ScriptName '35-Storage-Reliability-Audit.ps1' -Mode $Mode -Result $resultToken -Findings @($Findings.ToArray()) -Summary $summary -Metadata @{ Disks = @($disks); Reliability = @($rel); Config = $Config }
Write-ResultObject -ResultObject $v2Result -OutputFormat $OutputFormat -OutputPath $OutputPath
if ($PassThru) { $v2Result }

# endregion Main
exit 0
