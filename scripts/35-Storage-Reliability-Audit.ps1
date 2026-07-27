#requires -version 5.1
<#
.SYNOPSIS
Audits physical disks and (if available) storage reliability counters.

.DESCRIPTION
Best-practice output model (PowerShell 5.1):
- Pipeline output: structured objects only (safe for Export-Csv/ConvertTo-Json/Where-Object).
- Console output: all formatting uses Write-UiLine / Write-Information only.

Features:
- Lists PhysicalDisks (status, media, size, bus, identifiers).
- Optionally reads reliability counters (controller/stack dependent).
- Generates findings (health not healthy, operational not OK, counter issues).
- Optional CSV export.
- Optional JSON-driven thresholds; safe defaults if JSON is missing/invalid.
- A colorized console summary at the end.

.PARAMETER ExportPath
Optional: Base path/filename for CSV export (suffixes: _summary/_findings/_disks/_reliability).

.PARAMETER ConfigJsonPath
Optional: JSON config path supplied with $ConfigJsonPath.

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
Import-Module (Join-Path $script:LibPath 'Common.psm1') -Force -DisableNameChecking
Import-Module (Join-Path $script:LibPath 'Console.psm1') -Force
Import-Module (Join-Path $script:LibPath 'Results.psm1') -Force
Import-Module (Join-Path $script:LibPath Serialization.psm1) -Force

Set-StrictMode -Version Latest
# v2-init (migrated to Initialize-V2Context)
$script:__V2Context = Initialize-V2Context -ScriptName '35-Storage-Reliability-Audit.ps1' -BoundParameters $PSBoundParameters `
  -Mode $Mode -ConfigPath $ConfigPath -OutputFormat $OutputFormat -OutputPath $OutputPath `
  -PassThru:$PassThru -Strict:$Strict -Quiet:$Quiet -NoColor:$NoColor
if ($script:__V2Context.Quiet) { $InformationPreference = 'SilentlyContinue'; $VerbosePreference = 'SilentlyContinue' }
$script:NoColor = [bool]$script:__V2Context.NoColor
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
  $unsupportedResult = if ($Strict) { 'FAIL' } else { 'WARN' }
  $result = Get-V2ResultObject -ScriptName '35-Storage-Reliability-Audit.ps1' -Mode $Mode -Result $unsupportedResult -Findings @() -Summary $summary -Metadata @{ UnsupportedHost = $true }
  Write-ResultObject -ResultObject $result -OutputFormat $OutputFormat -OutputPath $OutputPath
  if ($PassThru) { $result }
  exit (Get-V2ExitCode -Result $unsupportedResult)
}

# region Helpers

function Test-CmdletAvailable {
  param([Parameter(Mandatory)][string]$Name)
  return [bool](Get-Command -Name $Name -ErrorAction SilentlyContinue)
}

function Get-DefaultConfig {
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

  $cfg = Get-DefaultConfig

  $pathDisplay = $Path
  if ([string]::IsNullOrWhiteSpace($pathDisplay)) { $pathDisplay = "<empty>" }

  if ([string]::IsNullOrWhiteSpace($Path) -or -not (Test-Path -Path $Path -PathType Leaf)) {
    Add-Finding -FindingList $Findings -Code 'CFG-NotFound' -Severity 'Info' -Message ("Config JSON not found; using defaults. Path='{0}'." -f $pathDisplay) -TypeName 'StorageAudit.Finding'
    return $cfg
  }

  try {
    # ConvertFrom-Json can throw terminating errors; always use try/catch in PS 5.1.
    $raw = Get-BoundedUtf8FileContent -Path $Path -MaximumBytes 1048576
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
    Add-Finding -FindingList $Findings -Code 'CFG-InvalidJson' -Severity 'Info' -Message ("Config JSON invalid/unreadable; using defaults. Path='{0}'. Error='{1}'." -f $Path, $_.Exception.Message) -TypeName 'StorageAudit.Finding'
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
  } catch {
    Write-Verbose ("Physical disk UniqueId resolution failed for '{0}': {1}" -f $DiskRow.UniqueId,$_.Exception.Message)
  }

  try {
    if ($null -ne $DiskRow.DeviceId -and "$($DiskRow.DeviceId)" -ne "") {
      $pd = Get-PhysicalDisk | Where-Object { $_.DeviceId -eq $DiskRow.DeviceId } | Select-Object -First 1
      if ($pd) { return $pd }
    }
  } catch {
    Write-Verbose ("Physical disk DeviceId resolution failed for '{0}': {1}" -f $DiskRow.DeviceId,$_.Exception.Message)
  }

  try {
    if (-not [string]::IsNullOrWhiteSpace([string]$DiskRow.FriendlyName)) {
      return (Get-PhysicalDisk -FriendlyName $DiskRow.FriendlyName -ErrorAction Stop | Select-Object -First 1)
    }
  } catch {
    Write-Verbose ("Physical disk FriendlyName resolution failed for '{0}': {1}" -f $DiskRow.FriendlyName,$_.Exception.Message)
  }

  throw "Unable to resolve PhysicalDisk object for '$($DiskRow.FriendlyName)'."
}

# Ensure-Directory imported from lib/Common.psm1

# endregion Helpers

# region Main

$Findings = Get-FindingsList

if (-not (Test-CmdletAvailable -Name 'Get-PhysicalDisk')) {
  Add-Finding -FindingList $Findings -Code 'STO-CmdletMissing' -Severity 'Critical' -Message 'Required cmdlet missing: Get-PhysicalDisk (Storage module/OS).' -TypeName 'StorageAudit.Finding'
  $v2Result = Get-V2ResultObject -ScriptName '35-Storage-Reliability-Audit.ps1' -Mode $Mode -Result 'FAIL' -Findings (ConvertTo-ObjectArray -InputObject $Findings.ToArray()) -Summary @{} -Metadata @{}
  Write-ResultObject -ResultObject $v2Result -OutputFormat $OutputFormat -OutputPath $OutputPath
  if ($PassThru) { $v2Result }
  exit (Get-V2ExitCode -Result 'FAIL')
}

$hasReliability = Test-CmdletAvailable -Name 'Get-StorageReliabilityCounter'
if (-not $hasReliability) {
  Add-Finding -FindingList $Findings -Code 'STO-ReliabilityCmdletMissing' -Severity 'Info' -Message 'Get-StorageReliabilityCounter is not available (OS/stack dependent).' -TypeName 'StorageAudit.Finding'
}

$Config = Load-Config -Path $ConfigJsonPath

$script:UseWriteInformation = $false
try { $script:UseWriteInformation = [bool]$Config.Output.UseWriteInformation } catch {
  Write-Verbose ("Storage output config read failed: {0}" -f $_.Exception.Message)
  $script:UseWriteInformation = $false
}

$disks = Get-PhysicalDisk | Select-Object `
  FriendlyName, SerialNumber, UniqueId, DeviceId, MediaType, Size, HealthStatus, OperationalStatus, BusType

foreach ($d in $disks) {
  $diskKey = Get-DiskKey -Disk $d

  if ($null -ne $d.HealthStatus -and $d.HealthStatus -ne 'Healthy') {
    Add-Finding -FindingList $Findings -Code 'STO-HealthNotHealthy' -Severity 'High' -Message ("Disk HealthStatus={0}." -f $d.HealthStatus) -TypeName 'StorageAudit.Finding' -Extra @{ DiskKey = $diskKey }
  }

  $op = @($d.OperationalStatus)
  if ($op.Count -gt 0 -and ($op -notcontains 'OK')) {
    Add-Finding -FindingList $Findings -Code 'STO-OperationalNotOK' -Severity 'High' -Message ("Disk OperationalStatus={0}." -f ($op -join ',')) -TypeName 'StorageAudit.Finding' -Extra @{ DiskKey = $diskKey }
  }

  if ([string]::IsNullOrWhiteSpace([string]$d.SerialNumber)) {
    Add-Finding -FindingList $Findings -Code 'STO-SerialMissing' -Severity 'Low' -Message 'Disk SerialNumber is empty (provider/controller dependent).' -TypeName 'StorageAudit.Finding' -Extra @{ DiskKey = $diskKey }
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

      # Thresholds (defensive parsing)
      $tWarn = 55; $tHigh = 65
      try { $tWarn = [int]$Config.Thresholds.TemperatureWarnC } catch {
        Write-Verbose ("TemperatureWarnC threshold cast failed: {0}" -f $_.Exception.Message)
      }
      try { $tHigh = [int]$Config.Thresholds.TemperatureHighC } catch {
        Write-Verbose ("TemperatureHighC threshold cast failed: {0}" -f $_.Exception.Message)
      }
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
          Add-Finding -FindingList $Findings -Code 'STO-TempHigh' -Severity 'High' -Message ("Temperature={0}C (>= {1}C)." -f $r.Temperature, $tHigh) -TypeName 'StorageAudit.Finding' -Extra @{ DiskKey = $diskKey }
        }
        elseif ($r.Temperature -ge $tWarn) {
          Add-Finding -FindingList $Findings -Code 'STO-TempWarn' -Severity 'Medium' -Message ("Temperature={0}C (>= {1}C)." -f $r.Temperature, $tWarn) -TypeName 'StorageAudit.Finding' -Extra @{ DiskKey = $diskKey }
        }
      }

      if ($null -ne $r.UncorrectableErrors -and $r.UncorrectableErrors -ge $thrUnc) {
        Add-Finding -FindingList $Findings -Code 'STO-UncorrectableErrors' -Severity 'High' -Message ("UncorrectableErrors={0} (>= {1})." -f $r.UncorrectableErrors, $thrUnc) -TypeName 'StorageAudit.Finding' -Extra @{ DiskKey = $diskKey }
      }

      if ($null -ne $r.ReadErrorsTotal -and $r.ReadErrorsTotal -ge $thrRead) {
        Add-Finding -FindingList $Findings -Code 'STO-ReadErrors' -Severity 'Medium' -Message ("ReadErrorsTotal={0} (>= {1})." -f $r.ReadErrorsTotal, $thrRead) -TypeName 'StorageAudit.Finding' -Extra @{ DiskKey = $diskKey }
      }

      if ($null -ne $r.WriteErrorsTotal -and $r.WriteErrorsTotal -ge $thrWrite) {
        Add-Finding -FindingList $Findings -Code 'STO-WriteErrors' -Severity 'Medium' -Message ("WriteErrorsTotal={0} (>= {1})." -f $r.WriteErrorsTotal, $thrWrite) -TypeName 'StorageAudit.Finding' -Extra @{ DiskKey = $diskKey }
      }

      if ($null -ne $r.Wear -and $r.Wear -le $wearWarn) {
        Add-Finding -FindingList $Findings -Code 'STO-WearWarn' -Severity 'Medium' -Message ("Wear={0} (<= {1}; provider-dependent semantics)." -f $r.Wear, $wearWarn) -TypeName 'StorageAudit.Finding' -Extra @{ DiskKey = $diskKey }
      }
    }
    catch {
      Add-Finding -FindingList $Findings -Code 'STO-ReliabilityUnavailable' -Severity 'Info' -Message ("ReliabilityCounter unavailable: {0}" -f $_.Exception.Message) -TypeName 'StorageAudit.Finding' -Extra @{ DiskKey = $diskKey }
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
  [void](Ensure-Directory -Path $folder)

  $base = [IO.Path]::GetFileNameWithoutExtension($ExportPath)

  $summary            | Export-Csv -Path (Join-Path $folder ($base + "_summary.csv"))     -NoTypeInformation -Encoding UTF8
  $Findings.ToArray() | Export-Csv -Path (Join-Path $folder ($base + "_findings.csv"))    -NoTypeInformation -Encoding UTF8
  $disks              | Export-Csv -Path (Join-Path $folder ($base + "_disks.csv"))       -NoTypeInformation -Encoding UTF8
  $rel                | Export-Csv -Path (Join-Path $folder ($base + "_reliability.csv")) -NoTypeInformation -Encoding UTF8
}

if (-not $NoConsole) {
  $findingsAL = ConvertTo-ArrayList -InputObject $Findings.ToArray()
  Write-ConsoleSummary -Summary $summary -Findings $findingsAL `
    -CustomFields ([ordered]@{
      PhysicalDisks   = $summary.PhysicalDisks
      ReliabilityRead = $summary.ReliabilityRead
    })
  # Disk table
  $showDiskTable = $true
  try { $showDiskTable = [bool]$Config.Output.ShowDiskTable } catch { <# best-effort: config property cast #> $showDiskTable = $true }
  if ($showDiskTable -and $disks -and @($disks).Count -gt 0) {
    Write-DecorativeRule -Title "Physical disks" -Color 'Gray'
    Write-UiLine -Text (((@($disks) | Select-Object FriendlyName, MediaType, BusType, HealthStatus, OperationalStatus, Size) |
        Format-Table -AutoSize | Out-String).TrimEnd()) -Color 'Gray'
  }
  # Reliability counters
  if ($rel -and @($rel).Count -gt 0) {
    Write-DecorativeRule -Title "Reliability counters (sample fields)" -Color 'Gray'
    Write-UiLine -Text (((@($rel) | Select-Object FriendlyName, Temperature, Wear, UncorrectableErrors, ReadErrorsTotal, WriteErrorsTotal, PowerOnHours |
        Format-Table -AutoSize | Out-String).TrimEnd())) -Color 'Gray'
  }
}

# V2 output contract
$resultToken = if ($Strict -and $Findings.Count -gt 0) { 'FAIL' } elseif ($Findings.Count -gt 0) { 'WARN' } else { 'OK' }
$v2Result = Get-V2ResultObject -ScriptName '35-Storage-Reliability-Audit.ps1' -Mode $Mode -Result $resultToken -Findings (ConvertTo-ObjectArray -InputObject $Findings.ToArray()) -Summary $summary -Metadata @{ Disks = @($disks); Reliability = @($rel); Config = $Config }
Write-ResultObject -ResultObject $v2Result -OutputFormat $OutputFormat -OutputPath $OutputPath
if ($PassThru) { $v2Result }

# endregion Main
exit (Get-V2ExitCode -Result $resultToken)
