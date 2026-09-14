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
$script:__V2Context = Initialize-V2Context -ScriptName '35-Storage-Reliability-Audit.ps1' -BoundParameters $PSBoundParameters `
  -Values @{ Mode = $Mode; ConfigPath = $ConfigPath; OutputFormat = $OutputFormat; OutputPath = $OutputPath; PassThru = $PassThru; Strict = $Strict; Quiet = $Quiet; NoColor = $NoColor; DeriveRemediate = $false }
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

  if ((Test-AnyCondition -Conditions @({ [string]::IsNullOrWhiteSpace($Path) }, { -not (Test-Path -Path $Path -PathType Leaf) }))) {
    Add-Finding -FindingList $Findings -Code 'CFG-NotFound' -Severity 'Info' -Message ("Config JSON not found; using defaults. Path='{0}'." -f $pathDisplay) -TypeName 'StorageAudit.Finding'
    return $cfg
  }

  try {
    # ConvertFrom-Json can throw terminating errors; always use try/catch in PS 5.1.
    $raw = Get-BoundedUtf8FileContent -Path $Path -MaximumBytes 1048576
    $userCfg = $raw | ConvertFrom-Json

    Merge-StorageConfigSection -Target $cfg.Thresholds -Source $userCfg.Thresholds -Names @('TemperatureWarnC','TemperatureHighC','WearWarnPercentRemaining','UncorrectableErrorsHigh','ReadErrorsWarn','WriteErrorsWarn')
    Merge-StorageConfigSection -Target $cfg.Output -Source $userCfg.Output -Names @('ConsoleSummaryTopFindings','ShowDiskTable','UseWriteInformation')

    return $cfg
  }
  catch {
    Add-Finding -FindingList $Findings -Code 'CFG-InvalidJson' -Severity 'Info' -Message ("Config JSON invalid/unreadable; using defaults. Path='{0}'. Error='{1}'." -f $Path, $_.Exception.Message) -TypeName 'StorageAudit.Finding'
    return $cfg
  }
}
function Merge-StorageConfigSection {
  param($Target, [AllowNull()]$Source, [string[]]$Names)
  if ($null -eq $Source) { return }
  foreach ($name in $Names) {
    $property = $Source.PSObject.Properties[$name]
    if ($null -ne $property) { $Target.$name = $property.Value }
  }
}

function Resolve-PhysicalDisk {
  param([Parameter(Mandatory)][pscustomobject]$DiskRow)

  # DiskRow is projected; resolve to MSFT_PhysicalDisk for cmdlet parameter binding.
  $disk = Find-PhysicalDiskByUniqueId -DiskRow $DiskRow
  if ($disk) { return $disk }
  $disk = Find-PhysicalDiskByDeviceId -DiskRow $DiskRow
  if ($disk) { return $disk }
  $disk = Find-PhysicalDiskByFriendlyName -DiskRow $DiskRow
  if ($disk) { return $disk }
  throw "Unable to resolve PhysicalDisk object for '$($DiskRow.FriendlyName)'."
}
function Find-PhysicalDiskByUniqueId {
  param($DiskRow)
  if ([string]::IsNullOrWhiteSpace([string]$DiskRow.UniqueId)) { return $null }
  try { return Get-PhysicalDisk -UniqueId $DiskRow.UniqueId -ErrorAction Stop }
  catch { Write-Verbose ("Physical disk UniqueId resolution failed for '{0}': {1}" -f $DiskRow.UniqueId,$_.Exception.Message); return $null }
}
function Find-PhysicalDiskByDeviceId {
  param($DiskRow)
  if ($null -eq $DiskRow.DeviceId -or "$($DiskRow.DeviceId)" -eq '') { return $null }
  try { return Get-PhysicalDisk | Where-Object { $_.DeviceId -eq $DiskRow.DeviceId } | Select-Object -First 1 }
  catch { Write-Verbose ("Physical disk DeviceId resolution failed for '{0}': {1}" -f $DiskRow.DeviceId,$_.Exception.Message); return $null }
}
function Find-PhysicalDiskByFriendlyName {
  param($DiskRow)
  if ([string]::IsNullOrWhiteSpace([string]$DiskRow.FriendlyName)) { return $null }
  try { return Get-PhysicalDisk -FriendlyName $DiskRow.FriendlyName -ErrorAction Stop | Select-Object -First 1 }
  catch { Write-Verbose ("Physical disk FriendlyName resolution failed for '{0}': {1}" -f $DiskRow.FriendlyName,$_.Exception.Message); return $null }
}

# Ensure-Directory imported from lib/Common.psm1

# endregion Helpers

# region Main

function Invoke-Capability35MainPhase01 {
  param([hashtable]$RunState)
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

  $RunState.disks = Get-PhysicalDisk | Select-Object `
    FriendlyName, SerialNumber, UniqueId, DeviceId, MediaType, Size, HealthStatus, OperationalStatus, BusType
}
function Invoke-Capability35MainPhase02 {
  param([hashtable]$RunState)
  foreach ($d in $RunState.disks) {
    $RunState.diskKey = Get-DiskKey -Disk $d

    if ($null -ne $d.HealthStatus -and $d.HealthStatus -ne 'Healthy') {
      Add-Finding -FindingList $Findings -Code 'STO-HealthNotHealthy' -Severity 'High' -Message ("Disk HealthStatus={0}." -f $d.HealthStatus) -TypeName 'StorageAudit.Finding' -Extra @{ DiskKey = $RunState.diskKey }
    }

    $op = @($d.OperationalStatus)
    if ($op.Count -gt 0 -and ($op -notcontains 'OK')) {
      Add-Finding -FindingList $Findings -Code 'STO-OperationalNotOK' -Severity 'High' -Message ("Disk OperationalStatus={0}." -f ($op -join ',')) -TypeName 'StorageAudit.Finding' -Extra @{ DiskKey = $RunState.diskKey }
    }

    if ([string]::IsNullOrWhiteSpace([string]$d.SerialNumber)) {
      Add-Finding -FindingList $Findings -Code 'STO-SerialMissing' -Severity 'Low' -Message 'Disk SerialNumber is empty (provider/controller dependent).' -TypeName 'StorageAudit.Finding' -Extra @{ DiskKey = $RunState.diskKey }
    }
  }
}
function Invoke-Capability35MainPhase03 {
  param([hashtable]$RunState)
  $RunState.rel = @()
}
function Invoke-Capability35MainPhase04Step01 {
  param([hashtable]$RunState)
$RunState.diskKey = Get-DiskKey -Disk $d
}

function Invoke-Capability35MainPhase04Step02Stage01 {
  param([hashtable]$RunState)
$pd = Resolve-PhysicalDisk -DiskRow $d
        $r = $pd | Get-StorageReliabilityCounter -ErrorAction Stop

        $RunState.rel += ($r | Select-Object `
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

        $RunState.thrUnc = 1; $RunState.thrRead = 1; $RunState.thrWrite = 1; $RunState.wearWarn = 20
        try { $RunState.thrUnc   = [int]$Config.Thresholds.UncorrectableErrorsHigh } catch { <# best-effort: config threshold cast #> $RunState.thrUnc = 1 }
        try { $RunState.thrRead  = [int]$Config.Thresholds.ReadErrorsWarn } catch { <# best-effort: config threshold cast #> $RunState.thrRead = 1 }
}

function Invoke-Capability35MainPhase04Step02Stage02 {
  param([hashtable]$RunState)
try { $RunState.thrWrite = [int]$Config.Thresholds.WriteErrorsWarn } catch { <# best-effort: config threshold cast #> $RunState.thrWrite = 1 }
        try { $RunState.wearWarn = [int]$Config.Thresholds.WearWarnPercentRemaining } catch { <# best-effort: config threshold cast #> $RunState.wearWarn = 20 }

        if ($RunState.thrUnc -lt 1)   { $RunState.thrUnc = 1 }
        if ($RunState.thrRead -lt 1)  { $RunState.thrRead = 1 }
        if ($RunState.thrWrite -lt 1) { $RunState.thrWrite = 1 }
}

function Invoke-Capability35MainPhase04Step02Stage03 {
  param([hashtable]$RunState)
if ($RunState.wearWarn -lt 1) { $RunState.wearWarn = 20 }

        if ($null -ne $r.Temperature) {
          if ($r.Temperature -ge $tHigh) {
            Add-Finding -FindingList $Findings -Code 'STO-TempHigh' -Severity 'High' -Message ("Temperature={0}C (>= {1}C)." -f $r.Temperature, $tHigh) -TypeName 'StorageAudit.Finding' -Extra @{ DiskKey = $RunState.diskKey }
          }
          elseif ($r.Temperature -ge $tWarn) {
            Add-Finding -FindingList $Findings -Code 'STO-TempWarn' -Severity 'Medium' -Message ("Temperature={0}C (>= {1}C)." -f $r.Temperature, $tWarn) -TypeName 'StorageAudit.Finding' -Extra @{ DiskKey = $RunState.diskKey }
          }
        }

        if ((Test-AllConditions -Conditions @({ $null -ne $r.UncorrectableErrors }, { $r.UncorrectableErrors -ge $RunState.thrUnc }))) {
          Add-Finding -FindingList $Findings -Code 'STO-UncorrectableErrors' -Severity 'High' -Message ("UncorrectableErrors={0} (>= {1})." -f $r.UncorrectableErrors, $RunState.thrUnc) -TypeName 'StorageAudit.Finding' -Extra @{ DiskKey = $RunState.diskKey }
        }
}

function Invoke-Capability35MainPhase04Step02Stage04 {
  param([hashtable]$RunState)
if ((Test-AllConditions -Conditions @({ $null -ne $r.ReadErrorsTotal }, { $r.ReadErrorsTotal -ge $RunState.thrRead }))) {
          Add-Finding -FindingList $Findings -Code 'STO-ReadErrors' -Severity 'Medium' -Message ("ReadErrorsTotal={0} (>= {1})." -f $r.ReadErrorsTotal, $RunState.thrRead) -TypeName 'StorageAudit.Finding' -Extra @{ DiskKey = $RunState.diskKey }
        }

        if ((Test-AllConditions -Conditions @({ $null -ne $r.WriteErrorsTotal }, { $r.WriteErrorsTotal -ge $RunState.thrWrite }))) {
          Add-Finding -FindingList $Findings -Code 'STO-WriteErrors' -Severity 'Medium' -Message ("WriteErrorsTotal={0} (>= {1})." -f $r.WriteErrorsTotal, $RunState.thrWrite) -TypeName 'StorageAudit.Finding' -Extra @{ DiskKey = $RunState.diskKey }
        }

        if ((Test-AllConditions -Conditions @({ $null -ne $r.Wear }, { $r.Wear -le $RunState.wearWarn }))) {
          Add-Finding -FindingList $Findings -Code 'STO-WearWarn' -Severity 'Medium' -Message ("Wear={0} (<= {1}; provider-dependent semantics)." -f $r.Wear, $RunState.wearWarn) -TypeName 'StorageAudit.Finding' -Extra @{ DiskKey = $RunState.diskKey }
        }
}

function Invoke-Capability35MainPhase04Step02 {
  param([hashtable]$RunState)
try {
        . Invoke-Capability35MainPhase04Step02Stage01 -RunState $RunState
. Invoke-Capability35MainPhase04Step02Stage02 -RunState $RunState
. Invoke-Capability35MainPhase04Step02Stage03 -RunState $RunState
. Invoke-Capability35MainPhase04Step02Stage04 -RunState $RunState
      }
      catch {
        Add-Finding -FindingList $Findings -Code 'STO-ReliabilityUnavailable' -Severity 'Info' -Message ("ReliabilityCounter unavailable: {0}" -f $_.Exception.Message) -TypeName 'StorageAudit.Finding' -Extra @{ DiskKey = $RunState.diskKey }
      }
}

function Invoke-Capability35MainPhase04 {
  param([hashtable]$RunState)
  if ($hasReliability) {
    foreach ($d in $RunState.disks) {
      . Invoke-Capability35MainPhase04Step01 -RunState $RunState
. Invoke-Capability35MainPhase04Step02 -RunState $RunState
    }
  }
}
function Invoke-Capability35MainPhase05 {
  param([hashtable]$RunState)
  $summary = [pscustomobject]@{
    PSTypeName      = 'StorageAudit.Summary'
    ComputerName    = $env:COMPUTERNAME
    PhysicalDisks   = ($RunState.disks | Measure-Object).Count
    ReliabilityRead = ($RunState.rel   | Measure-Object).Count
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
    $RunState.disks              | Export-Csv -Path (Join-Path $folder ($base + "_disks.csv"))       -NoTypeInformation -Encoding UTF8
    $RunState.rel                | Export-Csv -Path (Join-Path $folder ($base + "_reliability.csv")) -NoTypeInformation -Encoding UTF8
  }
}
function Invoke-Capability35MainPhase06Step01 {
  param([hashtable]$RunState)
$findingsAL = ConvertTo-ArrayList -InputObject $Findings.ToArray()
    Write-ConsoleSummary -Summary $summary -Findings $findingsAL `
      -CustomFields ([ordered]@{
        PhysicalDisks   = $summary.PhysicalDisks
        ReliabilityRead = $summary.ReliabilityRead
      })
    # Disk table
    $showDiskTable = $true
    try { $showDiskTable = [bool]$Config.Output.ShowDiskTable } catch { <# best-effort: config property cast #> $showDiskTable = $true }
    if ($showDiskTable -and $RunState.disks -and @($RunState.disks).Count -gt 0) {
      Write-DecorativeRule -Title "Physical disks" -Color 'Gray'
      Write-UiLine -Text (((@($RunState.disks) | Select-Object FriendlyName, MediaType, BusType, HealthStatus, OperationalStatus, Size) |
          Format-Table -AutoSize | Out-String).TrimEnd()) -Color 'Gray'
    }
}

function Invoke-Capability35MainPhase06Step02 {
  param([hashtable]$RunState)
if ($RunState.rel -and @($RunState.rel).Count -gt 0) {
      Write-DecorativeRule -Title "Reliability counters (sample fields)" -Color 'Gray'
      Write-UiLine -Text (((@($RunState.rel) | Select-Object FriendlyName, Temperature, Wear, UncorrectableErrors, ReadErrorsTotal, WriteErrorsTotal, PowerOnHours |
          Format-Table -AutoSize | Out-String).TrimEnd())) -Color 'Gray'
    }
}

function Invoke-Capability35MainPhase06 {
  param([hashtable]$RunState)
  if (-not $NoConsole) {
    . Invoke-Capability35MainPhase06Step01 -RunState $RunState
. Invoke-Capability35MainPhase06Step02 -RunState $RunState
  }
}
function Invoke-Capability35Main {
  param($EntryBoundParameters, $EntryCmdlet, $EntryInvocation)
  $RunState = @{

  }
  $script:__EntryBoundParameters = $EntryBoundParameters
  $script:__EntryCmdlet = $EntryCmdlet
  $script:__EntryInvocation = $EntryInvocation
  . Invoke-Capability35MainPhase01 -RunState $RunState
  . Invoke-Capability35MainPhase02 -RunState $RunState
  . Invoke-Capability35MainPhase03 -RunState $RunState
  . Invoke-Capability35MainPhase04 -RunState $RunState
  . Invoke-Capability35MainPhase05 -RunState $RunState
  . Invoke-Capability35MainPhase06 -RunState $RunState
  $script:RunState = $RunState
}

. Invoke-Capability35Main -EntryBoundParameters $PSBoundParameters -EntryCmdlet $PSCmdlet -EntryInvocation $MyInvocation

# V2 output contract
function Get-Capability35ResultToken {
  $resultToken = if ($Strict -and $Findings.Count -gt 0) { 'FAIL' } elseif ($Findings.Count -gt 0) { 'WARN' } else { 'OK' }
  return $resultToken
}
$resultToken = Get-Capability35ResultToken
$v2Result = Get-V2ResultObject -ScriptName '35-Storage-Reliability-Audit.ps1' -Mode $Mode -Result $resultToken -Findings (ConvertTo-ObjectArray -InputObject $Findings.ToArray()) -Summary $summary -Metadata @{ Disks = @($RunState.disks); Reliability = @($RunState.rel); Config = $Config }
Write-ResultObject -ResultObject $v2Result -OutputFormat $OutputFormat -OutputPath $OutputPath
if ($PassThru) { $v2Result }

# endregion Main
exit (Get-V2ExitCode -Result $resultToken)
