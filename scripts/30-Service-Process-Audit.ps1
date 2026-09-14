#requires -version 5.1
<#
.SYNOPSIS
Audits running processes and services (Top CPU/RAM, service->process mapping, start mode, image path).

.DESCRIPTION
Best-practice output model (Windows PowerShell 5.1):
- Pipeline: one structured object only (easy for ConvertTo-Json, Export-Csv, Where-Object).
- Console: all formatting uses Write-UiLine / Write-Information and does not write to the pipeline.
- Optional JSON config with safe defaults when missing/invalid.

.PARAMETER TopN
Number of processes to include in Top CPU (CPU seconds) and Top RAM (WorkingSet).

.PARAMETER ExportPath
Optional. Base path for CSV export (suffixes are appended).

.PARAMETER ConfigJsonPath
Optional. Path to a JSON config file. If missing/unreadable/invalid, safe defaults are used.

.PARAMETER NoConsole
Suppress all console output (only pipeline object is emitted).

.PARAMETER NoColor
Disable colored console output (useful for non-interactive hosts).


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

.OUTPUTS
ProcessServiceAudit.Record (pscustomobject) with Summary, TopCpu, TopRam, Services, Config.
.EXAMPLE
  .\30-Service-Process-Audit.ps1

#>


[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
  [ValidateRange(1, 1000)]
  [int]$TopN = 20,

  [string]$ExportPath,

  [string]$ConfigJsonPath,

  [switch]$NoConsole,

  [switch]$NoColor

,
  [ValidateSet('Audit','Remediate')][string]$Mode = 'Audit',
  [string]$ConfigPath,
  [ValidateSet('Console','Json','Csv','None')][string]$OutputFormat = 'Console',
  [string]$OutputPath,
  [switch]$PassThru,
  [switch]$Strict,
  [switch]$Quiet
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
function Initialize-Capability30Runtime {
  param($EntryBoundParameters)
  $RunState = @{

  }
Import-Module (Join-Path $script:LibPath 'Output.psm1') -Force
Import-Module (Join-Path $script:LibPath 'JsonCatalog.psm1') -Force
Import-Module (Join-Path $script:LibPath Serialization.psm1) -Force


Set-StrictMode -Version Latest
$script:__V2Context = Initialize-V2Context -ScriptName '30-Service-Process-Audit.ps1' -BoundParameters $EntryBoundParameters `
  -Values @{ Mode = $Mode; ConfigPath = $ConfigPath; OutputFormat = $OutputFormat; OutputPath = $OutputPath; PassThru = $PassThru; Strict = $Strict; Quiet = $Quiet; NoColor = $NoColor; DeriveRemediate = $false }
if ($script:__V2Context.Quiet) { $InformationPreference = 'SilentlyContinue'; $VerbosePreference = 'SilentlyContinue' }
$script:NoColor = [bool]$script:__V2Context.NoColor
$ErrorActionPreference = 'Stop'

$RunState.isWindowsHost = ($env:OS -eq 'Windows_NT')
  $script:RunState = $RunState
}

. Initialize-Capability30Runtime -EntryBoundParameters $PSBoundParameters
if (-not $RunState.isWindowsHost) {
  $summary = [pscustomobject]@{
    ComputerName = $env:COMPUTERNAME
    Timestamp    = Get-Date
    Mode         = $Mode
    Supported    = $false
    Notes        = @('Skipped: this script is only supported on Windows hosts.')
  }
  $unsupportedResult = if ($Strict) { 'FAIL' } else { 'WARN' }
  $result = Get-V2ResultObject -ScriptName '30-Service-Process-Audit.ps1' -Mode $Mode -Result $unsupportedResult -Findings @() -Summary $summary -Metadata @{ UnsupportedHost = $true }
  Write-ResultObject -ResultObject $result -OutputFormat $OutputFormat -OutputPath $OutputPath
  if ($PassThru) { $result }
  exit (Get-V2ExitCode -Result $unsupportedResult)
}

# -----------------------------
# Console helpers (no pipeline)
# -----------------------------
function Test-InteractiveHost {
  [CmdletBinding()]
  param()

  try { return ($Host -and $Host.UI -and $Host.UI.RawUI) }
  catch { return $false }
}

function Initialize-ServiceProcessConsoleState {
  param()
$script:IsInteractive = Test-InteractiveHost
$script:UseColor = (-not $NoColor) -and $script:IsInteractive
}
. Initialize-ServiceProcessConsoleState




function Format-Bytes {
  [CmdletBinding()]
  param([Nullable[double]]$Bytes)

  if ($null -eq $Bytes) { return $null }

  $b = [double]$Bytes
  if ($b -ge 1TB) { return ("{0:N2} TB" -f ($b / 1TB)) }
  if ($b -ge 1GB) { return ("{0:N2} GB" -f ($b / 1GB)) }
  if ($b -ge 1MB) { return ("{0:N2} MB" -f ($b / 1MB)) }
  if ($b -ge 1KB) { return ("{0:N2} KB" -f ($b / 1KB)) }
  return ("{0:N0} B" -f $b)
}

# -----------------------------
# Config (defaults + JSON merge)
# -----------------------------
function Import-OptionalJsonConfig {
  [CmdletBinding()]
  param(
    [string]$Path
  )

  Read-JsonFileWithStatus -Path $Path
}

# Defaults used when JSON is missing/unreadable/invalid
function Apply-ServiceProcessDisplayConfiguration {
if ($null -ne $jsonCfg.TopN) {
    $tmp = $jsonCfg.TopN -as [int]
    if ((Test-AllConditions -Conditions @({ $tmp -ge 1 }, { $tmp -le 1000 }))) { $Config.TopN = $tmp }
  }

  if ($null -ne $jsonCfg.ExportEnabled)         { $Config.ExportEnabled = [bool]$jsonCfg.ExportEnabled }
  if ($null -ne $jsonCfg.ShowListsInConsole)    { $Config.ShowListsInConsole = [bool]$jsonCfg.ShowListsInConsole }
  if ($null -ne $jsonCfg.ShowServicesInConsole) { $Config.ShowServicesInConsole = [bool]$jsonCfg.ShowServicesInConsole }
}

function Apply-ServiceProcessRankingConfiguration {
if ($null -ne $jsonCfg.ShowTopCpuInConsole)   { $Config.ShowTopCpuInConsole = [bool]$jsonCfg.ShowTopCpuInConsole }
  if ($null -ne $jsonCfg.ShowTopRamInConsole)   { $Config.ShowTopRamInConsole = [bool]$jsonCfg.ShowTopRamInConsole }

  if ($null -ne $jsonCfg.ConsoleMaxServices) {
    $tmp2 = $jsonCfg.ConsoleMaxServices -as [int]
    if ((Test-AllConditions -Conditions @({ $tmp2 -ge 1 }, { $tmp2 -le 5000 }))) { $Config.ConsoleMaxServices = $tmp2 }
  }
}

function Initialize-ServiceProcessConfiguration {
  param([hashtable]$RunState)
$Config = [ordered]@{
  TopN                  = $TopN
  ExportEnabled         = [bool](-not [string]::IsNullOrWhiteSpace($ExportPath))
  ExportEncoding        = 'utf8'  # PS 5.1: UTF-8 with BOM (commonly Excel-friendly).
  ShowListsInConsole    = $true
  ShowServicesInConsole = $true
  ShowTopCpuInConsole   = $true
  ShowTopRamInConsole   = $true
  ConsoleMaxServices    = 60      # prevent “wall of text” by default
}

$configLoad = Import-OptionalJsonConfig -Path $ConfigJsonPath
$jsonCfg = $configLoad.Data
$configMeta = $configLoad.Meta
$configPathProvided = -not [string]::IsNullOrWhiteSpace($ConfigJsonPath)
$configLoadIssue = (Test-AllConditions -Conditions @({ $configPathProvided }, { -not [bool]$configMeta.Loaded }))
$findings = @()

if ($configLoadIssue) {
  $findings += [pscustomobject]@{
    Code     = 'CFG-ConfigLoadFailed'
    Severity = 'Medium'
    Message  = ("Explicit ConfigJsonPath was not loaded ({0}). Defaults were used." -f $configMeta.Status)
    Path     = $ConfigJsonPath
    Status   = $configMeta.Status
    Error    = $configMeta.Error
  }
}

if ($null -ne $jsonCfg) {
  . Apply-ServiceProcessDisplayConfiguration
. Apply-ServiceProcessRankingConfiguration
}

$RunState.effectiveTopN = [int]$Config.TopN

if (-not $NoConsole) {
  if ((Test-AllConditions -Conditions @({ $null -eq $jsonCfg }, { -not [string]::IsNullOrWhiteSpace($ConfigJsonPath) }))) {
    Write-ConsoleInfo ("Config JSON not loaded (using defaults): {0}" -f $ConfigJsonPath)
  }
}
}
. Initialize-ServiceProcessConfiguration -RunState $RunState

# -----------------------------
# Data collection
# -----------------------------
function Get-SafeProcessSnapshot {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]
    [System.Diagnostics.Process]$Process
  )

  $startTime = $null
  try { $startTime = $Process.StartTime } catch {
    Write-Verbose ("Process StartTime read failed for PID {0}: {1}" -f $Process.Id,$_.Exception.Message)
  }

  $path = $null
  try { $path = $Process.Path } catch {
    Write-Verbose ("Process path read failed for PID {0}: {1}" -f $Process.Id,$_.Exception.Message)
  }

  [pscustomobject]@{
    Name         = $Process.Name
    Id           = $Process.Id
    CPU          = $Process.CPU          # CPU is cumulative seconds, not %.
    WorkingSet64 = $Process.WorkingSet64
    StartTime    = $startTime
    Path         = $path
  }
}

function Resolve-ExportTarget {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]
    [string]$ExportPath
  )

  $folder = Split-Path -Path $ExportPath -Parent
  if ([string]::IsNullOrWhiteSpace($folder)) { $folder = (Get-Location).Path }

  if (-not (Test-Path -LiteralPath $folder)) {
    New-Item -Path $folder -ItemType Directory -Force | Out-Null
  }

  $base = [IO.Path]::GetFileNameWithoutExtension($ExportPath)

  [pscustomobject]@{
    Folder = $folder
    Base   = $base
  }
}

# Processes (single pass; property access is defensive)
function Invoke-Capability30MainPhase01 {
  param([hashtable]$RunState)
  $procsRaw = @(Get-Process -ErrorAction SilentlyContinue)
  $procs = @(foreach ($p in $procsRaw) { Get-SafeProcessSnapshot -Process $p })

  $RunState.topCpu = $procs | Sort-Object CPU -Descending | Select-Object -First $RunState.effectiveTopN
  $RunState.topRam = $procs | Sort-Object WorkingSet64 -Descending | Select-Object -First $RunState.effectiveTopN

  # Join map: PID -> process image path (if accessible)
  $procPathById = @{}
  foreach ($p in $procs) {
    if (-not $procPathById.ContainsKey($p.Id)) { $procPathById[$p.Id] = $p.Path }
  }

  # Services via CIM (Win32_Service provides StartMode/StartName/PathName/ProcessId).
  $RunState.svc = @(Get-CimInstance -ClassName Win32_Service |
    Select-Object Name, DisplayName, State, StartMode, StartName, ProcessId, PathName)
}
function Invoke-Capability30MainPhase02 {
  param([hashtable]$RunState)
  $svcEnriched = @(foreach ($s in $RunState.svc) {
    [pscustomobject]@{
      Name        = $s.Name
      DisplayName = $s.DisplayName
      State       = $s.State
      StartMode   = $s.StartMode
      StartName   = $s.StartName
      ProcessId   = $s.ProcessId
      PathName    = $s.PathName
      ProcessPath = if ($s.ProcessId -gt 0 -and $procPathById.ContainsKey($s.ProcessId)) { $procPathById[$s.ProcessId] } else { $null }
    }
  })

  $RunState.runningServicesCount = ($svcEnriched | Where-Object { $_.State -eq 'Running' } | Measure-Object).Count
}
function Invoke-Capability30MainPhase03 {
  param([hashtable]$RunState)
  $summary = [pscustomobject]@{
    ComputerName     = $env:COMPUTERNAME
    Timestamp        = Get-Date
    TopN             = $RunState.effectiveTopN
    ProcessCount     = $procs.Count
    ServiceCount     = $svcEnriched.Count
    RunningServices  = $RunState.runningServicesCount
    ConfigJsonPath   = if ([string]::IsNullOrWhiteSpace($ConfigJsonPath)) { $null } else { $ConfigJsonPath }
    ConfigPathProvided = [bool]$configPathProvided
    ConfigLoaded     = [bool]($null -ne $jsonCfg)
    ConfigLoadStatus = [string]$configMeta.Status
    ConfigLoadError  = $configMeta.Error
    ExportEnabled    = [bool]($Config.ExportEnabled -and -not [string]::IsNullOrWhiteSpace($ExportPath))
    ExportBasePath   = if ([string]::IsNullOrWhiteSpace($ExportPath)) { $null } else { $ExportPath }
  }

  if ($summary.ExportEnabled) {
    $target = Resolve-ExportTarget -ExportPath $ExportPath

    $summary      | Export-Csv -Path (Join-Path $target.Folder ($target.Base + "_summary.csv"))   -NoTypeInformation -Encoding $Config.ExportEncoding
    $RunState.topCpu       | Export-Csv -Path (Join-Path $target.Folder ($target.Base + "_topcpu.csv"))    -NoTypeInformation -Encoding $Config.ExportEncoding
    $RunState.topRam       | Export-Csv -Path (Join-Path $target.Folder ($target.Base + "_topram.csv"))    -NoTypeInformation -Encoding $Config.ExportEncoding
    $svcEnriched  | Export-Csv -Path (Join-Path $target.Folder ($target.Base + "_services.csv"))  -NoTypeInformation -Encoding $Config.ExportEncoding

    Write-ConsoleInfo ("CSV export written to: {0}\{1}_*.csv" -f $target.Folder, $target.Base)
  }
}
function Invoke-Capability30MainPhase04Step01 {
Write-UiLine ""

    Write-UiRule -Title "Process/Service Audit"
    Write-ConsoleLine -Message ("Computer : {0}" -f $summary.ComputerName) -Style Header
    Write-ConsoleLine -Message ("Time     : {0}" -f $summary.Timestamp) -Style Dim

    Write-UiLine ""
    Write-UiRule -Title "Counts"
    Write-ConsoleLine -Message ("Processes        : {0}" -f $summary.ProcessCount) -Style Default

    $svcLine = "Services         : {0} (Running: {1})" -f $summary.ServiceCount, $summary.RunningServices
    if ($summary.RunningServices -gt 0) { Write-ConsoleLine -Message $svcLine -Style Ok } else { Write-ConsoleLine -Message $svcLine -Style Warn }

    Write-ConsoleLine -Message ("TopN             : {0}" -f $summary.TopN) -Style Default

    Write-UiLine ""
    Write-UiRule -Title "Config"
    if ($summary.ConfigLoaded) {
      Write-ConsoleLine -Message "Config loaded    : True" -Style Ok
    } elseif ($configLoadIssue) {
      Write-ConsoleLine -Message ("Config loaded    : False ({0}; defaults in use)" -f $summary.ConfigLoadStatus) -Style Warn
    } else {
      Write-ConsoleLine -Message "Config loaded    : False (defaults in use)" -Style Warn
    }

    if ($summary.ConfigJsonPath) {
      Write-ConsoleLine -Message ("Config JSON path : {0}" -f $summary.ConfigJsonPath) -Style Dim
    }

    if ($summary.ExportEnabled) {
      Write-ConsoleLine -Message "CSV export       : Enabled" -Style Ok
    } else {
      Write-ConsoleLine -Message "CSV export       : Disabled" -Style Dim
    }
}

function Invoke-Capability30MainPhase04Step02Stage01 {
  param([hashtable]$RunState)
if ($Config.ShowTopCpuInConsole) {
        Write-UiLine ""
        Write-UiRule -Title ("Top CPU (CPU seconds, cumulative) - Top {0}" -f $RunState.effectiveTopN)
        $RunState.topCpu |
          Select-Object Name, Id, CPU, WorkingSet64, StartTime, Path |
          ForEach-Object {
            $ws = Format-Bytes $_.WorkingSet64
            Write-ConsoleLine -Message ("{0,-28} {1,6}  CPU(s): {2,10:N2}  WS: {3,10}  Start: {4}" -f $_.Name, $_.Id, $_.CPU, $ws, $_.StartTime) -Style Default
          }
      }

      if ($Config.ShowTopRamInConsole) {
        Write-UiLine ""
        Write-UiRule -Title ("Top RAM (WorkingSet) - Top {0}" -f $RunState.effectiveTopN)
        $RunState.topRam |
          Select-Object Name, Id, CPU, WorkingSet64, StartTime, Path |
          ForEach-Object {
            $ws = Format-Bytes $_.WorkingSet64
            Write-ConsoleLine -Message ("{0,-28} {1,6}  WS: {2,10}  CPU(s): {3,10:N2}  Start: {4}" -f $_.Name, $_.Id, $ws, $_.CPU, $_.StartTime) -Style Default
          }
      }
}

function Invoke-Capability30MainPhase04Step02Stage02 {
if ($Config.ShowServicesInConsole) {
        Write-UiLine ""
        Write-UiRule -Title ("Services (sample) - showing up to {0}" -f $Config.ConsoleMaxServices)

        $svcSample = $svcEnriched | Select-Object -First $Config.ConsoleMaxServices
        foreach ($s in $svcSample) {
          $stateStyle = if ($s.State -eq 'Running') { 'Ok' } else { 'Dim' }
          Write-ConsoleLine -Message ("[{0}] {1} ({2})  StartMode={3}  Account={4}" -f $s.State, $s.Name, $s.DisplayName, $s.StartMode, $s.StartName) -Style $stateStyle
        }

        if ($svcEnriched.Count -gt $Config.ConsoleMaxServices) {
          Write-ConsoleLine -Message ("... truncated: {0} more services not shown (pipeline output still contains all)." -f ($svcEnriched.Count - $Config.ConsoleMaxServices)) -Style Warn
        }
      }
}

function Invoke-Capability30MainPhase04Step02 {
  param([hashtable]$RunState)
if ($Config.ShowListsInConsole) {
      . Invoke-Capability30MainPhase04Step02Stage01 -RunState $RunState
. Invoke-Capability30MainPhase04Step02Stage02
    }
}

function Invoke-Capability30MainPhase04Step03 {
Write-UiLine ""
    Write-UiRule -Title "End"
}

function Invoke-Capability30MainPhase04 {
  param([hashtable]$RunState)
  if (-not $NoConsole) {
    . Invoke-Capability30MainPhase04Step01
. Invoke-Capability30MainPhase04Step02 -RunState $RunState
. Invoke-Capability30MainPhase04Step03
  }
}
function Invoke-Capability30Main {
  param($EntryBoundParameters, $EntryCmdlet, $EntryInvocation, [hashtable]$RunState)
  $script:__EntryBoundParameters = $EntryBoundParameters
  $script:__EntryCmdlet = $EntryCmdlet
  $script:__EntryInvocation = $EntryInvocation
  . Invoke-Capability30MainPhase01 -RunState $RunState
  . Invoke-Capability30MainPhase02 -RunState $RunState
  . Invoke-Capability30MainPhase03 -RunState $RunState
  . Invoke-Capability30MainPhase04 -RunState $RunState
}
. Invoke-Capability30Main -EntryBoundParameters $PSBoundParameters -EntryCmdlet $PSCmdlet -EntryInvocation $MyInvocation -RunState $RunState

# V2 output contract
function Get-Capability30ResultToken {
  $resultToken = if ($configLoadIssue) { 'WARN' } else { 'OK' }
  if ($Strict -and $resultToken -eq 'WARN') { $resultToken = 'FAIL' }
  return $resultToken
}
$resultToken = Get-Capability30ResultToken
$v2Result = Get-V2ResultObject -ScriptName '30-Service-Process-Audit.ps1' -Mode $Mode -Result $resultToken -Findings @($findings) -Summary $summary -Metadata @{ TopCpu = $RunState.topCpu; TopRam = $RunState.topRam; Services = $svcEnriched; Config = [pscustomobject]$Config }
Write-ResultObject -ResultObject $v2Result -OutputFormat $OutputFormat -OutputPath $OutputPath
if ($PassThru) { $v2Result }
exit (Get-V2ExitCode -Result $resultToken)
