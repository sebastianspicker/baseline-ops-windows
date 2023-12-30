#requires -version 5.1
<#
.SYNOPSIS
Audits running processes and services (Top CPU/RAM, service->process mapping, start mode, image path).

.DESCRIPTION
Best-practice output model (Windows PowerShell 5.1):
- Pipeline: one structured object only (easy for ConvertTo-Json, Export-Csv, Where-Object).
- Console: all human-friendly formatting via Write-Host / Write-Information (no pipeline pollution).
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

.OUTPUTS
ProcessServiceAudit.Record (pscustomobject) with Summary, TopCpu, TopRam, Services, Config.
.EXAMPLE
  .\30-Service-Process-Audit.ps1

#>


[CmdletBinding()]
param(
  [ValidateRange(1, 1000)]
  [int]$TopN = 20,

  [string]$ExportPath,

  [string]$ConfigJsonPath = "PATH/TO/JSON\process-service-audit.json",

  [switch]$NoConsole,

  [switch]$NoColor
)

$script:LibPath = Join-Path $PSScriptRoot 'lib'
Import-Module (Join-Path $script:LibPath 'Output.psm1') -Force


Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

# -----------------------------
# Console helpers (no pipeline)
# -----------------------------
function Test-InteractiveHost {
  [CmdletBinding()]
  param()

  try { return ($Host -and $Host.UI -and $Host.UI.RawUI) }
  catch { return $false }
}

$script:IsInteractive = Test-InteractiveHost
$script:UseColor = (-not $NoColor) -and $script:IsInteractive

function Write-ConsoleInfo {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]
    [string]$Message
  )

  if ($NoConsole) { return }

  # Information stream is suppressed by default ($InformationPreference=SilentlyContinue),
  # therefore we force display with -InformationAction Continue. [web:78][web:98]
  Write-Information -MessageData $Message -InformationAction Continue
}


function Write-ConsoleRule {
  [CmdletBinding()]
  param(
    [string]$Title
  )

  if ($NoConsole) { return }

  $width = 80
  try {
    if ($Host.UI.RawUI.WindowSize.Width -gt 0) { $width = [Math]::Min(120, [Math]::Max(60, $Host.UI.RawUI.WindowSize.Width)) }
  }
  catch { }

  if ([string]::IsNullOrWhiteSpace($Title)) {
    Write-ConsoleLine -Message ('-' * $width) -Style Dim
    return
  }

  $titleText = " $Title "
  $dashCount = [Math]::Max(0, $width - $titleText.Length)
  Write-ConsoleLine -Message ($titleText + ('-' * $dashCount)) -Style Dim
}

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

  if ([string]::IsNullOrWhiteSpace($Path)) { return $null }
  if (-not (Test-Path -LiteralPath $Path)) { return $null }

  try {
    $jsonText = Get-Content -LiteralPath $Path -Raw -ErrorAction Stop
    if ([string]::IsNullOrWhiteSpace($jsonText)) { return $null }
    return ($jsonText | ConvertFrom-Json -ErrorAction Stop) # ConvertFrom-Json converts JSON to objects. [web:38]
  }
  catch {
    return $null
  }
}

# Defaults used when JSON is missing/unreadable/invalid
$Config = [ordered]@{
  TopN                  = $TopN
  ExportEnabled         = [bool](-not [string]::IsNullOrWhiteSpace($ExportPath))
  ExportEncoding        = 'utf8'  # PS 5.1: UTF-8 with BOM (commonly Excel-friendly). [web:16]
  ShowListsInConsole    = $true
  ShowServicesInConsole = $true
  ShowTopCpuInConsole   = $true
  ShowTopRamInConsole   = $true
  ConsoleMaxServices    = 60      # prevent “wall of text” by default
}

$jsonCfg = Import-OptionalJsonConfig -Path $ConfigJsonPath

if ($null -ne $jsonCfg) {
  if ($null -ne $jsonCfg.TopN) {
    $tmp = $jsonCfg.TopN -as [int]
    if ($tmp -ge 1 -and $tmp -le 1000) { $Config.TopN = $tmp }
  }

  if ($null -ne $jsonCfg.ExportEnabled)         { $Config.ExportEnabled = [bool]$jsonCfg.ExportEnabled }
  if ($null -ne $jsonCfg.ShowListsInConsole)    { $Config.ShowListsInConsole = [bool]$jsonCfg.ShowListsInConsole }
  if ($null -ne $jsonCfg.ShowServicesInConsole) { $Config.ShowServicesInConsole = [bool]$jsonCfg.ShowServicesInConsole }
  if ($null -ne $jsonCfg.ShowTopCpuInConsole)   { $Config.ShowTopCpuInConsole = [bool]$jsonCfg.ShowTopCpuInConsole }
  if ($null -ne $jsonCfg.ShowTopRamInConsole)   { $Config.ShowTopRamInConsole = [bool]$jsonCfg.ShowTopRamInConsole }

  if ($null -ne $jsonCfg.ConsoleMaxServices) {
    $tmp2 = $jsonCfg.ConsoleMaxServices -as [int]
    if ($tmp2 -ge 1 -and $tmp2 -le 5000) { $Config.ConsoleMaxServices = $tmp2 }
  }
}

$effectiveTopN = [int]$Config.TopN

if (-not $NoConsole) {
  if ($null -eq $jsonCfg -and -not [string]::IsNullOrWhiteSpace($ConfigJsonPath)) {
    Write-ConsoleInfo ("Config JSON not loaded (using defaults): {0}" -f $ConfigJsonPath)
  }
}

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
  try { $startTime = $Process.StartTime } catch { }

  $path = $null
  try { $path = $Process.Path } catch { }

  [pscustomobject]@{
    Name         = $Process.Name
    Id           = $Process.Id
    CPU          = $Process.CPU          # CPU is cumulative seconds, not %. [web:29]
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
$procsRaw = @(Get-Process -ErrorAction SilentlyContinue)
$procs = foreach ($p in $procsRaw) { Get-SafeProcessSnapshot -Process $p }

$topCpu = $procs | Sort-Object CPU -Descending | Select-Object -First $effectiveTopN
$topRam = $procs | Sort-Object WorkingSet64 -Descending | Select-Object -First $effectiveTopN

# Join map: PID -> process image path (if accessible)
$procPathById = @{}
foreach ($p in $procs) {
  if (-not $procPathById.ContainsKey($p.Id)) { $procPathById[$p.Id] = $p.Path }
}

# Services via CIM (Win32_Service provides StartMode/StartName/PathName/ProcessId). [web:47]
$svc = Get-CimInstance -ClassName Win32_Service |
  Select-Object Name, DisplayName, State, StartMode, StartName, ProcessId, PathName

$svcEnriched = foreach ($s in $svc) {
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
}

$runningServicesCount = ($svcEnriched | Where-Object { $_.State -eq 'Running' } | Measure-Object).Count

# -----------------------------
# Summary + optional export
# -----------------------------
$summary = [pscustomobject]@{
  ComputerName     = $env:COMPUTERNAME
  Timestamp        = Get-Date
  TopN             = $effectiveTopN
  ProcessCount     = $procs.Count
  ServiceCount     = $svcEnriched.Count
  RunningServices  = $runningServicesCount
  ConfigJsonPath   = if ([string]::IsNullOrWhiteSpace($ConfigJsonPath)) { $null } else { $ConfigJsonPath }
  ConfigLoaded     = [bool]($null -ne $jsonCfg)
  ExportEnabled    = [bool]($Config.ExportEnabled -and -not [string]::IsNullOrWhiteSpace($ExportPath))
  ExportBasePath   = if ([string]::IsNullOrWhiteSpace($ExportPath)) { $null } else { $ExportPath }
}

if ($summary.ExportEnabled) {
  $target = Resolve-ExportTarget -ExportPath $ExportPath

  $summary      | Export-Csv -Path (Join-Path $target.Folder ($target.Base + "_summary.csv"))   -NoTypeInformation -Encoding $Config.ExportEncoding
  $topCpu       | Export-Csv -Path (Join-Path $target.Folder ($target.Base + "_topcpu.csv"))    -NoTypeInformation -Encoding $Config.ExportEncoding
  $topRam       | Export-Csv -Path (Join-Path $target.Folder ($target.Base + "_topram.csv"))    -NoTypeInformation -Encoding $Config.ExportEncoding
  $svcEnriched  | Export-Csv -Path (Join-Path $target.Folder ($target.Base + "_services.csv"))  -NoTypeInformation -Encoding $Config.ExportEncoding

  Write-ConsoleInfo ("CSV export written to: {0}\{1}_*.csv" -f $target.Folder, $target.Base)
}

# -----------------------------
# Pretty console output
# -----------------------------
if (-not $NoConsole) {
  Write-Host ""

  Write-ConsoleRule -Title "Process/Service Audit"
  Write-ConsoleLine -Message ("Computer : {0}" -f $summary.ComputerName) -Style Header
  Write-ConsoleLine -Message ("Time     : {0}" -f $summary.Timestamp) -Style Dim

  Write-Host ""
  Write-ConsoleRule -Title "Counts"
  Write-ConsoleLine -Message ("Processes        : {0}" -f $summary.ProcessCount) -Style Default

  $svcLine = "Services         : {0} (Running: {1})" -f $summary.ServiceCount, $summary.RunningServices
  if ($summary.RunningServices -gt 0) { Write-ConsoleLine -Message $svcLine -Style Ok } else { Write-ConsoleLine -Message $svcLine -Style Warn }

  Write-ConsoleLine -Message ("TopN             : {0}" -f $summary.TopN) -Style Default

  Write-Host ""
  Write-ConsoleRule -Title "Config"
  if ($summary.ConfigLoaded) {
    Write-ConsoleLine -Message "Config loaded    : True" -Style Ok
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

  if ($Config.ShowListsInConsole) {
    if ($Config.ShowTopCpuInConsole) {
      Write-Host ""
      Write-ConsoleRule -Title ("Top CPU (CPU seconds, cumulative) - Top {0}" -f $effectiveTopN)
      $topCpu |
        Select-Object Name, Id, CPU, WorkingSet64, StartTime, Path |
        ForEach-Object {
          $ws = Format-Bytes $_.WorkingSet64
          Write-ConsoleLine -Message ("{0,-28} {1,6}  CPU(s): {2,10:N2}  WS: {3,10}  Start: {4}" -f $_.Name, $_.Id, $_.CPU, $ws, $_.StartTime) -Style Default
        }
    }

    if ($Config.ShowTopRamInConsole) {
      Write-Host ""
      Write-ConsoleRule -Title ("Top RAM (WorkingSet) - Top {0}" -f $effectiveTopN)
      $topRam |
        Select-Object Name, Id, CPU, WorkingSet64, StartTime, Path |
        ForEach-Object {
          $ws = Format-Bytes $_.WorkingSet64
          Write-ConsoleLine -Message ("{0,-28} {1,6}  WS: {2,10}  CPU(s): {3,10:N2}  Start: {4}" -f $_.Name, $_.Id, $ws, $_.CPU, $_.StartTime) -Style Default
        }
    }

    if ($Config.ShowServicesInConsole) {
      Write-Host ""
      Write-ConsoleRule -Title ("Services (sample) - showing up to {0}" -f $Config.ConsoleMaxServices)

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

  Write-Host ""
  Write-ConsoleRule -Title "End"
}

# -----------------------------
# Pipeline output (single structured object)
# -----------------------------
#[pscustomobject]@{
#  PSTypeName = 'ProcessServiceAudit.Record'
#  Summary    = $summary
#  TopCpu     = $topCpu
#  TopRam     = $topRam
#  Services   = $svcEnriched
#  Config     = [pscustomobject]$Config
#}
