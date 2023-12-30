#requires -version 5.1
<#
.SYNOPSIS
Fast event log triage (Windows PowerShell 5.1) using Get-WinEvent -FilterHashtable.

.DESCRIPTION
Best-practice layout:
- Success output stream: structured objects only (safe for Export-Csv / ConvertTo-Json / Where-Object). [web:90]
- Console UX: pretty blocks, separators, and colors via Write-Host / Write-Information only. [web:89][web:104]

Features:
- Optional JSON config overrides (PATH/TO/JSON\triage.json). Falls back to defaults if missing/invalid.
- Optional record de-duplication (true duplicates only).
- Optional "collapse" summary: groups similar events without removing records.
- Optional CSV export.

.PARAMETER ConfigPath
Optional path to JSON config (e.g. "PATH/TO/JSON\triage.json"). If unreadable/invalid, defaults apply.

.PARAMETER Quiet
Suppresses console output (still returns objects).

.PARAMETER NoColor
Disables colored console output (still prints text).

.PARAMETER Collapse
Builds "similar event" groups for the summary (does not remove records).

.PARAMETER CollapseTop
Number of top similar groups shown in the summary.

.PARAMETER Deduplicate
Removes true duplicates from output (default: disabled). Uses RecordId when available.

.PARAMETER NormalizeMessage
If enabled, produces NormalizedMessage (single-line) and uses it for collapse grouping & CSV export.

.PARAMETER ExportPath
Optional CSV export path.
.EXAMPLE
  .\26-Get-WinEvent-FastTriage.ps1

#>


[CmdletBinding()]
param(
  [Parameter()]
  [string]$ConfigPath,

  [Parameter()]
  [switch]$Quiet,

  [Parameter()]
  [switch]$NoColor,

  [Parameter()]
  [bool]$Collapse = $true,

  [Parameter()]
  [ValidateRange(1, 50)]
  [int]$CollapseTop = 5,

  [Parameter()]
  [bool]$Deduplicate = $false,

  [Parameter()]
  [bool]$NormalizeMessage = $true,

  [Parameter()]
  [ValidateNotNullOrEmpty()]
  [string]$LogName = 'System',

  [Parameter()]
  [ValidateRange(1, 24*365)]
  [int]$HoursBack = 6,

  [Parameter()]
  [ValidateSet(1,2,3,4,5)]
  [int[]]$Level = @(2,3),

  [Parameter()]
  [string[]]$ProviderName,

  [Parameter()]
  [int[]]$Id,

  [Parameter()]
  [ValidateRange(1, 1000000)]
  [int]$MaxEvents = 500,

  [Parameter()]
  [string]$ExportPath
)

$script:LibPath = Join-Path $PSScriptRoot 'lib'
Import-Module (Join-Path $script:LibPath 'Output.psm1') -Force


$script:Quiet = [bool]$Quiet
$script:NoColor = [bool]$NoColor


Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

# -------------------------
# Console helpers (no pipeline pollution)
# -------------------------
function Write-InfoLine {
  [CmdletBinding()]
  param([AllowNull()][string]$Message)

  if ($script:Quiet) { return }

  # Write-Information rejects empty strings in PS 5.1; treat them as a blank line via Write-Host. [web:89][web:104]
  if ([string]::IsNullOrEmpty($Message)) {
    Write-Host ''
    return
  }

  Write-Information $Message -InformationAction Continue
}

function Write-HostLine {
  [CmdletBinding()]
  param(
    [AllowNull()][string]$Message,
    [ConsoleColor]$ForegroundColor,
    [ConsoleColor]$BackgroundColor,
    [switch]$NoNewLine
  )

  if ($script:Quiet) { return }

  if ($null -eq $Message) { $Message = '' }

  if ($script:NoColor) {
    if ($NoNewLine) { Write-Host $Message -NoNewline } else { Write-Host $Message }
    return
  }

  $params = @{ Object = $Message }
  if ($PSBoundParameters.ContainsKey('ForegroundColor')) { $params.ForegroundColor = $ForegroundColor }
  if ($PSBoundParameters.ContainsKey('BackgroundColor')) { $params.BackgroundColor = $BackgroundColor }
  if ($NoNewLine) { $params.NoNewline = $true }
  Write-Host @params
}


function Get-LevelColor {
  [CmdletBinding()]
  param([AllowNull()][string]$LevelDisplayName)

  switch ($LevelDisplayName) {
    'Critical'     { 'Magenta' }
    'Error'        { 'Red' }
    'Warning'      { 'Yellow' }
    'Information'  { 'Gray' }
    'Verbose'      { 'DarkGray' }
    default        { 'Gray' }
  }
}

# -------------------------
# Config loading (optional) with safe defaults
# -------------------------
function Resolve-TriageConfig {
  [CmdletBinding()]
  param([string]$Path)

  if ([string]::IsNullOrWhiteSpace($Path)) { return $null }

  if (-not (Test-Path -LiteralPath $Path)) {
    Write-InfoLine ("Config not found: {0}. Using defaults." -f $Path)
    return $null
  }

  try {
    $raw = Get-Content -LiteralPath $Path -Raw -ErrorAction Stop
    if ([string]::IsNullOrWhiteSpace($raw)) { return $null }
    return ($raw | ConvertFrom-Json -ErrorAction Stop)
  }
  catch {
    Write-InfoLine ("Config invalid/unreadable: {0}. Using defaults." -f $Path)
    Write-InfoLine ("Config error: {0}" -f $_.Exception.Message)
    return $null
  }
}

function Apply-ConfigOverrides {
  [CmdletBinding()]
  param([Parameter(Mandatory=$true)][pscustomobject]$Config)

  if ($null -ne $Config.LogName -and -not [string]::IsNullOrWhiteSpace([string]$Config.LogName)) {
    $script:LogName = [string]$Config.LogName
  }

  if ($null -ne $Config.HoursBack) {
    $hb = 0
    if ([int]::TryParse([string]$Config.HoursBack, [ref]$hb) -and $hb -ge 1 -and $hb -le (24*365)) {
      $script:HoursBack = $hb
    }
  }

  if ($null -ne $Config.Level) {
    $levels = @()
    foreach ($l in @($Config.Level)) {
      $parsed = $null
      if ([int]::TryParse([string]$l, [ref]$parsed) -and $parsed -in 1,2,3,4,5) {
        $levels += $parsed
      }
    }
    if ($levels.Count -gt 0) { $script:Level = $levels }
  }

  if ($null -ne $Config.ProviderName) {
    $p = @()
    foreach ($x in @($Config.ProviderName)) {
      if (-not [string]::IsNullOrWhiteSpace([string]$x)) { $p += [string]$x }
    }
    if ($p.Count -gt 0) { $script:ProviderName = $p }
  }

  if ($null -ne $Config.Id) {
    $ids = @()
    foreach ($x in @($Config.Id)) {
      $parsed = $null
      if ([int]::TryParse([string]$x, [ref]$parsed) -and $parsed -gt 0) { $ids += $parsed }
    }
    if ($ids.Count -gt 0) { $script:Id = $ids }
  }

  if ($null -ne $Config.MaxEvents) {
    $m = 0
    if ([int]::TryParse([string]$Config.MaxEvents, [ref]$m) -and $m -ge 1 -and $m -le 1000000) {
      $script:MaxEvents = $m
    }
  }

  if ($null -ne $Config.ExportPath -and -not [string]::IsNullOrWhiteSpace([string]$Config.ExportPath)) {
    $script:ExportPath = [string]$Config.ExportPath
  }

  if ($null -ne $Config.Deduplicate) {
    $d = $null
    if ([bool]::TryParse([string]$Config.Deduplicate, [ref]$d)) { $script:Deduplicate = $d }
  }

  if ($null -ne $Config.Collapse) {
    $c = $null
    if ([bool]::TryParse([string]$Config.Collapse, [ref]$c)) { $script:Collapse = $c }
  }

  if ($null -ne $Config.CollapseTop) {
    $ct = 0
    if ([int]::TryParse([string]$Config.CollapseTop, [ref]$ct) -and $ct -ge 1 -and $ct -le 50) {
      $script:CollapseTop = $ct
    }
  }

  if ($null -ne $Config.NormalizeMessage) {
    $nm = $null
    if ([bool]::TryParse([string]$Config.NormalizeMessage, [ref]$nm)) { $script:NormalizeMessage = $nm }
  }

  if ($null -ne $Config.Quiet) {
    $q = $null
    if ([bool]::TryParse([string]$Config.Quiet, [ref]$q)) { $script:Quiet = $q }
  }

  if ($null -ne $Config.NoColor) {
    $nc = $null
    if ([bool]::TryParse([string]$Config.NoColor, [ref]$nc)) { $script:NoColor = $nc }
  }
}

# -------------------------
# Data helpers
# -------------------------
function Normalize-Message {
  [CmdletBinding()]
  param([AllowNull()][string]$Message)

  if ($null -eq $Message) { return '' }
  $m = ($Message -replace "(`r`n|`n|`r)", ' ')
  $m = ($m -replace '\s{2,}', ' ').Trim()
  return $m
}

function Get-EventDedupeKey {
  [CmdletBinding()]
  param([Parameter(Mandatory=$true)]$Event)

  if ($null -ne $Event.RecordId) { return ("{0}|{1}" -f $Event.LogName, $Event.RecordId) }

  $tc = $Event.TimeCreated
  $msg = Normalize-Message -Message ([string]$Event.Message)
  return ("{0}|{1:o}|{2}|{3}|{4}" -f $Event.LogName, $tc, $Event.Id, $Event.ProviderName, $msg)
}

function Get-CollapseKey {
  [CmdletBinding()]
  param([Parameter(Mandatory=$true)]$Event)

  $sep = [char]0x1F
  $msg = if ($script:NormalizeMessage) { $Event.NormalizedMessage } else { Normalize-Message -Message ([string]$Event.Message) }
  return ("{0}{4}{1}{4}{2}{4}{3}" -f $Event.ProviderName, $Event.Id, $Event.LevelDisplayName, $msg, $sep)
}

# -------------------------
# Load config and apply defaults
# -------------------------
$config = Resolve-TriageConfig -Path $ConfigPath
if ($null -ne $config) { Apply-ConfigOverrides -Config $config }

if ($HoursBack -lt 1)  { $HoursBack = 6 }
if ($MaxEvents -lt 1)  { $MaxEvents = 500 }
if (-not $Level -or $Level.Count -eq 0) { $Level = @(2,3) }
if ($CollapseTop -lt 1) { $CollapseTop = 5 }

$startTime = (Get-Date).AddHours(-$HoursBack)

# -------------------------
# Query
# -------------------------
$filter = @{
  LogName   = $LogName
  StartTime = $startTime
  Level     = $Level
}
if ($ProviderName -and $ProviderName.Count -gt 0) { $filter.ProviderName = $ProviderName }
if ($Id -and $Id.Count -gt 0)                     { $filter.ID          = $Id }

$eventsRaw = @()
try {
  $eventsRaw = Get-WinEvent -FilterHashtable $filter -MaxEvents $MaxEvents -ErrorAction Stop
}
catch {
  if ($_.Exception.Message -match 'No events were found') {
    $eventsRaw = @()
  } else {
    throw
  }
}

$events = foreach ($e in $eventsRaw) {
  $msg = $null
  try { $msg = $e.Message } catch { $msg = $null }

  $norm = if ($NormalizeMessage) { Normalize-Message -Message ([string]$msg) } else { $null }

  [pscustomobject]@{
    TimeCreated       = $e.TimeCreated
    LevelDisplayName  = $e.LevelDisplayName
    Id                = $e.Id
    ProviderName      = $e.ProviderName
    LogName           = $LogName
    RecordId          = $e.RecordId
    Message           = $msg
    NormalizedMessage = $norm
  }
}

$dedupRemoved = 0
if ($Deduplicate -and $events.Count -gt 1) {
  $seen = New-Object 'System.Collections.Generic.HashSet[string]'
  $tmp = New-Object 'System.Collections.Generic.List[object]'
  foreach ($ev in $events) {
    $k = Get-EventDedupeKey -Event $ev
    if ($seen.Add($k)) { [void]$tmp.Add($ev) }
  }
  $dedupRemoved = ($events.Count - $tmp.Count)
  $events = $tmp.ToArray()
}

$exported = $false
if ($ExportPath) {
  try {
    $dir = Split-Path -Path $ExportPath -Parent
    if ($dir -and -not (Test-Path -LiteralPath $dir)) {
      New-Item -Path $dir -ItemType Directory -Force | Out-Null
    }

    if ($NormalizeMessage) {
      $events |
        Select-Object TimeCreated, LevelDisplayName, Id, ProviderName, LogName, RecordId, NormalizedMessage |
        Export-Csv -Path $ExportPath -NoTypeInformation -Encoding UTF8 -ErrorAction Stop
    } else {
      $events |
        Select-Object TimeCreated, LevelDisplayName, Id, ProviderName, LogName, RecordId, Message |
        Export-Csv -Path $ExportPath -NoTypeInformation -Encoding UTF8 -ErrorAction Stop
    }

    $exported = $true
  }
  catch {
    Write-Warning ("CSV export failed for '{0}'. Error: {1}" -f $ExportPath, $_.Exception.Message)
  }
}

# -------------------------
# Summary (console only)
# -------------------------
$minTime = $null
$maxTime = $null
$levelStats = @()
$providerStats = @()
$idStats = @()
$collapseSummary = @()

if ($events.Count -gt 0) {
  $minTime = ($events | Measure-Object -Property TimeCreated -Minimum).Minimum
  $maxTime = ($events | Measure-Object -Property TimeCreated -Maximum).Maximum

  $levelStats = $events | Group-Object -Property LevelDisplayName | Sort-Object Count -Descending
  $providerStats = $events | Group-Object -Property ProviderName | Sort-Object Count -Descending | Select-Object -First 5
  $idStats = $events | Group-Object -Property Id | Sort-Object Count -Descending | Select-Object -First 5

  if ($Collapse) {
    $collapseSummary =
      $events |
      Group-Object -Property { Get-CollapseKey -Event $_ } |
      Sort-Object Count -Descending |
      Select-Object -First $CollapseTop |
      ForEach-Object {
        $sample = $_.Group[0]
        $times = $_.Group | Select-Object -ExpandProperty TimeCreated
        [pscustomobject]@{
          Count     = $_.Count
          Provider  = $sample.ProviderName
          Id        = $sample.Id
          Level     = $sample.LevelDisplayName
          FirstSeen = ($times | Measure-Object -Minimum).Minimum
          LastSeen  = ($times | Measure-Object -Maximum).Maximum
        }
      }
  }
}

if (-not $Quiet) {
  Write-Section "Eventlog Triage Summary"

  Write-HostLine ("LogName      : {0}" -f $LogName) -ForegroundColor White
  Write-HostLine ("HoursBack    : {0}" -f $HoursBack) -ForegroundColor White
  Write-HostLine ("StartTime    : {0}" -f $startTime) -ForegroundColor White
  Write-HostLine ("Level(s)     : {0}" -f ($Level -join ', ')) -ForegroundColor White
  Write-HostLine ("ProviderName : {0}" -f ($(if ($ProviderName -and $ProviderName.Count -gt 0) { $ProviderName -join ', ' } else { '<none>' }))) -ForegroundColor White
  Write-HostLine ("Id(s)        : {0}" -f ($(if ($Id -and $Id.Count -gt 0) { $Id -join ', ' } else { '<none>' }))) -ForegroundColor White
  Write-HostLine ("MaxEvents    : {0}" -f $MaxEvents) -ForegroundColor White
  Write-HostLine ("Returned     : {0}" -f $events.Count) -ForegroundColor White

  if ($events.Count -gt 0) {
    Write-HostLine ("TimeRange    : {0} .. {1}" -f $minTime, $maxTime) -ForegroundColor White
  } else {
    Write-HostLine ("TimeRange    : <n/a>") -ForegroundColor DarkGray
  }

  Write-HostLine ("Deduplicate  : {0} (removed: {1})" -f $Deduplicate, $dedupRemoved) -ForegroundColor DarkGray
  Write-HostLine ("Collapse     : {0} (top: {1})" -f $Collapse, $CollapseTop) -ForegroundColor DarkGray
  Write-HostLine ("ExportPath   : {0}" -f ($(if ($ExportPath) { $ExportPath } else { '<none>' }))) -ForegroundColor DarkGray
  Write-HostLine ("Exported     : {0}" -f $exported) -ForegroundColor DarkGray

  Write-InfoLine ""  # blank line (safe now)

  if ($levelStats.Count -gt 0) {
    Write-HostLine "Levels:" -ForegroundColor Cyan
    foreach ($g in $levelStats) {
      $c = Get-LevelColor -LevelDisplayName $g.Name
      Write-HostLine ("  {0,-12} {1,6}" -f $g.Name, $g.Count) -ForegroundColor $c
    }
  }

  if ($providerStats.Count -gt 0) {
    Write-InfoLine ""
    Write-HostLine "Top Providers:" -ForegroundColor Cyan
    foreach ($g in $providerStats) {
      Write-HostLine ("  {0,-40} {1,6}" -f $g.Name, $g.Count) -ForegroundColor Gray
    }
  }

  if ($idStats.Count -gt 0) {
    Write-InfoLine ""
    Write-HostLine "Top Event IDs:" -ForegroundColor Cyan
    foreach ($g in $idStats) {
      Write-HostLine ("  {0,-10} {1,6}" -f $g.Name, $g.Count) -ForegroundColor Gray
    }
  }

  if ($collapseSummary.Count -gt 0) {
    Write-InfoLine ""
    Write-HostLine "Top Similar (collapsed):" -ForegroundColor Cyan
    foreach ($row in $collapseSummary) {
      $c = Get-LevelColor -LevelDisplayName $row.Level
      Write-HostLine ("  {0,6}x  {1}/{2}/{3}   {4} .. {5}" -f $row.Count, $row.Provider, $row.Id, $row.Level, $row.FirstSeen, $row.LastSeen) -ForegroundColor $c
    }
  }

  Write-HostLine ('-' * 70) -ForegroundColor DarkGray
}

# Success output: objects only.
#$events
