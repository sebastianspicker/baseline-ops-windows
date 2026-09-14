#requires -version 5.1
<#
.SYNOPSIS
Capability-private presentation and normalization helpers.

.DESCRIPTION
Provides bounded helper functions loaded by the matching public capability
after repository bootstrap and trust validation complete.
#>

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

function Resolve-TriageConfig {
  [CmdletBinding()]
  param([string]$Path)

  if ([string]::IsNullOrWhiteSpace($Path)) { return $null }

  if (-not (Test-Path -LiteralPath $Path)) {
    Write-Info ("Config not found: {0}. Using defaults." -f $Path)
    return $null
  }

  try {
    $raw = Get-BoundedUtf8FileContent -Path $Path -MaximumBytes 1048576
    if ([string]::IsNullOrWhiteSpace($raw)) { return $null }
    return ($raw | ConvertFrom-Json -ErrorAction Stop)
  }
  catch {
    Write-Info ("Config invalid/unreadable: {0}. Using defaults." -f $Path)
    Write-Info ("Config error: {0}" -f $_.Exception.Message)
    return $null
  }
}

function Apply-ConfigOverridesSection01 {
  param([hashtable]$RunState)
if ($null -ne $RunState.Config.LogName -and -not [string]::IsNullOrWhiteSpace([string]$RunState.Config.LogName)) {
    $script:LogName = [string]$RunState.Config.LogName
  }
}

function Apply-ConfigOverridesSection02 {
  param([hashtable]$RunState)
if ($null -ne $RunState.Config.HoursBack) {
    $hb = 0
    if ([int]::TryParse([string]$RunState.Config.HoursBack, [ref]$hb) -and $hb -ge 1 -and $hb -le (24*365)) {
      $script:HoursBack = $hb
    }
  }
}

function Apply-ConfigOverridesSection03 {
  param([hashtable]$RunState)
if ($null -ne $RunState.Config.Level) {
    $levels = @()
    foreach ($l in @($RunState.Config.Level)) {
      $parsed = $null
      if ([int]::TryParse([string]$l, [ref]$parsed) -and $parsed -in 1,2,3,4,5) {
        $levels += $parsed
      }
    }
    if ($levels.Count -gt 0) { $script:Level = $levels }
  }
}

function Apply-ConfigOverridesSection04 {
  param([hashtable]$RunState)
if ($null -ne $RunState.Config.ProviderName) {
    $p = @()
    foreach ($x in @($RunState.Config.ProviderName)) {
      if (-not [string]::IsNullOrWhiteSpace([string]$x)) { $p += [string]$x }
    }
    if ($p.Count -gt 0) { $script:ProviderName = $p }
  }
}

function Apply-ConfigOverridesSection05 {
  param([hashtable]$RunState)
if ($null -ne $RunState.Config.Id) {
    $ids = @()
    foreach ($x in @($RunState.Config.Id)) {
      $parsed = $null
      if ([int]::TryParse([string]$x, [ref]$parsed) -and $parsed -gt 0) { $ids += $parsed }
    }
    if ($ids.Count -gt 0) { $script:Id = $ids }
  }
}

function Apply-ConfigOverridesSection06 {
  param([hashtable]$RunState)
if ($null -ne $RunState.Config.MaxEvents) {
    $m = 0
    if ([int]::TryParse([string]$RunState.Config.MaxEvents, [ref]$m) -and $m -ge 1 -and $m -le 1000000) {
      $script:MaxEvents = $m
    }
  }
}

function Apply-ConfigOverridesSection07 {
  param([hashtable]$RunState)
if ($null -ne $RunState.Config.ExportPath -and -not [string]::IsNullOrWhiteSpace([string]$RunState.Config.ExportPath)) {
    Write-Info 'Ignoring config ExportPath; provide the output location explicitly with -ExportPath.'
  }

  if ($null -ne $RunState.Config.Deduplicate) {
    $d = $null
    if ([bool]::TryParse([string]$RunState.Config.Deduplicate, [ref]$d)) { $script:Deduplicate = $d }
  }
}

function Apply-ConfigOverridesSection08 {
  param([hashtable]$RunState)
if ($null -ne $RunState.Config.Collapse) {
    $c = $null
    if ([bool]::TryParse([string]$RunState.Config.Collapse, [ref]$c)) { $script:Collapse = $c }
  }
}

function Apply-ConfigOverridesSection09 {
  param([hashtable]$RunState)
if ($null -ne $RunState.Config.CollapseTop) {
    $ct = 0
    if ([int]::TryParse([string]$RunState.Config.CollapseTop, [ref]$ct) -and $ct -ge 1 -and $ct -le 50) {
      $script:CollapseTop = $ct
    }
  }
}

function Apply-ConfigOverridesSection10 {
  param([hashtable]$RunState)
if ($null -ne $RunState.Config.NormalizeMessage) {
    $nm = $null
    if ([bool]::TryParse([string]$RunState.Config.NormalizeMessage, [ref]$nm)) { $script:NormalizeMessage = $nm }
  }

  if ($null -ne $RunState.Config.Quiet) {
    $q = $null
    if ([bool]::TryParse([string]$RunState.Config.Quiet, [ref]$q)) { $script:Quiet = $q }
  }
}

function Apply-ConfigOverridesSection11 {
  param([hashtable]$RunState)
if ($null -ne $RunState.Config.NoColor) {
    $nc = $null
    if ([bool]::TryParse([string]$RunState.Config.NoColor, [ref]$nc)) { $script:NoColor = $nc }
  }
}

function Apply-ConfigOverrides {
  [CmdletBinding()]
  param([Parameter(Mandatory=$true)][pscustomobject]$Config, [hashtable]$RunState)
  $RunState.Config = $Config

    . Apply-ConfigOverridesSection01 -RunState $RunState
    . Apply-ConfigOverridesSection02 -RunState $RunState
    . Apply-ConfigOverridesSection03 -RunState $RunState
    . Apply-ConfigOverridesSection04 -RunState $RunState
    . Apply-ConfigOverridesSection05 -RunState $RunState
    . Apply-ConfigOverridesSection06 -RunState $RunState
    . Apply-ConfigOverridesSection07 -RunState $RunState
    . Apply-ConfigOverridesSection08 -RunState $RunState
    . Apply-ConfigOverridesSection09 -RunState $RunState
    . Apply-ConfigOverridesSection10 -RunState $RunState
    . Apply-ConfigOverridesSection11 -RunState $RunState
}

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

function Invoke-Capability26MainPhase01 {
  param([hashtable]$RunState)
  $RunState.config = Resolve-TriageConfig -Path $ConfigPath
  if ($null -ne $RunState.config) { Apply-ConfigOverrides -Config $RunState.config -RunState $RunState }

  if ($HoursBack -lt 1)  { $HoursBack = 6 }
  if ($MaxEvents -lt 1)  { $MaxEvents = 500 }
  if (-not $Level -or $Level.Count -eq 0) { $Level = @(2,3) }
}

function Invoke-Capability26MainPhase02 {
  param([hashtable]$RunState)
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

  $RunState.eventsRaw = @()
}

function Invoke-Capability26MainPhase03 {
  param([hashtable]$RunState)
  try {
    $RunState.eventsRaw = @(Get-WinEvent -FilterHashtable $filter -MaxEvents $MaxEvents -ErrorAction Stop)
  }
  catch {
    if ($_.Exception.Message -match 'No events were found') {
      $RunState.eventsRaw = @()
    } else {
      Write-Warning "Get-WinEvent query failed: $($_.Exception.Message)"
      $v2Result = Get-V2ResultObject -ScriptName '26-Get-WinEvent-FastTriage.ps1' -Mode $Mode -Result 'FAIL' -Findings @() -Summary @{ Error = $_.Exception.Message } -Metadata @{}
      Write-ResultObject -ResultObject $v2Result -OutputFormat $OutputFormat -OutputPath $OutputPath
      if ($PassThru) { $v2Result }
      exit (Get-V2ExitCode -Result 'FAIL')
    }
  }
}

function Invoke-Capability26MainPhase04 {
  param([hashtable]$RunState)
  $RunState.events = @(foreach ($e in $RunState.eventsRaw) {
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
  })

  $RunState.dedupRemoved = 0
}

function Invoke-Capability26MainPhase05 {
  param([hashtable]$RunState)
  if ($Deduplicate -and $RunState.events.Count -gt 1) {
    $seen = New-Object 'System.Collections.Generic.HashSet[string]'
    $tmp = New-Object 'System.Collections.Generic.List[object]'
    foreach ($ev in $RunState.events) {
      $k = Get-EventDedupeKey -Event $ev
      if ($seen.Add($k)) { [void]$tmp.Add($ev) }
    }
    $RunState.dedupRemoved = ($RunState.events.Count - $tmp.Count)
    $RunState.events = $tmp.ToArray()
  }

  $RunState.exported = $false
  $RunState.exportError = $null
}

function Invoke-Capability26MainPhase06 {
  param([hashtable]$RunState)
  if ($ExportPath) {
    try {
      if ($NormalizeMessage) {
        Save-Csv -InputObject @($RunState.events |
          Select-Object TimeCreated, LevelDisplayName, Id, ProviderName, LogName, RecordId, NormalizedMessage) -Path $ExportPath
      } else {
        Save-Csv -InputObject @($RunState.events |
          Select-Object TimeCreated, LevelDisplayName, Id, ProviderName, LogName, RecordId, Message) -Path $ExportPath
      }

      $RunState.exported = $true
    }
    catch {
      $RunState.exportError = $_.Exception.Message
      Write-Warning ("CSV export failed for '{0}'. Error: {1}" -f $ExportPath, $RunState.exportError)
    }
  }

  # -------------------------
  # Summary (console only)
  # -------------------------
  $RunState.minTime = $null
  $RunState.maxTime = $null
  $RunState.levelStats = @()
  $RunState.providerStats = @()
  $RunState.idStats = @()
  $RunState.collapseSummary = @()
}

function Invoke-Capability26MainPhase07 {
  param([hashtable]$RunState)
  if ($RunState.events.Count -gt 0) {
    $RunState.minTime = ($RunState.events | Measure-Object -Property TimeCreated -Minimum).Minimum
    $RunState.maxTime = ($RunState.events | Measure-Object -Property TimeCreated -Maximum).Maximum

    $RunState.levelStats = @($RunState.events | Group-Object -Property LevelDisplayName | Sort-Object Count -Descending)
    $RunState.providerStats = @($RunState.events | Group-Object -Property ProviderName | Sort-Object Count -Descending | Select-Object -First 5)
    $RunState.idStats = @($RunState.events | Group-Object -Property Id | Sort-Object Count -Descending | Select-Object -First 5)

    if ($Collapse) {
      $RunState.collapseSummary = @(
        $RunState.events |
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
      )
    }
  }
}

function Invoke-Capability26MainPhase08Step01 {
  param([hashtable]$RunState)
Write-Section "Eventlog Triage Summary"

    Write-UiLine ("LogName      : {0}" -f $LogName) -ForegroundColor White
    Write-UiLine ("HoursBack    : {0}" -f $HoursBack) -ForegroundColor White
    Write-UiLine ("StartTime    : {0}" -f $startTime) -ForegroundColor White
    Write-UiLine ("Level(s)     : {0}" -f ($Level -join ', ')) -ForegroundColor White
    Write-UiLine ("ProviderName : {0}" -f ($(if ($ProviderName -and $ProviderName.Count -gt 0) { $ProviderName -join ', ' } else { '<none>' }))) -ForegroundColor White
    Write-UiLine ("Id(s)        : {0}" -f ($(if ($Id -and $Id.Count -gt 0) { $Id -join ', ' } else { '<none>' }))) -ForegroundColor White
    Write-UiLine ("MaxEvents    : {0}" -f $MaxEvents) -ForegroundColor White
    Write-UiLine ("Returned     : {0}" -f $RunState.events.Count) -ForegroundColor White

    if ($RunState.events.Count -gt 0) {
      Write-UiLine ("TimeRange    : {0} .. {1}" -f $RunState.minTime, $RunState.maxTime) -ForegroundColor White
    } else {
      Write-UiLine ("TimeRange    : <n/a>") -ForegroundColor DarkGray
    }

    Write-UiLine ("Deduplicate  : {0} (removed: {1})" -f $Deduplicate, $RunState.dedupRemoved) -ForegroundColor DarkGray
    Write-UiLine ("Collapse     : {0} (top: {1})" -f $Collapse, $CollapseTop) -ForegroundColor DarkGray
}

function Invoke-Capability26MainPhase08Step02 {
  param([hashtable]$RunState)
Write-UiLine ("ExportPath   : {0}" -f ($(if ($ExportPath) { $ExportPath } else { '<none>' }))) -ForegroundColor DarkGray
    Write-UiLine ("Exported     : {0}" -f $RunState.exported) -ForegroundColor DarkGray

    Write-Info ""  # blank line (safe now)

    if ($RunState.levelStats.Count -gt 0) {
      Write-UiLine "Levels:" -ForegroundColor Cyan
      foreach ($g in $RunState.levelStats) {
        $c = Get-LevelColor -LevelDisplayName $g.Name
        Write-UiLine ("  {0,-12} {1,6}" -f $g.Name, $g.Count) -ForegroundColor $c
      }
    }

    if ($RunState.providerStats.Count -gt 0) {
      Write-Info ""
      Write-UiLine "Top Providers:" -ForegroundColor Cyan
      foreach ($g in $RunState.providerStats) {
        Write-UiLine ("  {0,-40} {1,6}" -f $g.Name, $g.Count) -ForegroundColor Gray
      }
    }
}

function Invoke-Capability26MainPhase08Step03 {
  param([hashtable]$RunState)
if ($RunState.idStats.Count -gt 0) {
      Write-Info ""
      Write-UiLine "Top Event IDs:" -ForegroundColor Cyan
      foreach ($g in $RunState.idStats) {
        Write-UiLine ("  {0,-10} {1,6}" -f $g.Name, $g.Count) -ForegroundColor Gray
      }
    }

    if ($RunState.collapseSummary.Count -gt 0) {
      Write-Info ""
      Write-UiLine "Top Similar (collapsed):" -ForegroundColor Cyan
      foreach ($row in $RunState.collapseSummary) {
        $c = Get-LevelColor -LevelDisplayName $row.Level
        Write-UiLine ("  {0,6}x  {1}/{2}/{3}   {4} .. {5}" -f $row.Count, $row.Provider, $row.Id, $row.Level, $row.FirstSeen, $row.LastSeen) -ForegroundColor $c
      }
    }

    Write-UiLine ('-' * 70) -ForegroundColor DarkGray
}

function Invoke-Capability26MainPhase08 {
  param([hashtable]$RunState)
  if (-not $Quiet) {
    . Invoke-Capability26MainPhase08Step01 -RunState $RunState
. Invoke-Capability26MainPhase08Step02 -RunState $RunState
. Invoke-Capability26MainPhase08Step03 -RunState $RunState
  }
}

function Invoke-Capability26MainPhase09 {
  param([hashtable]$RunState)
  $exportRequested = -not [string]::IsNullOrWhiteSpace($ExportPath)
  $findings = @()
  if ($exportRequested -and -not $RunState.exported) {
    $findings += [pscustomobject]@{
      Code     = 'EVT-ExportFailed'
      Severity = 'Medium'
      Message  = ("Requested CSV export failed for '{0}': {1}" -f $ExportPath, $RunState.exportError)
    }
  }
}

function Invoke-Capability26Main {
  param($EntryBoundParameters, $EntryCmdlet, $EntryInvocation, [hashtable]$RunState)
  $script:__EntryBoundParameters = $EntryBoundParameters
  $script:__EntryCmdlet = $EntryCmdlet
  $script:__EntryInvocation = $EntryInvocation
  . Invoke-Capability26MainPhase01 -RunState $RunState
  . Invoke-Capability26MainPhase02 -RunState $RunState
  . Invoke-Capability26MainPhase03 -RunState $RunState
  . Invoke-Capability26MainPhase04 -RunState $RunState
  . Invoke-Capability26MainPhase05 -RunState $RunState
  . Invoke-Capability26MainPhase06 -RunState $RunState
  . Invoke-Capability26MainPhase07 -RunState $RunState
  . Invoke-Capability26MainPhase08 -RunState $RunState
  . Invoke-Capability26MainPhase09 -RunState $RunState
}

function Get-Capability26ResultToken {
  param([hashtable]$RunState)
  $resultToken = if ($findings.Count -gt 0) { 'WARN' } else { 'OK' }
  if ($Strict -and $resultToken -eq 'WARN') { $resultToken = 'FAIL' }
  $RunState.summary = [pscustomobject]@{
    ComputerName    = $env:COMPUTERNAME
    Timestamp       = Get-Date
    EventsReturned  = @($RunState.events).Count
    ExportRequested = $exportRequested
    ExportPath      = $(if ($exportRequested) { $ExportPath } else { $null })
    Exported        = $RunState.exported
    ExportError     = $RunState.exportError
  }
  return $resultToken
}
