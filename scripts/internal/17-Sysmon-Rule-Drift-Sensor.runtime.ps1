#requires -version 5.1
<#
.SYNOPSIS
Runtime query, remediation, and presentation helpers for the Sysmon sensor.

.DESCRIPTION
Provides bounded event-query, remediation-closure, result, and console helpers
loaded by the primary Sysmon helper after repository trust validation.
#>

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
function Get-SysmonChannelXmlValue {
  param($Xml, [string]$Property)
  try { return $Xml.channel.$Property.'#text' } catch { return $null }
}
function Get-SysmonChannelMaxSize {
  param($Xml)
  try { return $Xml.channel.logging.maxSize.'#text' } catch { return $null }
}
function Get-SysmonChannelStatus {
  $info = [pscustomobject]@{
    LogName = $script:SysmonLogName
    Exists  = $false
    Enabled = $false
    MaxSize = 0
    OldestRecord = $null
    Error = $null
  }
  try {
    # S9 fix: use Invoke-Wevtutil wrapper with array-based args instead of direct wevtutil call
    $wevtResult = Invoke-Wevtutil -Arguments @('gl', $script:SysmonLogName, '/f:xml') -CaptureOutput
    if ((Test-AllConditions -Conditions @({ $wevtResult }, { -not $wevtResult.Success }))) {
      $info.Error = (@($wevtResult.Output) -join [Environment]::NewLine).Trim()
      return $info
    }
    $xml = if ((Test-AllConditions -Conditions @({ $wevtResult }, { $wevtResult.Output }))) { (@($wevtResult.Output) -join [Environment]::NewLine) } else { $null }
    if (-not $xml) { return $info }
    $x = [xml]$xml
    $info.Exists = $true
    $enabledText = Get-SysmonChannelXmlValue -Xml $x -Property 'enabled'
    if ((Test-AllConditions -Conditions @({ $null -ne $enabledText }, { $enabledText -ne '' }))) {
      $info.Enabled = [bool]::Parse([string]$enabledText)
    }
    $maxText = Get-SysmonChannelMaxSize -Xml $x
    if ($maxText) { $info.MaxSize = [int64]$maxText }
  } catch {
    $info.Error = $_.Exception.Message
  }
  return $info
}

function Enable-SysmonChannelIfRequested {
  param([pscustomobject]$ChannelStatus)
  if ($Mode -ne 'Remediate' -or -not $AttemptEnableChannel) { return $ChannelStatus }
  if (-not $ChannelStatus.Exists) { return $ChannelStatus }
  if ($ChannelStatus.Enabled) { return $ChannelStatus }
  if (-not (Test-IsAdmin)) { return $ChannelStatus }
  try {
    # S9 fix: use Invoke-Wevtutil wrapper with array-based args instead of direct wevtutil call
    Invoke-Wevtutil -Arguments @('sl', $script:SysmonLogName, '/e:true') | Out-Null
  } catch {
    Write-Verbose ("Sysmon channel enable failed: {0}" -f $_.Exception.Message)
  }
  return (Get-SysmonChannelStatus)
}

function Invoke-BoundedSysmonEventQuerySection01 {
  param([hashtable]$RunState)
$RunState.pipeline = [powershell]::Create()
  $RunState.async = $null
  $RunState.events = @(); $RunState.queryError = $null; $RunState.timedOut = $false
  $RunState.stopwatch = [Diagnostics.Stopwatch]::StartNew()
}

function Complete-BoundedSysmonEventQuery {
  param([hashtable]$RunState)
      $invokeException = $null
      try { $RunState.events = @($RunState.pipeline.EndInvoke($RunState.async)) } catch { $invokeException = $_.Exception.Message }
      $queryErrors = @($RunState.pipeline.Streams.Error)
      $materialErrors = @($queryErrors | Where-Object { $_.FullyQualifiedErrorId -notmatch '^NoMatchingEventsFound(?:,|$)' })
      if ($materialErrors.Count -gt 0) { $RunState.queryError = ($materialErrors | ForEach-Object { $_.Exception.Message } | Select-Object -Unique) -join '; ' }
      elseif ((Test-AllConditions -Conditions @({ $invokeException }, { $queryErrors.Count -eq 0 }))) { $RunState.queryError = $invokeException }
}
function Invoke-BoundedSysmonEventQuerySection02 {
  param([hashtable]$RunState)
try {
    [void]$RunState.pipeline.AddCommand('Get-WinEvent').AddParameter('FilterHashtable',$RunState.FilterHashtable).AddParameter('MaxEvents',($RunState.MaximumEvents + 1)).AddParameter('ErrorAction','Stop')
    $RunState.async = $RunState.pipeline.BeginInvoke()
    if (-not $RunState.async.AsyncWaitHandle.WaitOne([TimeSpan]::FromSeconds($RunState.MaximumSeconds))) {
      $RunState.timedOut = $true
      try { $RunState.pipeline.Stop() } catch { Write-Verbose "Stopping timed-out Sysmon event query failed: $($_.Exception.Message)" }
    } else {
      . Complete-BoundedSysmonEventQuery -RunState $RunState
    }
  } catch { $RunState.queryError = $_.Exception.Message }
  finally {
    $RunState.stopwatch.Stop()
    if ((Test-AllConditions -Conditions @({ $RunState.async }, { $RunState.async.AsyncWaitHandle }))) { $RunState.async.AsyncWaitHandle.Close() }
    $RunState.pipeline.Dispose()
  }
}

function Invoke-BoundedSysmonEventQuerySection03 {
  param([hashtable]$RunState)
[pscustomobject]@{ Events = $RunState.events; Error = $RunState.queryError; TimedOut = $RunState.timedOut; ElapsedMilliseconds = $RunState.stopwatch.ElapsedMilliseconds }
}

function Invoke-BoundedSysmonEventQuery {
  param(
    [Parameter(Mandatory)][hashtable]$FilterHashtable,
    [Parameter(Mandatory)][int]$MaximumEvents,
    [Parameter(Mandatory)][int]$MaximumSeconds
  , [hashtable]$RunState)
  $RunState.FilterHashtable = $FilterHashtable
  $RunState.MaximumEvents = $MaximumEvents
  $RunState.MaximumSeconds = $MaximumSeconds
    . Invoke-BoundedSysmonEventQuerySection01 -RunState $RunState
    . Invoke-BoundedSysmonEventQuerySection02 -RunState $RunState
    . Invoke-BoundedSysmonEventQuerySection03 -RunState $RunState
}

function Get-BoundedSysmonEventEvidence {
  param(
    [Parameter(Mandatory)][int[]]$EventIds,
    [Parameter(Mandatory)][datetime]$StartTime,
    [Parameter(Mandatory)][int]$MaximumEvents,
    [Parameter(Mandatory)][int]$MaximumSeconds
  , [hashtable]$RunState)
  $uniqueIds = @($EventIds | Sort-Object -Unique)
  $RunState.stopwatch = [Diagnostics.Stopwatch]::StartNew()
  $RunState.events = New-Object System.Collections.Generic.List[object]
  $truncated = $false; $RunState.timedOut = $false; $RunState.queryError = $null
  try {
    $filter = @{ LogName = $script:SysmonLogName; ID = $uniqueIds; StartTime = $StartTime }
    $query = Invoke-BoundedSysmonEventQuery -FilterHashtable $filter -MaximumEvents $MaximumEvents -MaximumSeconds $MaximumSeconds -RunState $RunState
    $RunState.queryError = $query.Error; $RunState.timedOut = [bool]$query.TimedOut
    foreach ($eventRecord in @($query.Events)) {
      if ($RunState.stopwatch.Elapsed.TotalSeconds -ge $MaximumSeconds) { $RunState.timedOut = $true; break }
      if ($RunState.events.Count -ge $MaximumEvents) { $truncated = $true; break }
      [void]$RunState.events.Add($eventRecord)
    }
  } catch { $RunState.queryError = $_.Exception.Message }
  finally { if ($RunState.stopwatch.Elapsed.TotalSeconds -ge $MaximumSeconds) { $RunState.timedOut = $true }; $RunState.stopwatch.Stop() }
  [pscustomobject]@{
    Complete = [bool]((Test-AllConditions -Conditions @({ (Test-AllConditions -Conditions @({ -not $RunState.queryError }, { -not $truncated })) }, { -not $RunState.timedOut })))
    Truncated = $truncated
    TimedOut = $RunState.timedOut
    Error = Get-SysmonEvidenceError -QueryError $RunState.queryError -TimedOut $RunState.timedOut -Truncated $truncated
    EventIds = $uniqueIds
    EventsRead = $RunState.events.Count
    MaximumEvents = $MaximumEvents
    MaximumSeconds = $MaximumSeconds
    ElapsedMilliseconds = $RunState.stopwatch.ElapsedMilliseconds
    Events = @($RunState.events.ToArray())
  }
}

function Get-SysmonEvidenceError {
  param([string]$QueryError, [bool]$TimedOut, [bool]$Truncated)
  if ($QueryError) { return $QueryError }
  if ($TimedOut) { return 'Event query or processing exceeded its global wall-clock budget.' }
  if ($Truncated) { return 'Event evidence exceeded the global event-count budget.' }
  return $null
}

function New-SysmonMessageRegex {
  param([string]$Pattern)
  if ([string]::IsNullOrWhiteSpace($Pattern)) { return $null }
  return [regex]::new($Pattern,[Text.RegularExpressions.RegexOptions]::CultureInvariant,[TimeSpan]::FromSeconds(1))
}

function Get-EventCountFromEvidence {
  param([Parameter(Mandatory)]$Evidence,[Parameter(Mandatory)][int]$EventId,[string]$MessageRegex,[Parameter(Mandatory)][Diagnostics.Stopwatch]$WorkStopwatch,[Parameter(Mandatory)][int]$MaximumSeconds, [hashtable]$RunState)
  $RunState.EventId = $EventId
  if (-not $Evidence.Complete) {
    $errorText = if ($Evidence.Error) { $Evidence.Error } else { 'Event evidence is incomplete or truncated.' }
    return [pscustomobject]@{ Success = $false; Count = $null; Error = $errorText }
  }
  try {
    $rx = New-SysmonMessageRegex -Pattern $MessageRegex
    $count = 0
    foreach ($eventRecord in @($Evidence.Events)) {
      if ($WorkStopwatch.Elapsed.TotalSeconds -ge $MaximumSeconds) { return [pscustomobject]@{ Success = $false; Count = $null; Error = 'Event processing exceeded its global wall-clock budget.' } }
      if ((Test-AllConditions -Conditions @({ [int]$eventRecord.Id -eq $EventId }, { ((Test-AnyCondition -Conditions @({ $null -eq $rx }, { $rx.IsMatch([string]$eventRecord.Message) }))) }))) { $count++ }
    }
    return [pscustomobject]@{ Success = $true; Count = $count; Error = $null }
  } catch { return [pscustomobject]@{ Success = $false; Count = $null; Error = $_.Exception.Message } }
}

function Resolve-SysmonOverallStatus {
  param([object[]]$Rules,[bool]$StateWriteOk,[bool]$EvidenceComplete)
  if (-not $EvidenceComplete -or @($Rules | Where-Object { $_.Status -in @('QUERY_ERROR','INCOMPLETE') }).Count -gt 0) { return 'ERROR' }
  if (@($Rules | Where-Object { $_.Status -ne 'OK' }).Count -gt 0 -or -not $StateWriteOk) { return 'ANOMALIES_DETECTED' }
  return 'OK'
}

function Resolve-RemediationScriptPath {
  param([Parameter(Mandatory)][string]$ScriptPath)
  $scriptRoot = Split-Path -Parent $PSScriptRoot  # repo root
  $scriptsDir = Join-Path $scriptRoot 'scripts'
  try {
    $resolvedScriptsDir = Resolve-Path -LiteralPath $scriptsDir -ErrorAction Stop
    $resolvedScriptPath = Resolve-Path -LiteralPath $ScriptPath -ErrorAction Stop
  } catch {
    throw "Resolve-RemediationScriptPath: ScriptPath '$ScriptPath' is missing or cannot be resolved."
  }
  $canonicalScriptsDir = $resolvedScriptsDir.ProviderPath
  $canonicalScriptPath = $resolvedScriptPath.ProviderPath
  if (-not (Test-PathUnderRoot -Path $canonicalScriptPath -Root $canonicalScriptsDir)) {
    throw "Resolve-RemediationScriptPath: ScriptPath '$ScriptPath' is not under the expected scripts directory."
  }
  if (Test-PathContainsReparsePoint -Path $resolvedScriptPath.Path -Root $resolvedScriptsDir.Path) {
    throw "Resolve-RemediationScriptPath: ScriptPath '$ScriptPath' traverses a reparse point."
  }
  $scriptFileName = Split-Path -Leaf $canonicalScriptPath
  if (-not (Test-SafeScriptName -Name $scriptFileName)) {
    throw "Resolve-RemediationScriptPath: ScriptPath file name '$scriptFileName' failed safety validation."
  }
  try {
    $scriptItem = Get-Item -LiteralPath $canonicalScriptPath -Force -ErrorAction Stop
  } catch {
    throw "Resolve-RemediationScriptPath: ScriptPath '$ScriptPath' is missing or cannot be inspected."
  }
  if ($scriptItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
    throw "Resolve-RemediationScriptPath: ScriptPath '$ScriptPath' is a reparse point."
  }
  return $canonicalScriptPath
}

function Get-SysmonRemediationExecutionClosure {
  param([Parameter(Mandatory)][string]$ScriptPath)
  # The updater resolves only these files before it starts privileged work. Keep
  # this list explicit: discovering arbitrary files from lib would make the
  # trusted execution boundary depend on directory contents.
  $scriptsDirectory = Split-Path -Parent $ScriptPath
  $repositoryRoot = Split-Path -Parent $scriptsDirectory
  $expectedEntryScript = Join-Path $scriptsDirectory '16-Sysmon-Config-Updater.ps1'
  if (-not [string]::Equals([IO.Path]::GetFullPath($ScriptPath), [IO.Path]::GetFullPath($expectedEntryScript), [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Remediation execution is restricted to 16-Sysmon-Config-Updater.ps1.'
  }

  $closurePaths = @(
    $expectedEntryScript,
    (Join-Path $scriptsDirectory 'internal\16-Sysmon-Config-Updater.helpers.ps1'),
    (Join-Path $scriptsDirectory '_lib\Bootstrap.ps1')
  )
  foreach ($moduleName in @('Output.psm1','Common.psm1','EventLog.psm1','Evidence.psm1','External.psm1','Results.psm1','Serialization.psm1','Validation.psm1')) {
    $closurePaths += Join-Path $repositoryRoot (Join-Path 'lib' $moduleName)
  }
  # External.psm1 dot-sources these platform implementations. Lock them with
  # the facade so a privileged launch cannot observe an unlocked code path.
  foreach ($platformFile in @('Executable.ps1','NativeProcess.ps1','NativeTools.ps1','WindowsOperations.ps1')) {
    $closurePaths += Join-Path $repositoryRoot (Join-Path 'lib\platform' $platformFile)
  }
  return @($closurePaths)
}

function Assert-LockedSysmonRemediationClosure {
  param(
    [Parameter(Mandatory)][string[]]$ClosurePaths,
    [Parameter(Mandatory)][string]$RepositoryRoot
  )
  foreach ($closurePath in $ClosurePaths) {
    $item = Get-Item -LiteralPath $closurePath -Force -ErrorAction Stop
    if ($item.PSIsContainer -or (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) -or (Test-PathContainsReparsePoint -Path $item.FullName -Root $RepositoryRoot)) {
      throw 'Remediation execution closure contains a reparse point or non-file item.'
    }
    Assert-TrustedWindowsPathAcl -Path $item.FullName -CheckAncestors | Out-Null
  }
}

function Open-SysmonRemediationClosure {
    $scriptsDirectory = Split-Path -Parent $ScriptPath
    $repositoryRoot = Split-Path -Parent $scriptsDirectory
    $closurePaths = Get-SysmonRemediationExecutionClosure -ScriptPath $ScriptPath
    $stage = [pscustomobject]@{ Path = $ScriptPath; Streams = @() }
    foreach ($closurePath in $closurePaths) {
      $item = Get-Item -LiteralPath $closurePath -Force -ErrorAction Stop
      $stage.Streams += [IO.File]::Open($item.FullName, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    }
    Assert-LockedSysmonRemediationClosure -ClosurePaths $closurePaths -RepositoryRoot $repositoryRoot
}
function Assert-SysmonRemediationSignature {
  param([hashtable]$RunState)
    if (-not $RunState.RequireSignature) { return }
    $signature = Get-AuthenticodeSignature -FilePath $ScriptPath -ErrorAction Stop
    if ($signature.Status -ne 'Valid') { throw "Remediation script signature is not valid: $($signature.Status)." }
}
function Invoke-SysmonRemediationProcess {
  param([hashtable]$RunState)
    $argList = @('-NoProfile')
    if ($AllowExecutionPolicyBypass) { $argList += @('-ExecutionPolicy', 'Bypass') }
    $argList += @('-File', $stage.Path, '-Mode', 'Remediate')
    $native = Invoke-NativeCommand -Command $windowsPowerShell -Arguments $argList -CaptureOutput -Quiet -TimeoutSeconds 300 -MaxOutputBytes 65536
    $RunState.result.ExitCode = if ($native) { $native.ExitCode } else { $null }
    $RunState.result.Success = [bool]((Test-AllConditions -Conditions @({ (Test-AllConditions -Conditions @({ (Test-AllConditions -Conditions @({ $native }, { $native.Success })) }, { -not $native.TimedOut })) }, { -not $native.OutputTruncated })) -and -not $native.StderrTruncated)
    if ((Test-AllConditions -Conditions @({ -not $RunState.result.Success }, { $native }))) { $RunState.result.Error = (($native.Stderr, $native.Stdout | Where-Object { $_ }) -join [Environment]::NewLine).Trim() }
}
function Invoke-RemediationScript {
  [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
  param(
    [Parameter(Mandatory)][string]$ScriptPath,
    [switch]$RequireSignature
  , [hashtable]$RunState)
  $RunState.RequireSignature = $RequireSignature
  $ScriptPath = Resolve-RemediationScriptPath -ScriptPath $ScriptPath
  $stage = $null
  $RunState.result = [pscustomobject]@{
    Attempted = $true
    Success = $false
    ExitCode = $null
    Error = $null
    ScriptPath = $ScriptPath
  }
  try {
    $windowsPowerShell = Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::System)) 'WindowsPowerShell\v1.0\powershell.exe'
    if ((Test-AnyCondition -Conditions @({ -not [System.IO.Path]::IsPathRooted($windowsPowerShell) }, { -not (Test-Path -LiteralPath $windowsPowerShell -PathType Leaf) }))) { throw 'The absolute Windows PowerShell executable could not be found.' }
    $windowsPowerShell = (Assert-TrustedWindowsPathAcl -Path $windowsPowerShell -CheckAncestors).FullName
    if (-not $PSCmdlet.ShouldProcess($ScriptPath, 'Launch trusted remediation PowerShell process')) {
      $RunState.result.Attempted = $false
      return $RunState.result
    }
    # Do not stage a lone entry script: it changes PSScriptRoot and breaks its
    # trusted imports. Instead, lock the explicit original execution closure
    # before evaluating ACLs or the entry script signature, and keep every
    # deny-write/delete handle open until the child process exits.
    . Open-SysmonRemediationClosure
    Assert-SysmonRemediationSignature -RunState $RunState
    . Invoke-SysmonRemediationProcess -RunState $RunState
  } catch {
    $RunState.result.Error = $_.Exception.Message
  } finally {
    if ($stage) {
      foreach ($stream in @($stage.Streams)) { $stream.Dispose() }
    }
  }
  return $RunState.result
}

function Get-RuleResult {
  param($Data)
  [pscustomobject]@{
    Id = $Data.Id
    Name = $Data.Name
    Count = $Data.Count
    PriorBaseline = $Data.PriorBaseline
    Baseline = $Data.NewBaseline
    Ratio = $Data.Ratio
    MinPerWindow = $Data.MinPerWindow
    IsCritical = $Data.IsCritical
    Status = $Data.Status
    MessageRegex = $Data.MessageRegex
    QueryError = $Data.QueryError
  }
}

function Get-FinalResult {
  param([Parameter(Mandatory)]$Data)
  $OverallStatus = [string]$Data.OverallStatus
  $StartTime = [datetime]$Data.StartTime
  $ChannelStatus = $Data.ChannelStatus
  $ConfigChanged = $Data.ConfigChanged
  $Remediation = $Data.Remediation
  $Rules = @($Data.Rules)
  $Evidence = $Data.Evidence
  $CatalogSource = [string]$Data.CatalogSource
  $StatePathUsed = [string]$Data.StatePathUsed
  $StateWriteOk = [bool]$Data.StateWriteOk
  $anoms = ($Rules | Where-Object { $_.Status -ne 'OK' } | Measure-Object).Count
  $hardZeros = ($Rules | Where-Object { $_.Status -eq 'HARDZERO' } | Measure-Object).Count
  [pscustomobject]@{
    Timestamp = (Get-Date).ToString('s')
    HostName = $env:COMPUTERNAME
    WindowHours = $WindowHours
    StartTime = $StartTime.ToString('s')
    Status = $OverallStatus
    CatalogSource = $CatalogSource
    StatePath = $StatePathUsed
    StateWriteOk = $StateWriteOk
    ConfigChanged = $ConfigChanged
    Evidence = $Evidence
    Channel = $ChannelStatus
    Remediation = $Remediation
    Summary = [pscustomobject]@{
      TotalRules = $Rules.Count
      Anomalies = $anoms
      HardZero = $hardZeros
    }
    Rules = $Rules
  }
}

function Show-ConsoleSummarySection01 {
  param([hashtable]$RunState)
$statusColor = Get-StatusColor -Status $RunState.Result.Status
  Write-UiSeparator -Char '=' -Width 78 -Style 'Cyan'
  Write-ConsoleLine -Text ("Sysmon Drift Sensor  |  Host: {0}  |  Time: {1}" -f $RunState.Result.HostName, $RunState.Result.Timestamp) -Color 'Cyan'
  Write-UiSeparator -Char '=' -Width 78 -Style 'Cyan'
  Write-ConsoleLine -Text ("Status: {0}" -f $RunState.Result.Status) -Color $statusColor
  Write-ConsoleLine -Text ("WindowHours: {0} | Rules: {1} | Anomalies: {2} | HardZero: {3}" -f $RunState.Result.WindowHours, $RunState.Result.Summary.TotalRules, $RunState.Result.Summary.Anomalies, $RunState.Result.Summary.HardZero) -Color 'White'
  $oldestTxt = 'n/a'
  if ($RunState.Result.Channel.OldestRecord) { $oldestTxt = $RunState.Result.Channel.OldestRecord.ToString('s') }
  Write-ConsoleLine -Text ("Channel: Exists={0} Enabled={1} Oldest={2}" -f $RunState.Result.Channel.Exists, $RunState.Result.Channel.Enabled, $oldestTxt) -Color 'White'
  if ($RunState.Result.Channel.Error) {
    Write-ConsoleLine -Text ("ChannelError: {0}" -f $RunState.Result.Channel.Error) -Color 'Yellow'
  }
  Write-ConsoleLine -Text ("ConfigChangedInWindow: {0}" -f $RunState.Result.ConfigChanged) -Color 'White'
  Write-ConsoleLine -Text ("Catalog: {0}" -f $RunState.Result.CatalogSource) -Color 'White'
  Write-ConsoleLine -Text ("State: {0} | WriteOk: {1}" -f $RunState.Result.StatePath, $RunState.Result.StateWriteOk) -Color 'White'
}

function Show-ConsoleSummarySection02 {
  param([hashtable]$RunState)
if ($RunState.Result.Remediation -and $RunState.Result.Remediation.Attempted) {
    $rc = 'Yellow'
    if ($RunState.Result.Remediation.Success) { $rc = 'Green' }
    if (-not $RunState.Result.Remediation.Success) { $rc = 'Red' }
    Write-ConsoleLine -Text ("Remediation: Success={0} ExitCode={1}" -f $RunState.Result.Remediation.Success, $RunState.Result.Remediation.ExitCode) -Color $rc
    if ($RunState.Result.Remediation.Error) {
      Write-ConsoleLine -Text ("RemediationError: {0}" -f $RunState.Result.Remediation.Error) -Color 'Yellow'
    }
  }
}

function Show-ConsoleSummarySection03 {
  param([hashtable]$RunState)
if ($RunState.Result.Rules -and $RunState.Result.Rules.Count -gt 0) {
    $bad = @($RunState.Result.Rules | Where-Object { $_.Status -ne 'OK' } | Sort-Object Status, Id)
    if ($bad.Count -gt 0) {
      Write-UiLine ""
      Write-ConsoleLine -Text "Top anomalies:" -Color 'Cyan'
      $bad | Select-Object -First 20 | ForEach-Object {
        $c = Get-RuleStatusColor -Status $_.Status
        $baseTxt = 'n/a'
        if ($null -ne $_.PriorBaseline) { $baseTxt = ([math]::Round([double]$_.PriorBaseline, 1)).ToString() }
        $ratioTxt = 'n/a'
        if ($null -ne $_.Ratio) { $ratioTxt = $_.Ratio.ToString() }
        Write-ConsoleLine -Text ("  ID {0,-4} | {1,-26} | Cnt {2,-6} | Base {3,-8} | Ratio {4,-6} | {5}" -f $_.Id, $_.Name, $_.Count, $baseTxt, $ratioTxt, $_.Status) -Color $c
      }
      if ($bad.Count -gt 20) {
        Write-ConsoleLine -Text ("  ... and {0} more" -f ($bad.Count - 20)) -Color 'Gray'
      }
    }
  }
}

function Show-ConsoleSummarySection04 {
  param([hashtable]$RunState)
if ($RunState.Result.Status -eq 'CHANNEL_UNAVAILABLE') {
    Write-UiLine ""
    Write-ConsoleLine -Text "Next steps:" -Color 'Cyan'
    Write-ConsoleLine -Text "  - Check if Sysmon is installed and running (Sysmon/Sysmon64 service)." -Color 'Gray'
    Write-ConsoleLine -Text "  - List logs: wevtutil el | findstr /i sysmon" -Color 'Gray'
    Write-ConsoleLine -Text "  - If log exists but disabled: run as admin and enable it: wevtutil sl Microsoft-Windows-Sysmon/Operational /e:true" -Color 'Gray'
  }
  Write-UiSeparator -Char '=' -Width 78 -Style 'Cyan'
  Write-UiLine ""
}

function Show-ConsoleSummary {
  param([Parameter(Mandatory)][pscustomobject]$Result, [hashtable]$RunState)
  $RunState.Result = $Result
    . Show-ConsoleSummarySection01 -RunState $RunState
    . Show-ConsoleSummarySection02 -RunState $RunState
    . Show-ConsoleSummarySection03 -RunState $RunState
    . Show-ConsoleSummarySection04 -RunState $RunState
}
