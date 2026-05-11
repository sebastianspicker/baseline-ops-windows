#requires -version 5.1
<#
.SYNOPSIS
Detects Sysmon event rule drift within a configurable time window and reports anomalies.
.DESCRIPTION
This script monitors the Sysmon Operational event log and evaluates event-count "drift" for a defined set of Sysmon Event IDs.
It compares the current event volume in a time window against an exponentially weighted moving average (EMA) baseline that is persisted to disk.
Typical use cases:
- Detect missing Sysmon coverage (e.g., a critical event type stops appearing).
- Detect reduced telemetry (drift down) caused by misconfiguration, tampering, log disablement, or agent issues.
- Optionally detect surges (abnormally high volume) for selected rules.
- Optionally trigger a remediation script when a critical rule is at HARDZERO.
How it works:
1) Load a rule catalog from JSON (or fall back to safe defaults).
2) Load the persisted baseline state from JSON (or initialize an empty baseline).
3) Count Sysmon events per rule within the last WindowHours.
4) Determine a rule status:
   - OK: Within expected range.
   - HARDZERO: A critical rule has Count = 0.
   - LOW: Count is below MinPerWindow.
   - DRIFT_DOWN: Ratio (Count / Baseline) is below RatioFloor.
   - SURGE: Ratio is above RatioUpper (only if -IncludeSurge is set).
5) Update the baseline using EMA (or overwrite baseline with the current counts if -Rebaseline is set).
6) Persist the updated baseline state to StatePath.
7) Optionally execute remediation if at least one rule is HARDZERO and -TriggerReapply is set.
8) Write an audit summary to the Windows Application event log (custom source).
9) Print a human-friendly console summary (unless -PassThru is used).
Catalog JSON model (conceptual):
- Rules: array of rule objects with:
  - Id (int): Sysmon Event ID
  - Name (string, optional)
  - Critical (bool, optional)
  - MinPerWindow (int, optional)
  - MessageRegex (string, optional): Only count events where the message matches this regex
  - Disabled (bool, optional)
Baseline model:
- For each Event ID, a floating-point baseline value is stored and updated using EMA.
.PARAMETER WindowHours
The size of the analysis window in hours.
Events are counted from (Now - WindowHours) until Now.
.PARAMETER CatalogPath
Path to the JSON catalog file that defines which Sysmon Event IDs to monitor and how to evaluate them.
If the catalog cannot be loaded, a safe default catalog is used.
.PARAMETER StatePath
Path to the JSON state file used to persist baselines between runs.
If the state file cannot be read, a fresh baseline state is used.
If the state file cannot be written, the run is marked as not OK.
.PARAMETER Alpha
EMA smoothing factor in range 0.01..1.0.
Higher values adapt the baseline faster to recent changes; lower values smooth more strongly.
.PARAMETER RatioFloor
Lower threshold for DRIFT_DOWN.
If Baseline >= MinBaselineToCompare and (Count / Baseline) < RatioFloor, the rule status becomes DRIFT_DOWN.
.PARAMETER RatioUpper
Upper threshold for SURGE.
If -IncludeSurge is set and Baseline >= MinBaselineToCompare and (Count / Baseline) > RatioUpper, the rule status becomes SURGE.
.PARAMETER IncludeSurge
Enables SURGE detection (disabled by default).
When not set, ratios above RatioUpper do not change the status (only drift-down is evaluated).
.PARAMETER MinBaselineToCompare
Minimum baseline value required before ratios are evaluated.
This prevents unstable ratio decisions while the baseline is still "warming up" or when volumes are near zero.
.PARAMETER Rebaseline
If set, overwrites each baseline value with the current window count (no EMA smoothing for that run).
Useful after known environment changes or after deploying a new Sysmon configuration.
.PARAMETER TriggerReapply
If set, triggers remediation when at least one rule is HARDZERO.
Remediation is only attempted if the remediation script passes policy checks (existence and optional signature requirement).
.PARAMETER RemediationScriptPath
Path to the remediation script that is called when remediation is triggered.
The script is started in a new PowerShell process with additional parameters: -Mode Remediate.
.PARAMETER RequireSignedRemediationScript
If set, remediation will only be executed if RemediationScriptPath has a valid Authenticode signature.
If the signature is missing or invalid, remediation is blocked and reported.
.PARAMETER AllowExecutionPolicyBypass
If set, the remediation process is started with -ExecutionPolicy Bypass.
Use only if you explicitly require it for your environment.
.PARAMETER UseBuiltInDefaultRules
If the catalog cannot be loaded, use a small built-in rule set instead of an empty catalog.
If not set (default), catalog fallback uses an empty rule list to avoid false positives.
.PARAMETER AttemptEnableChannel
If the Sysmon channel exists but is disabled, optionally attempt to enable it.
This requires elevated permissions. If the channel cannot be enabled, the script continues with CHANNEL_UNAVAILABLE.
.PARAMETER PassThru
Pipeline mode:
- If set, the script outputs a single structured result object to the pipeline.
- If not set, the script prints a formatted console summary and does not emit pipeline output.
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
When -PassThru is specified:
A single PSCustomObject with these top-level properties (subject to minor extensions):
- Timestamp (string)
- HostName (string)
- WindowHours (int)
- StartTime (string)
- Status (string): OK | ANOMALIES_DETECTED | CHANNEL_UNAVAILABLE | ERROR
- CatalogSource (string): Path or DEFAULT
- StatePath (string)
- StateWriteOk (bool)
- ConfigChanged (bool): Whether Sysmon configuration change events were detected in the window
- Channel (object): Sysmon channel status details
- Remediation (object or null): remediation attempt details (Attempted, Success, ExitCode, Error, ScriptPath)
- Summary (object): TotalRules, Anomalies, HardZero
- Rules (array): per-rule results suitable for Export-Csv and filtering
When -PassThru is not specified:
No pipeline output. A formatted human-readable summary is printed to the console.
.EXAMPLE
Run with default settings (console summary output):
.\17-Sysmon-Rule-Drift-Sensor.ps1
.EXAMPLE
Pipeline mode: export per-rule results to CSV:
$result = .\17-Sysmon-Rule-Drift-Sensor.ps1 -PassThru
$result.Rules | Export-Csv -NoTypeInformation -Path .\sysmon-drift.csv
.EXAMPLE
Pipeline mode: fail a CI/task if any HARDZERO is present:
$result = .\17-Sysmon-Rule-Drift-Sensor.ps1 -PassThru
if ($result.Rules | Where-Object { $_.Status -eq 'HARDZERO' }) { exit 1 }
.EXAMPLE
Enable surge detection:
.\17-Sysmon-Rule-Drift-Sensor.ps1 -IncludeSurge
.EXAMPLE
Force a full baseline reset (rebaseline):
.\17-Sysmon-Rule-Drift-Sensor.ps1 -Rebaseline
.EXAMPLE
Run with remediation enabled (and require signed remediation script):
.\17-Sysmon-Rule-Drift-Sensor.ps1 -TriggerReapply -RequireSignedRemediationScript
.EXAMPLE
Run with custom catalog and state paths:
.\17-Sysmon-Rule-Drift-Sensor.ps1 `
  -CatalogPath "PATH/TO/JSON/drift-catalog.json" `
  -StatePath "PATH/TO/JSON/drift_state.json"
.NOTES
Behavioral details and gotchas:
- Regex filtering (MessageRegex) requires reading the event message and can be slower; use sparingly and only when needed.
- A rule ratio is only calculated when the stored baseline is large enough (MinBaselineToCompare).
- If the Sysmon channel is missing/disabled, the script reports CHANNEL_UNAVAILABLE and does not evaluate rules.
- Remediation is triggered only by HARDZERO, not by LOW/DRIFT_DOWN/SURGE.
- The script is designed to be run repeatedly (e.g., scheduled task) to build and maintain baselines over time.
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
  [ValidateRange(1,168)]
  [int]$WindowHours = 24,
  [string]$CatalogPath,
  [string]$StatePath,
  [ValidateRange(0.01,1.0)]
  [double]$Alpha = 0.3,
  [ValidateRange(0.0,1.0)]
  [double]$RatioFloor = 0.3,
  [ValidateRange(1.0,1000.0)]
  [double]$RatioUpper = 3.0,
  [switch]$IncludeSurge,
  [ValidateRange(0,1000000)]
  [int]$MinBaselineToCompare = 10,
  [switch]$Rebaseline,
  [switch]$TriggerReapply,
  [string]$RemediationScriptPath,
  [switch]$RequireSignedRemediationScript,
  [switch]$AllowExecutionPolicyBypass,
  [switch]$UseBuiltInDefaultRules,
  [switch]$AttemptEnableChannel,
  [switch]$PassThru
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
Import-Module (Join-Path $script:LibPath 'Common.psm1') -Force -DisableNameChecking
Import-Module (Join-Path $script:LibPath 'Output.psm1') -Force
Import-Module (Join-Path $script:LibPath 'EventLog.psm1') -Force
Import-Module (Join-Path $script:LibPath 'External.psm1') -Force -DisableNameChecking
Import-Module (Join-Path $script:LibPath 'Validation.psm1') -Force
Import-Module (Join-Path $script:LibPath 'JsonCatalog.psm1') -Force
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

$isWindowsHost = ($env:OS -eq 'Windows_NT')
if (-not $isWindowsHost) {
  $summary = [pscustomobject]@{
    ComputerName = $env:COMPUTERNAME
    Timestamp    = Get-Date
    Mode         = $Mode
    Supported    = $false
    Notes        = @('Skipped: this script is only supported on Windows hosts.')
  }
  $result = New-V2ResultObject -ScriptName '17-Sysmon-Rule-Drift-Sensor.ps1' -Mode $Mode -Result 'OK' -Findings @() -Summary $summary -Metadata @{ UnsupportedHost = $true }
  Write-ResultObject -ResultObject $result -OutputFormat $OutputFormat -OutputPath $OutputPath
  if ($PassThru) { $result }
  exit 0
}

# -----------------------------
# Constants (ASCII only)
# -----------------------------
$script:SysmonLogName          = 'Microsoft-Windows-Sysmon/Operational'
$script:EventLogName           = 'Application'
$script:EventSourceName        = 'SysmonDriftSensor'
$script:EventIdOk              = 4720
$script:EventIdWarn            = 4730
$script:MaxEventMessageLength  = 30000
# -----------------------------
# Console helpers (no pipeline output)
# -----------------------------
function Get-StatusColor {
  param([string]$Status)
  switch ($Status) {
    'OK'                 { 'Green'; break }
    'ANOMALIES_DETECTED' { 'Yellow'; break }
    'CHANNEL_UNAVAILABLE'{ 'Red'; break }
    'ERROR'              { 'Red'; break }
    default              { 'Yellow'; break }
  }
}
function Get-RuleStatusColor {
  param([string]$Status)
  switch ($Status) {
    'OK'         { 'Green'; break }
    'HARDZERO'   { 'Red'; break }
    'LOW'        { 'Yellow'; break }
    'DRIFT_DOWN' { 'Yellow'; break }
    'SURGE'      { 'Yellow'; break }
    default      { 'Yellow'; break }
  }
}
# -----------------------------
# Utility: Hashtable normalization
# -----------------------------
function ConvertTo-Hashtable {
  param([object]$InputObject)
  if ($null -eq $InputObject) { return @{} }
  if ($InputObject -is [hashtable]) { return $InputObject }
  if ($InputObject -is [System.Management.Automation.PSCustomObject]) {
    $ht = @{}
    foreach ($p in $InputObject.PSObject.Properties) {
      if ($p.Value -is [System.Management.Automation.PSCustomObject]) {
        $ht[$p.Name] = ConvertTo-Hashtable -InputObject $p.Value
      } else {
        $ht[$p.Name] = $p.Value
      }
    }
    return $ht
  }
  return @{}
}
# -----------------------------
# Utility: File IO (safe)
# -----------------------------
# Read-JsonFile replaced by Read-JsonFileSafe from lib/JsonCatalog.psm1
# Write-JsonFile: replaced by canonical Save-Json from lib/Serialization.psm1
# -----------------------------
# Catalog defaults
# -----------------------------
function New-DefaultCatalog {
  param(
    [int]$DefaultWindowHours,
    [double]$DefaultAlpha,
    [double]$DefaultRatioFloor,
    [double]$DefaultRatioUpper,
    [int]$DefaultMinBaselineToCompare,
    [switch]$WithBuiltInRules
  )
  $rules = @()
  if ($WithBuiltInRules) {
    $rules = @(
      [pscustomobject]@{ Id = 1;  Name = 'Process Create';  Critical = $true;  MinPerWindow = 1;    MessageRegex = $null; Disabled = $false },
      [pscustomobject]@{ Id = 3;  Name = 'Network Connect'; Critical = $false; MinPerWindow = $null; MessageRegex = $null; Disabled = $false },
      [pscustomobject]@{ Id = 11; Name = 'File Create';     Critical = $false; MinPerWindow = $null; MessageRegex = $null; Disabled = $false },
      [pscustomobject]@{ Id = 16; Name = 'Config Change';   Critical = $false; MinPerWindow = $null; MessageRegex = $null; Disabled = $false },
      [pscustomobject]@{ Id = 22; Name = 'DNS Query';       Critical = $false; MinPerWindow = $null; MessageRegex = $null; Disabled = $false }
    )
  }
  [pscustomobject]@{
    WindowHours = $DefaultWindowHours
    Alpha = $DefaultAlpha
    RatioFloor = $DefaultRatioFloor
    RatioUpper = $DefaultRatioUpper
    MinBaselineToCompare = $DefaultMinBaselineToCompare
    Rules = $rules
  }
}
function Load-CatalogOrDefault {
  param(
    [string]$Path,
    [pscustomobject]$DefaultCatalog
  )
  $cat = Read-JsonFileSafe -Path $Path
  if ($null -eq $cat) { return $DefaultCatalog }
  if ($null -eq $cat.Rules) {
    $cat | Add-Member -NotePropertyName Rules -NotePropertyValue @() -Force
  }
  return $cat
}
# -----------------------------
# Event Log (audit)
# -----------------------------
function Limit-EventMessage {
  param([Parameter(Mandatory)][string]$Message)
  if ($Message.Length -le $script:MaxEventMessageLength) { return $Message }
  return ($Message.Substring(0, $script:MaxEventMessageLength) + "`r`n[TRUNCATED]")
}
function Write-AuditEvent {
  param(
    [int]$EventId,
    [string]$Message,
    [ValidateSet('Information','Warning','Error')]
    [string]$Level
  )
  $msg = Limit-EventMessage -Message $Message
  try {
    Write-EventLog -LogName $script:EventLogName -Source $script:EventSourceName -EventId $EventId -EntryType $Level -Message $msg -ErrorAction Stop
  } catch {
    # Console fallback, do not emit pipeline output.
    Write-UiLine ("[{0}][{1}] {2}" -f $Level,$EventId,$msg)
  }
}
# -----------------------------
# Sysmon channel probe
# -----------------------------
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
    if ($wevtResult -and -not $wevtResult.Success) {
      $info.Error = (@($wevtResult.Output) -join [Environment]::NewLine).Trim()
      return $info
    }
    $xml = if ($wevtResult -and $wevtResult.Output) { (@($wevtResult.Output) -join [Environment]::NewLine) } else { $null }
    if (-not $xml) { return $info }
    $x = [xml]$xml
    $info.Exists = $true
    $enabledText = $null
    try { $enabledText = $x.channel.enabled.'#text' } catch { $enabledText = $null }
    if ($null -ne $enabledText -and $enabledText -ne '') {
      $info.Enabled = [bool]::Parse([string]$enabledText)
    }
    $maxText = $null
    try { $maxText = $x.channel.logging.maxSize.'#text' } catch { $maxText = $null }
    if ($maxText) { $info.MaxSize = [int64]$maxText }
    try {
      $oldest = Get-WinEvent -LogName $script:SysmonLogName -MaxEvents 1 -Oldest -ErrorAction SilentlyContinue
      if ($oldest) { $info.OldestRecord = $oldest.TimeCreated }
    } catch { <# best-effort: oldest event record may not be readable #> }
  } catch {
    $info.Error = $_.Exception.Message
  }
  return $info
}
function Enable-SysmonChannelIfRequested {
  param([pscustomobject]$ChannelStatus)
  if (-not $AttemptEnableChannel) { return $ChannelStatus }
  if (-not $ChannelStatus.Exists) { return $ChannelStatus }
  if ($ChannelStatus.Enabled) { return $ChannelStatus }
  if (-not (Test-IsAdmin)) { return $ChannelStatus }
  try {
    # S9 fix: use Invoke-Wevtutil wrapper with array-based args instead of direct wevtutil call
    Invoke-Wevtutil -Arguments @('sl', $script:SysmonLogName, '/e:true') | Out-Null
  } catch { <# best-effort: channel enable may fail without admin rights #> }
  return (Get-SysmonChannelStatus)
}
# -----------------------------
# Counting
# -----------------------------
function Get-EventCount {
  param(
    [Parameter(Mandatory)][int]$EventId,
    [Parameter(Mandatory)][datetime]$StartTime,
    [string]$MessageRegex
  )
  $filter = @{
    LogName = $script:SysmonLogName
    ID = $EventId
    StartTime = $StartTime
  }
  try {
    if ([string]::IsNullOrWhiteSpace($MessageRegex)) {
      return (Get-WinEvent -FilterHashtable $filter -ErrorAction Stop | Measure-Object).Count
    }
    $rx = [regex]::new($MessageRegex)
    return (Get-WinEvent -FilterHashtable $filter -ErrorAction Stop |
      Where-Object { $_.Message -match $rx } |
      Measure-Object
    ).Count
  } catch {
    return 0
  }
}
# -----------------------------
# Remediation
# -----------------------------
# HARDZERO remediation launches another PowerShell script, so normalize the path
# to a real file inside this repo's scripts directory before any signature check
# or process launch. This prevents catalog/profile input from selecting an
# arbitrary local script through traversal or reparse points.
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
function Test-RemediationScriptAllowed {
  param(
    [Parameter(Mandatory)][string]$ScriptPath,
    [switch]$RequireSignature
  )
  try {
    $canonicalScriptPath = Resolve-RemediationScriptPath -ScriptPath $ScriptPath
  } catch {
    return $false
  }
  if (-not $RequireSignature) { return $true }
  $sig = Get-AuthenticodeSignature -FilePath $canonicalScriptPath
  return ($sig.Status -eq 'Valid')
}
function Invoke-RemediationScript {
  [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
  param([Parameter(Mandatory)][string]$ScriptPath)
  $ScriptPath = Resolve-RemediationScriptPath -ScriptPath $ScriptPath
  $result = [pscustomobject]@{
    Attempted = $true
    Success = $false
    ExitCode = $null
    Error = $null
    ScriptPath = $ScriptPath
  }
  try {
    $argList = @('-NoProfile')
    if ($AllowExecutionPolicyBypass) {
      $argList += @('-ExecutionPolicy', 'Bypass')
    }
    $argList += @('-File', $ScriptPath, '-Mode', 'Remediate')
    if ($PSCmdlet.ShouldProcess($ScriptPath, 'Launch remediation PowerShell process')) {
      $p = Start-Process -FilePath "powershell.exe" -ArgumentList $argList -WindowStyle Hidden -PassThru -Wait -ErrorAction Stop
      $result.ExitCode = $p.ExitCode
      $result.Success = ($p.ExitCode -eq 0)
    } else {
      $result.Attempted = $false
    }
  } catch {
    $result.Error = $_.Exception.Message
  }
  return $result
}
# -----------------------------
# Result objects (pipeline)
# -----------------------------
function New-RuleResult {
  param(
    [int]$Id,
    [string]$Name,
    [int]$Count,
    [Nullable[double]]$PriorBaseline,
    [double]$NewBaseline,
    [Nullable[double]]$Ratio,
    [Nullable[int]]$MinPerWindow,
    [bool]$IsCritical,
    [string]$Status,
    [string]$MessageRegex
  )
  [pscustomobject]@{
    Id = $Id
    Name = $Name
    Count = $Count
    PriorBaseline = $PriorBaseline
    Baseline = $NewBaseline
    Ratio = $Ratio
    MinPerWindow = $MinPerWindow
    IsCritical = $IsCritical
    Status = $Status
    MessageRegex = $MessageRegex
  }
}
function New-FinalResult {
  param(
    [string]$OverallStatus,
    [datetime]$StartTime,
    [pscustomobject]$ChannelStatus,
    [bool]$ConfigChanged,
    [pscustomobject]$Remediation,
    [object[]]$Rules,
    [string]$CatalogSource,
    [string]$StatePathUsed,
    [bool]$StateWriteOk
  )
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
# -----------------------------
# Console summary (no pipeline pollution)
# -----------------------------
function Show-ConsoleSummary {
  param([Parameter(Mandatory)][pscustomobject]$Result)
  $statusColor = Get-StatusColor -Status $Result.Status
  Write-UiSeparator -Char '=' -Width 78 -Style 'Cyan'
  Write-ConsoleLine -Text ("Sysmon Drift Sensor  |  Host: {0}  |  Time: {1}" -f $Result.HostName, $Result.Timestamp) -Color 'Cyan'
  Write-UiSeparator -Char '=' -Width 78 -Style 'Cyan'
  Write-ConsoleLine -Text ("Status: {0}" -f $Result.Status) -Color $statusColor
  Write-ConsoleLine -Text ("WindowHours: {0} | Rules: {1} | Anomalies: {2} | HardZero: {3}" -f $Result.WindowHours, $Result.Summary.TotalRules, $Result.Summary.Anomalies, $Result.Summary.HardZero) -Color 'White'
  $oldestTxt = 'n/a'
  if ($Result.Channel.OldestRecord) { $oldestTxt = $Result.Channel.OldestRecord.ToString('s') }
  Write-ConsoleLine -Text ("Channel: Exists={0} Enabled={1} Oldest={2}" -f $Result.Channel.Exists, $Result.Channel.Enabled, $oldestTxt) -Color 'White'
  if ($Result.Channel.Error) {
    Write-ConsoleLine -Text ("ChannelError: {0}" -f $Result.Channel.Error) -Color 'Yellow'
  }
  Write-ConsoleLine -Text ("ConfigChangedInWindow: {0}" -f $Result.ConfigChanged) -Color 'White'
  Write-ConsoleLine -Text ("Catalog: {0}" -f $Result.CatalogSource) -Color 'White'
  Write-ConsoleLine -Text ("State: {0} | WriteOk: {1}" -f $Result.StatePath, $Result.StateWriteOk) -Color 'White'
  if ($Result.Remediation -and $Result.Remediation.Attempted) {
    $rc = 'Yellow'
    if ($Result.Remediation.Success) { $rc = 'Green' }
    if (-not $Result.Remediation.Success) { $rc = 'Red' }
    Write-ConsoleLine -Text ("Remediation: Success={0} ExitCode={1}" -f $Result.Remediation.Success, $Result.Remediation.ExitCode) -Color $rc
    if ($Result.Remediation.Error) {
      Write-ConsoleLine -Text ("RemediationError: {0}" -f $Result.Remediation.Error) -Color 'Yellow'
    }
  }
  # Print top anomalies (human-friendly)
  if ($Result.Rules -and $Result.Rules.Count -gt 0) {
    $bad = $Result.Rules | Where-Object { $_.Status -ne 'OK' } | Sort-Object Status, Id
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
  # Next steps hints (only for humans)
  if ($Result.Status -eq 'CHANNEL_UNAVAILABLE') {
    Write-UiLine ""
    Write-ConsoleLine -Text "Next steps:" -Color 'Cyan'
    Write-ConsoleLine -Text "  - Check if Sysmon is installed and running (Sysmon/Sysmon64 service)." -Color 'Gray'
    Write-ConsoleLine -Text "  - List logs: wevtutil el | findstr /i sysmon" -Color 'Gray'
    Write-ConsoleLine -Text "  - If log exists but disabled: run as admin and enable it: wevtutil sl Microsoft-Windows-Sysmon/Operational /e:true" -Color 'Gray'
  }
  Write-UiSeparator -Char '=' -Width 78 -Style 'Cyan'
  Write-UiLine ""
}
# -----------------------------
# MAIN
# -----------------------------
Ensure-EventSource -SourceName $script:EventSourceName -LogName $script:EventLogName
$channel = Get-SysmonChannelStatus
$channel = Enable-SysmonChannelIfRequested -ChannelStatus $channel
$defaultCatalog = New-DefaultCatalog -DefaultWindowHours $WindowHours -DefaultAlpha $Alpha -DefaultRatioFloor $RatioFloor -DefaultRatioUpper $RatioUpper -DefaultMinBaselineToCompare $MinBaselineToCompare -WithBuiltInRules:$UseBuiltInDefaultRules
$catalogSource = 'DEFAULT'
$catalog = Load-CatalogOrDefault -Path $CatalogPath -DefaultCatalog $defaultCatalog
if ($catalog -ne $defaultCatalog) { $catalogSource = $CatalogPath }
# Apply catalog settings only if caller did not override
if ($catalog.WindowHours -and -not $PSBoundParameters.ContainsKey('WindowHours')) { $WindowHours = [int]$catalog.WindowHours }
if ($catalog.Alpha -and -not $PSBoundParameters.ContainsKey('Alpha')) { $Alpha = [double]$catalog.Alpha }
if ($catalog.RatioFloor -and -not $PSBoundParameters.ContainsKey('RatioFloor')) { $RatioFloor = [double]$catalog.RatioFloor }
if ($catalog.RatioUpper -and -not $PSBoundParameters.ContainsKey('RatioUpper')) { $RatioUpper = [double]$catalog.RatioUpper }
if ($catalog.MinBaselineToCompare -and -not $PSBoundParameters.ContainsKey('MinBaselineToCompare')) { $MinBaselineToCompare = [int]$catalog.MinBaselineToCompare }
$startTime = (Get-Date).AddHours(-$WindowHours)
if (-not $channel.Exists -or -not $channel.Enabled) {
  $final = New-FinalResult -OverallStatus 'CHANNEL_UNAVAILABLE' -StartTime $startTime -ChannelStatus $channel -ConfigChanged $false -Remediation $null -Rules @() -CatalogSource $catalogSource -StatePathUsed $StatePath -StateWriteOk $false
  Write-AuditEvent -EventId $script:EventIdWarn -Message ("Sysmon channel unavailable: Exists={0} Enabled={1} Error={2}" -f $channel.Exists,$channel.Enabled,$channel.Error) -Level 'Warning'
  if ($PassThru) { $final } else { Show-ConsoleSummary -Result $final }
  exit 1
}
# Load baseline state (tolerant)
$baseline = @{}
$state = Read-JsonFileSafe -Path $StatePath
if ($state -and $state.Baseline) {
  $baseline = ConvertTo-Hashtable -InputObject $state.Baseline
}
# Config change detection in window (Sysmon ID 16)
$configChanged = $false
try {
  $cfg = Get-WinEvent -FilterHashtable @{ LogName=$script:SysmonLogName; ID=16; StartTime=$startTime } -MaxEvents 1 -ErrorAction SilentlyContinue
  if ($cfg -and $cfg.Count -gt 0) { $configChanged = $true }
} catch { <# best-effort: Sysmon config change event may not exist in time window #> }
$ruleResults = @()
$remediationResult = $null
$overallStatus = 'OK'
$stateWriteOk = $false
try {
  foreach ($r in @($catalog.Rules)) {
    if (-not $r) { continue }
    if (-not $r.Id) { continue }
    if ($r.Disabled -eq $true) { continue }
    $id = [int]$r.Id
    $name = if ($r.Name) { [string]$r.Name } else { "EventID $id" }
    $isCritical = [bool]$r.Critical
    $minWin = $null
    if ($null -ne $r.MinPerWindow) { $minWin = [int]$r.MinPerWindow }
    $msgRegex = $null
    if ($r.MessageRegex) { $msgRegex = [string]$r.MessageRegex }
    # Validate regex; if invalid, ignore regex for counting.
    if ($msgRegex) {
      try { [void][regex]::new($msgRegex) } catch { $msgRegex = $null }
    }
    $count = Get-EventCount -EventId $id -StartTime $startTime -MessageRegex $msgRegex
    $priorBase = $null
    if ($baseline.ContainsKey("$id")) {
      try { $priorBase = [double]$baseline["$id"] } catch { $priorBase = $null }
    }
    $ratio = $null
    if ($null -ne $priorBase -and $priorBase -ge [double]$MinBaselineToCompare -and $priorBase -gt 0) {
      $ratio = [math]::Round($count / $priorBase, 2)
    }
    $status = 'OK'
    if ($isCritical -and $count -eq 0) { $status = 'HARDZERO' }
    elseif ($null -ne $minWin -and $count -lt $minWin) { $status = 'LOW' }
    elseif ($null -ne $ratio -and $ratio -lt $RatioFloor) { $status = 'DRIFT_DOWN' }
    elseif ($IncludeSurge -and $null -ne $ratio -and $ratio -gt $RatioUpper) { $status = 'SURGE' }
    if ($status -ne 'OK') { $overallStatus = 'ANOMALIES_DETECTED' }
    # EMA baseline update
    $newBase = [double]$count
    if (-not $Rebaseline -and $null -ne $priorBase) {
      $newBase = [double]::Round(($Alpha * $count) + ((1 - $Alpha) * $priorBase), 2)
    }
    $baseline["$id"] = $newBase
    $ruleResults += (New-RuleResult -Id $id -Name $name -Count $count -PriorBaseline $priorBase -NewBaseline $newBase -Ratio $ratio -MinPerWindow $minWin -IsCritical $isCritical -Status $status -MessageRegex $msgRegex)
  }
  # Persist state (best effort)
  $stateObj = [pscustomobject]@{
    HostName = $env:COMPUTERNAME
    Timestamp = (Get-Date).ToString('s')
    WindowHours = $WindowHours
    Alpha = $Alpha
    Baseline = $baseline
    Channel = $channel
    ConfigChanged = $configChanged
    CatalogSource = $catalogSource
  }
  $stateWriteOk = $false
  try {
    Save-Json -InputObject $stateObj -Path $StatePath -Depth 10
    $stateWriteOk = $true
  } catch { <# state write failed #> }
  if (-not $stateWriteOk) { $overallStatus = 'ANOMALIES_DETECTED' }
  # Optional remediation (trigger on any HARDZERO)
  if ($TriggerReapply) {
    $hasHardZero = (($ruleResults | Where-Object { $_.Status -eq 'HARDZERO' } | Measure-Object).Count -gt 0)
    if ($hasHardZero) {
      if (Test-RemediationScriptAllowed -ScriptPath $RemediationScriptPath -RequireSignature:$RequireSignedRemediationScript) {
        $remediationResult = Invoke-RemediationScript -ScriptPath $RemediationScriptPath
      } else {
        $remediationResult = [pscustomobject]@{
          Attempted = $true
          Success   = $false
          ExitCode  = $null
          Error     = 'Remediation blocked (missing script or invalid signature)'
          ScriptPath= $RemediationScriptPath
        }
      }
    }
  }
  $final = New-FinalResult -OverallStatus $overallStatus -StartTime $startTime -ChannelStatus $channel -ConfigChanged $configChanged -Remediation $remediationResult -Rules $ruleResults -CatalogSource $catalogSource -StatePathUsed $StatePath -StateWriteOk $stateWriteOk
  # Audit event (short)
  $auditMsg = "Rules={0} Anomalies={1} HardZero={2} ConfigChanged={3} RemAttempted={4} RemSuccess={5} Catalog={6}" -f `
    $final.Summary.TotalRules, $final.Summary.Anomalies, $final.Summary.HardZero, $final.ConfigChanged, `
    ($(if ($final.Remediation) { $final.Remediation.Attempted } else { $false })), `
    ($(if ($final.Remediation) { $final.Remediation.Success } else { $false })), `
    $final.CatalogSource
  if ($final.Status -eq 'OK') {
    Write-AuditEvent -EventId $script:EventIdOk -Message $auditMsg -Level 'Information'
  } else {
    Write-AuditEvent -EventId $script:EventIdWarn -Message $auditMsg -Level 'Warning'
  }
} catch {
  $err = $_.Exception.Message
  $final = New-FinalResult -OverallStatus 'ERROR' -StartTime $startTime -ChannelStatus $channel -ConfigChanged $configChanged -Remediation $remediationResult -Rules $ruleResults -CatalogSource $catalogSource -StatePathUsed $StatePath -StateWriteOk $stateWriteOk
  $final | Add-Member -NotePropertyName Error -NotePropertyValue $err -Force
  Write-AuditEvent -EventId $script:EventIdWarn -Message ("Sysmon Drift Sensor ERROR: {0}" -f $err) -Level 'Error'
} finally {
  if (-not $PassThru) {
    Show-ConsoleSummary -Result $final
  }
  if ($final.Status -ne 'OK') { exit 1 }
}
# V2 output contract
$resultToken = if ($final.Status -eq 'FAIL') { 'FAIL' } elseif ($final.Status -ne 'OK') { 'WARN' } else { 'OK' }
$v2Result = New-V2ResultObject -ScriptName '17-Sysmon-Rule-Drift-Sensor.ps1' -Mode $Mode -Result $resultToken -Findings @() -Summary $final -Metadata @{}
Write-ResultObject -ResultObject $v2Result -OutputFormat $OutputFormat -OutputPath $OutputPath
if ($PassThru) { $v2Result }
exit 0
