#requires -version 5.1
<#
.SYNOPSIS
Detects Sysmon event rule drift within a configurable time window and reports anomalies.
.DESCRIPTION
This script monitors the Sysmon Operational event log and evaluates event-count "drift" for a defined set of Sysmon Event IDs.
It compares the current event volume in a time window against an exponentially weighted moving average (EMA) baseline that is persisted to disk.
Typical use cases:
- Detect missing Sysmon coverage (e.g., a critical event type stops appearing).
- Detect reduced telemetry (drift down) caused by misconfiguration, tampering, log disablement, or collector issues.
- Optionally detect surges (abnormally high volume) for selected rules.
- Optionally trigger a remediation script when a critical rule is at HARDZERO.
How it works:
1) Load a rule catalog from JSON (or fall back to safe defaults).
2) Load the persisted baseline state from JSON (or initialize an empty baseline).
3) Query the configured Sysmon event IDs once, within global event-count and wall-clock budgets, then count each rule from that bounded evidence.
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
9) Print a console summary (unless -PassThru is used).
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
  Optional identity path for the remediation script. Only the canonical
  16-Sysmon-Config-Updater.ps1 beside this sensor is accepted; any other value
  is rejected. When omitted, that canonical updater is selected automatically.
  The updater is started in a new PowerShell process with -Mode Remediate.
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
.PARAMETER MaxEvents
Maximum number of event records retained for the entire run. If more records match, evidence is marked truncated and the result is FAIL.
.PARAMETER MaxQuerySeconds
Global wall-clock budget in seconds for querying and processing event evidence. Exceeding it marks evidence incomplete and the result is FAIL.
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
- ConfigChanged (bool or null): Whether Sysmon configuration change events were detected; null when evidence is incomplete
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
Run with a custom catalog. The state path remains fixed under CommonApplicationData:
.\17-Sysmon-Rule-Drift-Sensor.ps1 -CatalogPath $CatalogPath
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
  [ValidateRange(1,200000)]
  [int]$MaxEvents = 50000,
  [ValidateRange(1,300)]
  [int]$MaxQuerySeconds = 30,
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
function Initialize-Capability17Runtime {
  param($EntryBoundParameters)
  $RunState = @{
    Alpha = $Alpha
    MinBaselineToCompare = $MinBaselineToCompare
    RatioFloor = $RatioFloor
    RatioUpper = $RatioUpper
  }
Import-Module (Join-Path $script:LibPath 'Common.psm1') -Force -DisableNameChecking
Import-Module (Join-Path $script:LibPath 'Config.psm1') -Force
Import-Module (Join-Path $script:LibPath 'Output.psm1') -Force
Import-Module (Join-Path $script:LibPath 'EventLog.psm1') -Force
Import-Module (Join-Path $script:LibPath 'External.psm1') -Force -DisableNameChecking
Import-Module (Join-Path $script:LibPath 'Validation.psm1') -Force
Import-Module (Join-Path $script:LibPath 'JsonCatalog.psm1') -Force
Import-Module (Join-Path $script:LibPath Serialization.psm1) -Force
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'internal/17-Sysmon-Rule-Drift-Sensor.helpers.ps1')
$script:__V2Context = Initialize-V2Context -ScriptName '17-Sysmon-Rule-Drift-Sensor.ps1' -BoundParameters $EntryBoundParameters `
  -Values @{ Mode = $Mode; ConfigPath = $ConfigPath; OutputFormat = $OutputFormat; OutputPath = $OutputPath; PassThru = $PassThru; Strict = $Strict; Quiet = $Quiet; NoColor = $NoColor; DeriveRemediate = $false }
if ($script:__V2Context.Quiet) { $InformationPreference = 'SilentlyContinue'; $VerbosePreference = 'SilentlyContinue' }
$script:NoColor = [bool]$script:__V2Context.NoColor
$ErrorActionPreference = 'Stop'
if ([string]::IsNullOrWhiteSpace($RemediationScriptPath)) {
  $RemediationScriptPath = Join-Path $PSScriptRoot '16-Sysmon-Config-Updater.ps1'
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
# MAIN
# -----------------------------
if ($EntryBoundParameters.ContainsKey('CatalogPath')) {
  try {
    $RunState.catalog = Get-ExplicitCatalog -Path $CatalogPath -RunState $RunState
    $RunState.catalogSource = $CatalogPath
  } catch {
    Write-CatalogFailureResult -Message $_.Exception.Message
  }
} else {
  $RunState.catalog = $null
  $RunState.catalogSource = 'DEFAULT'
}
$RunState.isWindowsHost = ($env:OS -eq 'Windows_NT')
  $script:RunState = $RunState
}

. Initialize-Capability17Runtime -EntryBoundParameters $PSBoundParameters
function Get-Capability17UnsupportedState {
  param([hashtable]$RunState)
$summary = [pscustomobject]@{
  ComputerName = $env:COMPUTERNAME
  Timestamp    = Get-Date
  Mode         = $Mode
  Supported    = $false
  Notes        = @('Skipped: this script is only supported on Windows hosts.')
}
$RunState.unsupportedResult = if ($Strict) { 'FAIL' } else { 'WARN' }
$RunState.result = Get-V2ResultObject -ScriptName '17-Sysmon-Rule-Drift-Sensor.ps1' -Mode $Mode -Result $RunState.unsupportedResult -Findings @() -Summary $summary -Metadata @{ UnsupportedHost = $true }
  [pscustomobject]@{ Result = $RunState.result; Token = $RunState.unsupportedResult }
}
function Set-Capability17UnsupportedState {
  param([hashtable]$RunState)
  $unsupportedState = Get-Capability17UnsupportedState -RunState $RunState
  $RunState.result = $unsupportedState.Result
  $RunState.unsupportedResult = $unsupportedState.Token
}
if (-not $RunState.isWindowsHost) {
  . Set-Capability17UnsupportedState -RunState $RunState
  Write-ResultObject -ResultObject $RunState.result -OutputFormat $OutputFormat -OutputPath $OutputPath
  if ($PassThru) { $RunState.result }
  exit (Get-V2ExitCode -Result $RunState.unsupportedResult)
}
function Invoke-Capability17MainPhase01 {
  param([hashtable]$RunState)
  $StatePath = Get-SysmonStatePath -RequestedPath $StatePath -FileName 'rule-drift-sensor-state.json'
  if (-not (Ensure-EventSource -SourceName $script:EventSourceName -LogName $script:EventLogName)) {
    Write-Warning "EventSource could not be registered. EventLog tracing will be unavailable."
  }
  $channel = Get-SysmonChannelStatus
  $channel = Enable-SysmonChannelIfRequested -ChannelStatus $channel
  $defaultCatalog = Get-DefaultCatalog -DefaultWindowHours $WindowHours -DefaultAlpha $RunState.Alpha -DefaultRatioFloor $RunState.RatioFloor -DefaultRatioUpper $RunState.RatioUpper -DefaultMinBaselineToCompare $RunState.MinBaselineToCompare -WithBuiltInRules:$UseBuiltInDefaultRules
  if ($null -eq $RunState.catalog) { $RunState.catalog = $defaultCatalog }
  # Apply catalog settings only if caller did not override
  if ($RunState.catalog.PSObject.Properties.Name -contains 'WindowHours' -and -not $script:__EntryBoundParameters.ContainsKey('WindowHours')) { $WindowHours = [int]$RunState.catalog.WindowHours }
}
function Invoke-Capability17MainPhase02 {
  param([hashtable]$RunState)
  if ($RunState.catalog.PSObject.Properties.Name -contains 'Alpha' -and -not $script:__EntryBoundParameters.ContainsKey('Alpha')) { $RunState.Alpha = [double]$RunState.catalog.Alpha }
  if ($RunState.catalog.PSObject.Properties.Name -contains 'RatioFloor' -and -not $script:__EntryBoundParameters.ContainsKey('RatioFloor')) { $RunState.RatioFloor = [double]$RunState.catalog.RatioFloor }
}
function Invoke-Capability17MainPhase03 {
  param([hashtable]$RunState)
  if ($RunState.catalog.PSObject.Properties.Name -contains 'RatioUpper' -and -not $script:__EntryBoundParameters.ContainsKey('RatioUpper')) { $RunState.RatioUpper = [double]$RunState.catalog.RatioUpper }
  if ($RunState.catalog.PSObject.Properties.Name -contains 'MinBaselineToCompare' -and -not $script:__EntryBoundParameters.ContainsKey('MinBaselineToCompare')) { $RunState.MinBaselineToCompare = [int]$RunState.catalog.MinBaselineToCompare }
  $RunState.startTime = (Get-Date).AddHours(-$WindowHours)
}
function Set-SysmonUnavailableResult {
  param([hashtable]$RunState)
    $final = Get-FinalResult ([pscustomobject]@{
        OverallStatus = 'CHANNEL_UNAVAILABLE'
        StartTime = $RunState.startTime
        ChannelStatus = $channel
        ConfigChanged = $null
        Remediation = $null
        Rules = @()
        Evidence = $null
        CatalogSource = $RunState.catalogSource
        StatePathUsed = $StatePath
        StateWriteOk = $false
      })
    Write-AuditEvent -EventId $script:EventIdWarn -Message ("Sysmon channel unavailable: Exists={0} Enabled={1} Error={2}" -f $channel.Exists,$channel.Enabled,$channel.Error) -Level 'Warning'
    if (-not $PassThru) { Show-ConsoleSummary -Result $final -RunState $RunState }
}
function Initialize-SysmonRuleEvaluation {
  param([hashtable]$RunState)
    $RunState.baseline = @{}
    $state = Read-ValidatedSysmonState -Path $StatePath -RunState $RunState
    if ($state -and $state.Baseline) { $RunState.baseline = ConvertTo-Hashtable -Object $state.Baseline }
    $RunState.ruleResults = @(); $RunState.remediationResult = $null; $RunState.stateWriteOk = $false; $RunState.eventQueryFailed = $false; $RunState.configChanged = $null; $RunState.evidenceSummary = $null
}
function Get-SysmonRuleEvidence {
  param([hashtable]$RunState)
    $activeRules = @($RunState.catalog.Rules | Where-Object { $_ -and $_.PSObject.Properties.Name -contains 'Id' -and -not ($_.PSObject.Properties.Name -contains 'Disabled' -and $_.Disabled -eq $true) })
    $queryIds = @(@($activeRules | ForEach-Object { [int]$_.Id }) + 16 | Sort-Object -Unique)
    $workStopwatch = [Diagnostics.Stopwatch]::StartNew()
    $eventEvidence = Get-BoundedSysmonEventEvidence -EventIds $queryIds -StartTime $RunState.startTime -MaximumEvents $MaxEvents -MaximumSeconds $MaxQuerySeconds -RunState $RunState
    $configCount = Get-EventCountFromEvidence -Evidence $eventEvidence -EventId 16 -WorkStopwatch $workStopwatch -MaximumSeconds $MaxQuerySeconds -RunState $RunState
    if ($configCount.Success) { $RunState.configChanged = [bool]($configCount.Count -gt 0) } else { $RunState.eventQueryFailed = $true }
}
function Initialize-SysmonRuleIteration {
  param([hashtable]$RunState)
        $id = [int]$r.Id
        $RunState.name = if ((Test-AllConditions -Conditions @({ $r.PSObject.Properties.Name -contains 'Name' }, { $r.Name }))) { [string]$r.Name } else { "EventID $id" }
        $RunState.isCritical = [bool]((Test-AllConditions -Conditions @({ $r.PSObject.Properties.Name -contains 'Critical' }, { $r.Critical })))
        $RunState.minWin = if ((Test-AllConditions -Conditions @({ $r.PSObject.Properties.Name -contains 'MinPerWindow' }, { $null -ne $r.MinPerWindow }))) { [Nullable[int]][int]$r.MinPerWindow } else { $null }
        $msgRegex = if ((Test-AllConditions -Conditions @({ $r.PSObject.Properties.Name -contains 'MessageRegex' }, { $r.MessageRegex }))) { [string]$r.MessageRegex } else { $null }
        $RunState.countResult = Get-EventCountFromEvidence -Evidence $eventEvidence -EventId $id -MessageRegex $msgRegex -WorkStopwatch $workStopwatch -MaximumSeconds $MaxQuerySeconds -RunState $RunState
}
function Resolve-SysmonRuleStatus {
  param([hashtable]$RunState)
        $isCritical = $RunState.isCritical
        $minimumWindowCount = $RunState.minWin
        $ratioFloor = $RunState.RatioFloor
        $ratioUpper = $RunState.RatioUpper
        if ((Test-AllConditions -Conditions @({ $isCritical }, { $count -eq 0 }))) { return 'HARDZERO' }
        if ((Test-AllConditions -Conditions @({ $null -ne $minimumWindowCount }, { $count -lt $minimumWindowCount }))) { return 'LOW' }
        if ((Test-AllConditions -Conditions @({ $null -ne $ratio }, { $ratio -lt $ratioFloor }))) { return 'DRIFT_DOWN' }
        if ((Test-AllConditions -Conditions @({ (Test-AllConditions -Conditions @({ $IncludeSurge }, { $null -ne $ratio })) }, { $ratio -gt $ratioUpper }))) { return 'SURGE' }
        return 'OK'
}
function Add-SysmonSuccessfulRuleMeasurement {
  param([hashtable]$RunState)
        $count = [int]$RunState.countResult.Count; $priorBase = $null
        if ($RunState.baseline.ContainsKey("$id")) { try { $priorBase = [double]$RunState.baseline["$id"] } catch { $priorBase = $null } }
        $ratio = $null
        if ((Test-AllConditions -Conditions @({ (Test-AllConditions -Conditions @({ $null -ne $priorBase }, { $priorBase -ge [double]$RunState.MinBaselineToCompare })) }, { $priorBase -gt 0 }))) { $ratio = [math]::Round($count / $priorBase,2) }
        $status = Resolve-SysmonRuleStatus -RunState $RunState
        $newBase = [double]$count
        if ((Test-AllConditions -Conditions @({ -not $Rebaseline }, { $null -ne $priorBase }))) { $newBase = [double]::Round(($RunState.Alpha * $count) + ((1 - $RunState.Alpha) * $priorBase),2) }
        $RunState.baseline["$id"] = $newBase
        $RunState.ruleResults += Get-RuleResult ([pscustomobject]@{ Id=$id; Name=$RunState.name; Count=$count; PriorBaseline=$priorBase; NewBaseline=$newBase; Ratio=$ratio; MinPerWindow=$RunState.minWin; IsCritical=$RunState.isCritical; Status=$status; MessageRegex=$msgRegex; QueryError=$null })
}
function Measure-SysmonCatalogRules {
  param([hashtable]$RunState)
    foreach ($r in $activeRules) {
        . Initialize-SysmonRuleIteration -RunState $RunState
        if (-not $RunState.countResult.Success) {
          $RunState.eventQueryFailed = $true
          $RunState.ruleResults += Get-RuleResult ([pscustomobject]@{ Id=$id; Name=$RunState.name; Count=$null; PriorBaseline=$null; NewBaseline=$null; Ratio=$null; MinPerWindow=$RunState.minWin; IsCritical=$RunState.isCritical; Status='QUERY_ERROR'; MessageRegex=$msgRegex; QueryError=$RunState.countResult.Error })
          continue
        }
        . Add-SysmonSuccessfulRuleMeasurement -RunState $RunState
    }
}
function Complete-SysmonEvidenceCollection {
  param([hashtable]$RunState)
    $workStopwatch.Stop()
    $evidenceComplete = [bool]($eventEvidence.Complete -and -not $RunState.eventQueryFailed -and $workStopwatch.Elapsed.TotalSeconds -lt $MaxQuerySeconds)
    $RunState.evidenceSummary = [pscustomobject]@{ Complete = $evidenceComplete; Truncated = [bool]$eventEvidence.Truncated; TimedOut = [bool]($eventEvidence.TimedOut -or $workStopwatch.Elapsed.TotalSeconds -ge $MaxQuerySeconds); Error = $eventEvidence.Error; EventIds = @($eventEvidence.EventIds); EventsRead = $eventEvidence.EventsRead; MaximumEvents = $eventEvidence.MaximumEvents; MaximumSeconds = $eventEvidence.MaximumSeconds; ElapsedMilliseconds = $workStopwatch.ElapsedMilliseconds }
    if ($evidenceComplete) {
        $stateObj = [pscustomobject]@{ Version = 1; HostName = [string]$env:COMPUTERNAME; Timestamp = (Get-Date).ToString('s'); WindowHours = [int]$WindowHours; Alpha = [double]$RunState.Alpha; Baseline = [pscustomobject]$RunState.baseline; ConfigChanged = [bool]$RunState.configChanged; CatalogSource = [string]$RunState.catalogSource }
        try { Write-SysmonState -InputObject $stateObj -Path $StatePath -RunState $RunState; $RunState.stateWriteOk = $true } catch { Write-Verbose ("Sysmon drift state write failed: {0}" -f $_.Exception.Message) }
    }
}
function Invoke-SysmonReapplyIfNeeded {
  param([hashtable]$RunState)
    $overallStatus = Resolve-SysmonOverallStatus -Rules $RunState.ruleResults -StateWriteOk $RunState.stateWriteOk -EvidenceComplete $evidenceComplete
    if ((Test-AllConditions -Conditions @({ $Mode -eq 'Remediate' }, { $TriggerReapply })) -and $evidenceComplete -and $overallStatus -ne 'ERROR') {
        $hasHardZero = @($RunState.ruleResults | Where-Object { $_.Status -eq 'HARDZERO' }).Count -gt 0
        if ($hasHardZero) {
          $RunState.remediationResult = Invoke-RemediationScript -ScriptPath $RemediationScriptPath -RequireSignature:$RequireSignedRemediationScript -RunState $RunState
          if ((Test-AllConditions -Conditions @({ $RunState.remediationResult.Attempted }, { -not $RunState.remediationResult.Success }))) {
            $overallStatus = 'ERROR'
          }
        }
    }
}
function Set-SysmonSuccessfulResult {
  param([hashtable]$RunState)
    $final = Get-FinalResult ([pscustomobject]@{
        OverallStatus = $overallStatus
        StartTime = $RunState.startTime
        ChannelStatus = $channel
        ConfigChanged = $RunState.configChanged
        Remediation = $RunState.remediationResult
        Rules = $RunState.ruleResults
        Evidence = $RunState.evidenceSummary
        CatalogSource = $RunState.catalogSource
        StatePathUsed = $StatePath
        StateWriteOk = $RunState.stateWriteOk
      })
    $auditMsg = "Rules={0} Anomalies={1} HardZero={2} EvidenceComplete={3} Truncated={4} ConfigChanged={5} Catalog={6}" -f $final.Summary.TotalRules,$final.Summary.Anomalies,$final.Summary.HardZero,$final.Evidence.Complete,$final.Evidence.Truncated,$final.ConfigChanged,$final.CatalogSource
    if ($final.Status -eq 'OK') { Write-AuditEvent -EventId $script:EventIdOk -Message $auditMsg -Level 'Information' } else { Write-AuditEvent -EventId $script:EventIdWarn -Message $auditMsg -Level 'Warning' }
}
function Invoke-SysmonAvailableEvaluation {
  param([hashtable]$RunState)
    . Initialize-SysmonRuleEvaluation -RunState $RunState
    try {
      . Get-SysmonRuleEvidence -RunState $RunState
      . Measure-SysmonCatalogRules -RunState $RunState
      . Complete-SysmonEvidenceCollection -RunState $RunState
      . Invoke-SysmonReapplyIfNeeded -RunState $RunState
      . Set-SysmonSuccessfulResult -RunState $RunState
    } catch {
      $err = $_.Exception.Message
      $final = Get-FinalResult ([pscustomobject]@{
          OverallStatus = 'ERROR'
          StartTime = $RunState.startTime
          ChannelStatus = $channel
          ConfigChanged = $RunState.configChanged
          Remediation = $RunState.remediationResult
          Rules = $RunState.ruleResults
          Evidence = $RunState.evidenceSummary
          CatalogSource = $RunState.catalogSource
          StatePathUsed = $StatePath
          StateWriteOk = $RunState.stateWriteOk
        })
      $final | Add-Member -NotePropertyName Error -NotePropertyValue $err -Force
      Write-AuditEvent -EventId $script:EventIdWarn -Message ("Sysmon Drift Sensor ERROR: {0}" -f $err) -Level 'Error'
    } finally { if (-not $PassThru) { Show-ConsoleSummary -Result $final -RunState $RunState } }
}
function Invoke-Capability17MainPhase04 {
  param([hashtable]$RunState)
  if (-not $channel.Exists -or -not $channel.Enabled) {
    . Set-SysmonUnavailableResult -RunState $RunState
  } else {
    . Invoke-SysmonAvailableEvaluation -RunState $RunState
  }
}
function Invoke-Capability17Main {
  param($EntryBoundParameters, $EntryCmdlet, $EntryInvocation, [hashtable]$RunState)
  $script:__EntryBoundParameters = $EntryBoundParameters
  $script:__EntryCmdlet = $EntryCmdlet
  $script:__EntryInvocation = $EntryInvocation
  . Invoke-Capability17MainPhase01 -RunState $RunState
  . Invoke-Capability17MainPhase02 -RunState $RunState
  . Invoke-Capability17MainPhase03 -RunState $RunState
  . Invoke-Capability17MainPhase04 -RunState $RunState
}
. Invoke-Capability17Main -EntryBoundParameters $PSBoundParameters -EntryCmdlet $PSCmdlet -EntryInvocation $MyInvocation -RunState $RunState
# V2 output contract
function Get-Capability17ResultToken {
  $resultToken = if ($final.Status -in @('FAIL', 'ERROR')) { 'FAIL' } elseif ($final.Status -ne 'OK') { 'WARN' } else { 'OK' }
  if ($Strict -and $resultToken -eq 'WARN') { $resultToken = 'FAIL' }
  return $resultToken
}
$resultToken = Get-Capability17ResultToken
$v2Result = Get-V2ResultObject -ScriptName '17-Sysmon-Rule-Drift-Sensor.ps1' -Mode $Mode -Result $resultToken -Findings @() -Summary $final -Metadata @{}
Write-ResultObject -ResultObject $v2Result -OutputFormat $OutputFormat -OutputPath $OutputPath
if ($PassThru) { $v2Result }
exit (Get-V2ExitCode -Result $resultToken)
