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
# v2-init (migrated to Initialize-V2Context)
$script:__V2Context = Initialize-V2Context -ScriptName '17-Sysmon-Rule-Drift-Sensor.ps1' -BoundParameters $PSBoundParameters `
  -Mode $Mode -ConfigPath $ConfigPath -OutputFormat $OutputFormat -OutputPath $OutputPath `
  -PassThru:$PassThru -Strict:$Strict -Quiet:$Quiet -NoColor:$NoColor
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
if ($PSBoundParameters.ContainsKey('CatalogPath')) {
  try {
    $catalog = Get-ExplicitCatalog -Path $CatalogPath
    $catalogSource = $CatalogPath
  } catch {
    Write-CatalogFailureResult -Message $_.Exception.Message
  }
} else {
  $catalog = $null
  $catalogSource = 'DEFAULT'
}
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
  $result = Get-V2ResultObject -ScriptName '17-Sysmon-Rule-Drift-Sensor.ps1' -Mode $Mode -Result $unsupportedResult -Findings @() -Summary $summary -Metadata @{ UnsupportedHost = $true }
  Write-ResultObject -ResultObject $result -OutputFormat $OutputFormat -OutputPath $OutputPath
  if ($PassThru) { $result }
  exit (Get-V2ExitCode -Result $unsupportedResult)
}
$StatePath = Get-SysmonStatePath -RequestedPath $StatePath -FileName 'rule-drift-sensor-state.json'
if (-not (Ensure-EventSource -SourceName $script:EventSourceName -LogName $script:EventLogName)) {
  Write-Warning "EventSource could not be registered. EventLog tracing will be unavailable."
}
$channel = Get-SysmonChannelStatus
$channel = Enable-SysmonChannelIfRequested -ChannelStatus $channel
$defaultCatalog = Get-DefaultCatalog -DefaultWindowHours $WindowHours -DefaultAlpha $Alpha -DefaultRatioFloor $RatioFloor -DefaultRatioUpper $RatioUpper -DefaultMinBaselineToCompare $MinBaselineToCompare -WithBuiltInRules:$UseBuiltInDefaultRules
if ($null -eq $catalog) { $catalog = $defaultCatalog }
# Apply catalog settings only if caller did not override
if ($catalog.PSObject.Properties.Name -contains 'WindowHours' -and -not $PSBoundParameters.ContainsKey('WindowHours')) { $WindowHours = [int]$catalog.WindowHours }
if ($catalog.PSObject.Properties.Name -contains 'Alpha' -and -not $PSBoundParameters.ContainsKey('Alpha')) { $Alpha = [double]$catalog.Alpha }
if ($catalog.PSObject.Properties.Name -contains 'RatioFloor' -and -not $PSBoundParameters.ContainsKey('RatioFloor')) { $RatioFloor = [double]$catalog.RatioFloor }
if ($catalog.PSObject.Properties.Name -contains 'RatioUpper' -and -not $PSBoundParameters.ContainsKey('RatioUpper')) { $RatioUpper = [double]$catalog.RatioUpper }
if ($catalog.PSObject.Properties.Name -contains 'MinBaselineToCompare' -and -not $PSBoundParameters.ContainsKey('MinBaselineToCompare')) { $MinBaselineToCompare = [int]$catalog.MinBaselineToCompare }
$startTime = (Get-Date).AddHours(-$WindowHours)
if (-not $channel.Exists -or -not $channel.Enabled) {
  $final = Get-FinalResult -OverallStatus 'CHANNEL_UNAVAILABLE' -StartTime $startTime -ChannelStatus $channel -ConfigChanged $null -Remediation $null -Rules @() -CatalogSource $catalogSource -StatePathUsed $StatePath -StateWriteOk $false
  Write-AuditEvent -EventId $script:EventIdWarn -Message ("Sysmon channel unavailable: Exists={0} Enabled={1} Error={2}" -f $channel.Exists,$channel.Enabled,$channel.Error) -Level 'Warning'
  if (-not $PassThru) { Show-ConsoleSummary -Result $final }
} else {
  $baseline = @{}
  $state = Read-ValidatedSysmonState -Path $StatePath
  if ($state -and $state.Baseline) { $baseline = ConvertTo-Hashtable -Object $state.Baseline }
  $ruleResults = @(); $remediationResult = $null; $stateWriteOk = $false; $eventQueryFailed = $false; $configChanged = $null; $evidenceSummary = $null
  try {
    $activeRules = @($catalog.Rules | Where-Object { $_ -and $_.PSObject.Properties.Name -contains 'Id' -and -not ($_.PSObject.Properties.Name -contains 'Disabled' -and $_.Disabled -eq $true) })
    $queryIds = @(@($activeRules | ForEach-Object { [int]$_.Id }) + 16 | Sort-Object -Unique)
    $workStopwatch = [Diagnostics.Stopwatch]::StartNew()
    $eventEvidence = Get-BoundedSysmonEventEvidence -EventIds $queryIds -StartTime $startTime -MaximumEvents $MaxEvents -MaximumSeconds $MaxQuerySeconds
    $configCount = Get-EventCountFromEvidence -Evidence $eventEvidence -EventId 16 -WorkStopwatch $workStopwatch -MaximumSeconds $MaxQuerySeconds
    if ($configCount.Success) { $configChanged = [bool]($configCount.Count -gt 0) } else { $eventQueryFailed = $true }
    foreach ($r in $activeRules) {
      $id = [int]$r.Id
      $name = if ($r.PSObject.Properties.Name -contains 'Name' -and $r.Name) { [string]$r.Name } else { "EventID $id" }
      $isCritical = [bool]($r.PSObject.Properties.Name -contains 'Critical' -and $r.Critical)
      $minWin = if ($r.PSObject.Properties.Name -contains 'MinPerWindow' -and $null -ne $r.MinPerWindow) { [Nullable[int]][int]$r.MinPerWindow } else { $null }
      $msgRegex = if ($r.PSObject.Properties.Name -contains 'MessageRegex' -and $r.MessageRegex) { [string]$r.MessageRegex } else { $null }
      $countResult = Get-EventCountFromEvidence -Evidence $eventEvidence -EventId $id -MessageRegex $msgRegex -WorkStopwatch $workStopwatch -MaximumSeconds $MaxQuerySeconds
      if (-not $countResult.Success) { $eventQueryFailed = $true; $ruleResults += Get-RuleResult -Id $id -Name $name -Count $null -PriorBaseline $null -NewBaseline $null -Ratio $null -MinPerWindow $minWin -IsCritical $isCritical -Status 'QUERY_ERROR' -MessageRegex $msgRegex -QueryError $countResult.Error; continue }
      $count = [int]$countResult.Count; $priorBase = $null
      if ($baseline.ContainsKey("$id")) { try { $priorBase = [double]$baseline["$id"] } catch { $priorBase = $null } }
      $ratio = $null
      if ($null -ne $priorBase -and $priorBase -ge [double]$MinBaselineToCompare -and $priorBase -gt 0) { $ratio = [math]::Round($count / $priorBase,2) }
      $status = 'OK'
      if ($isCritical -and $count -eq 0) { $status = 'HARDZERO' } elseif ($null -ne $minWin -and $count -lt $minWin) { $status = 'LOW' } elseif ($null -ne $ratio -and $ratio -lt $RatioFloor) { $status = 'DRIFT_DOWN' } elseif ($IncludeSurge -and $null -ne $ratio -and $ratio -gt $RatioUpper) { $status = 'SURGE' }
      $newBase = [double]$count
      if (-not $Rebaseline -and $null -ne $priorBase) { $newBase = [double]::Round(($Alpha * $count) + ((1 - $Alpha) * $priorBase),2) }
      $baseline["$id"] = $newBase
      $ruleResults += Get-RuleResult -Id $id -Name $name -Count $count -PriorBaseline $priorBase -NewBaseline $newBase -Ratio $ratio -MinPerWindow $minWin -IsCritical $isCritical -Status $status -MessageRegex $msgRegex -QueryError $null
    }
    $workStopwatch.Stop()
    $evidenceComplete = [bool]($eventEvidence.Complete -and -not $eventQueryFailed -and $workStopwatch.Elapsed.TotalSeconds -lt $MaxQuerySeconds)
    $evidenceSummary = [pscustomobject]@{ Complete = $evidenceComplete; Truncated = [bool]$eventEvidence.Truncated; TimedOut = [bool]($eventEvidence.TimedOut -or $workStopwatch.Elapsed.TotalSeconds -ge $MaxQuerySeconds); Error = $eventEvidence.Error; EventIds = @($eventEvidence.EventIds); EventsRead = $eventEvidence.EventsRead; MaximumEvents = $eventEvidence.MaximumEvents; MaximumSeconds = $eventEvidence.MaximumSeconds; ElapsedMilliseconds = $workStopwatch.ElapsedMilliseconds }
    if ($evidenceComplete) {
      $stateObj = [pscustomobject]@{ Version = 1; HostName = [string]$env:COMPUTERNAME; Timestamp = (Get-Date).ToString('s'); WindowHours = [int]$WindowHours; Alpha = [double]$Alpha; Baseline = [pscustomobject]$baseline; ConfigChanged = [bool]$configChanged; CatalogSource = [string]$catalogSource }
      try { Write-SysmonState -InputObject $stateObj -Path $StatePath; $stateWriteOk = $true } catch { Write-Verbose ("Sysmon drift state write failed: {0}" -f $_.Exception.Message) }
    }
    $overallStatus = Resolve-SysmonOverallStatus -Rules $ruleResults -StateWriteOk $stateWriteOk -EvidenceComplete $evidenceComplete
    if ($Mode -eq 'Remediate' -and $TriggerReapply -and $evidenceComplete -and $overallStatus -ne 'ERROR') {
      $hasHardZero = @($ruleResults | Where-Object { $_.Status -eq 'HARDZERO' }).Count -gt 0
      if ($hasHardZero) {
        $remediationResult = Invoke-RemediationScript -ScriptPath $RemediationScriptPath -RequireSignature:$RequireSignedRemediationScript
        if ($remediationResult.Attempted -and -not $remediationResult.Success) {
          $overallStatus = 'ERROR'
        }
      }
    }
    $final = Get-FinalResult -OverallStatus $overallStatus -StartTime $startTime -ChannelStatus $channel -ConfigChanged $configChanged -Remediation $remediationResult -Rules $ruleResults -Evidence $evidenceSummary -CatalogSource $catalogSource -StatePathUsed $StatePath -StateWriteOk $stateWriteOk
    $auditMsg = "Rules={0} Anomalies={1} HardZero={2} EvidenceComplete={3} Truncated={4} ConfigChanged={5} Catalog={6}" -f $final.Summary.TotalRules,$final.Summary.Anomalies,$final.Summary.HardZero,$final.Evidence.Complete,$final.Evidence.Truncated,$final.ConfigChanged,$final.CatalogSource
    if ($final.Status -eq 'OK') { Write-AuditEvent -EventId $script:EventIdOk -Message $auditMsg -Level 'Information' } else { Write-AuditEvent -EventId $script:EventIdWarn -Message $auditMsg -Level 'Warning' }
  } catch {
    $err = $_.Exception.Message
    $final = Get-FinalResult -OverallStatus 'ERROR' -StartTime $startTime -ChannelStatus $channel -ConfigChanged $configChanged -Remediation $remediationResult -Rules $ruleResults -Evidence $evidenceSummary -CatalogSource $catalogSource -StatePathUsed $StatePath -StateWriteOk $stateWriteOk
    $final | Add-Member -NotePropertyName Error -NotePropertyValue $err -Force
    Write-AuditEvent -EventId $script:EventIdWarn -Message ("Sysmon Drift Sensor ERROR: {0}" -f $err) -Level 'Error'
  } finally { if (-not $PassThru) { Show-ConsoleSummary -Result $final } }
}
# V2 output contract
$resultToken = if ($final.Status -in @('FAIL', 'ERROR')) { 'FAIL' } elseif ($final.Status -ne 'OK') { 'WARN' } else { 'OK' }
if ($Strict -and $resultToken -eq 'WARN') { $resultToken = 'FAIL' }
$v2Result = Get-V2ResultObject -ScriptName '17-Sysmon-Rule-Drift-Sensor.ps1' -Mode $Mode -Result $resultToken -Findings @() -Summary $final -Metadata @{}
Write-ResultObject -ResultObject $v2Result -OutputFormat $OutputFormat -OutputPath $OutputPath
if ($PassThru) { $v2Result }
exit (Get-V2ExitCode -Result $resultToken)
