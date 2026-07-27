#requires -version 5.1
<#
.SYNOPSIS
  Immediately isolates a Windows host during an incident by enforcing a "block all" network posture using Windows Firewall,
  with optional break-glass access, optional adapter shutdown, and optional automatic rollback.

.DESCRIPTION
  This script is an emergency kill switch for incident response. It is designed to be run locally or remotely with administrative rights.

  Core actions (in order):
  1) Writes an audit/quarantine flag to the registry (timestamp + reason + optional user).
  2) Optionally schedules an automatic rollback after a specified number of minutes.
  3) Enforces Windows Firewall "block all" behavior by setting profile defaults to Block for inbound and outbound traffic.
  4) Creates explicit, run-scoped firewall rules for traceability and refuses overlapping activations while prior identities remain.
  5) Optionally creates a break-glass inbound allow rule for specified remote IPs/subnets.
  6) Optionally disables active network adapters (very aggressive; may cut off remote access immediately).

  Output behavior:
  - The script prints colored status and a final summary to the console.
  - The script emits exactly one structured object to the success pipeline, suitable for Export-Csv / ConvertTo-Json / filtering.

  Safety behavior:
  - Uses ShouldProcess / Confirm semantics. If confirmations are declined, the script records that and reports it in the summary.
  - Any failure is recorded in the structured result and in the console summary.

.PARAMETER Reason
  A human-readable reason that is written to the registry and included in the event message, for auditing and automation.

.PARAMETER DisableAdapters
  If set, disables all network adapters that are currently in "Up" state.
  This is extremely disruptive and should only be used when losing remote connectivity is acceptable.

.PARAMETER BreakGlassRemoteAddress
  One or more remote IP addresses or CIDR subnets that should be allowed inbound (break-glass).
  Use this to preserve a controlled recovery path (for example, an admin jump host subnet).
  If not provided, no break-glass allow is created. Prior activations are never
  removed by prefix; their exact rollback remains authoritative.

.PARAMETER BreakGlassLocalPort
  The TCP destination port exposed to BreakGlassRemoteAddress. Defaults to 3389.

.PARAMETER AutoRollbackMinutes
  If greater than 0, schedules a one-time rollback that:
  - Restores firewall profile defaults to Allow (inbound/outbound),
  - Removes the kill-switch firewall rules created by this script,
  - Removes the rollback task after it runs.
  Use this to reduce the risk of permanent lockout when executing remotely.

.PARAMETER ConfigJsonPath
  Optional path to a JSON configuration file supplied with $ConfigJsonPath.
  If the file is missing or invalid, the script continues with safe defaults and/or explicit parameters.

.PARAMETER ConfigJsonRaw
  Optional raw JSON string. If provided, it takes precedence over ConfigJsonPath.
  If invalid, the script continues with safe defaults and/or explicit parameters.


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

.PARAMETER NoColor
  Disable colored output.

.OUTPUTS
  System.Management.Automation.PSCustomObject

  The script writes exactly one object to the success pipeline with run metadata, effective configuration,
  action results, outcome status (IsolationActive), and an error list.

.NOTES
  Requirements:
  - Administrative privileges are required.

  Operational considerations:
  - Running with -DisableAdapters can immediately drop the current remote session.
  - Break-glass should be planned in advance (known management subnet/IPs).
  - AutoRollback is a safety control; ensure it aligns with the incident-response policy.

.EXAMPLE
  PS> .\21-EmergencyKillSwitch.ps1

  Runs with built-in defaults (no break-glass, no adapter disable, no auto-rollback).
  Confirmation prompts may appear depending on PowerShell preference settings.

.EXAMPLE
  PS> .\21-EmergencyKillSwitch.ps1 -Reason "Suspected malware beaconing"

  Same as default, but records a custom reason in the audit flag and event message.

.EXAMPLE
  PS> .\21-EmergencyKillSwitch.ps1 -BreakGlassRemoteAddress "10.10.10.0/24","203.0.113.10" -AutoRollbackMinutes 30

  Activates isolation while allowing inbound break-glass from the specified subnet/IP, and schedules rollback after 30 minutes.

.EXAMPLE
  PS> .\21-EmergencyKillSwitch.ps1 -DisableAdapters -AutoRollbackMinutes 10 -Confirm:$false

  Aggressively isolates the host (including disabling adapters) and schedules rollback after 10 minutes.
  -Confirm:$false suppresses confirmation prompts.

.EXAMPLE
  PS> $r = .\21-EmergencyKillSwitch.ps1 -ConfigJsonPath $ConfigJsonPath -Confirm:$false
  PS> $r | ConvertTo-Json -Depth 6
  PS> $r.Errors | Out-String

  Runs using optional JSON configuration, captures the structured result object, and exports it for logging/automation.

#>


[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
  [string]$Reason = "Incident/Compromise/Manual KillSwitch",
  [switch]$DisableAdapters,
  [string[]]$BreakGlassRemoteAddress = @(),
  [ValidateRange(1, 65535)]
  [int]$BreakGlassLocalPort = 3389,
  [ValidateRange(0, 1440)]
  [int]$AutoRollbackMinutes = 0,

  [string]$ConfigJsonPath,
  [string]$ConfigJsonRaw

,
  [ValidateSet('Audit','Remediate')][string]$Mode = 'Audit',
  [string]$ConfigPath,
  [ValidateSet('Console','Json','Csv','None')][string]$OutputFormat = 'Console',
  [string]$OutputPath,
  [switch]$PassThru,
  [switch]$Strict,
  [switch]$Quiet,
  [switch]$NoColor
)

. (Join-Path $PSScriptRoot '_lib/Bootstrap.ps1')
Import-Module (Join-Path $script:LibPath 'Common.psm1') -Force -DisableNameChecking
Import-Module (Join-Path $script:LibPath 'Output.psm1') -Force
Import-Module (Join-Path $script:LibPath 'EventLog.psm1') -Force
Import-Module (Join-Path $script:LibPath 'Results.psm1') -Force
Import-Module (Join-Path $script:LibPath Serialization.psm1) -Force


Set-StrictMode -Version Latest
# v2-init (migrated to Initialize-V2Context)
$script:__V2Context = Initialize-V2Context -ScriptName '21-EmergencyKillSwitch.ps1' -BoundParameters $PSBoundParameters `
  -Mode $Mode -ConfigPath $ConfigPath -OutputFormat $OutputFormat -OutputPath $OutputPath `
  -PassThru:$PassThru -Strict:$Strict -Quiet:$Quiet -NoColor:$NoColor -DeriveRemediate
$Remediate = [bool]$script:__V2Context.Remediate
if ($script:__V2Context.Quiet) { $InformationPreference = 'SilentlyContinue'; $VerbosePreference = 'SilentlyContinue' }
$script:NoColor = [bool]$script:__V2Context.NoColor
$ErrorActionPreference = 'Stop'
$Findings = Get-FindingsList

$isWindowsHost = ($env:OS -eq 'Windows_NT')
if (-not $isWindowsHost) {
  $summary = [pscustomobject]@{
    ComputerName = $env:COMPUTERNAME
    Timestamp    = Get-Date
    Mode         = $Mode
    Supported    = $false
    Notes        = @('Skipped: this script is only supported on Windows hosts.')
  }
  $resultToken = if ($Strict) { 'FAIL' } else { 'WARN' }
  $result = Get-V2ResultObject -ScriptName '21-EmergencyKillSwitch.ps1' -Mode $Mode -Result $resultToken -Findings @($Findings.ToArray()) -Summary $summary -Metadata @{ UnsupportedHost = $true }
  Write-ResultObject -ResultObject $result -OutputFormat $OutputFormat -OutputPath $OutputPath
  if ($PassThru) { $result }
  exit (Get-V2ExitCode -Result $resultToken)
}

# -------------------- Safe defaults
$Defaults = [ordered]@{
  EventSource = 'KillSwitch'
  EventLog    = 'Application'
  EventId     = 9001

  RegKey      = 'HKLM:\SOFTWARE\KillSwitch\Quarantine'

  RulePrefix  = 'KILLSWITCH'
  TaskName    = 'KILLSWITCH-ROLLBACK'

  IncludeUserInRegistry = $true

  DisableAdapters         = $false
  BreakGlassRemoteAddress = @()
  AutoRollbackMinutes     = 0
}

# -------------------- Run state for summary + pipeline output
$Run = [ordered]@{
  StartTime    = Get-Date
  EndTime      = $null
  Duration     = $null

  ComputerName = $env:COMPUTERNAME
  User         = "$env:USERDOMAIN\$env:USERNAME"
  IsAdmin      = $false

  JsonPath     = $ConfigJsonPath
  JsonUsed     = $false
  JsonError    = $null

  Effective    = [ordered]@{
    Reason                 = $Reason
    DisableAdapters         = $DisableAdapters.IsPresent
    BreakGlassRemoteAddress = @()
    AutoRollbackMinutes     = $AutoRollbackMinutes

    EventSource             = $Defaults.EventSource
    EventLog                = $Defaults.EventLog
    EventId                 = $Defaults.EventId

    RegKey                  = $Defaults.RegKey
    RulePrefix              = $Defaults.RulePrefix
    TaskName                = $Defaults.TaskName
    IncludeUserInRegistry   = $Defaults.IncludeUserInRegistry
  }

  Actions      = [ordered]@{
    RegistryWritten     = $false
    EventLogWritten     = $false
    FirewallProfileSet  = $false
    RulesCreated        = $false
    BreakGlassApplied   = $false
    BreakGlassCleanupChecked = $false
    BreakGlassRemoved   = $false
    AdaptersDisabled    = $false
    RollbackStateCaptured = $false
    RollbackScheduled   = $false

    # Tracks if user declined confirmations
    ConfirmDeclined     = $false
  }

  Outcome      = [ordered]@{
    IsolationActive     = $false
    IsolationIntended   = $true
  }

  Errors       = New-Object System.Collections.Generic.List[string]
}

function Add-RunError {
  param([string]$Message)
  [void]$Run.Errors.Add($Message)
}

. (Join-Path $PSScriptRoot 'internal/21-EmergencyKillSwitch.helpers.ps1')


function Set-QuarantineFlag {
  [CmdletBinding(SupportsShouldProcess = $true)]
  param(
    [string]$RegKey,
    [string]$ReasonText,
    [bool]$IncludeUser
  )

  try {
    New-Item -Path $RegKey -Force | Out-Null
    Set-ItemProperty -LiteralPath $RegKey -Name 'Isolated' -Value 1 -Force
    Set-ItemProperty -LiteralPath $RegKey -Name 'Time'     -Value ((Get-Date).ToString('s')) -Force
    Set-ItemProperty -LiteralPath $RegKey -Name 'Reason'   -Value $ReasonText -Force
    if ($IncludeUser) {
      Set-ItemProperty -LiteralPath $RegKey -Name 'User' -Value $Run.User -Force
    }
    $Run.Actions.RegistryWritten = $true
  } catch {
    Add-RunError "Registry flag write failed: $($_.Exception.Message)"
  }
}

function Schedule-AutoRollback {
  param(
    [int]$Minutes,
    [string]$TaskName,
    [object[]]$ManagedRules,
    [Parameter(Mandatory=$true)][string]$SnapshotJson
  )

  if ($Minutes -le 0) { return $false }

  # Validate inputs before embedding in heredoc (prevents PS code injection into
  # the base64-encoded rollback script that runs elevated via scheduled task).
  if ($TaskName -notmatch '^[a-zA-Z0-9\-_]+$') {
    Add-RunError "Schedule-AutoRollback: TaskName '$TaskName' contains invalid characters (allowed: a-z A-Z 0-9 - _)"
    return $false
  }
  try { Assert-ManagedFirewallRules -Rules $ManagedRules } catch { Add-RunError "Schedule-AutoRollback: invalid managed rule identities: $($_.Exception.Message)"; return $false }

  $runAt = (Get-Date).AddMinutes($Minutes)
  $logFileName = "KillSwitch-Rollback-$($TaskName -replace '[^a-zA-Z0-9]', '').log"
  $snapshotEncoded = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($SnapshotJson))

  # Improved rollback script with proper error handling and logging (fixes #21)
  $rollbackPs = @"
`$ErrorActionPreference = 'Stop'
`$logPath = Join-Path ([System.IO.Path]::GetTempPath()) '$logFileName'
function Write-RollbackLog { param([string]`$Message) try { Add-Content -Path `$logPath -Value "`$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') `$Message" } catch { <# best-effort: log file may not be writable #> } }
try {
  Write-RollbackLog 'Starting rollback...'
  `$snapshotJson = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('$snapshotEncoded'))
  `$saved = `$snapshotJson | ConvertFrom-Json -ErrorAction Stop
  `$requiredNames = @('Domain', 'Private', 'Public'); `$requiredFields = @('Name', 'Enabled', 'DefaultInboundAction', 'DefaultOutboundAction'); `$validActions = @('Allow', 'Block', 'NotConfigured')
  if (@(`$saved.PSObject.Properties.Name).Count -ne 4 -or @(`$saved.PSObject.Properties.Name | Where-Object { @('Version', 'Profiles', 'Adapters', 'ManagedRules') -notcontains `$_ }).Count -ne 0 -or [int]`$saved.Version -ne 3 -or @(`$saved.Profiles).Count -ne 3 -or @(`$saved.Adapters).Count -gt 128) { throw 'Embedded firewall snapshot has an invalid schema.' }
  `$seen = @{}
  foreach (`$s in @(`$saved.Profiles)) {
    if (`$null -eq `$s -or @(`$s.PSObject.Properties.Name).Count -ne `$requiredFields.Count -or @(`$s.PSObject.Properties.Name | Where-Object { `$requiredFields -notcontains `$_ }).Count -ne 0) { throw 'Embedded firewall snapshot profile has missing or unexpected fields.' }
    if (`$requiredNames -notcontains [string]`$s.Name -or `$seen.ContainsKey([string]`$s.Name)) { throw 'Embedded firewall snapshot has unknown or duplicate profile names.' }
    if (`$s.Enabled -isnot [bool] -or `$validActions -notcontains [string]`$s.DefaultInboundAction -or `$validActions -notcontains [string]`$s.DefaultOutboundAction) { throw 'Embedded firewall snapshot contains invalid profile values.' }
    `$seen[[string]`$s.Name] = `$true
  }
  if (@(`$seen.Keys | Where-Object { `$requiredNames -contains `$_ }).Count -ne 3) { throw 'Embedded firewall snapshot is missing required profiles.' }
  `$seenAdapters = @{}
  foreach (`$adapterName in @(`$saved.Adapters)) {
    if (`$adapterName -isnot [string] -or [string]::IsNullOrWhiteSpace(`$adapterName) -or `$adapterName.Length -gt 256 -or `$adapterName -match '[\x00-\x1f]' -or `$seenAdapters.ContainsKey(`$adapterName)) { throw 'Embedded firewall snapshot contains an invalid or duplicate adapter name.' }
    `$seenAdapters[`$adapterName] = `$true
  }
  `$seenRules = @{}
  foreach (`$managedRule in @(`$saved.ManagedRules)) {
    if (`$null -eq `$managedRule -or @(`$managedRule.PSObject.Properties.Name).Count -ne 3 -or @(`$managedRule.PSObject.Properties.Name | Where-Object { @('Name', 'Direction', 'Action') -notcontains `$_ }).Count -ne 0 -or `$managedRule.Name -isnot [string] -or `$managedRule.Name -notmatch '^[A-Za-z0-9_-]+$' -or `$seenRules.ContainsKey(`$managedRule.Name) -or @('Inbound','Outbound') -notcontains [string]`$managedRule.Direction -or @('Allow','Block') -notcontains [string]`$managedRule.Action) { throw 'Embedded firewall snapshot contains invalid managed rule identities.' }
    `$seenRules[`$managedRule.Name] = `$true
  }
  `$rollbackErrors = New-Object System.Collections.Generic.List[string]
  foreach (`$s in @(`$saved.Profiles)) {
    try { Set-NetFirewallProfile -Name `$s.Name -Enabled `$s.Enabled -DefaultInboundAction `$s.DefaultInboundAction -DefaultOutboundAction `$s.DefaultOutboundAction -ErrorAction Stop }
    catch { [void]`$rollbackErrors.Add("Firewall profile `$(`$s.Name): `$(`$_.Exception.Message)") }
  }
  Write-RollbackLog 'Firewall profiles restored from embedded pre-kill-switch snapshot'
  foreach (`$adapterName in @(`$saved.Adapters)) {
    try { Enable-NetAdapter -Name `$adapterName -Confirm:`$false -ErrorAction Stop }
    catch { [void]`$rollbackErrors.Add("Network adapter `$adapterName: `$(`$_.Exception.Message)") }
  }
  if (@(`$saved.Adapters).Count -gt 0) { Write-RollbackLog 'Network adapters disabled by the kill switch were re-enabled' }
  foreach (`$managedRule in @(`$saved.ManagedRules)) {
    try {
      `$existingRules = @(Get-NetFirewallRule -Name `$managedRule.Name -ErrorAction SilentlyContinue | Where-Object { `$null -ne `$_ })
      `$ownedRules = @(`$existingRules | Where-Object { [string]`$_.Name -eq [string]`$managedRule.Name -and [string]`$_.Direction -eq [string]`$managedRule.Direction -and [string]`$_.Action -eq [string]`$managedRule.Action })
      if (`$ownedRules.Count -ne `$existingRules.Count) { throw "Rule identity mismatch; refusing removal of `$(`$managedRule.Name)." }
      if (`$ownedRules.Count -gt 0) { `$ownedRules | Remove-NetFirewallRule -ErrorAction Stop }
    } catch {
      [void]`$rollbackErrors.Add("Rule `$(`$managedRule.Name) removal: `$(`$_.Exception.Message)")
    }
  }
  Write-RollbackLog 'Kill switch rules removed or already absent'
  if (`$rollbackErrors.Count -gt 0) { throw (`$rollbackErrors -join '; ') }
  Unregister-ScheduledTask -TaskName '$TaskName' -Confirm:`$false -ErrorAction Stop
  Write-RollbackLog 'Rollback task removed'
  Write-RollbackLog 'Rollback completed successfully'
} catch {
  Write-RollbackLog "ERROR: `$(`$_.Exception.Message)"
  exit 1
}
"@

  $bytes = [System.Text.Encoding]::Unicode.GetBytes($rollbackPs)
  $enc   = [Convert]::ToBase64String($bytes)
  $actionArguments = "-NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand $enc"
  if ($actionArguments.Length -gt 30000) {
    Add-RunError "Auto-rollback scheduled-task command exceeds the 30000-character safety limit ($($actionArguments.Length))."
    return $false
  }

  try {
    $powerShellPath = Resolve-CanonicalWindowsPowerShellPath
    $action = New-ScheduledTaskAction -Execute $powerShellPath -Argument $actionArguments
    $trigger = New-ScheduledTaskTrigger -Once -At $runAt
    $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit (New-TimeSpan -Minutes 15)
    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Settings $settings -User 'SYSTEM' -RunLevel Highest -Force -ErrorAction Stop | Out-Null
    $Run.Effective.RollbackRunAt = $runAt
  } catch {
    Add-RunError "Auto-rollback schedule failed: $($_.Exception.Message)"
    return $false
  }

  Write-UiLine "Auto-rollback scheduled for $runAt (log file in scheduled-task temp: $logFileName)" -Style Info
  return $true
}

# -------------------- Load JSON (optional) and merge with defaults/parameters
$config = Try-LoadConfigJson -Path $ConfigJsonPath -Raw $ConfigJsonRaw `
  -PathSupplied:$PSBoundParameters.ContainsKey('ConfigJsonPath') `
  -RawSupplied:$PSBoundParameters.ContainsKey('ConfigJsonRaw')
if ($null -ne $config) { $Run.JsonUsed = $true }
if (-not [string]::IsNullOrWhiteSpace($Run.JsonError)) {
  $message = "Kill-switch configuration is invalid: $($Run.JsonError)"
  Add-RunError $message
  [void](Add-Finding -FindingList $Findings -Code 'KS-InvalidConfig' -Severity 'High' -Message $message -TimeUtc)
  $resultToken = 'FAIL'
  $v2Result = Get-V2ResultObject -ScriptName '21-EmergencyKillSwitch.ps1' -Mode $Mode -Result $resultToken -Findings @($Findings.ToArray()) -Summary ([pscustomobject]$Run) -Metadata @{}
  Write-ResultObject -ResultObject $v2Result -OutputFormat $OutputFormat -OutputPath $OutputPath
  if ($PassThru) { $v2Result }
  exit (Get-V2ExitCode -Result $resultToken)
}

$Run.Effective.EventSource = Get-ConfigValue -Config $config -Name 'EventSource' -Default $Defaults.EventSource
$Run.Effective.EventLog    = Get-ConfigValue -Config $config -Name 'EventLog'    -Default $Defaults.EventLog
$Run.Effective.EventId     = [int](Get-ConfigValue -Config $config -Name 'EventId' -Default $Defaults.EventId)

$Run.Effective.RegKey      = Get-ConfigValue -Config $config -Name 'RegKey'     -Default $Defaults.RegKey

# S7 fix: validate RegKey against allowlist of safe registry prefixes
$regKeyAllowedPrefixes = @('HKLM:\SOFTWARE\', 'HKLM:\SYSTEM\')
$regKeyValid = $false
foreach ($prefix in $regKeyAllowedPrefixes) {
  if ($Run.Effective.RegKey -like "$prefix*") { $regKeyValid = $true; break }
}
if ($Run.Effective.RegKey -match '[*?\[\]]') { $regKeyValid = $false }
if (-not $regKeyValid) {
  $message = "RegKey '$($Run.Effective.RegKey)' must be a literal path under an allowed registry prefix ($($regKeyAllowedPrefixes -join ', ')) and contain no wildcard characters. Aborting."
  Add-RunError $message
  [void](Add-Finding -FindingList $Findings -Code 'KS-InvalidRegKey' -Severity 'High' -Message $message -TimeUtc)
}

$Run.Effective.RulePrefix  = Get-ConfigValue -Config $config -Name 'RulePrefix' -Default $Defaults.RulePrefix

# S8 fix: validate RulePrefix contains only safe characters (alphanumeric, hyphens, underscores) and reasonable length
if ($Run.Effective.RulePrefix -notmatch '^[a-zA-Z0-9_-]+$') {
  $message = "RulePrefix '$($Run.Effective.RulePrefix)' contains invalid characters. Only alphanumeric, hyphens, and underscores are allowed."
  Add-RunError $message
  [void](Add-Finding -FindingList $Findings -Code 'KS-InvalidRulePrefix' -Severity 'High' -Message $message -TimeUtc)
}
if ($Run.Effective.RulePrefix.Length -gt 64) {
  $message = "RulePrefix '$($Run.Effective.RulePrefix)' exceeds 64 characters."
  Add-RunError $message
  [void](Add-Finding -FindingList $Findings -Code 'KS-InvalidRulePrefix' -Severity 'High' -Message $message -TimeUtc)
}
$Run.Effective.TaskName    = Get-ConfigValue -Config $config -Name 'TaskName'   -Default $Defaults.TaskName
$Run.Effective.IncludeUserInRegistry = [bool](Get-ConfigValue -Config $config -Name 'IncludeUserInRegistry' -Default $Defaults.IncludeUserInRegistry)
if ($Run.Effective.TaskName -notmatch '^[a-zA-Z0-9_-]+$' -or $Run.Effective.TaskName.Length -gt 128) {
  $message = "TaskName '$($Run.Effective.TaskName)' must contain only letters, digits, hyphens, and underscores and be at most 128 characters."
  Add-RunError $message
  [void](Add-Finding -FindingList $Findings -Code 'KS-InvalidTaskName' -Severity 'High' -Message $message -TimeUtc)
}

# Apply JSON defaults only if caller did not provide explicit values
if (-not $DisableAdapters.IsPresent) {
  $fromJson = [bool](Get-ConfigValue -Config $config -Name 'DisableAdapters' -Default $Defaults.DisableAdapters)
  if ($fromJson) { $DisableAdapters = $true }
}
if ($BreakGlassRemoteAddress.Count -eq 0) {
  $bg = Get-ConfigValue -Config $config -Name 'BreakGlassRemoteAddress' -Default $Defaults.BreakGlassRemoteAddress
  if ($bg) { $BreakGlassRemoteAddress = @($bg) }
}
if (-not $PSBoundParameters.ContainsKey('BreakGlassLocalPort')) {
  $BreakGlassLocalPort = [int](Get-ConfigValue -Config $config -Name 'BreakGlassLocalPort' -Default $BreakGlassLocalPort)
}
if ($AutoRollbackMinutes -eq 0) {
  $arm = [int](Get-ConfigValue -Config $config -Name 'AutoRollbackMinutes' -Default $Defaults.AutoRollbackMinutes)
  if ($arm -gt 0) { $AutoRollbackMinutes = $arm }
}

$Run.Effective.Reason                 = $Reason
$Run.Effective.DisableAdapters         = $DisableAdapters.IsPresent
$Run.Effective.BreakGlassRemoteAddress = @($BreakGlassRemoteAddress)
$Run.Effective.BreakGlassLocalPort     = $BreakGlassLocalPort
$Run.Effective.AutoRollbackMinutes     = $AutoRollbackMinutes
try {
  Assert-KillSwitchConfig -Config ([pscustomobject]@{ BreakGlassRemoteAddress = @($Run.Effective.BreakGlassRemoteAddress) })
} catch {
  $message = $_.Exception.Message
  Add-RunError $message
  [void](Add-Finding -FindingList $Findings -Code 'KS-InvalidBreakGlassAddress' -Severity 'High' -Message $message -TimeUtc)
}

if ($Run.Errors.Count -gt 0) {
  $resultToken = 'FAIL'
  $v2Result = Get-V2ResultObject -ScriptName '21-EmergencyKillSwitch.ps1' -Mode $Mode -Result $resultToken -Findings @($Findings.ToArray()) -Summary ([pscustomobject]$Run) -Metadata @{}
  Write-ResultObject -ResultObject $v2Result -OutputFormat $OutputFormat -OutputPath $OutputPath
  if ($PassThru) { $v2Result }
  exit (Get-V2ExitCode -Result $resultToken)
}

# Derived identifiers
$rollbackRunId = [guid]::NewGuid().ToString('N')
$RuleInName  = "{0}-{1}-IN-BLOCK"            -f $Run.Effective.RulePrefix, $rollbackRunId
$RuleOutName = "{0}-{1}-OUT-BLOCK"           -f $Run.Effective.RulePrefix, $rollbackRunId
$RuleBgName  = "{0}-{1}-BREAKGLASS-IN-ALLOW" -f $Run.Effective.RulePrefix, $rollbackRunId
$ManagedRules = @(
  [pscustomobject][ordered]@{ Name = $RuleOutName; Direction = 'Outbound'; Action = 'Block' }
)
if ($Run.Effective.BreakGlassRemoteAddress -and $Run.Effective.BreakGlassRemoteAddress.Count -gt 0) {
  $ManagedRules += [pscustomobject][ordered]@{ Name = $RuleBgName; Direction = 'Inbound'; Action = 'Allow' }
} else {
  $ManagedRules += [pscustomobject][ordered]@{ Name = $RuleInName; Direction = 'Inbound'; Action = 'Block' }
}
$rollbackTaskName = "$($Run.Effective.TaskName)-$rollbackRunId"
$Run.Effective.RollbackRunId = $rollbackRunId
$Run.Effective.RollbackTaskName = $rollbackTaskName
$Run.Effective.RollbackSnapshotEmbedded = $false
$Run.Effective.RollbackSnapshotSha256 = $null
$Run.Effective.RollbackRunAt = $null

# -------------------- Execution
$Run.IsAdmin = Test-IsAdmin

if ($Remediate) {
  if (-not (Ensure-EventSource -Source $Run.Effective.EventSource -Log $Run.Effective.EventLog)) {
    Write-Warning "EventSource could not be registered. EventLog tracing will be unavailable."
  }
}

if (-not $Run.IsAdmin -and $Remediate) {
  Add-RunError 'Administrative privileges are required for remediation.'
  Write-UiHeader -Title "Kill Switch"
  Write-UiLine -Text "ERROR: Admin privileges required. Aborting." -Color Red

  if ($Remediate) {
    Write-HealthEvent -Log $Run.Effective.EventLog -Source $Run.Effective.EventSource -Id $Run.Effective.EventId `
      -Msg "KillSwitch aborted: admin privileges required." -Level 'Error'
  }

  Invoke-KillSwitchConsoleSummary
}
elseif (-not $Remediate) {
  Resolve-Outcome

  Write-UiHeader -Title "Kill Switch"
  Write-UiLine -Text "Audit mode: no kill switch actions applied." -Color Yellow
  Write-KeyValue -Key 'Reason' -Value $Run.Effective.Reason -ValueColor Cyan
  Write-KeyValue -Key 'BreakGlass' -Value ($Run.Effective.BreakGlassRemoteAddress -join ', ')
  Write-KeyValue -Key 'AutoRollbackMinutes' -Value $Run.Effective.AutoRollbackMinutes
} else {
$killSwitchLockStream = $null
$rollbackSnapshotJson = $null
$adapterNamesToDisable = @()
$createdManagedRules = New-Object System.Collections.Generic.List[object]
$firewallActivationCommitted = $false
try {
  try {
    $killSwitchLockStream = Enter-KillSwitchRemediationLock
  } catch [System.IO.IOException] {
    Add-RunError 'Another emergency kill-switch remediation is already in progress or its trusted lock cannot be opened exclusively; refusing concurrent execution.'
    throw 'Emergency kill-switch remediation is already in progress.'
  }
  # Inventory is read-only and must complete before scheduled-task mutation.
  # Existing UUID identities belong to an earlier activation whose
  # rollback must remain authoritative; never adopt or delete them by prefix.
  if (-not (Test-NoManagedFirewallRuleConflicts -RulePrefix $Run.Effective.RulePrefix -TaskPrefix $Run.Effective.TaskName)) {
    throw 'A preexisting kill-switch activation or unowned legacy rule was found; refusing overlapping activation.'
  }
  if ($Run.Effective.AutoRollbackMinutes -gt 0 -and -not $Run.Actions.ConfirmDeclined) {
    # Capture and embed immutable state only when automatic rollback is requested.
    if ($PSCmdlet.ShouldProcess($rollbackTaskName, "Capture and validate embedded firewall rollback snapshot")) {
      $rollbackSnapshotJson = Get-CanonicalFirewallRollbackSnapshot -CaptureAdapters:$Run.Effective.DisableAdapters -ManagedRules $ManagedRules
      if ([string]::IsNullOrWhiteSpace($rollbackSnapshotJson)) {
        throw 'Pre-kill-switch firewall snapshot capture failed; aborting before firewall mutation.'
      }
      $adapterNamesToDisable = @(($rollbackSnapshotJson | ConvertFrom-Json -ErrorAction Stop).Adapters)
      $snapshotHash = [System.Security.Cryptography.SHA256]::Create()
      try { $Run.Effective.RollbackSnapshotSha256 = ([System.BitConverter]::ToString($snapshotHash.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($rollbackSnapshotJson))) -replace '-', '').ToLowerInvariant() }
      finally { $snapshotHash.Dispose() }
    } else {
      $Run.Actions.ConfirmDeclined = $true
    }

    # Schedule only after the exact validated snapshot is embedded in its command.
    if ($PSCmdlet.ShouldProcess($rollbackTaskName, "Schedule automatic rollback task")) {
      $Run.Actions.RollbackScheduled = Schedule-AutoRollback -Minutes $Run.Effective.AutoRollbackMinutes -TaskName $rollbackTaskName -ManagedRules $ManagedRules -SnapshotJson $rollbackSnapshotJson
      if (-not $Run.Actions.RollbackScheduled) {
        throw 'Automatic rollback scheduling failed; aborting before firewall mutation.'
      }
      $Run.Effective.RollbackSnapshotEmbedded = $true
    } else {
      $Run.Actions.ConfirmDeclined = $true
    }
  }

  # A declined capture or schedule prompt must not be followed by a later
  # confirmed firewall mutation. Treat the safety prerequisites as one gate.
  if (-not $Run.Actions.ConfirmDeclined) {
  # Prepare and verify every exact rule identity before changing profile
  # defaults. In particular, break-glass failure must not strand the host in an
  # isolated state without its recovery path.
  if ($PSCmdlet.ShouldProcess("Windows Defender Firewall Rules", "Create kill switch rules")) {
    $inRuleCreated = $true
    if ($Run.Effective.BreakGlassRemoteAddress -and $Run.Effective.BreakGlassRemoteAddress.Count -gt 0) {
      $Run.Actions.BreakGlassApplied = New-OrReplaceRule -Name $RuleBgName -DisplayName "$($Run.Effective.RulePrefix) BreakGlass Inbound Allow" `
        -Direction Inbound -Action Allow -RemoteAddress $Run.Effective.BreakGlassRemoteAddress -Protocol TCP -LocalPort $Run.Effective.BreakGlassLocalPort -Description "Kill switch: break-glass inbound allow"
      if (-not $Run.Actions.BreakGlassApplied) { throw 'Break-glass firewall rule creation or verification failed; aborting before isolation.' }
      [void]$createdManagedRules.Add(($ManagedRules | Where-Object { $_.Name -eq $RuleBgName })[0])
    } else {
      $inRuleCreated = New-OrReplaceRule -Name $RuleInName  -DisplayName "$($Run.Effective.RulePrefix) Inbound Block"  -Direction Inbound  -Action Block -Description "Kill switch: block inbound"
      if (-not $inRuleCreated) { throw 'Inbound block firewall rule creation or verification failed.' }
      [void]$createdManagedRules.Add(($ManagedRules | Where-Object { $_.Name -eq $RuleInName })[0])
    }
    $outRuleCreated = New-OrReplaceRule -Name $RuleOutName -DisplayName "$($Run.Effective.RulePrefix) Outbound Block" -Direction Outbound -Action Block -Description "Kill switch: block outbound"
    if (-not $outRuleCreated) { throw 'Outbound block firewall rule creation or verification failed.' }
    [void]$createdManagedRules.Add(($ManagedRules | Where-Object { $_.Name -eq $RuleOutName })[0])
    $Run.Actions.RulesCreated = [bool]($inRuleCreated -and $outRuleCreated)
  } else {
    $Run.Actions.ConfirmDeclined = $true
  }

  if (-not $Run.Actions.ConfirmDeclined -and $PSCmdlet.ShouldProcess("Windows Firewall Profiles", "Enable firewall + set DefaultInboundAction=Block, DefaultOutboundAction=Block")) {
    Set-NetFirewallProfile -All -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Block
    $Run.Actions.FirewallProfileSet = $true
    $firewallActivationCommitted = $true
    # Do not persist an isolation indicator until the protective firewall
    # posture has committed. Pre-commit failures must leave no false state.
    if ($PSCmdlet.ShouldProcess($Run.Effective.RegKey, "Write quarantine registry flag")) {
      Set-QuarantineFlag -RegKey $Run.Effective.RegKey -ReasonText $Run.Effective.Reason -IncludeUser $Run.Effective.IncludeUserInRegistry
    } else {
      $Run.Actions.ConfirmDeclined = $true
    }
  } else {
    $Run.Actions.ConfirmDeclined = $true
  }

  if ($DisableAdapters) {
    if ($PSCmdlet.ShouldProcess("Network Adapters", "Disable all Up adapters")) {
      if ($Run.Effective.AutoRollbackMinutes -le 0) {
        $adapterNamesToDisable = @(Get-NetAdapter -ErrorAction Stop | Where-Object { $_.Status -eq 'Up' } | ForEach-Object { [string]$_.Name })
      }
      foreach ($adapterName in $adapterNamesToDisable) {
        Disable-NetAdapter -Name $adapterName -Confirm:$false -ErrorAction Stop
      }
      $Run.Actions.AdaptersDisabled = ($adapterNamesToDisable.Count -gt 0)
    } else {
      $Run.Actions.ConfirmDeclined = $true
    }
  }
  }

  Resolve-Outcome

  $level = if ($Run.Outcome.IsolationActive) { 'Warning' } else { 'Information' }
  $eventMsg = @"
Kill switch run completed.
IsolationActive: $($Run.Outcome.IsolationActive)
Reason: $($Run.Effective.Reason)
Time  : $(Get-Date -Format 's')
FirewallProfileSet: $($Run.Actions.FirewallProfileSet)
RulesCreated: $($Run.Actions.RulesCreated)
AdaptersDisabled: $($Run.Actions.AdaptersDisabled)
BreakGlassApplied: $($Run.Actions.BreakGlassApplied)
AutoRollbackMinutes: $($Run.Effective.AutoRollbackMinutes)
"@.Trim()

  Write-HealthEvent -Log $Run.Effective.EventLog -Source $Run.Effective.EventSource -Id $Run.Effective.EventId -Msg $eventMsg -Level $level

  Write-UiHeader -Title "Kill Switch"
  if ($Run.Outcome.IsolationActive) {
    Write-UiLine -Text "Isolation is ACTIVE." -Color Green
  } else {
    Write-UiLine -Text "Isolation is NOT active (actions were skipped/declined)." -Color Yellow
  }
  Write-KeyValue -Key 'Reason' -Value $Run.Effective.Reason -ValueColor Cyan
  Write-KeyValue -Key 'BreakGlass' -Value ($Run.Effective.BreakGlassRemoteAddress -join ', ')
  Write-KeyValue -Key 'AutoRollbackMinutes' -Value $Run.Effective.AutoRollbackMinutes
}
catch {
  $err = $_.Exception.Message
  Add-RunError "Unhandled error: $err"

  $rollbackTaskCancelled = $true
  if (-not $firewallActivationCommitted -and $Run.Actions.RollbackScheduled) {
    try {
      Unregister-ScheduledTask -TaskName $rollbackTaskName -Confirm:$false -ErrorAction Stop
      $Run.Actions.RollbackScheduled = $false
      $Run.Effective.RollbackSnapshotEmbedded = $false
    } catch {
      $rollbackTaskCancelled = $false
      Add-RunError "Failed activation rollback-task cancellation failed: $($_.Exception.Message)"
    }
  }
  if (-not $firewallActivationCommitted -and $rollbackTaskCancelled -and $createdManagedRules.Count -gt 0) {
    try {
      Remove-ExactManagedFirewallRules -Rules @($createdManagedRules.ToArray())
    } catch {
      Add-RunError "Partial activation cleanup failed: $($_.Exception.Message)"
    }
  }

  Write-HealthEvent -Log $Run.Effective.EventLog -Source $Run.Effective.EventSource -Id $Run.Effective.EventId `
    -Msg ("KillSwitch failed: {0}" -f $err) -Level 'Error'

  Write-UiHeader -Title "Kill Switch"
  Write-UiLine -Text ("ERROR: {0}" -f $err) -Color Red
}
finally {
  # Always write console summary, even if an exception is thrown.
  try { Invoke-KillSwitchConsoleSummary } catch { Write-UiLine "Summary failed: $($_.Exception.Message)" -ForegroundColor Yellow }
  if ($null -ne $killSwitchLockStream) {
    $killSwitchLockStream.Dispose()
  }
}
}

# V2 output contract
$completedActionNames = @(
  'RegistryWritten',
  'EventLogWritten',
  'FirewallProfileSet',
  'RulesCreated',
  'BreakGlassApplied',
  'BreakGlassRemoved',
  'AdaptersDisabled',
  'RollbackScheduled'
)
$successfulActions = @($completedActionNames | Where-Object { $Run.Actions[$_] -eq $true })
$actionsDeclinedOrDryRun = ($WhatIfPreference -eq $true -or $Run.Actions.ConfirmDeclined)
if ($Run.Errors.Count -eq 0 -and $successfulActions.Count -eq 0 -and $actionsDeclinedOrDryRun) {
  $null = Add-Finding -FindingList $Findings -Code 'KS-ActionsDeclinedOrDryRun' -Severity 'Medium' `
    -Message 'Kill switch ran but no protective actions were completed.'
}
$resultToken = if ($Run.Errors.Count -gt 0) { 'FAIL' } elseif ($successfulActions.Count -gt 0 -or $Findings.Count -gt 0) { 'WARN' } else { 'OK' }
if ($Strict -and $resultToken -eq 'WARN') { $resultToken = 'FAIL' }
$v2Result = Get-V2ResultObject -ScriptName '21-EmergencyKillSwitch.ps1' -Mode $Mode -Result $resultToken -Findings @($Findings.ToArray()) -Summary ([pscustomobject]$Run) -Metadata @{}
Write-ResultObject -ResultObject $v2Result -OutputFormat $OutputFormat -OutputPath $OutputPath
if ($PassThru) { $v2Result }
exit (Get-V2ExitCode -Result $resultToken)
