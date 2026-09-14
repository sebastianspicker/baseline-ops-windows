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
function Initialize-Capability21Runtime {
  param($EntryBoundParameters)
  $RunState = @{

  }
Import-Module (Join-Path $script:LibPath 'Common.psm1') -Force -DisableNameChecking
Import-Module (Join-Path $script:LibPath 'Output.psm1') -Force
Import-Module (Join-Path $script:LibPath 'EventLog.psm1') -Force
Import-Module (Join-Path $script:LibPath 'Results.psm1') -Force
Import-Module (Join-Path $script:LibPath Serialization.psm1) -Force


Set-StrictMode -Version Latest
$script:__V2Context = Initialize-V2Context -ScriptName '21-EmergencyKillSwitch.ps1' -BoundParameters $EntryBoundParameters `
  -Values @{ Mode = $Mode; ConfigPath = $ConfigPath; OutputFormat = $OutputFormat; OutputPath = $OutputPath; PassThru = $PassThru; Strict = $Strict; Quiet = $Quiet; NoColor = $NoColor; DeriveRemediate = $true }
$RunState.Remediate = [bool]$script:__V2Context.Remediate
if ($script:__V2Context.Quiet) { $InformationPreference = 'SilentlyContinue'; $VerbosePreference = 'SilentlyContinue' }
$script:NoColor = [bool]$script:__V2Context.NoColor
$ErrorActionPreference = 'Stop'
$RunState.Findings = Get-FindingsList

$RunState.isWindowsHost = ($env:OS -eq 'Windows_NT')
  $script:RunState = $RunState
}

. Initialize-Capability21Runtime -EntryBoundParameters $PSBoundParameters
if (-not $RunState.isWindowsHost) {
  $summary = [pscustomobject]@{
    ComputerName = $env:COMPUTERNAME
    Timestamp    = Get-Date
    Mode         = $Mode
    Supported    = $false
    Notes        = @('Skipped: this script is only supported on Windows hosts.')
  }
  $resultToken = if ($Strict) { 'FAIL' } else { 'WARN' }
  $result = Get-V2ResultObject -ScriptName '21-EmergencyKillSwitch.ps1' -Mode $Mode -Result $resultToken -Findings @($RunState.Findings.ToArray()) -Summary $summary -Metadata @{ UnsupportedHost = $true }
  Write-ResultObject -ResultObject $result -OutputFormat $OutputFormat -OutputPath $OutputPath
  if ($PassThru) { $result }
  exit (Get-V2ExitCode -Result $resultToken)
}

# -------------------- Safe defaults
function Initialize-Capability21Defaults {
  param([hashtable]$RunState)
$RunState.Defaults = [ordered]@{
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
}
function Initialize-Capability21RunState {
  param([hashtable]$RunState)
$RunState.Run = [ordered]@{
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

    EventSource             = $RunState.Defaults.EventSource
    EventLog                = $RunState.Defaults.EventLog
    EventId                 = $RunState.Defaults.EventId

    RegKey                  = $RunState.Defaults.RegKey
    RulePrefix              = $RunState.Defaults.RulePrefix
    TaskName                = $RunState.Defaults.TaskName
    IncludeUserInRegistry   = $RunState.Defaults.IncludeUserInRegistry
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
}
function Initialize-EmergencyKillSwitchState {
  param([hashtable]$RunState)
  . Initialize-Capability21Defaults -RunState $RunState
  . Initialize-Capability21RunState -RunState $RunState
}
. Initialize-EmergencyKillSwitchState -RunState $RunState

. (Join-Path $PSScriptRoot 'internal/21-EmergencyKillSwitch.helpers.ps1')




# -------------------- Load JSON (optional) and merge with defaults/parameters
function Invoke-Capability21MainPhase01 {
  param([hashtable]$RunState)
  $RunState.config = Try-LoadConfigJson -Path $ConfigJsonPath -Raw $ConfigJsonRaw `
    -PathSupplied:$script:__EntryBoundParameters.ContainsKey('ConfigJsonPath') `
    -RawSupplied:$script:__EntryBoundParameters.ContainsKey('ConfigJsonRaw') -RunState $RunState
  if ($null -ne $RunState.config) { $RunState.Run.JsonUsed = $true }
  if (-not [string]::IsNullOrWhiteSpace($RunState.Run.JsonError)) {
    $message = "Kill-switch configuration is invalid: $($RunState.Run.JsonError)"
    Add-RunError $message -RunState $RunState
    [void](Add-Finding -FindingList $RunState.Findings -Code 'KS-InvalidConfig' -Severity 'High' -Message $message -TimeUtc)
    $resultToken = 'FAIL'
    $v2Result = Get-V2ResultObject -ScriptName '21-EmergencyKillSwitch.ps1' -Mode $Mode -Result $resultToken -Findings @($RunState.Findings.ToArray()) -Summary ([pscustomobject]$RunState.Run) -Metadata @{}
    Write-ResultObject -ResultObject $v2Result -OutputFormat $OutputFormat -OutputPath $OutputPath
    if ($PassThru) { $v2Result }
    exit (Get-V2ExitCode -Result $resultToken)
  }

  $RunState.Run.Effective.EventSource = Get-ConfigValue -Config $RunState.config -Name 'EventSource' -Default $RunState.Defaults.EventSource
  $RunState.Run.Effective.EventLog    = Get-ConfigValue -Config $RunState.config -Name 'EventLog'    -Default $RunState.Defaults.EventLog
  $RunState.Run.Effective.EventId     = [int](Get-ConfigValue -Config $RunState.config -Name 'EventId' -Default $RunState.Defaults.EventId)

  $RunState.Run.Effective.RegKey      = Get-ConfigValue -Config $RunState.config -Name 'RegKey'     -Default $RunState.Defaults.RegKey

  # S7 fix: validate RegKey against allowlist of safe registry prefixes
  $regKeyAllowedPrefixes = @('HKLM:\SOFTWARE\', 'HKLM:\SYSTEM\')
  $RunState.regKeyValid = $false
  foreach ($prefix in $regKeyAllowedPrefixes) {
    if ($RunState.Run.Effective.RegKey -like "$prefix*") { $RunState.regKeyValid = $true; break }
  }
}
function Invoke-Capability21MainPhase02 {
  param([hashtable]$RunState)
  if ($RunState.Run.Effective.RegKey -match '[*?\[\]]') { $RunState.regKeyValid = $false }
  if (-not $RunState.regKeyValid) {
    $message = "RegKey '$($RunState.Run.Effective.RegKey)' must be a literal path under an allowed registry prefix ($($regKeyAllowedPrefixes -join ', ')) and contain no wildcard characters. Aborting."
    Add-RunError $message -RunState $RunState
    [void](Add-Finding -FindingList $RunState.Findings -Code 'KS-InvalidRegKey' -Severity 'High' -Message $message -TimeUtc)
  }

  $RunState.Run.Effective.RulePrefix  = Get-ConfigValue -Config $RunState.config -Name 'RulePrefix' -Default $RunState.Defaults.RulePrefix

  # S8 fix: validate RulePrefix contains only safe characters (alphanumeric, hyphens, underscores) and reasonable length
  if ($RunState.Run.Effective.RulePrefix -notmatch '^[a-zA-Z0-9_-]+$') {
    $message = "RulePrefix '$($RunState.Run.Effective.RulePrefix)' contains invalid characters. Only alphanumeric, hyphens, and underscores are allowed."
    Add-RunError $message -RunState $RunState
    [void](Add-Finding -FindingList $RunState.Findings -Code 'KS-InvalidRulePrefix' -Severity 'High' -Message $message -TimeUtc)
  }
  if ($RunState.Run.Effective.RulePrefix.Length -gt 64) {
    $message = "RulePrefix '$($RunState.Run.Effective.RulePrefix)' exceeds 64 characters."
    Add-RunError $message -RunState $RunState
    [void](Add-Finding -FindingList $RunState.Findings -Code 'KS-InvalidRulePrefix' -Severity 'High' -Message $message -TimeUtc)
  }
  $RunState.Run.Effective.TaskName    = Get-ConfigValue -Config $RunState.config -Name 'TaskName'   -Default $RunState.Defaults.TaskName
  $RunState.Run.Effective.IncludeUserInRegistry = [bool](Get-ConfigValue -Config $RunState.config -Name 'IncludeUserInRegistry' -Default $RunState.Defaults.IncludeUserInRegistry)
}
function Invoke-Capability21MainPhase03 {
  param([hashtable]$RunState)
  if ($RunState.Run.Effective.TaskName -notmatch '^[a-zA-Z0-9_-]+$' -or $RunState.Run.Effective.TaskName.Length -gt 128) {
    $message = "TaskName '$($RunState.Run.Effective.TaskName)' must contain only letters, digits, hyphens, and underscores and be at most 128 characters."
    Add-RunError $message -RunState $RunState
    [void](Add-Finding -FindingList $RunState.Findings -Code 'KS-InvalidTaskName' -Severity 'High' -Message $message -TimeUtc)
  }

  # Apply JSON defaults only if caller did not provide explicit values
  if (-not $DisableAdapters.IsPresent) {
    $fromJson = [bool](Get-ConfigValue -Config $RunState.config -Name 'DisableAdapters' -Default $RunState.Defaults.DisableAdapters)
    if ($fromJson) { $DisableAdapters = $true }
  }
}
function Invoke-Capability21MainPhase04 {
  param([hashtable]$RunState)
  if ($BreakGlassRemoteAddress.Count -eq 0) {
    $bg = Get-ConfigValue -Config $RunState.config -Name 'BreakGlassRemoteAddress' -Default $RunState.Defaults.BreakGlassRemoteAddress
    if ($bg) { $BreakGlassRemoteAddress = @($bg) }
  }
  if (-not $script:__EntryBoundParameters.ContainsKey('BreakGlassLocalPort')) {
    $BreakGlassLocalPort = [int](Get-ConfigValue -Config $RunState.config -Name 'BreakGlassLocalPort' -Default $BreakGlassLocalPort)
  }
  if ($AutoRollbackMinutes -eq 0) {
    $arm = [int](Get-ConfigValue -Config $RunState.config -Name 'AutoRollbackMinutes' -Default $RunState.Defaults.AutoRollbackMinutes)
    if ($arm -gt 0) { $AutoRollbackMinutes = $arm }
  }

  $RunState.Run.Effective.Reason                 = $Reason
  $RunState.Run.Effective.DisableAdapters         = $DisableAdapters.IsPresent
  $RunState.Run.Effective.BreakGlassRemoteAddress = @($BreakGlassRemoteAddress)
  $RunState.Run.Effective.BreakGlassLocalPort     = $BreakGlassLocalPort
  $RunState.Run.Effective.AutoRollbackMinutes     = $AutoRollbackMinutes
}
function Invoke-Capability21MainPhase05 {
  param([hashtable]$RunState)
  try {
    Assert-KillSwitchConfig -Config ([pscustomobject]@{ BreakGlassRemoteAddress = @($RunState.Run.Effective.BreakGlassRemoteAddress) }) -RunState $RunState
  } catch {
    $message = $_.Exception.Message
    Add-RunError $message -RunState $RunState
    [void](Add-Finding -FindingList $RunState.Findings -Code 'KS-InvalidBreakGlassAddress' -Severity 'High' -Message $message -TimeUtc)
  }

  if ($RunState.Run.Errors.Count -gt 0) {
    $resultToken = 'FAIL'
    $v2Result = Get-V2ResultObject -ScriptName '21-EmergencyKillSwitch.ps1' -Mode $Mode -Result $resultToken -Findings @($RunState.Findings.ToArray()) -Summary ([pscustomobject]$RunState.Run) -Metadata @{}
    Write-ResultObject -ResultObject $v2Result -OutputFormat $OutputFormat -OutputPath $OutputPath
    if ($PassThru) { $v2Result }
    exit (Get-V2ExitCode -Result $resultToken)
  }

  # Derived identifiers
  $rollbackRunId = [guid]::NewGuid().ToString('N')
  $RuleInName  = "{0}-{1}-IN-BLOCK"            -f $RunState.Run.Effective.RulePrefix, $rollbackRunId
  $RuleOutName = "{0}-{1}-OUT-BLOCK"           -f $RunState.Run.Effective.RulePrefix, $rollbackRunId
  $RuleBgName  = "{0}-{1}-BREAKGLASS-IN-ALLOW" -f $RunState.Run.Effective.RulePrefix, $rollbackRunId
  $ManagedRules = @(
    [pscustomobject][ordered]@{ Name = $RuleOutName; Direction = 'Outbound'; Action = 'Block' }
  )
  if ($RunState.Run.Effective.BreakGlassRemoteAddress -and $RunState.Run.Effective.BreakGlassRemoteAddress.Count -gt 0) {
    $ManagedRules += [pscustomobject][ordered]@{ Name = $RuleBgName; Direction = 'Inbound'; Action = 'Allow' }
  } else {
    $ManagedRules += [pscustomobject][ordered]@{ Name = $RuleInName; Direction = 'Inbound'; Action = 'Block' }
  }
  $rollbackTaskName = "$($RunState.Run.Effective.TaskName)-$rollbackRunId"
  $RunState.Run.Effective.RollbackRunId = $rollbackRunId
  $RunState.Run.Effective.RollbackTaskName = $rollbackTaskName
  $RunState.Run.Effective.RollbackSnapshotEmbedded = $false
  $RunState.Run.Effective.RollbackSnapshotSha256 = $null
  $RunState.Run.Effective.RollbackRunAt = $null

  # -------------------- Execution
  $RunState.Run.IsAdmin = Test-IsAdmin
}
function Invoke-Capability21MainPhase06 {
  param([hashtable]$RunState)
  if ($RunState.Remediate) {
    if (-not (Ensure-EventSource -Source $RunState.Run.Effective.EventSource -Log $RunState.Run.Effective.EventLog)) {
      Write-Warning "EventSource could not be registered. EventLog tracing will be unavailable."
    }
  }
}
function Invoke-Capability21MainPhase07Step01 {
  param([hashtable]$RunState)
$RunState.killSwitchLockStream = $null
  $RunState.rollbackSnapshotJson = $null
  $RunState.adapterNamesToDisable = @()
  $RunState.createdManagedRules = New-Object System.Collections.Generic.List[object]
  $RunState.firewallActivationCommitted = $false
}

function Invoke-Capability21MainPhase07Step02Stage01 {
  param([hashtable]$RunState)
try {
      $RunState.killSwitchLockStream = Enter-KillSwitchRemediationLock
    } catch [System.IO.IOException] {
      Add-RunError 'Another emergency kill-switch remediation is already in progress or its trusted lock cannot be opened exclusively; refusing concurrent execution.' -RunState $RunState
      throw 'Emergency kill-switch remediation is already in progress.'
    }
    # Inventory is read-only and must complete before scheduled-task mutation.
    # Existing UUID identities belong to an earlier activation whose
    # rollback must remain authoritative; never adopt or delete them by prefix.
    if (-not (Test-NoManagedFirewallRuleConflicts -RulePrefix $RunState.Run.Effective.RulePrefix -TaskPrefix $RunState.Run.Effective.TaskName -RunState $RunState)) {
      throw 'A preexisting kill-switch activation or unowned legacy rule was found; refusing overlapping activation.'
    }
}

function Invoke-Capability21MainPhase07Step02Stage02 {
  param([hashtable]$RunState)
if ((Test-AllConditions -Conditions @({ $RunState.Run.Effective.AutoRollbackMinutes -gt 0 }, { -not $RunState.Run.Actions.ConfirmDeclined }))) {
      # Capture and embed immutable state only when automatic rollback is requested.
      if ($script:__EntryCmdlet.ShouldProcess($rollbackTaskName, "Capture and validate embedded firewall rollback snapshot")) {
        $RunState.rollbackSnapshotJson = Get-CanonicalFirewallRollbackSnapshot -CaptureAdapters:$RunState.Run.Effective.DisableAdapters -ManagedRules $ManagedRules -RunState $RunState
        if ([string]::IsNullOrWhiteSpace($RunState.rollbackSnapshotJson)) {
          throw 'Pre-kill-switch firewall snapshot capture failed; aborting before firewall mutation.'
        }
        $RunState.adapterNamesToDisable = @(($RunState.rollbackSnapshotJson | ConvertFrom-Json -ErrorAction Stop).Adapters)
        $snapshotHash = [System.Security.Cryptography.SHA256]::Create()
        try { $RunState.Run.Effective.RollbackSnapshotSha256 = ([System.BitConverter]::ToString($snapshotHash.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($RunState.rollbackSnapshotJson))) -replace '-', '').ToLowerInvariant() }
        finally { $snapshotHash.Dispose() }
      } else {
        $RunState.Run.Actions.ConfirmDeclined = $true
      }

      # Schedule only after the exact validated snapshot is embedded in its command.
      if ($script:__EntryCmdlet.ShouldProcess($rollbackTaskName, "Schedule automatic rollback task")) {
        $RunState.Run.Actions.RollbackScheduled = Schedule-AutoRollback -Minutes $RunState.Run.Effective.AutoRollbackMinutes -TaskName $rollbackTaskName -ManagedRules $ManagedRules -SnapshotJson $RunState.rollbackSnapshotJson -RunState $RunState
        if (-not $RunState.Run.Actions.RollbackScheduled) {
          throw 'Automatic rollback scheduling failed; aborting before firewall mutation.'
        }
        $RunState.Run.Effective.RollbackSnapshotEmbedded = $true
      } else {
        $RunState.Run.Actions.ConfirmDeclined = $true
      }
    }
}

function Add-KillSwitchFirewallRules {
  param([hashtable]$RunState)
    if ($script:__EntryCmdlet.ShouldProcess("Windows Defender Firewall Rules", "Create kill switch rules")) {
      $inRuleCreated = $true
      if ((Test-AllConditions -Conditions @({ $RunState.Run.Effective.BreakGlassRemoteAddress }, { $RunState.Run.Effective.BreakGlassRemoteAddress.Count -gt 0 }))) {
        $breakGlassRule = New-KillSwitchFirewallRuleData -Name $RuleBgName `
          -DisplayName "$($RunState.Run.Effective.RulePrefix) BreakGlass Inbound Allow" -Direction Inbound -Action Allow `
          -RemoteAddress $RunState.Run.Effective.BreakGlassRemoteAddress -Protocol TCP `
          -LocalPort $RunState.Run.Effective.BreakGlassLocalPort -Description 'Kill switch: break-glass inbound allow'
        $RunState.Run.Actions.BreakGlassApplied = Invoke-NewOrReplaceRule -Data $breakGlassRule -RunState $RunState -DecisionContext $script:__EntryCmdlet
        if (-not $RunState.Run.Actions.BreakGlassApplied) { throw 'Break-glass firewall rule creation or verification failed; aborting before isolation.' }
        [void]$RunState.createdManagedRules.Add(($ManagedRules | Where-Object { $_.Name -eq $RuleBgName })[0])
      } else {
        $inboundRule = New-KillSwitchFirewallRuleData -Name $RuleInName `
          -DisplayName "$($RunState.Run.Effective.RulePrefix) Inbound Block" -Direction Inbound -Action Block `
          -Description 'Kill switch: block inbound'
        $inRuleCreated = Invoke-NewOrReplaceRule -Data $inboundRule -RunState $RunState -DecisionContext $script:__EntryCmdlet
        if (-not $inRuleCreated) { throw 'Inbound block firewall rule creation or verification failed.' }
        [void]$RunState.createdManagedRules.Add(($ManagedRules | Where-Object { $_.Name -eq $RuleInName })[0])
      }
      $outboundRule = New-KillSwitchFirewallRuleData -Name $RuleOutName `
        -DisplayName "$($RunState.Run.Effective.RulePrefix) Outbound Block" -Direction Outbound -Action Block `
        -Description 'Kill switch: block outbound'
      $outRuleCreated = Invoke-NewOrReplaceRule -Data $outboundRule -RunState $RunState -DecisionContext $script:__EntryCmdlet
      if (-not $outRuleCreated) { throw 'Outbound block firewall rule creation or verification failed.' }
      [void]$RunState.createdManagedRules.Add(($ManagedRules | Where-Object { $_.Name -eq $RuleOutName })[0])
      $RunState.Run.Actions.RulesCreated = [bool]((Test-AllConditions -Conditions @({ $inRuleCreated }, { $outRuleCreated })))
    } else {
      $RunState.Run.Actions.ConfirmDeclined = $true
    }
}
function Enable-KillSwitchFirewallProfiles {
  param([hashtable]$RunState)
    if ((Test-AllConditions -Conditions @({ -not $RunState.Run.Actions.ConfirmDeclined }, { $script:__EntryCmdlet.ShouldProcess("Windows Firewall Profiles", "Enable firewall + set DefaultInboundAction=Block, DefaultOutboundAction=Block") }))) {
      Set-NetFirewallProfile -All -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Block
      $RunState.Run.Actions.FirewallProfileSet = $true
      $RunState.firewallActivationCommitted = $true
      # Do not persist an isolation indicator until the protective firewall
      # posture has committed. Pre-commit failures must leave no false state.
      if ($script:__EntryCmdlet.ShouldProcess($RunState.Run.Effective.RegKey, "Write quarantine registry flag")) {
        Set-QuarantineFlag -RegKey $RunState.Run.Effective.RegKey -ReasonText $RunState.Run.Effective.Reason -IncludeUser $RunState.Run.Effective.IncludeUserInRegistry -RunState $RunState
      } else {
        $RunState.Run.Actions.ConfirmDeclined = $true
      }
    } else {
      $RunState.Run.Actions.ConfirmDeclined = $true
    }
}
function Disable-KillSwitchNetworkAdapters {
  param([hashtable]$RunState)
    if ($DisableAdapters) {
      if ($script:__EntryCmdlet.ShouldProcess("Network Adapters", "Disable all Up adapters")) {
        if ($RunState.Run.Effective.AutoRollbackMinutes -le 0) {
          $RunState.adapterNamesToDisable = @(Get-NetAdapter -ErrorAction Stop | Where-Object { $_.Status -eq 'Up' } | ForEach-Object { [string]$_.Name })
        }
        foreach ($adapterName in $RunState.adapterNamesToDisable) {
          Disable-NetAdapter -Name $adapterName -Confirm:$false -ErrorAction Stop
        }
        $RunState.Run.Actions.AdaptersDisabled = ($RunState.adapterNamesToDisable.Count -gt 0)
      } else {
        $RunState.Run.Actions.ConfirmDeclined = $true
      }
    }
}
function Invoke-Capability21MainPhase07Step02Stage03 {
  param([hashtable]$RunState)
  if (-not $RunState.Run.Actions.ConfirmDeclined) {
    . Add-KillSwitchFirewallRules -RunState $RunState
    . Enable-KillSwitchFirewallProfiles -RunState $RunState
    . Disable-KillSwitchNetworkAdapters -RunState $RunState
    }
}
function Undo-PartialKillSwitchActivation {
  param([hashtable]$RunState)
    $rollbackTaskCancelled = $true
    if ((Test-AllConditions -Conditions @({ -not $RunState.firewallActivationCommitted }, { $RunState.Run.Actions.RollbackScheduled }))) {
      try {
        Unregister-ScheduledTask -TaskName $rollbackTaskName -Confirm:$false -ErrorAction Stop
        $RunState.Run.Actions.RollbackScheduled = $false
        $RunState.Run.Effective.RollbackSnapshotEmbedded = $false
      } catch {
        $rollbackTaskCancelled = $false
        Add-RunError "Failed activation rollback-task cancellation failed: $($_.Exception.Message)" -RunState $RunState
      }
    }
    if ((Test-AllConditions -Conditions @({ (Test-AllConditions -Conditions @({ -not $RunState.firewallActivationCommitted }, { $rollbackTaskCancelled })) }, { $RunState.createdManagedRules.Count -gt 0 }))) {
      try { Remove-ExactManagedFirewallRules -Rules @($RunState.createdManagedRules.ToArray()) -RunState $RunState }
      catch { Add-RunError "Partial activation cleanup failed: $($_.Exception.Message)" -RunState $RunState }
    }
}

function Invoke-Capability21MainPhase07Step02Stage04 {
  param([hashtable]$RunState)
Resolve-Outcome -RunState $RunState

    $level = if ($RunState.Run.Outcome.IsolationActive) { 'Warning' } else { 'Information' }
    $eventMsg = @"
  Kill switch run completed.
  IsolationActive: $($RunState.Run.Outcome.IsolationActive)
  Reason: $($RunState.Run.Effective.Reason)
  Time  : $(Get-Date -Format 's')
  FirewallProfileSet: $($RunState.Run.Actions.FirewallProfileSet)
  RulesCreated: $($RunState.Run.Actions.RulesCreated)
  AdaptersDisabled: $($RunState.Run.Actions.AdaptersDisabled)
  BreakGlassApplied: $($RunState.Run.Actions.BreakGlassApplied)
  AutoRollbackMinutes: $($RunState.Run.Effective.AutoRollbackMinutes)
"@.Trim()

    Write-HealthEvent -Log $RunState.Run.Effective.EventLog -Source $RunState.Run.Effective.EventSource -Id $RunState.Run.Effective.EventId -Msg $eventMsg -Level $level

    Write-UiHeader -Title "Kill Switch"
    if ($RunState.Run.Outcome.IsolationActive) {
      Write-UiLine -Text "Isolation is ACTIVE." -Color Green
    } else {
      Write-UiLine -Text "Isolation is NOT active (actions were skipped/declined)." -Color Yellow
    }
    Write-KeyValue -Key 'Reason' -Value $RunState.Run.Effective.Reason -ValueColor Cyan
    Write-KeyValue -Key 'BreakGlass' -Value ($RunState.Run.Effective.BreakGlassRemoteAddress -join ', ')
    Write-KeyValue -Key 'AutoRollbackMinutes' -Value $RunState.Run.Effective.AutoRollbackMinutes
}

function Invoke-Capability21MainPhase07Step02 {
  param([hashtable]$RunState)
try {
    . Invoke-Capability21MainPhase07Step02Stage01 -RunState $RunState
. Invoke-Capability21MainPhase07Step02Stage02 -RunState $RunState
. Invoke-Capability21MainPhase07Step02Stage03 -RunState $RunState
. Invoke-Capability21MainPhase07Step02Stage04 -RunState $RunState
  }
  catch {
    $err = $_.Exception.Message
    Add-RunError "Unhandled error: $err" -RunState $RunState
    . Undo-PartialKillSwitchActivation -RunState $RunState
    Write-HealthEvent -Log $RunState.Run.Effective.EventLog -Source $RunState.Run.Effective.EventSource -Id $RunState.Run.Effective.EventId `
      -Msg ("KillSwitch failed: {0}" -f $err) -Level 'Error'

    Write-UiHeader -Title "Kill Switch"
    Write-UiLine -Text ("ERROR: {0}" -f $err) -Color Red
  }
  finally {
    # Always write console summary, even if an exception is thrown.
    try { Invoke-KillSwitchConsoleSummary -RunState $RunState } catch { Write-UiLine "Summary failed: $($_.Exception.Message)" -ForegroundColor Yellow }
    if ($null -ne $RunState.killSwitchLockStream) {
      $RunState.killSwitchLockStream.Dispose()
    }
  }
}

function Invoke-Capability21MainPhase07 {
  param([hashtable]$RunState)
  if (-not $RunState.Run.IsAdmin -and $RunState.Remediate) {
    Add-RunError 'Administrative privileges are required for remediation.' -RunState $RunState
    Write-UiHeader -Title "Kill Switch"
    Write-UiLine -Text "ERROR: Admin privileges required. Aborting." -Color Red

    if ($RunState.Remediate) {
      Write-HealthEvent -Log $RunState.Run.Effective.EventLog -Source $RunState.Run.Effective.EventSource -Id $RunState.Run.Effective.EventId `
        -Msg "KillSwitch aborted: admin privileges required." -Level 'Error'
    }

    Invoke-KillSwitchConsoleSummary -RunState $RunState
  }
  elseif (-not $RunState.Remediate) {
    Resolve-Outcome -RunState $RunState

    Write-UiHeader -Title "Kill Switch"
    Write-UiLine -Text "Audit mode: no kill switch actions applied." -Color Yellow
    Write-KeyValue -Key 'Reason' -Value $RunState.Run.Effective.Reason -ValueColor Cyan
    Write-KeyValue -Key 'BreakGlass' -Value ($RunState.Run.Effective.BreakGlassRemoteAddress -join ', ')
    Write-KeyValue -Key 'AutoRollbackMinutes' -Value $RunState.Run.Effective.AutoRollbackMinutes
  } else {
  . Invoke-Capability21MainPhase07Step01 -RunState $RunState
. Invoke-Capability21MainPhase07Step02 -RunState $RunState
  }
}
function Invoke-Capability21MainPhase08 {
  param([hashtable]$RunState)
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
  $successfulActions = @($completedActionNames | Where-Object { $RunState.Run.Actions[$_] -eq $true })
  $actionsDeclinedOrDryRun = ($WhatIfPreference -eq $true -or $RunState.Run.Actions.ConfirmDeclined)
  if ($RunState.Run.Errors.Count -eq 0 -and $successfulActions.Count -eq 0 -and $actionsDeclinedOrDryRun) {
    $null = Add-Finding -FindingList $RunState.Findings -Code 'KS-ActionsDeclinedOrDryRun' -Severity 'Medium' `
      -Message 'Kill switch ran but no protective actions were completed.'
  }
}
function Invoke-Capability21Main {
  param($EntryBoundParameters, $EntryCmdlet, $EntryInvocation, [hashtable]$RunState)
  $script:__EntryBoundParameters = $EntryBoundParameters
  $script:__EntryCmdlet = $EntryCmdlet
  $script:__EntryInvocation = $EntryInvocation
  . Invoke-Capability21MainPhase01 -RunState $RunState
  . Invoke-Capability21MainPhase02 -RunState $RunState
  . Invoke-Capability21MainPhase03 -RunState $RunState
  . Invoke-Capability21MainPhase04 -RunState $RunState
  . Invoke-Capability21MainPhase05 -RunState $RunState
  . Invoke-Capability21MainPhase06 -RunState $RunState
  . Invoke-Capability21MainPhase07 -RunState $RunState
  . Invoke-Capability21MainPhase08 -RunState $RunState
}
. Invoke-Capability21Main -EntryBoundParameters $PSBoundParameters -EntryCmdlet $PSCmdlet -EntryInvocation $MyInvocation -RunState $RunState
function Get-Capability21ResultToken {
  param([hashtable]$RunState)
  $resultToken = if ($RunState.Run.Errors.Count -gt 0) { 'FAIL' } elseif ($successfulActions.Count -gt 0 -or $RunState.Findings.Count -gt 0) { 'WARN' } else { 'OK' }
  if ($Strict -and $resultToken -eq 'WARN') { $resultToken = 'FAIL' }
  return $resultToken
}
$resultToken = Get-Capability21ResultToken -RunState $RunState
$v2Result = Get-V2ResultObject -ScriptName '21-EmergencyKillSwitch.ps1' -Mode $Mode -Result $resultToken -Findings @($RunState.Findings.ToArray()) -Summary ([pscustomobject]$RunState.Run) -Metadata @{}
Write-ResultObject -ResultObject $v2Result -OutputFormat $OutputFormat -OutputPath $OutputPath
if ($PassThru) { $v2Result }
exit (Get-V2ExitCode -Result $resultToken)
