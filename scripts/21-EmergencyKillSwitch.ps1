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
  4) Creates explicit, idempotent firewall rules for traceability (stable rule names, safe to run multiple times).
  5) Optionally creates a break-glass inbound allow rule for specified remote IPs/subnets.
  6) Optionally disables active network adapters (very aggressive; may cut off remote access immediately).

  Output behavior:
  - The script prints a human-friendly, colored status and a final summary to the console.
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
  If not provided, any existing break-glass rule created by this script is removed.

.PARAMETER AutoRollbackMinutes
  If greater than 0, schedules a one-time rollback that:
  - Restores firewall profile defaults to Allow (inbound/outbound),
  - Removes the kill-switch firewall rules created by this script,
  - Removes the rollback task after it runs.
  Use this to reduce the risk of permanent lockout when executing remotely.

.PARAMETER ConfigJsonPath
  Optional path to a JSON configuration file (example: "PATH/TO/JSON/kill-switch.json").
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
  - AutoRollback is a safety net; ensure it aligns with your incident response policy.

.EXAMPLE
  PS> .\21-EmergencyKillSwitch.ps1

  Runs with built-in defaults (no break-glass, no adapter disable, no auto-rollback).
  Confirmation prompts may appear depending on your preference settings.

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
  PS> $r = .\21-EmergencyKillSwitch.ps1 -ConfigJsonPath "PATH/TO/JSON/kill-switch.json" -Confirm:$false
  PS> $r | ConvertTo-Json -Depth 6
  PS> $r.Errors | Out-String

  Runs using optional JSON configuration, captures the structured result object, and exports it for logging/automation.

#>


[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
  [string]$Reason = "Incident/Compromise/Manual KillSwitch",
  [switch]$DisableAdapters,
  [string[]]$BreakGlassRemoteAddress = @(),
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
Import-Module (Join-Path $script:LibPath 'Common.psm1') -Force
Import-Module (Join-Path $script:LibPath 'Output.psm1') -Force
Import-Module (Join-Path $script:LibPath 'EventLog.psm1') -Force
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
    AdaptersDisabled    = $false
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

# ---------- Console helpers (never write to pipeline)





function Try-LoadConfigJson {
  param([string]$Path,[string]$Raw)

  try {
    if ($Raw -and $Raw.Trim()) {
      return ($Raw | ConvertFrom-Json)
    }

    if ($Path -and (Test-Path -LiteralPath $Path)) {
      $text = Get-Content -LiteralPath $Path -Raw -Encoding UTF8
      if ($text -and $text.Trim()) {
        return ($text | ConvertFrom-Json)
      }
    }

    return $null
  } catch {
    $Run.JsonError = $_.Exception.Message
    return $null
  }
}

function Get-ConfigValue {
  param(
    [object]$Config,
    [Parameter(Mandatory=$true)][string]$Name,
    [Parameter(Mandatory=$true)][object]$Default
  )

  if ($null -eq $Config) { return $Default }

  $p = $Config.PSObject.Properties[$Name]
  if ($null -eq $p) { return $Default }

  if ($p.Value -is [string] -and -not $p.Value.Trim()) { return $Default }

  return $p.Value
}


function Set-QuarantineFlag {
  param(
    [string]$RegKey,
    [string]$ReasonText,
    [bool]$IncludeUser
  )

  try {
    New-Item -Path $RegKey -Force | Out-Null
    Set-ItemProperty -Path $RegKey -Name 'Isolated' -Value 1 -Force
    Set-ItemProperty -Path $RegKey -Name 'Time'     -Value ((Get-Date).ToString('s')) -Force
    Set-ItemProperty -Path $RegKey -Name 'Reason'   -Value $ReasonText -Force
    if ($IncludeUser) {
      Set-ItemProperty -Path $RegKey -Name 'User' -Value $Run.User -Force
    }
    $Run.Actions.RegistryWritten = $true
  } catch {
    Add-RunError "Registry flag write failed: $($_.Exception.Message)"
  }
}

function New-OrReplaceRule {
  param(
    [string]$Name,
    [string]$DisplayName,
    [ValidateSet('Inbound','Outbound')]
    [string]$Direction,
    [ValidateSet('Block','Allow')]
    [string]$Action,
    [string[]]$RemoteAddress = @(),
    [string]$Description = ''
  )

  # Remove existing rule if present (ignore if not found)
  try {
    $existingRule = Get-NetFirewallRule -Name $Name -ErrorAction Stop
    if ($existingRule) {
      Remove-NetFirewallRule -Name $Name -ErrorAction Stop
    }
  } catch {
    # Rule doesn't exist, which is fine
  }

  $params = @{
    Name        = $Name
    DisplayName = $DisplayName
    Direction   = $Direction
    Action      = $Action
    Profile     = 'Any'
    Enabled     = 'True'
    Description = $Description
  }

  if ($RemoteAddress -and $RemoteAddress.Count -gt 0) {
    $params.RemoteAddress = $RemoteAddress
  }

  New-NetFirewallRule @params | Out-Null
}

function Schedule-AutoRollback {
  param(
    [int]$Minutes,
    [string]$TaskName,
    [string[]]$RuleNames
  )

  if ($Minutes -le 0) { return $false }

  # Validate inputs before embedding in heredoc (prevents PS code injection into
  # the base64-encoded rollback script that runs elevated via scheduled task).
  if ($TaskName -notmatch '^[a-zA-Z0-9\-_\\]+$') {
    Add-RunError "Schedule-AutoRollback: TaskName '$TaskName' contains invalid characters (allowed: a-z A-Z 0-9 - _ \)"
    return $false
  }
  foreach ($rn in $RuleNames) {
    if ($rn -match "'") {
      Add-RunError "Schedule-AutoRollback: RuleNames entry '$rn' contains a single quote, which is not allowed"
      return $false
    }
    if ($rn -match '[`$;{}]') {
      Add-RunError "Schedule-AutoRollback: RuleNames entry '$rn' contains invalid characters (backtick, dollar, semicolon, or braces)"
      return $false
    }
  }

  $runAt = (Get-Date).AddMinutes($Minutes)
  $logPath = Join-Path $env:TEMP "KillSwitch-Rollback-$($TaskName -replace '[^a-zA-Z0-9]', '').log"

  # Improved rollback script with proper error handling and logging (fixes #21)
  $rollbackPs = @"
`$ErrorActionPreference = 'Stop'
`$logPath = '$logPath'
function Write-RollbackLog { param([string]`$Message) try { Add-Content -Path `$logPath -Value "`$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') `$Message" } catch { <# best-effort: log file may not be writable #> } }
try {
  Write-RollbackLog 'Starting rollback...'
  `$fwStatePath = Join-Path `$env:TEMP 'KillSwitch-PreFirewallState.json'
  if (Test-Path -LiteralPath `$fwStatePath) {
    `$saved = Get-Content -LiteralPath `$fwStatePath -Raw -Encoding UTF8 | ConvertFrom-Json
    foreach (`$profileName in `$saved.PSObject.Properties.Name) {
      `$s = `$saved.`$profileName
      Set-NetFirewallProfile -Name `$profileName -Enabled `$s.Enabled -DefaultInboundAction `$s.DefaultInboundAction -DefaultOutboundAction `$s.DefaultOutboundAction
    }
    Write-RollbackLog 'Firewall profiles restored from saved pre-kill-switch state'
    Remove-Item -LiteralPath `$fwStatePath -Force -ErrorAction SilentlyContinue
  } else {
    Set-NetFirewallProfile -All -Enabled True -DefaultInboundAction Allow -DefaultOutboundAction Allow
    Write-RollbackLog 'No saved firewall state found; firewall profiles reset to Allow (fallback)'
  }
  try {
    Get-NetFirewallRule -Name '$($RuleNames -join "','")' | Remove-NetFirewallRule -ErrorAction Stop
    Write-RollbackLog 'Kill switch rules removed'
  } catch {
    Write-RollbackLog "Rule removal warning: `$(`$_.Exception.Message)"
  }
  `$delOutput = schtasks.exe /Delete /TN '$TaskName' /F 2>&1
  if (`$LASTEXITCODE -eq 0) { Write-RollbackLog 'Rollback task removed' }
  else { Write-RollbackLog "Task removal exit code: `$LASTEXITCODE - `$delOutput" }
  Write-RollbackLog 'Rollback completed successfully'
} catch {
  Write-RollbackLog "ERROR: `$(`$_.Exception.Message)"
  exit 1
}
"@

  $bytes = [System.Text.Encoding]::Unicode.GetBytes($rollbackPs)
  $enc   = [Convert]::ToBase64String($bytes)
  $tr    = "PowerShell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand $enc"

  # Use array-based invocation to avoid argument-splitting edge cases (S4)
  $schtasksArgs = @('/Create', '/TN', $TaskName, '/SC', 'ONCE',
                    '/ST', $runAt.ToString('HH:mm'), '/TR', $tr, '/RL', 'HIGHEST', '/F')
  $output = schtasks.exe @schtasksArgs 2>&1
  if ($LASTEXITCODE -ne 0) {
    Add-RunError "Auto-rollback schedule failed (exit code $LASTEXITCODE): $output"
    return $false
  }

  Write-UiLine "Auto-rollback scheduled for $runAt (log: $logPath)" -Style Info
  return $true
}

function Update-Outcome {
  # Consider isolation "active" only if at least the firewall default policy was set OR rules were created.
  $Run.Outcome.IsolationActive = [bool]($Run.Actions.FirewallProfileSet -or $Run.Actions.RulesCreated -or $Run.Actions.AdaptersDisabled)
}

function Write-ConsoleSummary {
  $Run.EndTime = Get-Date
  $Run.Duration = New-TimeSpan -Start $Run.StartTime -End $Run.EndTime

  Update-Outcome

  $hasProblems = ($Run.Errors.Count -gt 0) -or ($Run.Actions.ConfirmDeclined)

  $title = 'Kill Switch Summary (OK)'
  if ($hasProblems) { $title = 'Kill Switch Summary (Attention)' }

  $durationColor = [ConsoleColor]::Green
  if ($hasProblems) { $durationColor = [ConsoleColor]::Yellow }

  $jsonUsedColor = [ConsoleColor]::DarkGray
  if ($Run.JsonUsed) { $jsonUsedColor = [ConsoleColor]::Green }

  Write-UiHeader -Title $title

  Write-KeyValue   -Key 'ComputerName' -Value $Run.ComputerName -ValueColor White
  Write-KeyValue   -Key 'User'         -Value $Run.User
  Write-UiBool -Key 'Admin'        -Value $Run.IsAdmin
  Write-KeyValue   -Key 'StartTime'    -Value $Run.StartTime.ToString('s')
  Write-KeyValue   -Key 'EndTime'      -Value $Run.EndTime.ToString('s')
  Write-KeyValue   -Key 'Duration'     -Value $Run.Duration -ValueColor $durationColor

  Write-UiLine ""
  Write-KeyValue -Key 'JSON used' -Value $Run.JsonUsed -ValueColor $jsonUsedColor
  Write-KeyValue -Key 'JSON path' -Value $Run.JsonPath
  if ($Run.JsonError) { Write-KeyValue -Key 'JSON error' -Value $Run.JsonError -ValueColor Yellow }

  Write-UiLine ""
  Write-KeyValue   -Key 'Reason' -Value $Run.Effective.Reason -ValueColor Cyan
  Write-UiBool -Key 'IsolationActive' -Value $Run.Outcome.IsolationActive
  Write-UiBool -Key 'DisableAdapters' -Value ([bool]$Run.Effective.DisableAdapters)
  Write-KeyValue   -Key 'BreakGlass' -Value ($Run.Effective.BreakGlassRemoteAddress -join ', ')
  Write-KeyValue   -Key 'AutoRollbackMinutes' -Value $Run.Effective.AutoRollbackMinutes

  Write-UiLine ""
  Write-UiBool -Key 'RegistryWritten'    -Value $Run.Actions.RegistryWritten
  Write-UiBool -Key 'EventLogWritten'    -Value $Run.Actions.EventLogWritten
  Write-UiBool -Key 'FirewallProfileSet' -Value $Run.Actions.FirewallProfileSet
  Write-UiBool -Key 'RulesCreated'       -Value $Run.Actions.RulesCreated
  Write-UiBool -Key 'BreakGlassApplied'  -Value $Run.Actions.BreakGlassApplied
  Write-UiBool -Key 'AdaptersDisabled'   -Value $Run.Actions.AdaptersDisabled
  Write-UiBool -Key 'RollbackScheduled'  -Value $Run.Actions.RollbackScheduled

  if ($Run.Actions.ConfirmDeclined) {
    Write-UiLine ""
    Write-UiLine -Text "NOTE: One or more operations were declined in a Confirm prompt (No / No to All)." -Color Yellow
  }

  if ($Run.Errors.Count -gt 0) {
    Write-UiLine ""
    Write-UiLine -Text "Warnings/Errors:" -Color Yellow
    foreach ($e in $Run.Errors) { Write-UiLine -Text ("- {0}" -f $e) -Color Yellow }
  }

  Write-UiLine ("-" * 78) -ForegroundColor DarkGray
}


# -------------------- Load JSON (optional) and merge with defaults/parameters
$config = Try-LoadConfigJson -Path $ConfigJsonPath -Raw $ConfigJsonRaw
if ($null -ne $config) { $Run.JsonUsed = $true }

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
if (-not $regKeyValid) {
  throw "RegKey '$($Run.Effective.RegKey)' is not under an allowed registry prefix ($($regKeyAllowedPrefixes -join ', ')). Aborting."
}

$Run.Effective.RulePrefix  = Get-ConfigValue -Config $config -Name 'RulePrefix' -Default $Defaults.RulePrefix

# S8 fix: validate RulePrefix contains only safe characters (alphanumeric, hyphens, underscores) and reasonable length
if ($Run.Effective.RulePrefix -notmatch '^[a-zA-Z0-9_-]+$') {
  throw "RulePrefix '$($Run.Effective.RulePrefix)' contains invalid characters. Only alphanumeric, hyphens, and underscores are allowed."
}
if ($Run.Effective.RulePrefix.Length -gt 64) {
  throw "RulePrefix '$($Run.Effective.RulePrefix)' exceeds 64 characters."
}
$Run.Effective.TaskName    = Get-ConfigValue -Config $config -Name 'TaskName'   -Default $Defaults.TaskName
$Run.Effective.IncludeUserInRegistry = [bool](Get-ConfigValue -Config $config -Name 'IncludeUserInRegistry' -Default $Defaults.IncludeUserInRegistry)

# Apply JSON defaults only if caller did not provide explicit values
if (-not $DisableAdapters.IsPresent) {
  $fromJson = [bool](Get-ConfigValue -Config $config -Name 'DisableAdapters' -Default $Defaults.DisableAdapters)
  if ($fromJson) { $DisableAdapters = $true }
}
if ($BreakGlassRemoteAddress.Count -eq 0) {
  $bg = Get-ConfigValue -Config $config -Name 'BreakGlassRemoteAddress' -Default $Defaults.BreakGlassRemoteAddress
  if ($bg) { $BreakGlassRemoteAddress = @($bg) }
}
if ($AutoRollbackMinutes -eq 0) {
  $arm = [int](Get-ConfigValue -Config $config -Name 'AutoRollbackMinutes' -Default $Defaults.AutoRollbackMinutes)
  if ($arm -gt 0) { $AutoRollbackMinutes = $arm }
}

$Run.Effective.Reason                 = $Reason
$Run.Effective.DisableAdapters         = $DisableAdapters.IsPresent
$Run.Effective.BreakGlassRemoteAddress = @($BreakGlassRemoteAddress)
$Run.Effective.AutoRollbackMinutes     = $AutoRollbackMinutes

# Derived identifiers
$RuleInName  = "{0}-IN-BLOCK"            -f $Run.Effective.RulePrefix
$RuleOutName = "{0}-OUT-BLOCK"           -f $Run.Effective.RulePrefix
$RuleBgName  = "{0}-BREAKGLASS-IN-ALLOW" -f $Run.Effective.RulePrefix
$RuleNames   = @($RuleInName, $RuleOutName, $RuleBgName)

# -------------------- Execution
$Run.IsAdmin = Test-IsAdmin

Ensure-EventSource -Source $Run.Effective.EventSource -Log $Run.Effective.EventLog

if (-not $Run.IsAdmin) {
  Write-UiHeader -Title "Kill Switch"
  Write-UiLine -Text "ERROR: Admin privileges required. Aborting." -Color Red

  Write-HealthEvent -Log $Run.Effective.EventLog -Source $Run.Effective.EventSource -Id $Run.Effective.EventId `
    -Msg "KillSwitch aborted: admin privileges required." -Level 'Error'

  Write-ConsoleSummary
  [pscustomobject]$Run
  return
}

try {
  Set-QuarantineFlag -RegKey $Run.Effective.RegKey -ReasonText $Run.Effective.Reason -IncludeUser $Run.Effective.IncludeUserInRegistry

  if ($Run.Effective.AutoRollbackMinutes -gt 0) {
    $Run.Actions.RollbackScheduled = Schedule-AutoRollback -Minutes $Run.Effective.AutoRollbackMinutes -TaskName $Run.Effective.TaskName -RuleNames $RuleNames
  }

  # Capture current firewall profile settings before applying kill switch so rollback can restore them
  $preKillSwitchFirewallState = @{}
  try {
    foreach ($fwProfile in Get-NetFirewallProfile) {
      $preKillSwitchFirewallState[$fwProfile.Name] = @{
        Enabled              = [string]$fwProfile.Enabled
        DefaultInboundAction = [string]$fwProfile.DefaultInboundAction
        DefaultOutboundAction = [string]$fwProfile.DefaultOutboundAction
      }
    }
    $fwStateJson = $preKillSwitchFirewallState | ConvertTo-Json -Depth 4 -Compress
    $fwStatePath = Join-Path $env:TEMP 'KillSwitch-PreFirewallState.json'
    Set-Content -LiteralPath $fwStatePath -Value $fwStateJson -Encoding UTF8 -Force
  } catch {
    Add-RunError "Failed to capture pre-kill-switch firewall state: $($_.Exception.Message)"
  }

  if ($PSCmdlet.ShouldProcess("Windows Firewall Profiles", "Enable firewall + set DefaultInboundAction=Block, DefaultOutboundAction=Block")) {
    Set-NetFirewallProfile -All -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Block
    $Run.Actions.FirewallProfileSet = $true
  } else {
    $Run.Actions.ConfirmDeclined = $true
  }

  if ($PSCmdlet.ShouldProcess("Windows Defender Firewall Rules", "Create kill switch rules")) {
    New-OrReplaceRule -Name $RuleInName  -DisplayName "$($Run.Effective.RulePrefix) Inbound Block"  -Direction Inbound  -Action Block -Description "Kill switch: block inbound"
    New-OrReplaceRule -Name $RuleOutName -DisplayName "$($Run.Effective.RulePrefix) Outbound Block" -Direction Outbound -Action Block -Description "Kill switch: block outbound"
    $Run.Actions.RulesCreated = $true
  } else {
    $Run.Actions.ConfirmDeclined = $true
  }

  if ($Run.Effective.BreakGlassRemoteAddress -and $Run.Effective.BreakGlassRemoteAddress.Count -gt 0) {
    if ($PSCmdlet.ShouldProcess("Windows Defender Firewall Rules", "Create break-glass inbound allow rule")) {
      New-OrReplaceRule -Name $RuleBgName -DisplayName "$($Run.Effective.RulePrefix) BreakGlass Inbound Allow" `
        -Direction Inbound -Action Allow -RemoteAddress $Run.Effective.BreakGlassRemoteAddress -Description "Kill switch: break-glass inbound allow"
      $Run.Actions.BreakGlassApplied = $true
    } else {
      $Run.Actions.ConfirmDeclined = $true
    }
  } else {
    try {
      $rule = Get-NetFirewallRule -Name $RuleBgName -ErrorAction Stop
      if ($rule) { $rule | Remove-NetFirewallRule -ErrorAction Stop }
    } catch {
      Write-Warning "Could not remove break-glass firewall rule: $($_.Exception.Message)"
    }
  }

  if ($DisableAdapters) {
    if ($PSCmdlet.ShouldProcess("Network Adapters", "Disable all Up adapters")) {
      $netAdapters = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' }
      foreach ($a in $netAdapters) {
        Disable-NetAdapter -Name $a.Name -Confirm:$false
      }
      $Run.Actions.AdaptersDisabled = $true
    } else {
      $Run.Actions.ConfirmDeclined = $true
    }
  }

  Update-Outcome

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

  Write-HealthEvent -Log $Run.Effective.EventLog -Source $Run.Effective.EventSource -Id $Run.Effective.EventId `
    -Msg ("KillSwitch failed: {0}" -f $err) -Level 'Error'

  Write-UiHeader -Title "Kill Switch"
  Write-UiLine -Text ("ERROR: {0}" -f $err) -Color Red
}
finally {
  # Always write console summary, even if an exception is thrown.
  try { Write-ConsoleSummary } catch { Write-UiLine "Summary failed: $($_.Exception.Message)" -ForegroundColor Yellow }
}

# V2 output contract
$resultToken = if ($Run.Errors.Count -gt 0) { 'FAIL' } elseif (($Run.Actions.Values | Where-Object { $_ -eq $true }).Count -gt 0) { 'WARN' } else { 'OK' }
$v2Result = New-V2ResultObject -ScriptName '21-EmergencyKillSwitch.ps1' -Mode $Mode -Result $resultToken -Findings @() -Summary ([pscustomobject]$Run) -Metadata @{}
Write-ResultObject -ResultObject $v2Result -OutputFormat $OutputFormat -OutputPath $OutputPath
if ($PassThru) { $v2Result }
if ($Run.Errors.Count -gt 0) { exit 1 }
exit 0
