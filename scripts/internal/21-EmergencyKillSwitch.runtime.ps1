<#
.SYNOPSIS
Runtime firewall helpers for the emergency kill switch.

.DESCRIPTION
Creates and verifies managed rules and validates canonical rollback records.
#>

function Remove-ExactJustCreatedFirewallRule {
  param(
    [Parameter(Mandatory=$true)][ValidatePattern('^[A-Za-z0-9_-]+$')][ValidateLength(1,256)][string]$Name,
    [Parameter(Mandatory=$true)][ValidateSet('Inbound','Outbound')][string]$Direction,
    [Parameter(Mandatory=$true)][ValidateSet('Block','Allow')][string]$Action
  , [hashtable]$RunState)
  try {
    Remove-NetFirewallRule -Name $Name -ErrorAction Stop
    return $true
  } catch {
    $message = "Exact cleanup of just-created firewall rule '$Name' failed after verification failure: $($_.Exception.Message)"
    Add-RunError $message -RunState $RunState
    $null = Add-Finding -FindingList $RunState.Findings -Code 'Firewall-RuleCleanupFailed' -Severity 'High' -Message $message -Extra @{ RuleName = $Name; Direction = $Direction; Action = $Action }
    return $false
  }
}

function New-OrReplaceRule {
  [CmdletBinding(SupportsShouldProcess = $true)]
  param(
    [ValidatePattern('^[A-Za-z0-9_-]+$')]
    [ValidateLength(1, 256)]
    [string]$Name,
    [string]$DisplayName,
    [ValidateSet('Inbound', 'Outbound')]
    [string]$Direction,
    [ValidateSet('Block', 'Allow')]
    [string]$Action,
    [string[]]$RemoteAddress = @(),
    [ValidateSet('TCP', 'UDP', 'Any')]
    [string]$Protocol = 'Any',
    [string]$LocalPort,
    [string]$Description = ''
  )
  $data = [pscustomobject]@{
    Name = $Name
    DisplayName = $DisplayName
    Direction = $Direction
    Action = $Action
    RemoteAddress = $RemoteAddress
    Protocol = $Protocol
    LocalPort = $LocalPort
    Description = $Description
  }
  $compatibilityState = @{
    Findings = $Findings
    Run = $Run
  }
  return Invoke-NewOrReplaceRule -Data $data -RunState $compatibilityState -DecisionContext $PSCmdlet
}

function Invoke-NewOrReplaceRule {
  param($Data, [hashtable]$RunState, $DecisionContext)
  try { $existingRules = @(Get-NetFirewallRule -Name $Data.Name -ErrorAction SilentlyContinue | Where-Object { $null -ne $_ }) } catch { $existingRules = @() }
  if ($existingRules.Count -gt 0) { $message = "Firewall rule '$($Data.Name)' already exists; refusing to replace owner-unknown rule."; Add-RunError -Message $message -RunState $RunState; $null = Add-Finding -FindingList $RunState.Findings -Code 'Firewall-RuleCollision' -Severity 'High' -Message $message -Extra @{ RuleName = $Data.Name }; return $false }
  # Keep the caller-scoped value available to native-command test doubles, as
  # it was when this logic lived in New-OrReplaceRule.
  $displayName = [string]$Data.DisplayName
  $params = Get-NewKillSwitchFirewallRuleParameters -Data $Data
  $params.DisplayName = $displayName
  try {
    if (-not $DecisionContext.ShouldProcess($Data.Name, 'Create firewall rule')) {
      Add-RunError -Message "Firewall rule '$($Data.Name)' creation skipped by ShouldProcess." -RunState $RunState
      return $false
    }
    New-NetFirewallRule @params | Out-Null
  }
  catch { $message = "Firewall rule '$($Data.Name)' creation failed: $($_.Exception.Message)"; Add-RunError -Message $message -RunState $RunState; $null = Add-Finding -FindingList $RunState.Findings -Code 'Firewall-RuleCreateFailed' -Severity 'High' -Message $message -Extra @{ RuleName = $Data.Name; Direction = $Data.Direction; Action = $Data.Action }; return $false }
  $verificationError = $null
  try { $createdRules = @(Get-NetFirewallRule -Name $Data.Name -ErrorAction Stop | Where-Object { $null -ne $_ }) } catch { $createdRules = @(); $verificationError = $_.Exception.Message }
  $verifiedRules = @($createdRules | Where-Object {
      Test-CreatedKillSwitchFirewallRule -Rule $_ -Name $Data.Name -Direction $Data.Direction -Action $Data.Action
    })
  if (Test-KillSwitchRuleVerificationFailed -ErrorText $verificationError -CreatedRules $createdRules -VerifiedRules $verifiedRules) {
    $message = Get-KillSwitchRuleVerificationMessage -Name $Data.Name -ErrorText $verificationError
    Add-RunError -Message $message -RunState $RunState
    $null = Add-Finding -FindingList $RunState.Findings -Code 'Firewall-RuleCreateFailed' -Severity 'High' -Message $message -Extra @{ RuleName = $Data.Name; Direction = $Data.Direction; Action = $Data.Action; VerificationError = $verificationError }
    [void](Remove-ExactJustCreatedFirewallRule -Name $Data.Name -Direction $Data.Direction -Action $Data.Action -RunState $RunState)
    return $false
  }
  return $true
}

function Get-KillSwitchRuleVerificationMessage {
  param([string]$Name, [AllowNull()][string]$ErrorText)
  if ($ErrorText) { return "Firewall rule '$Name' post-create verification query failed: $ErrorText" }
  return "Firewall rule '$Name' was not found, was not enabled, or did not match requested settings after creation."
}

function Test-KillSwitchRuleVerificationFailed {
  param([AllowNull()][string]$ErrorText, [object[]]$CreatedRules, [object[]]$VerifiedRules)
  if ($ErrorText) { return $true }
  if ($CreatedRules.Count -ne 1) { return $true }
  return ($VerifiedRules.Count -ne 1)
}

function Test-CreatedKillSwitchFirewallRule {
  param($Rule, [string]$Name, [string]$Direction, [string]$Action)
  if ([string]$Rule.Name -ne $Name) { return $false }
  if ([string]$Rule.Enabled -ne 'True') { return $false }
  if ([string]$Rule.Direction -ne $Direction) { return $false }
  return ([string]$Rule.Action -eq $Action)
}

function Get-NewKillSwitchFirewallRuleParameters {
  param($Data)
  $params = @{
    Name = $Data.Name
    DisplayName = $Data.DisplayName
    Direction = $Data.Direction
    Action = $Data.Action
    Profile = 'Any'
    Enabled = 'True'
    Description = $Data.Description
  }
  if ($Data.RemoteAddress -and $Data.RemoteAddress.Count -gt 0) { $params.RemoteAddress = $Data.RemoteAddress }
  if ($Data.Protocol -ne 'Any') { $params.Protocol = $Data.Protocol }
  if (-not [string]::IsNullOrWhiteSpace($Data.LocalPort)) { $params.LocalPort = $Data.LocalPort }
  return $params
}

function New-KillSwitchFirewallRuleData {
  param(
    [string]$Name,
    [string]$DisplayName,
    [ValidateSet('Inbound', 'Outbound')][string]$Direction,
    [ValidateSet('Block', 'Allow')][string]$Action,
    [string[]]$RemoteAddress = @(),
    [ValidateSet('TCP', 'UDP', 'Any')][string]$Protocol = 'Any',
    [AllowNull()][string]$LocalPort,
    [string]$Description = ''
  )
  return [pscustomobject]@{
    Name = $Name
    DisplayName = $DisplayName
    Direction = $Direction
    Action = $Action
    RemoteAddress = $RemoteAddress
    Protocol = $Protocol
    LocalPort = $LocalPort
    Description = $Description
  }
}

function Assert-ManagedFirewallRulesSection01 {
  param([hashtable]$RunState)
if ($RunState.Rules.Count -lt 1 -or $RunState.Rules.Count -gt 3) { throw 'Managed rule identities must contain between one and three rules.' }
  $RunState.seen = @{}
}

function Assert-ManagedFirewallRulesSection02Stage01 {
  param([hashtable]$RunState)
if ((Test-AnyCondition -Conditions @({ $null -eq $rule }, { @($rule.PSObject.Properties.Name).Count -ne 3 })) -or @($rule.PSObject.Properties.Name | Where-Object { @('Name','Direction','Action') -notcontains $_ }).Count -ne 0) { throw 'Managed rule identity contains missing or unexpected fields.' }
    if ((Test-AnyCondition -Conditions @({ $rule.Name -isnot [string] }, { $rule.Name -notmatch '^[A-Za-z0-9_-]+$' })) -or $rule.Name.Length -gt 256 -or $RunState.seen.ContainsKey($rule.Name)) { throw 'Managed rule identity has an invalid or duplicate name.' }
}

function Assert-ManagedFirewallRulesSection02Stage02 {
  param([hashtable]$RunState)
if ((Test-AnyCondition -Conditions @({ @('Inbound','Outbound') -notcontains [string]$rule.Direction }, { @('Allow','Block') -notcontains [string]$rule.Action }))) { throw 'Managed rule identity has an invalid direction or action.' }
    $RunState.seen[$rule.Name] = $true
}

function Assert-ManagedFirewallRulesSection02 {
  param([hashtable]$RunState)
foreach ($rule in $RunState.Rules) {
    . Assert-ManagedFirewallRulesSection02Stage01 -RunState $RunState
. Assert-ManagedFirewallRulesSection02Stage02 -RunState $RunState
  }
}

function Assert-ManagedFirewallRules {
  param([Parameter(Mandatory=$true)][object[]]$Rules, [hashtable]$RunState)
  $RunState.Rules = $Rules
    . Assert-ManagedFirewallRulesSection01 -RunState $RunState
    . Assert-ManagedFirewallRulesSection02 -RunState $RunState
}

function Test-NoManagedFirewallRuleConflicts {
  param(
    [Parameter(Mandatory=$true)][string]$RulePrefix,
    [Parameter(Mandatory=$true)][string]$TaskPrefix
  , [hashtable]$RunState)
  try {
    $escapedRulePrefix = [regex]::Escape($RulePrefix)
    $pattern = '^' + $escapedRulePrefix + '-(?:[a-fA-F0-9]{32}-)?(?:IN-BLOCK|OUT-BLOCK|BREAKGLASS-IN-ALLOW)$'
    $conflicts = @(Get-NetFirewallRule -ErrorAction Stop | Where-Object { $_ -and [string]$_.Name -match $pattern })
    $taskPattern = '^' + [regex]::Escape($TaskPrefix) + '(?:-[a-fA-F0-9]{32})?$'
    $taskConflicts = @(Get-ScheduledTask -ErrorAction Stop | Where-Object { $_ -and [string]$_.TaskName -match $taskPattern })
    if ($conflicts.Count -eq 0 -and $taskConflicts.Count -eq 0) { return $true }
    $identities = @($conflicts.Name) + @($taskConflicts.TaskName)
    $message = "Preexisting kill-switch rule or rollback-task identity detected ($($identities -join ', ')); refusing an overlapping activation so the existing rollback remains authoritative."
    Add-RunError $message -RunState $RunState
    $null = Add-Finding -FindingList $RunState.Findings -Code 'Firewall-ManagedRuleConflict' -Severity 'High' -Message $message
    return $false
  } catch {
    $message = "Unable to inspect existing kill-switch rule and rollback-task identities before mutation: $($_.Exception.Message)"
    Add-RunError $message -RunState $RunState
    $null = Add-Finding -FindingList $RunState.Findings -Code 'Firewall-ManagedRuleConflict' -Severity 'High' -Message $message
    return $false
  }
}

function Remove-ExactManagedFirewallRules {
  param([Parameter(Mandatory=$true)][object[]]$Rules, [hashtable]$RunState)
  Assert-ManagedFirewallRules -Rules $Rules -RunState $RunState
  foreach ($managedRule in $Rules) {
    $existingRules = @(Get-NetFirewallRule -Name $managedRule.Name -ErrorAction SilentlyContinue | Where-Object { $null -ne $_ })
    $ownedRules = @($existingRules | Where-Object {
        [string]$_.Name -eq [string]$managedRule.Name -and
        [string]$_.Direction -eq [string]$managedRule.Direction -and
        [string]$_.Action -eq [string]$managedRule.Action
      })
    if ($ownedRules.Count -ne $existingRules.Count) {
      throw "Firewall rule identity mismatch for '$($managedRule.Name)'; refusing removal."
    }
    if ($ownedRules.Count -gt 0) { $ownedRules | Remove-NetFirewallRule -ErrorAction Stop }
  }
}

function Resolve-CanonicalWindowsPowerShellPath {
  $systemDirectory = [Environment]::GetFolderPath([Environment+SpecialFolder]::System)
  if ([string]::IsNullOrWhiteSpace($systemDirectory)) {
    # Non-Windows test hosts do not expose SpecialFolder.System. This literal is
    # only a candidate and must still pass the same Get-Item validation below.
    $systemDirectory = 'C:\Windows\System32'
  }
  $candidate = Join-Path -Path $systemDirectory -ChildPath 'WindowsPowerShell\v1.0\powershell.exe'
  $item = Get-Item -LiteralPath $candidate -Force -ErrorAction Stop
  if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
    throw 'Canonical Windows PowerShell executable must be a regular, non-reparse file.'
  }
  return [string]$item.FullName
}

function ConvertTo-StrictFirewallBoolean { param([Parameter(Mandatory=$true)]$Value,[Parameter(Mandatory=$true)][string]$FieldName); if ($Value -is [bool]) { return [bool]$Value }; if ([string]$Value -eq 'True') { return $true }; if ([string]$Value -eq 'False') { return $false }; throw "Firewall profile field '$FieldName' must be a boolean." }

function Schedule-AutoRollback {
  param(
    [int]$Minutes,
    [string]$TaskName,
    [object[]]$ManagedRules,
    [Parameter(Mandatory=$true)][string]$SnapshotJson
  , [hashtable]$RunState)

  if ($Minutes -le 0) { return $false }

  # Validate inputs before embedding in heredoc (prevents PS code injection into
  # the base64-encoded rollback script that runs elevated via scheduled task).
  if ($TaskName -notmatch '^[a-zA-Z0-9\-_]+$') {
    Add-RunError "Schedule-AutoRollback: TaskName '$TaskName' contains invalid characters (allowed: a-z A-Z 0-9 - _)" -RunState $RunState
    return $false
  }
  try { Assert-ManagedFirewallRules -Rules $ManagedRules -RunState $RunState } catch { Add-RunError "Schedule-AutoRollback: invalid managed rule identities: $($_.Exception.Message)" -RunState $RunState; return $false }

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
    Add-RunError "Auto-rollback scheduled-task command exceeds the 30000-character safety limit ($($actionArguments.Length))." -RunState $RunState
    return $false
  }

  try {
    $powerShellPath = Resolve-CanonicalWindowsPowerShellPath
    $action = New-ScheduledTaskAction -Execute $powerShellPath -Argument $actionArguments
    $trigger = New-ScheduledTaskTrigger -Once -At $runAt
    $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit (New-TimeSpan -Minutes 15)
    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Settings $settings -User 'SYSTEM' -RunLevel Highest -Force -ErrorAction Stop | Out-Null
    $RunState.Run.Effective.RollbackRunAt = $runAt
  } catch {
    Add-RunError "Auto-rollback schedule failed: $($_.Exception.Message)" -RunState $RunState
    return $false
  }

  Write-UiLine "Auto-rollback scheduled for $runAt (log file in scheduled-task temp: $logFileName)" -Style Info
  return $true
}
