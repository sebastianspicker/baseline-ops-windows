<#
.SYNOPSIS
Internal validation, locking, firewall, and rollback helpers for the kill switch.

.DESCRIPTION
Validates the fail-closed configuration, serializes remediation, and captures a
canonical rollback snapshot before changing managed firewall state. The entry
script creates its run context and imports shared modules before dot-sourcing.
#>
function Test-JsonInteger {
  param($Value)
  return (
    $Value -is [byte] -or $Value -is [sbyte] -or
    $Value -is [int16] -or $Value -is [uint16] -or
    $Value -is [int32] -or $Value -is [uint32] -or
    $Value -is [int64] -or $Value -is [uint64]
  )
}
# Applies a closed schema and bounded values before configuration can influence
# isolation, break-glass access, or rollback scheduling.
function Assert-KillSwitchConfig {
  param([Parameter(Mandatory=$true)]$Config)
  if ($null -eq $Config -or $Config -is [string] -or $Config -is [System.ValueType] -or $Config -is [System.Collections.IEnumerable]) { throw 'Kill-switch configuration root must be an object.' }
  $allowedFields = @('EventSource','EventLog','EventId','RegKey','RulePrefix','TaskName','IncludeUserInRegistry','DisableAdapters','BreakGlassRemoteAddress','BreakGlassLocalPort','AutoRollbackMinutes')
  $seen = @{}
  foreach ($property in $Config.PSObject.Properties) {
    $normalizedName = $property.Name.ToLowerInvariant()
    if ($seen.ContainsKey($normalizedName)) { throw "Kill-switch configuration contains duplicate field '$($property.Name)'." }
    $seen[$normalizedName] = $true
    if ($allowedFields -notcontains $property.Name) { throw "Kill-switch configuration contains unknown field '$($property.Name)'." }
  }
  foreach ($field in @('EventSource','EventLog','RegKey','RulePrefix','TaskName')) {
    $property = $Config.PSObject.Properties[$field]
    if ($null -ne $property -and ($property.Value -isnot [string] -or [string]::IsNullOrWhiteSpace($property.Value) -or $property.Value.Length -gt 256 -or $property.Value -match '[\x00-\x1f]')) { throw "Kill-switch configuration field '$field' must be a non-empty string of at most 256 characters without control characters." }
  }
  foreach ($field in @('IncludeUserInRegistry','DisableAdapters')) { $property = $Config.PSObject.Properties[$field]; if ($null -ne $property -and $property.Value -isnot [bool]) { throw "Kill-switch configuration field '$field' must be a boolean." } }
  $eventIdProperty = $Config.PSObject.Properties['EventId']; if ($null -ne $eventIdProperty -and ((-not (Test-JsonInteger $eventIdProperty.Value)) -or [int64]$eventIdProperty.Value -lt 1 -or [int64]$eventIdProperty.Value -gt 65535)) { throw "Kill-switch configuration field 'EventId' must be an integer from 1 through 65535." }
  $rollbackProperty = $Config.PSObject.Properties['AutoRollbackMinutes']; if ($null -ne $rollbackProperty -and ((-not (Test-JsonInteger $rollbackProperty.Value)) -or [int64]$rollbackProperty.Value -lt 0 -or [int64]$rollbackProperty.Value -gt 1440)) { throw "Kill-switch configuration field 'AutoRollbackMinutes' must be an integer from 0 through 1440." }
  $breakGlassPortProperty = $Config.PSObject.Properties['BreakGlassLocalPort']; if ($null -ne $breakGlassPortProperty -and ((-not (Test-JsonInteger $breakGlassPortProperty.Value)) -or [int64]$breakGlassPortProperty.Value -lt 1 -or [int64]$breakGlassPortProperty.Value -gt 65535)) { throw "Kill-switch configuration field 'BreakGlassLocalPort' must be an integer from 1 through 65535." }
  $addressesProperty = $Config.PSObject.Properties['BreakGlassRemoteAddress']
  if ($null -ne $addressesProperty) {
    if ($addressesProperty.Value -is [string] -or $addressesProperty.Value -isnot [System.Collections.IEnumerable]) { throw "Kill-switch configuration field 'BreakGlassRemoteAddress' must be an array of IP addresses or CIDR ranges." }
    $addresses = @($addressesProperty.Value); if ($addresses.Count -gt 64) { throw "Kill-switch configuration field 'BreakGlassRemoteAddress' supports at most 64 entries." }
    foreach ($address in $addresses) {
      if ($address -isnot [string] -or [string]::IsNullOrWhiteSpace($address) -or $address.Length -gt 128) { throw 'Each BreakGlassRemoteAddress entry must be a non-empty string of at most 128 characters.' }
      $parts = $address.Split('/'); $parsedAddress = $null
      if ($parts.Count -gt 2 -or -not [System.Net.IPAddress]::TryParse($parts[0],[ref]$parsedAddress)) { throw "BreakGlassRemoteAddress entry '$address' is not an IP address or CIDR range." }
      if ($parts.Count -eq 2) { $prefixLength = 0; $maximumPrefix = if ($parsedAddress.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) { 32 } else { 128 }; if (-not [int]::TryParse($parts[1],[ref]$prefixLength) -or $prefixLength -lt 0 -or $prefixLength -gt $maximumPrefix) { throw "BreakGlassRemoteAddress entry '$address' has an invalid prefix length." } }
    }
  }
}
function Try-LoadConfigJson {
  param([string]$Path,[string]$Raw,[bool]$PathSupplied,[bool]$RawSupplied)
  try {
    if ($PathSupplied -and $RawSupplied) { throw 'Specify only one of ConfigJsonPath or ConfigJsonRaw.' }; if (-not $PathSupplied -and -not $RawSupplied) { return $null }
    if ($RawSupplied) { if ([string]::IsNullOrWhiteSpace($Raw)) { throw 'ConfigJsonRaw was supplied but is empty.' }; if ([Text.Encoding]::UTF8.GetByteCount($Raw) -gt 65536) { throw 'ConfigJsonRaw exceeds the 64 KiB limit.' }; $text = $Raw }
    else { $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop; if ($item.PSIsContainer -or $item.Length -gt 65536 -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'ConfigJsonPath must identify a non-reparse file no larger than 64 KiB.' }; $text = Get-BoundedUtf8FileContent -Path $item.FullName -MaximumBytes 65536; if ([string]::IsNullOrWhiteSpace($text)) { throw 'ConfigJsonPath identifies an empty file.' } }
    $configObject = $text | ConvertFrom-Json -ErrorAction Stop; Assert-KillSwitchConfig -Config $configObject; return $configObject
  } catch { $Run.JsonError = $_.Exception.Message; return $null }
}
function Get-ConfigValue {
  param([object]$Config,[Parameter(Mandatory=$true)][string]$Name,[Parameter(Mandatory=$true)][object]$Default)
  if ($null -eq $Config) { return $Default }; $p = $Config.PSObject.Properties[$Name]; if ($null -eq $p) { return $Default }; if ($p.Value -is [string] -and -not $p.Value.Trim()) { return $Default }; return $p.Value
}
function Get-KillSwitchLockAcl {
  param([switch]$Directory)

  $administrators = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')
  $system = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-18')
  if ($Directory) {
    $acl = New-Object System.Security.AccessControl.DirectorySecurity
    $inheritance = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
      [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
  } else {
    $acl = New-Object System.Security.AccessControl.FileSecurity
    $inheritance = [System.Security.AccessControl.InheritanceFlags]::None
  }
  $acl.SetOwner($administrators)
  $acl.SetAccessRuleProtection($true, $false)
  foreach ($sid in @($administrators, $system)) {
    [void]$acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule(
          $sid,
          [System.Security.AccessControl.FileSystemRights]::FullControl,
          $inheritance,
          [System.Security.AccessControl.PropagationFlags]::None,
          [System.Security.AccessControl.AccessControlType]::Allow)))
  }
  return $acl
}
function Assert-KillSwitchLockAcl {
  param(
    [Parameter(Mandatory)][string]$Path,
    [switch]$Directory
  )

  Assert-TrustedWindowsPathAcl -Path $Path -CheckAncestors | Out-Null
  $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
  if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw "Kill-switch lock path is a reparse point: $Path"
  }
  if ($Directory -ne [bool]$item.PSIsContainer) {
    throw "Kill-switch lock path has an unexpected type: $Path"
  }

  $acl = Get-Acl -LiteralPath $item.FullName -ErrorAction Stop
  $administratorsSid = 'S-1-5-32-544'
  $systemSid = 'S-1-5-18'
  if ($acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value -ne $administratorsSid -or
      -not $acl.AreAccessRulesProtected) {
    throw "Kill-switch lock ACL is not protected and Administrators-owned: $Path"
  }
  $expectedSids = @($administratorsSid, $systemSid)
  $rules = @($acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]) | Where-Object {
      $_.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Allow -and
      ($_.PropagationFlags -band [System.Security.AccessControl.PropagationFlags]::InheritOnly) -eq 0
    })
  if ($rules.Count -ne 2 -or @($rules | Where-Object {
        $_.IdentityReference.Value -notin $expectedSids -or
        -not $_.FileSystemRights.HasFlag([System.Security.AccessControl.FileSystemRights]::FullControl)
      }).Count -ne 0) {
    throw "Kill-switch lock ACL must grant FullControl only to SYSTEM and Administrators: $Path"
  }
}
function Assert-KillSwitchLockParent {
  param([Parameter(Mandatory)][string]$Path)

  Assert-TrustedWindowsPathAcl -Path $Path -CheckAncestors | Out-Null
  $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
  $trustedSids = @{'S-1-5-32-544' = $true; 'S-1-5-18' = $true; 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464' = $true }
  $writeMask = [System.Security.AccessControl.FileSystemRights]::Write -bor
    [System.Security.AccessControl.FileSystemRights]::Modify -bor
    [System.Security.AccessControl.FileSystemRights]::FullControl
  foreach ($rule in @($acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]))) {
    if ($rule.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow -or
        ($rule.PropagationFlags -band [System.Security.AccessControl.PropagationFlags]::InheritOnly) -ne 0 -or
        $trustedSids.ContainsKey([string]$rule.IdentityReference.Value)) { continue }
    if (([int64]$rule.FileSystemRights -band [int64]$writeMask) -ne 0) {
      throw "Kill-switch lock parent permits untrusted creation or modification: $Path"
    }
  }
}
function Get-KillSwitchLockDirectory {
  $programData = [System.Environment]::GetFolderPath([System.Environment+SpecialFolder]::CommonApplicationData)
  if ([string]::IsNullOrWhiteSpace($programData)) {
    throw 'CommonApplicationData could not be resolved for the kill-switch lock.'
  }
  $programData = [System.IO.Path]::GetFullPath($programData)
  $volumeRoot = [System.IO.Path]::GetPathRoot($programData)
  if (Test-PathContainsReparsePoint -Path $programData -Root $volumeRoot) {
    throw "CommonApplicationData traverses a reparse point: $programData"
  }

  # Use a pre-existing Windows-managed parent, not a new user-creatable
  # ProgramData component. A standard user therefore cannot pre-create the
  # lock directory before an elevated remediation run.
  $trustedParent = Join-Path $programData 'Microsoft\Windows'
  if (-not (Test-Path -LiteralPath $trustedParent -PathType Container) -or
      (Test-PathContainsReparsePoint -Path $trustedParent -Root $programData)) {
    throw "Trusted Windows ProgramData parent is missing or unsafe: $trustedParent"
  }
  Assert-KillSwitchLockParent -Path $trustedParent
  $directory = Join-Path $trustedParent 'BaselineOpsForWindows-EmergencyKillSwitch'
  $security = Get-KillSwitchLockAcl -Directory
  if ($PSVersionTable.PSEdition -eq 'Desktop') {
    [void][System.IO.Directory]::CreateDirectory($directory, $security)
  } else {
    [void][System.IO.FileSystemAclExtensions]::CreateDirectory($security, $directory)
  }
  if (Test-PathContainsReparsePoint -Path $directory -Root $trustedParent) {
    throw "Kill-switch lock directory traverses a reparse point: $directory"
  }
  Assert-KillSwitchLockAcl -Path $directory -Directory
  return $directory
}
# Acquires an exclusive administrator-owned lock so concurrent isolation runs
# cannot capture conflicting rollback state or create overlapping rules.
function Enter-KillSwitchRemediationLock {
  [OutputType([System.IO.FileStream])]
  param([string]$LockDirectory)

  # The entry script is Windows-only. This branch keeps helper-level tests
  # portable without weakening the Windows privileged-path contract below.
  if ([System.Environment]::OSVersion.Platform -ne [System.PlatformID]::Win32NT) {
    if ([string]::IsNullOrWhiteSpace($LockDirectory)) {
      $LockDirectory = Join-Path ([System.IO.Path]::GetTempPath()) 'baselineops-windows-emergency-kill-switch'
    }
    [void][System.IO.Directory]::CreateDirectory($LockDirectory)
    return [System.IO.File]::Open((Join-Path $LockDirectory 'remediation.lock'), [System.IO.FileMode]::OpenOrCreate, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
  }
  if ([string]::IsNullOrWhiteSpace($LockDirectory)) {
    $LockDirectory = Get-KillSwitchLockDirectory
  }

  Assert-KillSwitchLockAcl -Path $LockDirectory -Directory
  $lockPath = Join-Path $LockDirectory 'remediation.lock'
  if (Test-Path -LiteralPath $lockPath) {
    Assert-KillSwitchLockAcl -Path $lockPath
  }
  $stream = $null
  try {
    $security = Get-KillSwitchLockAcl
    $fileInfo = New-Object System.IO.FileInfo($lockPath)
    if ($PSVersionTable.PSEdition -eq 'Desktop') {
      $stream = $fileInfo.Create([System.IO.FileMode]::OpenOrCreate,
        [System.Security.AccessControl.FileSystemRights]::ReadWrite,
        [System.IO.FileShare]::None, 4096, [System.IO.FileOptions]::WriteThrough, $security)
    } else {
      $stream = [System.IO.FileSystemAclExtensions]::Create($fileInfo, [System.IO.FileMode]::OpenOrCreate,
        [System.Security.AccessControl.FileSystemRights]::ReadWrite,
        [System.IO.FileShare]::None, 4096, [System.IO.FileOptions]::WriteThrough, $security)
    }
    Assert-KillSwitchLockAcl -Path $lockPath
    return $stream
  } catch {
    if ($null -ne $stream) { $stream.Dispose() }
    throw
  }
}
function Remove-ExactJustCreatedFirewallRule {
  param(
    [Parameter(Mandatory=$true)][ValidatePattern('^[A-Za-z0-9_-]+$')][ValidateLength(1,256)][string]$Name,
    [Parameter(Mandatory=$true)][ValidateSet('Inbound','Outbound')][string]$Direction,
    [Parameter(Mandatory=$true)][ValidateSet('Block','Allow')][string]$Action
  )
  try {
    Remove-NetFirewallRule -Name $Name -ErrorAction Stop
    return $true
  } catch {
    $message = "Exact cleanup of just-created firewall rule '$Name' failed after verification failure: $($_.Exception.Message)"
    Add-RunError $message
    $null = Add-Finding -FindingList $Findings -Code 'Firewall-RuleCleanupFailed' -Severity 'High' -Message $message -Extra @{ RuleName = $Name; Direction = $Direction; Action = $Action }
    return $false
  }
}
# Refuses owner-unknown name collisions and verifies the exact newly created
# firewall rule; a failed verification triggers cleanup of only that rule.
function New-OrReplaceRule {
  [CmdletBinding(SupportsShouldProcess = $true)]
  param([ValidatePattern('^[A-Za-z0-9_-]+$')][ValidateLength(1,256)][string]$Name,[string]$DisplayName,[ValidateSet('Inbound','Outbound')][string]$Direction,[ValidateSet('Block','Allow')][string]$Action,[string[]]$RemoteAddress = @(),[ValidateSet('TCP','UDP','Any')][string]$Protocol = 'Any',[string]$LocalPort,[string]$Description = '')
  try { $existingRules = @(Get-NetFirewallRule -Name $Name -ErrorAction SilentlyContinue | Where-Object { $null -ne $_ }) } catch { $existingRules = @() }
  if ($existingRules.Count -gt 0) { $message = "Firewall rule '$Name' already exists; refusing to replace owner-unknown rule."; Add-RunError $message; $null = Add-Finding -FindingList $Findings -Code 'Firewall-RuleCollision' -Severity 'High' -Message $message -Extra @{ RuleName = $Name }; return $false }
  $params = @{ Name = $Name; DisplayName = $DisplayName; Direction = $Direction; Action = $Action; Profile = 'Any'; Enabled = 'True'; Description = $Description }
  if ($RemoteAddress -and $RemoteAddress.Count -gt 0) { $params.RemoteAddress = $RemoteAddress }
  if ($Protocol -ne 'Any') { $params.Protocol = $Protocol }
  if (-not [string]::IsNullOrWhiteSpace($LocalPort)) { $params.LocalPort = $LocalPort }
  try { if (-not $PSCmdlet.ShouldProcess($Name, 'Create firewall rule')) { Add-RunError "Firewall rule '$Name' creation skipped by ShouldProcess."; return $false }; New-NetFirewallRule @params | Out-Null }
  catch { $message = "Firewall rule '$Name' creation failed: $($_.Exception.Message)"; Add-RunError $message; $null = Add-Finding -FindingList $Findings -Code 'Firewall-RuleCreateFailed' -Severity 'High' -Message $message -Extra @{ RuleName = $Name; Direction = $Direction; Action = $Action }; return $false }
  $verificationError = $null
  try { $createdRules = @(Get-NetFirewallRule -Name $Name -ErrorAction Stop | Where-Object { $null -ne $_ }) } catch { $createdRules = @(); $verificationError = $_.Exception.Message }
  $verifiedRules = @($createdRules | Where-Object { [string]$_.Name -eq $Name -and [string]$_.Enabled -eq 'True' -and [string]$_.Direction -eq $Direction -and [string]$_.Action -eq $Action })
  if ($verificationError -or $createdRules.Count -ne 1 -or $verifiedRules.Count -ne 1) {
    $message = if ($verificationError) { "Firewall rule '$Name' post-create verification query failed: $verificationError" } else { "Firewall rule '$Name' was not found, was not enabled, or did not match requested settings after creation." }
    Add-RunError $message
    $null = Add-Finding -FindingList $Findings -Code 'Firewall-RuleCreateFailed' -Severity 'High' -Message $message -Extra @{ RuleName = $Name; Direction = $Direction; Action = $Action; VerificationError = $verificationError }
    [void](Remove-ExactJustCreatedFirewallRule -Name $Name -Direction $Direction -Action $Action)
    return $false
  }
  return $true
}
# Validates the minimal rule identity set stored for rollback, preventing a
# snapshot from authorizing deletion of unrelated firewall rules.
function Assert-ManagedFirewallRules {
  param([Parameter(Mandatory=$true)][object[]]$Rules)
  if ($Rules.Count -lt 1 -or $Rules.Count -gt 3) { throw 'Managed rule identities must contain between one and three rules.' }
  $seen = @{}
  foreach ($rule in $Rules) {
    if ($null -eq $rule -or @($rule.PSObject.Properties.Name).Count -ne 3 -or @($rule.PSObject.Properties.Name | Where-Object { @('Name','Direction','Action') -notcontains $_ }).Count -ne 0) { throw 'Managed rule identity contains missing or unexpected fields.' }
    if ($rule.Name -isnot [string] -or $rule.Name -notmatch '^[A-Za-z0-9_-]+$' -or $rule.Name.Length -gt 256 -or $seen.ContainsKey($rule.Name)) { throw 'Managed rule identity has an invalid or duplicate name.' }
    if (@('Inbound','Outbound') -notcontains [string]$rule.Direction -or @('Allow','Block') -notcontains [string]$rule.Action) { throw 'Managed rule identity has an invalid direction or action.' }
    $seen[$rule.Name] = $true
  }
}
function Test-NoManagedFirewallRuleConflicts {
  param(
    [Parameter(Mandatory=$true)][string]$RulePrefix,
    [Parameter(Mandatory=$true)][string]$TaskPrefix
  )
  try {
    $escapedRulePrefix = [regex]::Escape($RulePrefix)
    $pattern = '^' + $escapedRulePrefix + '-(?:[a-fA-F0-9]{32}-)?(?:IN-BLOCK|OUT-BLOCK|BREAKGLASS-IN-ALLOW)$'
    $conflicts = @(Get-NetFirewallRule -ErrorAction Stop | Where-Object { $_ -and [string]$_.Name -match $pattern })
    $taskPattern = '^' + [regex]::Escape($TaskPrefix) + '(?:-[a-fA-F0-9]{32})?$'
    $taskConflicts = @(Get-ScheduledTask -ErrorAction Stop | Where-Object { $_ -and [string]$_.TaskName -match $taskPattern })
    if ($conflicts.Count -eq 0 -and $taskConflicts.Count -eq 0) { return $true }
    $identities = @($conflicts.Name) + @($taskConflicts.TaskName)
    $message = "Preexisting kill-switch rule or rollback-task identity detected ($($identities -join ', ')); refusing an overlapping activation so the existing rollback remains authoritative."
    Add-RunError $message
    $null = Add-Finding -FindingList $Findings -Code 'Firewall-ManagedRuleConflict' -Severity 'High' -Message $message
    return $false
  } catch {
    $message = "Unable to inspect existing kill-switch rule and rollback-task identities before mutation: $($_.Exception.Message)"
    Add-RunError $message
    $null = Add-Finding -FindingList $Findings -Code 'Firewall-ManagedRuleConflict' -Severity 'High' -Message $message
    return $false
  }
}
function Remove-ExactManagedFirewallRules {
  param([Parameter(Mandatory=$true)][object[]]$Rules)
  Assert-ManagedFirewallRules -Rules $Rules
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
function Assert-CanonicalFirewallSnapshot {
  param([Parameter(Mandatory=$true)]$Snapshot)
  $requiredNames = @('Domain','Private','Public'); $requiredFields = @('Name','Enabled','DefaultInboundAction','DefaultOutboundAction'); $validActions = @('Allow','Block','NotConfigured')
  if ($null -eq $Snapshot -or @($Snapshot.PSObject.Properties.Name).Count -ne 4 -or @($Snapshot.PSObject.Properties.Name | Where-Object { @('Version','Profiles','Adapters','ManagedRules') -notcontains $_ }).Count -ne 0) { throw 'Firewall rollback snapshot must contain exactly Version, Profiles, Adapters, and ManagedRules.' }
  if (-not (Test-JsonInteger $Snapshot.Version) -or [int]$Snapshot.Version -ne 3) { throw 'Firewall rollback snapshot has an unsupported version.' }; $profiles = @($Snapshot.Profiles); if ($profiles.Count -ne $requiredNames.Count) { throw 'Firewall rollback snapshot must contain Domain, Private, and Public exactly once.' }
  $seen = @{}; foreach ($firewallProfile in $profiles) { if ($null -eq $firewallProfile -or @($firewallProfile.PSObject.Properties.Name).Count -ne $requiredFields.Count -or @($firewallProfile.PSObject.Properties.Name | Where-Object { $requiredFields -notcontains $_ }).Count -ne 0) { throw "Firewall rollback profile contains missing or unexpected fields (received: $(@($firewallProfile.PSObject.Properties.Name) -join ','))." }; $name = [string]$firewallProfile.Name; if ($requiredNames -notcontains $name) { throw "Firewall rollback snapshot contains unknown profile '$name'." }; if ($seen.ContainsKey($name)) { throw "Firewall rollback snapshot contains duplicate profile '$name'." }; $seen[$name] = $true; $null = ConvertTo-StrictFirewallBoolean -Value $firewallProfile.Enabled -FieldName "$name.Enabled"; foreach ($actionField in @('DefaultInboundAction','DefaultOutboundAction')) { if ($validActions -notcontains [string]$firewallProfile.$actionField) { throw "Firewall rollback profile '$name' has invalid $actionField value '$($firewallProfile.$actionField)'." } } }
  foreach ($requiredName in $requiredNames) { if (-not $seen.ContainsKey($requiredName)) { throw "Firewall rollback snapshot is missing profile '$requiredName'." } }; $adapterNames = @($Snapshot.Adapters); if ($adapterNames.Count -gt 128) { throw 'Firewall rollback snapshot contains too many adapters.' }; $seenAdapters = @{}; foreach ($adapterName in $adapterNames) { if ($adapterName -isnot [string] -or [string]::IsNullOrWhiteSpace($adapterName) -or $adapterName.Length -gt 256 -or $adapterName -match '[\x00-\x1f]') { throw 'Firewall rollback snapshot contains an invalid adapter name.' }; if ($seenAdapters.ContainsKey($adapterName)) { throw "Firewall rollback snapshot contains duplicate adapter '$adapterName'." }; $seenAdapters[$adapterName] = $true }; Assert-ManagedFirewallRules -Rules @($Snapshot.ManagedRules)
}
# Captures and round-trips the pre-isolation firewall state before mutation so
# rollback is based on validated, deterministic data rather than live guesses.
function Get-CanonicalFirewallRollbackSnapshot {
  param([switch]$CaptureAdapters,[Parameter(Mandatory=$true)][object[]]$ManagedRules)
  try { $capturedProfiles = @(Get-NetFirewallProfile -ErrorAction Stop); if ($capturedProfiles.Count -ne 3) { throw 'Firewall profile capture must contain Domain, Private, and Public exactly once.' }; $profiles = foreach ($profileName in @('Domain','Private','Public')) { $profileMatches = @($capturedProfiles | Where-Object { [string]$_.Name -eq $profileName }); if ($profileMatches.Count -ne 1) { throw "Firewall profile '$profileName' must be present exactly once (captured: $($capturedProfiles.Count); names: $(@($capturedProfiles | ForEach-Object { $_.Name }) -join ','))." }; $fwProfile = $profileMatches[0]; [pscustomobject][ordered]@{ Name = $profileName; Enabled = ConvertTo-StrictFirewallBoolean -Value $fwProfile.Enabled -FieldName "$profileName.Enabled"; DefaultInboundAction = [string]$fwProfile.DefaultInboundAction; DefaultOutboundAction = [string]$fwProfile.DefaultOutboundAction } }; $adapterNames = @(); if ($CaptureAdapters) { $adapterNames = @(Get-NetAdapter -ErrorAction Stop | Where-Object { $_.Status -eq 'Up' } | ForEach-Object { [string]$_.Name }) }; $snapshot = [pscustomobject][ordered]@{ Version = 3; Profiles = @($profiles); Adapters = @($adapterNames); ManagedRules = @($ManagedRules) }; Assert-CanonicalFirewallSnapshot -Snapshot $snapshot; $json = $snapshot | ConvertTo-Json -Depth 4 -Compress; $verified = $json | ConvertFrom-Json -ErrorAction Stop; Assert-CanonicalFirewallSnapshot -Snapshot $verified; $Run.Actions.RollbackStateCaptured = $true; return $json }
  catch { Add-RunError "Failed to capture and validate pre-kill-switch firewall snapshot: $($_.Exception.Message)"; return $null }
}
function Resolve-Outcome { $Run.Outcome.IsolationActive = [bool]($Run.Actions.FirewallProfileSet -or $Run.Actions.RulesCreated -or $Run.Actions.AdaptersDisabled) }
function Invoke-KillSwitchConsoleSummary {
  $Run.EndTime = Get-Date; $Run.Duration = New-TimeSpan -Start $Run.StartTime -End $Run.EndTime; Resolve-Outcome
  $summaryObj = [pscustomobject]@{ ComputerName = $Run.ComputerName; Timestamp = $Run.EndTime }
  Write-ConsoleSummary -Summary $summaryObj -Findings ([System.Collections.ArrayList]::new()) -CustomFields ([ordered]@{ User = $Run.User; IsAdmin = $Run.IsAdmin; Duration = $Run.Duration; 'JSON used' = $Run.JsonUsed; Reason = $Run.Effective.Reason; IsolationActive = [string]$Run.Outcome.IsolationActive; DisableAdapters = [string][bool]$Run.Effective.DisableAdapters; AutoRollbackMinutes = $Run.Effective.AutoRollbackMinutes })
  Write-UiLine ""; foreach ($name in @('RegistryWritten','EventLogWritten','FirewallProfileSet','RulesCreated','BreakGlassApplied','BreakGlassCleanupChecked','BreakGlassRemoved','AdaptersDisabled','RollbackScheduled')) { Write-UiBool -Key $name -Value $Run.Actions[$name] }
  if ($Run.Actions.ConfirmDeclined) { Write-UiLine ""; Write-UiLine -Text "NOTE: One or more operations were declined in a Confirm prompt (No / No to All)." -Color Yellow }
  if ($Run.Errors.Count -gt 0) { Write-UiLine ""; Write-UiLine -Text 'Warnings/Errors:' -Color Yellow; foreach ($e in $Run.Errors) { Write-UiLine -Text ("- {0}" -f $e) -Color Yellow } }
}
