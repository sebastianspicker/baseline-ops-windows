<#
.SYNOPSIS
Internal validation, locking, firewall, and rollback helpers for the kill switch.

.DESCRIPTION
Validates the fail-closed configuration, serializes remediation, and captures a
canonical rollback snapshot before changing managed firewall state. The entry
script creates its run context and imports shared modules before dot-sourcing.
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
function Test-JsonInteger {
  param($Value)
  return (
    (Test-AnyCondition -Conditions @({ $Value -is [byte] }, { $Value -is [sbyte] })) -or
    $Value -is [int16] -or $Value -is [uint16] -or
    $Value -is [int32] -or $Value -is [uint32] -or
    $Value -is [int64] -or $Value -is [uint64]
  )
}
# Applies a closed schema and bounded values before configuration can influence
# isolation, break-glass access, or rollback scheduling.
function Assert-KillSwitchConfigSection01 {
  param([hashtable]$RunState)
if ($null -eq $RunState.Config -or $RunState.Config -is [string] -or $RunState.Config -is [System.ValueType] -or $RunState.Config -is [System.Collections.IEnumerable]) { throw 'Kill-switch configuration root must be an object.' }
  $RunState.allowedFields = @('EventSource','EventLog','EventId','RegKey','RulePrefix','TaskName','IncludeUserInRegistry','DisableAdapters','BreakGlassRemoteAddress','BreakGlassLocalPort','AutoRollbackMinutes')
  $RunState.seen = @{}
}

function Assert-KillSwitchConfigSection02 {
  param([hashtable]$RunState)
foreach ($property in $RunState.Config.PSObject.Properties) {
    $normalizedName = $property.Name.ToLowerInvariant()
    if ($RunState.seen.ContainsKey($normalizedName)) { throw "Kill-switch configuration contains duplicate field '$($property.Name)'." }
    $RunState.seen[$normalizedName] = $true
    if ($RunState.allowedFields -notcontains $property.Name) { throw "Kill-switch configuration contains unknown field '$($property.Name)'." }
  }
}

function Assert-KillSwitchConfigSection03 {
  param([hashtable]$RunState)
foreach ($field in @('EventSource','EventLog','RegKey','RulePrefix','TaskName')) {
    $property = $RunState.Config.PSObject.Properties[$field]
    if ($null -ne $property -and ($property.Value -isnot [string] -or [string]::IsNullOrWhiteSpace($property.Value) -or $property.Value.Length -gt 256 -or $property.Value -match '[\x00-\x1f]')) { throw "Kill-switch configuration field '$field' must be a non-empty string of at most 256 characters without control characters." }
  }
}

function Assert-KillSwitchConfigSection04 {
  param([hashtable]$RunState)
foreach ($field in @('IncludeUserInRegistry','DisableAdapters')) { $property = $RunState.Config.PSObject.Properties[$field]; if ($null -ne $property -and $property.Value -isnot [bool]) { throw "Kill-switch configuration field '$field' must be a boolean." } }
  $RunState.eventIdProperty = $RunState.Config.PSObject.Properties['EventId']
}

function Assert-KillSwitchConfigSection05 {
  param([hashtable]$RunState)
if ($null -ne $RunState.eventIdProperty -and ((-not (Test-JsonInteger $RunState.eventIdProperty.Value)) -or [int64]$RunState.eventIdProperty.Value -lt 1 -or [int64]$RunState.eventIdProperty.Value -gt 65535)) { throw "Kill-switch configuration field 'EventId' must be an integer from 1 through 65535." }
  $RunState.rollbackProperty = $RunState.Config.PSObject.Properties['AutoRollbackMinutes']
}

function Assert-KillSwitchConfigSection06 {
  param([hashtable]$RunState)
if ($null -ne $RunState.rollbackProperty -and ((-not (Test-JsonInteger $RunState.rollbackProperty.Value)) -or [int64]$RunState.rollbackProperty.Value -lt 0 -or [int64]$RunState.rollbackProperty.Value -gt 1440)) { throw "Kill-switch configuration field 'AutoRollbackMinutes' must be an integer from 0 through 1440." }
  $RunState.breakGlassPortProperty = $RunState.Config.PSObject.Properties['BreakGlassLocalPort']
}

function Assert-KillSwitchConfigSection07 {
  param([hashtable]$RunState)
if ($null -ne $RunState.breakGlassPortProperty -and ((-not (Test-JsonInteger $RunState.breakGlassPortProperty.Value)) -or [int64]$RunState.breakGlassPortProperty.Value -lt 1 -or [int64]$RunState.breakGlassPortProperty.Value -gt 65535)) { throw "Kill-switch configuration field 'BreakGlassLocalPort' must be an integer from 1 through 65535." }
  $RunState.addressesProperty = $RunState.Config.PSObject.Properties['BreakGlassRemoteAddress']
}

function Assert-KillSwitchConfigSection08Stage01 {
  param([hashtable]$RunState)
if ((Test-AnyCondition -Conditions @({ $RunState.addressesProperty.Value -is [string] }, { $RunState.addressesProperty.Value -isnot [System.Collections.IEnumerable] }))) { throw "Kill-switch configuration field 'BreakGlassRemoteAddress' must be an array of IP addresses or CIDR ranges." }
    $addresses = @($RunState.addressesProperty.Value); if ($addresses.Count -gt 64) { throw "Kill-switch configuration field 'BreakGlassRemoteAddress' supports at most 64 entries." }
}

function Assert-KillSwitchConfigSection08Stage02 {
foreach ($address in $addresses) {
      if ((Test-AnyCondition -Conditions @({ (Test-AnyCondition -Conditions @({ $address -isnot [string] }, { [string]::IsNullOrWhiteSpace($address) })) }, { $address.Length -gt 128 }))) { throw 'Each BreakGlassRemoteAddress entry must be a non-empty string of at most 128 characters.' }
      $parts = $address.Split('/'); $parsedAddress = $null
      if ((Test-AnyCondition -Conditions @({ $parts.Count -gt 2 }, { -not [System.Net.IPAddress]::TryParse($parts[0],[ref]$parsedAddress) }))) { throw "BreakGlassRemoteAddress entry '$address' is not an IP address or CIDR range." }
      if ($parts.Count -eq 2) { $prefixLength = 0; $maximumPrefix = if ($parsedAddress.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) { 32 } else { 128 }; if ((Test-AnyCondition -Conditions @({ (Test-AnyCondition -Conditions @({ -not [int]::TryParse($parts[1],[ref]$prefixLength) }, { $prefixLength -lt 0 })) }, { $prefixLength -gt $maximumPrefix }))) { throw "BreakGlassRemoteAddress entry '$address' has an invalid prefix length." } }
    }
}

function Assert-KillSwitchConfigSection08 {
  param([hashtable]$RunState)
if ($null -ne $RunState.addressesProperty) {
    . Assert-KillSwitchConfigSection08Stage01 -RunState $RunState
. Assert-KillSwitchConfigSection08Stage02
  }
}

function Assert-KillSwitchConfig {
  param([Parameter(Mandatory=$true)]$Config, [hashtable]$RunState)
  $RunState.Config = $Config
    . Assert-KillSwitchConfigSection01 -RunState $RunState
    . Assert-KillSwitchConfigSection02 -RunState $RunState
    . Assert-KillSwitchConfigSection03 -RunState $RunState
    . Assert-KillSwitchConfigSection04 -RunState $RunState
    . Assert-KillSwitchConfigSection05 -RunState $RunState
    . Assert-KillSwitchConfigSection06 -RunState $RunState
    . Assert-KillSwitchConfigSection07 -RunState $RunState
    . Assert-KillSwitchConfigSection08 -RunState $RunState
}
function Try-LoadConfigJson {
  param([string]$Path,[string]$Raw,[bool]$PathSupplied,[bool]$RawSupplied, [hashtable]$RunState)
  try {
    if ($PathSupplied -and $RawSupplied) { throw 'Specify only one of ConfigJsonPath or ConfigJsonRaw.' }
    if (-not $PathSupplied -and -not $RawSupplied) { return $null }
    $text = if ($RawSupplied) {
      Read-KillSwitchRawConfig -Raw $Raw
    } else {
      Read-KillSwitchFileConfig -Path $Path
    }
    $configObject = $text | ConvertFrom-Json -ErrorAction Stop
    Assert-KillSwitchConfig -Config $configObject -RunState $RunState
    return $configObject
  } catch {
    $RunState.Run.JsonError = $_.Exception.Message
    return $null
  }
}
function Read-KillSwitchRawConfig {
  param([AllowNull()][string]$Raw)
  if ([string]::IsNullOrWhiteSpace($Raw)) { throw 'ConfigJsonRaw was supplied but is empty.' }
  if ([Text.Encoding]::UTF8.GetByteCount($Raw) -gt 65536) { throw 'ConfigJsonRaw exceeds the 64 KiB limit.' }
  return $Raw
}
function Read-KillSwitchFileConfig {
  param([AllowEmptyString()][string]$Path)
  $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
  if ($item.PSIsContainer) { throw 'ConfigJsonPath must identify a non-reparse file no larger than 64 KiB.' }
  if ($item.Length -gt 65536) { throw 'ConfigJsonPath must identify a non-reparse file no larger than 64 KiB.' }
  if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'ConfigJsonPath must identify a non-reparse file no larger than 64 KiB.' }
  $text = Get-BoundedUtf8FileContent -Path $item.FullName -MaximumBytes 65536
  if ([string]::IsNullOrWhiteSpace($text)) { throw 'ConfigJsonPath identifies an empty file.' }
  return $text
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
function Read-KillSwitchLockAclState {
  param([hashtable]$AclState)
Assert-TrustedWindowsPathAcl -Path $AclState.Path -CheckAncestors | Out-Null
  $item = Get-Item -LiteralPath $AclState.Path -Force -ErrorAction Stop
  if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw "Kill-switch lock path is a reparse point: $($AclState.Path)"
  }
  if ($AclState.IsDirectory -ne [bool]$item.PSIsContainer) {
    throw "Kill-switch lock path has an unexpected type: $($AclState.Path)"
  }

  $acl = Get-Acl -LiteralPath $item.FullName -ErrorAction Stop
  $administratorsSid = 'S-1-5-32-544'
  $systemSid = 'S-1-5-18'
  if ($acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value -ne $administratorsSid -or
      -not $acl.AreAccessRulesProtected) {
    throw "Kill-switch lock ACL is not protected and Administrators-owned: $($AclState.Path)"
  }
  $AclState.ExpectedSids = @($administratorsSid, $systemSid)
  $AclState.Rules = @($acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]) | Where-Object {
      $_.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Allow -and
      ($_.PropagationFlags -band [System.Security.AccessControl.PropagationFlags]::InheritOnly) -eq 0
    })
}

function Assert-KillSwitchLockAclRules {
  param([hashtable]$AclState)
if ($AclState.Rules.Count -ne 2 -or @($AclState.Rules | Where-Object {
        $_.IdentityReference.Value -notin $AclState.ExpectedSids -or
        -not $_.FileSystemRights.HasFlag([System.Security.AccessControl.FileSystemRights]::FullControl)
      }).Count -ne 0) {
    throw "Kill-switch lock ACL must grant FullControl only to SYSTEM and Administrators: $($AclState.Path)"
  }
}

function Assert-KillSwitchLockAcl {
  param(
    [Parameter(Mandatory)][string]$Path,
    [switch]$Directory
  )
  $aclState = @{
    Path = $Path
    IsDirectory = [bool]$Directory
  }
  . Read-KillSwitchLockAclState -AclState $aclState
  . Assert-KillSwitchLockAclRules -AclState $aclState
}
function Assert-KillSwitchLockParent {
  param([Parameter(Mandatory)][string]$Path)

  Assert-TrustedWindowsPathAcl -Path $Path -CheckAncestors | Out-Null
  $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
  $trustedSids = @{'S-1-5-32-544' = $true; 'S-1-5-18' = $true; 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464' = $true }
  $writeMask = [System.Security.AccessControl.FileSystemRights]::WriteData -bor
    [System.Security.AccessControl.FileSystemRights]::AppendData -bor
    [System.Security.AccessControl.FileSystemRights]::WriteExtendedAttributes -bor
    [System.Security.AccessControl.FileSystemRights]::WriteAttributes -bor
    [System.Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor
    [System.Security.AccessControl.FileSystemRights]::Delete -bor
    [System.Security.AccessControl.FileSystemRights]::ChangePermissions -bor
    [System.Security.AccessControl.FileSystemRights]::TakeOwnership
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
    return Open-PortableKillSwitchRemediationLock -LockDirectory $LockDirectory
  }
  if ([string]::IsNullOrWhiteSpace($LockDirectory)) {
    $LockDirectory = Get-KillSwitchLockDirectory
  }

  Assert-KillSwitchLockAcl -Path $LockDirectory -Directory
  $lockPath = Join-Path $LockDirectory 'remediation.lock'
  if (Test-Path -LiteralPath $lockPath) {
    Assert-KillSwitchLockAcl -Path $lockPath
  }
  return Open-WindowsKillSwitchRemediationLock -Path $lockPath
}
function Open-PortableKillSwitchRemediationLock {
  param([AllowEmptyString()][string]$LockDirectory)
  if ([string]::IsNullOrWhiteSpace($LockDirectory)) {
    $LockDirectory = Join-Path ([System.IO.Path]::GetTempPath()) 'baselineops-windows-emergency-kill-switch'
  }
  [void][System.IO.Directory]::CreateDirectory($LockDirectory)
  return [System.IO.File]::Open((Join-Path $LockDirectory 'remediation.lock'), [System.IO.FileMode]::OpenOrCreate, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)
}
function Open-WindowsKillSwitchRemediationLock {
  param([string]$Path)
  $stream = $null
  try {
    $security = Get-KillSwitchLockAcl
    $fileInfo = New-Object System.IO.FileInfo($Path)
    if ($PSVersionTable.PSEdition -eq 'Desktop') {
      $stream = $fileInfo.Create([System.IO.FileMode]::OpenOrCreate,
        [System.Security.AccessControl.FileSystemRights]::ReadWrite,
        [System.IO.FileShare]::None, 4096, [System.IO.FileOptions]::WriteThrough, $security)
    } else {
      $stream = [System.IO.FileSystemAclExtensions]::Create($fileInfo, [System.IO.FileMode]::OpenOrCreate,
        [System.Security.AccessControl.FileSystemRights]::ReadWrite,
        [System.IO.FileShare]::None, 4096, [System.IO.FileOptions]::WriteThrough, $security)
    }
    Assert-KillSwitchLockAcl -Path $Path
    return $stream
  } catch {
    if ($null -ne $stream) { $stream.Dispose() }
    throw
  }
}
# Refuses owner-unknown name collisions and verifies the exact newly created
# firewall rule; a failed verification triggers cleanup of only that rule.
# Validates the minimal rule identity set stored for rollback, preventing a
# snapshot from authorizing deletion of unrelated firewall rules.
function Assert-CanonicalFirewallSnapshotSection01 {
  param([hashtable]$RunState)
$RunState.requiredNames = @('Domain','Private','Public'); $RunState.requiredFields = @('Name','Enabled','DefaultInboundAction','DefaultOutboundAction'); $RunState.validActions = @('Allow','Block','NotConfigured')
  if ($null -eq $RunState.Snapshot -or @($RunState.Snapshot.PSObject.Properties.Name).Count -ne 4 -or @($RunState.Snapshot.PSObject.Properties.Name | Where-Object { @('Version','Profiles','Adapters','ManagedRules') -notcontains $_ }).Count -ne 0) { throw 'Firewall rollback snapshot must contain exactly Version, Profiles, Adapters, and ManagedRules.' }
  if (-not (Test-JsonInteger $RunState.Snapshot.Version) -or [int]$RunState.Snapshot.Version -ne 3) { throw 'Firewall rollback snapshot has an unsupported version.' }; $RunState.profiles = @($RunState.Snapshot.Profiles)
}

function Assert-CanonicalFirewallSnapshotSection02 {
  param([hashtable]$RunState)
if ($RunState.profiles.Count -ne $RunState.requiredNames.Count) { throw 'Firewall rollback snapshot must contain Domain, Private, and Public exactly once.' }
  $RunState.seen = @{}
}

function Assert-CanonicalFirewallSnapshotSection03Stage01 {
  param([hashtable]$RunState)
if ((Test-AnyCondition -Conditions @({ $null -eq $firewallProfile }, { @($firewallProfile.PSObject.Properties.Name).Count -ne $RunState.requiredFields.Count })) -or @($firewallProfile.PSObject.Properties.Name | Where-Object { $RunState.requiredFields -notcontains $_ }).Count -ne 0) { throw "Firewall rollback profile contains missing or unexpected fields (received: $(@($firewallProfile.PSObject.Properties.Name) -join ','))." }; $name = [string]$firewallProfile.Name; if ($RunState.requiredNames -notcontains $name) { throw "Firewall rollback snapshot contains unknown profile '$name'." }; if ($RunState.seen.ContainsKey($name)) { throw "Firewall rollback snapshot contains duplicate profile '$name'." }; $RunState.seen[$name] = $true; $null = ConvertTo-StrictFirewallBoolean -Value $firewallProfile.Enabled -FieldName "$name.Enabled"
}

function Assert-CanonicalFirewallSnapshotSection03Stage02 {
  param([hashtable]$RunState)
foreach ($actionField in @('DefaultInboundAction','DefaultOutboundAction')) { if ($RunState.validActions -notcontains [string]$firewallProfile.$actionField) { throw "Firewall rollback profile '$name' has invalid $actionField value '$($firewallProfile.$actionField)'." } }
}

function Assert-CanonicalFirewallSnapshotSection03 {
  param([hashtable]$RunState)
foreach ($firewallProfile in $RunState.profiles) { . Assert-CanonicalFirewallSnapshotSection03Stage01 -RunState $RunState
. Assert-CanonicalFirewallSnapshotSection03Stage02 -RunState $RunState }
}

function Assert-CanonicalFirewallSnapshotSection04 {
  param([hashtable]$RunState)
foreach ($requiredName in $RunState.requiredNames) { if (-not $RunState.seen.ContainsKey($requiredName)) { throw "Firewall rollback snapshot is missing profile '$requiredName'." } }; $adapterNames = @($RunState.Snapshot.Adapters); if ($adapterNames.Count -gt 128) { throw 'Firewall rollback snapshot contains too many adapters.' }; $RunState.seenAdapters = @{}
}

function Assert-CanonicalFirewallSnapshotSection05 {
  param([hashtable]$RunState)
foreach ($adapterName in $adapterNames) { if ($adapterName -isnot [string] -or [string]::IsNullOrWhiteSpace($adapterName) -or $adapterName.Length -gt 256 -or $adapterName -match '[\x00-\x1f]') { throw 'Firewall rollback snapshot contains an invalid adapter name.' }; if ($RunState.seenAdapters.ContainsKey($adapterName)) { throw "Firewall rollback snapshot contains duplicate adapter '$adapterName'." }; $RunState.seenAdapters[$adapterName] = $true }
}

function Assert-CanonicalFirewallSnapshotSection06 {
  param([hashtable]$RunState)
Assert-ManagedFirewallRules -Rules @($RunState.Snapshot.ManagedRules) -RunState $RunState
}

function Assert-CanonicalFirewallSnapshot {
  param([Parameter(Mandatory=$true)]$Snapshot, [hashtable]$RunState)
  $RunState.Snapshot = $Snapshot
    . Assert-CanonicalFirewallSnapshotSection01 -RunState $RunState
    . Assert-CanonicalFirewallSnapshotSection02 -RunState $RunState
    . Assert-CanonicalFirewallSnapshotSection03 -RunState $RunState
    . Assert-CanonicalFirewallSnapshotSection04 -RunState $RunState
    . Assert-CanonicalFirewallSnapshotSection05 -RunState $RunState
    . Assert-CanonicalFirewallSnapshotSection06 -RunState $RunState
}
# Captures and round-trips the pre-isolation firewall state before mutation so
# rollback is based on validated, deterministic data rather than live guesses.
function Get-CanonicalFirewallRollbackSnapshot {
  param([switch]$CaptureAdapters,[Parameter(Mandatory=$true)][object[]]$ManagedRules, [hashtable]$RunState)
  try { $capturedProfiles = @(Get-NetFirewallProfile -ErrorAction Stop); if ($capturedProfiles.Count -ne 3) { throw 'Firewall profile capture must contain Domain, Private, and Public exactly once.' }; $RunState.profiles = foreach ($profileName in @('Domain','Private','Public')) { $profileMatches = @($capturedProfiles | Where-Object { [string]$_.Name -eq $profileName }); if ($profileMatches.Count -ne 1) { throw "Firewall profile '$profileName' must be present exactly once (captured: $($capturedProfiles.Count); names: $(@($capturedProfiles | ForEach-Object { $_.Name }) -join ','))." }; $fwProfile = $profileMatches[0]; [pscustomobject][ordered]@{ Name = $profileName; Enabled = ConvertTo-StrictFirewallBoolean -Value $fwProfile.Enabled -FieldName "$profileName.Enabled"; DefaultInboundAction = [string]$fwProfile.DefaultInboundAction; DefaultOutboundAction = [string]$fwProfile.DefaultOutboundAction } }; $adapterNames = @(); if ($CaptureAdapters) { $adapterNames = @(Get-NetAdapter -ErrorAction Stop | Where-Object { $_.Status -eq 'Up' } | ForEach-Object { [string]$_.Name }) }; $RunState.snapshot = [pscustomobject][ordered]@{ Version = 3; Profiles = @($RunState.profiles); Adapters = @($adapterNames); ManagedRules = @($ManagedRules) }; Assert-CanonicalFirewallSnapshot -Snapshot $RunState.snapshot -RunState $RunState; $json = $RunState.snapshot | ConvertTo-Json -Depth 4 -Compress; $verified = $json | ConvertFrom-Json -ErrorAction Stop; Assert-CanonicalFirewallSnapshot -Snapshot $verified -RunState $RunState; $RunState.Run.Actions.RollbackStateCaptured = $true; return $json }
  catch { Add-RunError "Failed to capture and validate pre-kill-switch firewall snapshot: $($_.Exception.Message)" -RunState $RunState; return $null }
}
function Resolve-Outcome {
  param([hashtable]$RunState) $RunState.Run.Outcome.IsolationActive = [bool]($RunState.Run.Actions.FirewallProfileSet -or $RunState.Run.Actions.RulesCreated -or $RunState.Run.Actions.AdaptersDisabled) }
function Invoke-KillSwitchConsoleSummary {
  param([hashtable]$RunState)
  $RunState.Run.EndTime = Get-Date; $RunState.Run.Duration = New-TimeSpan -Start $RunState.Run.StartTime -End $RunState.Run.EndTime; Resolve-Outcome -RunState $RunState
  $summaryObj = [pscustomobject]@{ ComputerName = $RunState.Run.ComputerName; Timestamp = $RunState.Run.EndTime }
  Write-ConsoleSummary -Summary $summaryObj -Findings ([System.Collections.ArrayList]::new()) -CustomFields ([ordered]@{ User = $RunState.Run.User; IsAdmin = $RunState.Run.IsAdmin; Duration = $RunState.Run.Duration; 'JSON used' = $RunState.Run.JsonUsed; Reason = $RunState.Run.Effective.Reason; IsolationActive = [string]$RunState.Run.Outcome.IsolationActive; DisableAdapters = [string][bool]$RunState.Run.Effective.DisableAdapters; AutoRollbackMinutes = $RunState.Run.Effective.AutoRollbackMinutes })
  Write-UiLine ""; foreach ($name in @('RegistryWritten','EventLogWritten','FirewallProfileSet','RulesCreated','BreakGlassApplied','BreakGlassCleanupChecked','BreakGlassRemoved','AdaptersDisabled','RollbackScheduled')) { Write-UiBool -Key $name -Value $RunState.Run.Actions[$name] }
  if ($RunState.Run.Actions.ConfirmDeclined) { Write-UiLine ""; Write-UiLine -Text "NOTE: One or more operations were declined in a Confirm prompt (No / No to All)." -Color Yellow }
  if ($RunState.Run.Errors.Count -gt 0) { Write-UiLine ""; Write-UiLine -Text 'Warnings/Errors:' -Color Yellow; foreach ($e in $RunState.Run.Errors) { Write-UiLine -Text ("- {0}" -f $e) -Color Yellow } }
}


function Add-RunError {
  param([string]$Message, [hashtable]$RunState)
  [void]$RunState.Run.Errors.Add($Message)
}

function Set-QuarantineFlag {
  [CmdletBinding(SupportsShouldProcess = $true)]
  param(
    [string]$RegKey,
    [string]$ReasonText,
    [bool]$IncludeUser
  , [hashtable]$RunState)

  try {
    New-Item -Path $RegKey -Force | Out-Null
    Set-ItemProperty -LiteralPath $RegKey -Name 'Isolated' -Value 1 -Force
    Set-ItemProperty -LiteralPath $RegKey -Name 'Time'     -Value ((Get-Date).ToString('s')) -Force
    Set-ItemProperty -LiteralPath $RegKey -Name 'Reason'   -Value $ReasonText -Force
    if ($IncludeUser) {
      Set-ItemProperty -LiteralPath $RegKey -Name 'User' -Value $RunState.Run.User -Force
    }
    $RunState.Run.Actions.RegistryWritten = $true
  } catch {
    Add-RunError "Registry flag write failed: $($_.Exception.Message)" -RunState $RunState
  }
}

. (Join-Path $PSScriptRoot '21-EmergencyKillSwitch.runtime.ps1')
