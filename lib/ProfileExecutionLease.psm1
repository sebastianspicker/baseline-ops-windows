<#
.SYNOPSIS
Creates and validates private execution-closure leases for profile runners.

.DESCRIPTION
Keeps trusted code open with read-only sharing while a
profile or direct local run executes. Lease authority is stored by object
identity in this module instance and is never inferred from caller-supplied
object properties.
#>

Set-StrictMode -Version Latest
$script:LeaseModulePath = [System.IO.Path]::GetFullPath($PSCommandPath)
$script:LeaseGate = [object]::new()
$script:LeaseMembership = [System.Runtime.CompilerServices.ConditionalWeakTable[object, object]]::new()
$script:ClosedMembership = [System.Runtime.CompilerServices.ConditionalWeakTable[object, object]]::new()
$script:ActiveProfileOwners = [System.Collections.Generic.List[object]]::new()

function Get-LeasePathComparison {
  if ([System.Environment]::OSVersion.Platform -eq [System.PlatformID]::Win32NT) { return [System.StringComparison]::OrdinalIgnoreCase }
  return [System.StringComparison]::Ordinal
}

function Get-LeasePathComparer {
  if ([System.Environment]::OSVersion.Platform -eq [System.PlatformID]::Win32NT) { return [System.StringComparer]::OrdinalIgnoreCase }
  return [System.StringComparer]::Ordinal
}

function Get-CanonicalLeaseRoot {
  [CmdletBinding()]
  param([Parameter(Mandatory)][string]$Path)
  $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
  if (-not $item.PSIsContainer) { throw "Execution lease root is not a directory: $Path" }
  if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) { throw "Execution lease root is a reparse point: $Path" }
  $separators = [char[]]@([System.IO.Path]::DirectorySeparatorChar, [System.IO.Path]::AltDirectorySeparatorChar)
  return [System.IO.Path]::GetFullPath($item.FullName).TrimEnd($separators)
}

function Test-LeaseRootEquality {
  [CmdletBinding()]
  param([Parameter(Mandatory)][string]$Left,[Parameter(Mandatory)][string]$Right)
  return [string]::Equals($Left,$Right,(Get-LeasePathComparison))
}

function Test-LeasePathWithinRoot {
  param([string]$Path, [string]$Root)

  if (Test-LeaseRootEquality $Path $Root) { return $true }
  $separators = [char[]]@([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar)
  $prefix = $Root.TrimEnd($separators) + [IO.Path]::DirectorySeparatorChar
  return $Path.StartsWith($prefix, (Get-LeasePathComparison))
}

function Get-LeaseContainingRoot {
  param([string]$Path, [string[]]$Roots)

  foreach ($root in $Roots) {
    if (Test-LeasePathWithinRoot $Path $root) { return $root }
  }
  throw "Execution lease path is outside its canonical runner and target roots: $Path"
}

function Assert-LeaseNoReparseChain {
  param([string]$Path, [string]$Root)

  $current = $Path
  while ($true) {
    $item = Get-Item -LiteralPath $current -Force -ErrorAction Stop
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
      throw "Privileged code closure contains a reparse-point item: $current"
    }
    if (Test-LeaseRootEquality $current $Root) { return }
    $parent = Split-Path -Parent $current
    if ([string]::IsNullOrWhiteSpace($parent)) {
      throw "Execution lease path escaped its canonical root: $Path"
    }
    $current = [IO.Path]::GetFullPath($parent)
  }
}

function Get-LeaseCallerFrames {
  return @(Get-PSCallStack | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_.ScriptName) -and -not [string]::Equals([System.IO.Path]::GetFullPath([string]$_.ScriptName),$script:LeaseModulePath,(Get-LeasePathComparison)) })
}

function Assert-LeaseCaller {
  param([Parameter(Mandatory)][object[]]$Frames)
  if ($Frames.Count -lt 1) { throw 'Execution lease caller identity is unavailable.' }
  $leaf = Split-Path -Leaf ([string]$Frames[0].ScriptName)
  if ($leaf -notin @('00-Run-Profile.ps1','00-Run-Local.ps1')) { throw "Execution lease caller is not an approved runner: $leaf" }
  return $leaf
}

function Assert-LeaseCallerPath {
  param([string]$Caller, [object[]]$Frames, [string]$RunnerRoot)

  $scriptsRoot = Join-Path $RunnerRoot 'scripts'
  $expected = [IO.Path]::GetFullPath((Join-Path $scriptsRoot $Caller))
  $actual = [IO.Path]::GetFullPath([string]$Frames[0].ScriptName)
  if (-not [string]::Equals($actual, $expected, (Get-LeasePathComparison))) {
    throw "Execution lease caller path is outside the canonical runner control plane: $actual"
  }
}

function Test-LeaseElevatedWindows {
  if ([System.Environment]::OSVersion.Platform -ne [System.PlatformID]::Win32NT) { return $false }
  $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
  $principal = [System.Security.Principal.WindowsPrincipal]::new($identity)
  return $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-LeaseTrustMasks {
  $rights = [System.Security.AccessControl.FileSystemRights]
  $writeMask = $rights::WriteData -bor $rights::AppendData -bor $rights::WriteExtendedAttributes -bor `
    $rights::WriteAttributes -bor $rights::DeleteSubdirectoriesAndFiles -bor $rights::Delete -bor `
    $rights::ChangePermissions -bor $rights::TakeOwnership
  $replaceMask = $rights::Delete -bor $rights::DeleteSubdirectoriesAndFiles -bor `
    $rights::ChangePermissions -bor $rights::TakeOwnership
  return [pscustomobject]@{
    TrustedSids = @{
      'S-1-5-18' = $true
      'S-1-5-32-544' = $true
      'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464' = $true
    }
    WriteMask = $writeMask
    ReplaceMask = $replaceMask
  }
}

function Assert-LeaseAclRules {
  param($Acl,[hashtable]$TrustedSids,[int64]$Mask,[string]$Path)
  $ownerSid = $Acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value
  if (-not $TrustedSids.ContainsKey($ownerSid)) { throw "Privileged execution path has an untrusted owner SID: $Path" }
  foreach ($rule in @($Acl.GetAccessRules($true,$true,[System.Security.Principal.SecurityIdentifier]))) {
    $effective = $rule.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Allow -and ($rule.PropagationFlags -band [System.Security.AccessControl.PropagationFlags]::InheritOnly) -eq 0
    if ($effective -and -not $TrustedSids.ContainsKey([string]$rule.IdentityReference.Value) -and ([int64]$rule.FileSystemRights -band $Mask) -ne 0) { throw "Privileged execution path grants write/replace rights to an untrusted SID: $Path" }
  }
}

function Assert-LeaseTrustedPath {
  param([Parameter(Mandatory)][string]$Path, [switch]$CheckAncestors)

  if (-not (Test-LeaseElevatedWindows)) { return }
  $masks = Get-LeaseTrustMasks
  $current = (Get-Item -LiteralPath $Path -Force -ErrorAction Stop).FullName
  $protected = $true
  while (-not [string]::IsNullOrWhiteSpace($current)) {
    $item = Get-Item -LiteralPath $current -Force -ErrorAction Stop
    if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) { throw "Privileged execution path contains a reparse point: $current" }
    $mask = if ($protected) { $masks.WriteMask } else { $masks.ReplaceMask }
    Assert-LeaseAclRules -Acl (Get-Acl -LiteralPath $item.FullName -ErrorAction Stop) -TrustedSids $masks.TrustedSids -Mask $mask -Path $current
    $parent = Get-LeaseTrustedParent -Item $item -CheckAncestors:$CheckAncestors
    if (-not $parent) { break }
    $current = $parent
    $protected = $false
  }
}

function Get-LeaseTrustedParent {
  param($Item, [switch]$CheckAncestors)

  if (-not $CheckAncestors) { return $null }
  $parent = Split-Path -Parent $Item.FullName
  if ([string]::IsNullOrWhiteSpace($parent)) { return $null }
  if ([string]::Equals($parent, $Item.FullName, [System.StringComparison]::OrdinalIgnoreCase)) { return $null }
  return $parent
}

function Add-LeaseItemCount {
  param($State)
  $State.ItemCount++
  if ($State.ItemCount -gt $State.MaximumItems) { throw "Privileged code closure exceeds the $($State.MaximumItems)-item safety limit." }
}

function Add-LeaseFileStream {
  param([string]$Path, $State)

  $canonical = [System.IO.Path]::GetFullPath((Get-Item -LiteralPath $Path -Force -ErrorAction Stop).FullName)
  $containingRoot = Get-LeaseContainingRoot -Path $canonical -Roots $State.AllowedRoots
  Assert-LeaseNoReparseChain -Path $canonical -Root $containingRoot
  if (-not $State.SeenFiles.Add($canonical)) { return }
  Add-LeaseItemCount -State $State
  $stream = [System.IO.FileStream]::new(
    $canonical,
    [System.IO.FileMode]::Open,
    [System.IO.FileAccess]::Read,
    [System.IO.FileShare]::Read
  )
  try {
    $lockedItem = Get-Item -LiteralPath $canonical -Force -ErrorAction Stop
    if (($lockedItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) { throw "Privileged code closure contains a reparse-point item: $canonical" }
    Assert-LeaseTrustedPath -Path $lockedItem.FullName
    $State.Streams.Add($stream)
    $stream = $null
  } finally {
    if ($null -ne $stream) { $stream.Dispose() }
  }
}

function Add-LeaseDirectory {
  param([string]$Path, $State)

  $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
  $canonical = [IO.Path]::GetFullPath($item.FullName)
  $containingRoot = Get-LeaseContainingRoot -Path $canonical -Roots $State.AllowedRoots
  Assert-LeaseNoReparseChain -Path $canonical -Root $containingRoot
  if (-not $item.PSIsContainer) { throw "Privileged code closure root is not a directory: $Path" }
  if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) { throw "Privileged code closure contains a reparse-point directory: $Path" }
  if ($State.SeenDirectories.Add($item.FullName)) {
    Add-LeaseItemCount -State $State
    $State.Pending.Enqueue($item.FullName)
  }
}

function Add-LeaseClosureEntry {
  param([string]$Path,$State)
  $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
  if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) { throw "Privileged code closure contains a reparse-point item: $($item.FullName)" }
  if ($item.PSIsContainer) { Add-LeaseDirectory -Path $item.FullName -State $State } else { Add-LeaseFileStream -Path $item.FullName -State $State }
}

function Add-LeaseClosureRoot {
  param([string]$Path, $State)

  Add-LeaseDirectory -Path $Path -State $State
  while ($State.Pending.Count -gt 0) {
    $directory = $State.Pending.Dequeue()
    $item = Get-Item -LiteralPath $directory -Force -ErrorAction Stop
    if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) { throw "Privileged code closure contains a reparse-point directory: $directory" }
    Assert-LeaseTrustedPath -Path $item.FullName
    $enumerator = [System.IO.Directory]::EnumerateFileSystemEntries($item.FullName).GetEnumerator()
    try {
      while ($enumerator.MoveNext()) {
        Add-LeaseClosureEntry -Path ([string]$enumerator.Current) -State $State
      }
    } finally {
      if ($enumerator -is [System.IDisposable]) { $enumerator.Dispose() }
    }
  }
}

function New-LeaseState {
  param([int]$MaximumItems, [string[]]$AllowedRoots)

  $comparer = Get-LeasePathComparer
  return [pscustomobject]@{
    Pending = [System.Collections.Generic.Queue[string]]::new()
    SeenDirectories = [System.Collections.Generic.HashSet[string]]::new($comparer)
    SeenFiles = [System.Collections.Generic.HashSet[string]]::new($comparer)
    Streams = [System.Collections.Generic.List[System.IO.FileStream]]::new()
    ItemCount = 0
    MaximumItems = $MaximumItems
    AllowedRoots = $AllowedRoots
  }
}

function Close-LeaseStreams {
  param([Parameter(Mandatory)]$Record)

  $firstError = $null
  foreach ($stream in $Record.Streams) {
    try {
      $stream.Dispose()
    } catch {
      if ($null -eq $firstError) { $firstError = $_ }
    }
  }
  $Record.Streams.Clear()
  if ($null -ne $firstError) { throw $firstError }
}

function Get-LeaseRecord {
  param([Parameter(Mandatory)]$Lease)
  $record = $null
  [System.Threading.Monitor]::Enter($script:LeaseGate)
  try {
    if (-not $script:LeaseMembership.TryGetValue($Lease,[ref]$record)) { throw 'Execution lease identity is not registered or is no longer live.' }
    if ($record.Disposed -or ($record.Kind -eq 'Borrower' -and $record.Owner.Disposed)) { throw 'Execution lease is disposed or its owner is no longer live.' }
  }
  finally { [System.Threading.Monitor]::Exit($script:LeaseGate) }
  return $record
}

function Find-ProfileOwnerRecord {
  param([string]$RunnerRoot, [string]$TargetRoot, [object[]]$Frames)

  if ($Frames.Count -lt 2) { return $null }
  $parentPath = [System.IO.Path]::GetFullPath([string]$Frames[1].ScriptName)
  foreach ($record in $script:ActiveProfileOwners) {
    if ($record.Disposed) { continue }
    $runnerMatches = Test-LeaseRootEquality $record.RunnerRoot $RunnerRoot
    $targetMatches = Test-LeaseRootEquality $record.TargetRoot $TargetRoot
    if (-not $runnerMatches -or -not $targetMatches) { continue }
    if ([string]::Equals($record.OwnerScriptPath,$parentPath,(Get-LeasePathComparison))) { return $record }
  }
  return $null
}

function New-LeaseHandle {
  param($Record)

  $handle = [pscustomobject]@{
    Kind = $Record.Kind
    RunnerRoot = $Record.RunnerRoot
    TargetRoot = $Record.TargetRoot
  }
  $script:LeaseMembership.Add($handle,$Record)
  return $handle
}

function Open-LeaseBorrower {
  param([string]$Caller, [object[]]$Frames, [string]$RunnerRoot, [string]$TargetRoot)

  $directParent = $Caller -eq '00-Run-Local.ps1' -and $Frames.Count -ge 2 -and `
    (Split-Path -Leaf ([string]$Frames[1].ScriptName)) -eq '00-Run-Profile.ps1'
  if (-not $directParent) { return $null }
  [Threading.Monitor]::Enter($script:LeaseGate)
  try {
    $owner = Find-ProfileOwnerRecord -RunnerRoot $RunnerRoot -TargetRoot $TargetRoot -Frames $Frames
    if (-not $owner) {
      throw 'RunLocal profile lease reuse failed because the owner is disposed or its canonical roots do not match.'
    }
    $record = [pscustomobject]@{
      Kind = 'Borrower'
      RunnerRoot = $RunnerRoot
      TargetRoot = $TargetRoot
      Owner = $owner
      OwnerScriptPath = [IO.Path]::GetFullPath([string]$Frames[0].ScriptName)
      Streams = [Collections.Generic.List[IO.FileStream]]::new()
      Disposed = $false
    }
    return (New-LeaseHandle -Record $record)
  } finally {
    [Threading.Monitor]::Exit($script:LeaseGate)
  }
}

function Add-LeaseRequestedPaths {
  param($State, [string[]]$ControlFiles, [string[]]$ClosureRoots)

  foreach ($file in $ControlFiles) {
    Add-LeaseFileStream -Path $file -State $State
  }
  foreach ($root in $ClosureRoots) {
    Add-LeaseClosureRoot -Path $root -State $State
  }
}

function Register-LeaseOwner {
  param($Record)

  $handle = $null
  [Threading.Monitor]::Enter($script:LeaseGate)
  try {
    try {
      $handle = New-LeaseHandle -Record $Record
      if ($Record.Kind -eq 'ProfileOwner') { $script:ActiveProfileOwners.Add($Record) }
      return $handle
    } catch {
      if ($null -ne $handle) { [void]$script:LeaseMembership.Remove($handle) }
      [void]$script:ActiveProfileOwners.Remove($Record)
      throw
    }
  } finally {
    [Threading.Monitor]::Exit($script:LeaseGate)
  }
}

function New-LeaseOwner {
  param(
    [string]$Caller,
    [object[]]$Frames,
    [string]$RunnerRoot,
    [string]$TargetRoot,
    [string[]]$ControlFiles,
    [string[]]$ClosureRoots,
    [int]$MaximumItems
  )

  $state = New-LeaseState -MaximumItems $MaximumItems -AllowedRoots @($RunnerRoot, $TargetRoot)
  try {
    Assert-LeaseTrustedPath -Path $RunnerRoot -CheckAncestors
    Assert-LeaseTrustedPath -Path $TargetRoot -CheckAncestors
    Add-LeaseRequestedPaths -State $state -ControlFiles $ControlFiles -ClosureRoots $ClosureRoots
    $kind = if ($Caller -eq '00-Run-Profile.ps1') { 'ProfileOwner' } else { 'DirectOwner' }
    $record = [pscustomobject]@{
      Kind = $kind
      RunnerRoot = $RunnerRoot
      TargetRoot = $TargetRoot
      OwnerScriptPath = [IO.Path]::GetFullPath([string]$Frames[0].ScriptName)
      Streams = $state.Streams
      Disposed = $false
      ItemCount = $state.ItemCount
    }
    return (Register-LeaseOwner -Record $record)
  } catch {
    foreach ($stream in $state.Streams) {
      try {
        $stream.Dispose()
      } catch {
        Write-Verbose ("Partial lease cleanup failed: {0}" -f $_.Exception.Message)
      }
    }
    throw
  }
}

function Open-ProfileExecutionLease {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$RunnerRoot,
    [Parameter(Mandatory)][string]$TargetRoot,
    [Parameter(Mandatory)][string[]]$ControlFiles,
    [Parameter(Mandatory)][string[]]$ClosureRoots,
    [ValidateRange(1,8192)][int]$MaximumItems = 4096
  )

  $frames = @(Get-LeaseCallerFrames)
  $caller = Assert-LeaseCaller -Frames $frames
  $canonicalRunner = Get-CanonicalLeaseRoot $RunnerRoot
  $canonicalTarget = Get-CanonicalLeaseRoot $TargetRoot
  Assert-LeaseCallerPath -Caller $caller -Frames $frames -RunnerRoot $canonicalRunner
  $borrower = Open-LeaseBorrower -Caller $caller -Frames $frames -RunnerRoot $canonicalRunner -TargetRoot $canonicalTarget
  if ($borrower) { return $borrower }
  return (New-LeaseOwner -Caller $caller -Frames $frames -RunnerRoot $canonicalRunner -TargetRoot $canonicalTarget -ControlFiles $ControlFiles -ClosureRoots $ClosureRoots -MaximumItems $MaximumItems)
}

function Close-ProfileExecutionLease {
  [CmdletBinding()]
  param([Parameter(Mandatory)]$Lease)

  $record = $null
  $closed = $null
  [System.Threading.Monitor]::Enter($script:LeaseGate)
  try {
    if ($script:ClosedMembership.TryGetValue($Lease,[ref]$closed)) { return }
    if (-not $script:LeaseMembership.TryGetValue($Lease,[ref]$record)) { throw 'Execution lease identity is not registered.' }
    $frames = @(Get-LeaseCallerFrames)
    if ($frames.Count -eq 0) { throw 'Execution lease disposal caller identity is unavailable.' }
    $callerPath = [IO.Path]::GetFullPath([string]$frames[0].ScriptName)
    if (-not [string]::Equals($callerPath, $record.OwnerScriptPath, (Get-LeasePathComparison))) {
      throw 'Only the registered lease owner or borrower invocation may dispose this lease identity.'
    }
    [void]$script:LeaseMembership.Remove($Lease)
    $script:ClosedMembership.Add($Lease,[object]::new())
    $record.Disposed = $true
    if ($record.Kind -eq 'ProfileOwner') { [void]$script:ActiveProfileOwners.Remove($record) }
  } finally { [System.Threading.Monitor]::Exit($script:LeaseGate) }
  if ($record.Kind -ne 'Borrower') { Close-LeaseStreams -Record $record }
}

function Get-ProfileExecutionLeaseInfo {
  [CmdletBinding()]
  param([Parameter(Mandatory)]$Lease)

  $record = Get-LeaseRecord -Lease $Lease
  $itemCount = if ($record.PSObject.Properties['ItemCount']) { $record.ItemCount } else { 0 }
  return [pscustomobject]@{
    Kind = $record.Kind
    RunnerRoot = $record.RunnerRoot
    TargetRoot = $record.TargetRoot
    StreamCount = $record.Streams.Count
    ItemCount = $itemCount
  }
}

Export-ModuleMember -Function Open-ProfileExecutionLease,Close-ProfileExecutionLease,Get-ProfileExecutionLeaseInfo
