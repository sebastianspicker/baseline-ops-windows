#requires -version 5.1
<#
.SYNOPSIS
Copy an explicitly pinned repository commit into C:\install\mdm\ps1\.

.DESCRIPTION
Creates a fresh, policy-constrained clone and transactionally replaces the
deployed scripts/ and lib/ directories. Existing clones are never executed or
updated in place.

.PARAMETER RepoUrl
Git repository URL to pull from.

.PARAMETER DestinationRoot
Destination root (default: C:\install\mdm\ps1).

.PARAMETER RepoPath
Optional path within the fixed protected staging root. Existing paths are
refused; a fresh clone is never reused or removed in place.

.PARAMETER RepoRef
Required for non-WhatIf synchronization: a full 40- or 64-character commit
identifier obtained from authenticated release provenance. Branches, tags, and
mutable remote defaults are refused.

.PARAMETER GitPath
Optional absolute path to a trusted Git executable. On Windows, the default is
resolved only from the standard Program Files Git installation directories.

.EXAMPLE
$SourceCommit = '<verified 40-character release commit>'
.\00-Copy-Local.ps1 -RepoRef $SourceCommit

.EXAMPLE
$SourceCommit = '<verified 40-character release commit>'
.\00-Copy-Local.ps1 -RepoRef $SourceCommit -DestinationRoot D:\mdm\ps1

.EXAMPLE
$SourceCommit = '<verified 40-character release commit>'
.\00-Copy-Local.ps1 -RepoUrl https://github.com/sebastianspicker/baseline-ops.git -RepoRef $SourceCommit
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
  [string]$RepoUrl = 'https://github.com/sebastianspicker/baseline-ops.git',
  [string]$DestinationRoot = 'C:\install\mdm\ps1',
  [string]$RepoPath,
  [string]$RepoRef,
  [string]$GitPath,
  [ValidateSet('Audit','Remediate')][string]$Mode = 'Audit',
  [string]$ConfigPath,
  [ValidateSet('Console','Json','Csv','None')][string]$OutputFormat = 'Console',
  [string]$OutputPath,
  [switch]$PassThru,
  [switch]$Strict,
  [switch]$Quiet,
  [switch]$NoColor
)

function Assert-CopyLocalBootstrapPathTrust {
  [CmdletBinding()]
  param([Parameter(Mandatory)][string]$Path, [switch]$CheckAncestors)
  $trustedSids = @{
    'S-1-5-18' = $true; 'S-1-5-32-544' = $true
    'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464' = $true
  }
  $writeMask = [Security.AccessControl.FileSystemRights]::WriteData -bor [Security.AccessControl.FileSystemRights]::AppendData -bor
    [Security.AccessControl.FileSystemRights]::WriteExtendedAttributes -bor [Security.AccessControl.FileSystemRights]::WriteAttributes -bor
    [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor [Security.AccessControl.FileSystemRights]::Delete -bor
    [Security.AccessControl.FileSystemRights]::ChangePermissions -bor [Security.AccessControl.FileSystemRights]::TakeOwnership
  $replaceMask = [Security.AccessControl.FileSystemRights]::Delete -bor [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor
    [Security.AccessControl.FileSystemRights]::ChangePermissions -bor [Security.AccessControl.FileSystemRights]::TakeOwnership
  $current = (Microsoft.PowerShell.Management\Get-Item -LiteralPath $Path -Force -ErrorAction Stop).FullName; $isLeaf = $true
  while (-not [string]::IsNullOrWhiteSpace($current)) {
    $item = Microsoft.PowerShell.Management\Get-Item -LiteralPath $current -Force -ErrorAction Stop
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw "CopyLocal bootstrap path contains a reparse point: $current" }
    if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) {
      $acl = Microsoft.PowerShell.Security\Get-Acl -LiteralPath $item.FullName -ErrorAction Stop
      $ownerSid = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
      if (-not $trustedSids.ContainsKey($ownerSid)) { throw "CopyLocal bootstrap path has an untrusted owner SID: $current" }
      $effectiveMask = if ($isLeaf) { $writeMask } else { $replaceMask }
      foreach ($rule in @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))) {
        if ($rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or
            ($rule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) -ne 0) { continue }
        if (-not $trustedSids.ContainsKey([string]$rule.IdentityReference.Value) -and
            ([int64]$rule.FileSystemRights -band [int64]$effectiveMask) -ne 0) { throw "CopyLocal bootstrap path grants write/replace rights to an untrusted SID: $current" }
      }
    }
    if (-not $CheckAncestors) { break }
    $parentInfo = [IO.Directory]::GetParent($item.FullName)
    if ($null -eq $parentInfo) { break }
    $parent = $parentInfo.FullName
    $current = $parent; $isLeaf = $false
  }
}

$copyLocalRoot = [IO.Directory]::GetParent([IO.Path]::GetFullPath($PSScriptRoot)).FullName
$copyLocalBootstrapLocks = [Collections.Generic.List[IO.FileStream]]::new()
$copyLocalBootstrapPath = [IO.Path]::Combine($PSScriptRoot, '_lib', 'Bootstrap.ps1')
$copyLocalCommonPath = [IO.Path]::Combine($copyLocalRoot, 'lib', 'Common.psm1')
$copyLocalOutputPath = [IO.Path]::Combine($copyLocalRoot, 'lib', 'Output.psm1')
$copyLocalValidationPath = [IO.Path]::Combine($copyLocalRoot, 'lib', 'Validation.psm1')
$copyLocalSerializationPath = [IO.Path]::Combine($copyLocalRoot, 'lib', 'Serialization.psm1')
$copyLocalExternalPath = [IO.Path]::Combine($copyLocalRoot, 'lib', 'External.psm1')
$copyLocalHelperPath = [IO.Path]::Combine($PSScriptRoot, 'internal', '00-Copy-Local.helpers.ps1')
$copyLocalBootstrapPaths = @(
  $PSCommandPath, $copyLocalBootstrapPath, $copyLocalCommonPath, $copyLocalOutputPath,
  $copyLocalValidationPath, $copyLocalSerializationPath, $copyLocalExternalPath, $copyLocalHelperPath
)
try {
  foreach ($bootstrapPath in $copyLocalBootstrapPaths) {
    $stream = [IO.File]::Open($bootstrapPath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    try { Assert-CopyLocalBootstrapPathTrust -Path $bootstrapPath -CheckAncestors; [void]$copyLocalBootstrapLocks.Add($stream); $stream = $null }
    finally { if ($null -ne $stream) { $stream.Dispose() } }
  }
  . $copyLocalBootstrapPath
  Microsoft.PowerShell.Core\Import-Module $copyLocalCommonPath -Force -Global -DisableNameChecking
  Microsoft.PowerShell.Core\Import-Module $copyLocalOutputPath -Force
  Microsoft.PowerShell.Core\Import-Module $copyLocalValidationPath -Force
  Microsoft.PowerShell.Core\Import-Module $copyLocalSerializationPath -Force
  Microsoft.PowerShell.Core\Import-Module $copyLocalExternalPath -Force -DisableNameChecking
  . $copyLocalHelperPath
} finally {
  # Every closure member is fully parsed into this runspace at this point.
  # Release source handles before a same-root transaction renames scripts/lib.
  foreach ($bootstrapLock in $copyLocalBootstrapLocks) { $bootstrapLock.Dispose() }
}

Set-StrictMode -Version Latest
# v2-init (migrated to Initialize-V2Context)
$script:__V2Context = Initialize-V2Context -ScriptName '00-Copy-Local.ps1' -BoundParameters $PSBoundParameters `
  -Mode $Mode -ConfigPath $ConfigPath -OutputFormat $OutputFormat -OutputPath $OutputPath `
  -PassThru:$PassThru -Strict:$Strict -Quiet:$Quiet -NoColor:$NoColor
if ($script:__V2Context.Quiet) { $InformationPreference = 'SilentlyContinue'; $VerbosePreference = 'SilentlyContinue' }
$script:NoColor = [bool]$script:__V2Context.NoColor
$ErrorActionPreference = 'Stop'
$gitExecutableLock = $null
$hooksPath = $null
$deployStage = $null
$stagingRoot = $null
$clonePath = $null
$destinationLock = $null
$destinationCreatedPaths = New-Object System.Collections.Generic.List[string]
$deploymentCommitted = $false
$rollbackResidue = @()
$gitEnvironmentSnapshot = New-Object System.Collections.Generic.List[object]
$gitEnvironmentActive = $false
try {
# Validate deployment parameters to prevent option injection and unsafe paths.
if ($RepoUrl -match '^\s*-') {
  throw 'RepoUrl must not start with "-" or leading whitespace (option injection prevention).'
}
if (-not [string]::IsNullOrWhiteSpace($RepoPath) -and $RepoPath -match '^\s*-') {
  throw 'RepoPath must not start with "-" or leading whitespace (option injection prevention).'
}
if (-not [string]::IsNullOrWhiteSpace($RepoRef) -and $RepoRef -match '^\s*-') {
  throw 'RepoRef must not start with "-" or leading whitespace (option injection prevention).'
}
if (-not [string]::IsNullOrWhiteSpace($RepoRef) -and
    $RepoRef -notmatch '^[a-fA-F0-9]{40}([a-fA-F0-9]{24})?$') {
  throw 'RepoRef must be a full 40- or 64-character commit identifier; branches and tags are not accepted.'
}
if (-not [string]::IsNullOrWhiteSpace($RepoRef) -and -not (Test-ValidGitRef -Ref $RepoRef)) {
  throw "RepoRef '$RepoRef' is not a valid git ref (contains invalid characters or patterns)."
}
$destRootFull = [System.IO.Path]::GetFullPath($DestinationRoot)
$destVolumeRoot = [System.IO.Path]::GetPathRoot($destRootFull)
$separatorChars = @([System.IO.Path]::DirectorySeparatorChar, [System.IO.Path]::AltDirectorySeparatorChar)
$destRootNormalized = $destRootFull.TrimEnd($separatorChars)
$destVolumeNormalized = $destVolumeRoot.TrimEnd($separatorChars)
if ([string]::IsNullOrWhiteSpace($destVolumeRoot) -or $destRootNormalized -eq $destVolumeNormalized) {
  throw 'DestinationRoot must be a subdirectory, not a volume root (e.g. use C:\install\mdm\ps1 not C:\).'
}
function Get-CopyLocalStagingRoot {
  [CmdletBinding()]
  [OutputType([string])]
  param()
  if ([Environment]::OSVersion.Platform -eq [System.PlatformID]::Win32NT) {
    $commonApplicationData = [Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)
    if ([string]::IsNullOrWhiteSpace($commonApplicationData)) {
      throw 'The system CommonApplicationData directory could not be resolved for trusted staging.'
    }
    return (Join-Path $commonApplicationData 'BaselineOpsForWindows\CopyLocalStaging')
  }
  # Non-Windows hosts are used only for parser/Pester coverage of this Windows
  # deployment script. The Windows ACL policy below remains mandatory there.
  $temporaryRoot = [System.IO.Path]::GetTempPath()
  if (Test-Path -LiteralPath $temporaryRoot -PathType Container) {
    $temporaryRoot = (Resolve-Path -LiteralPath $temporaryRoot -ErrorAction Stop).ProviderPath
  }
  return (Join-Path $temporaryRoot 'baselineops-windows-copy-local-staging')
}
function Set-CopyLocalStagingAcl {
  [CmdletBinding(SupportsShouldProcess = $true)]
  param([Parameter(Mandatory)][string]$Path)
  if ([Environment]::OSVersion.Platform -ne [System.PlatformID]::Win32NT) { return }
  if (-not $PSCmdlet.ShouldProcess($Path, 'Restrict trusted staging directory ACL to Administrators and SYSTEM')) {
    throw 'Trusted staging root ACL configuration was declined.'
  }
  $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
  $acl.SetAccessRuleProtection($true, $false)
  $inheritance = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
    [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
  $propagation = [System.Security.AccessControl.PropagationFlags]::None
  foreach ($sid in @('S-1-5-18', 'S-1-5-32-544')) {
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
      (New-Object System.Security.Principal.SecurityIdentifier($sid)),
      [System.Security.AccessControl.FileSystemRights]::FullControl,
      $inheritance,
      $propagation,
      [System.Security.AccessControl.AccessControlType]::Allow)
    [void]$acl.AddAccessRule($rule)
  }
  Set-Acl -LiteralPath $Path -AclObject $acl -ErrorAction Stop
  $verified = Get-Acl -LiteralPath $Path -ErrorAction Stop
  if (-not $verified.AreAccessRulesProtected) {
    throw 'Trusted staging root ACL inheritance could not be disabled.'
  }
  $rules = @($verified.GetAccessRules($true, $false, [System.Security.Principal.SecurityIdentifier]))
  $allowedSids = @('S-1-5-18', 'S-1-5-32-544')
  if ($rules.Count -ne 2 -or @($rules | Where-Object {
        -not $_.AccessControlType.Equals([System.Security.AccessControl.AccessControlType]::Allow) -or
        -not $_.FileSystemRights.HasFlag([System.Security.AccessControl.FileSystemRights]::FullControl) -or
        $allowedSids -notcontains $_.IdentityReference.Value
      }).Count -ne 0) {
    throw 'Trusted staging root ACL is not restricted to Administrators and SYSTEM.'
  }
}
function Initialize-CopyLocalStagingRoot {
  [CmdletBinding()]
  [OutputType([string])]
  param()
  $root = Get-CopyLocalStagingRoot
  $parent = Split-Path -Path $root -Parent
  $trustedBase = Split-Path -Path $parent -Parent
  if (-not (Test-Path -LiteralPath $trustedBase -PathType Container)) {
    throw 'Trusted staging root base does not exist.'
  }
  $baseResolved = (Resolve-Path -LiteralPath $trustedBase -ErrorAction Stop).ProviderPath
  $baseVolume = [System.IO.Path]::GetPathRoot($baseResolved)
  if (Test-PathContainsReparsePoint -Path $baseResolved -Root $baseVolume) {
    throw 'Trusted staging root parent contains a reparse point.'
  }
  if (-not (Test-Path -LiteralPath $parent)) {
    [void][System.IO.Directory]::CreateDirectory($parent)
  }
  $parentResolved = (Resolve-Path -LiteralPath $parent -ErrorAction Stop).ProviderPath
  if (-not (Test-PathUnderRoot -Path $parentResolved -Root $baseResolved) -or
      (Test-PathContainsReparsePoint -Path $parentResolved -Root $baseResolved)) {
    throw 'Trusted staging root parent contains a reparse point.'
  }
  Set-CopyLocalStagingAcl -Path $parentResolved
  if (-not (Test-Path -LiteralPath $root)) {
    [void][System.IO.Directory]::CreateDirectory($root)
  }
  $resolved = (Resolve-Path -LiteralPath $root -ErrorAction Stop).ProviderPath
  if (-not (Test-PathUnderRoot -Path $resolved -Root $parentResolved)) {
    throw 'Trusted staging root is outside its fixed parent.'
  }
  if (Test-PathContainsReparsePoint -Path $resolved -Root $parentResolved) {
    throw 'Trusted staging root contains a reparse point.'
  }
  Set-CopyLocalStagingAcl -Path $resolved
  return $resolved
}
function Get-CopyLocalDestinationLockPath {
  [CmdletBinding()]
  [OutputType([string])]
  param(
    [Parameter(Mandatory)][string]$DestinationRoot,
    [Parameter(Mandatory)][string]$StagingRoot
  )
  $canonicalDestination = [System.IO.Path]::GetFullPath($DestinationRoot).TrimEnd(
    [System.IO.Path]::DirectorySeparatorChar,
    [System.IO.Path]::AltDirectorySeparatorChar)
  if ([Environment]::OSVersion.Platform -eq [System.PlatformID]::Win32NT) {
    $canonicalDestination = $canonicalDestination.ToUpperInvariant()
  }
  $sha256 = [System.Security.Cryptography.SHA256]::Create()
  try {
    $digest = $sha256.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($canonicalDestination))
  } finally {
    $sha256.Dispose()
  }
  $identity = -join @($digest | ForEach-Object { $_.ToString('x2') })
  return (Join-Path $StagingRoot ('.destination-{0}.lock' -f $identity))
}
function Enter-CopyLocalDestinationLock {
  [CmdletBinding()]
  [OutputType([System.IO.FileStream])]
  param(
    [Parameter(Mandatory)][string]$DestinationRoot,
    [Parameter(Mandatory)][string]$StagingRoot
  )
  $lockPath = Get-CopyLocalDestinationLockPath -DestinationRoot $DestinationRoot -StagingRoot $StagingRoot
  try {
    return [System.IO.File]::Open(
      $lockPath,
      [System.IO.FileMode]::OpenOrCreate,
      [System.IO.FileAccess]::ReadWrite,
      [System.IO.FileShare]::None)
  } catch {
    throw 'Another CopyLocal deployment is already active for this destination; no deployment changes were made.'
  }
}
function Get-CopyLocalTrustedWriterSid {
  [CmdletBinding()]
  [OutputType([string[]])]
  param()
  return @(
    'S-1-5-18',        # LocalSystem
    'S-1-5-32-544',    # BUILTIN\Administrators
    'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464' # TrustedInstaller
  )
}
function Assert-CopyLocalAclObjectTrust {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]$Acl,
    [Parameter(Mandatory)][string]$Path,
    [string]$BoundaryLabel = 'Destination',
    [switch]$ReplacementOnly,
    [switch]$RequireProtected
  )
  $trustedSids = @(Get-CopyLocalTrustedWriterSid)
  $ownerSid = $Acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value
  if ($trustedSids -notcontains $ownerSid) {
    throw "$BoundaryLabel ACL owner '$ownerSid' is not trusted at '$Path'."
  }
  if ($RequireProtected -and -not $Acl.AreAccessRulesProtected) {
    throw "$BoundaryLabel ACL inheritance is not protected at '$Path'."
  }
  $writeMask = [System.Security.AccessControl.FileSystemRights]::Delete -bor
    [System.Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor
    [System.Security.AccessControl.FileSystemRights]::ChangePermissions -bor
    [System.Security.AccessControl.FileSystemRights]::TakeOwnership
  if (-not $ReplacementOnly) {
    $writeMask = $writeMask -bor [System.Security.AccessControl.FileSystemRights]::Write
  }
  $rules = @($Acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]))
  foreach ($rule in $rules) {
    if ($rule.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) { continue }
    if (($rule.PropagationFlags -band [System.Security.AccessControl.PropagationFlags]::InheritOnly) -ne 0) { continue }
    if (([int64]$rule.FileSystemRights -band [int64]$writeMask) -eq 0) { continue }
    $writerSid = $rule.IdentityReference.Value
    if ($trustedSids -notcontains $writerSid) {
      $rightKind = if ($ReplacementOnly) { 'replacement-capable' } else { 'write-capable' }
      throw "$BoundaryLabel ACL grants $rightKind access to untrusted SID '$writerSid' at '$Path'."
    }
  }
}
function Assert-CopyLocalDestinationAclTrust {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Path,
    [switch]$RequireProtected
  )
  if ([Environment]::OSVersion.Platform -ne [System.PlatformID]::Win32NT) { return }
  $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
  Assert-CopyLocalAclObjectTrust -Acl $acl -Path $Path -RequireProtected:$RequireProtected
}
function Assert-CopyLocalAncestorChainTrust {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Path,
    [string]$BoundaryLabel = 'Destination'
  )
  if ([Environment]::OSVersion.Platform -ne [System.PlatformID]::Win32NT) { return }
  $resolved = (Resolve-Path -LiteralPath $Path -ErrorAction Stop).ProviderPath
  $volume = [System.IO.Path]::GetPathRoot($resolved)
  if (Test-PathContainsReparsePoint -Path $resolved -Root $volume) {
    throw "$BoundaryLabel path or one of its ancestors is a reparse point."
  }
  $ancestor = Split-Path -Path $resolved -Parent
  while (-not [string]::IsNullOrWhiteSpace($ancestor)) {
    $acl = Get-Acl -LiteralPath $ancestor -ErrorAction Stop
    Assert-CopyLocalAclObjectTrust -Acl $acl -Path $ancestor `
      -BoundaryLabel "$BoundaryLabel ancestor" -ReplacementOnly
    if ([string]::Equals($ancestor.TrimEnd('\'), $volume.TrimEnd('\'), [System.StringComparison]::OrdinalIgnoreCase)) {
      break
    }
    $parent = Split-Path -Path $ancestor -Parent
    if ([string]::Equals($parent, $ancestor, [System.StringComparison]::OrdinalIgnoreCase)) { break }
    $ancestor = $parent
  }
}
function Protect-CopyLocalDestinationAcl {
  [CmdletBinding()]
  param([Parameter(Mandatory)][string]$Path)
  if ([Environment]::OSVersion.Platform -ne [System.PlatformID]::Win32NT) { return }
  $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
  Assert-CopyLocalAclObjectTrust -Acl $acl -Path $Path
  if (-not $acl.AreAccessRulesProtected) {
    # Preserve currently safe read/execute ACEs as explicit entries while
    # preventing a later parent ACL change from introducing new writers.
    $acl.SetAccessRuleProtection($true, $true)
    Set-Acl -LiteralPath $Path -AclObject $acl -ErrorAction Stop
  }
  Assert-CopyLocalDestinationAclTrust -Path $Path -RequireProtected
}
function Set-CopyLocalNewDestinationAcl {
  [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'None')]
  param([Parameter(Mandatory)][string]$Path)
  if ([Environment]::OSVersion.Platform -ne [System.PlatformID]::Win32NT) { return }
  if (-not $PSCmdlet.ShouldProcess($Path, 'Apply protected Administrators and SYSTEM destination ACL')) {
    throw 'New destination ACL configuration was declined.'
  }
  $acl = New-Object System.Security.AccessControl.DirectorySecurity
  $acl.SetAccessRuleProtection($true, $false)
  $administrators = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')
  $acl.SetOwner($administrators)
  $inheritance = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
    [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
  foreach ($sidValue in @('S-1-5-18', 'S-1-5-32-544')) {
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
      (New-Object System.Security.Principal.SecurityIdentifier($sidValue)),
      [System.Security.AccessControl.FileSystemRights]::FullControl,
      $inheritance,
      [System.Security.AccessControl.PropagationFlags]::None,
      [System.Security.AccessControl.AccessControlType]::Allow)
    [void]$acl.AddAccessRule($rule)
  }
  Set-Acl -LiteralPath $Path -AclObject $acl -ErrorAction Stop
  Assert-CopyLocalDestinationAclTrust -Path $Path -RequireProtected
}
function Initialize-CopyLocalDestinationRoot {
  [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'None')]
  param(
    [Parameter(Mandatory)][string]$DestinationRoot,
    [Parameter(Mandatory)][AllowEmptyCollection()][System.Collections.Generic.List[string]]$CreatedPaths
  )
  $destinationFull = [System.IO.Path]::GetFullPath($DestinationRoot)
  $missing = New-Object System.Collections.Generic.List[string]
  $existingAncestor = $destinationFull
  while (-not (Test-Path -LiteralPath $existingAncestor -PathType Container)) {
    [void]$missing.Add($existingAncestor)
    $parent = Split-Path -Path $existingAncestor -Parent
    if ([string]::IsNullOrWhiteSpace($parent) -or $parent -eq $existingAncestor) {
      throw 'DestinationRoot has no existing parent directory that can be validated.'
    }
    $existingAncestor = $parent
  }
  $existingResolved = (Resolve-Path -LiteralPath $existingAncestor -ErrorAction Stop).ProviderPath
  $existingVolume = [System.IO.Path]::GetPathRoot($existingResolved)
  if (Test-PathContainsReparsePoint -Path $existingResolved -Root $existingVolume) {
    throw 'The nearest existing DestinationRoot ancestor contains a reparse point.'
  }
  if ([Environment]::OSVersion.Platform -eq [System.PlatformID]::Win32NT) {
    $parentAcl = Get-Acl -LiteralPath $existingResolved -ErrorAction Stop
    # The nearest existing parent must also reject create/write access so an
    # untrusted identity cannot win the create-before-protect race.
    Assert-CopyLocalAclObjectTrust -Acl $parentAcl -Path $existingResolved -BoundaryLabel 'Destination parent'
    Assert-CopyLocalAncestorChainTrust -Path $existingResolved -BoundaryLabel 'Destination parent'
  }
  for ($index = $missing.Count - 1; $index -ge 0; $index--) {
    $path = $missing[$index]
    if (-not $PSCmdlet.ShouldProcess($path, 'Create and protect destination directory')) {
      throw 'New destination directory creation was declined.'
    }
    [void][System.IO.Directory]::CreateDirectory($path)
    [void]$CreatedPaths.Add($path)
    Set-CopyLocalNewDestinationAcl -Path $path -Confirm:$false
    $resolved = (Resolve-Path -LiteralPath $path -ErrorAction Stop).ProviderPath
    if (Test-PathContainsReparsePoint -Path $resolved -Root $existingResolved) {
      throw 'A newly created destination directory contains a reparse point.'
    }
  }
}
function Remove-CopyLocalEmptyCreatedDirectory {
  [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'None')]
  param([Parameter(Mandatory)][AllowEmptyCollection()][System.Collections.Generic.List[string]]$CreatedPaths)
  for ($index = $CreatedPaths.Count - 1; $index -ge 0; $index--) {
    $path = $CreatedPaths[$index]
    try {
      if (-not (Test-Path -LiteralPath $path -PathType Container)) { continue }
      $item = Get-Item -LiteralPath $path -Force -ErrorAction Stop
      if ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) { continue }
      if (@(Get-ChildItem -LiteralPath $path -Force -ErrorAction Stop).Count -ne 0) { continue }
      if ($PSCmdlet.ShouldProcess($path, 'Remove empty destination directory created by failed deployment')) {
        Remove-Item -LiteralPath $path -Force -ErrorAction Stop
      }
    } catch {
      Write-Verbose "Empty created destination cleanup failed for '$path': $($_.Exception.Message)"
    }
  }
}
function Resolve-CopyLocalDestinationBoundary {
  [CmdletBinding()]
  [OutputType([string])]
  param([Parameter(Mandatory)][string]$DestinationRoot)
  $resolved = (Resolve-Path -LiteralPath $DestinationRoot -ErrorAction Stop).ProviderPath
  $volume = [System.IO.Path]::GetPathRoot($resolved)
  if (Test-PathContainsReparsePoint -Path $resolved -Root $volume) {
    throw 'DestinationRoot or one of its ancestors is a reparse point.'
  }
  foreach ($name in @('scripts', 'lib')) {
    $target = Join-Path $resolved $name
    if ((Test-Path -LiteralPath $target) -and
        (Test-PathContainsReparsePoint -Path $target -Root $resolved)) {
      throw "Existing deployment target '$name' contains a reparse point; refusing to move or delete it."
    }
  }
  Assert-CopyLocalDestinationAclTrust -Path $resolved
  Assert-CopyLocalAncestorChainTrust -Path $resolved -BoundaryLabel 'Destination'
  foreach ($name in @('scripts', 'lib')) {
    $target = Join-Path $resolved $name
    if (Test-Path -LiteralPath $target -PathType Container) {
      Assert-CopyLocalDestinationAclTrust -Path $target
    }
  }
  return $resolved
}
# A clone path in a deployed tree would collide with transactional replacement.
# This is never safe.
if (-not [string]::IsNullOrWhiteSpace($RepoPath) -and
    (Test-RepoPathOverlapsDeploymentTarget -RepoPath $RepoPath -DestinationRoot $DestinationRoot)) {
  throw 'RepoPath must not equal or be contained by DestinationRoot\\scripts or DestinationRoot\\lib.'
}
if (-not $PSCmdlet.ShouldProcess($DestinationRoot, 'Synchronize repository content into the deployment root')) {
  $resultToken = 'WARN'
  if ($Strict) { $resultToken = 'FAIL' }
  $v2Result = Get-V2ResultObject `
    -ScriptName '00-Copy-Local.ps1' `
    -Mode $Mode `
    -Result $resultToken `
    -Findings @([pscustomobject]@{
        Code = 'COPY-LOCAL-EXECUTION-SKIPPED'
        Severity = 'Info'
        Message = 'Repository synchronization was skipped by WhatIf or confirmation.'
      }) `
    -Summary ([pscustomobject]@{ DestinationRoot = $DestinationRoot; RepoPath = $RepoPath; Executed = $false }) `
    -Metadata @{}
  Write-ResultObject -ResultObject $v2Result -OutputFormat $OutputFormat -OutputPath $OutputPath
  if ($PassThru) { $v2Result }
  exit (Get-V2ExitCode -Result $resultToken)
}
if ([string]::IsNullOrWhiteSpace($RepoRef)) {
  throw 'RepoRef is required and must be the full commit identifier from authenticated release provenance.'
}
# Reject an unsafe existing destination before creating staging or changing any
# destination ACL. This is repeated under the destination lock below.
if (Test-Path -LiteralPath $DestinationRoot) {
  [void](Resolve-CopyLocalDestinationBoundary -DestinationRoot $DestinationRoot)
}
$stagingRoot = Initialize-CopyLocalStagingRoot
$destinationLock = Enter-CopyLocalDestinationLock -DestinationRoot $DestinationRoot -StagingRoot $stagingRoot
if (-not (Test-Path -LiteralPath $DestinationRoot)) {
  Initialize-CopyLocalDestinationRoot -DestinationRoot $DestinationRoot `
    -CreatedPaths $destinationCreatedPaths -Confirm:$false
}
$destinationResolved = Resolve-CopyLocalDestinationBoundary -DestinationRoot $DestinationRoot
$destinationVolume = [System.IO.Path]::GetPathRoot($destinationResolved)
Protect-CopyLocalDestinationAcl -Path $destinationResolved
if ([string]::IsNullOrWhiteSpace($RepoPath)) {
  $RepoPath = Join-Path $stagingRoot ('clone-{0}' -f [guid]::NewGuid().ToString('N'))
} else {
  $repoPathFull = Get-FullPath -Path $RepoPath
  if (-not (Test-PathUnderRoot -Path $repoPathFull -Root $stagingRoot)) {
    throw 'RepoPath must be within the fixed trusted staging root.'
  }
  $RepoPath = $repoPathFull
}
if (Test-Path -LiteralPath $RepoPath) {
  throw 'RepoPath already exists; refusing to reuse or remove an existing clone.'
}
$clonePath = $RepoPath
$repoUri = $null
if (-not [System.Uri]::TryCreate($RepoUrl, [System.UriKind]::Absolute, [ref]$repoUri) -or
    $repoUri.Scheme -ne 'https' -or -not [string]::IsNullOrEmpty($repoUri.UserInfo)) {
  throw 'RepoUrl must be an absolute HTTPS URL without embedded credentials.'
}
$gitCandidate = $null
$explicitGitPath = -not [string]::IsNullOrWhiteSpace($GitPath)
if ($explicitGitPath) {
  if (-not [System.IO.Path]::IsPathRooted($GitPath)) { throw 'GitPath must be absolute.' }
  $gitCandidate = $GitPath
} elseif ($env:OS -eq 'Windows_NT') {
  $gitCandidate = Resolve-TrustedGitPath
} else {
  $gitCommand = Get-Command -Name git -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
  if ($gitCommand) { $gitCandidate = $gitCommand.Source }
}
if ([string]::IsNullOrWhiteSpace($gitCandidate) -or -not (Test-Path -LiteralPath $gitCandidate -PathType Leaf)) {
  throw 'Trusted Git executable not found. Install Git in Program Files or pass an absolute -GitPath.'
}
$script:GitExecutablePath = (Resolve-Path -LiteralPath $gitCandidate -ErrorAction Stop).ProviderPath
$gitVolume = [System.IO.Path]::GetPathRoot($script:GitExecutablePath)
if (Test-PathContainsReparsePoint -Path $script:GitExecutablePath -Root $gitVolume) {
  throw 'GitPath contains a reparse point.'
}
if ([Environment]::OSVersion.Platform -eq [System.PlatformID]::Win32NT) {
  $gitAcl = Get-Acl -LiteralPath $script:GitExecutablePath -ErrorAction Stop
  Assert-CopyLocalAclObjectTrust -Acl $gitAcl -Path $script:GitExecutablePath -BoundaryLabel 'Git executable'
  Assert-CopyLocalAncestorChainTrust -Path $script:GitExecutablePath -BoundaryLabel 'Git executable'
}
$gitExecutableLock = [System.IO.File]::Open($script:GitExecutablePath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
$gitEnvironmentActive = $true
Enable-CopyLocalSafeGitEnvironment -Snapshot $gitEnvironmentSnapshot
$hooksPath = Join-Path $stagingRoot ('.git-hooks-{0}' -f [guid]::NewGuid().ToString('N'))
[void][System.IO.Directory]::CreateDirectory($hooksPath)
$cloneArgs = @('clone', '--no-checkout')
$cloneArgs += @('--', $RepoUrl, $RepoPath)
Invoke-GitCommand -GitArgs $cloneArgs | Out-Null
$remoteResult = Invoke-GitCommand -GitArgs @('-C', $RepoPath, 'remote', 'get-url', 'origin')
$configuredRemote = $remoteResult.Stdout.Trim()
if (-not [string]::Equals($configuredRemote, $RepoUrl.Trim(), [System.StringComparison]::Ordinal)) {
  throw 'Fresh clone origin does not exactly match RepoUrl.'
}
$requestedRef = $RepoRef
$commitResult = Invoke-GitCommand -GitArgs @('-C', $RepoPath, 'rev-parse', '--verify', ("{0}^{{commit}}" -f $requestedRef)) -AllowFailure
if (-not $commitResult.Success) { throw "RepoRef could not be resolved to a commit: $requestedRef" }
$resolvedCommit = $commitResult.Stdout.Trim()
if ($resolvedCommit -notmatch '^[a-fA-F0-9]{40}([a-fA-F0-9]{24})?$') { throw 'Git did not resolve a valid commit object.' }
if (-not [string]::Equals($resolvedCommit, $RepoRef, [System.StringComparison]::OrdinalIgnoreCase)) {
  throw 'Resolved commit does not match the authenticated RepoRef.'
}
Invoke-GitCommand -GitArgs @('-C', $RepoPath, 'checkout', '--force', '--detach', $resolvedCommit, '--') | Out-Null
$statusResult = Invoke-GitCommand -GitArgs @('-C', $RepoPath, 'status', '--porcelain=v1', '-z', '--untracked-files=all', '--ignored=matching', '--', 'scripts', 'lib')
if (-not [string]::IsNullOrEmpty($statusResult.Stdout)) { throw 'Fresh clone scripts/lib worktree is not clean.' }
$sourceScripts = Join-Path $RepoPath 'scripts'
$sourceLib = Join-Path $RepoPath 'lib'
if (-not (Test-Path -LiteralPath $sourceScripts -PathType Container)) {
  throw "Source scripts folder not found after pull: $sourceScripts"
}
if (-not (Test-Path -LiteralPath $sourceLib -PathType Container)) {
  throw "Source lib folder not found after pull: $sourceLib"
}
$repoResolved = (Resolve-Path -LiteralPath $RepoPath -ErrorAction Stop).ProviderPath
if (Test-PathContainsReparsePoint -Path $repoResolved -Root $stagingRoot) { throw 'Fresh clone path contains a reparse point.' }
foreach ($item in Get-ChildItem -LiteralPath $sourceScripts,$sourceLib -Recurse -Force) {
  if ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
    throw "Fresh clone contains a reparse point: $($item.FullName)"
  }
}
$deployStage = Join-Path $stagingRoot ('.deploy-{0}' -f [guid]::NewGuid().ToString('N'))
[void][System.IO.Directory]::CreateDirectory($deployStage)
Copy-Item -LiteralPath $sourceScripts -Destination $deployStage -Recurse -Force
Copy-Item -LiteralPath $sourceLib -Destination $deployStage -Recurse -Force
# Revalidate the destination boundary immediately before the commit. The
# destination lock serializes cooperating CopyLocal processes; the ACL and
# reparse checks reject changes by identities outside the trusted writer set.
if (Test-PathContainsReparsePoint -Path $destinationResolved -Root $destinationVolume) {
  throw 'DestinationRoot or one of its ancestors became a reparse point before deployment.'
}
Assert-CopyLocalDestinationAclTrust -Path $destinationResolved -RequireProtected
foreach ($name in @('scripts', 'lib')) {
  $deploymentTarget = Join-Path $destinationResolved $name
  if (-not (Test-Path -LiteralPath $deploymentTarget)) { continue }
  if (Test-PathContainsReparsePoint -Path $deploymentTarget -Root $destinationResolved) {
    throw "Existing deployment target '$name' became a reparse point before deployment."
  }
  Assert-CopyLocalDestinationAclTrust -Path $deploymentTarget
}
$swaps = New-Object System.Collections.Generic.List[object]
try {
  foreach ($name in @('scripts','lib')) {
    $target = Join-Path $destinationResolved $name
    $incoming = Join-Path $deployStage $name
    $backup = Join-Path $destinationResolved ('.{0}.previous-{1}' -f $name,[guid]::NewGuid().ToString('N'))
    $hadExisting = Test-Path -LiteralPath $target
    if ($hadExisting) { Move-Item -LiteralPath $target -Destination $backup -ErrorAction Stop }
    [void]$swaps.Add([pscustomobject]@{ Target = $target; Backup = $backup; HadExisting = $hadExisting; Installed = $false })
    Move-Item -LiteralPath $incoming -Destination $target -ErrorAction Stop
    $swaps[$swaps.Count - 1].Installed = $true
  }
  foreach ($name in @('scripts', 'lib')) {
    $target = Join-Path $destinationResolved $name
    if (-not (Test-Path -LiteralPath $target -PathType Container)) {
      throw "Committed deployment target '$name' is missing."
    }
    if (Test-PathContainsReparsePoint -Path $target -Root $destinationResolved) {
      throw "Committed deployment target '$name' contains a reparse point."
    }
    Protect-CopyLocalDestinationAcl -Path $target
  }
  Assert-CopyLocalDestinationAclTrust -Path $destinationResolved -RequireProtected
  Assert-CopyLocalAncestorChainTrust -Path $destinationResolved -BoundaryLabel 'Destination'
} catch {
  $swapError = $_
  $rollbackResidue = @(Restore-CopyLocalDeploymentSwaps -Swaps $swaps)
  if ($rollbackResidue.Count -gt 0) {
    throw [System.InvalidOperationException]::new(
      ("Deployment swap failed: {0} Rollback residue was retained; inspect the terminal result RollbackResidue data." -f $swapError.Exception.Message),
      $swapError.Exception)
  }
  throw $swapError
}
$deploymentCommitted = $true
$backupResidue = @(Remove-CopyLocalCommittedBackup -Swaps $swaps)
$findings = @()
$resultToken = 'OK'
if ($backupResidue.Count -gt 0) {
  $resultToken = if ($Strict) { 'FAIL' } else { 'WARN' }
  $findings = @([pscustomobject]@{
      Code = 'COPY-LOCAL-BACKUP-CLEANUP-RESIDUE'
      Severity = 'Medium'
      Message = 'Deployment committed successfully, but one or more previous-version backup directories could not be removed.'
      Data = [pscustomobject]@{ Residue = $backupResidue }
    })
}
Write-UiLine "Installed scripts/ and lib/ from commit $resolvedCommit to $DestinationRoot"
$v2Result = Get-V2ResultObject `
  -ScriptName '00-Copy-Local.ps1' `
  -Mode $Mode `
  -Result $resultToken `
  -Findings $findings `
  -Summary ([pscustomobject]@{
      DestinationRoot = $DestinationRoot
      RepoPath = $RepoPath
      RepoRef = $RepoRef
      Commit = $resolvedCommit
      DeploymentCommitted = $true
      BackupResidue = $backupResidue
    }) `
  -Metadata @{}
Write-ResultObject -ResultObject $v2Result -OutputFormat $OutputFormat -OutputPath $OutputPath
if ($PassThru) { $v2Result }
exit (Get-V2ExitCode -Result $resultToken)
} catch {
  $errorMessage = $_.Exception.Message
  $resultToken = 'FAIL'
  $failureFindings = New-Object System.Collections.Generic.List[object]
  [void]$failureFindings.Add([pscustomobject]@{
      Code = 'COPY-LOCAL-TERMINAL-FAIL'
      Severity = 'High'
      Message = $errorMessage
    })
  if ($rollbackResidue.Count -gt 0) {
    [void]$failureFindings.Add([pscustomobject]@{
        Code = 'COPY-LOCAL-DEPLOYMENT-ROLLBACK-RESIDUE'
        Severity = 'High'
        Message = 'Deployment rollback could not prove every target invariant; affected targets and retained backups are recorded in Data.'
        Data = [pscustomobject]@{ RollbackResidue = $rollbackResidue }
      })
  }
  $v2Result = Get-V2ResultObject `
    -ScriptName '00-Copy-Local.ps1' `
    -Mode $Mode `
    -Result $resultToken `
    -Findings $failureFindings.ToArray() `
    -Summary ([pscustomobject]@{ Error = $errorMessage; RollbackResidue = $rollbackResidue }) `
    -Metadata @{}
  Write-ResultObject -ResultObject $v2Result -OutputFormat $OutputFormat -OutputPath $OutputPath
  if ($PassThru) { $v2Result }
  exit (Get-V2ExitCode -Result $resultToken)
} finally {
  if ($null -ne $gitExecutableLock) { $gitExecutableLock.Dispose() }
  if ($gitEnvironmentActive) {
    Restore-CopyLocalGitEnvironment -Snapshot $gitEnvironmentSnapshot
  }
  foreach ($path in @($deployStage,$hooksPath,$clonePath)) {
    if (-not [string]::IsNullOrWhiteSpace($path) -and (Test-Path -LiteralPath $path)) {
      Remove-Item -LiteralPath $path -Recurse -Force -ErrorAction SilentlyContinue
    }
  }
  if (-not $deploymentCommitted -and $destinationCreatedPaths.Count -gt 0) {
    Remove-CopyLocalEmptyCreatedDirectory -CreatedPaths $destinationCreatedPaths -Confirm:$false
  }
  if ($null -ne $destinationLock) { $destinationLock.Dispose() }
}
