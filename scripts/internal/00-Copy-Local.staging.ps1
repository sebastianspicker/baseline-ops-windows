#requires -version 5.1
<#
.SYNOPSIS
  Provides private transactional deployment phases.
.DESCRIPTION
  Preserves validated source acquisition, protected destination boundaries, commit recovery, and cleanup. The public bootstrap validates and retains every private file until its functions are loaded.
#>

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
function Assert-CopyLocalStagingAclRules {
  [CmdletBinding()]
  param([Parameter(Mandatory)]$Acl)

  if (-not $Acl.AreAccessRulesProtected) {
    throw 'Trusted staging root ACL inheritance could not be disabled.'
  }
  $rules = @($Acl.GetAccessRules($true, $false, [System.Security.Principal.SecurityIdentifier]))
  $allowedSids = @('S-1-5-18', 'S-1-5-32-544')
  $unexpectedRule = @($rules | Where-Object {
      -not $_.AccessControlType.Equals([System.Security.AccessControl.AccessControlType]::Allow) -or
      -not $_.FileSystemRights.HasFlag([System.Security.AccessControl.FileSystemRights]::FullControl) -or
      $allowedSids -notcontains $_.IdentityReference.Value
    }).Count -ne 0
  if ($rules.Count -ne 2 -or $unexpectedRule) {
    throw 'Trusted staging root ACL is not restricted to Administrators and SYSTEM.'
  }
}

function Set-CopyLocalStagingAcl {
  [CmdletBinding(SupportsShouldProcess = $true)]
  param([Parameter(Mandatory)][string]$Path)
  if ([Environment]::OSVersion.Platform -ne [System.PlatformID]::Win32NT) {
    return
  }
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
  Assert-CopyLocalStagingAclRules -Acl (Get-Acl -LiteralPath $Path -ErrorAction Stop)
}
function Assert-CopyLocalStagingPathTrust {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][string]$Root,
    [Parameter(Mandatory)][string]$OutsideRootMessage,
    [Parameter(Mandatory)][string]$ReparsePointMessage
  )

  if (-not (Test-PathUnderRoot -Path $Path -Root $Root)) {
    throw $OutsideRootMessage
  }
  if (Test-PathContainsReparsePoint -Path $Path -Root $Root) {
    throw $ReparsePointMessage
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
  Assert-CopyLocalStagingPathTrust -Path $parentResolved -Root $baseResolved `
    -OutsideRootMessage 'Trusted staging root parent contains a reparse point.' `
    -ReparsePointMessage 'Trusted staging root parent contains a reparse point.'
  Set-CopyLocalStagingAcl -Path $parentResolved
  if (-not (Test-Path -LiteralPath $root)) {
    [void][System.IO.Directory]::CreateDirectory($root)
  }
  $resolved = (Resolve-Path -LiteralPath $root -ErrorAction Stop).ProviderPath
  Assert-CopyLocalStagingPathTrust -Path $resolved -Root $parentResolved `
    -OutsideRootMessage 'Trusted staging root is outside its fixed parent.' `
    -ReparsePointMessage 'Trusted staging root contains a reparse point.'
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
  }
  finally {
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
  }
  catch {
    throw 'Another CopyLocal deployment is already active for this destination; no deployment changes were made.'
  }
}
