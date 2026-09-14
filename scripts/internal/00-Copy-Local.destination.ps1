#requires -version 5.1
<#
.SYNOPSIS
  Provides private transactional deployment phases.
.DESCRIPTION
  Preserves validated source acquisition, protected destination boundaries, commit recovery, and cleanup. The public bootstrap validates and retains every private file until its functions are loaded.
#>

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
function Get-CopyLocalAclWriteMask {
  [CmdletBinding()]
  [OutputType([System.Security.AccessControl.FileSystemRights])]
  param([switch]$ReplacementOnly)

  $mask = [System.Security.AccessControl.FileSystemRights]::Delete -bor [System.Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor [System.Security.AccessControl.FileSystemRights]::ChangePermissions -bor [System.Security.AccessControl.FileSystemRights]::TakeOwnership
  if (-not $ReplacementOnly) {
    $mask = $mask -bor [System.Security.AccessControl.FileSystemRights]::Write
  }
  return $mask
}

function Assert-CopyLocalAclWriterTrust {
  [CmdletBinding()]
  param([Parameter(Mandatory)]$Acl, [Parameter(Mandatory)][string[]]$TrustedSids, [Parameter(Mandatory)][int64]$WriteMask, [Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$BoundaryLabel, [switch]$ReplacementOnly)

  foreach ($rule in @($Acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]))) {
    $isEffectiveWriter = $rule.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Allow -and ($rule.PropagationFlags -band [System.Security.AccessControl.PropagationFlags]::InheritOnly) -eq 0 -and ([int64]$rule.FileSystemRights -band $WriteMask) -ne 0
    if ($isEffectiveWriter -and $TrustedSids -notcontains $rule.IdentityReference.Value) {
      $rightKind = if ($ReplacementOnly) {
        'replacement-capable'
      }
      else {
        'write-capable'
      }
      throw "$BoundaryLabel ACL grants $rightKind access to untrusted SID '$($rule.IdentityReference.Value)' at '$Path'."
    }
  }
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
  $writeMask = Get-CopyLocalAclWriteMask -ReplacementOnly:$ReplacementOnly
  Assert-CopyLocalAclWriterTrust -Acl $Acl -TrustedSids $trustedSids -WriteMask $writeMask `
    -Path $Path -BoundaryLabel $BoundaryLabel -ReplacementOnly:$ReplacementOnly
}
function Assert-CopyLocalDestinationAclTrust {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Path,
    [switch]$RequireProtected
  )
  if ([Environment]::OSVersion.Platform -ne [System.PlatformID]::Win32NT) {
    return
  }
  $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
  Assert-CopyLocalAclObjectTrust -Acl $acl -Path $Path -RequireProtected:$RequireProtected
}
function Assert-CopyLocalAncestorChainTrust {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Path,
    [string]$BoundaryLabel = 'Destination'
  )
  if ([Environment]::OSVersion.Platform -ne [System.PlatformID]::Win32NT) {
    return
  }
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
    if ([string]::Equals($parent, $ancestor, [System.StringComparison]::OrdinalIgnoreCase)) {
      break
    }
    $ancestor = $parent
  }
}
function Protect-CopyLocalDestinationAcl {
  [CmdletBinding()]
  param([Parameter(Mandatory)][string]$Path)
  if ([Environment]::OSVersion.Platform -ne [System.PlatformID]::Win32NT) {
    return
  }
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
  if ([Environment]::OSVersion.Platform -ne [System.PlatformID]::Win32NT) {
    return
  }
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
function Get-CopyLocalMissingDestinationPaths {
  [CmdletBinding()]
  [OutputType([object])]
  param([Parameter(Mandatory)][string]$DestinationRoot)

  $missing = New-Object System.Collections.Generic.List[string]
  $existingAncestor = [System.IO.Path]::GetFullPath($DestinationRoot)
  while (-not (Test-Path -LiteralPath $existingAncestor -PathType Container)) {
    [void]$missing.Add($existingAncestor)
    $parent = Split-Path -Path $existingAncestor -Parent
    if ([string]::IsNullOrWhiteSpace($parent) -or $parent -eq $existingAncestor) {
      throw 'DestinationRoot has no existing parent directory that can be validated.'
    }
    $existingAncestor = $parent
  }
  return [pscustomobject]@{ ExistingAncestor = $existingAncestor
    Missing = $missing
  }
}

function New-CopyLocalDestinationDirectories {
  [CmdletBinding(SupportsShouldProcess = $true)]
  param([Parameter(Mandatory)][System.Collections.Generic.List[string]]$Missing, [Parameter(Mandatory)][string]$ExistingRoot, [Parameter(Mandatory)][System.Collections.Generic.List[string]]$CreatedPaths)

  for ($index = $Missing.Count - 1; $index -ge 0; $index--) {
    $path = $Missing[$index]
    if (-not $PSCmdlet.ShouldProcess($path, 'Create and protect destination directory')) {
      throw 'New destination directory creation was declined.'
    }
    [void][System.IO.Directory]::CreateDirectory($path)
    [void]$CreatedPaths.Add($path)
    Set-CopyLocalNewDestinationAcl -Path $path -Confirm:$false
    $resolved = (Resolve-Path -LiteralPath $path -ErrorAction Stop).ProviderPath
    if (Test-PathContainsReparsePoint -Path $resolved -Root $ExistingRoot) {
      throw 'A newly created destination directory contains a reparse point.'
    }
  }
}

function Initialize-CopyLocalDestinationRoot {
  [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'None')]
  param(
    [Parameter(Mandatory)][string]$DestinationRoot,
    [Parameter(Mandatory)][AllowEmptyCollection()][System.Collections.Generic.List[string]]$CreatedPaths
  )
  $destinationPaths = Get-CopyLocalMissingDestinationPaths -DestinationRoot $DestinationRoot
  $existingResolved = (Resolve-Path -LiteralPath $destinationPaths.ExistingAncestor -ErrorAction Stop).ProviderPath
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
  New-CopyLocalDestinationDirectories -Missing $destinationPaths.Missing -ExistingRoot $existingResolved -CreatedPaths $CreatedPaths -Confirm:$false
}
function Remove-CopyLocalEmptyCreatedDirectory {
  [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'None')]
  param([Parameter(Mandatory)][AllowEmptyCollection()][System.Collections.Generic.List[string]]$CreatedPaths)
  for ($index = $CreatedPaths.Count - 1; $index -ge 0; $index--) {
    $path = $CreatedPaths[$index]
    try {
      if (-not (Test-Path -LiteralPath $path -PathType Container)) {
        continue
      }
      $item = Get-Item -LiteralPath $path -Force -ErrorAction Stop
      if ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
        continue
      }
      if (@(Get-ChildItem -LiteralPath $path -Force -ErrorAction Stop).Count -ne 0) {
        continue
      }
      if ($PSCmdlet.ShouldProcess($path, 'Remove empty destination directory created by failed deployment')) {
        Remove-Item -LiteralPath $path -Force -ErrorAction Stop
      }
    }
    catch {
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
