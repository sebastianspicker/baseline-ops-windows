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
  [ValidateSet('Audit', 'Remediate')][string]$Mode = 'Audit',
  [string]$ConfigPath,
  [ValidateSet('Console', 'Json', 'Csv', 'None')][string]$OutputFormat = 'Console',
  [string]$OutputPath,
  [switch]$PassThru,
  [switch]$Strict,
  [switch]$Quiet,
  [switch]$NoColor
)

function Get-CopyLocalBootstrapTrustConfiguration {
  [CmdletBinding()]
  param()

  $writeMask = [Security.AccessControl.FileSystemRights]::WriteData -bor [Security.AccessControl.FileSystemRights]::AppendData -bor [Security.AccessControl.FileSystemRights]::WriteExtendedAttributes -bor [Security.AccessControl.FileSystemRights]::WriteAttributes -bor [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor [Security.AccessControl.FileSystemRights]::Delete -bor [Security.AccessControl.FileSystemRights]::ChangePermissions -bor [Security.AccessControl.FileSystemRights]::TakeOwnership
  $replaceMask = [Security.AccessControl.FileSystemRights]::Delete -bor [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor [Security.AccessControl.FileSystemRights]::ChangePermissions -bor [Security.AccessControl.FileSystemRights]::TakeOwnership

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

function Assert-CopyLocalBootstrapAclTrust {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]$Acl,
    [Parameter(Mandatory)][hashtable]$TrustedSids,
    [Parameter(Mandatory)][int64]$EffectiveMask,
    [Parameter(Mandatory)][string]$Path
  )

  $ownerSid = $Acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
  if (-not $TrustedSids.ContainsKey($ownerSid)) {
    throw "CopyLocal bootstrap path has an untrusted owner SID: $Path"
  }
  foreach ($rule in @($Acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))) {
    $isEffectiveAllow = $rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and
    ($rule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) -eq 0
    if ($isEffectiveAllow -and -not $TrustedSids.ContainsKey([string]$rule.IdentityReference.Value) -and
      ([int64]$rule.FileSystemRights -band $EffectiveMask) -ne 0) {
      throw "CopyLocal bootstrap path grants write/replace rights to an untrusted SID: $Path"
    }
  }
}

function Assert-CopyLocalBootstrapPathTrust {
  [CmdletBinding()]
  param([Parameter(Mandatory)][string]$Path, [switch]$CheckAncestors)
  $configuration = Get-CopyLocalBootstrapTrustConfiguration
  $current = (Microsoft.PowerShell.Management\Get-Item -LiteralPath $Path -Force -ErrorAction Stop).FullName
  $isLeaf = $true
  while (-not [string]::IsNullOrWhiteSpace($current)) {
    $item = Microsoft.PowerShell.Management\Get-Item -LiteralPath $current -Force -ErrorAction Stop
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
      throw "CopyLocal bootstrap path contains a reparse point: $current"
    }
    if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) {
      $acl = Microsoft.PowerShell.Security\Get-Acl -LiteralPath $item.FullName -ErrorAction Stop
      $effectiveMask = if ($isLeaf) {
        $configuration.WriteMask
      }
      else {
        $configuration.ReplaceMask
      }
      Assert-CopyLocalBootstrapAclTrust -Acl $acl -TrustedSids $configuration.TrustedSids -EffectiveMask $effectiveMask -Path $current
    }
    if (-not $CheckAncestors) {
      break
    }
    $parentInfo = [IO.Directory]::GetParent($item.FullName)
    if ($null -eq $parentInfo) {
      break
    }
    $parent = $parentInfo.FullName
    $current = $parent
    $isLeaf = $false
  }
}

function Import-CopyLocalBootstrap {
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
    $copyLocalValidationPath, $copyLocalSerializationPath, $copyLocalExternalPath, $copyLocalHelperPath,
    [IO.Path]::Combine($PSScriptRoot, 'internal', '00-Copy-Local.staging.ps1'),
    [IO.Path]::Combine($PSScriptRoot, 'internal', '00-Copy-Local.destination.ps1'),
    [IO.Path]::Combine($PSScriptRoot, 'internal', '00-Copy-Local.source.ps1'),
    [IO.Path]::Combine($PSScriptRoot, 'internal', '00-Copy-Local.deployment.ps1'),
    [IO.Path]::Combine($PSScriptRoot, 'internal', '00-Copy-Local.runtime.ps1')
  )
  try {
    foreach ($bootstrapPath in $copyLocalBootstrapPaths) {
      $stream = [IO.File]::Open($bootstrapPath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
      try {
        Assert-CopyLocalBootstrapPathTrust -Path $bootstrapPath -CheckAncestors
        [void]$copyLocalBootstrapLocks.Add($stream)
        $stream = $null
      }
      finally {
        if ($null -ne $stream) {
          $stream.Dispose()
        }
      }
    }
    . $copyLocalBootstrapPath
    Microsoft.PowerShell.Core\Import-Module $copyLocalCommonPath -Force -Global -DisableNameChecking
    Microsoft.PowerShell.Core\Import-Module $copyLocalOutputPath -Force
    Microsoft.PowerShell.Core\Import-Module $copyLocalValidationPath -Force
    Microsoft.PowerShell.Core\Import-Module $copyLocalSerializationPath -Force
    Microsoft.PowerShell.Core\Import-Module $copyLocalExternalPath -Force -DisableNameChecking
    . $copyLocalHelperPath
  }
  finally {
    # Every closure member is fully parsed into this runspace at this point.
    # Release source handles before a same-root transaction renames scripts/lib.
    foreach ($bootstrapLock in $copyLocalBootstrapLocks) {
      $bootstrapLock.Dispose()
    }
  }

}
. Import-CopyLocalBootstrap

Set-StrictMode -Version Latest
function Get-CopyLocalV2Context {
  param($BoundParameters)
  return Initialize-V2Context -ScriptName '00-Copy-Local.ps1' -BoundParameters $BoundParameters `
    -Values @{ Mode = $Mode
    ConfigPath = $ConfigPath
    OutputFormat = $OutputFormat
    OutputPath = $OutputPath
    PassThru = $PassThru
    Strict = $Strict
    Quiet = $Quiet
    NoColor = $NoColor
    DeriveRemediate = $false
  }
}
$script:__V2Context = Get-CopyLocalV2Context -BoundParameters $PSBoundParameters
if ($script:__V2Context.Quiet) {
  $InformationPreference = 'SilentlyContinue'
  $VerbosePreference = 'SilentlyContinue'
}
$script:NoColor = [bool]$script:__V2Context.NoColor
$ErrorActionPreference = 'Stop'
function Get-CopyLocalInvocationState {
  return New-CopyLocalRunState -Inputs @{
    RepoUrl = $RepoUrl
    RepoPath = $RepoPath
    RepoRef = $RepoRef
    GitPath = $GitPath
    DestinationRoot = $DestinationRoot
    Mode = $Mode
    OutputFormat = $OutputFormat
    OutputPath = $OutputPath
    PassThru = $PassThru
    Strict = $Strict
  }
}
$RunState = Get-CopyLocalInvocationState

try {
  Assert-CopyLocalSourceArguments -RunState $RunState
  Assert-CopyLocalDestinationArgument -RunState $RunState
  Assert-CopyLocalCloneOverlap -RunState $RunState
  if (-not $PSCmdlet.ShouldProcess($DestinationRoot, 'Synchronize repository content into the deployment root')) {
    Write-CopyLocalSkipped -RunState $RunState
    exit (Get-V2ExitCode -Result $RunState.resultToken)
  }
  Invoke-CopyLocalDeployment -RunState $RunState
  Write-CopyLocalSuccess -RunState $RunState
  exit (Get-V2ExitCode -Result $RunState.resultToken)
}
catch {
  Write-CopyLocalFailure -RunState $RunState -ErrorRecord $_
  exit (Get-V2ExitCode -Result $RunState.resultToken)
}
finally {
  Clear-CopyLocalRun -RunState $RunState
}
