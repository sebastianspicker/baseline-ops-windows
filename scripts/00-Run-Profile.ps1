#requires -version 5.1
<#
.SYNOPSIS
Execute a v2 orchestration profile.

.DESCRIPTION
Runs profile steps with dependency checks and optional integrity verification
through 00-Run-Local.ps1.
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
  [Parameter(Mandatory)]
  [string]$ProfilePath,

  [ValidateSet('Audit','Remediate')]
  [string]$Mode,

  [string]$RootPath = 'C:\install\mdm\ps1',

  [ValidateSet('Console','Json','Csv','None')]
  [string]$OutputFormat = 'Console',

  [string]$OutputPath,

  [switch]$PassThru,

  [switch]$Strict,

  [switch]$RequireSigned

,
  [string]$ConfigPath,
  [switch]$Quiet,
  [switch]$NoColor
)

function Get-RunProfileTrustMasks {
  [CmdletBinding()]
  param()

  $writeMask =
    [System.Security.AccessControl.FileSystemRights]::WriteData -bor
    [System.Security.AccessControl.FileSystemRights]::AppendData -bor
    [System.Security.AccessControl.FileSystemRights]::WriteExtendedAttributes -bor
    [System.Security.AccessControl.FileSystemRights]::WriteAttributes -bor
    [System.Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor
    [System.Security.AccessControl.FileSystemRights]::Delete -bor
    [System.Security.AccessControl.FileSystemRights]::ChangePermissions -bor
    [System.Security.AccessControl.FileSystemRights]::TakeOwnership
  $replacementMask =
    [System.Security.AccessControl.FileSystemRights]::Delete -bor
    [System.Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor
    [System.Security.AccessControl.FileSystemRights]::ChangePermissions -bor
    [System.Security.AccessControl.FileSystemRights]::TakeOwnership
  return [pscustomobject]@{
    TrustedSids = @{
      'S-1-5-18' = $true
      'S-1-5-32-544' = $true
      'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464' = $true
    }
    WriteMask = $writeMask
    ReplaceMask = $replacementMask
  }
}

function Assert-RunProfileAclTrust {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]$Acl,
    [Parameter(Mandatory)][hashtable]$TrustedSids,
    [Parameter(Mandatory)][int64]$EffectiveMask,
    [Parameter(Mandatory)][string]$Path
  )

  $ownerSid = $Acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value
  if (-not $TrustedSids.ContainsKey($ownerSid)) {
    throw "Privileged execution path has an untrusted owner SID: $Path"
  }
  foreach ($rule in @($Acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]))) {
    $effectiveAllow =
      $rule.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Allow -and
      ($rule.PropagationFlags -band [System.Security.AccessControl.PropagationFlags]::InheritOnly) -eq 0
    $untrustedWrite =
      -not $TrustedSids.ContainsKey([string]$rule.IdentityReference.Value) -and
      ([int64]$rule.FileSystemRights -band $EffectiveMask) -ne 0
    if ($effectiveAllow -and $untrustedWrite) {
      throw "Privileged execution path grants write/replace rights to an untrusted SID: $Path"
    }
  }
}

function Assert-RunProfileTrustedWindowsAcl {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Path,
    [switch]$CheckAncestors
  )

  $trustMasks = Get-RunProfileTrustMasks
  $current = (Get-Item -LiteralPath $Path -Force -ErrorAction Stop).FullName
  $isProtectedItem = $true
  while (-not [string]::IsNullOrWhiteSpace($current)) {
    $currentItem = Get-Item -LiteralPath $current -Force -ErrorAction Stop
    if (($currentItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
      throw "Privileged execution path contains a reparse point: $current"
    }
    $acl = Get-Acl -LiteralPath $currentItem.FullName -ErrorAction Stop
    $effectiveMask = if ($isProtectedItem) { $trustMasks.WriteMask } else { $trustMasks.ReplaceMask }
    Assert-RunProfileAclTrust `
      -Acl $acl `
      -TrustedSids $trustMasks.TrustedSids `
      -EffectiveMask $effectiveMask `
      -Path $current
    if (-not $CheckAncestors) {
      break
    }
    $parent = Split-Path -Parent $currentItem.FullName
    if ([string]::IsNullOrWhiteSpace($parent) -or
        [string]::Equals($parent, $currentItem.FullName, [System.StringComparison]::OrdinalIgnoreCase)) {
      break
    }
    $current = $parent
    $isProtectedItem = $false
  }
}

function Resolve-RunProfileRootPath {
  param(
    [string]$RequestedRoot,
    [bool]$Explicit,
    [string]$ScriptRoot
  )

  $deploymentPresent = $false
  if ([System.Environment]::OSVersion.Platform -eq [System.PlatformID]::Win32NT) {
    $deploymentPresent = Test-Path -LiteralPath (Join-Path $RequestedRoot 'scripts') -PathType Container
  }
  if ($Explicit -or $RequestedRoot -ne 'C:\install\mdm\ps1' -or $deploymentPresent) {
    return $RequestedRoot
  }
  $repositoryRoot = Split-Path -Parent $ScriptRoot
  if (Test-Path -LiteralPath (Join-Path $repositoryRoot 'scripts') -PathType Container) {
    return $repositoryRoot
  }
  return $RequestedRoot
}

function New-RunProfileBootstrapContext {
  param(
    [string]$RootPath,
    [string]$ScriptRoot
  )

  $runnerRoot = Split-Path -Parent $ScriptRoot
  $runnerLib = Join-Path $runnerRoot 'lib'
  $isElevated = $false
  if ([System.Environment]::OSVersion.Platform -eq [System.PlatformID]::Win32NT) {
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
    $isElevated = $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
  }
  return [pscustomobject]@{
    RootPath = $RootPath
    RunnerRoot = $runnerRoot
    RunnerLib = $runnerLib
    IsElevated = $isElevated
    LeaseModulePath = Join-Path $runnerLib 'ProfileExecutionLease.psm1'
    BootstrapPath = Join-Path $ScriptRoot '_lib/Bootstrap.ps1'
    HelperPath = Join-Path $ScriptRoot 'internal/00-Run-Profile.helpers.ps1'
    DependencyPath = Join-Path $ScriptRoot 'internal/00-Run-Profile.dependencies.ps1'
    RuntimePath = Join-Path $ScriptRoot 'internal/00-Run-Profile.runtime.ps1'
    SchedulerPath = Join-Path $ScriptRoot 'internal/00-Run-Profile.scheduler.ps1'
    PresentationPath = Join-Path $ScriptRoot 'internal/00-Run-Profile.presentation.ps1'
    ValidatorPath = Join-Path $ScriptRoot '00-Validate-Profile.ps1'
    ValidatorHelperPath = Join-Path $ScriptRoot 'internal/00-Validate-Profile.helpers.ps1'
    RunLocalPath = Join-Path $ScriptRoot '00-Run-Local.ps1'
    RunLocalHelperPath = Join-Path $ScriptRoot 'internal/00-Run-Local.helpers.ps1'
    RunLocalDependencyPath = Join-Path $ScriptRoot 'internal/00-Run-Local.dependencies.ps1'
    RunLocalRuntimePath = Join-Path $ScriptRoot 'internal/00-Run-Local.runtime.ps1'
  }
}

function Get-RunProfileControlFiles {
  param($Context)

  return @(
    $PSCommandPath
    $Context.LeaseModulePath
    $Context.BootstrapPath
    $Context.HelperPath
    $Context.DependencyPath
    $Context.RuntimePath
    $Context.SchedulerPath
    $Context.PresentationPath
    $Context.ValidatorPath
    $Context.ValidatorHelperPath
    $Context.RunLocalPath
    $Context.RunLocalHelperPath
    $Context.RunLocalDependencyPath
    $Context.RunLocalRuntimePath
    (Join-Path $Context.RunnerLib 'Output.psm1')
    (Join-Path $Context.RunnerLib 'Common.psm1')
    (Join-Path $Context.RunnerLib 'Config.psm1')
    (Join-Path $Context.RunnerLib 'Validation.psm1')
    (Join-Path $Context.RunnerLib 'Serialization.psm1')
    (Join-Path $Context.RunnerLib 'Execution.psm1')
  )
}

function Get-RunProfileClosureRoots {
  param($Context)

  return @(
    (Join-Path $Context.RunnerRoot 'scripts/_lib')
    (Join-Path $Context.RunnerRoot 'scripts/internal')
    (Join-Path $Context.RunnerRoot 'lib')
    (Join-Path $Context.RootPath 'scripts/_lib')
    (Join-Path $Context.RootPath 'scripts/internal')
    (Join-Path $Context.RootPath 'lib')
  )
}

function Assert-RunProfileBootstrapTrust {
  param($Context, [string]$ScriptRoot)

  if (-not $Context.IsElevated) {
    return
  }
  $paths = @(
    $Context.RunnerRoot
    $ScriptRoot
    $Context.RunnerLib
    $Context.RootPath
    (Join-Path $Context.RootPath 'scripts')
    (Join-Path $Context.RootPath 'lib')
  ) + @(Get-RunProfileControlFiles $Context)
  foreach ($trustedPath in @($paths | Select-Object -Unique)) {
    $checkAncestors = $trustedPath -in @($Context.RunnerRoot, $Context.RootPath)
    Assert-RunProfileTrustedWindowsAcl -Path $trustedPath -CheckAncestors:$checkAncestors
  }
}

function Invoke-RunProfileValidator {
  param($Context, $Options)

  & $Context.ValidatorPath `
    -ProfilePath $Options.ProfilePath `
    -RootPath $Options.RootPath `
    -OutputFormat 'None' `
    -PassThru
}

function Invoke-RunProfileChild {
  param($Context, [hashtable]$RunParameters)

  & $Context.RunLocalPath @RunParameters
}

function Assert-RunProfileLockedHelpers {
  param($Context)

  if (-not $Context.IsElevated) {
    return
  }
  foreach ($path in @(
      $Context.HelperPath,
      $Context.DependencyPath,
      $Context.RuntimePath,
      $Context.SchedulerPath,
      $Context.PresentationPath)) {
    Assert-RunProfileTrustedWindowsAcl -Path $path
  }
}

$RootPath = Resolve-RunProfileRootPath $RootPath $PSBoundParameters.ContainsKey('RootPath') $PSScriptRoot
$bootstrap = New-RunProfileBootstrapContext $RootPath $PSScriptRoot
Assert-RunProfileBootstrapTrust $bootstrap $PSScriptRoot
$leaseModulePath = $bootstrap.LeaseModulePath
Import-Module $leaseModulePath -DisableNameChecking
$profileExecutionLease = $null
try {
  $profileExecutionLease = Open-ProfileExecutionLease `
    -RunnerRoot $bootstrap.RunnerRoot `
    -TargetRoot $RootPath `
    -ControlFiles (Get-RunProfileControlFiles $bootstrap) `
    -ClosureRoots (Get-RunProfileClosureRoots $bootstrap)
  . $bootstrap.DependencyPath
  Assert-RunProfileLockedHelpers $bootstrap
  $options = New-RunProfileOptions $PSBoundParameters $PSCmdlet.ParameterSetName $RootPath $WhatIfPreference
  $terminal = Invoke-RunProfile $options $bootstrap
  Write-ResultObject `
    -ResultObject $terminal.ResultObject `
    -OutputFormat $terminal.OutputFormat `
    -OutputPath $terminal.OutputPath
  if ($PassThru) {
    $terminal.ResultObject
  }
  exit $terminal.ExitCode
} finally {
  if ($null -ne $profileExecutionLease) {
    Close-ProfileExecutionLease -Lease $profileExecutionLease
  }
}
