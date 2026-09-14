#requires -version 5.1
<#
.SYNOPSIS
Run a script from C:\install\mdm\ps1\scripts on the local machine.

.DESCRIPTION
Looks up the script file in C:\install\mdm\ps1\scripts (or an override)
and executes it. Optional -ScriptArgs are passed through to the script.

Supports optional integrity verification via signature check or hash comparison.

.PARAMETER ScriptName
Script file name to run (for example: 18-Firewall-Baseline.ps1).

.PARAMETER ScriptNumber
Script number only (for example: 18). Matches "18-*.ps1".

.PARAMETER ScriptArgs
Optional arguments to pass to the target script.

.PARAMETER RootPath
Override root path (default: C:\install\mdm\ps1).

.PARAMETER RequireSigned
If set, verifies the script has a valid Authenticode signature before execution.

.PARAMETER ExpectedHash
Expected hash value for the script. Format: "ALGORITHM:HASH" or just "HASH" (defaults to SHA256).
Example: "SHA256:ABC123..." or just "ABC123..."

.PARAMETER HashAlgorithm
Hash algorithm to use for verification (default: SHA256).
Valid values: SHA256, SHA384, SHA512

.EXAMPLE
.\00-Run-Local.ps1 -ScriptName 18-Firewall-Baseline.ps1

.EXAMPLE
.\00-Run-Local.ps1 -ScriptNumber 18

.EXAMPLE
.\00-Run-Local.ps1 -ScriptName 31-PowerShell-Logging-Baseline.ps1 -ScriptArgs @('-Mode','Audit')

.EXAMPLE
.\00-Run-Local.ps1 -ScriptNumber 18 -RequireSigned

.EXAMPLE
.\00-Run-Local.ps1 -ScriptName 18-Firewall-Baseline.ps1 -ExpectedHash "SHA256:ABC123DEF456..."

.EXAMPLE
# Verify hash from a hash file
$hash = (Get-Content .\hashes.txt | Where-Object { $_ -like "18-Firewall-Baseline.ps1=*" }).Split('=')[1]
.\00-Run-Local.ps1 -ScriptNumber 18 -ExpectedHash $hash
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
  [Parameter(Mandatory, ParameterSetName = 'ByName')]
  [ValidateNotNullOrEmpty()]
  [string]$ScriptName,

  [Parameter(Mandatory, ParameterSetName = 'ByNumber')]
  [ValidatePattern('^\d{1,2}$')]
  [string]$ScriptNumber,

  [string[]]$ScriptArgs,

  # Default deployment path. Override with -RootPath to use a different location
  # (for example, -RootPath $KitRoot or a value supplied by the deployment pipeline).
  [string]$RootPath = 'C:\install\mdm\ps1',

  [switch]$RequireSigned,

  [string]$ExpectedHash,

  [ValidateSet('SHA256','SHA384','SHA512')]
  [string]$HashAlgorithm = 'SHA256'

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

function Get-RunLocalTrustMasks {
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
  $ancestorReplacementMask =
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
    ReplaceMask = $ancestorReplacementMask
  }
}

function Assert-RunLocalAclTrust {
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

function Assert-RunLocalTrustedWindowsAcl {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Path,
    [switch]$CheckAncestors
  )

  $trustMasks = Get-RunLocalTrustMasks

  $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
  $current = $item.FullName
  $isProtectedItem = $true
  while (-not [string]::IsNullOrWhiteSpace($current)) {
    $currentItem = Get-Item -LiteralPath $current -Force -ErrorAction Stop
    if (($currentItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
      throw "Privileged execution path contains a reparse point: $current"
    }
    $acl = Get-Acl -LiteralPath $currentItem.FullName -ErrorAction Stop
    $effectiveMask = if ($isProtectedItem) { $trustMasks.WriteMask } else { $trustMasks.ReplaceMask }
    Assert-RunLocalAclTrust -Acl $acl -TrustedSids $trustMasks.TrustedSids -EffectiveMask $effectiveMask -Path $current
    if (-not $CheckAncestors) { break }
    $parent = Split-Path -Parent $currentItem.FullName
    if ([string]::IsNullOrWhiteSpace($parent) -or
        [string]::Equals($parent, $currentItem.FullName, [System.StringComparison]::OrdinalIgnoreCase)) { break }
    $current = $parent
    $isProtectedItem = $false
  }
}

function Resolve-RunLocalRootPath {
  param(
    [string]$RequestedRoot,
    [bool]$Explicit,
    [string]$ScriptRoot
  )
  $deploymentPresent = $false
  if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) {
    $deploymentPresent = Test-Path -LiteralPath (Join-Path $RequestedRoot 'scripts') -PathType Container
  }
  if ($Explicit -or $RequestedRoot -ne 'C:\install\mdm\ps1' -or $deploymentPresent) {
    return $RequestedRoot
  }
  $repoRoot = Split-Path -Parent $ScriptRoot
  if (Test-Path -LiteralPath (Join-Path $repoRoot 'scripts') -PathType Container) {
    return $repoRoot
  }
  return $RequestedRoot
}

function New-RunLocalBootstrapContext {
  param(
    [string]$RootPath,
    [string]$ScriptRoot
  )
  $runnerRoot = Split-Path -Parent $ScriptRoot
  $runnerLib = Join-Path $runnerRoot 'lib'
  $isWindowsPlatform = [Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT
  $isElevated = $false
  if ($isWindowsPlatform) {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    $isElevated = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  }
  return [pscustomobject]@{
    RootPath = $RootPath
    RunnerRoot = $runnerRoot
    RunnerLib = $runnerLib
    IsElevated = $isElevated
    LeaseModulePath = Join-Path $runnerLib 'ProfileExecutionLease.psm1'
    HelperPath = Join-Path $ScriptRoot 'internal/00-Run-Local.helpers.ps1'
    RuntimePath = Join-Path $ScriptRoot 'internal/00-Run-Local.runtime.ps1'
    DependencyPath = Join-Path $ScriptRoot 'internal/00-Run-Local.dependencies.ps1'
  }
}

function Assert-RunLocalBootstrapTrust {
  param(
    $Context,
    [string]$ScriptRoot,
    [string]$CommandPath
  )
  if (-not $Context.IsElevated) {
    return
  }
  $paths = @(
    $Context.RunnerRoot
    $ScriptRoot
    $CommandPath
    $Context.RunnerLib
    (Join-Path $ScriptRoot '_lib/Bootstrap.ps1')
    (Join-Path $Context.RunnerLib 'Validation.psm1')
    (Join-Path $Context.RunnerLib 'Output.psm1')
    (Join-Path $Context.RunnerLib 'Execution.psm1')
    (Join-Path $Context.RunnerLib 'Serialization.psm1')
    $Context.LeaseModulePath
    $Context.HelperPath
    $Context.RuntimePath
    $Context.DependencyPath
    $Context.RootPath
    (Join-Path $Context.RootPath 'scripts')
    (Join-Path $Context.RootPath 'lib')
  ) | Select-Object -Unique
  foreach ($path in $paths) {
    $checkAncestors = $path -in @($Context.RunnerRoot, $Context.RootPath)
    Assert-RunLocalTrustedWindowsAcl -Path $path -CheckAncestors:$checkAncestors
  }
}

function Get-RunLocalLeasePaths {
  param($Context, [string]$ScriptRoot, [string]$CommandPath)

  return [pscustomobject]@{
    ControlFiles = @(
      $CommandPath
      $Context.LeaseModulePath
      $Context.HelperPath
      $Context.RuntimePath
      $Context.DependencyPath
      (Join-Path $ScriptRoot '_lib/Bootstrap.ps1')
      (Join-Path $Context.RunnerLib 'Validation.psm1')
      (Join-Path $Context.RunnerLib 'Output.psm1')
      (Join-Path $Context.RunnerLib 'Execution.psm1')
      (Join-Path $Context.RunnerLib 'Serialization.psm1')
    )
    ClosureRoots = @(
      (Join-Path $Context.RunnerRoot 'scripts/_lib')
      (Join-Path $Context.RunnerRoot 'scripts/internal')
      (Join-Path $Context.RunnerRoot 'lib')
      (Join-Path $Context.RootPath 'scripts/_lib')
      (Join-Path $Context.RootPath 'scripts/internal')
      (Join-Path $Context.RootPath 'lib')
    )
  }
}

function Invoke-TargetScript {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Path,
    [string[]]$Arguments = @(),
    [switch]$CaptureV2Result,
    [System.Collections.IDictionary]$RunnerBoundParameters = @{}
  )

  $parsed = Convert-ArgumentTokens -Arguments $Arguments
  $namedArguments = $parsed.Named
  $positionalArguments = @($parsed.Positional)
  Add-RunLocalForwardedArguments -NamedArguments $namedArguments -RunnerBoundParameters $RunnerBoundParameters

  if ($CaptureV2Result) {
    $namedArguments['PassThru'] = $true
    $namedArguments['OutputFormat'] = 'None'
    if ($namedArguments.ContainsKey('OutputPath')) {
      $namedArguments.Remove('OutputPath')
    }
  }

  if ($positionalArguments.Count -gt 0) {
    & $Path @namedArguments @positionalArguments
  } else {
    & $Path @namedArguments
  }
}

function Assert-RunLocalLockedHelpers {
  param($Context)

  if (-not $Context.IsElevated) {
    return
  }
  Assert-RunLocalTrustedWindowsAcl -Path $Context.HelperPath
  Assert-RunLocalTrustedWindowsAcl -Path $Context.RuntimePath
}

$RootPath = Resolve-RunLocalRootPath $RootPath $PSBoundParameters.ContainsKey('RootPath') $PSScriptRoot
$bootstrap = New-RunLocalBootstrapContext $RootPath $PSScriptRoot
Assert-RunLocalBootstrapTrust $bootstrap $PSScriptRoot $PSCommandPath

Import-Module $bootstrap.LeaseModulePath -DisableNameChecking
$localExecutionLease = $null
try {
  $leasePaths = Get-RunLocalLeasePaths $bootstrap $PSScriptRoot $PSCommandPath
  $localExecutionLease = Open-ProfileExecutionLease `
    -RunnerRoot $bootstrap.RunnerRoot `
    -TargetRoot $RootPath `
    -ControlFiles $leasePaths.ControlFiles `
    -ClosureRoots $leasePaths.ClosureRoots
  . $bootstrap.DependencyPath
  Assert-RunLocalLockedHelpers $bootstrap
  $options = New-RunLocalOptions $PSBoundParameters $PSCmdlet.ParameterSetName $RootPath
  $terminal = Invoke-RunLocalCapability $options $bootstrap
  foreach ($outputItem in @($terminal.Output)) {
    Write-Output -InputObject $outputItem -NoEnumerate
  }
  exit $terminal.ExitCode
} finally {
  if ($null -ne $localExecutionLease) {
    Close-ProfileExecutionLease -Lease $localExecutionLease
  }
}
