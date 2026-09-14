#requires -version 5.1
<#
.SYNOPSIS
Run a categorized batch of scripts via profile orchestration.

.DESCRIPTION
Builds a temporary profile for the selected script category and delegates its
execution to the profile runner. This preserves one validation, dependency,
integrity, and result-handling path instead of maintaining a second scheduler.
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
  [ValidateSet('All','Audit','Remediation','Collection','Utility','Monitoring')]
  [string]$Category = 'Audit',

  [ValidateSet('Audit','Remediate')]
  [string]$Mode = 'Audit',

  [string]$RootPath = 'C:\install\mdm\ps1',

  [switch]$ContinueOnError,

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

function Resolve-RunBatchRootPath {
  [CmdletBinding()]
  [OutputType([string])]
  param([Parameter(Mandatory)][string]$Candidate, [Parameter(Mandatory)][bool]$WasExplicit)

  $hasDeployment = [System.Environment]::OSVersion.Platform -eq [System.PlatformID]::Win32NT -and (Test-Path -LiteralPath (Join-Path $Candidate 'scripts') -PathType Container)
  if ($WasExplicit -or $Candidate -ne 'C:\install\mdm\ps1' -or $hasDeployment) { return $Candidate }
  $repositoryRoot = Split-Path -Parent $PSScriptRoot
  if (Test-Path -LiteralPath (Join-Path $repositoryRoot 'scripts') -PathType Container) { return $repositoryRoot }
  return $Candidate
}

$RootPath = Resolve-RunBatchRootPath -Candidate $RootPath -WasExplicit $PSBoundParameters.ContainsKey('RootPath')

function Get-RunBatchTrustMasks {
  [CmdletBinding()]
  param()
  $writeMask = [System.Security.AccessControl.FileSystemRights]::WriteData -bor [System.Security.AccessControl.FileSystemRights]::AppendData -bor [System.Security.AccessControl.FileSystemRights]::WriteExtendedAttributes -bor [System.Security.AccessControl.FileSystemRights]::WriteAttributes -bor [System.Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor [System.Security.AccessControl.FileSystemRights]::Delete -bor [System.Security.AccessControl.FileSystemRights]::ChangePermissions -bor [System.Security.AccessControl.FileSystemRights]::TakeOwnership
  $ancestorReplacementMask = [System.Security.AccessControl.FileSystemRights]::Delete -bor [System.Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor [System.Security.AccessControl.FileSystemRights]::ChangePermissions -bor [System.Security.AccessControl.FileSystemRights]::TakeOwnership
  return [pscustomobject]@{
    TrustedSids = @{ 'S-1-5-18' = $true; 'S-1-5-32-544' = $true; 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464' = $true }
    WriteMask = $writeMask; ReplaceMask = $ancestorReplacementMask
  }
}

function Assert-RunBatchAclTrust {
  [CmdletBinding()]
  param([Parameter(Mandatory)]$Acl, [Parameter(Mandatory)][hashtable]$TrustedSids, [Parameter(Mandatory)][int64]$EffectiveMask, [Parameter(Mandatory)][string]$Path)
  $ownerSid = $Acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value
  if (-not $TrustedSids.ContainsKey($ownerSid)) { throw "Privileged execution path has an untrusted owner SID: $Path" }
  foreach ($rule in @($Acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]))) {
    $effectiveAllow = $rule.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Allow -and ($rule.PropagationFlags -band [System.Security.AccessControl.PropagationFlags]::InheritOnly) -eq 0
    if ($effectiveAllow -and -not $TrustedSids.ContainsKey([string]$rule.IdentityReference.Value) -and ([int64]$rule.FileSystemRights -band $EffectiveMask) -ne 0) { throw "Privileged execution path grants write/replace rights to an untrusted SID: $Path" }
  }
}

function Assert-RunBatchTrustedWindowsAcl {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Path,
    [switch]$CheckAncestors
  )

  $trustMasks = Get-RunBatchTrustMasks

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
    Assert-RunBatchAclTrust -Acl $acl -TrustedSids $trustMasks.TrustedSids -EffectiveMask $effectiveMask -Path $current
    if (-not $CheckAncestors) { break }
    $parent = Split-Path -Parent $currentItem.FullName
    if ([string]::IsNullOrWhiteSpace($parent) -or
        [string]::Equals($parent, $currentItem.FullName, [System.StringComparison]::OrdinalIgnoreCase)) { break }
    $current = $parent
    $isProtectedItem = $false
  }
}

$runProfilePath = Join-Path $PSScriptRoot '00-Run-Profile.ps1'
$runBatchHelperPath = Join-Path $PSScriptRoot 'internal/00-Run-Batch.helpers.ps1'
function Test-RunBatchElevatedWindows {
  [CmdletBinding()]
  [OutputType([bool])]
  param()
  if ([System.Environment]::OSVersion.Platform -ne [System.PlatformID]::Win32NT) { return $false }
  $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
  $principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
  return $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Assert-RunBatchBootstrapClosure {
  [CmdletBinding()]
  param([Parameter(Mandatory)][string]$ProfilePath, [Parameter(Mandatory)][string]$HelperPath, [Parameter(Mandatory)][string]$TargetRoot)

  $runnerRoot = Split-Path -Parent $PSScriptRoot
  $runnerLib = Join-Path $runnerRoot 'lib'
  $trustedBootstrapPaths = @(
    $runnerRoot,
    $PSScriptRoot,
    $PSCommandPath,
    $runnerLib,
    (Join-Path $PSScriptRoot '_lib/Bootstrap.ps1'),
    (Join-Path $runnerLib 'Output.psm1'),
    (Join-Path $runnerLib 'Serialization.psm1'),
    $HelperPath,
    $ProfilePath,
    $TargetRoot,
    (Join-Path $TargetRoot 'scripts'),
    (Join-Path $TargetRoot 'lib')
  ) | Select-Object -Unique
  foreach ($trustedPath in $trustedBootstrapPaths) {
    Assert-RunBatchTrustedWindowsAcl -Path $trustedPath -CheckAncestors:($trustedPath -in @($runnerRoot, $RootPath))
  }
}

$isElevatedWindows = Test-RunBatchElevatedWindows
if ($isElevatedWindows) { Assert-RunBatchBootstrapClosure -ProfilePath $runProfilePath -HelperPath $runBatchHelperPath -TargetRoot $RootPath }

. (Join-Path $PSScriptRoot '_lib/Bootstrap.ps1')
Import-Module (Join-Path $script:LibPath 'Output.psm1') -Force
Import-Module (Join-Path $script:LibPath 'Serialization.psm1') -Force
if ($isElevatedWindows) { Assert-RunBatchTrustedWindowsAcl -Path $runBatchHelperPath }
. $runBatchHelperPath

Set-StrictMode -Version Latest
$script:__V2Context = Initialize-V2Context -ScriptName '00-Run-Batch.ps1' -BoundParameters $PSBoundParameters `
  -Values @{ Mode = $Mode; ConfigPath = $ConfigPath; OutputFormat = $OutputFormat; OutputPath = $OutputPath; PassThru = $PassThru; Strict = $Strict; Quiet = $Quiet; NoColor = $NoColor; DeriveRemediate = $false }
if ($script:__V2Context.Quiet) { $InformationPreference = 'SilentlyContinue'; $VerbosePreference = 'SilentlyContinue' }
$script:NoColor = [bool]$script:__V2Context.NoColor
$ErrorActionPreference = 'Stop'

function Write-BatchTerminalResult {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][ValidateSet('WARN','FAIL')][string]$Result,
    [Parameter(Mandatory)][string]$Code,
    [Parameter(Mandatory)][string]$Message,
    [string[]]$SelectedScripts = @()
  )

  $severity = if ($Result -eq 'FAIL') { 'High' } else { 'Info' }
  $batchResult = Get-V2ResultObject `
    -ScriptName '00-Run-Batch.ps1' `
    -Mode $Mode `
    -Result $Result `
    -Findings @([pscustomobject]@{ Code = $Code; Severity = $severity; Message = $Message }) `
    -Summary ([pscustomobject]@{
        Category      = $Category
        SelectedCount = @($SelectedScripts).Count
        Executed      = $false
        Message       = $Message
      }) `
    -Metadata @{ SelectedScripts = @($SelectedScripts) }

  Write-ResultObject -ResultObject $batchResult -OutputFormat $OutputFormat -OutputPath $OutputPath
  if ($PassThru) { $batchResult }
}

function Set-BatchAdminSystemAcl {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Path,
    [switch]$Directory
  )

  $adminsSid = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')
  $systemSid = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-18')
  $acl = if ($Directory) {
    New-Object System.Security.AccessControl.DirectorySecurity
  } else {
    New-Object System.Security.AccessControl.FileSecurity
  }
  $acl.SetOwner($adminsSid)
  $acl.SetAccessRuleProtection($true, $false)
  $inheritance = if ($Directory) {
    [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
      [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
  } else {
    [System.Security.AccessControl.InheritanceFlags]::None
  }
  foreach ($sid in @($adminsSid, $systemSid)) {
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
      $sid,
      [System.Security.AccessControl.FileSystemRights]::FullControl,
      $inheritance,
      [System.Security.AccessControl.PropagationFlags]::None,
      [System.Security.AccessControl.AccessControlType]::Allow
    )
    [void]$acl.AddAccessRule($rule)
  }
  Set-Acl -LiteralPath $Path -AclObject $acl -ErrorAction Stop
}

function New-BatchProfileWorkspace {
  [CmdletBinding()]
  param()

  if ($isElevatedWindows) {
    $programData = [System.Environment]::GetFolderPath(
      [System.Environment+SpecialFolder]::CommonApplicationData
    )
    if ([string]::IsNullOrWhiteSpace($programData)) {
      throw 'Unable to resolve the protected CommonApplicationData directory.'
    }
    $trustedParent = Join-Path $programData 'Microsoft\Windows'
    Assert-RunBatchTrustedWindowsAcl -Path $trustedParent -CheckAncestors
    $directory = Join-Path $trustedParent ("BaselineOpsForWindows-Batch-{0}" -f [guid]::NewGuid().ToString('N'))
    [void][System.IO.Directory]::CreateDirectory($directory)
    Set-BatchAdminSystemAcl -Path $directory -Directory
    Assert-RunBatchTrustedWindowsAcl -Path $directory -CheckAncestors
    return $directory
  }

  # There is no elevated Windows boundary on this path. The unique directory
  # preserves portable development runs; the profile itself is locked below.
  $directory = Join-Path ([System.IO.Path]::GetTempPath()) ("baselineops-windows-batch-{0}" -f [guid]::NewGuid().ToString('N'))
  [void][System.IO.Directory]::CreateDirectory($directory)
  return $directory
}

function Get-BatchCategoryMap {
  [CmdletBinding()]
  param()

  return @{
    Audit       = @('01','02','03','04','05','06','07','09','10','11','13','14','15','18','19','20','22','23','24','26','27','28','29','30','31','32','33','34','35','36','37','38','39','40','41','42','43','44','45','46','47','48','49','50','51','52')
    Remediation = @('01','02','03','04','05','06','07','08','13','14','16','18','21','22','25','31','32','33','38','39','40','44')
    Collection  = @('09','10','11','12','20')
    Utility     = @('08','25')
    Monitoring  = @('17','32','34','38')
  }
}

function Get-BatchSelectedScripts {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Category,
    [Parameter(Mandatory)][string[]]$ScriptNames
  )

  if ($Category -eq 'All') {
    return @($ScriptNames | Sort-Object)
  }

  $selected = foreach ($prefix in (Get-BatchCategoryMap)[$Category]) {
    $ScriptNames | Where-Object { $_ -like "$prefix-*" }
  }
  return @($selected | Sort-Object -Unique)
}

function New-BatchProfileDocument {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Category,
    [Parameter(Mandatory)][string]$Mode,
    [Parameter(Mandatory)][bool]$Strict,
    [Parameter(Mandatory)][bool]$RequireSigned,
    [Parameter(Mandatory)][bool]$ContinueOnError,
    [Parameter(Mandatory)][string[]]$SelectedScripts
  )

  $batchProfile = [ordered]@{
    ProfileName = "batch-$($Category.ToLowerInvariant())"
    Version     = '2.0'
    Defaults    = [ordered]@{
      Mode         = $Mode
      Strict       = $Strict
      OutputFormat = 'Console'
      OutputPath   = $null
    }
    Steps        = @()
    Integrity    = [ordered]@{
      RequireSigned = $RequireSigned
      ExpectedHashes = @{}
    }
  }

  foreach ($scriptName in $SelectedScripts) {
    $batchProfile.Steps += [ordered]@{
      Script          = $scriptName
      Args            = @()
      ContinueOnError = $ContinueOnError
      DependsOn       = @()
    }
  }

  return $batchProfile
}

Invoke-RunBatch
