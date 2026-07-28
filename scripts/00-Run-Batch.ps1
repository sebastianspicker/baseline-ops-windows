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

$rootPathWasExplicit = $PSBoundParameters.ContainsKey('RootPath')
$defaultDeploymentPresent = $false
if ([System.Environment]::OSVersion.Platform -eq [System.PlatformID]::Win32NT) {
  $defaultDeploymentPresent = Test-Path -LiteralPath (Join-Path $RootPath 'scripts') -PathType Container
}
if (-not $rootPathWasExplicit -and $RootPath -eq 'C:\install\mdm\ps1' -and -not $defaultDeploymentPresent) {
  $repoRootCandidate = Split-Path -Parent $PSScriptRoot
  if (Test-Path -LiteralPath (Join-Path $repoRootCandidate 'scripts') -PathType Container) {
    $RootPath = $repoRootCandidate
  }
}

function Assert-RunBatchTrustedWindowsAcl {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Path,
    [switch]$CheckAncestors
  )

  $trustedSids = @{
    'S-1-5-18' = $true
    'S-1-5-32-544' = $true
    'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464' = $true
  }
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

  $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
  $current = $item.FullName
  $isProtectedItem = $true
  while (-not [string]::IsNullOrWhiteSpace($current)) {
    $currentItem = Get-Item -LiteralPath $current -Force -ErrorAction Stop
    if (($currentItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
      throw "Privileged execution path contains a reparse point: $current"
    }
    $acl = Get-Acl -LiteralPath $currentItem.FullName -ErrorAction Stop
    $ownerSid = $acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value
    if (-not $trustedSids.ContainsKey($ownerSid)) {
      throw "Privileged execution path has an untrusted owner SID: $current"
    }
    $effectiveMask = if ($isProtectedItem) { $writeMask } else { $ancestorReplacementMask }
    foreach ($rule in @($acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]))) {
      if ($rule.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) { continue }
      if (($rule.PropagationFlags -band [System.Security.AccessControl.PropagationFlags]::InheritOnly) -ne 0) { continue }
      $sid = [string]$rule.IdentityReference.Value
      if (-not $trustedSids.ContainsKey($sid) -and
          ([int64]$rule.FileSystemRights -band [int64]$effectiveMask) -ne 0) {
        throw "Privileged execution path grants write/replace rights to an untrusted SID: $current"
      }
    }
    if (-not $CheckAncestors) { break }
    $parent = Split-Path -Parent $currentItem.FullName
    if ([string]::IsNullOrWhiteSpace($parent) -or
        [string]::Equals($parent, $currentItem.FullName, [System.StringComparison]::OrdinalIgnoreCase)) { break }
    $current = $parent
    $isProtectedItem = $false
  }
}

$runProfilePath = Join-Path $PSScriptRoot '00-Run-Profile.ps1'
$isWindowsPlatform = [System.Environment]::OSVersion.Platform -eq [System.PlatformID]::Win32NT
$isElevatedWindows = $false
if ($isWindowsPlatform) {
  $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
  $principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
  $isElevatedWindows = $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

if ($isElevatedWindows) {
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
    $runProfilePath,
    $RootPath,
    (Join-Path $RootPath 'scripts'),
    (Join-Path $RootPath 'lib')
  ) | Select-Object -Unique
  foreach ($trustedPath in $trustedBootstrapPaths) {
    Assert-RunBatchTrustedWindowsAcl -Path $trustedPath -CheckAncestors:($trustedPath -in @($runnerRoot, $RootPath))
  }
}

. (Join-Path $PSScriptRoot '_lib/Bootstrap.ps1')
Import-Module (Join-Path $script:LibPath 'Output.psm1') -Force
Import-Module (Join-Path $script:LibPath 'Serialization.psm1') -Force

Set-StrictMode -Version Latest
# v2-init (migrated to Initialize-V2Context)
$script:__V2Context = Initialize-V2Context -ScriptName '00-Run-Batch.ps1' -BoundParameters $PSBoundParameters `
  -Mode $Mode -ConfigPath $ConfigPath -OutputFormat $OutputFormat -OutputPath $OutputPath `
  -PassThru:$PassThru -Strict:$Strict -Quiet:$Quiet -NoColor:$NoColor
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

if (-not (Test-Path -LiteralPath $runProfilePath -PathType Leaf)) {
  Write-BatchTerminalResult -Result FAIL -Code 'Batch-MissingProfileRunner' -Message "Missing Run-Profile script: $runProfilePath"
  exit (Get-V2ExitCode -Result 'FAIL')
}

$categoryMap = @{
  Audit       = @('01','02','03','04','05','06','07','09','10','11','13','14','15','18','19','20','22','23','24','26','27','28','29','30','31','32','33','34','35','36','37','38','39','40','41','42','43','44','45','46','47','48','49','50','51','52')
  Remediation = @('01','02','03','04','05','06','07','08','13','14','16','18','21','22','25','31','32','33','38','39','40','44')
  Collection  = @('09','10','11','12','20')
  Utility     = @('08','25')
  Monitoring  = @('17','32','34','38')
}

$scriptsDir = [System.IO.Path]::Combine($RootPath, 'scripts')
if (-not (Test-Path -LiteralPath $scriptsDir -PathType Container)) {
  Write-BatchTerminalResult -Result FAIL -Code 'Batch-MissingScriptsDirectory' -Message "Scripts directory not found: $scriptsDir"
  exit (Get-V2ExitCode -Result 'FAIL')
}

$allScripts = @(Get-ChildItem -LiteralPath $scriptsDir -Filter '*.ps1' -File | Where-Object { $_.Name -match '^\d{2}-' -and $_.Name -notmatch '^00-' })
$selected = @()

if ($Category -eq 'All') {
  $selected = @($allScripts | Sort-Object Name | Select-Object -ExpandProperty Name)
} else {
  $prefixes = $categoryMap[$Category]
  foreach ($prefix in $prefixes) {
    $match = @($allScripts | Where-Object { $_.Name -like "$prefix-*" } | Select-Object -ExpandProperty Name)
    $selected += $match
  }
  $selected = @($selected | Sort-Object -Unique)
}

if ($selected.Count -eq 0) {
  Write-BatchTerminalResult -Result FAIL -Code 'Batch-NoScriptsSelected' -Message "No scripts found for category '$Category'."
  exit (Get-V2ExitCode -Result 'FAIL')
}

$batchProfile = [ordered]@{
  ProfileName = "batch-$($Category.ToLowerInvariant())"
  Version     = '2.0'
  Defaults    = [ordered]@{
    Mode         = $Mode
    Strict       = [bool]$Strict
    OutputFormat = 'Console'
    OutputPath   = $null
  }
  Steps        = @()
  Integrity    = [ordered]@{
    RequireSigned = [bool]$RequireSigned
    ExpectedHashes = @{}
  }
}

foreach ($scriptName in $selected) {
  $batchProfile.Steps += [ordered]@{
    Script          = $scriptName
    Args            = @()
    ContinueOnError = [bool]$ContinueOnError
    DependsOn       = @()
  }
}

if (-not $PSCmdlet.ShouldProcess("batch-$($Category.ToLowerInvariant())", "Execute $($selected.Count) scripts via profile")) {
  Write-BatchTerminalResult -Result WARN -Code 'Batch-ExecutionSkipped' -Message 'Batch execution was skipped by WhatIf or confirmation.' -SelectedScripts $selected
  exit (Get-V2ExitCode -Result 'WARN')
}

$tempProfileDirectory = $null
$tempProfile = $null
$profileLockStream = $null
$exitCode = $null
$invocationError = $null
try {
  $tempProfileDirectory = New-BatchProfileWorkspace
  $tempProfile = Join-Path $tempProfileDirectory 'profile.json'
  $batchProfile | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $tempProfile -Encoding UTF8
  if ($isElevatedWindows) {
    Set-BatchAdminSystemAcl -Path $tempProfile
    Assert-RunBatchTrustedWindowsAcl -Path $tempProfile
  }

  # Permit validator/profile reads while denying writes, deletion, and
  # replacement through the complete Run-Profile invocation.
  $profileLockStream = New-Object System.IO.FileStream(
    $tempProfile,
    [System.IO.FileMode]::Open,
    [System.IO.FileAccess]::Read,
    [System.IO.FileShare]::Read
  )

  $params = @{
    ProfilePath  = $tempProfile
    Mode         = $Mode
    RootPath     = $RootPath
    OutputFormat = $OutputFormat
    OutputPath   = $OutputPath
    Strict       = $Strict
    RequireSigned = $RequireSigned
  }
  if ($PassThru) { $params.PassThru = $true }
  if ($WhatIfPreference) { $params.WhatIf = $true }
  if ($PSBoundParameters.ContainsKey('Confirm')) { $params.Confirm = [bool]$PSBoundParameters['Confirm'] }

  & $runProfilePath @params
  $exitCode = $LASTEXITCODE
} catch {
  $invocationError = $_.Exception.Message
} finally {
  if ($null -ne $profileLockStream) {
    $profileLockStream.Dispose()
  }
  if (-not [string]::IsNullOrWhiteSpace([string]$tempProfileDirectory) -and
      (Test-Path -LiteralPath $tempProfileDirectory)) {
    Remove-Item -LiteralPath $tempProfileDirectory -Recurse -Force -ErrorAction SilentlyContinue
  }
}

if (-not [string]::IsNullOrWhiteSpace([string]$invocationError)) {
  Write-BatchTerminalResult -Result FAIL -Code 'Batch-ProfileInvocationFailed' -Message $invocationError -SelectedScripts $selected
  exit (Get-V2ExitCode -Result 'FAIL')
}

if ($null -ne $exitCode) { exit [int]$exitCode }
exit (Get-V2ExitCode -Result 'OK')
