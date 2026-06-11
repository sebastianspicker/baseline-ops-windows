#requires -version 5.1
<#
.SYNOPSIS
Pull latest repo version and copy "scripts" and "lib" to C:\install\mdm\ps1\.

.DESCRIPTION
Ensures the repo is cloned/pulled locally and then copies scripts/ and lib/
into the destination root.

.PARAMETER RepoUrl
Git repository URL to pull from.

.PARAMETER DestinationRoot
Destination root (default: C:\install\mdm\ps1).

.PARAMETER RepoPath
Local clone path (default: <DestinationRoot>\_repo).

.PARAMETER RepoRef
Optional git ref (tag/branch/commit) to check out for deterministic deployments.

.PARAMETER AllowUnsafeRepoPath
Bypass safety guardrails for RepoPath deletion (use with caution).

.EXAMPLE
.\00-Copy-Local.ps1

.EXAMPLE
.\00-Copy-Local.ps1 -DestinationRoot D:\mdm\ps1

.EXAMPLE
.\00-Copy-Local.ps1 -RepoUrl https://github.com/org/repo.git
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
  [string]$RepoUrl = 'https://github.com/sebastianspicker/win-mdm-security-hardening-kit.git',
  [string]$DestinationRoot = 'C:\install\mdm\ps1',
  [string]$RepoPath,
  [string]$RepoRef,
  [switch]$AllowUnsafeRepoPath

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

. (Join-Path $PSScriptRoot '_lib/Bootstrap.ps1')
Import-Module (Join-Path $script:LibPath 'Output.psm1') -Force
Import-Module (Join-Path $script:LibPath 'Validation.psm1') -Force

Set-StrictMode -Version Latest
# v2-init (migrated to Initialize-V2Context)
Initialize-V2Context -ScriptName '00-Copy-Local.ps1' -BoundParameters $PSBoundParameters
$ErrorActionPreference = 'Stop'

# Validate deployment parameters to prevent option injection and unsafe paths (§10/§23/§24)
if ($RepoUrl -match '^\s*-') {
  throw 'RepoUrl must not start with "-" or leading whitespace (option injection prevention).'
}
if (-not [string]::IsNullOrWhiteSpace($RepoPath) -and $RepoPath -match '^\s*-') {
  throw 'RepoPath must not start with "-" or leading whitespace (option injection prevention).'
}
if (-not [string]::IsNullOrWhiteSpace($RepoRef) -and $RepoRef -match '^\s*-') {
  throw 'RepoRef must not start with "-" or leading whitespace (option injection prevention).'
}
if (-not [string]::IsNullOrWhiteSpace($RepoRef) -and -not (Test-ValidGitRef -Ref $RepoRef)) {
  throw "RepoRef '$RepoRef' is not a valid git ref (contains invalid characters or patterns)."
}
$destRootFull = [System.IO.Path]::GetFullPath($DestinationRoot)
$destRootRoot = [System.IO.Path]::GetPathRoot($destRootFull).TrimEnd([System.IO.Path]::DirectorySeparatorChar)
if ($destRootFull -eq $destRootRoot -or [string]::IsNullOrWhiteSpace($destRootRoot)) {
  throw 'DestinationRoot must be a subdirectory, not a volume root (e.g. use C:\install\mdm\ps1 not C:\).'
}

function Invoke-GitCommand {
  [CmdletBinding()]
  param([Parameter(Mandatory)][string[]]$GitArgs)
  & git.exe @GitArgs
  if ($LASTEXITCODE -ne 0) {
    throw ("git failed (exit {0}): git {1}" -f $LASTEXITCODE, ($GitArgs -join ' '))
  }
}

function Get-FullPath {
  [CmdletBinding()]
  param([Parameter(Mandatory)][string]$Path)
  try { return [System.IO.Path]::GetFullPath($Path) } catch { return $Path }
}

function Test-RepoPathSafe {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$RepoPath,
    [Parameter(Mandatory)][string]$DestinationRoot,
    [switch]$AllowUnsafeRepoPath
  )

  if ($AllowUnsafeRepoPath) { return $true }

  $repoFull = Get-FullPath -Path $RepoPath
  $destFull = Get-FullPath -Path $DestinationRoot
  $sep = [System.IO.Path]::DirectorySeparatorChar

  $repoTrim = $repoFull.TrimEnd($sep)
  $destTrim = $destFull.TrimEnd($sep)
  $root = [System.IO.Path]::GetPathRoot($repoTrim).TrimEnd($sep)

  if ([string]::IsNullOrWhiteSpace($root)) { return $false }
  if ($repoTrim -eq $root) { return $false }
  if ($repoTrim -eq $destTrim) { return $false }

  $destPrefix = $destTrim + $sep
  return $repoFull.StartsWith($destPrefix, [System.StringComparison]::OrdinalIgnoreCase)
}

if (-not $RepoPath) {
  $RepoPath = Join-Path $DestinationRoot '_repo'
}

if (-not (Get-Command -Name git.exe -ErrorAction SilentlyContinue)) {
  throw 'git.exe not found. Install Git or add it to PATH.'
}

if (-not (Test-Path -LiteralPath $DestinationRoot)) {
  New-Item -Path $DestinationRoot -ItemType Directory -Force | Out-Null
}

if (Test-Path -LiteralPath (Join-Path $RepoPath '.git')) {
  # Verify existing clone matches intended RepoUrl to avoid supply-chain drift (§24)
  try {
    $configuredRemote = (git -C $RepoPath remote get-url origin 2>$null).Trim()
    $normalizedUrl = $RepoUrl.Trim().ToLowerInvariant()
    $normalizedRemote = $configuredRemote.Trim().ToLowerInvariant()
    if (-not [string]::IsNullOrWhiteSpace($configuredRemote) -and $normalizedRemote -ne $normalizedUrl) {
      throw ("Configured remote URL does not match -RepoUrl. Remote: {0}; Expected: {1}. Use a clean path or re-clone." -f $configuredRemote, $RepoUrl)
    }
  } catch {
    if ($_.Exception.Message -match 'does not match') { throw }
    # git remote get-url can fail if no origin; continue
  }
  Invoke-GitCommand -GitArgs @('-C', $RepoPath, 'fetch', '--all', '--prune', '--tags')
  if ($RepoRef) {
    Invoke-GitCommand -GitArgs @('-C', $RepoPath, 'checkout', $RepoRef)
  } else {
    Invoke-GitCommand -GitArgs @('-C', $RepoPath, 'pull', '--ff-only')
  }
} else {
  if (Test-Path -LiteralPath $RepoPath) {
    if (-not (Test-RepoPathSafe -RepoPath $RepoPath -DestinationRoot $DestinationRoot -AllowUnsafeRepoPath:$AllowUnsafeRepoPath)) {
      throw "Unsafe RepoPath for deletion: $RepoPath. Place RepoPath under DestinationRoot or pass -AllowUnsafeRepoPath to override."
    }
    if ($PSCmdlet.ShouldProcess($RepoPath, 'Remove existing non-git repo path')) {
      Remove-Item -LiteralPath $RepoPath -Recurse -Force
    } else {
      throw 'Deletion declined by ShouldProcess. Aborting.'
    }
  }
  $cloneArgs = @('clone')
  if (-not $RepoRef) { $cloneArgs += @('--depth','1') }
  $cloneArgs += @($RepoUrl, $RepoPath)
  Invoke-GitCommand -GitArgs $cloneArgs
  if ($RepoRef) {
    Invoke-GitCommand -GitArgs @('-C', $RepoPath, 'checkout', $RepoRef)
  }
}

$sourceScripts = Join-Path $RepoPath 'scripts'
$sourceLib = Join-Path $RepoPath 'lib'

if (-not (Test-Path -LiteralPath $sourceScripts)) {
  throw "Source scripts folder not found after pull: $sourceScripts"
}
if (-not (Test-Path -LiteralPath $sourceLib)) {
  throw "Source lib folder not found after pull: $sourceLib"
}

Copy-Item -Path $sourceScripts -Destination $DestinationRoot -Recurse -Force
Copy-Item -Path $sourceLib -Destination $DestinationRoot -Recurse -Force

Write-UiLine "Copied scripts/ and lib/ to $DestinationRoot"
exit 0
