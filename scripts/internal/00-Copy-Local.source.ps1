#requires -version 5.1
<#
.SYNOPSIS
  Provides private transactional deployment phases.
.DESCRIPTION
  Preserves validated source acquisition, protected destination boundaries, commit recovery, and cleanup. The public bootstrap validates and retains every private file until its functions are loaded.
#>

function Resolve-CopyLocalClonePath {
  param($RunState)
  if ([string]::IsNullOrWhiteSpace($RunState.RepoPath)) {
    $RunState.RepoPath = Join-Path $RunState.stagingRoot ('clone-{0}' -f [guid]::NewGuid().ToString('N'))
  }
  else {
    $repoPathFull = Get-FullPath -Path $RunState.RepoPath
    if (-not (Test-PathUnderRoot -Path $repoPathFull -Root $RunState.stagingRoot)) {
      throw 'RepoPath must be within the fixed trusted staging root.'
    }
    $RunState.RepoPath = $repoPathFull
  }
  if (Test-Path -LiteralPath $RunState.RepoPath) {
    throw 'RepoPath already exists; refusing to reuse or remove an existing clone.'
  }
  $RunState.clonePath = $RunState.RepoPath

}

function Assert-CopyLocalRepositoryUrl {
  param($RunState)
  $repoUri = $null
  if (-not [System.Uri]::TryCreate($RunState.RepoUrl, [System.UriKind]::Absolute, [ref]$repoUri) -or
    $repoUri.Scheme -ne 'https' -or -not [string]::IsNullOrEmpty($repoUri.UserInfo)) {
    throw 'RepoUrl must be an absolute HTTPS URL without embedded credentials.'
  }

}

function Get-CopyLocalGitCandidate {
  param([string]$GitPath)
  $gitCandidate = $null
  $explicitGitPath = -not [string]::IsNullOrWhiteSpace($GitPath)
  if ($explicitGitPath) {
    if (-not [System.IO.Path]::IsPathRooted($GitPath)) {
      throw 'GitPath must be absolute.'
    }
    $gitCandidate = $GitPath
  }
  elseif ($env:OS -eq 'Windows_NT') {
    $gitCandidate = Resolve-TrustedGitPath
  }
  else {
    $gitCommand = Get-Command -Name git -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($gitCommand) {
      $gitCandidate = $gitCommand.Source
    }
  }
  return $gitCandidate
}

function Open-CopyLocalGitExecutable {
  param($RunState)
  $gitCandidate = Get-CopyLocalGitCandidate -GitPath $RunState.GitPath
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
  $RunState.gitExecutableLock = [System.IO.File]::Open($script:GitExecutablePath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)

}

function Initialize-CopyLocalGitEnvironment {
  param($RunState)
  $RunState.gitEnvironmentActive = $true
  Enable-CopyLocalSafeGitEnvironment -Snapshot $RunState.gitEnvironmentSnapshot
  $RunState.hooksPath = Join-Path $RunState.stagingRoot ('.git-hooks-{0}' -f [guid]::NewGuid().ToString('N'))
  [void][System.IO.Directory]::CreateDirectory($RunState.hooksPath)

}

function Invoke-CopyLocalClone {
  param($RunState)
  $cloneArgs = @('clone', '--no-checkout')
  $cloneArgs += @('--', $RunState.RepoUrl, $RunState.RepoPath)
  Invoke-GitCommand -RunState $RunState -GitArgs $cloneArgs | Out-Null
  $remoteResult = Invoke-GitCommand -RunState $RunState -GitArgs @('-C', $RunState.RepoPath, 'remote', 'get-url', 'origin')
  $configuredRemote = $remoteResult.Stdout.Trim()
  if (-not [string]::Equals($configuredRemote, $RunState.RepoUrl.Trim(), [System.StringComparison]::Ordinal)) {
    throw 'Fresh clone origin does not exactly match RepoUrl.'
  }

}

function Resolve-CopyLocalCommit {
  param($RunState)
  $requestedRef = $RunState.RepoRef
  $commitResult = Invoke-GitCommand -RunState $RunState -GitArgs @('-C', $RunState.RepoPath, 'rev-parse', '--verify', ("{0}^{{commit}}" -f $requestedRef)) -AllowFailure
  if (-not $commitResult.Success) {
    throw "RepoRef could not be resolved to a commit: $requestedRef"
  }
  $RunState.resolvedCommit = $commitResult.Stdout.Trim()
  if ($RunState.resolvedCommit -notmatch '^[a-fA-F0-9]{40}([a-fA-F0-9]{24})?$') {
    throw 'Git did not resolve a valid commit object.'
  }
  if (-not [string]::Equals($RunState.resolvedCommit, $RunState.RepoRef, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw 'Resolved commit does not match the authenticated RepoRef.'
  }
  Invoke-GitCommand -RunState $RunState -GitArgs @('-C', $RunState.RepoPath, 'checkout', '--force', '--detach', $RunState.resolvedCommit, '--') | Out-Null

}

function Assert-CopyLocalSourceTree {
  param($RunState)
  $statusResult = Invoke-GitCommand -RunState $RunState -GitArgs @('-C', $RunState.RepoPath, 'status', '--porcelain=v1', '-z', '--untracked-files=all', '--ignored=matching', '--', 'scripts', 'lib')
  if (-not [string]::IsNullOrEmpty($statusResult.Stdout)) {
    throw 'Fresh clone scripts/lib worktree is not clean.'
  }
  $RunState.sourceScripts = Join-Path $RunState.RepoPath 'scripts'
  $RunState.sourceLib = Join-Path $RunState.RepoPath 'lib'
  if (-not (Test-Path -LiteralPath $RunState.sourceScripts -PathType Container)) {
    throw "Source scripts folder not found after pull: $($RunState.sourceScripts)"
  }
  if (-not (Test-Path -LiteralPath $RunState.sourceLib -PathType Container)) {
    throw "Source lib folder not found after pull: $($RunState.sourceLib)"
  }
  $repoResolved = (Resolve-Path -LiteralPath $RunState.RepoPath -ErrorAction Stop).ProviderPath
  if (Test-PathContainsReparsePoint -Path $repoResolved -Root $RunState.stagingRoot) {
    throw 'Fresh clone path contains a reparse point.'
  }
  foreach ($item in Get-ChildItem -LiteralPath $RunState.sourceScripts, $RunState.sourceLib -Recurse -Force) {
    if ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
      throw "Fresh clone contains a reparse point: $($item.FullName)"
    }
  }

}
