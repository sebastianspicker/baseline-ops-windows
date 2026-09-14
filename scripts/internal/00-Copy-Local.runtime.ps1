#requires -version 5.1
<#
.SYNOPSIS
  Provides private transactional deployment phases.
.DESCRIPTION
  Preserves validated source acquisition, protected destination boundaries, commit recovery, and cleanup. The public bootstrap validates and retains every private file until its functions are loaded.
#>

function Assert-CopyLocalSourceArguments {
  param($RunState)
  # Validate deployment parameters to prevent option injection and unsafe paths.
  if ($RunState.RepoUrl -match '^\s*-') {
    throw 'RepoUrl must not start with "-" or leading whitespace (option injection prevention).'
  }
  if (-not [string]::IsNullOrWhiteSpace($RunState.RepoPath) -and $RunState.RepoPath -match '^\s*-') {
    throw 'RepoPath must not start with "-" or leading whitespace (option injection prevention).'
  }
  Assert-CopyLocalCommitArgument -RunState $RunState
}

function Assert-CopyLocalCommitArgument {
  param($RunState)
  if (-not [string]::IsNullOrWhiteSpace($RunState.RepoRef) -and $RunState.RepoRef -match '^\s*-') {
    throw 'RepoRef must not start with "-" or leading whitespace (option injection prevention).'
  }
  if (-not [string]::IsNullOrWhiteSpace($RunState.RepoRef) -and
    $RunState.RepoRef -notmatch '^[a-fA-F0-9]{40}([a-fA-F0-9]{24})?$') {
    throw 'RepoRef must be a full 40- or 64-character commit identifier; branches and tags are not accepted.'
  }
  if (-not [string]::IsNullOrWhiteSpace($RunState.RepoRef) -and -not (Test-ValidGitRef -Ref $RunState.RepoRef)) {
    throw "RepoRef '$($RunState.RepoRef)' is not a valid git ref (contains invalid characters or patterns)."
  }
}

function Assert-CopyLocalDestinationArgument {
  param($RunState)
  $destRootFull = [System.IO.Path]::GetFullPath($RunState.DestinationRoot)
  $destVolumeRoot = [System.IO.Path]::GetPathRoot($destRootFull)
  $separatorChars = @([System.IO.Path]::DirectorySeparatorChar, [System.IO.Path]::AltDirectorySeparatorChar)
  $destRootNormalized = $destRootFull.TrimEnd($separatorChars)
  $destVolumeNormalized = $destVolumeRoot.TrimEnd($separatorChars)
  if ([string]::IsNullOrWhiteSpace($destVolumeRoot) -or $destRootNormalized -eq $destVolumeNormalized) {
    throw 'DestinationRoot must be a subdirectory, not a volume root (e.g. use C:\install\mdm\ps1 not C:\).'
  }

}

function Assert-CopyLocalCloneOverlap {
  param($RunState)
  # A clone path in a deployed tree would collide with transactional replacement.
  # This is never safe.
  if (-not [string]::IsNullOrWhiteSpace($RunState.RepoPath) -and
    (Test-RepoPathOverlapsDeploymentTarget -RepoPath $RunState.RepoPath -DestinationRoot $RunState.DestinationRoot)) {
    throw 'RepoPath must not equal or be contained by DestinationRoot\\scripts or DestinationRoot\\lib.'
  }

}

function Write-CopyLocalSkipped {
  param($RunState)
  $RunState.resultToken = 'WARN'
  if ($RunState.Strict) {
    $RunState.resultToken = 'FAIL'
  }
  $v2Result = Get-V2ResultObject `
    -ScriptName '00-Copy-Local.ps1' `
    -Mode $RunState.Mode `
    -Result $RunState.resultToken `
    -Findings @([pscustomobject]@{
      Code = 'COPY-LOCAL-EXECUTION-SKIPPED'
      Severity = 'Info'
      Message = 'Repository synchronization was skipped by WhatIf or confirmation.'
    }) `
    -Summary ([pscustomobject]@{ DestinationRoot = $RunState.DestinationRoot
      RepoPath = $RunState.RepoPath
      Executed = $false
    }) `
    -Metadata @{}
  Write-ResultObject -ResultObject $v2Result -OutputFormat $RunState.OutputFormat -OutputPath $RunState.OutputPath
  if ($RunState.PassThru) {
    $v2Result
  }

}

function Write-CopyLocalSuccess {
  param($RunState)
  Write-UiLine "Installed scripts/ and lib/ from commit $($RunState.resolvedCommit) to $($RunState.DestinationRoot)"
  $v2Result = Get-V2ResultObject `
    -ScriptName '00-Copy-Local.ps1' `
    -Mode $RunState.Mode `
    -Result $RunState.resultToken `
    -Findings $RunState.findings `
    -Summary ([pscustomobject]@{
      DestinationRoot = $RunState.DestinationRoot
      RepoPath = $RunState.RepoPath
      RepoRef = $RunState.RepoRef
      Commit = $RunState.resolvedCommit
      DeploymentCommitted = $true
      BackupResidue = $RunState.backupResidue
    }) `
    -Metadata @{}
  Write-ResultObject -ResultObject $v2Result -OutputFormat $RunState.OutputFormat -OutputPath $RunState.OutputPath
  if ($RunState.PassThru) {
    $v2Result
  }

}

function Write-CopyLocalFailure {
  param($RunState, $ErrorRecord)
  $errorMessage = $ErrorRecord.Exception.Message
  $RunState.resultToken = 'FAIL'
  $failureFindings = New-Object System.Collections.Generic.List[object]
  [void]$failureFindings.Add([pscustomobject]@{
      Code = 'COPY-LOCAL-TERMINAL-FAIL'
      Severity = 'High'
      Message = $errorMessage
    })
  if ($RunState.rollbackResidue.Count -gt 0) {
    [void]$failureFindings.Add([pscustomobject]@{
        Code = 'COPY-LOCAL-DEPLOYMENT-ROLLBACK-RESIDUE'
        Severity = 'High'
        Message = 'Deployment rollback could not prove every target invariant; affected targets and retained backups are recorded in Data.'
        Data = [pscustomobject]@{ RollbackResidue = $RunState.rollbackResidue }
      })
  }
  $v2Result = Get-V2ResultObject `
    -ScriptName '00-Copy-Local.ps1' `
    -Mode $RunState.Mode `
    -Result $RunState.resultToken `
    -Findings $failureFindings.ToArray() `
    -Summary ([pscustomobject]@{ Error = $errorMessage
      RollbackResidue = $RunState.rollbackResidue
    }) `
    -Metadata @{}
  Write-ResultObject -ResultObject $v2Result -OutputFormat $RunState.OutputFormat -OutputPath $RunState.OutputPath
  if ($RunState.PassThru) {
    $v2Result
  }

}

function Clear-CopyLocalRun {
  param($RunState)
  if ($null -ne $RunState.gitExecutableLock) {
    $RunState.gitExecutableLock.Dispose()
  }
  if ($RunState.gitEnvironmentActive) {
    Restore-CopyLocalGitEnvironment -Snapshot $RunState.gitEnvironmentSnapshot
  }
  Remove-CopyLocalTemporaryDirectories -RunState $RunState
  if (-not $RunState.deploymentCommitted -and $RunState.destinationCreatedPaths.Count -gt 0) {
    Remove-CopyLocalEmptyCreatedDirectory -CreatedPaths $RunState.destinationCreatedPaths -Confirm:$false
  }
  if ($null -ne $RunState.destinationLock) {
    $RunState.destinationLock.Dispose()
  }

}

function Invoke-CopyLocalDeployment {
  param($RunState)
  Initialize-CopyLocalDeployment -RunState $RunState
  Resolve-CopyLocalClonePath -RunState $RunState
  Assert-CopyLocalRepositoryUrl -RunState $RunState
  Open-CopyLocalGitExecutable -RunState $RunState
  Initialize-CopyLocalGitEnvironment -RunState $RunState
  Invoke-CopyLocalClone -RunState $RunState
  Resolve-CopyLocalCommit -RunState $RunState
  Assert-CopyLocalSourceTree -RunState $RunState
  Copy-CopyLocalDeploymentStage -RunState $RunState
  Assert-CopyLocalCommitBoundary -RunState $RunState
  Invoke-CopyLocalDeploymentSwap -RunState $RunState
  Complete-CopyLocalDeployment -RunState $RunState
}

function New-CopyLocalRunState {
  param([hashtable]$Inputs)
  $RunState = @{}
  foreach ($key in $Inputs.Keys) {
    $RunState[$key] = $Inputs[$key]
  }
  $RunState.gitExecutableLock = $null
  $RunState.hooksPath = $null
  $RunState.deployStage = $null
  $RunState.stagingRoot = $null
  $RunState.clonePath = $null
  $RunState.destinationLock = $null
  $RunState.destinationCreatedPaths = New-Object System.Collections.Generic.List[string]
  $RunState.deploymentCommitted = $false
  $RunState.rollbackResidue = @()
  $RunState.gitEnvironmentSnapshot = New-Object System.Collections.Generic.List[object]
  $RunState.gitEnvironmentActive = $false
  return $RunState
}

function Remove-CopyLocalTemporaryDirectories {
  param($RunState)
  foreach ($path in @($RunState.deployStage, $RunState.hooksPath, $RunState.clonePath)) {
    if (-not [string]::IsNullOrWhiteSpace($path) -and (Test-Path -LiteralPath $path)) {
      Remove-Item -LiteralPath $path -Recurse -Force -ErrorAction SilentlyContinue
    }
  }
}
