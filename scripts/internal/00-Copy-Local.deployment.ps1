#requires -version 5.1
<#
.SYNOPSIS
  Provides private transactional deployment phases.
.DESCRIPTION
  Preserves validated source acquisition, protected destination boundaries, commit recovery, and cleanup. The public bootstrap validates and retains every private file until its functions are loaded.
#>

function Initialize-CopyLocalDeployment {
  param($RunState)
  if ([string]::IsNullOrWhiteSpace($RunState.RepoRef)) {
    throw 'RepoRef is required and must be the full commit identifier from authenticated release provenance.'
  }
  # Reject an unsafe existing destination before creating staging or changing any
  # destination ACL. This is repeated under the destination lock below.
  if (Test-Path -LiteralPath $RunState.DestinationRoot) {
    [void](Resolve-CopyLocalDestinationBoundary -DestinationRoot $RunState.DestinationRoot)
  }
  $RunState.stagingRoot = Initialize-CopyLocalStagingRoot
  $RunState.destinationLock = Enter-CopyLocalDestinationLock -DestinationRoot $RunState.DestinationRoot -StagingRoot $RunState.stagingRoot
  if (-not (Test-Path -LiteralPath $RunState.DestinationRoot)) {
    Initialize-CopyLocalDestinationRoot -DestinationRoot $RunState.DestinationRoot `
      -CreatedPaths $RunState.destinationCreatedPaths -Confirm:$false
  }
  $RunState.destinationResolved = Resolve-CopyLocalDestinationBoundary -DestinationRoot $RunState.DestinationRoot
  $RunState.destinationVolume = [System.IO.Path]::GetPathRoot($RunState.destinationResolved)
  Protect-CopyLocalDestinationAcl -Path $RunState.destinationResolved

}

function Copy-CopyLocalDeploymentStage {
  param($RunState)
  $RunState.deployStage = Join-Path $RunState.stagingRoot ('.deploy-{0}' -f [guid]::NewGuid().ToString('N'))
  [void][System.IO.Directory]::CreateDirectory($RunState.deployStage)
  Copy-Item -LiteralPath $RunState.sourceScripts -Destination $RunState.deployStage -Recurse -Force
  Copy-Item -LiteralPath $RunState.sourceLib -Destination $RunState.deployStage -Recurse -Force

}

function Assert-CopyLocalCommitBoundary {
  param($RunState)
  # Revalidate the destination boundary immediately before the commit. The
  # destination lock serializes cooperating CopyLocal processes; the ACL and
  # reparse checks reject changes by identities outside the trusted writer set.
  if (Test-PathContainsReparsePoint -Path $RunState.destinationResolved -Root $RunState.destinationVolume) {
    throw 'DestinationRoot or one of its ancestors became a reparse point before deployment.'
  }
  Assert-CopyLocalDestinationAclTrust -Path $RunState.destinationResolved -RequireProtected
  foreach ($name in @('scripts', 'lib')) {
    $deploymentTarget = Join-Path $RunState.destinationResolved $name
    if (-not (Test-Path -LiteralPath $deploymentTarget)) {
      continue
    }
    if (Test-PathContainsReparsePoint -Path $deploymentTarget -Root $RunState.destinationResolved) {
      throw "Existing deployment target '$name' became a reparse point before deployment."
    }
    Assert-CopyLocalDestinationAclTrust -Path $deploymentTarget
  }

}

function Invoke-CopyLocalDeploymentSwap {
  param($RunState)
  $RunState.swaps = New-Object System.Collections.Generic.List[object]
  try {
    foreach ($name in @('scripts', 'lib')) {
      $target = Join-Path $RunState.destinationResolved $name
      $incoming = Join-Path $RunState.deployStage $name
      $backup = Join-Path $RunState.destinationResolved ('.{0}.previous-{1}' -f $name, [guid]::NewGuid().ToString('N'))
      $hadExisting = Test-Path -LiteralPath $target
      if ($hadExisting) {
        Move-Item -LiteralPath $target -Destination $backup -ErrorAction Stop
      }
      [void]$RunState.swaps.Add([pscustomobject]@{ Target = $target
          Backup = $backup
          HadExisting = $hadExisting
          Installed = $false
        })
      Move-Item -LiteralPath $incoming -Destination $target -ErrorAction Stop
      $RunState.swaps[$RunState.swaps.Count - 1].Installed = $true
    }
    Assert-CopyLocalCommittedDeployment -RunState $RunState
  }
  catch {
    $swapError = $_
    $RunState.rollbackResidue = @(Restore-CopyLocalDeploymentSwaps -Swaps $RunState.swaps)
    if ($RunState.rollbackResidue.Count -gt 0) {
      throw [System.InvalidOperationException]::new(
        ("Deployment swap failed: {0} Rollback residue was retained; inspect the terminal result RollbackResidue data." -f $swapError.Exception.Message),
        $swapError.Exception)
    }
    throw $swapError
  }

}

function Complete-CopyLocalDeployment {
  param($RunState)
  $RunState.deploymentCommitted = $true
  $RunState.backupResidue = @(Remove-CopyLocalCommittedBackup -Swaps $RunState.swaps)
  $RunState.findings = @()
  $RunState.resultToken = 'OK'
  if ($RunState.backupResidue.Count -gt 0) {
    $RunState.resultToken = if ($RunState.Strict) {
      'FAIL'
    }
    else {
      'WARN'
    }
    $RunState.findings = @([pscustomobject]@{
        Code = 'COPY-LOCAL-BACKUP-CLEANUP-RESIDUE'
        Severity = 'Medium'
        Message = 'Deployment committed successfully, but one or more previous-version backup directories could not be removed.'
        Data = [pscustomobject]@{ Residue = $RunState.backupResidue }
      })
  }

}

function Assert-CopyLocalCommittedDeployment {
  param($RunState)
  foreach ($name in @('scripts', 'lib')) {
    $target = Join-Path $RunState.destinationResolved $name
    if (-not (Test-Path -LiteralPath $target -PathType Container)) {
      throw "Committed deployment target '$name' is missing."
    }
    if (Test-PathContainsReparsePoint -Path $target -Root $RunState.destinationResolved) {
      throw "Committed deployment target '$name' contains a reparse point."
    }
    Protect-CopyLocalDestinationAcl -Path $target
  }
  Assert-CopyLocalDestinationAclTrust -Path $RunState.destinationResolved -RequireProtected
  Assert-CopyLocalAncestorChainTrust -Path $RunState.destinationResolved -BoundaryLabel 'Destination'
}
