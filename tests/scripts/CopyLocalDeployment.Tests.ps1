#requires -version 5.1
<#
.SYNOPSIS
Verifies transactional deployment and Git input boundaries.
.DESCRIPTION
Exercises private deployment phases with temporary directories and controlled protection providers. No repository clone or endpoint remediation is performed.
#>
BeforeAll {
  . (Join-Path $PSScriptRoot '../../scripts/internal/00-Copy-Local.helpers.ps1')
  $script:ProtectionCalls = [Collections.Generic.List[object]]::new()
  function Test-PathContainsReparsePoint {
    param($Path, $Root)
    $script:ProtectionCalls.Add(@{ Operation = 'Reparse'; Path = $Path; Root = $Root })
    return $false
  }
  function Protect-CopyLocalDestinationAcl {
    param($Path)
    $script:ProtectionCalls.Add(@{ Operation = 'Protect'; Path = $Path })
  }
  function Assert-CopyLocalDestinationAclTrust {
    param($Path, [switch]$RequireProtected)
    $script:ProtectionCalls.Add(@{ Operation = 'Acl'; Path = $Path; RequireProtected = [bool]$RequireProtected })
  }
  function Assert-CopyLocalAncestorChainTrust {
    param($Path, $BoundaryLabel)
    $script:ProtectionCalls.Add(@{ Operation = 'Ancestor'; Path = $Path; Label = $BoundaryLabel })
  }
  function New-CopyLocalTestState {
    param($Root)
    $state = New-CopyLocalRunState -Inputs @{ DestinationRoot = $Root; Strict = $false }
    $state.destinationResolved = Join-Path $Root 'destination'
    $state.deployStage = Join-Path $Root 'stage'
    foreach ($parent in @($state.destinationResolved, $state.deployStage)) {
      foreach ($name in @('scripts', 'lib')) {
        $path = Join-Path $parent $name
        [void][IO.Directory]::CreateDirectory($path)
        [IO.File]::WriteAllText((Join-Path $path 'identity.txt'), $parent)
      }
    }
    return $state
  }
}
Describe 'CopyLocal transactional deployment' {
  BeforeEach { $script:ProtectionCalls.Clear() }
  It 'commits both incoming directories before deleting previous versions' {
    $state = New-CopyLocalTestState -Root (Join-Path $TestDrive 'commit')
    Invoke-CopyLocalDeploymentSwap -RunState $state
    $state.deploymentCommitted | Should -BeFalse
    @($script:ProtectionCalls | Where-Object Operation -eq Protect).Count | Should -Be 2
    $script:ProtectionCalls[-1].Operation | Should -Be 'Ancestor'
    foreach ($swap in $state.swaps) {
      [IO.File]::ReadAllText((Join-Path $swap.Target 'identity.txt')) | Should -Be $state.deployStage
      Test-Path -LiteralPath $swap.Backup | Should -BeTrue
    }
    Complete-CopyLocalDeployment -RunState $state
    $state.deploymentCommitted | Should -BeTrue
    $state.resultToken | Should -Be 'OK'
    $state.backupResidue.Count | Should -Be 0
    foreach ($swap in $state.swaps) { Test-Path -LiteralPath $swap.Backup | Should -BeFalse }
  }
  It 'restores both original directories when the second incoming directory is missing' {
    $state = New-CopyLocalTestState -Root (Join-Path $TestDrive 'rollback')
    Remove-Item -LiteralPath (Join-Path $state.deployStage 'lib') -Recurse -Force
    { Invoke-CopyLocalDeploymentSwap -RunState $state } | Should -Throw
    $state.deploymentCommitted | Should -BeFalse
    $state.rollbackResidue.Count | Should -Be 0
    foreach ($name in @('scripts', 'lib')) {
      [IO.File]::ReadAllText((Join-Path (Join-Path $state.destinationResolved $name) 'identity.txt')) | Should -Be $state.destinationResolved
    }
  }
  It 'rejects a reparse point detected after the directory swaps and rolls back' {
    $state = New-CopyLocalTestState -Root (Join-Path $TestDrive 'boundary')
    Mock Test-PathContainsReparsePoint { return $true }
    { Invoke-CopyLocalDeploymentSwap -RunState $state } | Should -Throw '*reparse point*'
    foreach ($name in @('scripts', 'lib')) {
      [IO.File]::ReadAllText((Join-Path (Join-Path $state.destinationResolved $name) 'identity.txt')) | Should -Be $state.destinationResolved
    }
  }
}
