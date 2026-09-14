#requires -version 5.1
<#
.SYNOPSIS
Verifies runner integration with the private execution lease.
.DESCRIPTION
Checks acquisition order, shared-module import, terminal disposal, public caller frames, and retained target verification contracts.
#>
BeforeAll {
  . (Join-Path $PSScriptRoot 'ProfileExecutionLease.Integration.Cases.ps1')
  $script:leaseRepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
  $script:profileSource = Get-Content -LiteralPath (Join-Path $script:leaseRepoRoot 'scripts/00-Run-Profile.ps1') -Raw
  $script:localSource = Get-Content -LiteralPath (Join-Path $script:leaseRepoRoot 'scripts/00-Run-Local.ps1') -Raw
  $script:localRuntimeSource = Get-Content -LiteralPath (Join-Path $script:leaseRepoRoot 'scripts/internal/00-Run-Local.runtime.ps1') -Raw
}

Describe 'Runner lease integration source' {
  It 'imports one shared module instance and keeps each owner through its public terminal boundary' {
    Test-RunnerLeaseImportsAndLifetime $script:profileSource $script:localSource
  }

  It 'acquires the profile closure before loading validation code and covers both roots' {
    Test-ProfileLeaseAcquisitionAndRoots $script:profileSource
  }

  It 'defines validator and child invocation frames in the public profile runner' {
    Test-ProfilePublicInvocationFrames $script:profileSource
  }

  It 'keeps independent RunLocal verification on the retained leaf handle' {
    Test-RunLocalLeaseAndTargetHandle $script:localSource $script:localRuntimeSource
  }
}
