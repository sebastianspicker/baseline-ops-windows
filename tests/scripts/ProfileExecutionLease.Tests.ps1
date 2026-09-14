#requires -version 5.1
<#
.SYNOPSIS
Verifies profile execution lease identity, root binding, and disposal behavior.
.DESCRIPTION
Exercises the private module registry and portable handle lifecycle with named
runner harnesses; Windows-only replacement-denial assertions remain explicit.
#>

BeforeAll {
  $repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
  $leaseModule = Join-Path $repoRoot 'lib/ProfileExecutionLease.psm1'
  Import-Module $leaseModule -Force
  . (Join-Path $PSScriptRoot 'ProfileExecutionLease.TestSupport.ps1')
}

Describe 'Profile execution lease registry' {
  BeforeEach { $fixture=New-LeaseFixture -BasePath $TestDrive -Name ([guid]::NewGuid().ToString('N'));$script:leaseHarness=New-LeaseHarness -BasePath $fixture.Root }

  It 'rejects forged identities and disposed leases while disposal stays idempotent' {
    { Get-ProfileExecutionLeaseInfo -Lease ([pscustomobject]@{Kind='ProfileOwner';RunnerRoot=$fixture.Root;TargetRoot=$fixture.Root}) } | Should -Throw '*identity*'
    $lease=& $script:leaseHarness.Parent -Module $leaseModule -RunnerRoot $fixture.Root -TargetRoot $fixture.Root -Control $fixture.Control -Closure $fixture.Closure -CloseTwice
    { Get-ProfileExecutionLeaseInfo -Lease $lease } | Should -Throw '*no longer live*'
  }

  It 'reuses one live exact-root owner and leaves owner handles live after borrowers close' {
    $info=@(& $script:leaseHarness.Parent -Module $leaseModule -RunnerRoot $fixture.Root -TargetRoot $fixture.Root -Control $fixture.Control -Closure $fixture.Closure -Child $script:leaseHarness.Child -ChildTargetRoot $fixture.Root -ChildControl (Join-Path $fixture.Root 'missing') -ChildClosure (Join-Path $fixture.Root 'missing'))
    $info.Count | Should -Be 2;$info[0].Kind | Should -Be 'Borrower';$info[0].StreamCount | Should -Be 0;$info[1].Kind | Should -Be 'ProfileOwner';$info[1].StreamCount | Should -Be 2
  }

  It 'allows only the registered owner invocation to dispose a live owner lease' {
    (& $script:leaseHarness.Parent -Module $leaseModule -RunnerRoot $fixture.Root -TargetRoot $fixture.Root -Control $fixture.Control -Closure $fixture.Closure -Rogue $script:leaseHarness.Rogue)|Should -BeTrue
  }

  It 'fails closed for sibling-prefix root mismatches and disposed owners' {
    $sibling=New-LeaseFixture -BasePath $TestDrive -Name ((Split-Path -Leaf $fixture.Root)+'-sibling')
    { & $script:leaseHarness.Parent -Module $leaseModule -RunnerRoot $fixture.Root -TargetRoot $fixture.Root -Control $fixture.Control -Closure $fixture.Closure -Child $script:leaseHarness.Child -ChildTargetRoot $sibling.Root -ChildControl $sibling.Control -ChildClosure $sibling.Closure } | Should -Throw '*roots do not match*'
    { & $script:leaseHarness.Parent -Module $leaseModule -RunnerRoot $fixture.Root -TargetRoot $fixture.Root -Control $fixture.Control -Closure $fixture.Closure -Child $script:leaseHarness.Child -ChildTargetRoot $fixture.Root -ChildControl $fixture.Control -ChildClosure $fixture.Closure -DisposeBeforeChild } | Should -Throw '*disposed*'
  }

  It 'acquires and disposes an independent direct RunLocal owner' {
    $info=& $script:leaseHarness.Child -Module $leaseModule -RunnerRoot $fixture.Root -TargetRoot $fixture.Root -Control $fixture.Control -Closure $fixture.Closure
    $info.Kind | Should -Be 'DirectOwner';$info.StreamCount | Should -Be 2
    { [IO.File]::Open($fixture.Control,[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None).Dispose() } | Should -Not -Throw
  }

  It 'cleans acquired streams when a later path fails' {
    $missing=Join-Path $fixture.Root 'missing.ps1'
    { & $script:leaseHarness.Parent -Module $leaseModule -RunnerRoot $fixture.Root -TargetRoot $fixture.Root -Control @($fixture.Control,$missing) -Closure $fixture.Closure } | Should -Throw
    { [IO.File]::Open($fixture.Control,[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None).Dispose() } | Should -Not -Throw
  }

  It 'keeps the bounded closure item cap' {
    { & $script:leaseHarness.Parent -Module $leaseModule -RunnerRoot $fixture.Root -TargetRoot $fixture.Root -Control $fixture.Control -Closure $fixture.Closure -MaximumItems 2 } | Should -Throw
  }

  It 'rejects reparse-point closure entries' {
    $target=Join-Path $fixture.Root 'outside.ps1';[IO.File]::WriteAllText($target,'outside');$link=Join-Path $fixture.Closure 'linked.ps1'
    try { [void](New-Item -ItemType SymbolicLink -Path $link -Target $target -ErrorAction Stop) } catch { Set-ItResult -Skipped -Because 'Symbolic links are unavailable.';return }
    { & $script:leaseHarness.Parent -Module $leaseModule -RunnerRoot $fixture.Root -TargetRoot $fixture.Root -Control $fixture.Control -Closure $fixture.Closure } | Should -Throw '*reparse-point*'
  }

  It 'denies target write delete and rename while the owner is live' -Skip:([System.Environment]::OSVersion.Platform -ne [System.PlatformID]::Win32NT) {
    $denial=& $script:leaseHarness.Parent -Module $leaseModule -RunnerRoot $fixture.Root -TargetRoot $fixture.Root -Control $fixture.Control -Closure $fixture.Closure -TestDeny
    $denial.WriteDenied|Should -BeTrue;$denial.DeleteDenied|Should -BeTrue;$denial.RenameDenied|Should -BeTrue
  }
}
