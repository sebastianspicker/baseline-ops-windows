#requires -version 5.1
<#
.SYNOPSIS
Verifies cross-root profile execution lease lifetime.
.DESCRIPTION
Checks that runner and target closure handles remain live through the parent
terminal callback and are released after owner cleanup.
#>

BeforeAll {
  $repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
  $leaseModule = Join-Path $repoRoot 'lib/ProfileExecutionLease.psm1'
  Import-Module $leaseModule -Force
  . (Join-Path $PSScriptRoot 'ProfileExecutionLease.TestSupport.ps1')
}

Describe 'Profile execution lease terminal lifetime' {
  BeforeEach {
    $fixture = New-LeaseFixture -BasePath $TestDrive -Name ([guid]::NewGuid().ToString('N'))
    $script:leaseHarness = New-LeaseHarness -BasePath $fixture.Root
    $script:leaseTarget = New-LeaseFixture -BasePath $TestDrive -Name ('target-' + [guid]::NewGuid().ToString('N'))
    $runnerLib = Join-Path $fixture.Root 'lib'
    [void](New-Item -ItemType Directory -Path $runnerLib)
    $console = Join-Path $runnerLib 'Console.psm1'
    $jsonInput = Join-Path $runnerLib 'JsonInput.psm1'
    [IO.File]::WriteAllText($console, 'console')
    [IO.File]::WriteAllText($jsonInput, 'json')
  }

  It 'keeps cross-root streams live through the parent terminal callback' {
    $lifetime = & $script:leaseHarness.Parent -Module $leaseModule -RunnerRoot $fixture.Root `
      -TargetRoot $script:leaseTarget.Root -Control $fixture.Control -Closure @($runnerLib, $script:leaseTarget.Closure) `
      -Probe $script:leaseHarness.Probe -ProbeMode Identity
    $lifetime.During | Should -BeTrue
    $lifetime.After | Should -BeFalse
  }

  It 'denies runner replacement during the callback and releases it afterward' `
      -Skip:([System.Environment]::OSVersion.Platform -ne [System.PlatformID]::Win32NT) {
    $lifetime = & $script:leaseHarness.Parent -Module $leaseModule -RunnerRoot $fixture.Root `
      -TargetRoot $script:leaseTarget.Root -Control $fixture.Control -Closure @($runnerLib, $script:leaseTarget.Closure) `
      -Probe $script:leaseHarness.Probe -ProbeMode ExclusiveWrite -ProbePaths @($console, $jsonInput)
    $lifetime.During | Should -BeFalse
    $lifetime.After | Should -BeTrue
  }
}
