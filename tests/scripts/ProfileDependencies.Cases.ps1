#requires -version 5.1
<#
.SYNOPSIS
Cases for the Run-Profile dependency ordering characterization tests.
.DESCRIPTION
Stubs the step executor and holds the Test-* behavior functions invoked by
ProfileDependencies.Tests.ps1. Drives Invoke-RunProfileSchedule from
scripts/internal/00-Run-Profile.scheduler.ps1 with the stub so ordering, skip
propagation, stop-on-failure, and dependency-cycle findings are pinned without
executing any capability.
#>

# Stub the executor: records execution order; statuses come from $script:stubStatus.
function Invoke-RunProfileStep {
  param($Options, $State, $Bootstrap, $Step)
  $null = $Options, $State, $Bootstrap
  $name = [string]$Step.Script
  [void]$script:executed.Add($name)
  $status = if ($script:stubStatus.ContainsKey($name)) { $script:stubStatus[$name] } else { 'Success' }
  $exit = @{ Success = 0; Partial = 2; Failed = 1 }[$status]
  return [pscustomobject]@{
    ExitCode = $exit; Status = $status; Message = 'stub'; ProcessExitCode = $exit
    ChildResult = $null; DeclaredResult = $null; Stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
  }
}
function Write-UiLine { param([string]$Text, $Style, $ForegroundColor) $null = $Text, $Style, $ForegroundColor }

function Invoke-StubbedSchedule {
  param([object[]]$Steps, [hashtable]$Status = @{})
  $script:executed = New-Object System.Collections.ArrayList
  $script:stubStatus = $Status
  $pending = New-Object System.Collections.ArrayList
  foreach ($step in $Steps) { [void]$pending.Add([pscustomobject]$step) }
  $state = [pscustomobject]@{
    Pending = $pending
    StepStatus = @{}
    Results = New-Object System.Collections.ArrayList
    Findings = New-Object System.Collections.ArrayList
    DependencyCycleDetected = $false
    DependencyCycleScripts = @()
  }
  Invoke-RunProfileSchedule -Options ([pscustomobject]@{}) -State $state -Bootstrap $null
  return $state
}

function Test-DependencyStateReadyWithoutDependencies {
  $s = Get-RunProfileDependencyState ([pscustomobject]@{ Script = 'a' }) @{}
  $s.Ready | Should -BeTrue
  $s.Failed | Should -BeFalse
}

function Test-DependencyStateNotReadyWithoutRecordedStatus {
  $s = Get-RunProfileDependencyState ([pscustomobject]@{ Script = 'b'; DependsOn = @('a') }) @{}
  $s.Ready | Should -BeFalse
  $s.Failed | Should -BeFalse
}

function Test-DependencyStateFailureByStatus {
  param([string]$Status, [bool]$Failed)
  $s = Get-RunProfileDependencyState ([pscustomobject]@{ Script = 'b'; DependsOn = @('a') }) @{ a = $Status }
  $s.Ready | Should -BeTrue
  $s.Failed | Should -Be $Failed
}

function Test-ScheduleRunsIndependentStepsInDeclarationOrder {
  $steps = @(@{ Script = 'c' }, @{ Script = 'a' }, @{ Script = 'b' })
  $state = Invoke-StubbedSchedule -Steps $steps
  $script:executed | Should -Be @('c', 'a', 'b')
  @($state.Results.ScriptName) | Should -Be @('c', 'a', 'b')
  $state.DependencyCycleDetected | Should -BeFalse
}

function Test-ScheduleOrdersReverseDeclaredDiamondDependenciesFirst {
  $steps = @(
    @{ Script = 'd'; DependsOn = @('b', 'c') }
    @{ Script = 'c'; DependsOn = @('a') }
    @{ Script = 'b'; DependsOn = @('a') }
    @{ Script = 'a' }
  )
  $null = Invoke-StubbedSchedule -Steps $steps
  $script:executed | Should -Be @('a', 'c', 'b', 'd')
}

function Test-ScheduleRunsForwardDeclaredDiamondInOrder {
  $steps = @(
    @{ Script = 'a' }
    @{ Script = 'b'; DependsOn = @('a') }
    @{ Script = 'c'; DependsOn = @('a') }
    @{ Script = 'd'; DependsOn = @('b', 'c') }
  )
  $null = Invoke-StubbedSchedule -Steps $steps
  $script:executed | Should -Be @('a', 'b', 'c', 'd')
}

function Test-ScheduleRunsDependentAfterPartialDependency {
  $steps = @(@{ Script = 'b'; DependsOn = @('a') }, @{ Script = 'a' })
  $state = Invoke-StubbedSchedule -Steps $steps -Status @{ a = 'Partial' }
  $script:executed | Should -Be @('a', 'b')
  $state.StepStatus['a'] | Should -Be 'Partial'
  $state.StepStatus['b'] | Should -Be 'Success'
}

function Test-ScheduleSkipsDependentOfContinueOnErrorFailure {
  $steps = @(
    @{ Script = 'a'; ContinueOnError = $true }
    @{ Script = 'b'; DependsOn = @('a') }
    @{ Script = 'c' }
  )
  $state = Invoke-StubbedSchedule -Steps $steps -Status @{ a = 'Failed' }
  $script:executed | Should -Be @('a', 'c')
  $state.StepStatus['b'] | Should -Be 'Skipped'
  $skip = $state.Results | Where-Object ScriptName -EQ 'b'
  $skip.Status | Should -Be 'Skipped'
  $skip.ExitCode | Should -Be 2
  $skip.Message | Should -Be 'Skipped due to failed dependency.'
}

function Test-ScheduleStopsProfileAfterFailureWithoutContinueOnError {
  $steps = @(@{ Script = 'a' }, @{ Script = 'b' }, @{ Script = 'c' })
  $state = Invoke-StubbedSchedule -Steps $steps -Status @{ a = 'Failed' }
  $script:executed | Should -Be @('a')
  @($state.Results.ScriptName) | Should -Be @('a', 'b', 'c')
  ($state.Results | Where-Object ScriptName -EQ 'b').Message | Should -Be 'Not run because the profile stopped after failure in a.'
  $state.Pending.Count | Should -Be 0
}

function Test-ScheduleReportsTwoStepCycleWithoutRunningSteps {
  $steps = @(@{ Script = 'a'; DependsOn = @('b') }, @{ Script = 'b'; DependsOn = @('a') })
  $state = Invoke-StubbedSchedule -Steps $steps
  $script:executed | Should -HaveCount 0
  $state.DependencyCycleDetected | Should -BeTrue
  $state.DependencyCycleScripts | Should -Be @('a', 'b')
  $state.Findings | Should -HaveCount 1
  $finding = $state.Findings[0]
  $finding.Code | Should -Be 'Profile-DependencyCycle'
  $finding.Severity | Should -Be 'High'
  $finding.Message | Should -Be 'Dependency cycle or unresolved dependency. Scripts not run: a, b'
  @($state.Results.Status | Select-Object -Unique) | Should -Be @('Skipped')
  @($state.Results.Message | Select-Object -Unique) | Should -Be @('Dependency cycle or unresolved dependency.')
}

function Test-ScheduleRunsStepsPrecedingCycle {
  $steps = @(@{ Script = 'ok' }, @{ Script = 'x'; DependsOn = @('y') }, @{ Script = 'y'; DependsOn = @('x') })
  $state = Invoke-StubbedSchedule -Steps $steps
  $script:executed | Should -Be @('ok')
  $state.DependencyCycleScripts | Should -Be @('x', 'y')
}

function Test-ScheduleTreatsUnknownDependencyAsCycle {
  $steps = @(@{ Script = 'a'; DependsOn = @('ghost') })
  $state = Invoke-StubbedSchedule -Steps $steps
  $script:executed | Should -HaveCount 0
  $state.Findings[0].Code | Should -Be 'Profile-DependencyCycle'
  $state.DependencyCycleScripts | Should -Be @('a')
}
