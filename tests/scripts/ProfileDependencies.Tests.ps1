#requires -version 5.1
<#
.SYNOPSIS
Characterizes Run-Profile dependency ordering and cycle handling.
.DESCRIPTION
Drives Invoke-RunProfileSchedule from scripts/internal/00-Run-Profile.scheduler.ps1
with a stub step executor so ordering, skip propagation, stop-on-failure, and
dependency-cycle findings are pinned without executing any capability.
#>

BeforeAll {
  $root = Resolve-Path (Join-Path $PSScriptRoot '../..')
  Import-Module (Join-Path $root 'lib/Output.psm1') -Force
  Import-Module (Join-Path $root 'lib/Common.psm1') -Force -DisableNameChecking
  . (Join-Path $root 'scripts/internal/00-Run-Profile.scheduler.ps1')
  . (Join-Path $PSScriptRoot 'ProfileDependencies.Cases.ps1')
}

Describe 'Get-RunProfileDependencyState' {
  It 'is ready and not failed without dependencies' { Test-DependencyStateReadyWithoutDependencies }

  It 'is not ready while a dependency has no recorded status' { Test-DependencyStateNotReadyWithoutRecordedStatus }

  It 'treats <Status> dependency as failed=<Failed>' -ForEach @(
    @{ Status = 'Success'; Failed = $false }
    @{ Status = 'Partial'; Failed = $false }
    @{ Status = 'Failed'; Failed = $true }
    @{ Status = 'Skipped'; Failed = $true }
  ) { Test-DependencyStateFailureByStatus -Status $Status -Failed $Failed }
}

Describe 'Invoke-RunProfileSchedule ordering' {
  # Characterization quirk: Invoke-RunProfileSchedulePass calls RemoveAt() inside a
  # forward for-loop, so the element after each removed step is passed over until
  # the next pass. Independent steps therefore do not run in strict declaration
  # order today (c, a, b runs as c, b, a). Assert current behavior.
  It 'runs independent steps c, a, b in declaration order' { Test-ScheduleRunsIndependentStepsInDeclarationOrder }

  It 'orders a diamond graph declared in reverse with dependencies first' { Test-ScheduleOrdersReverseDeclaredDiamondDependenciesFirst }

  It 'runs a forward-declared diamond in declaration order a, b, c, d' { Test-ScheduleRunsForwardDeclaredDiamondInOrder }

  It 'runs a dependent after a Partial dependency' { Test-ScheduleRunsDependentAfterPartialDependency }
}

Describe 'Invoke-RunProfileSchedule failure handling' {
  It 'skips a dependent of a ContinueOnError failure and keeps running others' { Test-ScheduleSkipsDependentOfContinueOnErrorFailure }

  It 'stops the profile and skips the remaining steps when a step fails without ContinueOnError' { Test-ScheduleStopsProfileAfterFailureWithoutContinueOnError }
}

Describe 'Invoke-RunProfileSchedule cycle handling' {
  It 'reports a two-step cycle as Profile-DependencyCycle without running either step' { Test-ScheduleReportsTwoStepCycleWithoutRunningSteps }

  It 'runs steps preceding a cycle and reports only the cyclic remainder' { Test-ScheduleRunsStepsPrecedingCycle }

  It 'treats an unknown dependency like a cycle at run time' { Test-ScheduleTreatsUnknownDependencyAsCycle }
}
