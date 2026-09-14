#requires -version 5.1
<#
.SYNOPSIS
  Verifies Defender allowlist normalization and result decisions.
.DESCRIPTION
  Covers risky exclusions, fallback, strict JSON failure, and independent remediation errors with controlled providers.
#>

BeforeAll {
  . (Join-Path $PSScriptRoot 'DefenderAllowlist.Fixture.ps1')
  Import-Module (New-DefenderAllowlistTestModule) -Force
  function New-AllowlistScenario {
    return @{
      Preference = [pscustomobject]@{
        ExclusionPath = @('D:\old')
        ExclusionProcess = @()
        ExclusionExtension = @()
        AttackSurfaceReductionOnlyExclusions = @('D:\asr')
        ControlledFolderAccessAllowedApplications = @()
        ControlledFolderAccessProtectedFolders = @()
      }
      Exists = $false
      Json = ''
      Strict = $false
      Remediate = $false
      Baseline = 'Current'
      Fail = $false
    }
  }
}

Describe 'Defender allowlist decisions' {
  It 'normalizes and deduplicates paths while preserving drive roots' {
    @(To-NormList -Input @(' D:\Apps\ ', 'd:\apps', 'D:\') -Kind path) | Should -Be @('d:\', 'd:\apps')
    Is-RiskyEntry -Item 'c:\windows\logs' -Kind path | Should -BeTrue
    Is-RiskyEntry -Item 'd:\apps' -Kind path | Should -BeFalse
    Is-RiskyEntry -Item '.exe' -Kind ext | Should -BeTrue
  }

  It 'keeps the current state when JSON is missing and Current fallback is selected' {
    $run = Invoke-DefenderAllowlistFixture (New-AllowlistScenario)
    $run.Result.Result | Should -Be 'OK_NO_DRIFT'
    $run.Result.BaselineUsed | Should -Be 'Current'
    $run.Result.TotalAdd | Should -Be 0
    $run.Result.TotalRemove | Should -Be 0
    $run.Events[0].Message | Should -Be 'Defender/ASR allowlist OK: no drift. JSON=controlled.json Audit='
    @($run.Calls) | Should -HaveCount 0
  }

  It 'reports strict missing JSON without attempting remediation' {
    $scenario = New-AllowlistScenario
    $scenario.Strict = $true
    $scenario.Remediate = $true
    $run = Invoke-DefenderAllowlistFixture $scenario
    $run.Result.Result | Should -Be 'FAILED'
    $run.Result.JsonError | Should -Be 'Defender/ASR allowlist failed: Allowlist JSON not found.'
    @($run.Calls) | Should -HaveCount 0
  }

  It 'retains add and remove errors independently in category order' {
    $scenario = New-AllowlistScenario
    $scenario.Exists = $true
    $scenario.Remediate = $true
    $scenario.Fail = $true
    $scenario.Json = '{"Defender":{"ExclusionPaths":["D:\\new"],"ExclusionProcesses":[],"ExclusionExtensions":[]},"ASR":{"OnlyExclusions":[]},"CFA":{"AllowedApplications":[],"ProtectedFolders":[]}}'
    $run = Invoke-DefenderAllowlistFixture $scenario
    $run.Result.Result | Should -Be 'REMEDIATION_ERRORS'
    $run.Result.TotalErrors | Should -Be 3
    @($run.Calls.Operation) | Should -Be @('Add', 'Remove', 'Remove')
    $run.Result.ErrorsFlat[0] | Should -Be 'Add failed for ExclusionPath: controlled add failure'
    $run.Result.ErrorsFlat[1] | Should -Be 'Remove failed for ExclusionPath: controlled remove failure'
  }
}
