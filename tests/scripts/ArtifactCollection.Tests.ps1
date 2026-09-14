#requires -version 5.1
<#
.SYNOPSIS
  Verifies controlled artifact collection orchestration.
.DESCRIPTION
  Uses in-memory collection, evidence, archive, and trigger providers to check output ordering and failure behavior without collecting endpoint artifacts.
#>

BeforeAll {
  . (Join-Path $PSScriptRoot 'ArtifactCollection.Fixture.ps1')
  Import-Module (New-ArtifactTestModule) -Force
  function New-ArtifactScenario {
    return @{Want = $true
      Samples = $false
      FailSave = $false
      FailZip = $false
      Suspicious = 0
    }
  }
}
Describe 'Artifact collection orchestration' {
  It 'retains catalog provenance when the trigger is absent' {
    $fixture = New-ArtifactScenario
    $fixture.Want = $false
    $run = Invoke-ArtifactFixture $fixture
    $run.Console.CatalogLoadNote | Should -Be 'Using defaults (no catalog configured)'
    $run.Summary.Output.WorkDir | Should -BeNullOrEmpty
    @($run.Calls | Where-Object { $_ -like 'Directory:*' }).Count | Should -Be 0
  }
  It 'copies only matching unsigned samples and hashes the retained evidence' {
    $fixture = New-ArtifactScenario
    $fixture.Samples = $true
    $run = Invoke-ArtifactFixture $fixture
    $run.Summary.Counts.Samples.Copied | Should -Be 1
    $run.Summary.Samples[0].Source | Should -Be 'C:\ProgramData\a.exe'
    $run.Summary.Samples[0].Sha256 | Should -Be 'controlled-hash'
    @($run.Calls | Where-Object { $_ -like 'Copy:*' }).Count | Should -Be 1
    @($run.Calls | Where-Object { $_ -like 'Hash:*' }).Count | Should -Be 1
  }
  It 'resets the trigger after bundle completion' {
    $run = Invoke-ArtifactFixture (New-ArtifactScenario)
    $run.Calls[-1] | Should -Be 'Registry:HKLM:\SOFTWARE\IR\Grabber/Request=0'
    $run.Errors.Count | Should -Be 0
    $run.Console.Version | Should -Be '2025.12.22-ps51'
  }
  It 'keeps zip failures in final output while retaining the saved summary snapshot' {
    $fixture = New-ArtifactScenario
    $fixture.FailZip = $true
    $run = Invoke-ArtifactFixture $fixture
    $run.Errors | Should -Be @('zip: controlled zip failure')
    ($run.Saved | ConvertFrom-Json).Errors.Count | Should -Be 0
    $run.Ok | Should -BeFalse
  }
  It 'does not archive or reset the trigger after a summary save failure' {
    $fixture = New-ArtifactScenario
    $fixture.FailSave = $true
    $run = Invoke-ArtifactFixture $fixture
    $run.Errors | Should -Be @('IR Grabber fatal: controlled save failure')
    @($run.Calls | Where-Object { $_ -like 'Zip:*' -or $_ -like 'Registry:*' }).Count | Should -Be 0
  }
}
