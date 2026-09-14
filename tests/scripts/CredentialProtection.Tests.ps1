#requires -version 5.1
<#
.SYNOPSIS
  Verifies credential protection policy and confirmation decisions.
.DESCRIPTION
  Uses controlled registry, DeviceGuard, and confirmation providers to preserve security gates and evidence without endpoint changes.
#>

BeforeAll {
  . (Join-Path $PSScriptRoot 'CredentialProtection.Fixture.ps1')
  Import-Module (New-CredentialTestModule) -Force
  function New-CredentialScenario {
    return @{Registry = 0
      Runtime = $false
      Remediate = $true
      Policy = $false
      Allow = $true
      Strict = $true
      Admin = $true
      Locked = 1
      WriteSucceeded = $true
    }
  }
}
Describe 'Credential protection remediation gates' {
  It 'preserves DeviceGuard policy ownership before requesting any registry write' {
    $fixture = New-CredentialScenario
    $fixture.Policy = $true
    $run = Invoke-CredentialFixture $fixture
    $run.Decisions.Count | Should -Be 0
    @($run.Calls | Where-Object Operation -eq Write).Count | Should -Be 0
    $run.Result.Warnings | Should -Contain 'Remediation requested but DeviceGuard policy key exists; skipping to avoid overriding policy.'
  }
  It 'requires elevation before requesting registry writes' {
    $fixture = New-CredentialScenario
    $fixture.Admin = $false
    $run = Invoke-CredentialFixture $fixture
    $run.Decisions.Count | Should -Be 0
    $run.Result.RemediationPerformed | Should -BeFalse
  }
  It 'honors declined confirmation for every proposed change' {
    $fixture = New-CredentialScenario
    $fixture.Allow = $false
    $run = Invoke-CredentialFixture $fixture
    $run.Decisions.Count | Should -BeGreaterThan 0
    @($run.Calls | Where-Object Operation -eq Write).Count | Should -Be 0
    $run.Result.RebootRequired | Should -BeFalse
  }
  It 'preserves existing UEFI locks while applying the other configured settings' {
    $run = Invoke-CredentialFixture (New-CredentialScenario)
    @($run.Calls | Where-Object { $_.Operation -eq 'Write' -and $_.Name -eq 'Locked' }).Count | Should -Be 0
    $run.Result.RebootRequired | Should -BeTrue
    $run.Decisions[0].Action | Should -Be 'Set RunAsPPL=1'
    $run.Result.Compliant | Should -BeFalse
  }
  It 'does not claim successful remediation actions when registry writes fail' {
    $fixture = New-CredentialScenario
    $fixture.WriteSucceeded = $false
    $run = Invoke-CredentialFixture $fixture
    $run.Result.RemediationActions.Count | Should -Be 0
    $run.Result.RebootRequired | Should -BeFalse
  }
}
