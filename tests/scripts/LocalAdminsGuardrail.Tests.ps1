#requires -version 5.1
<#
.SYNOPSIS
  Verifies local Administrators guardrail safety decisions.
.DESCRIPTION
  Checks fail-safe removal, domain-member protection, confirmation, and post-remediation observations.
#>

BeforeAll {
  . (Join-Path $PSScriptRoot 'LocalAdminsGuardrail.Fixture.ps1')
  Import-Module (New-GuardrailTestModule) -Force
  function New-GuardrailScenario {
    param($Allowed, [bool]$Domain, [bool]$Approve)
    return @{
      Allowed = $Allowed
      Remediate = $true
      Domain = $Domain
      Confirm = $Approve
      PostFailure = $false
      Members = @(
        [pscustomobject]@{ SID = 'S-500'
          Name = 'Builtin'
          PrincipalSource = 'Local'
          ObjectClass = 'User'
        }
        [pscustomobject]@{ SID = 'S-local'
          Name = 'Local'
          PrincipalSource = 'Local'
          ObjectClass = 'User'
        }
        [pscustomobject]@{ SID = 'S-domain'
          Name = 'Domain'
          PrincipalSource = 'Active Directory'
          ObjectClass = 'User'
        }
      )
    }
  }
}

Describe 'Local Administrators guardrail policy' {
  It 'suppresses removals when the effective allow-list is empty or unresolved' -ForEach @(
    @{ Allowed = @() }
    @{ Allowed = @('S-local', 'missing') }
  ) {
    $run = Invoke-GuardrailFixture (New-GuardrailScenario -Allowed $Allowed -Domain $true -Approve $true)
    $run.Result.FailSafeNoRemove | Should -BeTrue
    @($run.Result.ToRemove) | Should -HaveCount 0
    @($run.Removals) | Should -HaveCount 0
    @($run.Prompts) | Should -HaveCount 0
  }

  It 'preserves domain protection and leaves declined local removal visible in the post-check' {
    $run = Invoke-GuardrailFixture (New-GuardrailScenario -Allowed @('S-500') -Domain $false -Approve $false)
    @($run.Result.ToRemove.SID) | Should -Be @('S-local')
    @($run.Removals) | Should -HaveCount 0
    $run.Prompts | Should -Be @('Administrators|Remove S-local')
    $run.Reads | Should -Be 2
    $run.Result.PostCompliant | Should -BeFalse
  }

  It 'removes only approved drift and always retains the built-in Administrator' {
    $run = Invoke-GuardrailFixture (New-GuardrailScenario -Allowed @('S-500') -Domain $true -Approve $true)
    $run.Removals | Should -Be @('S-local', 'S-domain')
    @($run.Result.MembersAfter.SID) | Should -Be @('S-500')
    $run.Result.PostCompliant | Should -BeTrue
    $run.Result.DriftDetected | Should -BeTrue
    $run.Result.EventId | Should -Be 3500
  }
}
