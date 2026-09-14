#requires -version 5.1
<#
.SYNOPSIS
  Verifies LAPS policy and rotation decisions.
.DESCRIPTION
  Covers policy-age units, rotation diagnostics, post-rotation observations, and missing-policy behavior with controlled providers.
#>

BeforeAll {
  . (Join-Path $PSScriptRoot 'LapsHygiene.Fixture.ps1')
  Import-Module (New-LapsHygieneTestModule) -Force
  function New-LapsScenario {
    return @{
      Policy = [pscustomobject]@{
        Type = 'WindowsLAPS'
        Mechanism = 'GPO'
        RootPath = 'controlled'
        Policy = [pscustomobject]@{ BackupDirectory = 1
          PasswordAgeDays = 30
          PasswordComplexity = 4
          AdministratorAccountName = 'custom'
        }
      }
      Before = [pscustomobject]@{ Exists = $true
        Enabled = $true
        PasswordLastSet = [datetime]'2025-01-01T12:00:00Z'
        Source = 'fixture'
      }
      After = [pscustomobject]@{ Exists = $true
        Enabled = $true
        PasswordLastSet = [datetime]'2026-01-01T12:00:00Z'
        Source = 'fixture'
      }
      Remediate = $true
      Rotate = $false
      FailRead = $false
    }
  }
}

Describe 'LAPS hygiene decisions' {
  It 'converts legacy password age from hours and preserves boolean token defaults' {
    Get-PolicyPasswordAgeDays -PolicyType LegacyLAPS -PolicyObject ([pscustomobject]@{ PasswordAge = 25 }) -DefaultAgeDays 30 | Should -Be 2
    ConvertTo-BoolSafe -Value 'no' -Default $true | Should -BeFalse
    ConvertTo-BoolSafe -Value 'unknown' -Default $true | Should -BeTrue
  }

  It 'collects diagnostics after a failed Windows rotation without a post-rotation read' {
    $run = Invoke-LapsHygieneFixture (New-LapsScenario)
    $run.Result.NeedsRotate | Should -BeTrue
    $run.Result.Rotated | Should -BeFalse
    $run.Result.OkOverall | Should -BeFalse
    $run.Result.RotationError | Should -Be 'controlled method'
    $run.Diagnostics | Should -Be 1
    $run.Reads | Should -Be 1
  }

  It 'reads fresh account state after successful rotation' {
    $scenario = New-LapsScenario
    $scenario.Rotate = $true
    $run = Invoke-LapsHygieneFixture $scenario
    $run.Result.Rotated | Should -BeTrue
    $run.Result.PasswordAgeDays | Should -Be 0
    $run.Result.OkOverall | Should -BeTrue
    $run.Reads | Should -Be 2
    $run.Diagnostics | Should -Be 0
  }

  It 'reports a missing policy without rotating the account' {
    $scenario = New-LapsScenario
    $scenario.Policy = $null
    $run = Invoke-LapsHygieneFixture $scenario
    $run.Result.OkOverall | Should -BeFalse
    $run.Result.Reasons | Should -Be @('No LAPS policy detected')
    $run.Rotations | Should -Be 0
  }
}
