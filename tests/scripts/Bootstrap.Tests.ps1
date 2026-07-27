#requires -version 5.1
<#
.SYNOPSIS
Pester coverage for security-script contracts.

.DESCRIPTION
Verifies safe, repeatable operator behavior and evidence.
#>

Describe 'Bootstrap Initialize-V2Context' {
  BeforeAll {
    . (Join-Path $PSScriptRoot '../../scripts/_lib/Bootstrap.ps1')
  }

  AfterEach {
    Remove-Variable -Name __V2Context -Scope Script -ErrorAction SilentlyContinue
  }

  It 'declares ScriptName as mandatory' {
    $scriptNameParameter = (Get-Command Initialize-V2Context).Parameters['ScriptName']
    $scriptNameParameter | Should -Not -BeNullOrEmpty

    @($scriptNameParameter.Attributes |
      Where-Object { $_ -is [System.Management.Automation.ParameterAttribute] -and $_.Mandatory }).Count |
      Should -BeGreaterThan 0
  }

  It 'stores explicit ScriptName in the v2 context' {
    $context = Initialize-V2Context `
      -ScriptName '99-Test.ps1' `
      -BoundParameters @{ OutputFormat = 'None'; PassThru = $true; NoColor = $true } `
      -Mode Audit `
      -ConfigPath '.\config.json' `
      -OutputFormat None `
      -PassThru `
      -NoColor

    $context.ScriptName | Should -Be '99-Test.ps1'
    $context.Mode | Should -Be 'Audit'
    $context.OutputFormat | Should -Be 'None'
    $context.PassThru | Should -BeTrue
    $context.NoColor | Should -BeTrue
  }

  It 'returns derived Remediate without mutating caller state' {
    $Remediate = $false
    $null = $Mode
    $oldWhatIfPreference = $WhatIfPreference

    try {
      $WhatIfPreference = $true
      $context = Initialize-V2Context `
        -ScriptName '99-Test.ps1' `
        -BoundParameters @{ Mode = 'Remediate' } `
        -Mode Remediate `
        -DeriveRemediate

      $context.Remediate | Should -BeTrue
      $Remediate | Should -BeFalse
    } finally {
      $WhatIfPreference = $oldWhatIfPreference
    }
  }

  It 'does not probe or mutate caller scope' {
    $source = Get-Content -LiteralPath (Join-Path $PSScriptRoot '../../scripts/_lib/Bootstrap.ps1') -Raw

    $source | Should -Not -Match 'Get-Variable.+-Scope 1'
    $source | Should -Not -Match 'Set-Variable.+-Scope 1'
  }
}
