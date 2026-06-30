#requires -version 5.1

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
    $Mode = 'Audit'
    $ConfigPath = 'PATH/TO/config.json'
    $OutputFormat = 'None'
    $OutputPath = $null
    $PassThru = $true
    $Strict = $false
    $Quiet = $false
    $NoColor = $true
    $null = $Mode, $ConfigPath, $OutputFormat, $OutputPath, $PassThru, $Strict, $Quiet, $NoColor

    Initialize-V2Context -ScriptName '99-Test.ps1' -BoundParameters @{
      OutputFormat = 'None'
      PassThru = $true
      NoColor = $true
    }

    $script:__V2Context.ScriptName | Should -Be '99-Test.ps1'
    $script:__V2Context.Mode | Should -Be 'Audit'
    $script:__V2Context.OutputFormat | Should -Be 'None'
    $script:__V2Context.PassThru | Should -BeTrue
    $script:__V2Context.NoColor | Should -BeTrue
  }

  It 'sets derived Remediate even when WhatIfPreference is enabled' {
    $Mode = 'Remediate'
    $Remediate = $false
    $null = $Mode
    $oldWhatIfPreference = $WhatIfPreference

    try {
      $WhatIfPreference = $true
      Initialize-V2Context -ScriptName '99-Test.ps1' -BoundParameters @{ Mode = 'Remediate' } -DeriveRemediate

      $Remediate | Should -BeTrue
    } finally {
      $WhatIfPreference = $oldWhatIfPreference
    }
  }
}
