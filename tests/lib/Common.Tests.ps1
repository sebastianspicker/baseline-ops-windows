#requires -version 5.1
<#
.SYNOPSIS
Verifies shared common utility security behavior.
.DESCRIPTION
Checks that untrusted configuration cannot select an output destination while
explicit operator paths and fixed defaults keep their documented precedence.
#>

BeforeAll {
  Import-Module (Join-Path $PSScriptRoot '../../lib/Common.psm1') -Force
}

Describe 'Resolve-OperatorControlledOutputPath' {
  It 'ignores a differing configured destination and warns' {
    $warnings = @()
    $result = Resolve-OperatorControlledOutputPath -DefaultPath 'C:\fixed\proof.json' `
      -ConfiguredPath 'C:\attacker\proof.json' -SettingName 'Proof.OutFile' `
      -InputKind catalog -WarningVariable warnings -WarningAction SilentlyContinue

    $result | Should -Be 'C:\fixed\proof.json'
    @($warnings) | Should -HaveCount 1
    $warnings[0].Message | Should -Match 'Ignoring catalog Proof\.OutFile'
  }

  It 'keeps an explicit operator destination authoritative' {
    $warnings = @()
    $result = Resolve-OperatorControlledOutputPath -ExplicitPath 'C:\operator\result.csv' `
      -DefaultPath 'C:\fixed\result.csv' -ConfiguredPath 'C:\attacker\result.csv' `
      -SettingName 'ExportPath' -WarningVariable warnings -WarningAction SilentlyContinue

    $result | Should -Be 'C:\operator\result.csv'
    @($warnings) | Should -HaveCount 1
  }

  It 'does not warn when a merged catalog repeats the fixed default' {
    $warnings = @()
    $result = Resolve-OperatorControlledOutputPath -DefaultPath 'C:\fixed\proof.json' `
      -ConfiguredPath 'C:\fixed\proof.json' -SettingName 'Proof.OutFile' `
      -InputKind catalog -WarningVariable warnings -WarningAction SilentlyContinue

    $result | Should -Be 'C:\fixed\proof.json'
    @($warnings) | Should -HaveCount 0
  }
}
