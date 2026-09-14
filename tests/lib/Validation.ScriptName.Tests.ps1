<#
.SYNOPSIS
  Verifies Validation library contracts.
.DESCRIPTION
  Retains explicit contract cases and shared fixture setup for the library.
#>

BeforeAll {
  Import-Module (Join-Path $PSScriptRoot '../../lib/Validation.psm1') -Force

  . (Join-Path $PSScriptRoot 'Validation.Cases.ps1')
}

Describe 'Test-SafeScriptName' {
  It 'Accepts numbered script names' {
    Test-SafeScriptName -Name '18-Firewall-Baseline.ps1' | Should -Be $true
  }

  It 'Rejects path components' {
    Test-SafeScriptName -Name '..\outside.ps1' | Should -Be $false
  }

  It 'Rejects unsafe characters' {
    Test-SafeScriptName -Name '18-Bad:Name.ps1' | Should -Be $false
    Test-SafeScriptName -Name '18-Bad*Name.ps1' | Should -Be $false
  }

  It 'Rejects null or empty input' { Test-ValidationRejectsNullOrEmptyInput }

  It 'Rejects non-.ps1 extension' {
    Test-SafeScriptName -Name '01-Script.txt' | Should -Be $false
    Test-SafeScriptName -Name '01-Script.bat' | Should -Be $false
  }

  It 'Rejects names starting with a dot' {
    Test-SafeScriptName -Name '.hidden-script.ps1' | Should -Be $false
  }

  It 'Rejects names starting with a dash' {
    Test-SafeScriptName -Name '-dangerous.ps1' | Should -Be $false
  }

  It 'Rejects names containing backslash or forward slash' {
    Test-SafeScriptName -Name 'sub/script.ps1' | Should -Be $false
    Test-SafeScriptName -Name 'sub\script.ps1' | Should -Be $false
  }

  It 'Rejects names with leading or trailing whitespace' {
    Test-SafeScriptName -Name ' script.ps1' | Should -Be $false
    Test-SafeScriptName -Name 'script.ps1 ' | Should -Be $false
  }
}
