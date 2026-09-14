#requires -version 5.1
<#
.SYNOPSIS
  Provides controlled Office and browser policy fixtures.
.DESCRIPTION
  Replaces endpoint observations and registry writes with in-memory state to verify proof output and confirmation decisions.
#>

BeforeAll {
 . (Join-Path $PSScriptRoot 'OfficeBrowserProof.Fixture.ps1')
 Import-Module (New-OfficeBrowserTestModule) -Force
}
Describe 'Firefox enterprise policy construction' {
  It 'preserves addon allowlist entries and installation order' {
    $catalog = Get-DefaultOfficeBrowserCatalog | ConvertFrom-Json
    $catalog.Firefox.BlockAllAddonsExcept = @('a@example', '', 'b@example')
    $catalog.Firefox.InstallAddons = @('first.xpi', 'second.xpi')
    $policy = Build-FirefoxPolicies $catalog.Firefox
    $policy.policies.Extensions.Install | Should -Be @('first.xpi', 'second.xpi')
    $policy.policies.Extensions.ExtensionSettings['*'].installation_mode | Should -Be blocked
    $policy.policies.Extensions.ExtensionSettings['a@example'].installation_mode | Should -Be allowed
    $policy.policies.Extensions.ExtensionSettings.ContainsKey('') | Should -BeFalse
  }
}
