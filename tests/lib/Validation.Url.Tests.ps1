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

Describe 'Test-WingetPrivateSourceDefinition' {
  It 'allows explicitly supported source types on public HTTPS endpoints' -ForEach @('Microsoft.Rest', 'Microsoft.PreIndexed.Package') {
    Test-WingetPrivateSourceDefinition -Url 'https://packages.example.com/cache' -Type $_ | Should -BeTrue
  }

  It 'rejects unsupported types and unsafe endpoint forms' -ForEach @(
    @{ Url = 'https://packages.example.com/cache'; Type = 'Microsoft.SQLite' }
    @{ Url = 'http://packages.example.com/cache'; Type = 'Microsoft.Rest' }
    @{ Url = 'https://user:password@packages.example.com/cache'; Type = 'Microsoft.Rest' }
    @{ Url = 'https://packages.example.com/cache?access_token=secret'; Type = 'Microsoft.Rest' }
    @{ Url = 'https://packages.example.com/cache#access_token=secret'; Type = 'Microsoft.Rest' }
    @{ Url = 'https://localhost/cache'; Type = 'Microsoft.Rest' }
    @{ Url = 'https://repo.local/cache'; Type = 'Microsoft.Rest' }
    @{ Url = 'https://127.0.0.1/cache'; Type = 'Microsoft.Rest' }
    @{ Url = 'https://169.254.1.1/cache'; Type = 'Microsoft.Rest' }
    @{ Url = 'https://[fe80::1]/cache'; Type = 'Microsoft.Rest' }
    @{ Url = 'https://[fc00::1]/cache'; Type = 'Microsoft.Rest' }
    @{ Url = 'https://[::ffff:127.0.0.1]/cache'; Type = 'Microsoft.Rest' }
  ) {
    Test-WingetPrivateSourceDefinition -Url $Url -Type $Type | Should -BeFalse
  }
}
