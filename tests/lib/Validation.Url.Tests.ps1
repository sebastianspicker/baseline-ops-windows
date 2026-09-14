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

Describe 'Test-SafeUrl' {
  It 'Accepts https URL' {
    Test-SafeUrl -Url 'https://example.com/resource' | Should -Be $true
  }

  It 'Accepts http URL' {
    Test-SafeUrl -Url 'http://example.com/resource' | Should -Be $true
  }

  It 'Rejects file:// scheme' {
    Test-SafeUrl -Url 'file:///etc/passwd' | Should -Be $false
  }

  It 'Rejects ftp:// scheme' {
    Test-SafeUrl -Url 'ftp://evil.com/payload' | Should -Be $false
  }

  It 'Rejects null or empty' { Test-ValidationRejectsNullOrEmpty }

  It 'Rejects argument injection via leading dash' {
    Test-SafeUrl -Url '-http://evil.com' | Should -Be $false
  }

  It 'Rejects relative URLs' {
    Test-SafeUrl -Url '/relative/path' | Should -Be $false
  }

  It 'Accepts custom allowed schemes' {
    Test-SafeUrl -Url 'ftp://example.com' -AllowedSchemes @('ftp') | Should -Be $true
  }
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
