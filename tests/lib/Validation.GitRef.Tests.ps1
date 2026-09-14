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

Describe 'Test-ValidGitRef' {
  It '<Title>' -ForEach @(
    @{ Title = 'Accepts branch ref'; Ref = 'main'; Expected = $true }
    @{ Title = 'Rejects unsafe ref'; Ref = '../main'; Expected = $false }
    @{ Title = 'Rejects ref with double dot (..)'; Ref = 'main..branch'; Expected = $false }
    @{ Title = 'Rejects ref with tilde'; Ref = 'HEAD~1'; Expected = $false }
    @{ Title = 'Rejects ref with caret'; Ref = 'HEAD^2'; Expected = $false }
    @{ Title = 'Rejects ref with @{'; Ref = 'main@{0}'; Expected = $false }
    @{ Title = 'Rejects ref starting with dash'; Ref = '-branch'; Expected = $false }
    @{ Title = 'Rejects ref ending with .lock'; Ref = 'branch.lock'; Expected = $false }
    @{ Title = 'Rejects ref ending with dot'; Ref = 'branch.'; Expected = $false }
    @{ Title = 'Rejects ref ending with slash'; Ref = 'branch/'; Expected = $false }
    @{ Title = 'Rejects ref with backslash'; Ref = 'branch\name'; Expected = $false }
    @{ Title = 'Rejects ref with colon'; Ref = 'branch:name'; Expected = $false }
    @{ Title = 'Rejects ref with question mark'; Ref = 'branch?name'; Expected = $false }
    @{ Title = 'Rejects ref with asterisk'; Ref = 'branch*'; Expected = $false }
    @{ Title = 'Rejects ref with open bracket'; Ref = 'branch[0]'; Expected = $false }
    @{ Title = 'Accepts valid feature branch name'; Ref = 'feature/my-branch'; Expected = $true }
    @{ Title = 'Accepts valid tag format'; Ref = 'v1.2.3'; Expected = $true }
    @{ Title = 'Accepts ref with hyphen and numbers'; Ref = 'release-2024.01'; Expected = $true }
  ) {
    Test-ValidGitRef -Ref $Ref | Should -Be $Expected
  }

  It 'Rejects null or empty ref' { Test-ValidationRejectsNullOrEmptyRef }

}
