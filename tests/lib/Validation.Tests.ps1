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

Describe 'Test-PathTraversal' {
  It 'Returns true for traversal path' {
    Test-PathTraversal -Path '..\evil\file.txt' | Should -Be $true
  }

  It 'Returns false for safe path' {
    Test-PathTraversal -Path 'C:\Temp\safe.txt' | Should -Be $false
  }

  It 'Returns false for null or empty input' { Test-ValidationReturnsFalseForNullOrEmptyInput }

  It 'Detects forward-slash traversal' {
    Test-PathTraversal -Path '../etc/passwd' | Should -Be $true
  }

  It 'Detects mid-path forward-slash traversal' {
    Test-PathTraversal -Path 'safe/../evil.txt' | Should -Be $true
  }

  It 'Detects mid-path traversal' {
    Test-PathTraversal -Path 'C:\Temp\..\Windows' | Should -Be $true
  }
}
