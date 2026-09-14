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

Describe 'Get-BoundedUtf8FileContent' {
  It 'reads ordinary UTF-8 content and exposes a stable content hash' { Test-ValidationReadsOrdinaryUTF8ContentAndExposesAStableContentHash }

  It 'rejects an oversized file before reading it' { Test-ValidationRejectsAnOversizedFileBeforeReadingIt }

  It 'rejects invalid UTF-8' { Test-ValidationRejectsInvalidUTF8 }
}
