#requires -version 5.1
<#
.SYNOPSIS
Pester tests for EventLog.psm1 module

.DESCRIPTION
Unit tests for Ensure-EventSource and Write-HealthEvent.
These functions depend on Windows Event Log APIs and are skipped on non-Windows.
#>

[CmdletBinding()]
param()

$script:SkipWindowsTests = (-not $IsWindows)

BeforeAll {
  Import-Module (Join-Path $PSScriptRoot '../../lib/Common.psm1') -Force -DisableNameChecking
  Import-Module (Join-Path $PSScriptRoot '../../lib/EventLog.psm1') -Force -DisableNameChecking
}

Describe 'Ensure-EventSource' {
  It 'Returns false and emits warning when Source is empty' -Skip:$script:SkipWindowsTests {
    $result = Ensure-EventSource -Source '' -OnErrorMessage 'Test error message' 3>&1
    # Function returns $false when source is empty
    $result | Where-Object { $_ -eq $false } | Should -Not -BeNullOrEmpty
  }

  It 'Returns true when source already exists' -Skip:$script:SkipWindowsTests {
    # 'Application' source typically exists on Windows
    Mock -CommandName 'New-EventLog' -MockWith { } -ModuleName EventLog
    $result = Ensure-EventSource -Source 'Application' -LogName 'Application'
    $result | Should -Be $true
  }
}

Describe 'Write-HealthEvent' {
  It 'Returns false when Source is missing' -Skip:$script:SkipWindowsTests {
    $result = Write-HealthEvent -Id 1000 -Message 'Test' -OnErrorMessage 'Test error message' 3>&1
    $result | Where-Object { $_ -eq $false } | Should -Not -BeNullOrEmpty
  }

  It 'Returns false when LogName is missing' -Skip:$script:SkipWindowsTests {
    $result = Write-HealthEvent -Id 1000 -Message 'Test' -Source 'TestSource' -OnErrorMessage 'Test error message' 3>&1
    $result | Where-Object { $_ -eq $false } | Should -Not -BeNullOrEmpty
  }
}
