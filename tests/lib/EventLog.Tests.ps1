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
  Import-Module (Join-Path $PSScriptRoot '../../lib/EventLog.psm1') -Force

  function Get-WarningMessages {
    param([object[]]$Output)
    @($Output | Where-Object { $_ -is [System.Management.Automation.WarningRecord] } | ForEach-Object { $_.Message })
  }
}

Describe 'Deprecated EventLog caller-scope aliases' {
  It 'Ensure-EventSource warns when falling back to EventSourceName' {
    Set-Variable -Name EventSourceName -Scope Global -Value 'DeprecatedSource'
    try {
      $output = Ensure-EventSource -LogName 'Application' 3>&1
      Get-WarningMessages -Output $output | Should -Contain 'Use EventSource, not EventSourceName (deprecated)'
    } finally {
      Remove-Variable -Name EventSourceName -Scope Global -ErrorAction SilentlyContinue
    }
  }

  It 'Ensure-EventSource warns when falling back to EventLog' {
    Set-Variable -Name EventLog -Scope Global -Value 'Application'
    try {
      $output = Ensure-EventSource -Source 'DeprecatedSource' 3>&1
      Get-WarningMessages -Output $output | Should -Contain 'Use EventLogName, not EventLog (deprecated)'
    } finally {
      Remove-Variable -Name EventLog -Scope Global -ErrorAction SilentlyContinue
    }
  }

  It 'Write-HealthEvent warns when falling back to EventSourceName' {
    Set-Variable -Name EventSourceName -Scope Global -Value 'DeprecatedSource'
    try {
      $output = Write-HealthEvent -Id 1000 -Message 'Test' -LogName 'Application' 3>&1
      Get-WarningMessages -Output $output | Should -Contain 'Use EventSource, not EventSourceName (deprecated)'
    } finally {
      Remove-Variable -Name EventSourceName -Scope Global -ErrorAction SilentlyContinue
    }
  }

  It 'Write-HealthEvent warns when falling back to EventLog' {
    Set-Variable -Name EventLog -Scope Global -Value 'Application'
    try {
      $output = Write-HealthEvent -Id 1000 -Message 'Test' -Source 'DeprecatedSource' 3>&1
      Get-WarningMessages -Output $output | Should -Contain 'Use EventLogName, not EventLog (deprecated)'
    } finally {
      Remove-Variable -Name EventLog -Scope Global -ErrorAction SilentlyContinue
    }
  }
}

Describe 'Ensure-EventSource' {
  It 'prefers canonical caller-scope values over deprecated aliases' -Skip:$script:SkipWindowsTests {
    Mock -CommandName 'New-EventLog' -MockWith { } -ModuleName EventLog
    Set-Variable -Name EventSource -Scope Global -Value 'CanonicalSource'
    Set-Variable -Name EventSourceName -Scope Global -Value 'DeprecatedSource'
    Set-Variable -Name EventLogName -Scope Global -Value 'CanonicalLog'
    Set-Variable -Name EventLog -Scope Global -Value 'DeprecatedLog'

    try {
      $output = Ensure-EventSource 3>&1
      Get-WarningMessages -Output $output | Should -Not -Contain 'Use EventSource, not EventSourceName (deprecated)'
      Get-WarningMessages -Output $output | Should -Not -Contain 'Use EventLogName, not EventLog (deprecated)'
      $output | Where-Object { $_ -eq $true } | Should -Not -BeNullOrEmpty
      Should -Invoke -CommandName 'New-EventLog' -ModuleName EventLog -Times 1 -Exactly -ParameterFilter {
        $Source -eq 'CanonicalSource' -and $LogName -eq 'CanonicalLog'
      }
    } finally {
      Remove-Variable -Name EventSource,EventSourceName,EventLogName,EventLog -Scope Global -ErrorAction SilentlyContinue
    }
  }

  It 'defaults LogName to Application when no caller-scope log value exists' -Skip:$script:SkipWindowsTests {
    Mock -CommandName 'New-EventLog' -MockWith { } -ModuleName EventLog
    Set-Variable -Name EventSource -Scope Global -Value 'CanonicalSource'

    try {
      $output = Ensure-EventSource 3>&1
      $output | Where-Object { $_ -eq $true } | Should -Not -BeNullOrEmpty
      Should -Invoke -CommandName 'New-EventLog' -ModuleName EventLog -Times 1 -Exactly -ParameterFilter {
        $Source -eq 'CanonicalSource' -and $LogName -eq 'Application'
      }
    } finally {
      Remove-Variable -Name EventSource,EventSourceName,EventLogName,EventLog -Scope Global -ErrorAction SilentlyContinue
    }
  }

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
