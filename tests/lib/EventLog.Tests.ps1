#requires -version 5.1
<#
.SYNOPSIS
Pester tests for EventLog.psm1 module

.DESCRIPTION
Unit tests for Ensure-EventSource and Write-HealthEvent.
Private .NET boundary wrappers are mocked so the public contract runs on every
test host without registering sources or writing to the host event log.
#>

[CmdletBinding()]
param()

BeforeAll {
  Import-Module (Join-Path $PSScriptRoot '../../lib/Common.psm1') -Force -DisableNameChecking
  $script:EventLogModulePath = Join-Path $PSScriptRoot '../../lib/EventLog.psm1'
  $script:EventLogModuleSource = Get-Content -LiteralPath $script:EventLogModulePath -Raw
  Import-Module $script:EventLogModulePath -Force

  function Get-WarningMessages {
    param([object[]]$Output)
    @($Output | Where-Object { $_ -is [System.Management.Automation.WarningRecord] } | ForEach-Object { $_.Message })
  }

  function Clear-EventLogTestGlobals {
    Remove-Variable `
      -Name EventSource,EventSourceName,EventLogName,EventLog `
      -Scope Global `
      -ErrorAction SilentlyContinue
  }
}

Describe 'Deprecated EventLog caller-scope aliases' {
  BeforeEach {
    Mock -CommandName Test-EventLogSourceExists -ModuleName EventLog -MockWith { $true }
    Mock -CommandName Write-EventLogEntry -ModuleName EventLog -MockWith {}
  }

  AfterEach {
    Clear-EventLogTestGlobals
  }

  It 'Ensure-EventSource warns when falling back to EventSourceName' {
    Set-Variable -Name EventSourceName -Scope Global -Value 'DeprecatedSource'

    $output = Ensure-EventSource -LogName 'Application' 3>&1

    Get-WarningMessages -Output $output |
      Should -Contain 'Use EventSource, not EventSourceName (deprecated)'
  }

  It 'Ensure-EventSource warns when falling back to EventLog' {
    Set-Variable -Name EventLog -Scope Global -Value 'Application'

    $output = Ensure-EventSource -Source 'DeprecatedSource' 3>&1

    Get-WarningMessages -Output $output |
      Should -Contain 'Use EventLogName, not EventLog (deprecated)'
  }

  It 'Write-HealthEvent warns when falling back to EventSourceName' {
    Set-Variable -Name EventSourceName -Scope Global -Value 'DeprecatedSource'

    $output = Write-HealthEvent -Id 1000 -Message 'Test' -LogName 'Application' 3>&1

    Get-WarningMessages -Output $output |
      Should -Contain 'Use EventSource, not EventSourceName (deprecated)'
  }

  It 'Write-HealthEvent warns when falling back to EventLog' {
    Set-Variable -Name EventLog -Scope Global -Value 'Application'

    $output = Write-HealthEvent -Id 1000 -Message 'Test' -Source 'DeprecatedSource' 3>&1

    Get-WarningMessages -Output $output |
      Should -Contain 'Use EventLogName, not EventLog (deprecated)'
  }
}

Describe 'Ensure-EventSource' {
  BeforeEach {
    Mock -CommandName Test-EventLogSourceExists -ModuleName EventLog -MockWith { $true }
    Mock -CommandName Register-EventLogSource -ModuleName EventLog -MockWith {}
  }

  AfterEach {
    Clear-EventLogTestGlobals
  }

  It 'prefers canonical caller-scope values over deprecated aliases' {
    Mock -CommandName Test-EventLogSourceExists -ModuleName EventLog -MockWith { $false }
    Set-Variable -Name EventSource -Scope Global -Value 'CanonicalSource'
    Set-Variable -Name EventSourceName -Scope Global -Value 'DeprecatedSource'
    Set-Variable -Name EventLogName -Scope Global -Value 'CanonicalLog'
    Set-Variable -Name EventLog -Scope Global -Value 'DeprecatedLog'

    $output = Ensure-EventSource 3>&1

    Get-WarningMessages -Output $output |
      Should -Not -Contain 'Use EventSource, not EventSourceName (deprecated)'
    Get-WarningMessages -Output $output |
      Should -Not -Contain 'Use EventLogName, not EventLog (deprecated)'
    $output | Where-Object { $_ -eq $true } | Should -Not -BeNullOrEmpty
    Should -Invoke -CommandName Register-EventLogSource -ModuleName EventLog -Times 1 -Exactly -ParameterFilter {
      $Source -eq 'CanonicalSource' -and $LogName -eq 'CanonicalLog'
    }
  }

  It 'defaults LogName to Application when no caller-scope log value exists' {
    Mock -CommandName Test-EventLogSourceExists -ModuleName EventLog -MockWith { $false }
    Set-Variable -Name EventSource -Scope Global -Value 'CanonicalSource'

    $output = Ensure-EventSource 3>&1

    $output | Where-Object { $_ -eq $true } | Should -Not -BeNullOrEmpty
    Should -Invoke -CommandName Register-EventLogSource -ModuleName EventLog -Times 1 -Exactly -ParameterFilter {
      $Source -eq 'CanonicalSource' -and $LogName -eq 'Application'
    }
  }

  It 'returns false and emits the supplied warning when Source is empty' {
    $result = Ensure-EventSource -Source '' -OnErrorMessage 'Test error message' 3>&1

    $result | Where-Object { $_ -eq $false } | Should -Not -BeNullOrEmpty
    Get-WarningMessages -Output $result | Should -Contain 'Test error message'
    Should -Invoke -CommandName Test-EventLogSourceExists -ModuleName EventLog -Times 0
  }

  It 'returns true without registration when the source already exists' {
    $result = Ensure-EventSource -Source 'ExistingSource' -LogName 'Application'

    $result | Should -Be $true
    Should -Invoke -CommandName Register-EventLogSource -ModuleName EventLog -Times 0
  }

  It 'registers a missing source through the .NET wrapper' {
    Mock -CommandName Test-EventLogSourceExists -ModuleName EventLog -MockWith { $false }

    $result = Ensure-EventSource -Source 'NewSource' -LogName 'CustomLog'

    $result | Should -Be $true
    Should -Invoke -CommandName Register-EventLogSource -ModuleName EventLog -Times 1 -Exactly -ParameterFilter {
      $Source -eq 'NewSource' -and $LogName -eq 'CustomLog'
    }
  }

  It 'returns false and preserves custom error behavior when registration fails' {
    Mock -CommandName Test-EventLogSourceExists -ModuleName EventLog -MockWith { $false }
    Mock -CommandName Register-EventLogSource -ModuleName EventLog -MockWith { throw 'registration denied' }

    $output = Ensure-EventSource `
      -Source 'NewSource' `
      -LogName 'Application' `
      -OnErrorMessage 'event source unavailable' 3>&1

    $output | Where-Object { $_ -eq $false } | Should -Not -BeNullOrEmpty
    Get-WarningMessages -Output $output | Should -Contain 'event source unavailable'
  }
}

Describe 'Write-HealthEvent' {
  BeforeEach {
    Mock -CommandName Write-EventLogEntry -ModuleName EventLog -MockWith {}
  }

  AfterEach {
    Clear-EventLogTestGlobals
  }

  It 'returns false when Source is missing' {
    Set-Variable -Name EventLogName -Scope Global -Value 'Application'

    $result = Write-HealthEvent -Id 1000 -Message 'Test' -OnErrorMessage 'Test error message' 3>&1

    $result | Where-Object { $_ -eq $false } | Should -Not -BeNullOrEmpty
    Should -Invoke -CommandName Write-EventLogEntry -ModuleName EventLog -Times 0
  }

  It 'returns false when LogName is missing' {
    $result = Write-HealthEvent -Id 1000 -Message 'Test' -Source 'TestSource' -OnErrorMessage 'Test error message' 3>&1

    $result | Where-Object { $_ -eq $false } | Should -Not -BeNullOrEmpty
    Should -Invoke -CommandName Write-EventLogEntry -ModuleName EventLog -Times 0
  }

  It 'writes the requested event through the .NET wrapper' {
    $result = Write-HealthEvent `
      -Id 4242 `
      -Message 'Health check complete' `
      -Level Warning `
      -Source 'HealthSource' `
      -LogName 'Application'

    $result | Should -Be $true
    Should -Invoke -CommandName Write-EventLogEntry -ModuleName EventLog -Times 1 -Exactly -ParameterFilter {
      $LogName -eq 'Application' -and
      $Source -eq 'HealthSource' -and
      $Id -eq 4242 -and
      $Message -eq 'Health check complete' -and
      $Level -eq 'Warning'
    }
  }

  It 'returns false and preserves default exception warnings when writing fails' {
    Mock -CommandName Write-EventLogEntry -ModuleName EventLog -MockWith { throw 'write denied' }

    $output = Write-HealthEvent `
      -Id 1000 `
      -Message 'Test' `
      -Source 'TestSource' `
      -LogName 'Application' 3>&1

    $output | Where-Object { $_ -eq $false } | Should -Not -BeNullOrEmpty
    Get-WarningMessages -Output $output | Should -Contain 'write denied'
  }
}

Describe 'System.Diagnostics.EventLog implementation' {
  It 'uses the cross-runtime .NET API instead of removed Windows-only cmdlets' {
    $script:EventLogModuleSource | Should -Match '\[System\.Diagnostics\.EventLog\]::SourceExists'
    $script:EventLogModuleSource | Should -Match '\[System\.Diagnostics\.EventLog\]::CreateEventSource'
    $script:EventLogModuleSource | Should -Match '\[System\.Diagnostics\.EventLog\]::new'
    $script:EventLogModuleSource | Should -Match '\.WriteEntry\('
    $script:EventLogModuleSource | Should -Not -Match '(?m)^\s*New-EventLog\b'
    $script:EventLogModuleSource | Should -Not -Match '(?m)^\s*Write-EventLog\b'
  }
}
