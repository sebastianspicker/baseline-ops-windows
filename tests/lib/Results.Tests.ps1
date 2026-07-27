#requires -version 5.1
<#
.SYNOPSIS
Pester tests for Results.psm1 module

.DESCRIPTION
Unit tests for Get-FindingsList, Get-FindingObject, and Add-Finding.
#>

[CmdletBinding()]
param()

BeforeAll {
  Import-Module (Join-Path $PSScriptRoot '../../lib/Common.psm1') -Force -DisableNameChecking
  Import-Module (Join-Path $PSScriptRoot '../../lib/Results.psm1') -Force
}

Describe 'Get-FindingsList' {
  It 'Returns an empty generic list' {
    $list = Get-FindingsList
    # Empty collections are unrolled by pipeline; use direct assertions
    $null -ne $list | Should -Be $true
    $list.Count | Should -Be 0
    $list.GetType().Name | Should -Match 'List'
  }

  It 'Returns the empty list as a single object' {
    @(Get-FindingsList).Count | Should -Be 1
  }

  It 'Returns a list that supports Add method' {
    $list = Get-FindingsList
    { $list.Add('test') } | Should -Not -Throw
    $list.Count | Should -Be 1
  }
}

Describe 'Get-FindingObject' {
  It 'Creates finding with required fields' {
    $finding = Get-FindingObject -Code 'TEST-001' -Severity 'Warn' -Message 'Test finding'
    $finding.Code | Should -Be 'TEST-001'
    $finding.Severity | Should -Be 'Warn'
    $finding.Message | Should -Be 'Test finding'
  }

  It 'Inserts TypeName when provided' {
    $finding = Get-FindingObject -Code 'TEST-002' -Severity 'Fail' -Message 'Typed' -TypeName 'MyType'
    $finding.PSTypeNames | Should -Contain 'MyType'
  }

  It 'Merges Extra hashtable properties' {
    $extra = @{ Detail = 'extra info'; Count = 5 }
    $finding = Get-FindingObject -Code 'TEST-003' -Severity 'Info' -Message 'With extras' -Extra $extra
    $finding.Detail | Should -Be 'extra info'
    $finding.Count | Should -Be 5
  }

  It 'Works without optional parameters' {
    $finding = Get-FindingObject -Code 'MIN-001' -Severity 'OK' -Message 'Minimal'
    $finding | Should -Not -BeNullOrEmpty
    $finding.Code | Should -Be 'MIN-001'
  }

  It 'Rejects unknown severity values' {
    { Get-FindingObject -Code 'BAD-001' -Severity 'Severeish' -Message 'Bad severity' } |
      Should -Throw '*Severity*'
  }
}

Describe 'Add-Finding' {
  It 'Adds a finding to the provided list' {
    $list = Get-FindingsList
    Add-Finding -FindingList $list -Code 'ADD-001' -Severity 'Warn' -Message 'Added finding' | Out-Null
    $list.Count | Should -Be 1
    $list[0].Code | Should -Be 'ADD-001'
  }

  It 'Adds multiple findings to the same list' {
    $list = Get-FindingsList
    Add-Finding -FindingList $list -Code 'MULTI-001' -Severity 'Warn' -Message 'First' | Out-Null
    Add-Finding -FindingList $list -Code 'MULTI-002' -Severity 'Fail' -Message 'Second' | Out-Null
    $list.Count | Should -Be 2
    $list[0].Code | Should -Be 'MULTI-001'
    $list[1].Code | Should -Be 'MULTI-002'
  }

  It 'Includes ProfileName in Extra fields' {
    $list = Get-FindingsList
    Add-Finding -FindingList $list -Code 'PROF-001' -Severity 'Info' -Message 'Profile test' -ProfileName 'Baseline' | Out-Null
    $list[0].Profile | Should -Be 'Baseline'
  }

  It 'Throws when FindingList is null and no caller scope variable exists' {
    { Add-Finding -Code 'NOPE-001' -Severity 'Fail' -Message 'No list' } | Should -Throw '*FindingList*'
  }

  It 'does not emit the mutated list by default' {
    $list = Get-FindingsList
    $output = @(Add-Finding -FindingList $list -Code 'QUIET-001' -Severity 'OK' -Message 'Quiet mutation test')

    $output.Count | Should -Be 0
    $list.Count | Should -Be 1
    $list[0].Code | Should -Be 'QUIET-001'
  }

  It 'returns the FindingList when PassThru is requested' {
    $list = Get-FindingsList
    $result = Add-Finding -FindingList $list -Code 'RET-001' -Severity 'OK' -Message 'Return test' -PassThru
    $result | Should -Not -BeNullOrEmpty
    $result.Count | Should -Be 1
    [object]::ReferenceEquals($list, $result) | Should -BeTrue
  }

  It 'Merges Extra hashtable into the finding' {
    $list = Get-FindingsList
    Add-Finding -FindingList $list -Code 'EXT-001' -Severity 'Warn' -Message 'Extra test' -Extra @{ Path = 'C:\test' } | Out-Null
    $list[0].Path | Should -Be 'C:\test'
  }

  It 'Adds an explicit UTC timestamp when requested' {
    $list = Get-FindingsList
    $before = [datetime]::UtcNow.AddSeconds(-1)
    Add-Finding -FindingList $list -Code 'UTC-001' -Severity 'Info' -Message 'UTC timestamp' -TimeUtc | Out-Null
    $after = [datetime]::UtcNow.AddSeconds(1)

    $list[0].TimeUtc.Kind | Should -Be ([DateTimeKind]::Utc)
    $list[0].TimeUtc | Should -BeGreaterOrEqual $before
    $list[0].TimeUtc | Should -BeLessOrEqual $after
  }

  It 'Adds an explicit local timestamp when requested' {
    $list = Get-FindingsList
    Add-Finding -FindingList $list -Code 'LOCAL-001' -Severity 'Info' -Message 'Local timestamp' -TimestampLocal | Out-Null

    $list[0].PSObject.Properties.Name | Should -Contain 'Timestamp'
    $list[0].Timestamp | Should -BeOfType ([datetime])
  }

  It 'Preserves duplicate finding codes as separate target findings' {
    $list = Get-FindingsList
    Add-Finding -FindingList $list -Code 'DUP-001' -Severity 'Low' -Message 'First target' | Out-Null
    Add-Finding -FindingList $list -Code 'DUP-001' -Severity 'Low' -Message 'Second target' | Out-Null

    $list.Count | Should -Be 2
    $list[0].Message | Should -Be 'First target'
    $list[1].Message | Should -Be 'Second target'
  }

  It 'Rejects unknown severity values before appending' {
    $list = Get-FindingsList

    { Add-Finding -FindingList $list -Code 'BAD-002' -Severity 'Severeish' -Message 'Bad severity' } |
      Should -Throw '*Severity*'
    $list.Count | Should -Be 0
  }
}
