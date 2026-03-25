#requires -version 5.1
<#
.SYNOPSIS
Pester tests for Results.psm1 module

.DESCRIPTION
Unit tests for New-FindingsList, New-FindingObject, and Add-Finding.
#>

[CmdletBinding()]
param()

BeforeAll {
  Import-Module (Join-Path $PSScriptRoot '../../lib/Common.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '../../lib/Results.psm1') -Force
}

Describe 'New-FindingsList' {
  It 'Returns an empty generic list' {
    $list = New-FindingsList
    # Empty collections are unrolled by pipeline; use direct assertions
    $null -ne $list | Should -Be $true
    $list.Count | Should -Be 0
    $list.GetType().Name | Should -Match 'List'
  }

  It 'Returns a list that supports Add method' {
    $list = New-FindingsList
    { $list.Add('test') } | Should -Not -Throw
    $list.Count | Should -Be 1
  }
}

Describe 'New-FindingObject' {
  It 'Creates finding with required fields' {
    $finding = New-FindingObject -Code 'TEST-001' -Severity 'Warn' -Message 'Test finding'
    $finding.Code | Should -Be 'TEST-001'
    $finding.Severity | Should -Be 'Warn'
    $finding.Message | Should -Be 'Test finding'
  }

  It 'Inserts TypeName when provided' {
    $finding = New-FindingObject -Code 'TEST-002' -Severity 'Fail' -Message 'Typed' -TypeName 'MyType'
    $finding.PSTypeNames | Should -Contain 'MyType'
  }

  It 'Merges Extra hashtable properties' {
    $extra = @{ Detail = 'extra info'; Count = 5 }
    $finding = New-FindingObject -Code 'TEST-003' -Severity 'Info' -Message 'With extras' -Extra $extra
    $finding.Detail | Should -Be 'extra info'
    $finding.Count | Should -Be 5
  }

  It 'Works without optional parameters' {
    $finding = New-FindingObject -Code 'MIN-001' -Severity 'OK' -Message 'Minimal'
    $finding | Should -Not -BeNullOrEmpty
    $finding.Code | Should -Be 'MIN-001'
  }
}

Describe 'Add-Finding' {
  It 'Adds a finding to the provided list' {
    $list = New-FindingsList
    $result = Add-Finding -FindingList $list -Code 'ADD-001' -Severity 'Warn' -Message 'Added finding'
    $list.Count | Should -Be 1
    $list[0].Code | Should -Be 'ADD-001'
  }

  It 'Adds multiple findings to the same list' {
    $list = New-FindingsList
    Add-Finding -FindingList $list -Code 'MULTI-001' -Severity 'Warn' -Message 'First' | Out-Null
    Add-Finding -FindingList $list -Code 'MULTI-002' -Severity 'Fail' -Message 'Second' | Out-Null
    $list.Count | Should -Be 2
    $list[0].Code | Should -Be 'MULTI-001'
    $list[1].Code | Should -Be 'MULTI-002'
  }

  It 'Includes ProfileName in Extra fields' {
    $list = New-FindingsList
    Add-Finding -FindingList $list -Code 'PROF-001' -Severity 'Info' -Message 'Profile test' -ProfileName 'Baseline' | Out-Null
    $list[0].Profile | Should -Be 'Baseline'
  }

  It 'Throws when FindingList is null and no caller scope variable exists' {
    { Add-Finding -Code 'NOPE-001' -Severity 'Fail' -Message 'No list' } | Should -Throw '*FindingList*'
  }

  It 'Returns the FindingList after adding' {
    $list = New-FindingsList
    $result = Add-Finding -FindingList $list -Code 'RET-001' -Severity 'OK' -Message 'Return test'
    $result | Should -Not -BeNullOrEmpty
    $result.Count | Should -Be 1
  }

  It 'Merges Extra hashtable into the finding' {
    $list = New-FindingsList
    Add-Finding -FindingList $list -Code 'EXT-001' -Severity 'Warn' -Message 'Extra test' -Extra @{ Path = 'C:\test' } | Out-Null
    $list[0].Path | Should -Be 'C:\test'
  }
}
