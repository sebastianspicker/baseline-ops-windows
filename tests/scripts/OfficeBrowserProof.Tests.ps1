#requires -version 5.1
<#
.SYNOPSIS
  Provides controlled Office and browser policy fixtures.
.DESCRIPTION
  Replaces endpoint observations and registry writes with in-memory state to verify proof output and confirmation decisions.
#>

BeforeAll {
  . (Join-Path $PSScriptRoot 'OfficeBrowserProof.Fixture.ps1')
  Import-Module (New-OfficeBrowserTestModule) -Force
  function New-OfficeBrowserScenario {
    $catalog = Get-DefaultOfficeBrowserCatalog | ConvertFrom-Json
    $catalog.Firefox.Enable = $false
    $catalog.Edge.HomePageURL = 'https://home.example'
    $catalog.Edge.StartupURLs = @('https://a.example', 'https://b.example')
    $catalog.Proof.OutFile = '/controlled/proof.json'
    return @{
      Files = @{'catalog.json' = ($catalog | ConvertTo-Json -Depth 15) }
      Admin = $false
      FailSave = $false
      FailWrite = $false
      RegistryDefault = 0
      Remediate = $false
      Strict = $false
      CatalogPath = 'catalog.json'
      ConfigPath = ''
      WhatIf = $false
    }
  }
}
Describe 'Office and browser policy proof' {
  It 'preserves proof order and audit-only registry behavior' {
    $run = Invoke-OfficeBrowserFixture (New-OfficeBrowserScenario)
    $run.Writes.Count | Should -Be 0
    $run.Proof.Items[0].Product | Should -Be Office
    $run.Proof.Items[0].Policy | Should -Be VBAWarnings
    $run.Proof.Items[-1].Product | Should -Be Firefox
    $run.Proof.Items[-1].Message | Should -Be 'Skipped (Enable=false)'
    $run.Path | Should -Be '/controlled/proof.json'
    $run.Events[0].Id | Should -Be 4950
    $run.Ok | Should -BeFalse
  }
  It 'keeps WhatIf ahead of every Office and Edge registry mutation' {
    $fixture = New-OfficeBrowserScenario
    $fixture.Remediate = $true
    $fixture.WhatIf = $true
    $run = Invoke-OfficeBrowserFixture $fixture
    $run.Writes.Count | Should -Be 0
    @($run.Proof.Items | Where-Object Changed).Count | Should -Be 0
    @($run.Proof.Items | Where-Object Message -eq 'Set skipped by confirmation/WhatIf').Count | Should -BeGreaterThan 0
  }
  It 'records successful writes and rereads registry values' {
    $fixture = New-OfficeBrowserScenario
    $fixture.Remediate = $true
    $run = Invoke-OfficeBrowserFixture $fixture
    $run.Writes.Count | Should -BeGreaterThan 0
    $run.Proof.Items[0].Actual | Should -Be 3
    $run.Proof.Items[0].Changed | Should -BeTrue
    $run.Proof.Items[0].Compliant | Should -BeTrue
  }
  It 'retains save failures in final notes after the proof snapshot' {
    $fixture = New-OfficeBrowserScenario
    $fixture.FailSave = $true
    $run = Invoke-OfficeBrowserFixture $fixture
    $run.Notes[-1] | Should -Be 'Failed to write proof JSON: controlled save failure'
    $run.Proof.Notes | Should -Not -Contain $run.Notes[-1]
  }
}
