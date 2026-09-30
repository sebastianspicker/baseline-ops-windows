#requires -version 5.1
<#
.SYNOPSIS
Static analysis of every public script closure for binding and variable defects.
.DESCRIPTION
Parses each scripts/*.ps1 entry point together with its scripts/internal
helpers and the runner bootstrap, without executing them. Fails when a named
argument cannot bind to the called function or lib export, or when a variable
is read but never assigned anywhere in the closure. Both classes throw under
Set-StrictMode -Version Latest only on the code path that reaches them, which
portable tests rarely do for Windows-only capabilities.
#>

BeforeDiscovery {
  . (Join-Path $PSScriptRoot 'StaticAnalysis.Cases.ps1')
  $script:entryCases = @(Get-StaticAnalysisEntryCases)
}

BeforeAll {
  . (Join-Path $PSScriptRoot 'StaticAnalysis.Cases.ps1')
  $script:root = Get-StaticAnalysisRoot
  $script:libCatalog = Get-StaticAnalysisLibCatalog
}

Describe 'script closure static analysis' -Tag 'StaticAnalysis' {
  It '<Name> binds every named argument to a declared parameter' -ForEach $script:entryCases {
    $files = Get-StaticAnalysisClosure -EntryPath $Path
    $findings = @(Find-StaticAnalysisUnboundParameter -Files $files -LibCatalog $script:libCatalog -RootPath $script:root)
    ($findings -join [Environment]::NewLine) | Should -BeNullOrEmpty
  }

  It '<Name> assigns every variable it reads' -ForEach $script:entryCases {
    $files = Get-StaticAnalysisClosure -EntryPath $Path
    $findings = @(Find-StaticAnalysisUnassignedVariable -Files $files -LibCatalog $script:libCatalog -RootPath $script:root)
    ($findings -join [Environment]::NewLine) | Should -BeNullOrEmpty
  }
}

Describe 'static analysis detectors' -Tag 'StaticAnalysis' {
  BeforeAll {
    $script:fixture = New-StaticAnalysisFixture -Directory $TestDrive -Name '99-Fixture.ps1' -Lines @(
      'function Invoke-Fixture { [CmdletBinding(SupportsShouldProcess = $true)] param([string]$Target, [switch]$Force) $Target }'
      'Invoke-Fixture -Tar ''a'' -Remediate:$true -WhatIf -ErrorAction Stop'
      'Write-KeyValue -Key ''k'' -Label ''k'''
      'if ($null -ne $neverAssigned) { $script:assigned = 1 }'
      '$script:assigned; $env:PATH'
    )
    $script:importing = New-StaticAnalysisFixture -Directory $TestDrive -Name '98-Fixture.ps1' -Lines @(
      'Import-Module (Join-Path $script:LibPath ''Output.psm1'') -Force'
      'Write-KeyValue -Key ''k'' -Label ''k'''
    )
  }

  It 'reports a named argument that no parameter or unique prefix accepts' {
    $findings = @(Find-StaticAnalysisUnboundParameter -Files @($script:fixture) -LibCatalog $script:libCatalog -RootPath $TestDrive)
    $findings | Should -Be @('scripts/99-Fixture.ps1:2 Invoke-Fixture -Remediate (no such parameter)')
  }

  It 'resolves lib exports only when the closure imports their module' {
    $findings = @(Find-StaticAnalysisUnboundParameter -Files @($script:importing) -LibCatalog $script:libCatalog -RootPath $TestDrive)
    $findings | Should -Be @('scripts/98-Fixture.ps1:2 Write-KeyValue -Label (no such parameter)')
  }

  It 'reports a read of a variable that the closure never assigns' {
    $findings = @(Find-StaticAnalysisUnassignedVariable -Files @($script:fixture) -LibCatalog $script:libCatalog -RootPath $TestDrive)
    $findings | Should -Be @('scripts/99-Fixture.ps1:4 $neverAssigned')
  }
}
