<#
.SYNOPSIS
  Tests clone-baseline rationale carry-forward.
.DESCRIPTION
  Covers reviewed rationales for moved clones and review markers for changed clones.
#>

BeforeAll {
  $repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
  Import-Module (Join-Path $repoRoot 'dev/quality/CloneBaseline.psm1') -Force

  # Each start line adds one scripts/a.ps1 occurrence paired with a fixed anchor block.
  function New-FixtureEntries([string]$Fragment, [int[]]$Starts, [string]$FirstPath = 'scripts/a.ps1') {
    $anchor = [pscustomobject]@{ Name = 'scripts/anchor.ps1'; Start = 10; End = 14 }
    $duplicates = foreach ($start in $Starts) {
      $first = [pscustomobject]@{ Name = $FirstPath; Start = $start; End = ($start + 4) }
      [pscustomobject]@{ Fragment = $Fragment; FirstFile = $first; SecondFile = $anchor }
    }
    $report = [pscustomobject]@{
      Statistics = [pscustomobject]@{ Total = [pscustomobject]@{ Sources = 2 } }
      Duplicates = @($duplicates)
    }
    return @(ConvertFrom-JscpdReport $report PowerShell 5.1.2)
  }

  function New-ReviewedBaseline([string]$Fragment, [int[]]$Starts) {
    $entries = @(New-FixtureEntries $Fragment $Starts)
    foreach ($entry in $entries) { $entry.Rationale = 'Reviewed shared parser boundary.' }
    return [pscustomobject]@{ SchemaVersion = 1; Entries = @($entries) }
  }

  function Update-FixtureBaseline($Current, $Existing) {
    $path = Join-Path $TestDrive 'baseline.json'
    Update-CloneBaseline -Path $path -Current $Current -Existing $Existing
    return Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
  }
}

Describe 'Clone baseline rationale carry-forward' {
  It 'carries a reviewed rationale to a moved clone with unchanged content' {
    $existing = New-ReviewedBaseline 'same fragment' @(1)
    $current = @(New-FixtureEntries 'same fragment' @(2))
    (Compare-CloneBaseline $current $existing PowerShell).Kind | Should -Contain moved_clone
    $updated = Update-FixtureBaseline $current $existing
    $updated.Entries[0].Fingerprint | Should -Not -Be $existing.Entries[0].Fingerprint
    $updated.Entries[0].Rationale | Should -Be 'Reviewed shared parser boundary.'
  }

  It 'requires review when the normalized content changes' {
    $existing = New-ReviewedBaseline 'old fragment' @(1)
    $current = @(New-FixtureEntries 'new fragment' @(2))
    (Update-FixtureBaseline $current $existing).Entries[0].Rationale | Should -Be 'REVIEW REQUIRED'
  }

  It 'requires review when the same content now pairs different files' {
    $existing = New-ReviewedBaseline 'same fragment' @(1)
    $current = @(New-FixtureEntries 'same fragment' @(1) 'scripts/b.ps1')
    (Update-FixtureBaseline $current $existing).Entries[0].Rationale | Should -Be 'REVIEW REQUIRED'
  }

  It 'requires review when the occurrence count changes' {
    $existing = New-ReviewedBaseline 'same fragment' @(1)
    $current = @(New-FixtureEntries 'same fragment' @(2, 20))
    $current[0].Multiplicity | Should -Be 3
    (Update-FixtureBaseline $current $existing).Entries[0].Rationale | Should -Be 'REVIEW REQUIRED'
  }
}
