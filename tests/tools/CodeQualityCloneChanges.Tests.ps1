<#
.SYNOPSIS
  Tests clone-baseline change detection.
.DESCRIPTION
  Covers new, moved, expanded, and removed clone fingerprints.
#>

BeforeAll {
  $repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
  Import-Module (Join-Path $repoRoot 'tools/quality/CloneBaseline.psm1') -Force
  function New-CloneReport($fragment, $start) {
    $file1 = [pscustomobject]@{ Name='scripts/a.ps1'; Start=$start; End=($start + 4) }
    $file2 = [pscustomobject]@{ Name='scripts/b.ps1'; Start=10; End=14 }
    return [pscustomobject]@{
      Statistics=[pscustomobject]@{ Total=[pscustomobject]@{ Sources=2 } }
      Duplicates=@([pscustomobject]@{ Fragment=$fragment; FirstFile=$file1; SecondFile=$file2 })
    }
  }
  function New-Baseline($entries) { return [pscustomobject]@{ SchemaVersion=1; Entries=@($entries) } }
}

Describe 'Clone baseline changes' {
  It 'detects a new clone' {
    $current = ConvertFrom-JscpdReport (New-CloneReport 'alpha beta gamma' 1) PowerShell 5.1.2
    (Compare-CloneBaseline $current (New-Baseline @()) PowerShell).Kind | Should -Be new_clone
  }

  It 'detects a moved clone' {
    $old = ConvertFrom-JscpdReport (New-CloneReport 'same fragment' 1) PowerShell 5.1.2
    $new = ConvertFrom-JscpdReport (New-CloneReport 'same fragment' 2) PowerShell 5.1.2
    (Compare-CloneBaseline $new (New-Baseline $old) PowerShell).Kind | Should -Contain moved_clone
  }

  It 'detects expansion as stale plus new' {
    $old = ConvertFrom-JscpdReport (New-CloneReport 'small fragment' 1) PowerShell 5.1.2
    $new = ConvertFrom-JscpdReport (New-CloneReport 'small fragment expanded' 1) PowerShell 5.1.2
    $kinds = (Compare-CloneBaseline $new (New-Baseline $old) PowerShell).Kind
    $kinds | Should -Contain new_clone
    $kinds | Should -Contain stale_clone
  }

  It 'detects a removed clone as stale' {
    $old = ConvertFrom-JscpdReport (New-CloneReport 'old fragment' 1) PowerShell 5.1.2
    (Compare-CloneBaseline @() (New-Baseline $old) PowerShell).Kind | Should -Be stale_clone
  }
}
