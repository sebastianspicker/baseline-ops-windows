<#
.SYNOPSIS
  Tests clone-baseline schema validation.
.DESCRIPTION
  Covers malformed, out-of-scope, and unexplained accepted clone records.
#>

BeforeAll {
  $repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
  Import-Module (Join-Path $repoRoot 'tools/quality/CloneBaseline.psm1') -Force
  $fixtureRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('baseline-clones-' + [guid]::NewGuid())
  [void](New-Item -ItemType Directory -Path $fixtureRoot)
  function New-ValidationEntry {
    $file1 = [pscustomobject]@{ Name='scripts/a.ps1'; Start=1; End=5 }
    $file2 = [pscustomobject]@{ Name='scripts/b.ps1'; Start=1; End=5 }
    $report = [pscustomobject]@{
      Statistics=[pscustomobject]@{ Total=[pscustomobject]@{ Sources=2 } }
      Duplicates=@([pscustomobject]@{ Fragment='review me'; FirstFile=$file1; SecondFile=$file2 })
    }
    return @(ConvertFrom-JscpdReport $report PowerShell 5.1.2)[0]
  }
  function Write-Baseline($entry, $name) {
    $path = Join-Path $fixtureRoot $name
    [pscustomobject]@{ SchemaVersion=1; Entries=@($entry) } |
      ConvertTo-Json -Depth 12 | Set-Content $path
    return $path
  }
}

AfterAll { Remove-Item -LiteralPath $fixtureRoot -Recurse -Force }

Describe 'Clone baseline validation' {
  It 'rejects a missing rationale' {
    $entry = New-ValidationEntry
    { Read-CloneBaseline (Write-Baseline $entry 'missing.json') PowerShell 5.1.2 } | Should -Throw
  }

  It 'rejects an out-of-scope occurrence' {
    $entry = New-ValidationEntry; $entry.Rationale = 'Reviewed boundary.'
    $entry.Occurrences[0].Path = '../outside.ps1'
    { Read-CloneBaseline (Write-Baseline $entry 'scope.json') PowerShell 5.1.2 } | Should -Throw
  }

  It 'rejects a malformed fingerprint' {
    $entry = New-ValidationEntry; $entry.Rationale = 'Reviewed boundary.'; $entry.Fingerprint = 'bad'
    { Read-CloneBaseline (Write-Baseline $entry 'fingerprint.json') PowerShell 5.1.2 } | Should -Throw
  }

  It 'rejects a zero-file detector report' {
    $report = [pscustomobject]@{ Statistics=[pscustomobject]@{ Total=[pscustomobject]@{ Sources=0 } }; Duplicates=@() }
    { ConvertFrom-JscpdReport $report PowerShell 5.1.2 } | Should -Throw
  }

  It 'accepts Rust oracle adapters only within the Rust release-line scope' {
    $report = [pscustomobject]@{
      Statistics = [pscustomobject]@{ Total = [pscustomobject]@{ Sources = 2 } }
      Duplicates = @([pscustomobject]@{
          Fragment = 'shared rust oracle fragment'
          FirstFile = [pscustomobject]@{ Name = 'tests/RustV3Oracle.Adapter.ps1'; Start = 1; End = 5 }
          SecondFile = [pscustomobject]@{ Name = 'src/lib.rs'; Start = 1; End = 5 }
        })
    }
    $entry = @(ConvertFrom-JscpdReport $report Rust 5.1.2)[0]
    $entry.Rationale = 'Reviewed Rust oracle boundary.'
    { Read-CloneBaseline (Write-Baseline $entry 'rust-scope.json') Rust 5.1.2 } | Should -Not -Throw
    $entry.Occurrences[0].Path = 'tests/Unrelated.Tests.ps1'
    { Read-CloneBaseline (Write-Baseline $entry 'rust-outside.json') Rust 5.1.2 } | Should -Throw
  }
}
