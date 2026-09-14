<#
.SYNOPSIS
  Tests Rust metric boundary parsing.
.DESCRIPTION
  Locks the Lizard CSV and XML boundary behavior used by the Rust quality gate.
#>

BeforeAll {
  $repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
  Import-Module (Join-Path $repoRoot 'tools/quality/QualityScans.psm1') -Force
  $fixtureRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('baseline-rust-metrics-' + [guid]::NewGuid())
  [void](New-Item -ItemType Directory -Path $fixtureRoot)
}

AfterAll { Remove-Item -LiteralPath $fixtureRoot -Recurse -Force }

Describe 'Rust quality metric parsing' {
  It 'enforces function NLOC, complexity, and parameter boundaries' {
    $csv = Join-Path $fixtureRoot 'lizard.csv'
    @(
      '49,7,1,8,49,at_limit,src/limit.rs,at_limit,sig,1,49'
      '50,8,1,9,50,over_limit,src/over.rs,over_limit,sig,1,50'
    ) | Set-Content -LiteralPath $csv
    $findings = @(& (Get-Module QualityScans) { param($path) Read-LizardFunctionFindings $path } $csv)
    $findings.Count | Should -Be 3
    $findings.Kind | Should -Contain function_nloc
    $findings.Kind | Should -Contain function_ccn
    $findings.Kind | Should -Contain function_parameters
  }

  It 'enforces the file NLOC boundary' {
    $xml = Join-Path $fixtureRoot 'lizard.xml'
    @'
<cppncss><measure type="File">
  <item name="src/limit.rs"><value>1</value><value>499</value></item>
  <item name="src/over.rs"><value>2</value><value>500</value></item>
</measure></cppncss>
'@ | Set-Content -LiteralPath $xml
    $findings = @(& (Get-Module QualityScans) { param($path) Read-LizardFileFindings $path } $xml)
    $findings.Count | Should -Be 1
    $findings[0].Path | Should -Be 'src/over.rs'
    $findings[0].Kind | Should -Be file_nloc
  }
}
