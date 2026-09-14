<#
.SYNOPSIS
  Tests PowerShell metric boundary behavior.
.DESCRIPTION
  Exercises NLOC, complexity, parameter, nested-function, and deterministic reporting contracts.
#>

BeforeAll {
  $repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
  Import-Module (Join-Path $repoRoot 'tools/quality/PowerShellMetrics.psm1') -Force
  $fixtureRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('baseline-quality-' + [guid]::NewGuid())
  [void](New-Item -ItemType Directory -Path $fixtureRoot)

  function Test-FunctionNlocBoundary {
    $path = Join-Path $fixtureRoot 'nloc.ps1'
    @('function Test-Boundary {') + @('  1') * 47 + @('}') | Set-Content $path
    (Get-PowerShellMetricFindings $fixtureRoot @($path)).Kind | Should -Not -Contain function_nloc
    @('function Test-Boundary {') + @('  1') * 48 + @('}') | Set-Content $path
    (Get-PowerShellMetricFindings $fixtureRoot @($path)).Kind | Should -Contain function_nloc
  }

  function Test-FileNlocBoundary {
    $path = Join-Path $fixtureRoot 'file-nloc.ps1'
    @('1') * 499 | Set-Content $path
    (Get-PowerShellMetricFindings $fixtureRoot @($path)).Kind | Should -Not -Contain file_nloc
    @('1') * 500 | Set-Content $path
    (Get-PowerShellMetricFindings $fixtureRoot @($path)).Kind | Should -Contain file_nloc
  }

  function Test-ComplexityAndParameterBoundaries {
    $path = Join-Path $fixtureRoot 'branches.ps1'
    $ifs = @('  if ($true) { 1 }') * 6
    @('function Test-Boundary($a,$b,$c,$d,$e,$f,$g,$h) {') + $ifs + @('}') | Set-Content $path
    Get-PowerShellMetricFindings $fixtureRoot @($path) | Should -BeNullOrEmpty
    @('function Test-Boundary($a,$b,$c,$d,$e,$f,$g,$h,$i) {') + $ifs + @('  if ($true) { 1 }', '}') | Set-Content $path
    $kinds = (Get-PowerShellMetricFindings $fixtureRoot @($path)).Kind
    $kinds | Should -Contain function_ccn
    $kinds | Should -Contain function_parameters
  }

  function Test-NestedFunctionExclusion {
    $one = Join-Path $fixtureRoot 'one.ps1'; $two = Join-Path $fixtureRoot 'two.ps1'
    @('function Test-Outer {',' function Test-Inner {') + @('  1') * 48 + @(' }','}') | Set-Content $one
    'function Test-Two { 1 }' | Set-Content $two
    $first = @(Get-PowerShellMetricFindings $fixtureRoot @($two, $one))
    $second = @(Get-PowerShellMetricFindings $fixtureRoot @($one, $two))
    ($first | ConvertTo-Json -Depth 4) | Should -Be ($second | ConvertTo-Json -Depth 4)
    @($first | Where-Object Symbol -eq 'Test-Outer') | Should -BeNullOrEmpty
    @($first | Where-Object Symbol -eq 'Test-Inner').Kind | Should -Contain function_nloc
  }
}

AfterAll { Remove-Item -LiteralPath $fixtureRoot -Recurse -Force }

Describe 'PowerShell quality metrics' {
  It 'enforces NLOC at the exact boundary' {
    Test-FunctionNlocBoundary
  }

  It 'enforces the file NLOC boundary independently of script-body findings' {
    Test-FileNlocBoundary
  }

  It 'enforces complexity and parameter boundaries' {
    Test-ComplexityAndParameterBoundaries
  }

  It 'exempts public script parameter blocks from the function parameter ceiling' {
    $path = Join-Path $fixtureRoot 'public-script.ps1'
    'param($a,$b,$c,$d,$e,$f,$g,$h,$i) 1' | Set-Content $path
    (Get-PowerShellMetricFindings $fixtureRoot @($path)).Kind | Should -Not -Contain function_parameters
  }

  It 'excludes nested function bodies and reports deterministically' {
    Test-NestedFunctionExclusion
  }

  It 'fails a zero-file scan and remains PowerShell 5.1 parseable' {
    { Get-PowerShellMetricFindings $fixtureRoot @() } | Should -Throw
    $tokens = $null; $errors = $null
    [System.Management.Automation.Language.Parser]::ParseFile(
      (Join-Path $repoRoot 'tools/quality/Test-CodeQuality.ps1'), [ref]$tokens, [ref]$errors
    ) | Out-Null
    $errors | Should -BeNullOrEmpty
  }
}
