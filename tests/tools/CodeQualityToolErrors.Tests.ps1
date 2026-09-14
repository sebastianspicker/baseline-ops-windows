<#
.SYNOPSIS
  Tests fail-closed handling for quality-tool process errors.
.DESCRIPTION
  Verifies that an analyzer subprocess failure cannot be mistaken for a clean scan.
#>

BeforeAll {
  $repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
  Import-Module (Join-Path $repoRoot 'tools/quality/ExternalAnalyzers.psm1') -Force
  Import-Module (Join-Path $repoRoot 'tools/quality/QualityScans.psm1') -Force
  $script:PowerShellExecutable = (Get-Process -Id $PID).Path
}

Describe 'Quality tool errors' {
  It 'fails when a quality subprocess exits unsuccessfully' {
    {
      Invoke-QualityNative -Command $script:PowerShellExecutable -Arguments @(
        '-NoProfile', '-Command', 'exit 23'
      )
    } | Should -Throw
  }

  It 'keeps a single clone scan root as one native argument' {
    $module = Get-Module QualityScans
    $roots = @(& $module { Get-JscpdScanRoots -RootPath '/tmp/baseline-ops' -ReleaseLine PowerShell })
    $roots.Count | Should -Be 1
    $roots[0] | Should -Be '/tmp/baseline-ops'
  }
}

Describe 'Shared PowerShell analyzer scan' {
  BeforeAll {
    function global:Invoke-ScriptAnalyzer {
      param($Path, $Settings)
      throw "Unexpected unmocked analyzer call for $Path with $Settings"
    }
  }

  AfterAll {
    Remove-Item Function:\Invoke-ScriptAnalyzer -ErrorAction SilentlyContinue
  }

  It 'analyzes each file only once across overlapping requested paths' {
    Mock Invoke-ScriptAnalyzer -ModuleName QualityScans { @() }
    $paths = @((Join-Path $repoRoot 'tests/one.ps1'), (Join-Path $repoRoot 'tests/two.ps1'))
    $result = @(Invoke-PowerShellAnalyzerScan -RootPath $repoRoot -Paths ($paths + $paths))
    $result.Count | Should -Be 0
    Should -Invoke Invoke-ScriptAnalyzer -ModuleName QualityScans -Times 2 -Exactly
  }

  It 'reports a failed file and still analyzes the remaining files' {
    Mock Invoke-ScriptAnalyzer -ModuleName QualityScans {
      if ($Path.EndsWith('one.ps1')) { throw 'synthetic analyzer failure' }
    }
    $paths = @((Join-Path $repoRoot 'tests/one.ps1'), (Join-Path $repoRoot 'tests/two.ps1'))
    $result = @(Invoke-PowerShellAnalyzerScan -RootPath $repoRoot -Paths $paths)
    $result.Count | Should -Be 1
    $result[0].Kind | Should -Be 'analyzer_error'
    $result[0].Message | Should -Be 'synthetic analyzer failure'
    Should -Invoke Invoke-ScriptAnalyzer -ModuleName QualityScans -Times 2 -Exactly
  }
}
