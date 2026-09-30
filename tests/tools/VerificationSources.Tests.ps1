<#
.SYNOPSIS
  Verifies maintained-source discovery around local and generated folders.
.DESCRIPTION
  Keeps local npm dependencies, caches, and build output out of PowerShell analysis and rejects them if published.
#>

BeforeAll {
  $source = Join-Path $PSScriptRoot '../../tools/verify.ps1'
  $ast = [System.Management.Automation.Language.Parser]::ParseFile($source, [ref]$null, [ref]$null)
  foreach ($name in @(
      'Get-VerificationPowerShellTargets', 'Test-VerificationExcludedPath', 'Get-PublicSurfacePaths',
      'Get-FileSystemPublicSurfacePaths', 'Test-BlockedPublicSurfaceDirectory'
    )) {
    $definition = $ast.Find({
      param($node)
      $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name
    }, $true)
    . ([scriptblock]::Create($definition.Extent.Text))
  }
  # Exercise the file-system inventory used for extracted packages.
  function Get-GitPublicSurfacePaths { param([string]$Path) $null = $Path; return $null }
}

Describe 'Maintained PowerShell source boundary' {
  It 'discovers every maintained script and module without naming source directories' {
    $root = Join-Path $TestDrive 'package'
    foreach ($relative in @(
        'dev/demo/helpers/check.ps1', 'tools/Core.psm1', 'rust/oracles/Oracle.ps1',
        'dev/demo/node_modules/package/install.ps1', '.cache/quality/tool.ps1',
        'dist/staged/script.ps1', 'rust/target/debug/build.ps1', 'README.md'
      )) {
      $file = Join-Path $root $relative
      New-Item -ItemType Directory -Path (Split-Path -Parent $file) -Force | Out-Null
      Set-Content -LiteralPath $file -Value '# fixture'
    }
    $targets = @(Get-VerificationPowerShellTargets -Path $root)
    $targets.Count | Should -Be 3
    $targets.Name | Should -Contain 'check.ps1'
    $targets.Name | Should -Contain 'Core.psm1'
    $targets.Name | Should -Contain 'Oracle.ps1'
  }

  It 'rejects dependency folders if they enter the public working set' {
    Test-BlockedPublicSurfaceDirectory -Segments @('dev', 'demo', 'node_modules', 'package', 'install.ps1') |
      Should -Not -BeNullOrEmpty
  }
}
