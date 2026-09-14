<#
.SYNOPSIS
  Verifies maintained-source discovery around browser dependencies.
.DESCRIPTION
  Keeps local npm dependencies out of PowerShell analysis and rejects them if published.
#>

BeforeAll {
  $source = Join-Path $PSScriptRoot '../../tools/verify.ps1'
  $ast = [System.Management.Automation.Language.Parser]::ParseFile($source, [ref]$null, [ref]$null)
  foreach ($name in @('Get-VerificationPowerShellTargets', 'Test-BlockedPublicSurfaceDirectory')) {
    $definition = $ast.Find({
      param($node)
      $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name
    }, $true)
    . ([scriptblock]::Create($definition.Extent.Text))
  }
}

Describe 'Browser dependency source boundary' {
  It 'scans maintained scripts and modules but not installed npm dependencies' {
    $root = Join-Path $TestDrive 'tools'
    foreach ($relative in @('demo/helpers/check.ps1', 'demo/helpers/Core.psm1', 'demo/node_modules/package/install.ps1')) {
      $file = Join-Path $root $relative
      New-Item -ItemType Directory -Path (Split-Path -Parent $file) -Force | Out-Null
      Set-Content -LiteralPath $file -Value '# fixture'
    }
    $targets = @(Get-VerificationPowerShellTargets -Path $root)
    $targets.Count | Should -Be 2
    $targets.Name | Should -Contain 'check.ps1'
    $targets.Name | Should -Contain 'Core.psm1'
  }

  It 'rejects dependency folders if they enter the public working set' {
    Test-BlockedPublicSurfaceDirectory -Segments @('tools', 'demo', 'node_modules', 'package', 'install.ps1') |
      Should -Not -BeNullOrEmpty
  }
}
