<#
.SYNOPSIS
  Verifies development-only tooling is not shipped.
.DESCRIPTION
  Locks the release archive recipe to shipped directories and the extracted-package inventory check.
#>

BeforeAll {
  $repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
  $script:ReleaseWorkflow = Get-Content -LiteralPath (Join-Path $repoRoot '.github/workflows/release.yml') -Raw
}

Describe 'Release archive developer-tool isolation' {
  It 'archives only the shipped top-level paths' {
    $recipe = 'README.md CHANGELOG.md CONTRIBUTING.md LICENSE SECURITY.md PSScriptAnalyzerSettings.psd1 \\\s+docs examples lib scripts tools\s*\r?\n'
    $script:ReleaseWorkflow | Should -Match $recipe
  }

  It 'needs no pathspec exclusions because development tooling lives outside shipped directories' {
    $script:ReleaseWorkflow | Should -Not -Match ([regex]::Escape(':(exclude)'))
  }

  It 'rejects development tooling and the Rust workspace in the extracted package' {
    $script:ReleaseWorkflow | Should -Match '(?m)^\s+dev rust \\$'
  }
}
