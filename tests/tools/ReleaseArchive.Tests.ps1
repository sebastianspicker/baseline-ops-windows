<#
.SYNOPSIS
  Verifies developer-only quality tooling is not shipped.
.DESCRIPTION
  Locks the release workflow exclusion and extracted-package inventory check.
#>

BeforeAll {
  $repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
  $script:ReleaseWorkflow = Get-Content -LiteralPath (Join-Path $repoRoot '.github/workflows/release.yml') -Raw
}

Describe 'Release archive developer-tool isolation' {
  It 'excludes tools/quality from git archive' {
    $script:ReleaseWorkflow | Should -Match ([regex]::Escape("':(exclude)tools/quality'"))
  }

  It 'rejects tools/quality in the extracted package' {
    $script:ReleaseWorkflow | Should -Match 'scripts/ci-local\.sh tools/quality; do'
  }
}

Describe 'Browser developer-tool isolation' {
  It 'excludes browser tooling from git archive' -ForEach @('tools/demo', 'tools/demo-profiles.mjs') {
    $script:ReleaseWorkflow | Should -Match ([regex]::Escape("':(exclude)$_'"))
  }

  It 'rejects browser tooling in the extracted package' {
    $script:ReleaseWorkflow | Should -Match 'tools/demo tools/demo-profiles\.mjs'
  }
}
