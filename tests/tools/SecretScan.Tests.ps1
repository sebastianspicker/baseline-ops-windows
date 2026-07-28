#requires -version 5.1
<#
.SYNOPSIS
Pester coverage for repository tooling contracts.

.DESCRIPTION
Verifies tooling safeguards that protect maintainers and releases.
#>

[CmdletBinding()]
param()

Describe 'tools/secret-scan.ps1' {
  BeforeAll {
    $script:ToolPath = Join-Path $PSScriptRoot '../../tools/secret-scan.ps1'
  }

  It 'uses bounded, NUL-delimited Git file enumeration and rejects escaped paths' {
    $toolText = Get-Content -LiteralPath $script:ToolPath -Raw -Encoding UTF8

    $toolText | Should -Match 'Invoke-NativeCommand\s+-Command\s+''git'''
    $toolText | Should -Match "'ls-files', '-z'"
    $toolText | Should -Match 'TimeoutSeconds\s+30'
    $toolText | Should -Match 'OutputTruncated'
    $toolText | Should -Match 'ConvertTo-RootedGitFilePath'
    $toolText | Should -Match 'Where-Object\s+\{\s*\$_\s+-ne\s+''''\s*\}'
    $toolText | Should -Not -Match '&\s*git\b'
  }

  It 'scans non-git directory recursive fallback' {
    $scanRoot = Join-Path $TestDrive 'plain-folder'
    New-Item -Path $scanRoot -ItemType Directory -Force | Out-Null
    Set-Content -LiteralPath (Join-Path $scanRoot 'readme.md') -Value 'no secrets here' -Encoding UTF8

    & $script:ToolPath -RootPath $scanRoot

    $LASTEXITCODE | Should -Be 0
  }

  It 'matches exclusions by path segment only' {
    $scanRoot = Join-Path $TestDrive 'segment-excludes'
    $binRoot = Join-Path $scanRoot 'bin'
    New-Item -Path $binRoot -ItemType Directory -Force | Out-Null
    $key = 'to' + 'ken'
    Set-Content -LiteralPath (Join-Path $scanRoot 'cabinet.md') -Value ($key + ' = "' + '1234567890abcdef' + '"') -Encoding UTF8
    Set-Content -LiteralPath (Join-Path $binRoot 'ignored.md') -Value ($key + ' = "' + 'abcdef1234567890' + '"') -Encoding UTF8

    $output = & $script:ToolPath -RootPath $scanRoot -NoFail 6>&1 | Out-String

    $LASTEXITCODE | Should -Be 0
    $output | Should -Match 'cabinet\.md'
    $output | Should -Not -Match 'ignored\.md'
  }

  It 'scans shell, JavaScript module, and SVG source files' {
    $scanRoot = Join-Path $TestDrive 'additional-text-formats'
    New-Item -Path $scanRoot -ItemType Directory -Force | Out-Null
    $key = 'to' + 'ken'
    foreach ($name in @('build.sh', 'fuzz.mjs', 'diagram.svg')) {
      Set-Content -LiteralPath (Join-Path $scanRoot $name) `
        -Value ($key + ' = "1234567890abcdef"') -Encoding UTF8
    }

    $output = & $script:ToolPath -RootPath $scanRoot -NoFail 6>&1 | Out-String
    $compactOutput = $output -replace '\s', ''

    $LASTEXITCODE | Should -Be 0
    $compactOutput | Should -Match 'build\.sh'
    $compactOutput | Should -Match 'fuzz\.mjs'
    $compactOutput | Should -Match 'diagram\.svg'
  }

  It 'scans untracked non-ignored files in a git worktree' {
    if (-not (Get-Command -Name git -ErrorAction SilentlyContinue)) {
      Set-ItResult -Skipped -Because 'git is not available.'
      return
    }
    $scanRoot = Join-Path $TestDrive 'git-untracked'
    New-Item -Path $scanRoot -ItemType Directory -Force | Out-Null
    'tracked' | Set-Content -LiteralPath (Join-Path $scanRoot 'tracked.md') -Encoding UTF8
    & git -C $scanRoot init --quiet
    & git -C $scanRoot add tracked.md
    $key = 'to' + 'ken'
    Set-Content -LiteralPath (Join-Path $scanRoot 'untracked.md') -Value ($key + ' = "' + '1234567890abcdef' + '"') -Encoding UTF8

    $output = & $script:ToolPath -RootPath $scanRoot -NoFail 6>&1 | Out-String

    $LASTEXITCODE | Should -Be 0
    $output | Should -Match 'untracked\.md'
  }
}
