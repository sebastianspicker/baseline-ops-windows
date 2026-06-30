#requires -version 5.1

[CmdletBinding()]
param()

Describe 'tools/secret-scan.ps1' {
  BeforeAll {
    $script:ToolPath = Join-Path $PSScriptRoot '../../tools/secret-scan.ps1'
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
}
