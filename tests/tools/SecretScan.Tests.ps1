#requires -version 5.1

[CmdletBinding()]
param()

Describe 'tools/secret-scan.ps1' {
  BeforeAll {
    $script:ToolPath = Join-Path $PSScriptRoot '../../tools/secret-scan.ps1'
  }

  It 'scans a non-git directory using the recursive fallback' {
    $scanRoot = Join-Path $TestDrive 'plain-folder'
    New-Item -Path $scanRoot -ItemType Directory -Force | Out-Null
    Set-Content -LiteralPath (Join-Path $scanRoot 'readme.md') -Value 'no secrets here' -Encoding UTF8

    & $script:ToolPath -RootPath $scanRoot

    $LASTEXITCODE | Should -Be 0
  }
}
