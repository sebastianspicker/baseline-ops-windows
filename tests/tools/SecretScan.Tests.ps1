#requires -version 5.1
<#
.SYNOPSIS
Direct hostile-input secret scan check.
.DESCRIPTION
Verifies untracked shell-metacharacter filenames remain scanned without leaking values.
#>
Describe 'tools/secret-scan.ps1 hostile untracked input' -Tag 'Security' {
  It 'discovers an untracked hostile filename without revealing its secret value' {
    if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
      Set-ItResult -Skipped -Because 'git is not available.'
      return
    }
    $root = Join-Path $TestDrive 'hostile-untracked'
    New-Item -ItemType Directory -Path $root -Force | Out-Null
    & git -C $root init --quiet
    'tracked' | Set-Content -LiteralPath (Join-Path $root 'tracked.md') -Encoding UTF8
    & git -C $root add tracked.md
    $secretValue = 'ghp_' + ('a' * 36)
    $hostileName = 'untracked; $() [hostile].md'
    $secretValue | Set-Content -LiteralPath (Join-Path $root $hostileName) -Encoding UTF8

    $output = & (Join-Path $PSScriptRoot '../../tools/secret-scan.ps1') -RootPath $root -NoFail 6>&1 | Out-String
    $LASTEXITCODE | Should -Be 0
    $output | Should -Match ([regex]::Escape($hostileName))
    $output | Should -Not -Match ([regex]::Escape($secretValue))
  }
}
