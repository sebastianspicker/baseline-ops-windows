#requires -version 5.1

Describe 'scripts/ci-local.sh gate reporting' {
  BeforeAll {
    $script:RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
    $script:CiLocal = Join-Path $script:RepoRoot 'scripts/ci-local.sh'
  }

  It 'Reports skipped analyzer and tests as partial local CI' {
    if (-not (Get-Command -Name bash -ErrorAction SilentlyContinue)) {
      Set-ItResult -Skipped -Because 'bash is not available.'
      return
    }
    $pwsh = Get-Command -Name pwsh -ErrorAction SilentlyContinue
    if (-not $pwsh) {
      Set-ItResult -Skipped -Because 'pwsh is not available.'
      return
    }

    $previous = @{
      CI_SKIP_ANALYZER = $env:CI_SKIP_ANALYZER
      CI_SKIP_TESTS = $env:CI_SKIP_TESTS
      PWSH_BIN = $env:PWSH_BIN
    }

    try {
      $env:CI_SKIP_ANALYZER = '1'
      $env:CI_SKIP_TESTS = '1'
      $env:PWSH_BIN = $pwsh.Source

      $output = & bash $script:CiLocal 2>&1
      $exitCode = $LASTEXITCODE
    } finally {
      foreach ($name in $previous.Keys) {
        if ($null -eq $previous[$name]) {
          Remove-Item -LiteralPath "Env:$name" -ErrorAction SilentlyContinue
        } else {
          Set-Item -LiteralPath "Env:$name" -Value $previous[$name]
        }
      }
    }

    $text = $output | Out-String
    $exitCode | Should -Be 0
    $text | Should -Match 'CI gate summary'
    $text | Should -Match 'Analyzer.*SKIPPED'
    $text | Should -Match 'Tests.*SKIPPED'
    $text | Should -Match 'Overall.*PARTIAL'
  }
}
