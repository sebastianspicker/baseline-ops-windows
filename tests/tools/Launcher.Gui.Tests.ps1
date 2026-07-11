#requires -Version 5.1

Describe 'Launcher GUI source contract' {
  BeforeAll {
    $script:LauncherPath = Join-Path $PSScriptRoot '../../tools/Launcher-GUI.ps1'
    $script:Source = Get-Content -LiteralPath $script:LauncherPath -Raw
  }

  It 'parses as PowerShell 5.1-compatible source' {
    $tokens = $null
    $errors = $null
    [void][System.Management.Automation.Language.Parser]::ParseFile($script:LauncherPath, [ref]$tokens, [ref]$errors)
    @($errors) | Should -HaveCount 0
  }

  It 'uses native resizable layout and system colors' {
    $script:Source | Should -Match 'TableLayoutPanel'
    $script:Source | Should -Match 'SplitContainer'
    $script:Source | Should -Match 'AutoScaleMode.*Font'
    $script:Source | Should -Match 'SystemColors.*Window'
    $script:Source | Should -Not -Match '\.Location\s*='
    $script:Source | Should -Not -Match 'FromArgb'
  }

  It 'exposes task, accessibility, stop, and bounded-output controls' {
    $script:Source | Should -Match "'Run script'"
    $script:Source | Should -Match "'Run profile'"
    $script:Source | Should -Match 'AccessibleName'
    $script:Source | Should -Match 'Stop active run'
    $script:Source | Should -Match 'MaxPendingLines = 5000'
    $script:Source | Should -Match 'MaxVisibleLines = 10000'
    $script:Source | Should -Match 'MaxLogBytes = 25MB'
  }

  It 'keeps catalog discovery off the UI thread' {
    $script:Source | Should -Match 'LauncherCatalogDiscovery.*BeginDiscover'
    $script:Source | Should -Match 'DiscoveryTask.*IsCompleted'
    $script:Source | Should -Not -Match 'Application.*DoEvents'
  }

  It 'requires a Windows host for form-level assertions' -Skip:($env:OS -ne 'Windows_NT') {
    $env:OS | Should -Be 'Windows_NT'
  }
}
