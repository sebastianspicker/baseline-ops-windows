#requires -Version 5.1

<#
.SYNOPSIS
Pester coverage for repository tooling contracts.

.DESCRIPTION
Verifies tooling safeguards that protect maintainers and releases.
#>

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

  It 'attaches every worker to a kill-on-close Job Object before releasing its start gate' {
    $script:Source | Should -Match 'New-LauncherProcessJob'
    $script:Source | Should -Match 'Add-LauncherProcessToJob'
    $script:Source | Should -Match 'BASELINEOPS_LAUNCHER_START_GATE'
    $script:Source | Should -Match 'EventWaitHandle'
    $script:Source | Should -Match 'startGate\.Set\(\)'
  }

  It 'passes the manifest as bounded inherited data instead of a mutable temp file' {
    $script:Source | Should -Match 'BASELINEOPS_LAUNCHER_MANIFEST_B64'
    $script:Source | Should -Match 'manifestBytes\.Length -gt 16384'
    $script:Source | Should -Not -Match 'Manifest \| ConvertTo-Json[^\r\n]+Set-Content'
  }

  It 'routes stop and close requests through process-tree termination' {
    $script:Source | Should -Match 'Request-LauncherProcessStop'
    $script:Source | Should -Match 'Stop-LauncherProcessTree'
    $script:Source | Should -Not -Match '\$script:CurrentProcess\.Kill\('
  }

  It 'treats validation as stoppable and maps a stopped validation to Stopped' {
    $script:Source | Should -Match '\$btnStop\.Enabled = \$State -in @\(''Validating'', ''Running''\)'
    $validationStart = $script:Source.IndexOf("if (`$purpose -eq 'validation')")
    $stopIndex = $script:Source.IndexOf('if ($script:StopRequested)', $validationStart)
    $successIndex = $script:Source.IndexOf('elseif ($exitCode -in @(0, 2))', $validationStart)
    $stoppedStateIndex = $script:Source.IndexOf('Write-LauncherState -State Stopped', $validationStart)
    $validationStart | Should -BeGreaterOrEqual 0
    $stopIndex | Should -BeGreaterThan $validationStart
    $successIndex | Should -BeGreaterThan $stopIndex
    $stoppedStateIndex | Should -BeGreaterThan $stopIndex
    $stoppedStateIndex | Should -BeLessThan $successIndex
  }

  It 'uses fixed-size stream drains instead of line-based asynchronous readers' {
    $script:Source | Should -Match 'DrainOutputAsync'
    $script:Source | Should -Match 'DrainErrorAsync'
    $script:Source | Should -Not -Match 'BeginOutputReadLine'
    $script:Source | Should -Not -Match 'BeginErrorReadLine'
  }

  It 'waits for Job Object assignment before importing repository code in the worker' {
    $workerSource = Get-Content -LiteralPath (Join-Path $PSScriptRoot '../../tools/Launcher-Worker.ps1') -Raw
    $workerSource.IndexOf('WaitOne(15000)') | Should -BeLessThan $workerSource.IndexOf("Import-Module (Join-Path `$PSScriptRoot 'Launcher.Core.psm1')")
    $workerSource.IndexOf('FileShare]::Read') | Should -BeLessThan $workerSource.IndexOf("Import-Module (Join-Path `$PSScriptRoot 'Launcher.Core.psm1')")
  }

  It 'locks the worker, library, and runner closure before releasing the worker start gate' {
    $script:Source | Should -Match 'Enter-LauncherTrustedClosure'
    $script:Source.IndexOf('Enter-LauncherTrustedClosure') | Should -BeLessThan $script:Source.IndexOf('startGate.Set()')
    $workerSource = Get-Content -LiteralPath (Join-Path $PSScriptRoot '../../tools/Launcher-Worker.ps1') -Raw
    $workerSource | Should -Match 'Enter-LauncherTrustedClosure'
    $workerSource | Should -Match 'Launcher.Core\.psm1'
    $workerSource | Should -Match '\.\./lib/Validation\.psm1'
  }

  It 'passes operation-specific targets through elevated ACL closure validation' {
    $coreSource = Get-Content -LiteralPath (Join-Path $PSScriptRoot '../../tools/Launcher.Core.psm1') -Raw
    $script:Source | Should -Match 'SelectedExecutionPath \$selectedExecutionPath'
    $workerSource = Get-Content -LiteralPath (Join-Path $PSScriptRoot '../../tools/Launcher-Worker.ps1') -Raw
    $workerSource | Should -Match 'SelectedExecutionPath \$selectedExecutionPath'
    $workerSource.IndexOf('Enter-LauncherTrustedClosure') | Should -BeLessThan $workerSource.IndexOf('& $entryPoint')
    $coreSource | Should -Match 'Join-Path \$scriptsPath ''00-Validate-Profile\.ps1'''
    $coreSource | Should -Match 'Join-Path \$scriptsPath ''_lib/Bootstrap\.ps1'''
    $coreSource | Should -Match 'Join-Path \$libPath ''Validation\.psm1'''
  }

  It 'defaults signature enforcement on only for elevated GUI sessions' {
    $script:Source | Should -Match '\$chkRequireSigned\.Checked = \$script:IsElevated'
    $script:Source | Should -Not -Match '\$chkRequireSigned\.Checked = \$true'
  }

  It 'requires a Windows host for form-level assertions' -Skip:($env:OS -ne 'Windows_NT') {
    $env:OS | Should -Be 'Windows_NT'
  }
}
