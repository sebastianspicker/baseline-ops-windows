#requires -Version 5.1

BeforeAll {
  Import-Module (Join-Path $PSScriptRoot '../../tools/Launcher.Core.psm1') -Force
}

Describe 'Launcher argument policy' {
  It 'Parses quotes, whitespace, and literal boolean colon syntax' {
    $tokens = @(ConvertFrom-LauncherArgumentString '-Name "Jane Doe" -Path ''C:\Program Files\Kit'' -Enabled:$false')
    $tokens | Should -HaveCount 5
    $tokens[1] | Should -Be 'Jane Doe'
    $tokens[3] | Should -Be 'C:\Program Files\Kit'
    $tokens[4] | Should -Be '-Enabled:$false'
  }

  It 'Rejects unmatched quotes and executable syntax' {
    { ConvertFrom-LauncherArgumentString '-Name "unfinished' } | Should -Throw '*unmatched quote*'
    { ConvertFrom-LauncherArgumentString '-Name ok; Get-Process' } | Should -Throw '*executable syntax*'
    { ConvertFrom-LauncherArgumentString '-Name $(Get-Process)' } | Should -Throw '*subexpression*'
    { ConvertFrom-LauncherArgumentString '-Name $env:TEMP' } | Should -Throw '*variable*'
  }

  It 'Rejects runner-owned arguments case-insensitively' {
    foreach ($tokens in @(
        @('-Mode', 'Remediate'), @('-confirm:$false'), @('--RootPath=elsewhere'),
        @('-OutputPath', 'capture.json'), @('-Strict'), @('-ExpectedHash', 'ABC')
      )) {
      { Assert-LauncherArgumentsAllowed -ArgumentTokens $tokens } | Should -Throw '*controlled by the launcher*'
    }
  }
}

Describe 'Launcher manifest and state policy' {
  It 'Requires explicit approval for remediation' {
    { ConvertTo-LauncherManifest -Operation run-script -Root $TestDrive -Target '27-Test.ps1' -Mode Remediate } | Should -Throw '*explicit operator approval*'
  }

  It 'Rejects unknown manifest fields' {
    $manifest = [pscustomobject](ConvertTo-LauncherManifest -Operation run-script -Root $TestDrive -Target '27-Test.ps1')
    $manifest | Add-Member -NotePropertyName command -NotePropertyValue 'arbitrary'
    { Assert-LauncherManifest -Manifest $manifest } | Should -Throw '*unknown field*'
  }

  It 'Rejects invalid roots and unsafe targets at the worker boundary' {
    $invalidRoot = [pscustomobject](ConvertTo-LauncherManifest -Operation run-script -Root $TestDrive -Target '27-Test.ps1')
    { Assert-LauncherManifest -Manifest $invalidRoot } | Should -Throw '*kit root is invalid*'

    $scripts = Join-Path $TestDrive 'valid-root/scripts'
    New-Item -Path $scripts -ItemType Directory -Force | Out-Null
    'param()' | Set-Content -LiteralPath (Join-Path $scripts '00-Run-Local.ps1') -Encoding UTF8
    'param()' | Set-Content -LiteralPath (Join-Path $scripts '00-Run-Profile.ps1') -Encoding UTF8
    $unsafe = [pscustomobject](ConvertTo-LauncherManifest -Operation run-script -Root (Split-Path -Parent $scripts) -Target '..\outside.ps1')
    { Assert-LauncherManifest -Manifest $unsafe } | Should -Throw '*script target is invalid*'
  }

  It 'Rejects advanced argument tokens for profile operations' {
    $scripts = Join-Path $TestDrive 'profile-root/scripts'
    New-Item -Path $scripts -ItemType Directory -Force | Out-Null
    'param()' | Set-Content -LiteralPath (Join-Path $scripts '00-Run-Local.ps1') -Encoding UTF8
    'param()' | Set-Content -LiteralPath (Join-Path $scripts '00-Run-Profile.ps1') -Encoding UTF8
    $profilePath = Join-Path $TestDrive 'profile.json'
    '{}' | Set-Content -LiteralPath $profilePath -Encoding UTF8
    $manifest = [pscustomobject](ConvertTo-LauncherManifest -Operation run-profile -Root (Split-Path -Parent $scripts) -Target $profilePath -ArgumentTokens @('-Name', 'value'))
    { Assert-LauncherManifest -Manifest $manifest } | Should -Throw '*only valid for a single-script run*'
  }

  It 'Maps every process outcome to one terminal state' {
    Get-LauncherTerminalState -ExitCode 0 | Should -Be 'Completed'
    Get-LauncherTerminalState -ExitCode 2 | Should -Be 'Warning'
    Get-LauncherTerminalState -ExitCode 1 | Should -Be 'Failed'
    Get-LauncherTerminalState -ExitCode 99 | Should -Be 'Failed'
    Get-LauncherTerminalState -ExitCode 0 -Stopped | Should -Be 'Stopped'
  }

  It 'Keeps a high-volume pending queue bounded' {
    $logPath = Join-Path $TestDrive 'high-volume.log'
    $collector = New-Object LauncherOutputCollector($logPath, 1, 5000)
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    try {
      1..50000 | ForEach-Object { $collector.AddLine("line-$_") }
      $collector.Pending.Count | Should -Be 5000
      $first = $null
      [void]$collector.Pending.TryPeek([ref]$first)
      $first | Should -Be 'line-45001'
      $stopwatch.Elapsed.TotalSeconds | Should -BeLessThan 10
      $drained = $null
      while ($collector.TryDequeue([ref]$drained)) { $drained = $null }
      $collector.AddLine('after-drain')
      [void]$collector.TryDequeue([ref]$drained)
      $drained | Should -Be 'after-drain'
    } finally {
      $collector.Dispose()
    }
  }

  It 'Collects asynchronous process output without a PowerShell runspace callback' {
    $logPath = Join-Path $TestDrive 'collector.log'
    $collector = New-Object LauncherOutputCollector($logPath, 1MB, 20)
    $startInfo = New-Object System.Diagnostics.ProcessStartInfo
    $startInfo.FileName = (Get-Process -Id $PID).Path
    $startInfo.Arguments = '-NoProfile -Command "Write-Output collector-ok"'
    $startInfo.UseShellExecute = $false
    $startInfo.RedirectStandardOutput = $true
    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $startInfo
    $process.add_OutputDataReceived($collector.OutputHandler)
    try {
      [void]$process.Start()
      $process.BeginOutputReadLine()
      $process.WaitForExit()
      $line = $null
      for ($attempt = 0; $attempt -lt 20 -and $null -eq $line; $attempt++) {
        [void]$collector.TryDequeue([ref]$line)
        if ($null -eq $line) { Start-Sleep -Milliseconds 25 }
      }
      $line | Should -Be 'collector-ok'
    } finally {
      $collector.Dispose()
      $process.Dispose()
    }
    Get-Content -LiteralPath $logPath -Raw | Should -Match 'collector-ok'
  }

  It 'caps the full log and leaves the pending queue bounded' {
    $logPath = Join-Path $TestDrive 'capped-collector.log'
    $collector = New-Object LauncherOutputCollector($logPath, 160, 5)
    try {
      1..20 | ForEach-Object { $collector.AddLine(('line-{0}-{1}' -f $_, ('x' * 24))) }
      $collector.Pending.Count | Should -Be 5
    } finally {
      $collector.Dispose()
    }
    $text = Get-Content -LiteralPath $logPath -Raw
    $text | Should -Match 'OUTPUT TRUNCATED'
    ([System.Text.Encoding]::UTF8.GetByteCount($text)) | Should -BeLessOrEqual 240
  }
}

Describe 'Launcher discovery' {
  It 'Excludes orchestration scripts and returns numbered operator scripts' {
    $scripts = Join-Path $TestDrive 'scripts'
    New-Item -Path $scripts -ItemType Directory -Force | Out-Null
    foreach ($name in @('00-Run-Local.ps1', '00-Run-Profile.ps1', '27-Defender-Audit.ps1')) {
      'param()' | Set-Content -LiteralPath (Join-Path $scripts $name) -Encoding UTF8
    }
    $items = @(Get-LauncherScriptCatalog -RootPath $TestDrive)
    $items | Should -HaveCount 1
    $items[0].Number | Should -Be '27'
    $items[0].Name | Should -Be '27-Defender-Audit.ps1'
  }

  It 'discovers the catalog asynchronously without using the PowerShell UI runspace' {
    $root = Join-Path $TestDrive 'async-catalog'
    $scripts = Join-Path $root 'scripts'
    New-Item -Path $scripts -ItemType Directory -Force | Out-Null
    'param()' | Set-Content -LiteralPath (Join-Path $scripts '00-Run-Local.ps1') -Encoding UTF8
    'param()' | Set-Content -LiteralPath (Join-Path $scripts '00-Run-Profile.ps1') -Encoding UTF8
    @'
<#
.SYNOPSIS
Audit Microsoft Defender health.
#>
[CmdletBinding()]
param([ValidateSet('Audit','Remediate')][string]$Mode = 'Audit')
if ($Mode -eq 'Remediate') { Write-Output 'remediation fixture' }
'@ | Set-Content -LiteralPath (Join-Path $scripts '27-Defender-Health.ps1') -Encoding UTF8
    "param([ValidateSet('Audit','Remediate')][string]`$Mode = 'Audit')" |
      Set-Content -LiteralPath (Join-Path $scripts '28-Audit-Only.ps1') -Encoding UTF8
    "param([string]`$Mode = 'Audit')`nif (`$Mode -eq 'Remediate') { Write-Warning 'Remediate mode is not supported by this script.' }" |
      Set-Content -LiteralPath (Join-Path $scripts '29-Remediation-Unsupported.ps1') -Encoding UTF8
    "param([string]`$Mode = 'Audit')`nswitch (`$Mode) { 'Remediate' { Write-Output 'apply fixture' } }" |
      Set-Content -LiteralPath (Join-Path $scripts '30-Switch-Remediation.ps1') -Encoding UTF8

    $task = [LauncherCatalogDiscovery]::BeginDiscover($root)
    $task.Wait(5000) | Should -BeTrue
    $items = @($task.Result)
    $items | Should -HaveCount 4
    $items[0].Synopsis | Should -Be 'Audit Microsoft Defender health.'
    $items[0].SupportedModes | Should -Be 'Audit, Remediate'
    $items[1].SupportedModes | Should -Be 'Audit'
    $items[2].SupportedModes | Should -Be 'Audit'
    $items[3].SupportedModes | Should -Be 'Audit, Remediate'
  }
}

Describe 'Launcher worker protocol' {
  It 'Captures output and preserves warning exit code' {
    $scripts = Join-Path $TestDrive 'worker-root/scripts'
    New-Item -Path $scripts -ItemType Directory -Force | Out-Null
    @'
param($ScriptName, $RootPath, [string[]]$ScriptArgs, $OutputFormat, $Confirm)
Write-Output 'success-stream'
Write-Information 'information-stream' -InformationAction Continue
Write-Warning 'warning-stream'
Write-Error 'error-stream' -ErrorAction Continue
exit 2
'@ | Set-Content -LiteralPath (Join-Path $scripts '00-Run-Local.ps1') -Encoding UTF8
    'param()' | Set-Content -LiteralPath (Join-Path $scripts '00-Run-Profile.ps1') -Encoding UTF8
    $manifest = ConvertTo-LauncherManifest -Operation run-script -Root (Split-Path -Parent $scripts) -Target '27-Test.ps1'
    $manifestPath = Join-Path $TestDrive 'manifest.json'
    $manifest | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $manifestPath -Encoding UTF8

    $output = & pwsh -NoProfile -File (Join-Path $PSScriptRoot '../../tools/Launcher-Worker.ps1') -ManifestPath $manifestPath 2>&1
    $exitCode = $LASTEXITCODE
    $text = $output | Out-String
    $exitCode | Should -Be 2
    $text | Should -Match 'success-stream'
    $text | Should -Match 'information-stream'
    $text | Should -Match 'warning-stream'
    $text | Should -Match 'error-stream'
  }

  It 'preserves success and failure exit codes' {
    foreach ($expectedExit in @(0, 1)) {
      $root = Join-Path $TestDrive "worker-exit-$expectedExit"
      $scripts = Join-Path $root 'scripts'
      New-Item -Path $scripts -ItemType Directory -Force | Out-Null
      "param(`$ScriptName, `$RootPath, [string[]]`$ScriptArgs, `$OutputFormat, `$Confirm)`nWrite-Output 'exit-$expectedExit'`nexit $expectedExit" |
        Set-Content -LiteralPath (Join-Path $scripts '00-Run-Local.ps1') -Encoding UTF8
      'param()' | Set-Content -LiteralPath (Join-Path $scripts '00-Run-Profile.ps1') -Encoding UTF8
      $manifest = ConvertTo-LauncherManifest -Operation run-script -Root $root -Target '27-Test.ps1'
      $manifestPath = Join-Path $root 'manifest.json'
      $manifest | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $manifestPath -Encoding UTF8

      $output = & pwsh -NoProfile -File (Join-Path $PSScriptRoot '../../tools/Launcher-Worker.ps1') -ManifestPath $manifestPath 2>&1
      $LASTEXITCODE | Should -Be $expectedExit
      ($output | Out-String) | Should -Match "exit-$expectedExit"
    }
  }

  It 'can terminate a long-running worker and map the request to Stopped' {
    $root = Join-Path $TestDrive 'worker-stop'
    $scripts = Join-Path $root 'scripts'
    New-Item -Path $scripts -ItemType Directory -Force | Out-Null
    @'
param($ScriptName, $RootPath, [string[]]$ScriptArgs, $OutputFormat, $Confirm)
Start-Sleep -Seconds 30
exit 0
'@ | Set-Content -LiteralPath (Join-Path $scripts '00-Run-Local.ps1') -Encoding UTF8
    'param()' | Set-Content -LiteralPath (Join-Path $scripts '00-Run-Profile.ps1') -Encoding UTF8
    $manifest = ConvertTo-LauncherManifest -Operation run-script -Root $root -Target '27-Test.ps1'
    $manifestPath = Join-Path $root 'manifest.json'
    $manifest | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $manifestPath -Encoding UTF8

    $startInfo = New-Object System.Diagnostics.ProcessStartInfo
    $startInfo.FileName = (Get-Process -Id $PID).Path
    $workerPath = Join-Path $PSScriptRoot '../../tools/Launcher-Worker.ps1'
    $startInfo.Arguments = '-NoLogo -NoProfile -NonInteractive -File "{0}"' -f $workerPath.Replace('"', '""')
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.EnvironmentVariables['WIN_MDM_LAUNCHER_MANIFEST'] = $manifestPath
    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $startInfo
    try {
      [void]$process.Start()
      Start-Sleep -Milliseconds 350
      $process.HasExited | Should -BeFalse
      $process.Kill()
      $process.WaitForExit()
      Get-LauncherTerminalState -ExitCode $process.ExitCode -Stopped | Should -Be 'Stopped'
    } finally {
      if (-not $process.HasExited) { $process.Kill() }
      $process.Dispose()
    }
  }
}
