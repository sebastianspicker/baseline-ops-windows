#requires -version 5.1
<#
.SYNOPSIS
Pester coverage for security-script contracts.

.DESCRIPTION
Verifies safe, repeatable operator behavior and evidence.
#>

Describe 'WinGet bounded native command handling' {
  BeforeAll {
    $scriptPath = Join-Path $PSScriptRoot '../../scripts/08-WinGet-SelfHeal.ps1'
    $tokens = $null
    $parseErrors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$tokens, [ref]$parseErrors)
    $parseErrors | Should -BeNullOrEmpty

    Import-Module (Join-Path $PSScriptRoot '../../lib/External.psm1') -Force -DisableNameChecking
    Import-Module (Join-Path $PSScriptRoot '../../lib/Validation.psm1') -Force
    foreach ($functionName in @('Invoke-Winget', 'ConvertTo-ConservativeNativeArguments', 'Install-VcRedist')) {
      $definition = @($ast.Find({
          param($node)
          $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $functionName
      }, $true))[0]
      $definition | Should -Not -BeNullOrEmpty
      $functionScript = [scriptblock]::Create($definition.Extent.Text)
      . $functionScript
    }
  }

  It 'captures bounded high-volume stdout and stderr before the process exits' {
    $command = '[Console]::Out.Write(("o" * 262144 -join "")); [Console]::Error.Write(("e" * 262144 -join "")); exit 23'
    $wingetPath = @((Get-Command pwsh -CommandType Application))[0].Source
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $result = Invoke-Winget -WingetPath $wingetPath `
      -WingetArgs @('-NoProfile', '-Command', $command) -TimeoutSec 10
    $stopwatch.Stop()

    $result.ExitCode | Should -Be 23
    $result.StdOut.Length | Should -Be 262144
    $result.StdErr.Length | Should -Be 262144
    $result.StdOut | Should -Match '^o+$'
    $result.StdErr | Should -Match '^e+$'
    $stopwatch.Elapsed.TotalSeconds | Should -BeLessThan 10
    $result.Success | Should -BeFalse
  }

  It 'terminates a timed-out process and returns without waiting for its natural exit' {
    $command = 'Start-Sleep -Seconds 30'
    $wingetPath = @((Get-Command pwsh -CommandType Application))[0].Source
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $result = Invoke-Winget -WingetPath $wingetPath `
      -WingetArgs @('-NoProfile', '-Command', $command) -TimeoutSec 1
    $stopwatch.Stop()

    $result.ExitCode | Should -Be 408
    $result.TimedOut | Should -BeTrue
    $result.StdErr | Should -Match 'Timeout after 1 s'
    # Windows PowerShell can use the full job shutdown and stream-drain bounds.
    # Keep this below the command's 30-second natural exit without assuming the
    # faster cleanup timing normally observed under PowerShell 7.
    $stopwatch.Elapsed.TotalSeconds | Should -BeLessThan 20
  }

  It 'marks capped output as unusable rather than successful' {
    $command = '[Console]::Out.Write(("o" * 1200000 -join "")); exit 0'
    $wingetPath = @((Get-Command pwsh -CommandType Application))[0].Source

    $result = Invoke-Winget -WingetPath $wingetPath -WingetArgs @('-NoProfile', '-Command', $command) -TimeoutSec 10

    $result.ExitCode | Should -Be 413
    $result.OutputTruncated | Should -BeTrue
    $result.Success | Should -BeFalse
    $result.StdErr | Should -Match 'truncated'
  }

  It 'does not retain direct or unbounded process APIs' {
    $source = Get-Content -LiteralPath $scriptPath -Raw
    $source | Should -Not -Match 'System\.Diagnostics\.Process(StartInfo)?'
    $source | Should -Not -Match 'ReadToEndAsync|Start-Process|WaitForExit'
    $source | Should -Match 'Invoke-NativeCommand'
  }

  It 'passes conservatively parsed installer arguments to the bounded helper' -Skip:($env:OS -eq 'Windows_NT') {
    $installer = Join-Path $TestDrive 'vc_redist.x64.exe'
    Set-Content -LiteralPath $installer -Value 'test installer' -Encoding UTF8
    Mock -CommandName Invoke-NativeCommand -MockWith {
      param([string]$Command, [string[]]$Arguments)
      $script:InstallerCommand = $Command
      $script:InstallerArguments = $Arguments
      [pscustomobject]@{ ExitCode = 0; Success = $true; TimedOut = $false; OutputTruncated = $false; StderrTruncated = $false; Stdout = ''; Stderr = '' }
    }

    $ok, $detail = Install-VcRedist -Path $installer -InstallArgs '/install /quiet /log "C:\ProgramData\VC log.txt"' -Confirm:$false

    $ok | Should -BeTrue
    $detail | Should -Be 'OK'
    $script:InstallerCommand | Should -Be $installer
    $script:InstallerArguments | Should -Be @('/install', '/quiet', '/log', 'C:\ProgramData\VC log.txt')
    Assert-MockCalled -CommandName Invoke-NativeCommand -Times 1 -Exactly
  }

  It 'holds the validated installer against replacement through process launch' {
    $source = Get-Content -LiteralPath $scriptPath -Raw
    $source | Should -Match '\[System\.IO\.FileShare\]::Read'
    $source | Should -Match 'Get-AuthenticodeSignature -LiteralPath \$resolvedPath'
    $source | Should -Match 'O=Microsoft Corporation'
    $source | Should -Match 'VersionInfo\.OriginalFilename'
  }

  It 'rejects an installer path containing a reparse point' {
    $target = Join-Path $TestDrive 'vc_redist.x64.exe'
    $link = Join-Path $TestDrive 'linked-vc_redist.x64.exe'
    Set-Content -LiteralPath $target -Value 'test installer' -Encoding UTF8
    try {
      New-Item -ItemType SymbolicLink -Path $link -Target $target -ErrorAction Stop | Out-Null
    } catch {
      Set-ItResult -Skipped -Because "Symbolic links are unavailable: $($_.Exception.Message)"
      return
    }
    Mock -CommandName Invoke-NativeCommand -MockWith { throw 'must not launch' }

    $ok, $detail = Install-VcRedist -Path $link -Confirm:$false

    $ok | Should -BeFalse
    $detail | Should -Match 'reparse point'
    Assert-MockCalled -CommandName Invoke-NativeCommand -Times 0 -Exactly
  }

  It 'rejects an unsigned installer before launch on Windows' -Skip:($env:OS -ne 'Windows_NT') {
    $installer = Join-Path $TestDrive 'vc_redist.x64.exe'
    Set-Content -LiteralPath $installer -Value 'unsigned test installer' -Encoding UTF8
    Mock -CommandName Invoke-NativeCommand -MockWith { throw 'must not launch' }

    $ok, $detail = Install-VcRedist -Path $installer -Confirm:$false

    $ok | Should -BeFalse
    $detail | Should -Match 'valid Microsoft Authenticode signature'
    Assert-MockCalled -CommandName Invoke-NativeCommand -Times 0 -Exactly
  }

  It 'rejects ambiguous installer argument quoting before launch' {
    { ConvertTo-ConservativeNativeArguments -ArgumentString '/quiet "unterminated' } | Should -Throw '*unclosed quote*'
  }
}

Describe '08-WinGet-SelfHeal strict unsupported-host result' {
  It 'turns unsupported-host WARN into FAIL under Strict' {
    $oldOs = $env:OS
    $scriptPath = Join-Path $PSScriptRoot '../../scripts/08-WinGet-SelfHeal.ps1'
    try {
      $env:OS = 'NotWindows'
      $result = & $scriptPath -Strict -OutputFormat None -PassThru -NoConsole -Quiet -NoColor

      $LASTEXITCODE | Should -Be 1
      $result.Result | Should -Be 'FAIL'
      $result.Metadata.UnsupportedHost | Should -BeTrue
    } finally {
      if ($null -eq $oldOs) { Remove-Item -LiteralPath Env:OS -ErrorAction SilentlyContinue } else { $env:OS = $oldOs }
    }
  }
}
