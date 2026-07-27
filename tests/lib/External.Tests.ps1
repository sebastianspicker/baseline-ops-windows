#requires -version 5.1
<#
.SYNOPSIS
Pester tests for External.psm1 module

.DESCRIPTION
Unit tests for external command wrappers including injection guards,
command existence checks, and native command invocation.
#>

[CmdletBinding()]
param()

$script:IsWindowsHost = (
  [System.Environment]::OSVersion.Platform -eq [System.PlatformID]::Win32NT
)
$script:SkipWindowsTests = (-not $script:IsWindowsHost)

BeforeAll {
  $script:ExternalModulePath = Join-Path $PSScriptRoot '../../lib/External.psm1'
  Import-Module $script:ExternalModulePath -Force
  $script:NativeTestHostPath = (Get-Process -Id $PID -ErrorAction Stop).Path
}

Describe 'Test-CommandExists' {
  It 'Returns true for a command that exists' {
    Test-CommandExists -Name $script:NativeTestHostPath | Should -Be $true
  }

  It 'Returns false for a non-existent command' {
    Test-CommandExists -Name 'nonexistent-command-xyz-12345' | Should -Be $false
  }
}

Describe 'Ensure-Cmdlet' {
  It 'Returns true for an existing cmdlet' {
    $result = Ensure-Cmdlet -Name 'Get-ChildItem'
    $result | Should -Be $true
  }

  It 'Throws for a non-existent cmdlet' {
    { Ensure-Cmdlet -Name 'Invoke-NonExistentCmdlet12345' } | Should -Throw '*not found*'
  }

  It 'Throws with custom message' {
    { Ensure-Cmdlet -Name 'Fake-Cmdlet' -Message 'Custom error' } | Should -Throw 'Custom error'
  }
}

Describe 'Ensure-Exe' {
  It 'Returns true for an existing executable' {
    $result = Ensure-Exe -Name $script:NativeTestHostPath
    $result | Should -Be $true
  }

  It 'Throws for a non-existent executable' {
    { Ensure-Exe -Name 'nonexistent-exe-xyz-12345' } | Should -Throw '*not found*'
  }

  It 'Throws with custom message' {
    { Ensure-Exe -Name 'fake-exe-999' -Message 'Missing tool' } | Should -Throw 'Missing tool'
  }
}

Describe 'Invoke-NativeCommand' {
  It 'resolves executable identity to one absolute path before launch' {
    $resolved = Resolve-NativeExecutablePath -Name $script:NativeTestHostPath

    [System.IO.Path]::IsPathRooted($resolved) | Should -BeTrue
    Test-Path -LiteralPath $resolved -PathType Leaf | Should -BeTrue
    $source = Get-Content -LiteralPath (Join-Path $PSScriptRoot '../../lib/External.psm1') -Raw
    $source | Should -Match 'Command\s+= \$ResolvedCommand'
    $source | Should -Match 'Arguments\s+= @\(\$Arguments'
    $source | Should -Match '\$startInfo\.FileName = \[string\]\$manifest\.Command'
    $source | Should -Match '\[System\.IO\.FileShare\]::Read'
  }

  It 'Treats command text containing spaces as one executable path without invoking a shell' {
    $result = Invoke-NativeCommand -Command 'cmd /c dir' -Arguments @('test') -WarningAction SilentlyContinue
    $result | Should -BeNullOrEmpty
  }

  It 'Rejects empty command name' {
    { Invoke-NativeCommand -Command '  ' -Arguments @('test') } | Should -Throw '*non-empty executable*'
  }

  It 'Rejects control characters in a command path' {
    { Invoke-NativeCommand -Command "$script:NativeTestHostPath`n--version" -Arguments @('--version') } |
      Should -Throw '*control characters*'
  }

  It 'Returns null for non-existent command without ThrowOnError' {
    $result = Invoke-NativeCommand -Command 'nonexistent-cmd-xyz-999' -Arguments @('test') 3>$null
    $result | Should -BeNullOrEmpty
  }

  It 'Throws for non-existent command with ThrowOnError' {
    { Invoke-NativeCommand -Command 'nonexistent-cmd-xyz-999' -Arguments @('test') -ThrowOnError } | Should -Throw '*not found*'
  }

  It 'Executes a valid command with CaptureOutput' {
    $result = Invoke-NativeCommand -Command $script:NativeTestHostPath -Arguments @('-NoProfile', '-Command', 'Write-Output hello') -CaptureOutput
    $result | Should -Not -BeNullOrEmpty
    $result.ExitCode | Should -Be 0
    $result.Success | Should -Be $true
    # Output should contain 'hello'
    ($result.Output -join "`n") | Should -Match 'hello'
  }

  It 'preserves empty, quoted, Unicode, spaced, and trailing-slash arguments exactly' {
    $echoScriptPath = Join-Path $TestDrive 'echo-native-arguments.ps1'
    $echoScript = @'
[CmdletBinding()]
param(
  [Parameter(ValueFromRemainingArguments = $true)]
  [AllowEmptyCollection()]
  [AllowEmptyString()]
  [string[]]$Values
)

$json = ConvertTo-Json -InputObject @($Values) -Compress
[Console]::Out.Write([Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($json)))
'@
    [IO.File]::WriteAllText($echoScriptPath, $echoScript, [Text.UTF8Encoding]::new($false))
    $expected = @('', 'value with spaces', 'a"b', 'Grüße 世界', 'ends-with-\')

    $result = Invoke-NativeCommand `
      -Command $script:NativeTestHostPath `
      -Arguments (@('-NoProfile', '-File', $echoScriptPath) + $expected) `
      -CaptureOutput `
      -Quiet

    $result.Success | Should -BeTrue
    $json = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($result.Stdout))
    # Windows PowerShell 5.1 preserves a JSON array as one pipeline object.
    # Assign first so array enumeration is consistent across PowerShell hosts.
    $parsed = $json | ConvertFrom-Json
    $actual = @($parsed)
    $actual.Count | Should -Be $expected.Count
    for ($index = 0; $index -lt $expected.Count; $index++) {
      $actual[$index] | Should -BeExactly $expected[$index]
    }
  }

  It 'does not pass the worker manifest environment variable to the native child' {
    $environmentScriptPath = Join-Path $TestDrive 'read-native-environment.ps1'
    $environmentScript = @'
$value = [Environment]::GetEnvironmentVariable('BASELINEOPS_NATIVE_MANIFEST_B64', 'Process')
$state = if ([string]::IsNullOrEmpty($value)) { 'CLEARED' } else { 'LEAKED' }
[Console]::Out.Write($state)
'@
    [IO.File]::WriteAllText($environmentScriptPath, $environmentScript, [Text.UTF8Encoding]::new($false))
    $previousValue = [Environment]::GetEnvironmentVariable('BASELINEOPS_NATIVE_MANIFEST_B64', 'Process')
    try {
      [Environment]::SetEnvironmentVariable('BASELINEOPS_NATIVE_MANIFEST_B64', 'parent-sentinel', 'Process')

      $result = Invoke-NativeCommand `
        -Command $script:NativeTestHostPath `
        -Arguments @('-NoProfile', '-File', $environmentScriptPath) `
        -CaptureOutput `
        -Quiet

      $result.Success | Should -BeTrue
      $result.Stdout | Should -BeExactly 'CLEARED'
      [Environment]::GetEnvironmentVariable('BASELINEOPS_NATIVE_MANIFEST_B64', 'Process') |
        Should -BeExactly 'parent-sentinel'
    } finally {
      [Environment]::SetEnvironmentVariable('BASELINEOPS_NATIVE_MANIFEST_B64', $previousValue, 'Process')
    }
  }

  It 'Captures non-zero exit code' {
    $result = Invoke-NativeCommand -Command $script:NativeTestHostPath -Arguments @('-NoProfile', '-Command', 'exit 1') -CaptureOutput -Quiet
    $result.ExitCode | Should -Be 1
    $result.Success | Should -Be $false
  }

  It 'Captures stderr separately on non-zero exit with CaptureOutput' {
    $result = Invoke-NativeCommand -Command $script:NativeTestHostPath `
      -Arguments @('-NoProfile', '-Command', '[Console]::Error.WriteLine("native stderr marker"); exit 7') `
      -CaptureOutput -Quiet

    $result.ExitCode | Should -Be 7
    $result.Success | Should -Be $false
    $result.Stderr | Should -Match 'native stderr marker'
  }

  It 'preserves stdout and stderr as separate legacy Output lines' {
    $result = Invoke-NativeCommand -Command $script:NativeTestHostPath `
      -Arguments @(
        '-NoProfile',
        '-Command',
        '[Console]::Out.Write("OUT"); [Console]::Error.Write("ERR")'
      ) `
      -CaptureOutput `
      -Quiet

    @($result.Output) | Should -Be @('OUT', 'ERR')
    [string]$result.Output | Should -Not -BeExactly 'OUTERR'
  }

  It 'preserves literal CLIXML-looking native output' {
    $literal = "#< CLIXML`r`n<Objs>literal child text</Objs>"
    $result = Invoke-NativeCommand -Command $script:NativeTestHostPath `
      -Arguments @(
        '-NoProfile',
        '-Command',
        '[Console]::Error.Write("#< CLIXML`r`n<Objs>literal child text</Objs>")'
      ) `
      -CaptureOutput `
      -Quiet

    $result.Success | Should -BeTrue
    $result.Stdout | Should -BeNullOrEmpty
    $result.Stderr | Should -BeExactly $literal
  }

  It 'Includes stderr in warning when non-capture command fails' {
    $warnings = @()
    $result = Invoke-NativeCommand -Command $script:NativeTestHostPath `
      -Arguments @('-NoProfile', '-Command', '[Console]::Error.WriteLine("warning stderr marker"); exit 9') `
      -WarningVariable warnings

    $result | Should -Be $false
    ((@($warnings) | ForEach-Object { [string]$_ }) -join "`n") |
      Should -Match 'warning stderr marker'
  }

  It 'Returns false for a quiet non-capture command failure' {
    $result = Invoke-NativeCommand -Command $script:NativeTestHostPath `
      -Arguments @('-NoProfile', '-Command', 'exit 11') `
      -Quiet -WarningVariable warnings

    $result | Should -Be $false
    @($warnings).Count | Should -Be 0
  }

  It 'Throws for a quiet non-capture command failure with ThrowOnError' {
    {
      Invoke-NativeCommand -Command $script:NativeTestHostPath `
        -Arguments @('-NoProfile', '-Command', 'exit 12') `
        -Quiet -ThrowOnError
    } | Should -Throw '*exited with code 12*'
  }

  It 'reports a finite timeout through capture metadata' {
    $result = Invoke-NativeCommand -Command $script:NativeTestHostPath -Arguments @('-NoProfile', '-Command', 'Start-Sleep -Seconds 3') -CaptureOutput -TimeoutSeconds 1 -Quiet
    $result.Success | Should -BeFalse
    $result.TimedOut | Should -BeTrue
    $result.ExitCode | Should -Be -1
  }

  It 'terminates POSIX descendants that retain redirected output after their parent exits' -Skip:$script:IsWindowsHost {
    $pidPath = Join-Path $TestDrive 'native-descendant.pid'
    $shellPidPath = $pidPath -replace "'", "'\\''"
    $childPid = $null
    try {
      $result = Invoke-NativeCommand -Command '/bin/sh' -Arguments @(
        '-c',
        "sleep 30 & child=`$!; printf '%s' `$child > '$shellPidPath'"
      ) -CaptureOutput -TimeoutSeconds 1 -Quiet

      $result.Success | Should -BeFalse
      $result.TimedOut | Should -BeTrue
      $result.ExitCode | Should -Be -1
      $childPid = [int](Get-Content -LiteralPath $pidPath -Raw)

      $deadline = [DateTime]::UtcNow.AddSeconds(3)
      do {
        $descendant = Get-Process -Id $childPid -ErrorAction SilentlyContinue
        if ($null -eq $descendant) { break }
        Start-Sleep -Milliseconds 100
      } while ([DateTime]::UtcNow -lt $deadline)
      $descendant | Should -BeNullOrEmpty
    } finally {
      if ($null -ne $childPid) { Stop-Process -Id $childPid -Force -ErrorAction SilentlyContinue }
    }
  }

  It 'bounds stdout and stderr independently while draining both streams' {
    $result = Invoke-NativeCommand -Command $script:NativeTestHostPath -Arguments @('-NoProfile', '-Command', '$x="x" * 5000; [Console]::Out.Write($x); [Console]::Error.Write($x)') -CaptureOutput -MaxOutputBytes 1024 -Quiet
    $result.Success | Should -BeTrue
    $result.OutputTruncated | Should -BeTrue
    $result.StderrTruncated | Should -BeTrue
    [System.Text.Encoding]::UTF8.GetByteCount($result.Stdout) | Should -BeLessOrEqual 1024
    [System.Text.Encoding]::UTF8.GetByteCount($result.Stderr) | Should -BeLessOrEqual 1024
    (
      [System.Text.Encoding]::UTF8.GetByteCount($result.Stdout) +
      [System.Text.Encoding]::UTF8.GetByteCount($result.Stderr)
    ) | Should -BeLessOrEqual 2048
  }

  It 'does not split a UTF-16 surrogate pair at the UTF-8 output limit' {
    $result = Invoke-NativeCommand -Command $script:NativeTestHostPath `
      -Arguments @(
        '-NoProfile',
        '-Command',
        '[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false); $text = ("x" * 1021) + [char]::ConvertFromUtf32(0x1F600); [Console]::Out.Write($text)'
      ) `
      -CaptureOutput `
      -MaxOutputBytes 1024 `
      -Quiet

    $result.Success | Should -BeTrue
    $result.OutputTruncated | Should -BeTrue
    [System.Text.Encoding]::UTF8.GetByteCount($result.Stdout) | Should -BeLessOrEqual 1024
    [char]::IsHighSurrogate($result.Stdout[$result.Stdout.Length - 1]) | Should -BeFalse
    [char]::IsLowSurrogate($result.Stdout[$result.Stdout.Length - 1]) | Should -BeFalse
  }

  It 'quotes empty, embedded-quote, and trailing-slash arguments for the Windows PowerShell fallback' {
    InModuleScope External {
      (ConvertTo-WindowsCommandLineArgument -Argument '') | Should -Be '""'
      (ConvertTo-WindowsCommandLineArgument -Argument 'a b') | Should -Be '"a b"'
      (ConvertTo-WindowsCommandLineArgument -Argument 'a"b') | Should -Be '"a\"b"'
      (ConvertTo-WindowsCommandLineArgument -Argument 'a b\') | Should -Be '"a b\\"'
    }
  }
}

Describe 'external tool wrapper structure' {
  It 'Keeps common wrappers as thin Invoke-ExternalTool delegates' {
    $moduleText = Get-Content -LiteralPath $script:ExternalModulePath -Raw -Encoding UTF8

    foreach ($name in @('Invoke-Schtasks','Invoke-Auditpol','Invoke-Wevtutil','Invoke-Wecutil','Invoke-RegExe')) {
      $pattern = '(?s)function\s+{0}\b.*?Invoke-ExternalTool' -f [regex]::Escape($name)
      $moduleText | Should -Match $pattern
    }
  }

  It 'pins Windows system tools and WinGet instead of trusting PATH or mutable Windows environment variables' {
    $moduleText = Get-Content -LiteralPath $script:ExternalModulePath -Raw -Encoding UTF8

    $moduleText | Should -Match 'SpecialFolder\]::System'
    $moduleText | Should -Match 'SpecialFolder\]::ProgramFiles'
    $moduleText | Should -Match 'Get-AuthenticodeSignature -LiteralPath \$resolvedCommand'
    $moduleText | Should -Match 'O=Microsoft Corporation'
    $moduleText | Should -Not -Match 'Join-Path \$env:(?:SystemRoot|WINDIR|windir)'
  }

  It 'invokes WinRM through a locked System32 VBS file and cscript rather than winrm.cmd' {
    $moduleText = Get-Content -LiteralPath $script:ExternalModulePath -Raw -Encoding UTF8

    Get-Command Invoke-WinrmCommand -Module External | Should -Not -BeNullOrEmpty
    $moduleText | Should -Match "Resolve-TrustedWindowsSystemFile -LeafName 'winrm\.vbs'"
    $moduleText | Should -Match "Invoke-NativeCommand -Command 'cscript\.exe'"
    $moduleText | Should -Match '\$scriptLock = \[IO\.File\]::Open'
    $moduleText | Should -Not -Match "-Command 'winrm\.cmd'"
  }

  It 'gates Windows child launch until a kill-on-close job owns the worker process' {
    $moduleText = Get-Content -LiteralPath $script:ExternalModulePath -Raw -Encoding UTF8

    $moduleText | Should -Match 'JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE'
    $startIndex = $moduleText.IndexOf('if (-not $process.Start())')
    $assignIndex = $moduleText.IndexOf('$launchContext.NativeJob.Assign($process)')
    $releaseIndex = $moduleText.IndexOf('[void]$launchContext.StartGate.Set()')
    $waitIndex = $moduleText.IndexOf('$gate.WaitOne(30000)')
    $childIndex = $moduleText.IndexOf('$child = [Diagnostics.Process]::Start($startInfo)')
    $startIndex | Should -BeGreaterOrEqual 0
    $assignIndex | Should -BeGreaterThan $startIndex
    $releaseIndex | Should -BeGreaterThan $assignIndex
    $waitIndex | Should -BeGreaterOrEqual 0
    $childIndex | Should -BeGreaterThan $waitIndex
    $moduleText | Should -Match '\$timedOut = \$executionTimedOut -or -not \$drained'
  }

  It 'uses an argument vector and clears the manifest before launching the native child' {
    $moduleText = Get-Content -LiteralPath $script:ExternalModulePath -Raw -Encoding UTF8

    $moduleText | Should -Match '\$StartInfo\.ArgumentList\.Add'
    $moduleText | Should -Match '\$StartInfo\.Arguments ='
    $moduleText | Should -Not -Match 'CommandLine\s+= \$CommandLine'

    $decodeIndex = $moduleText.IndexOf('$json = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($encoded))')
    $clearIndex = $moduleText.IndexOf("[Environment]::SetEnvironmentVariable('BASELINEOPS_NATIVE_MANIFEST_B64', `$null")
    $manifestIndex = $moduleText.IndexOf('$manifest = $json | ConvertFrom-Json')
    $removeIndex = $moduleText.IndexOf("[void]`$startInfo.EnvironmentVariables.Remove('BASELINEOPS_NATIVE_MANIFEST_B64')")
    $childIndex = $moduleText.IndexOf('$child = [Diagnostics.Process]::Start($startInfo)')

    $decodeIndex | Should -BeGreaterOrEqual 0
    $clearIndex | Should -BeGreaterThan $decodeIndex
    $manifestIndex | Should -BeGreaterThan $clearIndex
    $removeIndex | Should -BeGreaterThan $manifestIndex
    $childIndex | Should -BeGreaterThan $removeIndex
  }
}

Describe 'Invoke-Wevtutil' -Skip:$script:SkipWindowsTests {
  It 'Passes arguments to wevtutil.exe' {
    # This would need wevtutil.exe which is Windows-only
    $result = Invoke-Wevtutil -Arguments @('gl', 'Application') -CaptureOutput
    $result | Should -Not -BeNullOrEmpty
  }
}

Describe 'Export-EventLog' {
  It 'Passes XPath query without embedded quote wrapping' {
    InModuleScope External {
      Mock Invoke-Wevtutil {
        param([string[]]$Arguments, [switch]$ThrowOnError)
        $null = $ThrowOnError
        $script:CapturedWevtutilArgs = $Arguments
        return $true
      }

      Export-EventLog -LogName 'Application' -OutputPath 'out.evtx' -Query "*[System[(Level=2)]]" | Should -Be $true

      $script:CapturedWevtutilArgs | Should -Be @('epl', 'Application', 'out.evtx', '/ow:true', '/q:*[System[(Level=2)]]')
      $script:CapturedWevtutilArgs[-1] | Should -Not -Match '^/q:"'
      $script:CapturedWevtutilArgs[-1] | Should -Not -Match '"$'
    }
  }
}

Describe 'Export-RegistryKey' {
  It 'Allows double dots inside output file name segment' {
    InModuleScope External {
      Mock Invoke-RegExe {
        param([string[]]$Arguments, [switch]$ThrowOnError)
        $null = $ThrowOnError
        $script:CapturedRegArgs = $Arguments
        return $true
      }

      Export-RegistryKey -KeyPath 'HKCU\Software\Test' -OutputPath 'out..backup.reg' | Should -Be $true

      $script:CapturedRegArgs | Should -Be @('export', 'HKCU\Software\Test', 'out..backup.reg', '/y')
    }
  }
}

Describe 'Invoke-Git' {
  It 'Executes git with CaptureOutput' {
    if (-not (Test-CommandExists -Name 'git')) {
      Set-ItResult -Skipped -Because 'A Git executable in an approved native location is unavailable.'
      return
    }
    $result = Invoke-Git -Arguments @('--version') -CaptureOutput
    $result | Should -Not -BeNullOrEmpty
    $result.Success | Should -Be $true
    ($result.Output -join "`n") | Should -Match 'git version'
  }

  It 'Handles WorkingDirectory parameter' {
    if (-not (Test-CommandExists -Name 'git')) {
      Set-ItResult -Skipped -Because 'A Git executable in an approved native location is unavailable.'
      return
    }
    $tempRoot = if ([string]::IsNullOrWhiteSpace($env:TEMP)) { [System.IO.Path]::GetTempPath() } else { $env:TEMP }
    $result = Invoke-Git -Arguments @('--version') -WorkingDirectory $tempRoot -CaptureOutput
    $result | Should -Not -BeNullOrEmpty
    $result.Success | Should -Be $true
  }
}

Describe 'New-MdmScheduledTask' -Skip:$script:SkipWindowsTests {
  It 'Rejects TaskName with invalid characters' {
    { New-MdmScheduledTask -TaskName 'bad;task' -TaskRun 'cmd.exe' } | Should -Throw '*invalid characters*'
  }

  It 'Rejects TaskName with special characters' {
    { New-MdmScheduledTask -TaskName 'task$(evil)' -TaskRun 'cmd.exe' } | Should -Throw '*invalid characters*'
  }
}
