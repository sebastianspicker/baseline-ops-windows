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

$script:SkipWindowsTests = (-not $IsWindows)

BeforeAll {
  $script:ExternalModulePath = Join-Path $PSScriptRoot '../../lib/External.psm1'
  Import-Module $script:ExternalModulePath -Force
}

Describe 'Test-CommandExists' {
  It 'Returns true for a command that exists' {
    # pwsh exists on all platforms where this test runs
    Test-CommandExists -Name 'pwsh' | Should -Be $true
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
    # 'pwsh' should exist as an Application
    $result = Ensure-Exe -Name 'pwsh'
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
  It 'Rejects command with spaces (injection guard)' {
    { Invoke-NativeCommand -Command 'cmd /c dir' -Arguments @('test') } | Should -Throw '*single executable*'
  }

  It 'Rejects empty command name' {
    { Invoke-NativeCommand -Command '  ' -Arguments @('test') } | Should -Throw '*single executable*'
  }

  It 'Returns null for non-existent command without ThrowOnError' {
    $result = Invoke-NativeCommand -Command 'nonexistent-cmd-xyz-999' -Arguments @('test') 3>$null
    $result | Should -BeNullOrEmpty
  }

  It 'Throws for non-existent command with ThrowOnError' {
    { Invoke-NativeCommand -Command 'nonexistent-cmd-xyz-999' -Arguments @('test') -ThrowOnError } | Should -Throw '*not found*'
  }

  It 'Executes a valid command with CaptureOutput' {
    $result = Invoke-NativeCommand -Command 'pwsh' -Arguments @('-NoProfile', '-Command', 'Write-Output hello') -CaptureOutput
    $result | Should -Not -BeNullOrEmpty
    $result.ExitCode | Should -Be 0
    $result.Success | Should -Be $true
    # Output should contain 'hello'
    ($result.Output -join "`n") | Should -Match 'hello'
  }

  It 'Captures non-zero exit code' {
    $result = Invoke-NativeCommand -Command 'pwsh' -Arguments @('-NoProfile', '-Command', 'exit 1') -CaptureOutput -Quiet
    $result.ExitCode | Should -Be 1
    $result.Success | Should -Be $false
  }

  It 'Captures stderr separately on non-zero exit with CaptureOutput' {
    $result = Invoke-NativeCommand -Command 'pwsh' `
      -Arguments @('-NoProfile', '-Command', '[Console]::Error.WriteLine("native stderr marker"); exit 7') `
      -CaptureOutput -Quiet

    $result.ExitCode | Should -Be 7
    $result.Success | Should -Be $false
    $result.Stderr | Should -Match 'native stderr marker'
  }

  It 'Includes stderr in warning when non-capture command fails' {
    $warnings = @()
    $result = Invoke-NativeCommand -Command 'pwsh' `
      -Arguments @('-NoProfile', '-Command', '[Console]::Error.WriteLine("warning stderr marker"); exit 9') `
      -WarningVariable warnings

    $result | Should -Be $false
    ($warnings | Out-String) | Should -Match 'warning stderr marker'
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
    $result = Invoke-Git -Arguments @('--version') -CaptureOutput
    $result | Should -Not -BeNullOrEmpty
    $result.Success | Should -Be $true
    ($result.Output -join "`n") | Should -Match 'git version'
  }

  It 'Handles WorkingDirectory parameter' {
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
