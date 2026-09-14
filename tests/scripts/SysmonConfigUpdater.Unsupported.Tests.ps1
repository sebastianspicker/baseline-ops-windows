#requires -version 5.1
<#
.SYNOPSIS
Pester coverage for security-script contracts.

.DESCRIPTION
Verifies safe, repeatable operator behavior and evidence.
#>

$script:SkipNonSystemWindowsIntegration = $false
if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) {
  try {
    $script:SkipNonSystemWindowsIntegration =
      [Security.Principal.WindowsIdentity]::GetCurrent().User.Value -ne 'S-1-5-18'
  } catch {
    $script:SkipNonSystemWindowsIntegration = $true
  }
}

Describe '16-Sysmon-Config-Updater strict unsupported-host result' -Tag 'Sysmon' {
  BeforeAll {
function Test-SysmonTurnsTheUnsupportedHostWarningIntoFAILUnderStrict {
    $oldOs = $env:OS
    try {
      $env:OS = 'NotWindows'
      $scriptPath = Join-Path $PSScriptRoot '../../scripts/16-Sysmon-Config-Updater.ps1'
      $result = & $scriptPath -Mode Audit -Strict -OutputFormat None -PassThru -NoConsoleSummary -Quiet -NoColor

      $LASTEXITCODE | Should -Be 1
      $result.Result | Should -Be 'FAIL'
      $result.Metadata.UnsupportedHost | Should -BeTrue
    } finally {
      if ($null -eq $oldOs) { Remove-Item -LiteralPath Env:OS -ErrorAction SilentlyContinue } else { $env:OS = $oldOs }
    }
  }
  }

  It 'turns the unsupported-host warning into FAIL under Strict' { Test-SysmonTurnsTheUnsupportedHostWarningIntoFAILUnderStrict }
}
