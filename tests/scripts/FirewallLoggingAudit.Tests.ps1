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

Describe '32-Firewall-Logging-Audit FailOnHigh V2 reporting' -Tag 'FirewallLoggingAudit' -Skip:$script:SkipNonSystemWindowsIntegration {
  BeforeAll {
    $script:FirewallLoggingAuditScript = Join-Path $PSScriptRoot '../../scripts/32-Firewall-Logging-Audit.ps1'
    Import-Module (Join-Path $PSScriptRoot '../../lib/Common.psm1') -Force
    function global:Get-NetFirewallProfile { }
    function global:Set-NetFirewallProfile { }
  }

  AfterAll {
    Remove-Item -LiteralPath Function:\Get-NetFirewallProfile -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath Function:\Set-NetFirewallProfile -ErrorAction SilentlyContinue
  }

  It 'reports high findings as V2 FAIL instead of throwing before V2 output' {
    $oldOS = $env:OS
    try {
      $env:OS = 'Windows_NT'
      Mock -CommandName Test-IsAdmin -MockWith { $true }
      Mock -CommandName Get-NetFirewallProfile -MockWith {
        [pscustomobject]@{
          Name = 'Domain'
          Enabled = $false
          LogFileName = 'C:\\Windows\\System32\\LogFiles\\Firewall\\pfirewall.log'
          LogMaxSizeKilobytes = 20480
          LogAllowed = $false
          LogBlocked = $true
        }
      }
      Mock -CommandName Set-NetFirewallProfile -MockWith { }

      $settingsPath = Join-Path $TestDrive 'firewall-settings.json'
      Set-Content -LiteralPath $settingsPath -Value '{"EnableDropped":true,"EnableAllowed":false,"LogFileName":"C:\\Windows\\System32\\LogFiles\\Firewall\\pfirewall.log","LogMaxSizeKB":20480}' -Encoding UTF8
      $output = & $script:FirewallLoggingAuditScript -SettingsJsonPath $settingsPath -FailOnHigh -NoConsoleSummary -OutputFormat None -PassThru 2>&1 3>&1 6>&1
      $result = @($output | Where-Object { $_ -and $_.PSObject.Properties.Name -contains 'Result' })[-1]

      $LASTEXITCODE | Should -Be 1
      $result.Result | Should -Be 'FAIL'
      @($result.Findings | Where-Object Code -eq 'FW-ProfileDisabled').Count | Should -Be 1
      @($result.Findings | Where-Object Code -eq 'FW-FailOnHigh').Count | Should -Be 1
      @($result.Findings | Where-Object Code -eq 'FW-FailOnHigh')[0].Message | Should -Match '1 High severity finding'
    } finally {
      if ($null -eq $oldOS) { Remove-Item -LiteralPath Env:OS -ErrorAction SilentlyContinue }
      else { $env:OS = $oldOS }
    }
  }
}
