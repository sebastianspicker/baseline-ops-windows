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

Describe '21-EmergencyKillSwitch break-glass cleanup failure reporting' -Tag 'EmergencyKillSwitch' -Skip:$script:SkipNonSystemWindowsIntegration {
  BeforeAll {
function Test-KillSwitchFailsPreflightBeforeMutationWhenExistingRuleInventoryCannotBeRead {
    $run = Invoke-EmergencyKillSwitchCleanupFailureCase

    $run.ExitCode | Should -Be 1
    $run.Result.Result | Should -Be 'FAIL'
    $run.Result.Summary.Actions.RegistryWritten | Should -BeFalse
    $run.Result.Summary.Actions.FirewallProfileSet | Should -BeFalse
    $run.Result.Summary.Actions.BreakGlassRemoved | Should -BeFalse
    @($run.Result.Summary.Errors | Where-Object { $_ -match 'Unable to inspect existing kill-switch rule and rollback-task identities' }).Count | Should -BeGreaterThan 0
    Should -Invoke Set-ItemProperty -Times 0
    Should -Invoke Remove-NetFirewallRule -Times 0
  }

function Test-KillSwitchReportsFirewallRuleCreationVerificationFailureAsAFailedRun {
    $run = Invoke-EmergencyKillSwitchRuleVerifyFailureCase

    $run.ExitCode | Should -Be 1
    $run.Result.Result | Should -Be 'FAIL'
    $run.Result.Summary.Actions.RulesCreated | Should -BeFalse
    @($run.Result.Summary.Errors | Where-Object { $_ -match "Firewall rule 'KILLSWITCH-[a-f0-9]{32}-IN-BLOCK' was not found" }).Count | Should -BeGreaterThan 0
    @($run.Result.Findings | Where-Object Code -eq 'Firewall-RuleCreateFailed').Count | Should -BeGreaterThan 0
  }

function Test-KillSwitchReportsWhatIfWithNoCompletedProtectiveActionsAsWARNWithAFinding {
    $run = Invoke-EmergencyKillSwitchWhatIfCase

    $run.Result.Result | Should -Be 'WARN'
    $run.Result.Summary.Actions.ConfirmDeclined | Should -BeTrue
    $run.Result.Summary.Actions.FirewallProfileSet | Should -BeFalse
    $run.Result.Summary.Actions.RulesCreated | Should -BeFalse
    @($run.Result.Findings | Where-Object Code -eq 'KS-ActionsDeclinedOrDryRun').Count | Should -Be 1
  }

function Test-KillSwitchMapsAWhatIfWarningToV2FAILInStrictMode {
    $run = Invoke-EmergencyKillSwitchWhatIfCase -Strict

    $run.ExitCode | Should -Be 1
    $run.Result.Result | Should -Be 'FAIL'
    @($run.Result.Findings | Where-Object Code -eq 'KS-ActionsDeclinedOrDryRun').Count | Should -Be 1
  }


    $script:KillSwitchScript = Join-Path $PSScriptRoot '../../scripts/21-EmergencyKillSwitch.ps1'
    Import-Module (Join-Path $PSScriptRoot '../../lib/Common.psm1') -Force
    Import-Module (Join-Path $PSScriptRoot '../../lib/EventLog.psm1') -Force

    function global:Get-NetFirewallProfile { }
    function global:Set-NetFirewallProfile { }
    function global:Get-NetFirewallRule { }
    function global:New-NetFirewallRule { }
    function global:Remove-NetFirewallRule { }
    function global:Get-ScheduledTask { }
    function global:Disable-NetAdapter { }
    function global:Enter-KillSwitchRemediationLock { }

    function Initialize-KillSwitchAllowingProfileMock {
        Mock -CommandName Get-NetFirewallProfile -MockWith {
          [pscustomobject]@{
            Name                  = 'Domain'
            Enabled               = 'True'
            DefaultInboundAction  = 'Allow'
            DefaultOutboundAction = 'Allow'
          }
        }
    }

    function Restore-KillSwitchTestEnvironment {
      param($OldOS, $OldTemp)
        if ($null -eq $oldOS) {
          Remove-Item -LiteralPath Env:OS -ErrorAction SilentlyContinue
        } else {
          $env:OS = $oldOS
        }
        if ($null -eq $oldTemp) {
          Remove-Item -LiteralPath Env:TEMP -ErrorAction SilentlyContinue
        } else {
          $env:TEMP = $oldTemp
        }
    }

    function Invoke-EmergencyKillSwitchCleanupFailureCase {
      $oldOS = $env:OS
      $oldTemp = $env:TEMP
      try {
        $env:OS = 'Windows_NT'
        $env:TEMP = $TestDrive

        Mock -CommandName Test-IsAdmin -MockWith { $true }
        Mock -CommandName Enter-KillSwitchRemediationLock -MockWith {
          [System.IO.File]::Open(
            (Join-Path $TestDrive ("remediation-{0}.lock" -f [guid]::NewGuid().ToString('N'))),
            [System.IO.FileMode]::OpenOrCreate,
            [System.IO.FileAccess]::ReadWrite,
            [System.IO.FileShare]::None)
        }
        Mock -CommandName Ensure-EventSource -MockWith { $true }
        Mock -CommandName Write-HealthEvent -MockWith { $true }
        Mock -CommandName New-Item -MockWith { [pscustomobject]@{} }
        Mock -CommandName Set-ItemProperty -MockWith { }
        Initialize-KillSwitchAllowingProfileMock
        Mock -CommandName Set-NetFirewallProfile -MockWith { }
        Mock -CommandName New-NetFirewallRule -MockWith { }
        Mock -CommandName Get-NetFirewallRule -MockWith {
          param([string]$Name)
          if ($Name -like '*BREAKGLASS*') {
            [pscustomobject]@{ Name = $Name }
          } else {
            throw 'rule not present'
          }
        }
        Mock -CommandName Remove-NetFirewallRule -MockWith { throw 'break-glass removal failed' }
        Mock -CommandName Get-ScheduledTask -MockWith { @() }

        $output = & $script:KillSwitchScript -Mode Remediate -OutputFormat None -PassThru -Confirm:$false 2>&1 3>&1 6>&1
        $exitCode = $LASTEXITCODE
      } finally {
        Restore-KillSwitchTestEnvironment -OldOS $oldOS -OldTemp $oldTemp
      }

      $result = @($output | Where-Object {
          $null -ne $_ -and
          $_.PSObject.Properties.Name -contains 'Result' -and
          $_.PSObject.Properties.Name -contains 'Summary'
        })[-1]

      return [pscustomobject]@{
        ExitCode = $exitCode
        Result   = $result
        Text     = ($output | Out-String)
      }
    }

    function Invoke-EmergencyKillSwitchRuleVerifyFailureCase {
      $oldOS = $env:OS
      $oldTemp = $env:TEMP
      try {
        $env:OS = 'Windows_NT'
        $env:TEMP = $TestDrive

        Mock -CommandName Test-IsAdmin -MockWith { $true }
        Mock -CommandName Enter-KillSwitchRemediationLock -MockWith {
          [System.IO.File]::Open(
            (Join-Path $TestDrive ("remediation-{0}.lock" -f [guid]::NewGuid().ToString('N'))),
            [System.IO.FileMode]::OpenOrCreate,
            [System.IO.FileAccess]::ReadWrite,
            [System.IO.FileShare]::None)
        }
        Mock -CommandName Ensure-EventSource -MockWith { $true }
        Mock -CommandName Write-HealthEvent -MockWith { $true }
        Mock -CommandName New-Item -MockWith { [pscustomobject]@{} }
        Mock -CommandName Set-ItemProperty -MockWith { }
        Mock -CommandName Get-NetFirewallProfile -MockWith {
          [pscustomobject]@{
            Name                  = 'Domain'
            Enabled               = 'True'
            DefaultInboundAction  = 'Allow'
            DefaultOutboundAction = 'Allow'
          }
        }
        Mock -CommandName Set-NetFirewallProfile -MockWith { }
        Mock -CommandName New-NetFirewallRule -MockWith { }
        Mock -CommandName Get-NetFirewallRule -MockWith { $null }
        Mock -CommandName Remove-NetFirewallRule -MockWith { }
        Mock -CommandName Get-ScheduledTask -MockWith { @() }

        $output = & $script:KillSwitchScript -Mode Remediate -OutputFormat None -PassThru -Confirm:$false 2>&1 3>&1 6>&1
        $exitCode = $LASTEXITCODE
      } finally {
        Restore-KillSwitchTestEnvironment -OldOS $oldOS -OldTemp $oldTemp
      }

      $result = @($output | Where-Object {
          $null -ne $_ -and
          $_.PSObject.Properties.Name -contains 'Result' -and
          $_.PSObject.Properties.Name -contains 'Summary'
        })[-1]

      return [pscustomobject]@{
        ExitCode = $exitCode
        Result   = $result
        Text     = ($output | Out-String)
      }
    }

    function Invoke-EmergencyKillSwitchWhatIfCase {
      param([switch]$Strict)
      $oldOS = $env:OS
      $oldTemp = $env:TEMP
      try {
        $env:OS = 'Windows_NT'
        $env:TEMP = $TestDrive

        Mock -CommandName Test-IsAdmin -MockWith { $true }
        Mock -CommandName Enter-KillSwitchRemediationLock -MockWith {
          [System.IO.File]::Open(
            (Join-Path $TestDrive ("remediation-{0}.lock" -f [guid]::NewGuid().ToString('N'))),
            [System.IO.FileMode]::OpenOrCreate,
            [System.IO.FileAccess]::ReadWrite,
            [System.IO.FileShare]::None)
        }
        Mock -CommandName Ensure-EventSource -MockWith { $true }
        Mock -CommandName Write-HealthEvent -MockWith { $true }
        Mock -CommandName Get-NetFirewallProfile -MockWith {
          [pscustomobject]@{
            Name                  = 'Domain'
            Enabled               = 'True'
            DefaultInboundAction  = 'Allow'
            DefaultOutboundAction = 'Allow'
          }
        }
        Mock -CommandName New-Item -MockWith { throw 'registry mutation should not run under WhatIf' }
        Mock -CommandName Set-ItemProperty -MockWith { throw 'registry mutation should not run under WhatIf' }
        Mock -CommandName Set-Content -MockWith { throw 'firewall state file should not be written under WhatIf' }
        Mock -CommandName Set-NetFirewallProfile -MockWith { throw 'firewall mutation should not run under WhatIf' }
        Mock -CommandName New-NetFirewallRule -MockWith { throw 'firewall mutation should not run under WhatIf' }
        Mock -CommandName Remove-NetFirewallRule -MockWith { throw 'firewall mutation should not run under WhatIf' }
        Mock -CommandName Disable-NetAdapter -MockWith { throw 'adapter mutation should not run under WhatIf' }
        Mock -CommandName Get-ScheduledTask -MockWith { @() }

        $output = & $script:KillSwitchScript -Mode Remediate -OutputFormat None -PassThru -Confirm:$false -WhatIf -Strict:$Strict 2>&1 3>&1 6>&1
        $exitCode = $LASTEXITCODE
      } finally {
        Restore-KillSwitchTestEnvironment -OldOS $oldOS -OldTemp $oldTemp
      }

      $result = @($output | Where-Object {
          $null -ne $_ -and
          $_.PSObject.Properties.Name -contains 'Result' -and
          $_.PSObject.Properties.Name -contains 'Summary'
        })[-1]

      return [pscustomobject]@{
        ExitCode = $exitCode
        Result   = $result
        Text     = ($output | Out-String)
      }
    }

  }



  AfterAll {
    foreach ($name in @(
        'Get-NetFirewallProfile',
        'Set-NetFirewallProfile',
        'Get-NetFirewallRule',
        'New-NetFirewallRule',
        'Remove-NetFirewallRule',
        'Get-ScheduledTask',
        'Disable-NetAdapter',
        'Enter-KillSwitchRemediationLock'
      )) {
      Remove-Item -LiteralPath "Function:\$name" -ErrorAction SilentlyContinue
    }
  }

  It 'fails preflight before mutation when existing rule inventory cannot be read' { Test-KillSwitchFailsPreflightBeforeMutationWhenExistingRuleInventoryCannotBeRead }

  It 'Reports firewall rule creation verification failure as a failed run' { Test-KillSwitchReportsFirewallRuleCreationVerificationFailureAsAFailedRun }

  It 'Reports WhatIf with no completed protective actions as WARN with a finding' { Test-KillSwitchReportsWhatIfWithNoCompletedProtectiveActionsAsWARNWithAFinding }

  It 'maps a WhatIf warning to V2 FAIL in Strict mode' { Test-KillSwitchMapsAWhatIfWarningToV2FAILInStrictMode }
}
