#requires -version 5.1

Describe '21-EmergencyKillSwitch break-glass cleanup failure reporting' -Tag 'EmergencyKillSwitch' {
  BeforeAll {
    $script:KillSwitchScript = Join-Path $PSScriptRoot '../../scripts/21-EmergencyKillSwitch.ps1'
    Import-Module (Join-Path $PSScriptRoot '../../lib/Common.psm1') -Force
    Import-Module (Join-Path $PSScriptRoot '../../lib/EventLog.psm1') -Force

    function global:Get-NetFirewallProfile { }
    function global:Set-NetFirewallProfile { }
    function global:Get-NetFirewallRule { }
    function global:New-NetFirewallRule { }
    function global:Remove-NetFirewallRule { }
    function global:Disable-NetAdapter { }

    function Invoke-EmergencyKillSwitchCleanupFailureCase {
      $oldOS = $env:OS
      $oldTemp = $env:TEMP
      try {
        $env:OS = 'Windows_NT'
        $env:TEMP = $TestDrive

        Mock -CommandName Test-IsAdmin -MockWith { $true }
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
        Mock -CommandName Get-NetFirewallRule -MockWith {
          param([string]$Name)
          if ($Name -like '*BREAKGLASS*') {
            [pscustomobject]@{ Name = $Name }
          } else {
            throw 'rule not present'
          }
        }
        Mock -CommandName Remove-NetFirewallRule -MockWith { throw 'break-glass removal failed' }

        $output = & $script:KillSwitchScript -Mode Remediate -OutputFormat None -PassThru -Confirm:$false 2>&1 3>&1 6>&1
        $exitCode = $LASTEXITCODE
      } finally {
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

        $output = & $script:KillSwitchScript -Mode Remediate -OutputFormat None -PassThru -Confirm:$false 2>&1 3>&1 6>&1
        $exitCode = $LASTEXITCODE
      } finally {
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
      $oldOS = $env:OS
      $oldTemp = $env:TEMP
      try {
        $env:OS = 'Windows_NT'
        $env:TEMP = $TestDrive

        Mock -CommandName Test-IsAdmin -MockWith { $true }
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

        $output = & $script:KillSwitchScript -Mode Remediate -OutputFormat None -PassThru -Confirm:$false -WhatIf 2>&1 3>&1 6>&1
        $exitCode = $LASTEXITCODE
      } finally {
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
        'Disable-NetAdapter'
      )) {
      Remove-Item -LiteralPath "Function:\$name" -ErrorAction SilentlyContinue
    }
  }

  It 'Reports failed managed break-glass rule removal as a failed run' {
    $run = Invoke-EmergencyKillSwitchCleanupFailureCase

    $run.ExitCode | Should -Be 1
    $run.Result.Result | Should -Be 'FAIL'
    $run.Result.Summary.Actions.BreakGlassCleanupChecked | Should -BeTrue
    $run.Result.Summary.Actions.BreakGlassRemoved | Should -BeFalse
    @($run.Result.Summary.Errors | Where-Object { $_ -match 'break-glass removal failed' }).Count | Should -BeGreaterThan 0
  }

  It 'Reports firewall rule creation verification failure as a failed run' {
    $run = Invoke-EmergencyKillSwitchRuleVerifyFailureCase

    $run.ExitCode | Should -Be 1
    $run.Result.Result | Should -Be 'FAIL'
    $run.Result.Summary.Actions.RulesCreated | Should -BeFalse
    @($run.Result.Summary.Errors | Where-Object { $_ -match "Firewall rule 'KILLSWITCH-IN-BLOCK' was not found" }).Count | Should -BeGreaterThan 0
    @($run.Result.Findings | Where-Object Code -eq 'Firewall-RuleCreateFailed').Count | Should -BeGreaterThan 0
  }

  It 'Reports WhatIf with no completed protective actions as WARN with a finding' {
    $run = Invoke-EmergencyKillSwitchWhatIfCase

    $run.Result.Result | Should -Be 'WARN'
    $run.Result.Summary.Actions.ConfirmDeclined | Should -BeTrue
    $run.Result.Summary.Actions.FirewallProfileSet | Should -BeFalse
    $run.Result.Summary.Actions.RulesCreated | Should -BeFalse
    @($run.Result.Findings | Where-Object Code -eq 'KS-ActionsDeclinedOrDryRun').Count | Should -Be 1
  }
}
