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

Describe '21-EmergencyKillSwitch trusted remediation lock' -Tag 'EmergencyKillSwitch' {
  BeforeAll {
    $script:KillSwitchScript = Join-Path $PSScriptRoot '../../scripts/21-EmergencyKillSwitch.ps1'
    $script:KillSwitchHelper = Join-Path $PSScriptRoot '../../scripts/internal/21-EmergencyKillSwitch.helpers.ps1'
    Import-Module (Join-Path $PSScriptRoot '../../lib/Common.psm1') -Force
    . $script:KillSwitchHelper
  }

  It 'uses a ProgramData lock file with a protected SYSTEM and Administrators ACL on Windows' -Skip:([System.Environment]::OSVersion.Platform -ne [System.PlatformID]::Win32NT) {
    $directory = Join-Path $TestDrive 'trusted-kill-switch-lock'
    try {
      $security = Get-KillSwitchLockAcl -Directory
      [void][System.IO.Directory]::CreateDirectory($directory, $security)
      $stream = Enter-KillSwitchRemediationLock -LockDirectory $directory
      try {
        { [System.IO.File]::Open((Join-Path $directory 'remediation.lock'), [System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None) } | Should -Throw
        Assert-KillSwitchLockAcl -Path $directory -Directory
        Assert-KillSwitchLockAcl -Path (Join-Path $directory 'remediation.lock')
      } finally {
        $stream.Dispose()
      }
    } catch {
      Set-ItResult -Skipped -Because "The Windows ACL fixture requires permission to create protected test paths: $($_.Exception.Message)"
    }
  }

  It 'holds a FileShare.None lock until its stream is disposed in portable helper tests' -Skip:([System.Environment]::OSVersion.Platform -eq [System.PlatformID]::Win32NT) {
    $directory = Join-Path $TestDrive 'portable-kill-switch-lock'
    $stream = Enter-KillSwitchRemediationLock -LockDirectory $directory
    try {
      { [System.IO.File]::Open((Join-Path $directory 'remediation.lock'), [System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None) } | Should -Throw
    } finally {
      $stream.Dispose()
    }
    { $retry = [System.IO.File]::Open((Join-Path $directory 'remediation.lock'), [System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None); $retry.Dispose() } | Should -Not -Throw
  }

  It 'contains no named mutex and validates the trusted ProgramData lock path in source' {
    $source = Get-Content -LiteralPath $script:KillSwitchScript -Raw
    $helperSource = Get-Content -LiteralPath $script:KillSwitchHelper -Raw

    $source | Should -Not -Match 'System\.Threading\.Mutex|Global\\BaselineOpsForWindows-EmergencyKillSwitch'
    $source | Should -Match 'Enter-KillSwitchRemediationLock'
    $source | Should -Match '\$killSwitchLockStream\.Dispose\(\)'
    $helperSource | Should -Match 'CommonApplicationData'
    $helperSource | Should -Match 'Microsoft\\Windows'
    $helperSource | Should -Match 'Assert-KillSwitchLockParent -Path \$trustedParent'
    $helperSource | Should -Match 'Test-PathContainsReparsePoint -Path \$directory -Root \$trustedParent'
    $helperSource | Should -Match 'Assert-TrustedWindowsPathAcl -Path \$Path -CheckAncestors'
    $helperSource | Should -Match '\[System\.IO\.FileShare\]::None'
    $helperSource | Should -Match "S-1-5-32-544"
    $helperSource | Should -Match "S-1-5-18"
  }
}

Describe '21-EmergencyKillSwitch break-glass cleanup failure reporting' -Tag 'EmergencyKillSwitch' -Skip:$script:SkipNonSystemWindowsIntegration {
  BeforeAll {
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
        Mock -CommandName Get-ScheduledTask -MockWith { @() }

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
        'Get-ScheduledTask',
        'Disable-NetAdapter',
        'Enter-KillSwitchRemediationLock'
      )) {
      Remove-Item -LiteralPath "Function:\$name" -ErrorAction SilentlyContinue
    }
  }

  It 'fails preflight before mutation when existing rule inventory cannot be read' {
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

  It 'Reports firewall rule creation verification failure as a failed run' {
    $run = Invoke-EmergencyKillSwitchRuleVerifyFailureCase

    $run.ExitCode | Should -Be 1
    $run.Result.Result | Should -Be 'FAIL'
    $run.Result.Summary.Actions.RulesCreated | Should -BeFalse
    @($run.Result.Summary.Errors | Where-Object { $_ -match "Firewall rule 'KILLSWITCH-[a-f0-9]{32}-IN-BLOCK' was not found" }).Count | Should -BeGreaterThan 0
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

  It 'maps a WhatIf warning to V2 FAIL in Strict mode' {
    $run = Invoke-EmergencyKillSwitchWhatIfCase -Strict

    $run.ExitCode | Should -Be 1
    $run.Result.Result | Should -Be 'FAIL'
    @($run.Result.Findings | Where-Object Code -eq 'KS-ActionsDeclinedOrDryRun').Count | Should -Be 1
  }
}

Describe '21-EmergencyKillSwitch exact post-create verification cleanup' -Tag 'EmergencyKillSwitch' {
  BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '../../lib/Results.psm1') -Force
    $script:KillSwitchHelper = Join-Path $PSScriptRoot '../../scripts/internal/21-EmergencyKillSwitch.helpers.ps1'
    $script:ExactCreatedRuleName = 'KILLSWITCH-0123456789abcdef0123456789abcdef-IN-BLOCK'
    function Add-RunError { param([string]$Message) [void]$script:Run.Errors.Add($Message) }
    function global:Get-NetFirewallRule { param([string]$Name,$ErrorAction) }
    function global:New-NetFirewallRule { param($Name,$DisplayName,$Direction,$Action,[Alias('Profile')]$FirewallProfile,$Enabled,$Description,$RemoteAddress,$Protocol,$LocalPort) }
    function global:Remove-NetFirewallRule { param([string]$Name,$ErrorAction) }
    . $script:KillSwitchHelper
  }

  BeforeEach {
    $script:Run = [pscustomobject]@{ Errors = (New-Object System.Collections.Generic.List[string]); Actions = @{}; Effective = @{}; Outcome = @{} }
    $script:Findings = Get-FindingsList
    $global:KillSwitchRuleVerificationQueryCount = 0
    $global:KillSwitchRuleVerificationMode = 'Empty'
    $global:KillSwitchRuleVerificationResult = $null
    Mock New-NetFirewallRule {
      param($Name,$Direction,$Action)
      [pscustomobject]@{ Name = $Name; Enabled = 'True'; Direction = [string]$Direction; Action = [string]$Action }
    }
    Mock Get-NetFirewallRule {
      $global:KillSwitchRuleVerificationQueryCount++
      if ($global:KillSwitchRuleVerificationQueryCount -eq 1) { return $null }
      if ($global:KillSwitchRuleVerificationMode -eq 'QueryError') { throw 'simulated post-create query failure' }
      return $global:KillSwitchRuleVerificationResult
    }
    Mock Remove-NetFirewallRule { }
  }

  AfterAll {
    foreach ($name in @('Get-NetFirewallRule','New-NetFirewallRule','Remove-NetFirewallRule')) { Remove-Item -LiteralPath "Function:\$name" -ErrorAction SilentlyContinue }
    Remove-Variable KillSwitchRuleVerificationQueryCount -Scope Global -ErrorAction SilentlyContinue
    Remove-Variable KillSwitchRuleVerificationMode -Scope Global -ErrorAction SilentlyContinue
    Remove-Variable KillSwitchRuleVerificationResult -Scope Global -ErrorAction SilentlyContinue
  }

  It 'removes the exact just-created rule when verification returns no rule' {
    $created = New-OrReplaceRule -Name $script:ExactCreatedRuleName -DisplayName 'test' -Direction Inbound -Action Block -Confirm:$false

    $created | Should -BeFalse
    Should -Invoke Remove-NetFirewallRule -Times 1 -Exactly -Scope It -ParameterFilter { $Name -eq 'KILLSWITCH-0123456789abcdef0123456789abcdef-IN-BLOCK' }
    @($script:Findings.ToArray() | Where-Object Code -eq 'Firewall-RuleCreateFailed') | Should -HaveCount 1
    @($script:Findings.ToArray() | Where-Object Code -eq 'Firewall-RuleCleanupFailed') | Should -HaveCount 0
  }

  It 'removes the exact just-created rule when verification settings mismatch' {
    $global:KillSwitchRuleVerificationResult = [pscustomobject]@{ Name = $script:ExactCreatedRuleName; Enabled = 'True'; Direction = 'Outbound'; Action = 'Block' }

    $created = New-OrReplaceRule -Name $script:ExactCreatedRuleName -DisplayName 'test' -Direction Inbound -Action Block -Confirm:$false

    $created | Should -BeFalse
    Should -Invoke Remove-NetFirewallRule -Times 1 -Exactly -Scope It -ParameterFilter { $Name -eq 'KILLSWITCH-0123456789abcdef0123456789abcdef-IN-BLOCK' }
    @($script:Run.Errors | Where-Object { $_ -match 'did not match requested settings' }) | Should -HaveCount 1
  }

  It 'removes the exact just-created rule when the verification query fails' {
    $global:KillSwitchRuleVerificationMode = 'QueryError'

    $created = New-OrReplaceRule -Name $script:ExactCreatedRuleName -DisplayName 'test' -Direction Inbound -Action Block -Confirm:$false

    $created | Should -BeFalse
    Should -Invoke Remove-NetFirewallRule -Times 1 -Exactly -Scope It -ParameterFilter { $Name -eq 'KILLSWITCH-0123456789abcdef0123456789abcdef-IN-BLOCK' }
    @($script:Run.Errors | Where-Object { $_ -match 'post-create verification query failed: simulated post-create query failure' }) | Should -HaveCount 1
  }

  It 'surfaces an exact-cleanup failure without attempting a broader removal' {
    Mock Remove-NetFirewallRule { throw 'simulated exact cleanup failure' }

    $created = New-OrReplaceRule -Name $script:ExactCreatedRuleName -DisplayName 'test' -Direction Inbound -Action Block -Confirm:$false

    $created | Should -BeFalse
    Should -Invoke Remove-NetFirewallRule -Times 1 -Exactly -Scope It -ParameterFilter { $Name -eq 'KILLSWITCH-0123456789abcdef0123456789abcdef-IN-BLOCK' }
    @($script:Run.Errors | Where-Object { $_ -match "Exact cleanup of just-created firewall rule '.+' failed.*simulated exact cleanup failure" }) | Should -HaveCount 1
    @($script:Findings.ToArray() | Where-Object Code -eq 'Firewall-RuleCleanupFailed') | Should -HaveCount 1
  }

  It 'keeps the compensating removal bound to the exact rule name in source' {
    $source = Get-Content -LiteralPath $script:KillSwitchHelper -Raw
    $source | Should -Match 'Remove-NetFirewallRule -Name \$Name -ErrorAction Stop'
    $source | Should -Not -Match 'Remove-NetFirewallRule[^\r\n]*(?:RulePrefix|-like|-match)'
  }
}

Describe '21-EmergencyKillSwitch rollback safety gate' -Tag 'EmergencyKillSwitch' -Skip:$script:SkipNonSystemWindowsIntegration {
  BeforeAll {
    $script:KillSwitchScript = Join-Path $PSScriptRoot '../../scripts/21-EmergencyKillSwitch.ps1'
    Import-Module (Join-Path $PSScriptRoot '../../lib/Common.psm1') -Force
    Import-Module (Join-Path $PSScriptRoot '../../lib/EventLog.psm1') -Force

    function global:Get-NetFirewallProfile { }
    function global:Set-NetFirewallProfile {
      param($Name, [switch]$All, $Enabled, $DefaultInboundAction, $DefaultOutboundAction, $ErrorAction)
    }
    function global:Get-NetFirewallRule { }
    function global:New-NetFirewallRule {
      param($Name, $DisplayName, $Direction, $Action, [Alias('Profile')]$FirewallProfile, $Enabled, $Description, $RemoteAddress, $Protocol, $LocalPort)
    }
    function global:Remove-NetFirewallRule { }
    function global:Get-NetAdapter { param([string]$Name) }
    function global:Disable-NetAdapter { param([string]$Name, [switch]$Confirm, $ErrorAction) }
    function global:New-ScheduledTaskAction { }
    function global:New-ScheduledTaskTrigger { }
    function global:New-ScheduledTaskSettingsSet { }
    function global:Register-ScheduledTask { }
    function global:Unregister-ScheduledTask { }
    function global:Get-ScheduledTask { }
    function global:Enter-KillSwitchRemediationLock { }
    function global:Resolve-CanonicalWindowsPowerShellPath { }
  }

  AfterAll {
    foreach ($name in @(
        'Get-NetFirewallProfile',
        'Set-NetFirewallProfile',
        'Get-NetFirewallRule',
        'New-NetFirewallRule',
        'Remove-NetFirewallRule',
        'Get-NetAdapter',
        'Disable-NetAdapter',
        'New-ScheduledTaskAction',
        'New-ScheduledTaskTrigger',
        'New-ScheduledTaskSettingsSet',
        'Register-ScheduledTask',
        'Unregister-ScheduledTask',
        'Get-ScheduledTask',
        'Enter-KillSwitchRemediationLock',
        'Resolve-CanonicalWindowsPowerShellPath'
      )) {
      Remove-Item -LiteralPath "Function:\$name" -ErrorAction SilentlyContinue
    }
  }

  BeforeEach {
    $script:oldOS = $env:OS
    $script:oldTemp = $env:TEMP
    $env:OS = 'Windows_NT'
    $env:TEMP = $TestDrive

    Mock -CommandName Test-IsAdmin -MockWith { $true }
    Mock -CommandName Ensure-EventSource -MockWith { $true }
    Mock -CommandName Write-HealthEvent -MockWith { $true }
    Mock -CommandName New-Item -MockWith { [pscustomobject]@{} }
    Mock -CommandName Set-ItemProperty -MockWith { }
    Mock -CommandName Get-NetFirewallProfile -MockWith {
      foreach ($profileName in @('Domain', 'Private', 'Public')) {
        [pscustomobject]@{
          Name                  = $profileName
          Enabled               = 'True'
          DefaultInboundAction  = 'Allow'
          DefaultOutboundAction = 'Allow'
        }
      }
    }
    Mock -CommandName Set-NetFirewallProfile -MockWith { }
    $global:EmergencyKillSwitchRuleStore = @{}
    $global:EmergencyKillSwitchTaskStore = @{}
    Mock -CommandName New-NetFirewallRule -MockWith {
      param($Name, $DisplayName, $Direction, $Action, [Alias('Profile')]$FirewallProfile, $Enabled, $Description, $RemoteAddress, $Protocol, $LocalPort)
      $global:EmergencyKillSwitchRuleStore[$Name] = [pscustomobject]@{
        Name = $Name; Enabled = 'True'; Direction = [string]$Direction; Action = [string]$Action
      }
    }
    Mock -CommandName Get-NetFirewallRule -MockWith {
      param([string]$Name)
      if ([string]::IsNullOrWhiteSpace($Name)) { return @($global:EmergencyKillSwitchRuleStore.Values) }
      if ($global:EmergencyKillSwitchRuleStore.ContainsKey($Name)) { return $global:EmergencyKillSwitchRuleStore[$Name] }
    }
    Mock -CommandName Get-ScheduledTask -MockWith { @($global:EmergencyKillSwitchTaskStore.Values) }
    Mock -CommandName Remove-NetFirewallRule -MockWith {
      $global:EmergencyKillSwitchRuleStore.Clear()
    }
    Mock -CommandName Enter-KillSwitchRemediationLock -MockWith { New-Object System.IO.MemoryStream }
    Mock -CommandName Resolve-CanonicalWindowsPowerShellPath -MockWith { 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' }
    Mock -CommandName Get-NetAdapter -MockWith { @() }
    Mock -CommandName Disable-NetAdapter -MockWith { param($Name, [switch]$Confirm, $ErrorAction) }
    Mock -CommandName New-ScheduledTaskAction -MockWith {
      param($Execute, $Argument)
      [pscustomobject]@{ Execute = $Execute; Argument = $Argument }
    }
    Mock -CommandName New-ScheduledTaskTrigger -MockWith {
      param([switch]$Once, [datetime]$At)
      [pscustomobject]@{ Once = [bool]$Once; At = $At }
    }
    Mock -CommandName New-ScheduledTaskSettingsSet -MockWith {
      param([switch]$StartWhenAvailable, [int]$RestartCount, [timespan]$RestartInterval, [timespan]$ExecutionTimeLimit)
      [pscustomobject]@{ StartWhenAvailable = [bool]$StartWhenAvailable; RestartCount = $RestartCount; RestartInterval = $RestartInterval; ExecutionTimeLimit = $ExecutionTimeLimit }
    }
    Mock -CommandName Register-ScheduledTask -MockWith {
      param($TaskName)
      $global:EmergencyKillSwitchTaskStore[$TaskName] = [pscustomobject]@{ TaskName = $TaskName }
      [pscustomobject]@{ Registered = $true }
    }
    Mock -CommandName Unregister-ScheduledTask -MockWith {
      param($TaskName)
      $null = $global:EmergencyKillSwitchTaskStore.Remove([string]$TaskName)
    }
  }

  AfterEach {
    Remove-Variable -Name EmergencyKillSwitchRuleStore -Scope Global -ErrorAction SilentlyContinue
    Remove-Variable -Name EmergencyKillSwitchTaskStore -Scope Global -ErrorAction SilentlyContinue
    if ($null -eq $script:oldOS) {
      Remove-Item -LiteralPath Env:OS -ErrorAction SilentlyContinue
    } else {
      $env:OS = $script:oldOS
    }
    if ($null -eq $script:oldTemp) {
      Remove-Item -LiteralPath Env:TEMP -ErrorAction SilentlyContinue
    } else {
      $env:TEMP = $script:oldTemp
    }
  }

  It 'aborts before firewall mutation when rollback scheduling fails' {
    Mock -CommandName Get-NetFirewallProfile -MockWith {
      foreach ($profileName in @('Domain', 'Private', 'Public')) {
        [pscustomobject]@{ Name = $profileName; Enabled = 'True'; DefaultInboundAction = 'Allow'; DefaultOutboundAction = 'Allow' }
      }
    }
    Mock -CommandName Register-ScheduledTask -MockWith { throw 'schedule failed' }

    $output = & $script:KillSwitchScript -Mode Remediate -AutoRollbackMinutes 5 -OutputFormat None -PassThru -Confirm:$false 2>&1 3>&1 6>&1
    $result = @($output | Where-Object { $_.PSObject.Properties.Name -contains 'Result' })[-1]

    $LASTEXITCODE | Should -Be 1
    $result.Result | Should -Be 'FAIL'
    $result.Summary.Actions.RollbackStateCaptured | Should -BeTrue
    $result.Summary.Actions.RollbackScheduled | Should -BeFalse
    $result.Summary.Actions.RegistryWritten | Should -BeFalse
    Should -Invoke Set-ItemProperty -Times 0
    Should -Invoke Set-NetFirewallProfile -Times 0
    Should -Invoke New-NetFirewallRule -Times 0
  }

  It 'refuses a rerun while exact identities from an earlier activation remain active' {
    Mock -CommandName Get-NetFirewallProfile -MockWith {
      foreach ($profileName in @('Domain', 'Private', 'Public')) {
        [pscustomobject]@{ Name = $profileName; Enabled = 'True'; DefaultInboundAction = 'Allow'; DefaultOutboundAction = 'Allow' }
      }
    }
    $global:ScheduledTaskCaptures = New-Object System.Collections.Generic.List[object]
    Mock -CommandName Register-ScheduledTask -MockWith {
      param($TaskName, $Action, $Trigger, $Settings, $User, $RunLevel, [switch]$Force, $ErrorAction)
      [void]$global:ScheduledTaskCaptures.Add([pscustomobject]@{ TaskName = $TaskName; Action = $Action; Trigger = $Trigger; Settings = $Settings; User = $User; RunLevel = $RunLevel })
      [pscustomobject]@{ Registered = $true }
    }

    $firstOutput = & $script:KillSwitchScript -Mode Remediate -AutoRollbackMinutes 5 -OutputFormat None -PassThru -Confirm:$false 2>&1 3>&1 6>&1
    $secondOutput = & $script:KillSwitchScript -Mode Remediate -AutoRollbackMinutes 5 -OutputFormat None -PassThru -Confirm:$false 2>&1 3>&1 6>&1
    $first = @($firstOutput | Where-Object { $_.PSObject.Properties.Name -contains 'Result' })[-1]
    $second = @($secondOutput | Where-Object { $_.PSObject.Properties.Name -contains 'Result' })[-1]

    $first.Summary.Effective.RollbackSnapshotEmbedded | Should -BeTrue -Because ($first.Summary.Errors -join '; ')
    $second.Result | Should -Be 'FAIL'
    @($second.Findings | Where-Object Code -eq 'Firewall-ManagedRuleConflict') | Should -HaveCount 1
    $second.Summary.Actions.RegistryWritten | Should -BeFalse
    $second.Summary.Actions.RollbackScheduled | Should -BeFalse
    $global:ScheduledTaskCaptures.Count | Should -Be 1

    $capture = $global:ScheduledTaskCaptures[0]
    $encodedCommand = $capture.Action.Argument.Split()[-1]
    $rollbackScript = [System.Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($encodedCommand))
    $rollbackScript | Should -Match 'foreach \(\$managedRule in'
    $rollbackScript | Should -Match 'Get-NetFirewallRule -Name \$managedRule.Name -ErrorAction SilentlyContinue'
    $rollbackScript | Should -Match 'Rule identity mismatch; refusing removal'
    $snapshotMatch = [regex]::Match($rollbackScript, "FromBase64String\('([^']+)'\)")
    $embeddedSnapshot = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($snapshotMatch.Groups[1].Value)) | ConvertFrom-Json
    $embeddedSnapshot.Version | Should -Be 3
    @($embeddedSnapshot.ManagedRules) | Should -HaveCount 2
    Remove-Variable -Name ScheduledTaskCaptures -Scope Global -ErrorAction SilentlyContinue
  }

  It 'captures and restores only adapters disabled by an auto-rollback run' {
    Mock -CommandName Get-NetAdapter -MockWith {
      @(
        [pscustomobject]@{ Name = 'Wi-Fi'; Status = 'Up' },
        [pscustomobject]@{ Name = 'Ethernet'; Status = 'Down' }
      )
    }
    $global:ScheduledTaskCapture = $null
    Mock -CommandName Register-ScheduledTask -MockWith {
      param($TaskName, $Action, $Trigger, $Settings, $User, $RunLevel, [switch]$Force, $ErrorAction)
      $global:ScheduledTaskCapture = [pscustomobject]@{ TaskName = $TaskName; Action = $Action; Trigger = $Trigger; Settings = $Settings }
      [pscustomobject]@{ Registered = $true }
    }

    $output = & $script:KillSwitchScript -Mode Remediate -DisableAdapters -AutoRollbackMinutes 5 -OutputFormat None -PassThru -Confirm:$false 2>&1 3>&1 6>&1
    $result = @($output | Where-Object { $_.PSObject.Properties.Name -contains 'Result' })[-1]
    $global:ScheduledTaskCapture | Should -Not -BeNullOrEmpty -Because ($result.Summary.Errors -join '; ')
    $encodedCommand = $global:ScheduledTaskCapture.Action.Argument.Split()[-1]
    $rollbackScript = [System.Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($encodedCommand))
    $snapshotMatch = [regex]::Match($rollbackScript, "FromBase64String\('([^']+)'\)")
    $embeddedSnapshot = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($snapshotMatch.Groups[1].Value)) | ConvertFrom-Json

    $result.Summary.Actions.AdaptersDisabled | Should -BeTrue -Because ($result.Summary.Errors -join '; ')
    @($embeddedSnapshot.Adapters) | Should -Be @('Wi-Fi')
    $rollbackScript | Should -Match 'Enable-NetAdapter -Name'
    Should -Invoke Disable-NetAdapter -Times 1 -ParameterFilter { $Name -eq 'Wi-Fi' }
    Should -Invoke Disable-NetAdapter -Times 0 -ParameterFilter { $Name -eq 'Ethernet' }
    Remove-Variable -Name ScheduledTaskCapture -Scope Global -ErrorAction SilentlyContinue
  }

  It 'aborts before firewall mutation when captured rollback state is malformed' {
    Mock -CommandName Get-NetFirewallProfile -MockWith {
      @(
        [pscustomobject]@{ Name = 'Domain'; Enabled = 'True'; DefaultInboundAction = 'Allow'; DefaultOutboundAction = 'Allow' },
        [pscustomobject]@{ Name = 'Domain'; Enabled = 'True'; DefaultInboundAction = 'Allow'; DefaultOutboundAction = 'Allow' },
        [pscustomobject]@{ Name = 'Public'; Enabled = 'not-a-boolean'; DefaultInboundAction = 'Allow'; DefaultOutboundAction = 'Allow' }
      )
    }

    $output = & $script:KillSwitchScript -Mode Remediate -AutoRollbackMinutes 5 -OutputFormat None -PassThru -Confirm:$false 2>&1 3>&1 6>&1
    $result = @($output | Where-Object { $_.PSObject.Properties.Name -contains 'Result' })[-1]

    $LASTEXITCODE | Should -Be 1
    $result.Result | Should -Be 'FAIL'
    $result.Summary.Actions.RollbackStateCaptured | Should -BeFalse
    Should -Invoke Set-NetFirewallProfile -Times 0
    Should -Invoke New-NetFirewallRule -Times 0
  }

  It 'ignores foreign similarly named rules while exact legacy identities block before registry and scheduling' {
    $legacyName = 'KILLSWITCH-' + ('a' * 32) + '-OUT-BLOCK'
    $global:EmergencyKillSwitchRuleStore[$legacyName] = [pscustomobject]@{
      Name = $legacyName; Enabled = 'True'; Direction = 'Outbound'; Action = 'Block'
    }

    $legacyOutput = & $script:KillSwitchScript -Mode Remediate -AutoRollbackMinutes 5 -OutputFormat None -PassThru -Confirm:$false 2>&1 3>&1 6>&1
    $legacyResult = @($legacyOutput | Where-Object { $_.PSObject.Properties.Name -contains 'Result' })[-1]
    $legacyResult.Result | Should -Be 'FAIL'
    @($legacyResult.Findings | Where-Object Code -eq 'Firewall-ManagedRuleConflict') | Should -HaveCount 1
    Should -Invoke Set-ItemProperty -Times 0 -Scope It
    Should -Invoke Register-ScheduledTask -Times 0 -Scope It

    $global:EmergencyKillSwitchRuleStore.Clear()
    $global:EmergencyKillSwitchRuleStore['KILLSWITCH-foreign-IN-BLOCK'] = [pscustomobject]@{
      Name = 'KILLSWITCH-foreign-IN-BLOCK'; Enabled = 'True'; Direction = 'Inbound'; Action = 'Block'
    }

    $foreignOutput = & $script:KillSwitchScript -Mode Remediate -OutputFormat None -PassThru -Confirm:$false 2>&1 3>&1 6>&1
    $foreignResult = @($foreignOutput | Where-Object { $_.PSObject.Properties.Name -contains 'Result' })[-1]
    $foreignResult.Summary.Actions.FirewallProfileSet | Should -BeTrue -Because ($foreignResult.Summary.Errors -join '; ')
  }

  It 'refuses an orphaned exact rollback task even when its rules are already absent' {
    $global:EmergencyKillSwitchTaskStore['KILLSWITCH-ROLLBACK'] = [pscustomobject]@{ TaskName = 'KILLSWITCH-ROLLBACK' }

    $output = & $script:KillSwitchScript -Mode Remediate -AutoRollbackMinutes 5 -OutputFormat None -PassThru -Confirm:$false 2>&1 3>&1 6>&1
    $result = @($output | Where-Object { $_.PSObject.Properties.Name -contains 'Result' })[-1]

    $result.Result | Should -Be 'FAIL'
    @($result.Findings | Where-Object Code -eq 'Firewall-ManagedRuleConflict') | Should -HaveCount 1
    $result.Summary.Actions.RegistryWritten | Should -BeFalse
    Should -Invoke Register-ScheduledTask -Times 0 -Scope It
    Should -Invoke Set-NetFirewallProfile -Times 0 -Scope It
  }

  It 'does not isolate when break-glass creation fails' {
    Mock -CommandName New-NetFirewallRule -MockWith {
      param($Name, $Direction, $Action)
      if ([string]$Action -eq 'Allow') { throw 'simulated break-glass creation failure' }
      $global:EmergencyKillSwitchRuleStore[$Name] = [pscustomobject]@{ Name = $Name; Enabled = 'True'; Direction = [string]$Direction; Action = [string]$Action }
    }

    $output = & $script:KillSwitchScript -Mode Remediate -BreakGlassRemoteAddress '192.0.2.10' -BreakGlassLocalPort 5986 -OutputFormat None -PassThru -Confirm:$false 2>&1 3>&1 6>&1
    $result = @($output | Where-Object { $_.PSObject.Properties.Name -contains 'Result' })[-1]

    $result.Result | Should -Be 'FAIL'
    $result.Summary.Actions.FirewallProfileSet | Should -BeFalse
    $result.Summary.Actions.BreakGlassApplied | Should -BeFalse
    Should -Invoke Set-NetFirewallProfile -Times 0 -Scope It
    Should -Invoke New-NetFirewallRule -Times 0 -Scope It -ParameterFilter { [string]$Action -eq 'Block' }
  }

  It 'uses profile-default inbound blocking with only the intended break-glass source and port allowed' {
    $output = & $script:KillSwitchScript -Mode Remediate -BreakGlassRemoteAddress '192.0.2.10' -BreakGlassLocalPort 5986 -OutputFormat None -PassThru -Confirm:$false 2>&1 3>&1 6>&1
    $result = @($output | Where-Object { $_.PSObject.Properties.Name -contains 'Result' })[-1]

    $result.Summary.Actions.FirewallProfileSet | Should -BeTrue -Because ($result.Summary.Errors -join '; ')
    $result.Summary.Actions.BreakGlassApplied | Should -BeTrue
    Should -Invoke Set-NetFirewallProfile -Times 1 -Scope It
    Should -Invoke New-NetFirewallRule -Times 0 -Scope It -ParameterFilter { [string]$Direction -eq 'Inbound' -and [string]$Action -eq 'Block' }
    Should -Invoke New-NetFirewallRule -Times 1 -Scope It -ParameterFilter {
      [string]$Direction -eq 'Inbound' -and [string]$Action -eq 'Allow' -and
      [string]$Protocol -eq 'TCP' -and [string]$LocalPort -eq '5986' -and
      @($RemoteAddress) -contains '192.0.2.10'
    }
  }

  It 'removes only the exact partial identity when later rule creation fails' {
    Mock -CommandName New-NetFirewallRule -MockWith {
      param($Name, $Direction, $Action)
      if ([string]$Direction -eq 'Outbound') { throw 'simulated outbound creation failure' }
      $global:EmergencyKillSwitchRuleStore[$Name] = [pscustomobject]@{ Name = $Name; Enabled = 'True'; Direction = [string]$Direction; Action = [string]$Action }
    }

    $output = & $script:KillSwitchScript -Mode Remediate -AutoRollbackMinutes 5 -OutputFormat None -PassThru -Confirm:$false 2>&1 3>&1 6>&1
    $result = @($output | Where-Object { $_.PSObject.Properties.Name -contains 'Result' })[-1]

    $result.Result | Should -Be 'FAIL'
    $result.Summary.Actions.RegistryWritten | Should -BeFalse
    $result.Summary.Actions.FirewallProfileSet | Should -BeFalse
    $global:EmergencyKillSwitchRuleStore.Count | Should -Be 0
    Should -Invoke Remove-NetFirewallRule -Times 1 -Scope It
    Should -Invoke Unregister-ScheduledTask -Times 1 -Scope It
    Should -Invoke Set-NetFirewallProfile -Times 0 -Scope It
    Should -Invoke Set-ItemProperty -Times 0 -Scope It
  }

  It 'does not persist the isolation registry flag when firewall profile activation fails' {
    Mock -CommandName Set-NetFirewallProfile -MockWith { throw 'simulated profile activation failure' }

    $output = & $script:KillSwitchScript -Mode Remediate -OutputFormat None -PassThru -Confirm:$false 2>&1 3>&1 6>&1
    $result = @($output | Where-Object { $_.PSObject.Properties.Name -contains 'Result' })[-1]

    $result.Result | Should -Be 'FAIL'
    $result.Summary.Actions.FirewallProfileSet | Should -BeFalse
    $result.Summary.Actions.RegistryWritten | Should -BeFalse
    Should -Invoke Set-ItemProperty -Times 0 -Scope It
  }

  It 'rejects a missing canonical Windows PowerShell host before firewall mutation and ignores poisoned root variables' {
    $oldSystemRoot = $env:SystemRoot
    $oldWindir = $env:WINDIR
    try {
      $env:SystemRoot = 'C:\attacker'
      $env:WINDIR = 'C:\attacker'
      Mock -CommandName Resolve-CanonicalWindowsPowerShellPath -MockWith { throw 'canonical Windows PowerShell is missing' }

      $output = & $script:KillSwitchScript -Mode Remediate -AutoRollbackMinutes 5 -OutputFormat None -PassThru -Confirm:$false 2>&1 3>&1 6>&1
      $result = @($output | Where-Object { $_.PSObject.Properties.Name -contains 'Result' })[-1]

      $result.Result | Should -Be 'FAIL'
      @($result.Summary.Errors | Where-Object { $_ -match 'canonical Windows PowerShell is missing' }) | Should -Not -BeNullOrEmpty
      Should -Invoke Set-NetFirewallProfile -Times 0 -Scope It
      Should -Invoke New-NetFirewallRule -Times 0 -Scope It

      $entrySource = Get-Content -LiteralPath $script:KillSwitchScript -Raw
      $helperSource = Get-Content -LiteralPath (Join-Path (Split-Path $script:KillSwitchScript) 'internal/21-EmergencyKillSwitch.helpers.ps1') -Raw
      $entrySource | Should -Not -Match '\$env:(?:SystemRoot|WINDIR)'
      $entrySource | Should -Not -Match '\$PSHOME'
      $helperSource | Should -Match 'SpecialFolder\]::System'
      $helperSource | Should -Match 'FileAttributes\]::ReparsePoint'
    } finally {
      if ($null -eq $oldSystemRoot) { Remove-Item Env:SystemRoot -ErrorAction SilentlyContinue } else { $env:SystemRoot = $oldSystemRoot }
      if ($null -eq $oldWindir) { Remove-Item Env:WINDIR -ErrorAction SilentlyContinue } else { $env:WINDIR = $oldWindir }
    }
  }
}

Describe '21-EmergencyKillSwitch configuration rejection V2 reporting' -Tag 'EmergencyKillSwitch' {
  BeforeAll {
    $script:KillSwitchScript = Join-Path $PSScriptRoot '../../scripts/21-EmergencyKillSwitch.ps1'
  }

  It 'reports invalid configuration as a V2 FAIL result' -TestCases @(
    @{ Name = 'an unsafe registry key'; ConfigJsonRaw = '{"RegKey":"HKCU:\\Unsafe"}'; FindingCode = 'KS-InvalidRegKey'; Message = 'RegKey' }
    @{ Name = 'a wildcard registry key'; ConfigJsonRaw = '{"RegKey":"HKLM:\\SOFTWARE\\KillSwitch\\*"}'; FindingCode = 'KS-InvalidRegKey'; Message = 'wildcard' }
    @{ Name = 'a rule prefix with unsafe characters'; ConfigJsonRaw = '{"RulePrefix":"unsafe prefix"}'; FindingCode = 'KS-InvalidRulePrefix'; Message = 'contains invalid characters' }
    @{ Name = 'an overlong rule prefix'; ConfigJsonRaw = ('{"RulePrefix":"' + ('A' * 65) + '"}'); FindingCode = 'KS-InvalidRulePrefix'; Message = 'exceeds 64 characters' }
  ) {
    param($ConfigJsonRaw, $FindingCode, $Message)

    $oldOS = $env:OS
    try {
      $env:OS = 'Windows_NT'
      $output = & $script:KillSwitchScript -Mode Audit -ConfigJsonRaw $ConfigJsonRaw -OutputFormat None -PassThru -Confirm:$false 2>&1 3>&1 6>&1
      $result = @($output | Where-Object { $_ -and $_.PSObject.Properties.Name -contains 'Result' })[-1]

      $LASTEXITCODE | Should -Be 1
      $result.Result | Should -Be 'FAIL'
      @($result.Findings | Where-Object Code -eq $FindingCode).Count | Should -Be 1
      @($result.Findings | Where-Object Code -eq $FindingCode)[0].Message | Should -Match $Message
    } finally {
      if ($null -eq $oldOS) { Remove-Item -LiteralPath Env:OS -ErrorAction SilentlyContinue }
      else { $env:OS = $oldOS }
    }
  }

  It 'fails closed with one V2 result for malformed or wrong-typed JSON' -TestCases @(
    @{ Json = '{'; Message = 'invalid' },
    @{ Json = '42'; Message = 'root must be an object' },
    @{ Json = '{"DisableAdapters":"false"}'; Message = 'must be a boolean' },
    @{ Json = '{"EventId":"9001"}'; Message = 'must be an integer' },
    @{ Json = '{"AutoRollbackMinutes":4.5}'; Message = 'must be an integer' },
    @{ Json = '{"BreakGlassRemoteAddress":"10.0.0.1"}'; Message = 'must be an array' },
    @{ Json = '{"Unexpected":true}'; Message = 'unknown field' }
  ) {
    param($Json, $Message)

    $oldOS = $env:OS
    try {
      $env:OS = 'Windows_NT'
      $output = & $script:KillSwitchScript -Mode Audit -ConfigJsonRaw $Json -OutputFormat None -PassThru -Confirm:$false 2>&1 3>&1 6>&1
      $results = @($output | Where-Object { $_ -and $_.PSObject.Properties.Name -contains 'Result' })

      $LASTEXITCODE | Should -Be 1
      $results | Should -HaveCount 1
      $results[0].Result | Should -Be 'FAIL'
      @($results[0].Findings | Where-Object Code -eq 'KS-InvalidConfig') | Should -HaveCount 1
      @($results[0].Findings | Where-Object Code -eq 'KS-InvalidConfig')[0].Message | Should -Match $Message
    } finally {
      if ($null -eq $oldOS) { Remove-Item -LiteralPath Env:OS -ErrorAction SilentlyContinue } else { $env:OS = $oldOS }
    }
  }
}

Describe '21-EmergencyKillSwitch Strict unsupported-host reporting' -Tag 'EmergencyKillSwitch' {
  It 'maps the unsupported-host WARN result to V2 FAIL and exit code 1' {
    $scriptPath = Join-Path $PSScriptRoot '../../scripts/21-EmergencyKillSwitch.ps1'
    $oldOS = $env:OS
    try {
      Remove-Item -LiteralPath Env:OS -ErrorAction SilentlyContinue
      $output = & $scriptPath -Mode Audit -OutputFormat None -PassThru -Strict 2>&1 3>&1 6>&1
      $exitCode = $LASTEXITCODE
      $result = @($output | Where-Object { $_ -and $_.PSObject.Properties.Name -contains 'Result' })[-1]

      $exitCode | Should -Be 1
      $result.Result | Should -Be 'FAIL'
      $result.Metadata.UnsupportedHost | Should -BeTrue
    } finally {
      if ($null -eq $oldOS) { Remove-Item -LiteralPath Env:OS -ErrorAction SilentlyContinue }
      else { $env:OS = $oldOS }
    }
  }
}
