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

Describe '21-EmergencyKillSwitch rollback safety gate' -Tag 'EmergencyKillSwitch' -Skip:$script:SkipNonSystemWindowsIntegration {
  BeforeAll {
function Remove-KillSwitchCommandStubs {

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
        'Resolve-CanonicalWindowsPowerShellPath',
        'Get-EmergencyKillSwitchFixtureState'
      )) {
      Remove-Item -LiteralPath "Function:\$name" -ErrorAction SilentlyContinue
    }
}

function Initialize-KillSwitchCommandStubs {

    $script:KillSwitchScript = Join-Path $PSScriptRoot '../../scripts/21-EmergencyKillSwitch.ps1'
    Import-Module (Join-Path $PSScriptRoot '../../lib/Common.psm1') -Force
    Import-Module (Join-Path $PSScriptRoot '../../lib/EventLog.psm1') -Force

    function global:Get-NetFirewallProfile { }
    function global:Set-NetFirewallProfile {
      param($Name, [switch]$All, $Enabled, $DefaultInboundAction, $DefaultOutboundAction, $ErrorAction)
      $null = $Name, $All, $Enabled, $DefaultInboundAction, $DefaultOutboundAction, $ErrorAction
    }
    function global:Get-NetFirewallRule { }
    function global:New-NetFirewallRule {
      param($Name, $Direction, $Action, [Alias('Profile')]$FirewallProfile, $Enabled, $RemoteAddress, $Protocol, $LocalPort)
      $null = $Name, $Direction, $Action, $FirewallProfile, $Enabled, $RemoteAddress, $Protocol, $LocalPort
    }
    function global:Remove-NetFirewallRule { }
    function global:Get-NetAdapter { param([string]$Name) $null = $Name }
    Set-Item -LiteralPath Function:\global:Disable-NetAdapter -Value {
      param([string]$Name, [Alias('Confirm')][switch]$ShouldConfirm, $ErrorAction)
      $null = $Name, $ShouldConfirm, $ErrorAction
    }
    function global:New-ScheduledTaskAction { }
    function global:New-ScheduledTaskTrigger { }
    function global:New-ScheduledTaskSettingsSet { }
    function global:Register-ScheduledTask { }
    function global:Unregister-ScheduledTask { }
    function global:Get-ScheduledTask { }
    function global:Enter-KillSwitchRemediationLock { }
    function global:Resolve-CanonicalWindowsPowerShellPath { }
    $fixtureState = [pscustomobject]@{
      RuleStore             = @{}
      TaskStore             = @{}
      ScheduledTaskCaptures = $null
      ScheduledTaskCapture  = $null
    }
    Set-Item -LiteralPath Function:\global:Get-EmergencyKillSwitchFixtureState -Value {
      return $fixtureState
    }.GetNewClosure()
}

function Initialize-KillSwitchFirewallFixture {

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
    $script:EmergencyKillSwitchFixtureState = Get-EmergencyKillSwitchFixtureState
    $script:EmergencyKillSwitchFixtureState.RuleStore = @{}
    $script:EmergencyKillSwitchFixtureState.TaskStore = @{}
    $script:EmergencyKillSwitchFixtureState.ScheduledTaskCaptures = $null
    $script:EmergencyKillSwitchFixtureState.ScheduledTaskCapture = $null
    Mock -CommandName New-NetFirewallRule -MockWith {
      param($Name, $Direction, $Action, [Alias('Profile')]$FirewallProfile, $Enabled, $RemoteAddress, $Protocol, $LocalPort)
      $null = $DisplayName, $FirewallProfile, $Enabled, $RemoteAddress, $Protocol, $LocalPort
      $fixtureState = Get-EmergencyKillSwitchFixtureState
      $fixtureState.RuleStore[$Name] = [pscustomobject]@{
        Name = $Name; Enabled = 'True'; Direction = [string]$Direction; Action = [string]$Action
      }
    }
    Mock -CommandName Get-NetFirewallRule -MockWith {
      param([string]$Name)
      $fixtureState = Get-EmergencyKillSwitchFixtureState
      if ([string]::IsNullOrWhiteSpace($Name)) { return @($fixtureState.RuleStore.Values) }
      if ($fixtureState.RuleStore.ContainsKey($Name)) { return $fixtureState.RuleStore[$Name] }
    }
    Mock -CommandName Get-ScheduledTask -MockWith {
      $fixtureState = Get-EmergencyKillSwitchFixtureState
      return @($fixtureState.TaskStore.Values)
    }
    Mock -CommandName Remove-NetFirewallRule -MockWith {
      $fixtureState = Get-EmergencyKillSwitchFixtureState
      $fixtureState.RuleStore.Clear()
    }
}

function Initialize-KillSwitchRollbackFixture {
    Mock -CommandName Enter-KillSwitchRemediationLock -MockWith { New-Object System.IO.MemoryStream }
    Mock -CommandName Resolve-CanonicalWindowsPowerShellPath -MockWith { 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' }
    Mock -CommandName Get-NetAdapter -MockWith { @() }
    Mock -CommandName Disable-NetAdapter -MockWith {
      param($Name, [Alias('Confirm')][switch]$ShouldConfirm, $ErrorAction)
      $null = $Name, $ShouldConfirm, $ErrorAction
    }
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
      $fixtureState = Get-EmergencyKillSwitchFixtureState
      $fixtureState.TaskStore[$TaskName] = [pscustomobject]@{ TaskName = $TaskName }
      [pscustomobject]@{ Registered = $true }
    }
    Mock -CommandName Unregister-ScheduledTask -MockWith {
      param($TaskName)
      $fixtureState = Get-EmergencyKillSwitchFixtureState
      $null = $fixtureState.TaskStore.Remove([string]$TaskName)
    }
}

function Test-KillSwitchAbortsBeforeFirewallMutationWhenRollbackSchedulingFails {
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

function Test-KillSwitchRefusesARerunWhileExactIdentitiesFromAnEarlierActivationRemainActive {
    Mock -CommandName Get-NetFirewallProfile -MockWith {
      foreach ($profileName in @('Domain', 'Private', 'Public')) {
        [pscustomobject]@{ Name = $profileName; Enabled = 'True'; DefaultInboundAction = 'Allow'; DefaultOutboundAction = 'Allow' }
      }
    }
    $script:EmergencyKillSwitchFixtureState.ScheduledTaskCaptures = New-Object System.Collections.Generic.List[object]
    Mock -CommandName Register-ScheduledTask -MockWith {
      param($TaskName, $Action, $Trigger, $Settings, $User, $RunLevel, [switch]$Force, $ErrorAction)
      $null = $Force, $ErrorAction
      $fixtureState = Get-EmergencyKillSwitchFixtureState
      [void]$fixtureState.ScheduledTaskCaptures.Add([pscustomobject]@{ TaskName = $TaskName; Action = $Action; Trigger = $Trigger; Settings = $Settings; User = $User; RunLevel = $RunLevel })
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
    $script:EmergencyKillSwitchFixtureState.ScheduledTaskCaptures.Count | Should -Be 1

    $capture = $script:EmergencyKillSwitchFixtureState.ScheduledTaskCaptures[0]
    $encodedCommand = $capture.Action.Argument.Split()[-1]
    $rollbackScript = [System.Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($encodedCommand))
    $rollbackScript | Should -Match 'foreach \(\$managedRule in'
    $rollbackScript | Should -Match 'Get-NetFirewallRule -Name \$managedRule.Name -ErrorAction SilentlyContinue'
    $rollbackScript | Should -Match 'Rule identity mismatch; refusing removal'
    $snapshotMatch = [regex]::Match($rollbackScript, "FromBase64String\('([^']+)'\)")
    $embeddedSnapshot = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($snapshotMatch.Groups[1].Value)) | ConvertFrom-Json
    $embeddedSnapshot.Version | Should -Be 3
    @($embeddedSnapshot.ManagedRules) | Should -HaveCount 2
    $script:EmergencyKillSwitchFixtureState.ScheduledTaskCaptures = $null
  }

function Test-KillSwitchCapturesAndRestoresOnlyAdaptersDisabledByAnAutoRollbackRun {
    Mock -CommandName Get-NetAdapter -MockWith {
      @(
        [pscustomobject]@{ Name = 'Wi-Fi'; Status = 'Up' },
        [pscustomobject]@{ Name = 'Ethernet'; Status = 'Down' }
      )
    }
    $script:EmergencyKillSwitchFixtureState.ScheduledTaskCapture = $null
    Mock -CommandName Register-ScheduledTask -MockWith {
      param($TaskName, $Action, $Trigger, $Settings, $User, $RunLevel, [switch]$Force, $ErrorAction)
      $null = $User, $RunLevel, $Force, $ErrorAction
      $fixtureState = Get-EmergencyKillSwitchFixtureState
      $fixtureState.ScheduledTaskCapture = [pscustomobject]@{ TaskName = $TaskName; Action = $Action; Trigger = $Trigger; Settings = $Settings }
      [pscustomobject]@{ Registered = $true }
    }

    $output = & $script:KillSwitchScript -Mode Remediate -DisableAdapters -AutoRollbackMinutes 5 -OutputFormat None -PassThru -Confirm:$false 2>&1 3>&1 6>&1
    $result = @($output | Where-Object { $_.PSObject.Properties.Name -contains 'Result' })[-1]
    $script:EmergencyKillSwitchFixtureState.ScheduledTaskCapture | Should -Not -BeNullOrEmpty -Because ($result.Summary.Errors -join '; ')
    $encodedCommand = $script:EmergencyKillSwitchFixtureState.ScheduledTaskCapture.Action.Argument.Split()[-1]
    $rollbackScript = [System.Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($encodedCommand))
    $snapshotMatch = [regex]::Match($rollbackScript, "FromBase64String\('([^']+)'\)")
    $embeddedSnapshot = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($snapshotMatch.Groups[1].Value)) | ConvertFrom-Json

    $result.Summary.Actions.AdaptersDisabled | Should -BeTrue -Because ($result.Summary.Errors -join '; ')
    @($embeddedSnapshot.Adapters) | Should -Be @('Wi-Fi')
    $rollbackScript | Should -Match 'Enable-NetAdapter -Name'
    Should -Invoke Disable-NetAdapter -Times 1 -ParameterFilter { $Name -eq 'Wi-Fi' }
    Should -Invoke Disable-NetAdapter -Times 0 -ParameterFilter { $Name -eq 'Ethernet' }
    $script:EmergencyKillSwitchFixtureState.ScheduledTaskCapture = $null
  }

function Test-KillSwitchAbortsBeforeFirewallMutationWhenCapturedRollbackStateIsMalformed {
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

function Test-KillSwitchIgnoresForeignSimilarlyNamedRulesWhileExactLegacyIdentitiesBlockBeforeRegistryAndScheduling {
    $legacyName = 'KILLSWITCH-' + ('a' * 32) + '-OUT-BLOCK'
    $script:EmergencyKillSwitchFixtureState.RuleStore[$legacyName] = [pscustomobject]@{
      Name = $legacyName; Enabled = 'True'; Direction = 'Outbound'; Action = 'Block'
    }

    $legacyOutput = & $script:KillSwitchScript -Mode Remediate -AutoRollbackMinutes 5 -OutputFormat None -PassThru -Confirm:$false 2>&1 3>&1 6>&1
    $legacyResult = @($legacyOutput | Where-Object { $_.PSObject.Properties.Name -contains 'Result' })[-1]
    $legacyResult.Result | Should -Be 'FAIL'
    @($legacyResult.Findings | Where-Object Code -eq 'Firewall-ManagedRuleConflict') | Should -HaveCount 1
    Should -Invoke Set-ItemProperty -Times 0 -Scope It
    Should -Invoke Register-ScheduledTask -Times 0 -Scope It

    $script:EmergencyKillSwitchFixtureState.RuleStore.Clear()
    $script:EmergencyKillSwitchFixtureState.RuleStore['KILLSWITCH-foreign-IN-BLOCK'] = [pscustomobject]@{
      Name = 'KILLSWITCH-foreign-IN-BLOCK'; Enabled = 'True'; Direction = 'Inbound'; Action = 'Block'
    }

    $foreignOutput = & $script:KillSwitchScript -Mode Remediate -OutputFormat None -PassThru -Confirm:$false 2>&1 3>&1 6>&1
    $foreignResult = @($foreignOutput | Where-Object { $_.PSObject.Properties.Name -contains 'Result' })[-1]
    $foreignResult.Summary.Actions.FirewallProfileSet | Should -BeTrue -Because ($foreignResult.Summary.Errors -join '; ')
  }

function Test-KillSwitchRefusesAnOrphanedExactRollbackTaskEvenWhenItsRulesAreAlreadyAbsent {
    $script:EmergencyKillSwitchFixtureState.TaskStore['KILLSWITCH-ROLLBACK'] = [pscustomobject]@{ TaskName = 'KILLSWITCH-ROLLBACK' }

    $output = & $script:KillSwitchScript -Mode Remediate -AutoRollbackMinutes 5 -OutputFormat None -PassThru -Confirm:$false 2>&1 3>&1 6>&1
    $result = @($output | Where-Object { $_.PSObject.Properties.Name -contains 'Result' })[-1]

    $result.Result | Should -Be 'FAIL'
    @($result.Findings | Where-Object Code -eq 'Firewall-ManagedRuleConflict') | Should -HaveCount 1
    $result.Summary.Actions.RegistryWritten | Should -BeFalse
    Should -Invoke Register-ScheduledTask -Times 0 -Scope It
    Should -Invoke Set-NetFirewallProfile -Times 0 -Scope It
  }

function Test-KillSwitchDoesNotIsolateWhenBreakGlassCreationFails {
    Mock -CommandName New-NetFirewallRule -MockWith {
      param($Name, $Direction, $Action)
      if ([string]$Action -eq 'Allow') { throw 'simulated break-glass creation failure' }
      $fixtureState = Get-EmergencyKillSwitchFixtureState
      $fixtureState.RuleStore[$Name] = [pscustomobject]@{ Name = $Name; Enabled = 'True'; Direction = [string]$Direction; Action = [string]$Action }
    }

    $output = & $script:KillSwitchScript -Mode Remediate -BreakGlassRemoteAddress '192.0.2.10' -BreakGlassLocalPort 5986 -OutputFormat None -PassThru -Confirm:$false 2>&1 3>&1 6>&1
    $result = @($output | Where-Object { $_.PSObject.Properties.Name -contains 'Result' })[-1]

    $result.Result | Should -Be 'FAIL'
    $result.Summary.Actions.FirewallProfileSet | Should -BeFalse
    $result.Summary.Actions.BreakGlassApplied | Should -BeFalse
    Should -Invoke Set-NetFirewallProfile -Times 0 -Scope It
    Should -Invoke New-NetFirewallRule -Times 0 -Scope It -ParameterFilter { [string]$Action -eq 'Block' }
  }

function Test-KillSwitchUsesProfileDefaultInboundBlockingWithOnlyTheIntendedBreakGlassSourceAndPortAllowed {
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

function Test-KillSwitchRemovesOnlyTheExactPartialIdentityWhenLaterRuleCreationFails {
    Mock -CommandName New-NetFirewallRule -MockWith {
      param($Name, $Direction, $Action)
      if ([string]$Direction -eq 'Outbound') { throw 'simulated outbound creation failure' }
      $fixtureState = Get-EmergencyKillSwitchFixtureState
      $fixtureState.RuleStore[$Name] = [pscustomobject]@{ Name = $Name; Enabled = 'True'; Direction = [string]$Direction; Action = [string]$Action }
    }

    $output = & $script:KillSwitchScript -Mode Remediate -AutoRollbackMinutes 5 -OutputFormat None -PassThru -Confirm:$false 2>&1 3>&1 6>&1
    $result = @($output | Where-Object { $_.PSObject.Properties.Name -contains 'Result' })[-1]

    $result.Result | Should -Be 'FAIL'
    $result.Summary.Actions.RegistryWritten | Should -BeFalse
    $result.Summary.Actions.FirewallProfileSet | Should -BeFalse
    $script:EmergencyKillSwitchFixtureState.RuleStore.Count | Should -Be 0
    Should -Invoke Remove-NetFirewallRule -Times 1 -Scope It
    Should -Invoke Unregister-ScheduledTask -Times 1 -Scope It
    Should -Invoke Set-NetFirewallProfile -Times 0 -Scope It
    Should -Invoke Set-ItemProperty -Times 0 -Scope It
  }

function Test-KillSwitchDoesNotPersistTheIsolationRegistryFlagWhenFirewallProfileActivationFails {
    Mock -CommandName Set-NetFirewallProfile -MockWith { throw 'simulated profile activation failure' }

    $output = & $script:KillSwitchScript -Mode Remediate -OutputFormat None -PassThru -Confirm:$false 2>&1 3>&1 6>&1
    $result = @($output | Where-Object { $_.PSObject.Properties.Name -contains 'Result' })[-1]

    $result.Result | Should -Be 'FAIL'
    $result.Summary.Actions.FirewallProfileSet | Should -BeFalse
    $result.Summary.Actions.RegistryWritten | Should -BeFalse
    Should -Invoke Set-ItemProperty -Times 0 -Scope It
  }

function Test-KillSwitchRejectsAMissingCanonicalWindowsPowerShellHostBeforeFirewallMutationAndIgnoresPoisonedRootVariables {
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
      $helperSource += Get-Content -LiteralPath (Join-Path (Split-Path $script:KillSwitchScript) 'internal/21-EmergencyKillSwitch.runtime.ps1') -Raw
      $entrySource | Should -Not -Match '\$env:(?:SystemRoot|WINDIR)'
      $entrySource | Should -Not -Match '\$PSHOME'
      $helperSource | Should -Match 'SpecialFolder\]::System'
      $helperSource | Should -Match 'FileAttributes\]::ReparsePoint'
    } finally {
      if ($null -eq $oldSystemRoot) { Remove-Item Env:SystemRoot -ErrorAction SilentlyContinue } else { $env:SystemRoot = $oldSystemRoot }
      if ($null -eq $oldWindir) { Remove-Item Env:WINDIR -ErrorAction SilentlyContinue } else { $env:WINDIR = $oldWindir }
    }
  }

 . Initialize-KillSwitchCommandStubs
  }



  AfterAll { Remove-KillSwitchCommandStubs }

  BeforeEach {
    . Initialize-KillSwitchFirewallFixture
    . Initialize-KillSwitchRollbackFixture
  }

  AfterEach {
    Remove-Variable -Name EmergencyKillSwitchFixtureState -Scope Script -ErrorAction SilentlyContinue
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

  It 'aborts before firewall mutation when rollback scheduling fails' { Test-KillSwitchAbortsBeforeFirewallMutationWhenRollbackSchedulingFails }

  It 'refuses a rerun while exact identities from an earlier activation remain active' { Test-KillSwitchRefusesARerunWhileExactIdentitiesFromAnEarlierActivationRemainActive }

  It 'captures and restores only adapters disabled by an auto-rollback run' { Test-KillSwitchCapturesAndRestoresOnlyAdaptersDisabledByAnAutoRollbackRun }

  It 'aborts before firewall mutation when captured rollback state is malformed' { Test-KillSwitchAbortsBeforeFirewallMutationWhenCapturedRollbackStateIsMalformed }

  It 'ignores foreign similarly named rules while exact legacy identities block before registry and scheduling' { Test-KillSwitchIgnoresForeignSimilarlyNamedRulesWhileExactLegacyIdentitiesBlockBeforeRegistryAndScheduling }

  It 'refuses an orphaned exact rollback task even when its rules are already absent' { Test-KillSwitchRefusesAnOrphanedExactRollbackTaskEvenWhenItsRulesAreAlreadyAbsent }

  It 'does not isolate when break-glass creation fails' { Test-KillSwitchDoesNotIsolateWhenBreakGlassCreationFails }

  It 'uses profile-default inbound blocking with only the intended break-glass source and port allowed' { Test-KillSwitchUsesProfileDefaultInboundBlockingWithOnlyTheIntendedBreakGlassSourceAndPortAllowed }

  It 'removes only the exact partial identity when later rule creation fails' { Test-KillSwitchRemovesOnlyTheExactPartialIdentityWhenLaterRuleCreationFails }

  It 'does not persist the isolation registry flag when firewall profile activation fails' { Test-KillSwitchDoesNotPersistTheIsolationRegistryFlagWhenFirewallProfileActivationFails }

  It 'rejects a missing canonical Windows PowerShell host before firewall mutation and ignores poisoned root variables' { Test-KillSwitchRejectsAMissingCanonicalWindowsPowerShellHostBeforeFirewallMutationAndIgnoresPoisonedRootVariables }
}
