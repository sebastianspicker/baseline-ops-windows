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

Describe '21-EmergencyKillSwitch exact post-create verification cleanup' -Tag 'EmergencyKillSwitch' {
  BeforeAll {
function Test-KillSwitchRemovesTheExactJustCreatedRuleWhenVerificationReturnsNoRule {
    $created = New-OrReplaceRule -Name $script:ExactCreatedRuleName -DisplayName 'test' -Direction Inbound -Action Block -Confirm:$false

    $created | Should -BeFalse
    Should -Invoke Remove-NetFirewallRule -Times 1 -Exactly -Scope It -ParameterFilter { $Name -eq 'KILLSWITCH-0123456789abcdef0123456789abcdef-IN-BLOCK' }
    @($script:Findings.ToArray() | Where-Object Code -eq 'Firewall-RuleCreateFailed') | Should -HaveCount 1
    @($script:Findings.ToArray() | Where-Object Code -eq 'Firewall-RuleCleanupFailed') | Should -HaveCount 0
  }

function Test-KillSwitchRemovesTheExactJustCreatedRuleWhenVerificationSettingsMismatch {
    $script:KillSwitchRuleVerificationResult = [pscustomobject]@{ Name = $script:ExactCreatedRuleName; Enabled = 'True'; Direction = 'Outbound'; Action = 'Block' }

    $created = New-OrReplaceRule -Name $script:ExactCreatedRuleName -DisplayName 'test' -Direction Inbound -Action Block -Confirm:$false

    $created | Should -BeFalse
    Should -Invoke Remove-NetFirewallRule -Times 1 -Exactly -Scope It -ParameterFilter { $Name -eq 'KILLSWITCH-0123456789abcdef0123456789abcdef-IN-BLOCK' }
    @($script:Run.Errors | Where-Object { $_ -match 'did not match requested settings' }) | Should -HaveCount 1
  }

function Test-KillSwitchRemovesTheExactJustCreatedRuleWhenTheVerificationQueryFails {
    $script:KillSwitchRuleVerificationMode = 'QueryError'

    $created = New-OrReplaceRule -Name $script:ExactCreatedRuleName -DisplayName 'test' -Direction Inbound -Action Block -Confirm:$false

    $created | Should -BeFalse
    Should -Invoke Remove-NetFirewallRule -Times 1 -Exactly -Scope It -ParameterFilter { $Name -eq 'KILLSWITCH-0123456789abcdef0123456789abcdef-IN-BLOCK' }
    @($script:Run.Errors | Where-Object { $_ -match 'post-create verification query failed: simulated post-create query failure' }) | Should -HaveCount 1
  }

function Test-KillSwitchSurfacesAnExactCleanupFailureWithoutAttemptingABroaderRemoval {
    Mock Remove-NetFirewallRule { throw 'simulated exact cleanup failure' }

    $created = New-OrReplaceRule -Name $script:ExactCreatedRuleName -DisplayName 'test' -Direction Inbound -Action Block -Confirm:$false

    $created | Should -BeFalse
    Should -Invoke Remove-NetFirewallRule -Times 1 -Exactly -Scope It -ParameterFilter { $Name -eq 'KILLSWITCH-0123456789abcdef0123456789abcdef-IN-BLOCK' }
    @($script:Run.Errors | Where-Object { $_ -match "Exact cleanup of just-created firewall rule '.+' failed.*simulated exact cleanup failure" }) | Should -HaveCount 1
    @($script:Findings.ToArray() | Where-Object Code -eq 'Firewall-RuleCleanupFailed') | Should -HaveCount 1
  }

function Test-KillSwitchKeepsTheCompensatingRemovalBoundToTheExactRuleNameInSource {
    $source = Get-Content -LiteralPath $script:KillSwitchHelper -Raw
    $source += Get-Content -LiteralPath (Join-Path (Split-Path $script:KillSwitchHelper) '21-EmergencyKillSwitch.runtime.ps1') -Raw
    $source | Should -Match 'Remove-NetFirewallRule -Name \$Name -ErrorAction Stop'
    $source | Should -Not -Match 'Remove-NetFirewallRule[^\r\n]*(?:RulePrefix|-like|-match)'
  }


    Import-Module (Join-Path $PSScriptRoot '../../lib/Results.psm1') -Force
    $script:KillSwitchHelper = Join-Path $PSScriptRoot '../../scripts/internal/21-EmergencyKillSwitch.helpers.ps1'
    $script:ExactCreatedRuleName = 'KILLSWITCH-0123456789abcdef0123456789abcdef-IN-BLOCK'
    function Add-RunError { param([string]$Message) [void]$script:Run.Errors.Add($Message) }
    function global:Get-NetFirewallRule { param([string]$Name,$ErrorAction) $null = $Name, $ErrorAction }
    function global:New-NetFirewallRule {
      param($Name,$Direction,$Action,[Alias('Profile')]$FirewallProfile,$Enabled,$RemoteAddress,$Protocol,$LocalPort)
      $null = $Name, $Direction, $Action, $FirewallProfile, $Enabled, $RemoteAddress, $Protocol, $LocalPort
    }
    function global:Remove-NetFirewallRule { param([string]$Name,$ErrorAction) $null = $Name, $ErrorAction }
    . $script:KillSwitchHelper

  }



  BeforeEach {
    $script:Run = [pscustomobject]@{ Errors = (New-Object System.Collections.Generic.List[string]); Actions = @{}; Effective = @{}; Outcome = @{} }
    $script:Findings = Get-FindingsList
    $script:KillSwitchRuleVerificationQueryCount = 0
    $script:KillSwitchRuleVerificationMode = 'Empty'
    $script:KillSwitchRuleVerificationResult = $null
    Mock New-NetFirewallRule {
      param($Name,$Direction,$Action)
      [pscustomobject]@{ Name = $Name; Enabled = 'True'; Direction = [string]$Direction; Action = [string]$Action }
    }
    Mock Get-NetFirewallRule {
      $script:KillSwitchRuleVerificationQueryCount++
      if ($script:KillSwitchRuleVerificationQueryCount -eq 1) { return $null }
      if ($script:KillSwitchRuleVerificationMode -eq 'QueryError') { throw 'simulated post-create query failure' }
      return $script:KillSwitchRuleVerificationResult
    }
    Mock Remove-NetFirewallRule { }
  }

  AfterAll {
    foreach ($name in @('Get-NetFirewallRule','New-NetFirewallRule','Remove-NetFirewallRule')) { Remove-Item -LiteralPath "Function:\$name" -ErrorAction SilentlyContinue }
    Remove-Variable KillSwitchRuleVerificationQueryCount -Scope Script -ErrorAction SilentlyContinue
    Remove-Variable KillSwitchRuleVerificationMode -Scope Script -ErrorAction SilentlyContinue
    Remove-Variable KillSwitchRuleVerificationResult -Scope Script -ErrorAction SilentlyContinue
  }

  It 'removes the exact just-created rule when verification returns no rule' { Test-KillSwitchRemovesTheExactJustCreatedRuleWhenVerificationReturnsNoRule }

  It 'removes the exact just-created rule when verification settings mismatch' { Test-KillSwitchRemovesTheExactJustCreatedRuleWhenVerificationSettingsMismatch }

  It 'removes the exact just-created rule when the verification query fails' { Test-KillSwitchRemovesTheExactJustCreatedRuleWhenTheVerificationQueryFails }

  It 'surfaces an exact-cleanup failure without attempting a broader removal' { Test-KillSwitchSurfacesAnExactCleanupFailureWithoutAttemptingABroaderRemoval }

  It 'keeps the compensating removal bound to the exact rule name in source' { Test-KillSwitchKeepsTheCompensatingRemovalBoundToTheExactRuleNameInSource }
}
