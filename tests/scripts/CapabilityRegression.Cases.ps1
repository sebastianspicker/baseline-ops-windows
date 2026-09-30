#requires -version 5.1
<#
.SYNOPSIS
Fixtures and cases for portable capability regression tests.
.DESCRIPTION
Loads capability function definitions without running script bodies, defines
minimal stand-ins for the Windows NetSecurity cmdlets so Pester can mock them,
and drives the remediation and presentation paths of capabilities 07, 18, 24,
and 32 under Set-StrictMode -Version Latest.
#>

function Get-CapabilityRegressionRoot {
  return (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
}

function Get-CapabilityFunctionSource {
  # Top-level function definitions only, so no script body runs. Dot-source the result.
  param([Parameter(Mandatory)][string]$RelativePath)
  $path = Join-Path (Get-CapabilityRegressionRoot) $RelativePath
  $ast = [System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$null, [ref]$null)
  $functions = @($ast.EndBlock.Statements | Where-Object { $_ -is [System.Management.Automation.Language.FunctionDefinitionAst] })
  return [scriptblock]::Create((($functions | ForEach-Object { $_.Extent.Text }) -join [Environment]::NewLine))
}

function Register-FirewallBaselineStub {
  # Parameters are limited to those the exercised 18-Firewall-Baseline paths pass.
  function global:Get-NetFirewallProfile { param([string]$Name) $null = $Name }
  function global:Set-NetFirewallProfile {
    param($Name, $Enabled, $DefaultInboundAction, $DefaultOutboundAction, $NotifyOnListen, $LogBlocked, $LogMaxSizeKilobytes, $LogFileName)
    $null = $Name, $Enabled, $DefaultInboundAction, $DefaultOutboundAction, $NotifyOnListen, $LogBlocked, $LogMaxSizeKilobytes, $LogFileName
  }
  function global:Get-NetFirewallRule { param($PolicyStore, $Direction, $Name, $DisplayName) $null = $PolicyStore, $Direction, $Name, $DisplayName }
  function global:Set-NetFirewallRule { param($PolicyStore, $Name, $Enabled) $null = $PolicyStore, $Name, $Enabled }
  function global:New-NetFirewallRule {
    param($PolicyStore, $Name, $Direction, $Action, $Protocol, $RemotePort, $Enabled)
    $null = $PolicyStore, $Name, $Direction, $Action, $Protocol, $RemotePort, $Enabled
  }
}

function Register-FirewallLoggingStub {
  function global:Get-NetFirewallProfile { param([string]$Name) $null = $Name }
  function global:Set-NetFirewallProfile {
    param($Name, $LogFileName, $LogMaxSizeKilobytes, $LogBlocked, $LogAllowed)
    $null = $Name, $LogFileName, $LogMaxSizeKilobytes, $LogBlocked, $LogAllowed
  }
}

function Remove-FirewallStub {
  foreach ($name in @('Get-NetFirewallProfile', 'Set-NetFirewallProfile', 'Get-NetFirewallRule', 'Set-NetFirewallRule', 'New-NetFirewallRule')) {
    Remove-Item -LiteralPath "Function:\$name" -ErrorAction SilentlyContinue
  }
}

function New-FirewallProfileDefinition {
  # LogAllowed is omitted so the remediation passes only the stubbed logging parameters.
  return [pscustomobject]@{
    Enabled = $true; DefaultInbound = 'Block'; DefaultOutbound = 'Allow'; NotifyOnListen = $false
    LogDropped = $true; LogMaxSizeKB = 16384; LogFile = 'C:\fw\pfirewall.log'
  }
}

function Set-FirewallBaselineMock {
  Mock Get-NetFirewallProfile {
    [pscustomobject]@{
      Name = $Name; Enabled = $true; DefaultInboundAction = 'Block'; DefaultOutboundAction = 'Allow'; NotifyOnListen = $false
      LogBlocked = $false; LogAllowed = $false; LogMaxSizeKilobytes = 4096; LogFileName = 'C:\fw\old.log'
    }
  }
  Mock Set-NetFirewallProfile { }
  Mock Get-NetFirewallRule { [pscustomobject]@{ Name = 'RemoteDesktop-In-TCP'; DisplayName = 'Remote Desktop - User Mode (TCP-In)'; Enabled = 'True' } } -ParameterFilter { $Direction -eq 'Inbound' }
  Mock Get-NetFirewallRule { } -ParameterFilter { $Direction -ne 'Inbound' }
  Mock Set-NetFirewallRule { }
  Mock New-NetFirewallRule { }
}

function Test-FirewallBaselineProfileRemediation {
  Set-StrictMode -Version Latest
  $runState = @{ Remediate = $true; LocalPolicyStore = 'PersistentStore' }

  $items = @(Ensure-Profile -Name Public -Def (New-FirewallProfileDefinition) -Remediate -RunState $runState)

  @($items | ForEach-Object { $_.Status }) | Should -Be @('Drift', 'Changed')
  Should -Invoke Set-NetFirewallProfile -Times 1 -Exactly -Scope It -ParameterFilter {
    $Name -eq 'Public' -and $LogBlocked -eq $true -and $LogMaxSizeKilobytes -eq 16384 -and $LogFileName -eq 'C:\fw\pfirewall.log'
  }
}

function New-FirewallBaselineCatalog {
  $definition = New-FirewallProfileDefinition
  return [pscustomobject]@{
    Profiles = [pscustomobject]@{ Domain = $definition; Private = $definition; Public = $definition }
    DisableInboundByNameLike = @('Remote Desktop*')
    EnsureRules = @([pscustomobject]@{ Name = 'Baseline-Test'; Direction = 'Outbound'; Action = 'Block'; Protocol = 'TCP'; RemotePort = '445'; Enabled = $true })
  }
}

function Test-FirewallBaselineRuleRemediation {
  # Phases are dot-sourced as the entry script does, so they share $cat and $results.
  Set-StrictMode -Version Latest
  $cat = New-FirewallBaselineCatalog
  $RunState = @{ Remediate = $true; LocalPolicyStore = 'PersistentStore'; DefaultCatalog = $cat; start = Get-Date }
  $results = New-Object System.Collections.Generic.List[object]
  $script:Findings = Get-FindingsList

  . Invoke-Capability18MainPhase02 -RunState $RunState
  . Invoke-Capability18MainPhase03 -RunState $RunState

  Should -Invoke Set-NetFirewallRule -Times 1 -Exactly -Scope It -ParameterFilter { $Name -eq 'RemoteDesktop-In-TCP' -and $Enabled -eq 'False' }
  Should -Invoke New-NetFirewallRule -Times 1 -Exactly -Scope It -ParameterFilter { $Name -eq 'Baseline-Test' -and $RemotePort -eq '445' }
  @($results | Where-Object { $_.Status -eq 'Error' }) | Should -HaveCount 0
  @($script:Findings.ToArray() | ForEach-Object { $_.Code } | Sort-Object -Unique) | Should -Be @('FW-EnsureRule-Drift', 'FW-InboundRule-Enabled', 'FW-Profile-Drift')
}

function Test-FirewallBaselineAuditLeavesRulesUntouched {
  Set-StrictMode -Version Latest
  $runState = @{ Remediate = $false; LocalPolicyStore = 'PersistentStore' }

  $inbound = @(Disable-InboundByNameLike -Patterns @('Remote Desktop*') -LocalPolicyStore 'PersistentStore' -RunState $runState)
  $ensure = @(Ensure-FwRule -Spec ([pscustomobject]@{ Name = 'Baseline-Test'; Direction = 'Outbound'; Action = 'Block' }) -LocalPolicyStore 'PersistentStore' -RunState $runState)

  @($inbound | ForEach-Object { $_.Status }) | Should -Be @('Drift')
  @($ensure | ForEach-Object { $_.Status }) | Should -Be @('Drift')
  Should -Invoke Set-NetFirewallRule -Times 0 -Exactly -Scope It
  Should -Invoke New-NetFirewallRule -Times 0 -Exactly -Scope It
}

function Set-FirewallLoggingMock {
  Mock Get-NetFirewallProfile { [pscustomobject]@{ Name = $Name; LogFileName = 'C:\old.log'; LogMaxSizeKilobytes = 4096; LogBlocked = $false; LogAllowed = $false } }
  Mock Set-NetFirewallProfile { }
}

function Test-FirewallLoggingAppliesDriftedSettings {
  Set-StrictMode -Version Latest
  Set-ProfileLoggingIfNeeded -ProfileName Domain -DesiredLogFileName 'C:\new.log' -DesiredMaxKB 16384 -DesiredLogBlocked $true -DesiredLogAllowed $true -RunState @{} -Confirm:$false

  Should -Invoke Set-NetFirewallProfile -Times 4 -Exactly -Scope It
  Should -Invoke Set-NetFirewallProfile -Times 1 -Exactly -Scope It -ParameterFilter { $LogFileName -eq 'C:\new.log' }
}

function Test-FirewallLoggingHonorsWhatIf {
  Set-StrictMode -Version Latest
  Set-ProfileLoggingIfNeeded -ProfileName Domain -DesiredLogFileName 'C:\new.log' -DesiredMaxKB 16384 -DesiredLogBlocked $true -DesiredLogAllowed $true -RunState @{} -WhatIf

  Should -Invoke Set-NetFirewallProfile -Times 0 -Exactly -Scope It
}

function Test-CertAutoEnrollmentSummaryRendersFields {
  Set-StrictMode -Version Latest
  $resultObject = [pscustomobject]@{
    ComputerName = 'HOST1'; Timestamp = '2026-01-01T00:00:00'; ConfigLoaded = $true; ConfigPath = 'C:\cfg.json'
    NoPulse = $false; AutoEnrollmentTriggered = $false; AutoEnrollmentError = 'pulse failed'
    EventQueryMode = 'Operational'; LogNameUsed = 'Microsoft-Windows-CertificateServicesClient-Lifecycle-System/Operational'
    HoursBack = 24; EventsFound = 2; EventQueryError = 'partial'; WarnDays = 30; IncludeExpired = $false
    RequirePrivateKey = $true; ExpiringCertsFound = 1; CertificateReadError = $null; ExportBasePath = 'C:\export'
  }

  $lines = @(Show-ConsoleSummary -ResultObject $resultObject -RunState @{} 6>&1 | ForEach-Object { [string]$_ })

  $lines | Should -Contain ('{0,-22}: {1}' -f 'Status', 'Warning')
  $lines | Should -Contain ('{0,-22}: {1}' -f 'PulseError', 'pulse failed')
  $lines | Should -Contain ('{0,-22}: {1}' -f 'CSV Export', 'Enabled')
}

function Test-ScheduledTaskCatalogFillsOutputDefaults {
  Set-StrictMode -Version Latest
  $fallback = Get-DefaultCatalog -QuarantineDir 'Q:\quarantine' -ProofOutFile 'Q:\proof.json'

  $catalog = Normalize-Catalog -cat ([pscustomobject]@{ Proof = [pscustomobject]@{ OutFile = '' } }) -fallback $fallback
  $missingProof = Normalize-Catalog -cat ([pscustomobject]@{}) -fallback $fallback

  $catalog.QuarantineDir | Should -Be 'Q:\quarantine'
  $catalog.Proof.OutFile | Should -Be 'Q:\proof.json'
  $missingProof.Proof.OutFile | Should -Be 'Q:\proof.json'
}
