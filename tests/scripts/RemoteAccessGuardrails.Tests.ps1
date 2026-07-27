#requires -version 5.1
<#
.SYNOPSIS
Pester coverage for security-script contracts.

.DESCRIPTION
Verifies safe, repeatable operator behavior and evidence.
#>

Describe '14-SecureRemoteAccessGuardrails firewall helpers' -Tag 'RemoteAccessGuardrails' {
  BeforeAll {
    $path = Join-Path $PSScriptRoot '../../scripts/14-SecureRemoteAccessGuardrails.ps1'
    $source = (Get-Content -LiteralPath $path -Raw) -replace "`r`n", "`n"
    $start = $source.IndexOf('function Normalize-Array')
    $end = $source.IndexOf("# ----------------------------`n# Local group enforcement")
    $script:RemoteAccessModule = New-Module -Name RemoteAccessGuardrailsTest -ScriptBlock ([scriptblock]::Create($source.Substring($start, $end - $start)))
    Import-Module $script:RemoteAccessModule -Force
    $script:CreatedRules = 0
    function global:Get-NetFirewallRule { @() }
    function global:New-NetFirewallRule { $script:CreatedRules++; [pscustomobject]@{} }
  }

  AfterAll {
    Remove-Module $script:RemoteAccessModule -Force -ErrorAction SilentlyContinue
    Remove-Item Function:\Get-NetFirewallRule -ErrorAction SilentlyContinue
    Remove-Item Function:\New-NetFirewallRule -ErrorAction SilentlyContinue
  }

  It 'reports missing RDP rules in Audit mode without creating them' {
    $script:CreatedRules = 0
    $result = & $script:RemoteAccessModule {
      Ensure-RdpFirewallRules -Rdp ([pscustomobject]@{ Enable = $true; Profiles = @('Domain'); RemoteAddresses = @('LocalSubnet'); Port = 3389; AllowUDP = $false })
    }

    @($result | Where-Object { $_ -match 'Missing local rule' }).Count | Should -Be 2
    $script:CreatedRules | Should -Be 0
  }

  It 'creates TCP and the configured UDP rule in Remediate mode' {
    $script:CreatedRules = 0
    $result = & $script:RemoteAccessModule {
      Ensure-RdpFirewallRules -Rdp ([pscustomobject]@{ Enable = $true; Profiles = @('Domain'); RemoteAddresses = @('LocalSubnet'); Port = 3389; AllowUDP = $false }) -Remediate
    }

    @($result | Where-Object { $_ -match '^Created ' }).Count | Should -Be 2
    $script:CreatedRules | Should -Be 2
  }

  It 'honors WhatIf when creating missing RDP rules' {
    $script:CreatedRules = 0
    $result = & $script:RemoteAccessModule {
      Ensure-RdpFirewallRules -Rdp ([pscustomobject]@{ Enable = $true; Profiles = @('Domain'); RemoteAddresses = @('LocalSubnet'); Port = 3389; AllowUDP = $false }) -Remediate -WhatIf
    }

    @($result | Where-Object { $_ -match 'Missing local rule' }).Count | Should -Be 2
    $script:CreatedRules | Should -Be 0
  }
}
