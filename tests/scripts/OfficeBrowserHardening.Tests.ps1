#requires -version 5.1
<#
.SYNOPSIS
Pester coverage for security-script contracts.

.DESCRIPTION
Verifies safe, repeatable operator behavior and evidence.
#>

Describe 'OfficeBrowser Edge hardening helpers' {
  BeforeAll {
    . (Join-Path $PSScriptRoot '../../scripts/internal/04-OfficeBrowser-Hardening-Proof.helpers.ps1')
    function Ensure-RegistryKey { param([string]$Path) }
    function Get-RegValue { param([string]$Path, [string]$Name) }
  }

  It 'evaluates the simple Edge policy defaults deterministically' {
    $config = [pscustomobject]@{
      SmartScreen = $true; PUA = $true; PasswordManager = $false
      AutofillAddress = $false; AutofillCreditCard = $false; SyncDisabled = $true
      SSLVersionMin = $null; TrackingPrevention = 'Strict'
    }

    $policies = @(Get-EdgePolicyDefinitions -EdgeCfg $config)
    ($policies | Where-Object Policy -eq 'SmartScreenEnabled').Value | Should -Be 1
    ($policies | Where-Object Policy -eq 'SSLVersionMin').Value | Should -Be 'tls1.2'
    ($policies | Where-Object Policy -eq 'TrackingPrevention').Value | Should -Be 3
  }

  It 'reports startup URL drift in audit mode without mutation' {
    $desired = Get-EdgeStartupUrlMap -StartupURLs @('https://baseline.example')
    $current = @{ '1' = 'https://drift.example'; '2' = 'https://unexpected.example' }

    $items = @(Get-EdgeStartupUrlAuditProofItems -Path 'HKLM:\Edge\RestoreOnStartupURLs' -DesiredUrls $desired -CurrentUrls $current)

    $items.Count | Should -Be 2
    @($items | Where-Object Compliant).Count | Should -Be 0
    ($items | Where-Object Name -eq '1').Message | Should -Be 'Drift detected'
    ($items | Where-Object Name -eq '2').Expected | Should -BeNullOrEmpty
  }

  Context 'startup URL remediation' {
    BeforeEach {
      Mock Ensure-RegistryKey {}
      Mock New-ItemProperty {}
      Mock Get-RegValue { 'https://baseline.example' }
    }

    It 'writes a requested startup URL and returns a changed compliant proof item' {
      $item = Set-EdgeStartupUrlProof -Path 'HKLM:\Edge\RestoreOnStartupURLs' -Name '1' -Expected 'https://baseline.example'

      Should -Invoke Ensure-RegistryKey -Times 1 -Exactly
      Should -Invoke New-ItemProperty -Times 1 -Exactly
      $item.Changed | Should -BeTrue
      $item.Compliant | Should -BeTrue
      $item.Message | Should -Be 'Set applied'
    }

    It 'does not mutate when the caller skipped a WhatIf-confirmed write' {
      $item = Set-EdgeStartupUrlProof -Path 'HKLM:\Edge\RestoreOnStartupURLs' -Name '1' -Expected 'https://baseline.example' -Skipped

      Should -Invoke Ensure-RegistryKey -Times 0 -Exactly
      Should -Invoke New-ItemProperty -Times 0 -Exactly
      $item.Changed | Should -BeFalse
      $item.Message | Should -Be 'Set skipped by confirmation/WhatIf'
    }
  }
}
