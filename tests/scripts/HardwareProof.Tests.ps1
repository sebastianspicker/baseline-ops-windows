#requires -version 5.1
<#
.SYNOPSIS
  Verifies hardware compliance observation and output behavior.
.DESCRIPTION
  Uses controlled CIM, Secure Boot, BitLocker, event, and proof providers without accessing endpoint hardware.
#>

BeforeAll {
  . (Join-Path $PSScriptRoot 'HardwareProof.Fixture.ps1')
  Import-Module (New-HardwareTestModule) -Force
  function New-HardwareScenario {
    return @{
      Tpm = [pscustomobject]@{SpecVersion = '2.0,1.2'
        ManufacturerID = 123
        PCRBanks = 'sha256'
        IsFirmware = $false
      }
      MethodValue = $true
      Protection = 1
      FailRead = $false
      FailSave = $false
      EventWrite = $true
      Admin = $true
      EventSource = $true
      SecureBoot = $true
      Strict = $false
    }
  }
}
Describe 'Hardware compliance audit phases' {
  It 'reports a missing TPM as a fatal compliance failure' {
    $fixture = New-HardwareScenario
    $fixture.Tpm = $null
    $run = Invoke-HardwareFixture $fixture
    $run.Fatal | Should -BeTrue
    $run.Drifts | Should -Contain 'TPM not present or not accessible'
    $run.Findings[0].Code | Should -Be HW-TPMDrift
  }
  It 'keeps successful proof output and the unresolved PCR observation' {
    $run = Invoke-HardwareFixture (New-HardwareScenario)
    $run.Proof.Results.OverallOk | Should -BeTrue
    $run.Proof.Results.Notes | Should -Contain 'PCR compliance not implemented: PCRBanks (if available) reports hash banks, not PCR indices.'
    $run.Reads.Class | Should -Be @('Win32_Tpm', 'Win32_BIOS')
    $run.Pipeline.Count | Should -Be 1
  }
  It 'retains readiness drift order and BitLocker diagnostics' {
    $fixture = New-HardwareScenario
    $fixture.MethodValue = $false
    $fixture.Protection = 0
    $run = Invoke-HardwareFixture $fixture
    $run.Drifts | Should -Be @('TPM not owned', 'TPM not enabled', 'TPM not activated', 'TPM not ready', 'BitLocker not active on OS volume')
    $run.Proof.Results.Notes[-1] | Should -Match '^BitLocker OS diagnostics:'
  }
  It 'records event failures after the saved proof snapshot' {
    $fixture = New-HardwareScenario
    $fixture.EventWrite = $false
    $run = Invoke-HardwareFixture $fixture
    $run.EventWrite | Should -BeFalse
    $run.Findings[-1].Code | Should -Be HW-EventLogWriteFailed
    $run.Proof.Results.Notes | Should -Not -Contain 'Required event log write failed.'
  }
  It 'classifies proof persistence failure and preserves the error event pipeline value' {
    $fixture = New-HardwareScenario
    $fixture.FailSave = $true
    $run = Invoke-HardwareFixture $fixture
    $run.Errors | Should -Be @('Hardware/TPM-Audit failed: controlled save failure')
    $run.Events[-1].Level | Should -Be Error
    $run.Pipeline | Should -Be @($true)
  }
}
