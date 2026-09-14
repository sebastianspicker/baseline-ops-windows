#requires -version 5.1
<#
.SYNOPSIS
  Verifies hardware compliance observation and output behavior.
.DESCRIPTION
  Uses controlled CIM, Secure Boot, BitLocker, event, and proof providers without accessing endpoint hardware.
#>

function New-HardwareTestModule {
  $helper = Join-Path $PSScriptRoot '../../scripts/internal/15-HardwareTPM-Audit.helpers.ps1'
  return New-Module -Name HardwareFixture -ArgumentList $helper -ScriptBlock {
    param($Helper)
    . $Helper
    Set-Alias -Name Invoke-CimMethod -Value Invoke-HardwareFixtureMethod
    Set-Alias -Name Get-CimInstance -Value Get-HardwareFixtureCim
    Set-Alias -Name Get-Date -Value Get-HardwareFixtureDate
    Set-StrictMode -Version Latest
    function Get-HardwareFixtureDate {
      [datetime]'2026-01-01T12:00:00Z'
    }
    function Test-IsAdmin {
      return $script:Fixture.Admin
    }
    function Ensure-EventSource {
      return $script:Fixture.EventSource
    }
    function Save-Json {
      param($InputObject, $Path)
      $script:Saved = $InputObject
      $script:SavedPath = $Path
      if ($script:Fixture.FailSave) {
        throw 'controlled save failure'
      }
    }
    function Write-HealthEvent {
      param($Id, $Message, $Level)
      $script:Events.Add([ordered]@{Id = $Id
          Message = $Message
          Level = $Level
        })
      return $script:Fixture.EventWrite
    }
    function Write-UiLine {
      param($Text, $Color)
      $script:Console.Add([ordered]@{Text = $Text
          Color = $Color
        })
    }
    function Write-UiHeader {
      param($Title)
      $script:Console.Add([ordered]@{Title = $Title })
    }
    function Write-ConsoleSummary {
      param($Summary, $Findings, $CustomFields)
      $script:Console.Add([ordered]@{Summary = $Summary
          Findings = $Findings
          CustomFields = $CustomFields
        })
    }
    function Add-Finding {
      param($FindingList, $Code, $Severity, $Message)
      $FindingList.Add([ordered]@{Code = $Code
          Severity = $Severity
          Message = $Message
        })
    }
    function Get-HardwareFixtureCim {
      param($ClassName, $Namespace)
      $script:Reads.Add([ordered]@{Class = $ClassName
          Namespace = $Namespace
        })
      if ($script:Fixture.FailRead) {
        throw 'controlled CIM failure'
      }
      if ($ClassName -eq 'Win32_Tpm') {
        return $script:Fixture.Tpm
      }
      return [pscustomobject]@{SerialNumber = 'controlled'
        SMBIOSBIOSVersion = '1'
        Manufacturer = 'vendor'
        Name = 'bios'
        ReleaseDate = '2025-01-01'
      }
    }
    function Invoke-HardwareFixtureMethod {
      param($MethodName)
      return [pscustomobject]@{$MethodName = $script:Fixture.MethodValue }
    }
    function Confirm-SecureBootUEFI {
      if ($script:Fixture.FailRead) {
        throw 'controlled boot failure'
      }
      return $script:Fixture.SecureBoot
    }
    function Get-BitLockerVolume {
      if ($script:Fixture.FailRead) {
        throw 'controlled BitLocker failure'
      }
      return [pscustomobject]@{VolumeType = 'OperatingSystem'
        ProtectionStatus = $script:Fixture.Protection
        MountPoint = 'C:'
        VolumeStatus = 'FullyEncrypted'
        EncryptionPercentage = 100
        EncryptionMethod = 'XtsAes256'
      }
    }
    function Invoke-HardwareFixture {
      param($Fixture)
      $script:Fixture = $Fixture
      $script:Findings = [Collections.Generic.List[object]]::new()
      $script:Reads = [Collections.Generic.List[object]]::new()
      $script:Events = [Collections.Generic.List[object]]::new()
      $script:Console = [Collections.Generic.List[object]]::new()
      $script:Saved = $null
      $script:SavedPath = $null
      $CatalogPath = ''
      $ConfigPath = ''
      $Strict = $Fixture.Strict
      $state = New-HardwareRunState -Inputs @{CatalogPath = $CatalogPath
        ConfigPath = $ConfigPath
        Strict = $Strict
      }
      $pipeline = @(Invoke-HardwareAudit -RunState $state)
      $drifts = $state.drifts
      $errors = $state.errors
      $fatalComplianceFailure = $state.fatalComplianceFailure
      $eventWriteSucceeded = $state.eventWriteSucceeded
      [ordered]@{Proof = $script:Saved
        Path = $script:SavedPath
        Drifts = $drifts.ToArray()
        Errors = $errors.ToArray()
        Fatal = $fatalComplianceFailure
        EventWrite = $eventWriteSucceeded
        Findings = $script:Findings.ToArray()
        Reads = $script:Reads.ToArray()
        Events = $script:Events.ToArray()
        Console = $script:Console.ToArray()
        Pipeline = $pipeline
      }
    }

    Export-ModuleMember -Function Invoke-HardwareFixture, Test-TpmMinVersion
  }
}
