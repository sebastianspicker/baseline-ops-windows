#requires -version 5.1
<#
.SYNOPSIS
  Builds controlled LapsHygiene capability fixtures.
.DESCRIPTION
  Replaces endpoint observations and mutations with deterministic in-memory state for behavioral assertions.
#>

function New-LapsHygieneTestModule {
  $helperPath = Join-Path $PSScriptRoot '../../scripts/internal/02-LAPS-Hygiene.helpers.ps1'
  return New-Module -Name LapsHygieneFixture -ArgumentList $helperPath -ScriptBlock {
    param($HelperPath)
    . $HelperPath
    Set-Alias -Name Get-Date -Value Get-FixtureDate
    Set-Alias -Name Start-Sleep -Value Wait-FixtureDelay
    Set-StrictMode -Version Latest
    function Get-FixtureDate {
      param($Date, $Format)
      $dt = [datetime]'2026-01-01T12:00:00Z'
      if ($Date) {
        $dt = [datetime]$Date
      }
      if ($Format) {
        return $dt.ToString($Format)
      }
      return $dt
    }
    function Get-FindingsList {
      return , [Collections.Generic.List[object]]::new()
    }
    function Add-Finding {
      param($FindingList, $Code, $Severity, $Message, $Extra)
      $FindingList.Add(@{Code = $Code
          Severity = $Severity
          Message = $Message
          Extra = $Extra
        })
    }
    function ConvertTo-ArrayList {
      param($InputObject)
      return , @($InputObject)
    }
    function Write-ConsoleSummary {
    }
    function Write-UiLine {
    }
    function Write-UiSeparator {
    }
    function Write-KeyValue {
    }
    function Ensure-EventSource {
      $true
    }
    function Write-HealthEvent {
      param($Id, $Msg, $Level)
      $script:Events.Add(@{Id = $Id
          Message = $Msg
          Level = $Level
        })
    }function Get-ActiveLapsPolicy {
      return $script:Fixture.Policy
    }
    function Get-BuiltInAdminNameRid500 {
      'Administrator'
    }
    function Get-LocalAdminInfo {
      param($Name)
      $null = $Name
      $script:Reads++
      if ($script:Fixture.FailRead) {
        throw 'controlled user read failure'
      }
      if ($script:Reads -gt 1) {
        return $script:Fixture.After
      }
      return $script:Fixture.Before
    }
    function Get-AADJoin {
      $true
    }
    function Get-ADJoin {
      $false
    }
    function Try-RotateWindowsLAPS {
      $script:Rotations++
      return $script:Fixture.Rotate, 'controlled method'
    }
    function Try-CollectLapsDiagnostics {
      $script:Diagnostics++
      return $true, 'controlled diagnostics'
    }
    function Wait-FixtureDelay {
    }
    function Invoke-LapsHygieneFixture {
      param($Fixture)
      $script:Fixture = $Fixture
      $script:Events = [Collections.Generic.List[object]]::new()
      $script:Reads = 0
      $script:Rotations = 0
      $script:Diagnostics = 0
      $config = [pscustomobject]@{EventLog = [pscustomobject]@{Enabled = $true
          Source = 'LAPS-Hygiene'
          LogName = 'Application'
          OkEventId = 3400
          WarnEventId = 3410
        }
        PolicyDefaults = [pscustomobject]@{PasswordAgeDays = 30 }
        Remediation = [pscustomobject]@{CollectDiagnosticsOnFail = $true
          DiagnosticsFolder = 'controlled'
          SleepAfterRotateSec = 3
        }
        Console = [pscustomobject]@{Width = 60
          ShowConfigPath = $false
        }
      }
      $runState = New-LapsRunState -Inputs @{ Remediate = $Fixture.Remediate; MinDaysBeforeRotate = 7; ConfigPath = ''; Config = $config }
      . Invoke-LapsHygiene -RunState $runState
      [pscustomobject]@{Result = $runState.result
        Findings = $script:Findings.ToArray()
        Events = $script:Events.ToArray()
        Reads = $script:Reads
        Rotations = $script:Rotations
        Diagnostics = $script:Diagnostics
      }
    }
    Export-ModuleMember -Function Invoke-LapsHygieneFixture, ConvertTo-BoolSafe, Merge-ConfigObject, Get-ManagedAdminAccountName, Get-PolicyPasswordAgeDays
  }
}
