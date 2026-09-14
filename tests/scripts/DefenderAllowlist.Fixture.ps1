#requires -version 5.1
<#
.SYNOPSIS
  Builds controlled DefenderAllowlist capability fixtures.
.DESCRIPTION
  Replaces endpoint observations and mutations with deterministic in-memory state for behavioral assertions.
#>

function New-DefenderAllowlistTestModule {
  $helperPath = Join-Path $PSScriptRoot '../../scripts/internal/01-ASR-Defender-Allowlist.helpers.ps1'
  return New-Module -Name DefenderAllowlistFixture -ArgumentList $helperPath -ScriptBlock {
    param($HelperPath)
    . $HelperPath
    Set-Alias -Name Get-Date -Value Get-FixtureDate
    Set-Alias -Name Test-Path -Value Test-FixturePath
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
    }function Get-MpPreference {
      return $script:Fixture.Preference
    }
    function Get-Config {
      return $null
    }
    function Test-FixturePath {
      return $script:Fixture.Exists
    }
    function Get-BoundedUtf8FileContent {
      return $script:Fixture.Json
    }
    function Write-AuditJson {
    }
    function Add-MpPreference {
      param($ExclusionPath, $ExclusionProcess, $ExclusionExtension, $AttackSurfaceReductionOnlyExclusions, $ControlledFolderAccessAllowedApplications, $ControlledFolderAccessProtectedFolders)
      $script:Calls.Add(@{Operation = 'Add'
          Values = $PSBoundParameters
        })
      if ($script:Fixture.Fail) {
        throw 'controlled add failure'
      }
    }
    function Remove-MpPreference {
      param($ExclusionPath, $ExclusionProcess, $ExclusionExtension, $AttackSurfaceReductionOnlyExclusions, $ControlledFolderAccessAllowedApplications, $ControlledFolderAccessProtectedFolders)
      $script:Calls.Add(@{Operation = 'Remove'
          Values = $PSBoundParameters
        })
      if ($script:Fixture.Fail) {
        throw 'controlled remove failure'
      }
    }
    function Invoke-DefenderAllowlistFixture {
      param($Fixture)
      $script:Fixture = $Fixture
      $script:Events = [Collections.Generic.List[object]]::new()
      $script:Calls = [Collections.Generic.List[object]]::new()
      $script:Findings = Get-FindingsList
      $runState = New-AllowlistRunState -Inputs @{
        Remediate = $Fixture.Remediate
        ConfigPath = ''
        ExceptionsPath = 'controlled.json'
        AuditPath = ''
        StrictJson = $Fixture.Strict
        BaselineMode = $Fixture.Baseline
      }
      $ConfirmPreference = 'None'
      . Invoke-AllowlistRun -RunState $runState
      [pscustomobject]@{Result = $runState.final
        Findings = $script:Findings.ToArray()
        Events = $script:Events.ToArray()
        Calls = $script:Calls.ToArray()
      }
    }
    Export-ModuleMember -Function Invoke-DefenderAllowlistFixture, To-NormList, Is-RiskyEntry, Diff-Lists
  }
}
