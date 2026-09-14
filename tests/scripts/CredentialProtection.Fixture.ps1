#requires -version 5.1
<#
.SYNOPSIS
  Verifies credential protection policy and confirmation decisions.
.DESCRIPTION
  Uses controlled registry, DeviceGuard, and confirmation providers to preserve security gates and evidence without endpoint changes.
#>

function New-CredentialTestModule {
  $helper = Join-Path $PSScriptRoot '../../scripts/internal/13-LSASS-CG-HVCI-VBS.helpers.ps1'
  return New-Module -Name CredentialFixture -ArgumentList $helper -ScriptBlock {
    param($Helper)
    . $Helper
    Set-Alias -Name Get-CimInstance -Value Get-CredentialFixtureCim
    Set-Alias -Name Test-Path -Value Test-CredentialFixturePath
    Set-Alias -Name Get-Date -Value Get-CredentialFixtureDate
    Set-StrictMode -Version Latest
    function Get-CredentialFixtureDate {
      [datetime]'2026-01-01T12:00:00Z'
    }
    function Test-IsAdmin {
      return $script:Fixture.Admin
    }
    function Ensure-EventSource {
      $true
    }
    function Get-CredentialFixtureCim {
      param($ClassName)
      switch ($ClassName) {
        'Win32_OperatingSystem' {
          return [pscustomobject]@{Caption = 'Windows fixture'
            BuildNumber = '26100'
            Version = '10.0'
          }
        }'Win32_ComputerSystem' {
          return [pscustomobject]@{HypervisorPresent = $script:Fixture.Runtime }
        }'Win32_DeviceGuard' {
          return [pscustomobject]@{SecurityServicesConfigured = @(1, 2)
            SecurityServicesRunning = $(if ($script:Fixture.Runtime) {
                @(1, 2)
              }
              else {
                @()
              })
            VirtualizationBasedSecurityStatus = $(if ($script:Fixture.Runtime) {
                2
              }
              else {
                0
              })
          }
        }
      }
    }
    function Test-CredentialFixturePath {
      return $script:Fixture.Policy
    }
    function Get-RegDword {
      param($Path, $Name)
      $script:Calls.Add([ordered]@{Operation = 'Read'
          Path = $Path
          Name = $Name
        })
      if ($Name -eq 'Locked') {
        return $script:Fixture.Locked
      }
      return $script:Fixture.Registry
    }
    function Set-RegDword {
      param($Path, $Name, $Value)
      $script:Calls.Add([ordered]@{Operation = 'Write'
          Path = $Path
          Name = $Name
          Value = $Value
        })
      return $script:Fixture.WriteSucceeded
    }
    function Write-HealthEvent {
      param($Id, $Msg, $Level, $Source)
      $script:Events.Add([ordered]@{Id = $Id
          Message = $Msg
          Level = $Level
          Source = $Source
        })
    }
    function Write-UiLine {
      param($Message, $ForegroundColor)
      $script:Console.Add([ordered]@{Message = $Message
          Color = $ForegroundColor
        })
    }
    function Add-Finding {
      param($FindingList, $Code, $Severity, $Message)
      $FindingList.Add([ordered]@{Code = $Code
          Severity = $Severity
          Message = $Message
        })
    }
    function Invoke-CredentialFixture {
      param($Fixture)
      $script:Fixture = $Fixture
      $script:Findings = [Collections.Generic.List[object]]::new()
      $script:Calls = [Collections.Generic.List[object]]::new()
      $script:Events = [Collections.Generic.List[object]]::new()
      $script:Console = [Collections.Generic.List[object]]::new()
      $ConfigPath = ''
      $Strict = $Fixture.Strict
      $RequireBlockList = $true
      $Remediate = $Fixture.Remediate
      $EntryBoundParameters = @{Strict = $Strict
        RequireBlockList = $true
      }
      $DecisionContext = [pscustomobject]@{Calls = [Collections.Generic.List[object]]::new()
        Allow = $Fixture.Allow
      }
      $DecisionContext | Add-Member -MemberType ScriptMethod -Name ShouldProcess -Value { param($Target, $Action)
        $this.Calls.Add([ordered]@{Target = $Target
            Action = $Action
          })
        return $this.Allow }
      $state = New-CredentialRunState -Inputs @{ConfigPath = $ConfigPath
        Strict = $Strict
        RequireBlockList = $RequireBlockList
        Remediate = $Remediate
        BoundParameters = $EntryBoundParameters
        DecisionContext = $DecisionContext
      }
      Invoke-CredentialAudit -RunState $state
      $result = $state.result
      [ordered]@{Result = $result
        Findings = $script:Findings.ToArray()
        Calls = $script:Calls.ToArray()
        Decisions = $DecisionContext.Calls.ToArray()
        Events = $script:Events.ToArray()
        Console = $script:Console.ToArray()
      }
    }

    Export-ModuleMember -Function Invoke-CredentialFixture
  }
}
