#requires -version 5.1
<#
.SYNOPSIS
  Builds controlled local Administrators guardrail fixtures.
.DESCRIPTION
  Replaces endpoint providers and mutations with in-memory state for policy and lifecycle assertions.
#>

function New-GuardrailTestModule {
  $helperPath = Join-Path $PSScriptRoot '../../scripts/internal/03-LocalAdmins-Guardrail.helpers.ps1'
  return New-Module -Name LocalAdminsGuardrailFixture -ArgumentList $helperPath -ScriptBlock {
    param($HelperPath)
    . $HelperPath
    Set-Alias -Name Get-Date -Value Get-FixtureDate
    Set-StrictMode -Version Latest
    $script:DefaultAllowList = @()
    $script:EventSource = 'LocalAdmins-Guardrail'
    $script:EventLogName = 'Application'
    function Get-FixtureDate {
      [datetime]'2026-01-01T12:00:00Z'
    }
    function Ensure-EventSource {
      $true
    }
    function Get-AdministratorsGroupName {
      'Administrators'
    }
    function Get-BuiltinAdministratorSid {
      'S-500'
    }
    function Get-Config {
      $null
    }
    function Read-AllowList {
      return $script:Fixture.Allowed
    }
    function Resolve-ToSid {
      param($IdOrName)
      if ($IdOrName -eq 'missing') {
        return $null
      }
      return $IdOrName
    }
    function Get-AdministratorsGroupMembers {
      $script:Reads++
      if ($script:Reads -gt 1 -and $script:Fixture.PostFailure) {
        throw 'post-read failed'
      }
      return $script:Members
    }
    function Remove-LocalGroupMember {
      param($Group, $Member)
      $null = $Group
      $script:Removed.Add($Member)
      $script:Members = @($script:Members | Where-Object SID -ne $Member)
    }
    function Write-HealthEvent {
    }
    function Write-ConsoleSummary {
    }
    function Write-UiLine {
    }
    function Invoke-GuardrailFixture {
      param($Fixture)
      $script:Fixture = $Fixture
      $script:Members = @($Fixture.Members)
      $script:Removed = [Collections.Generic.List[string]]::new()
      $script:Reads = 0
      $runState = New-GuardrailRunState -Inputs @{ Remediate = $Fixture.Remediate; AllowDomainRemediation = $Fixture.Domain; ConfigPath = ''; AllowListPath = ''; ExtraAllow = @(); Quiet = $true }
      $decision = [pscustomobject]@{Allowed = $Fixture.Confirm
        Calls = [Collections.Generic.List[string]]::new()
      }
      $decision | Add-Member ScriptMethod ShouldProcess { param($target, $action)
        $this.Calls.Add("$target|$action")
        return $this.Allowed }
      . Invoke-LocalAdminsGuardrail -RunState $runState -DecisionContext $decision
      [pscustomobject]@{Result = $runState.result
        Reads = $script:Reads
        Removals = $script:Removed.ToArray()
        Prompts = $decision.Calls.ToArray()
      }
    }
    Export-ModuleMember -Function Invoke-GuardrailFixture, Read-AllowListFromJson, ConvertTo-AdminMemberRecord
  }
}
