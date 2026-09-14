#requires -version 5.1
<#
.SYNOPSIS
  Provides controlled Office and browser policy fixtures.
.DESCRIPTION
  Replaces endpoint observations and registry writes with in-memory state to verify proof output and confirmation decisions.
#>

function New-OfficeBrowserTestModule {
  $helper = Join-Path $PSScriptRoot '../../scripts/internal/04-OfficeBrowser-Hardening-Proof.helpers.ps1'
  return New-Module -Name OfficeBrowserFixture -ArgumentList $helper -ScriptBlock {
    param($Helper)
    . $Helper
    Set-Alias -Name Remove-ItemProperty -Value Remove-OfficeFixtureProperty
    Set-Alias -Name Get-ItemProperty -Value Get-OfficeFixtureProperty
    Set-Alias -Name New-ItemProperty -Value New-OfficeFixtureProperty
    Set-Alias -Name Test-Path -Value Test-OfficeFixturePath
    Set-Alias -Name Join-Path -Value Join-OfficeFixturePath
    Set-Alias -Name Get-Date -Value Get-OfficeFixtureDate
    Set-StrictMode -Version Latest
    function Get-OfficeFixtureDate {
      [datetime]'2026-01-01T12:00:00Z'
    }
    function Join-OfficeFixturePath {
      param($Path, $ChildPath)
      return $Path.TrimEnd('/') + '/' + $ChildPath
    }
    function Test-OfficeFixturePath {
      param($LiteralPath)
      return $script:Fixture.Files.ContainsKey($LiteralPath)
    }
    function Get-BoundedUtf8FileContent {
      param($Path)
      return $script:Fixture.Files[$Path]
    }
    function Test-IsAdmin {
      return $script:Fixture.Admin
    }
    function Ensure-EventSource {
      $true
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
      param($Id, $Msg, $Level)
      $script:Events.Add([ordered]@{Id = $Id
          Msg = $Msg
          Level = $Level
        })
    }
    function Write-UiLine {
      param($Message, $Style, $ForegroundColor, [switch]$NoNewline)
      $script:Console.Add([ordered]@{Message = $Message
          Style = $Style
          Color = $ForegroundColor
          NoNewline = [bool]$NoNewline
        })
    }
    function Add-Finding {
      param($FindingList, $Code, $Severity, $Message, $Extra)
      $FindingList.Add([ordered]@{Code = $Code
          Severity = $Severity
          Message = $Message
          Extra = $Extra
        })
    }
    function Get-RegValue {
      param($Path, $Name)
      $key = $Path + '/' + $Name
      if ($script:Registry.ContainsKey($key)) {
        return $script:Registry[$key]
      }
      return $script:Fixture.RegistryDefault
    }
    function Ensure-RegistryKey {
      param($Path)
      $script:Writes.Add('Key:' + $Path)
    }
    function New-OfficeFixtureProperty {
      param($Path, $Name, $PropertyType, $Value, [switch]$Force)
      $script:Writes.Add($Path + '/' + $Name + ':' + $PropertyType + '=' + $Value + ':Force=' + [bool]$Force)
      if ($script:Fixture.FailWrite) {
        throw 'controlled write failure'
      }
      $script:Registry[$Path + '/' + $Name] = $Value
    }
    function Get-OfficeFixtureProperty {
      return [pscustomobject]@{'1' = 'https://old.example'
        Unrelated = 'keep'
      }
    }
    function Remove-OfficeFixtureProperty {
      param($Path, $Name)
      $script:Writes.Add('Remove:' + $Path + '/' + $Name)
    }
    function Invoke-OfficeBrowserFixture {
      param($Fixture)
      $script:Fixture = $Fixture
      $script:Registry = @{}
      $script:Findings = [Collections.Generic.List[object]]::new()
      $script:Writes = [Collections.Generic.List[object]]::new()
      $script:Events = [Collections.Generic.List[object]]::new()
      $script:Console = [Collections.Generic.List[object]]::new()
      $script:Saved = $null
      $script:SavedPath = $null
      $Remediate = $Fixture.Remediate
      $Strict = $Fixture.Strict
      $CatalogPath = $Fixture.CatalogPath
      $ConfigPath = $Fixture.ConfigPath
      $ConfirmPreference = 'None'
      $WhatIfPreference = $Fixture.WhatIf
      $runState = New-OfficeBrowserRunState -Inputs @{CatalogPath = $CatalogPath
        ConfigPath = $ConfigPath
        Remediate = $Remediate
        Strict = $Strict
      }
      Invoke-OfficeBrowserProof -RunState $runState
      $overallOk = $runState.overallOk
      $globalNotes = $runState.globalNotes
      [ordered]@{Proof = $script:Saved
        Path = $script:SavedPath
        Ok = $overallOk
        Notes = @($globalNotes)
        Findings = $script:Findings.ToArray()
        Writes = $script:Writes.ToArray()
        Events = $script:Events.ToArray()
        Console = $script:Console.ToArray()
      }
    }

    Export-ModuleMember -Function Invoke-OfficeBrowserFixture, Get-DefaultOfficeBrowserCatalog, Build-FirefoxPolicies
  }
}
