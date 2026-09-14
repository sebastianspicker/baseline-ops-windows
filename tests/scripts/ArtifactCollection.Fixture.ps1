#requires -version 5.1
<#
.SYNOPSIS
  Verifies controlled artifact collection orchestration.
.DESCRIPTION
  Uses in-memory collection, evidence, archive, and trigger providers to check output ordering and failure behavior without collecting endpoint artifacts.
#>

function New-ArtifactTestModule {
  $helper = Join-Path $PSScriptRoot '../../scripts/internal/12-Suspicious-Artifact-Grabber.helpers.ps1'
  return New-Module -Name ArtifactFixture -ArgumentList $helper -ScriptBlock {
    param($Helper)
    . $Helper
    Set-Alias -Name Import-Csv -Value Import-ArtifactFixtureCsv
    Set-Alias -Name New-ItemProperty -Value New-ArtifactFixtureProperty
    Set-Alias -Name Compress-Archive -Value Compress-ArtifactFixture
    Set-Alias -Name Test-Path -Value Test-ArtifactFixturePath
    Set-Alias -Name Get-Date -Value Get-ArtifactFixtureDate
    Set-StrictMode -Version Latest
    function Get-ArtifactFixtureDate {
      [datetime]'2026-01-01T12:00:00Z'
    }
    function Get-RunId {
      'controlled-run'
    }
    function Ensure-EventSource {
      $true
    }
    function Assert-ArtifactEvidenceOutputBase {
      param($OutputBase)
      $script:Calls.Add('Validate:' + $OutputBase)
      return '/controlled/evidence'
    }
    function Ensure-Directory {
      param($Path)
      $script:Calls.Add('Directory:' + $Path)
      return $true
    }
    function Test-ArtifactFixturePath {
      param($LiteralPath)
      return $LiteralPath -notlike '*.zip'
    }
    function Read-Trigger {
      return [pscustomobject]@{Want = $script:Fixture.Want
        Reason = 'controlled'
        Samples = $script:Fixture.Samples
        MaxFileMB = 20
        MaxTotalMB = 100
      }
    }
    function Write-HealthEvent {
      param($Id, $Message, $Level)
      $script:Calls.Add('Event:' + $Id + ':' + $Level + ':' + $Message)
    }
    function Save-Json {
      param($InputObject, $Path)
      $script:Saved = $InputObject | ConvertTo-Json -Depth 25 -Compress
      $script:Calls.Add('Save:' + $Path)
      if ($script:Fixture.FailSave) {
        throw 'controlled save failure'
      }
    }
    function Compress-ArtifactFixture {
      param($Path, $DestinationPath)
      $script:Calls.Add('Zip:' + $Path + ':' + $DestinationPath)
      if ($script:Fixture.FailZip) {
        throw 'controlled zip failure'
      }
    }
    function New-ArtifactFixtureProperty {
      param($Path, $Name, $Value)
      $script:Calls.Add('Registry:' + $Path + '/' + $Name + '=' + $Value)
    }
    function Collect-Processes {
      return @{Counts = @{Count = 3 }
        Errors = @()
      }
    }
    function Collect-Network {
      return @{Counts = @{Tcp = 1
          Listeners = 1
          Udp = 2
        }
        Errors = @()
        Notes = @('controlled network')
      }
    }
    function Collect-Tasks {
      return @{Counts = @{Total = 2
          Suspicious = $script:Fixture.Suspicious
          XmlExported = 0
        }
        Errors = @()
      }
    }
    function Collect-WmiPersistence {
      return @{Counts = @{Filters = 0
          Bindings = 0
          Cmd = 0
          ActiveScript = 0
          NTEventLog = 0
          LogFile = 0
        }
        Errors = @()
      }
    }
    function Export-Autoruns {
      return @{Counts = @{Items = 1 }
        Errors = @()
      }
    }
    function Import-ArtifactFixtureCsv {
      return @([pscustomobject]@{Path = 'C:\ProgramData\a.exe'
          Signed = 'False'
        }, [pscustomobject]@{Path = 'C:\ProgramData\b.exe'
          Signed = 'True'
        }, [pscustomobject]@{Path = 'C:\Windows\good.exe'
          Signed = 'False'
        })
    }
    function Copy-ToEvidence {
      param($SourcePath, $EvidenceBaseDir, $MaxFileSizeMB, $MaxTotalMB, $RunningTotalBytes)
      $script:Calls.Add('Copy:' + $SourcePath + ':' + $MaxFileSizeMB + ':' + $MaxTotalMB + ':' + $RunningTotalBytes.Value)
      $RunningTotalBytes.Value += 10
      return $true, ($EvidenceBaseDir + '/a.exe')
    }
    function Get-FileSha256 {
      param($Path)
      $script:Calls.Add('Hash:' + $Path)
      return 'controlled-hash'
    }
    function Add-Finding {
      param($FindingList, $Code, $Severity, $Message, $Extra)
      $FindingList.Add([ordered]@{Code = $Code
          Severity = $Severity
          Message = $Message
          Extra = $Extra
        })
    }
    function Print-ConsoleSummary {
      param($Summary, $Errors, $Findings, $CatalogLoadNote, $ScriptVersion)
      $script:Console = [ordered]@{Summary = $Summary
        Errors = $Errors.ToArray()
        Findings = $Findings
        CatalogLoadNote = $CatalogLoadNote
        Version = $ScriptVersion
      }
    }
    function Write-UiStatus {
      param($Label, $State, $Text)
      $script:Calls.Add('Status:' + $Label + ':' + $State + ':' + $Text)
    }
    function Invoke-ArtifactFixture {
      param($Fixture)
      $script:Fixture = $Fixture
      $script:Findings = [Collections.Generic.List[object]]::new()
      $script:Calls = [Collections.Generic.List[string]]::new()
      $script:Saved = $null
      $script:Console = $null
      $ScriptVersion = '2025.12.22-ps51'
      $CatalogPath = ''
      $ConfigPath = ''
      $Force = $false
      $CollectSamples = $false
      $HashAllProcesses = $false
      $Strict = $false
      $ConfirmPreference = 'None'
      $runState = New-ArtifactRunState -Inputs @{ScriptVersion = $ScriptVersion
        CatalogPath = $CatalogPath
        ConfigPath = $ConfigPath
        Force = $Force
        CollectSamples = $CollectSamples
        HashAllProcesses = $HashAllProcesses
        Strict = $Strict
      }
      Invoke-ArtifactCollection -RunState $runState
      $summary = $runState.summary
      $errors = $runState.errors
      $hasFindings = $runState.hasFindings
      $ok = $runState.ok
      [ordered]@{Summary = $summary
        Errors = $errors.ToArray()
        HasFindings = $hasFindings
        Ok = $ok
        Findings = $script:Findings.ToArray()
        Calls = $script:Calls.ToArray()
        Saved = $script:Saved
        Console = $script:Console
      }
    }

    Export-ModuleMember -Function Invoke-ArtifactFixture
  }
}
