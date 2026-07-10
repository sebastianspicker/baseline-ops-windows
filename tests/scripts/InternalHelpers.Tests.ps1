#requires -version 5.1
<#
.SYNOPSIS
  Pester tests for scripts/internal/ helper files.

.DESCRIPTION
  Dot-sources each helper file and validates that all exported functions are
  callable and return expected types. Tests focus on pure/stateless helpers
  with no external OS dependencies.
#>

[CmdletBinding()]
param()

# ---------------------------------------------------------------------------
# 04 - OfficeBrowser helpers
# ---------------------------------------------------------------------------
Describe '04 OfficeBrowser helpers' {
  BeforeAll {
    $helperPath = Join-Path $PSScriptRoot '../../scripts/internal/04-OfficeBrowser-Hardening-Proof.helpers.ps1'
    . $helperPath
  }

  Context 'Get-TextOrNull' {
    It 'returns null for null input' {
      Get-TextOrNull -Value $null | Should -BeNullOrEmpty
    }

    It 'returns null for empty string' {
      Get-TextOrNull -Value '' | Should -BeNullOrEmpty
    }

    It 'returns null for whitespace-only string' {
      Get-TextOrNull -Value '   ' | Should -BeNullOrEmpty
    }

    It 'returns the string for non-empty input' {
      Get-TextOrNull -Value 'hello' | Should -Be 'hello'
    }
  }

  Context 'Get-BoolDefault' {
    It 'returns default when value is null' {
      Get-BoolDefault -Value $null -Default $true | Should -Be $true
      Get-BoolDefault -Value $null -Default $false | Should -Be $false
    }

    It 'converts truthy value to true' {
      Get-BoolDefault -Value $true -Default $false | Should -Be $true
    }

    It 'converts falsy value to false' {
      Get-BoolDefault -Value $false -Default $true | Should -Be $false
    }
  }

  Context 'Get-IntDefault' {
    It 'returns default when value is null' {
      Get-IntDefault -Value $null -Default 42 | Should -Be 42
    }

    It 'converts numeric value' {
      Get-IntDefault -Value 7 -Default 0 | Should -Be 7
    }
  }

  Context 'Get-ArrayStrings' {
    It 'returns empty array for null' {
      $result = @(Get-ArrayStrings -Value $null)
      $result.Count | Should -Be 0
    }

    It 'returns string array for array input' {
      $result = Get-ArrayStrings -Value @('a', 'b')
      $result.Count | Should -Be 2
    }
  }

  Context 'Get-ProofItem' {
    It 'returns a PSCustomObject' {
      $item = Get-ProofItem -Product 'Office' -Area 'Macro' -Policy 'BlockVBA' `
        -Target 'HKLM:\...' -Name 'BlockMacros' -Type 'DWord' -Expected 1 -Actual 1 -Compliant $true
      $item | Should -Not -BeNullOrEmpty
      $item.PSObject.TypeNames | Should -Contain 'System.Management.Automation.PSCustomObject'
    }

    It 'carries the Name field' {
      $item = Get-ProofItem -Product 'Edge' -Area 'Security' -Policy 'SmartScreen' `
        -Target 'HKLM:\...' -Name 'SmartScreenEnabled' -Type 'DWord' -Expected 1 -Actual 1 -Compliant $true
      $item.Name | Should -Be 'SmartScreenEnabled'
    }
  }

  Context 'Get-ResultSummary' {
    It 'returns a PSCustomObject with Section and Ok fields' {
      $item = Get-ProofItem -Product 'Edge' -Area 'Security' -Policy 'SmartScreen' `
        -Target 'HKLM:\...' -Name 'SmartScreenEnabled' -Type 'DWord' -Expected 1 -Actual 1 -Compliant $true
      $s = Get-ResultSummary -Section 'Edge' -Items @($item)
      $s | Should -Not -BeNullOrEmpty
      $s.Section | Should -Be 'Edge'
      $s.Ok | Should -Be $true
      $s.NonCompliant | Should -Be 0
    }

    It 'sets Ok false when any item is non-compliant' {
      $item = Get-ProofItem -Product 'Edge' -Area 'Security' -Policy 'SmartScreen' `
        -Target 'HKLM:\...' -Name 'SmartScreenEnabled' -Type 'DWord' -Expected 1 -Actual 0 -Compliant $false
      $s = Get-ResultSummary -Section 'Edge' -Items @($item)
      $s.Ok | Should -Be $false
      $s.NonCompliant | Should -Be 1
    }
  }

  Context 'functions are dot-sourceable and defined' {
    It 'exports all expected function names' {
      $expected = @(
        'Get-TextOrNull', 'Get-BoolDefault', 'Get-IntDefault', 'Get-ArrayStrings',
        'Convert-RegValue', 'Get-ProofItem', 'Get-EdgeBaseKey', 'Has-Prop',
        'Bool-Prop', 'Ensure-ProofItemLike', 'Get-ResultSummary', 'Load-Catalog'
      )
      foreach ($fn in $expected) {
        Get-Command -Name $fn -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty -Because "$fn must be defined after dot-sourcing"
      }
    }
  }
}

# ---------------------------------------------------------------------------
# 09 - SupportBundle helpers
# ---------------------------------------------------------------------------
Describe '09 SupportBundle helpers' {
  BeforeAll {
    Import-Module (Join-Path $PSScriptRoot '../../lib/Common.psm1') -Force
    Import-Module (Join-Path $PSScriptRoot '../../lib/Output.psm1') -Force
    $helperPath = Join-Path $PSScriptRoot '../../scripts/internal/09-SupportBundle.helpers.ps1'
    . $helperPath
  }

  Context 'SB_NewRecord' {
    It 'creates a record with Name, Ok, ArtifactPath properties' {
      $rec = SB_NewRecord -Name 'TestRecord' -Ok $true -ArtifactPath 'C:\test.log' -Note ''
      $rec.Name | Should -Be 'TestRecord'
      $rec.Ok   | Should -Be $true
    }

    It 'creates a failed record' {
      $rec = SB_NewRecord -Name 'FailRecord' -Ok $false -ArtifactPath '' -Note 'something failed'
      $rec.Ok | Should -Be $false
    }
  }

  Context 'SB_NewDefaultConfig' {
    It 'returns a config object with Paths.ProofDir set' {
      $cfg = SB_NewDefaultConfig -ProofDirDefault 'C:\Temp\Proof'
      $cfg | Should -Not -BeNullOrEmpty
      $cfg.Paths.ProofDir | Should -Be 'C:\Temp\Proof'
    }
  }

  Context 'functions are dot-sourceable and defined' {
    It 'exports all expected function names' {
      $expected = @(
        'SB_WriteLog', 'SB_NewRecord',
        'SB_NewSummary', 'SB_AddRecord', 'SB_NewDefaultConfig',
        'SB_TryStep', 'SB_LoadJsonConfig', 'SB_TryGetRegValue'
      )
      foreach ($fn in $expected) {
        Get-Command -Name $fn -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty -Because "$fn must be defined after dot-sourcing"
      }
    }

    It 'does not redefine shared lib helper wrappers' {
      $removed = @('SB_WriteUi', 'SB_IsAdmin', 'SB_EnsureDir', 'SB_SafeFileName')
      foreach ($fn in $removed) {
        Get-Command -Name $fn -ErrorAction SilentlyContinue | Should -BeNullOrEmpty -Because "$fn must come from lib helpers or direct calls now"
      }
    }
  }
}

# ---------------------------------------------------------------------------
# 12 - SuspiciousArtifactGrabber helpers
# ---------------------------------------------------------------------------
Describe '12 SuspiciousArtifactGrabber helpers' {
  BeforeAll {
    $helperPath = Join-Path $PSScriptRoot '../../scripts/internal/12-Suspicious-Artifact-Grabber.helpers.ps1'
    . $helperPath
  }

  Context 'Safe-ToInt' {
    It 'returns default for null' {
      Safe-ToInt -Value $null -Default 5 | Should -Be 5
    }

    It 'converts integer string' {
      Safe-ToInt -Value '42' -Default 0 | Should -Be 42
    }

    It 'returns default for unconvertible value' {
      Safe-ToInt -Value 'not-a-number' -Default 99 | Should -Be 99
    }
  }

  Context 'Safe-ToBool' {
    It 'returns default for null' {
      Safe-ToBool -Value $null -Default $true | Should -Be $true
    }

    It 'converts true value' {
      Safe-ToBool -Value $true -Default $false | Should -Be $true
    }
  }

  Context 'Get-ResultObject' {
    It 'creates object with correct Name' {
      $obj = Get-ResultObject -Name 'TestScan'
      $obj.Name | Should -Be 'TestScan'
    }

    It 'initializes Errors and Notes as empty lists' {
      $obj = Get-ResultObject -Name 'X'
      $obj.Errors.Count | Should -Be 0
      $obj.Notes.Count  | Should -Be 0
    }
  }

  Context 'Add-Error / Add-Note' {
    It 'appends an error message' {
      $obj = Get-ResultObject -Name 'X'
      Add-Error -res $obj -msg 'something broke'
      $obj.Errors.Count | Should -Be 1
      $obj.Errors[0]    | Should -Be 'something broke'
    }

    It 'appends a note message' {
      $obj = Get-ResultObject -Name 'X'
      Add-Note -res $obj -msg 'a note'
      $obj.Notes.Count | Should -Be 1
    }

    It 'ignores null/empty error message' {
      $obj = Get-ResultObject -Name 'X'
      Add-Error -res $obj -msg $null
      Add-Error -res $obj -msg ''
      $obj.Errors.Count | Should -Be 0
    }
  }

  Context 'Get-RunId' {
    It 'returns a non-empty string in yyyyMMdd-HHmmss format' {
      $id = Get-RunId
      $id | Should -Match '^\d{8}-\d{6}$'
    }
  }

  Context 'Get-BaseClone' {
    It 'returns a deep copy of the object' {
      $orig = [pscustomobject]@{ Foo = 'bar'; Nested = @{ X = 1 } }
      $clone = Get-BaseClone -Obj $orig
      $clone.Foo    | Should -Be 'bar'
      $clone.Nested.X | Should -Be 1
    }
  }

  Context 'DefaultCatalog' {
    It 'uses concrete defaults instead of placeholder paths' {
      [string]$DefaultCatalog.OutputBase | Should -Not -Match 'PATH/TO|PLACEHOLDER|TODO'
      [string]$DefaultCatalog.Trigger.Registry | Should -Not -Match 'PATH/TO|PLACEHOLDER|TODO'
      $DefaultCatalog.Trigger.FileFlag | Should -BeNullOrEmpty
    }

    It 'handles a null trigger file without activating collection' {
      $trigger = Read-Trigger -cat $DefaultCatalog

      $trigger.Want | Should -BeFalse
    }
  }

  Context 'functions are dot-sourceable and defined' {
    It 'exports all expected function names' {
      $expected = @(
        'Get-ResultObject', 'Add-Error', 'Add-Note', 'Safe-ToInt', 'Safe-ToBool',
        'Get-RunId', 'Get-BaseClone', 'Merge-Catalog', 'Load-Catalog',
        'Read-Trigger', 'Collect-Processes'
      )
      foreach ($fn in $expected) {
        Get-Command -Name $fn -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty -Because "$fn must be defined after dot-sourcing"
      }
    }
  }
}

Describe '12 SuspiciousArtifactGrabber parent behavior' -Tag 'SuspiciousArtifactGrabber' {
  BeforeAll {
    $script:ArtifactGrabberScript = Join-Path $PSScriptRoot '../../scripts/12-Suspicious-Artifact-Grabber.ps1'
    Import-Module (Join-Path $PSScriptRoot '../../lib/EventLog.psm1') -Force
    $helperPath = Join-Path $PSScriptRoot '../../scripts/internal/12-Suspicious-Artifact-Grabber.helpers.ps1'
    . $helperPath

    function Invoke-ArtifactGrabberParentCase {
      param(
        [switch]$SuspiciousTask,
        [switch]$ProcessError
      )

      $oldOS = $env:OS
      $oldComputerName = $env:COMPUTERNAME
      Set-Variable -Name __ArtifactGrabberProcessError -Scope Global -Value ([bool]$ProcessError)
      try {
        $env:OS = 'Windows_NT'
        $env:COMPUTERNAME = 'TEST-HOST'

        $catalogPath = Join-Path $TestDrive ("grabber-catalog-{0}.json" -f [guid]::NewGuid().ToString('N'))
        $catalog = [ordered]@{
          OutputBase = $TestDrive
          Trigger    = [ordered]@{
            Registry = 'HKLM:\Software\TestArtifactGrabber'
            FileFlag = (Join-Path $TestDrive 'missing.flag')
          }
          Samples    = [ordered]@{
            Enable = $false
          }
          Tasks      = [ordered]@{
            ExportXmlForSuspicious = $false
            SuspiciousRegex        = @('AppData')
            MaxXml                 = 0
          }
        }
        $catalog | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $catalogPath -Encoding UTF8

        function global:Get-ScheduledTask {
          if (Get-Variable -Name __ArtifactGrabberSuspiciousTask -Scope Global -ValueOnly) {
            return @(
              [pscustomobject]@{
                TaskName  = 'SuspiciousTask'
                TaskPath  = '\'
                Principal = [pscustomobject]@{ UserId = 'SYSTEM' }
                Actions   = @(
                  [pscustomobject]@{
                    Execute   = 'C:\Users\alice\AppData\Roaming\bad.exe'
                    Arguments = ''
                  }
                )
              }
            )
          }

          return @()
        }

        function global:Get-ScheduledTaskInfo {
          [pscustomobject]@{ State = 'Ready' }
        }

        function global:Get-CimInstance {
          param(
            [string]$ClassName,
            [string]$Namespace
          )
          [void]$Namespace

          if ((Get-Variable -Name __ArtifactGrabberProcessError -Scope Global -ValueOnly) -and $ClassName -eq 'Win32_Process') {
            throw 'process source unavailable'
          }

          return @()
        }

        function global:Get-NetTCPConnection {
          @()
        }

        function global:Get-NetUDPEndpoint {
          @()
        }

        function global:Get-NetIPConfiguration {
          @()
        }

        function global:Get-NetRoute {
          @()
        }

        function global:Get-DnsClientCache {
          @()
        }

        function global:Compress-Archive {
          param(
            [string[]]$Path,
            [string]$DestinationPath,
            [switch]$Force
          )
          [void]$Path
          [void]$DestinationPath
          [void]$Force
        }

        Set-Variable -Name __ArtifactGrabberSuspiciousTask -Scope Global -Value ([bool]$SuspiciousTask)

        Mock -CommandName Ensure-EventSource -MockWith { }
        Mock -CommandName Write-HealthEvent -MockWith { $true }

        $output = & $script:ArtifactGrabberScript -Force -CatalogPath $catalogPath -OutputFormat None -PassThru -Quiet -Confirm:$false 2>&1 3>&1 6>&1
        $exitCode = $LASTEXITCODE
      } finally {
        if ($null -eq $oldOS) {
          Remove-Item -LiteralPath Env:OS -ErrorAction SilentlyContinue
        } else {
          $env:OS = $oldOS
        }
        if ($null -eq $oldComputerName) {
          Remove-Item -LiteralPath Env:COMPUTERNAME -ErrorAction SilentlyContinue
        } else {
          $env:COMPUTERNAME = $oldComputerName
        }
        Remove-Item -LiteralPath Function:\Get-ScheduledTask -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath Function:\Get-ScheduledTaskInfo -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath Function:\Get-CimInstance -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath Function:\Get-NetTCPConnection -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath Function:\Get-NetUDPEndpoint -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath Function:\Get-NetIPConfiguration -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath Function:\Get-NetRoute -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath Function:\Get-DnsClientCache -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath Function:\Compress-Archive -ErrorAction SilentlyContinue
        Remove-Variable -Scope Global -Name __ArtifactGrabberSuspiciousTask -ErrorAction SilentlyContinue
        Remove-Variable -Scope Global -Name __ArtifactGrabberProcessError -ErrorAction SilentlyContinue
      }

      $result = @($output | Where-Object {
          $null -ne $_ -and
          $_.PSObject.Properties.Name -contains 'Result' -and
          $_.PSObject.Properties.Name -contains 'Summary'
        })[-1]

      [pscustomobject]@{
        ExitCode = $exitCode
        Result   = $result
        Text     = ($output | Out-String)
      }
    }
  }

  It 'Surfaces suspicious task findings in the parent V2 result' {
    $run = Invoke-ArtifactGrabberParentCase -SuspiciousTask

    $run.Result.Result | Should -Be 'WARN'
    $run.Result.Summary.Counts.Tasks.Suspicious | Should -Be 1
    @($run.Result.Findings | Where-Object {
        $_.Code -eq 'Grabber-SuspiciousTask' -and $_.Severity -eq 'Medium'
      }).Count | Should -Be 1
  }

  It 'Reports helper collection errors as a failed parent V2 result' {
    $run = Invoke-ArtifactGrabberParentCase -ProcessError

    $run.Result.Result | Should -Be 'FAIL'
    @($run.Result.Summary.Errors | Where-Object { $_ -match 'process source unavailable' }).Count | Should -Be 1
  }
}
