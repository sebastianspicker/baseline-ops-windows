#requires -version 5.1
<#
.SYNOPSIS
Pester coverage for security-script contracts.

.DESCRIPTION
Verifies safe, repeatable operator behavior and evidence.
#>

Describe '26-Get-WinEvent-FastTriage export failure reporting' -Tag 'WinEvent' {
  BeforeAll {
    $script:WinEventScript = Join-Path $PSScriptRoot '../../scripts/26-Get-WinEvent-FastTriage.ps1'

    function Invoke-WinEventExportFailureCase {
      $oldOS = $env:OS
      $oldComputerName = $env:COMPUTERNAME

      try {
        $env:OS = 'Windows_NT'
        $env:COMPUTERNAME = 'TEST-HOST'

        function global:Get-WinEvent {
          [CmdletBinding()]
          param(
            [hashtable]$FilterHashtable,
            [int]$MaxEvents
          )

      $null = $FilterHashtable, $MaxEvents

      [pscustomobject]@{
            TimeCreated      = Get-Date
            LevelDisplayName = 'Error'
            Id               = 42
            ProviderName     = 'TestProvider'
            LogName          = 'System'
            RecordId         = 1001
            Message          = 'test event'
          }
        }

        function global:Export-Csv {
          [CmdletBinding()]
          param(
            [Parameter(ValueFromPipeline)]
            $InputObject,
            [string]$Path,
            [switch]$NoTypeInformation,
            $Encoding
          )
          process {
        $null = $InputObject, $Path, $NoTypeInformation, $Encoding
        throw 'csv export failed'
          }
        }

        $exportPath = Join-Path $TestDrive 'winevent.csv'
        $output = & $script:WinEventScript -ExportPath $exportPath -OutputFormat None -PassThru -Quiet -Confirm:$false 2>&1 3>&1 6>&1
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
        foreach ($name in @('Get-WinEvent','Export-Csv')) {
          Remove-Item -LiteralPath "Function:\$name" -ErrorAction SilentlyContinue
        }
      }

      $result = @($output | Where-Object {
          $null -ne $_ -and
          $_.PSObject.Properties.Name -contains 'Result' -and
          $_.PSObject.Properties.Name -contains 'Summary'
        })[-1]

      return [pscustomobject]@{
        ExitCode = $exitCode
        Result   = $result
        Text     = ($output | Out-String)
      }
    }

    function Invoke-WinEventHappyPathCase {
      $oldOS = $env:OS
      $oldComputerName = $env:COMPUTERNAME

      try {
        $env:OS = 'Windows_NT'
        $env:COMPUTERNAME = 'TEST-HOST'

        function global:Get-WinEvent {
          [CmdletBinding()]
          param(
            [hashtable]$FilterHashtable,
            [int]$MaxEvents
          )

      $null = $FilterHashtable, $MaxEvents

      [pscustomobject]@{
            TimeCreated      = Get-Date
            LevelDisplayName = 'Error'
            Id               = 42
            ProviderName     = 'TestProvider'
            LogName          = 'System'
            RecordId         = 1001
            Message          = 'happy path event'
          }
        }

        $exportPath = Join-Path $TestDrive 'winevent-happy.csv'
        $output = & $script:WinEventScript -ExportPath $exportPath -OutputFormat None -PassThru -Quiet -Confirm:$false 2>&1 3>&1 6>&1
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
        Remove-Item -LiteralPath 'Function:\Get-WinEvent' -ErrorAction SilentlyContinue
      }

      $result = @($output | Where-Object {
          $null -ne $_ -and
          $_.PSObject.Properties.Name -contains 'Result' -and
          $_.PSObject.Properties.Name -contains 'Summary'
        })[-1]

      return [pscustomobject]@{
        ExitCode   = $exitCode
        Result     = $result
        ExportPath = $exportPath
        Text       = ($output | Out-String)
      }
    }
  }

  It 'Downgrades the V2 result when a requested CSV export fails' {
    $run = Invoke-WinEventExportFailureCase

    $run.ExitCode | Should -Be 2
    $run.Result.Result | Should -Be 'WARN'
    $run.Result.Summary.ExportRequested | Should -BeTrue
    $run.Result.Summary.Exported | Should -BeFalse
    $run.Result.Summary.ExportError | Should -Match 'csv export failed'
    @($run.Result.Findings | Where-Object {
        $_.Code -eq 'EVT-ExportFailed' -and $_.Message -match 'csv export failed'
      }).Count | Should -Be 1
  }

  It 'Exports queried event rows on the happy path' {
    $run = Invoke-WinEventHappyPathCase

    $run.ExitCode | Should -Be 0
    $run.Result.Result | Should -Be 'OK'
    $run.Result.Summary.EventsReturned | Should -Be 1
    $run.Result.Summary.Exported | Should -BeTrue
    Test-Path -LiteralPath $run.ExportPath | Should -BeTrue
    (Get-Content -LiteralPath $run.ExportPath -Raw) | Should -Match 'happy path event'
  }
}
