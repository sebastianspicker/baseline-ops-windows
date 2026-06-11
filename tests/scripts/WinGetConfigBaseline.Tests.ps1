#requires -version 5.1

Describe 'WinGet config baseline runner config input reporting' -Tag 'Config' {
  BeforeAll {
    $script:WinGetRunnerScript = Join-Path $PSScriptRoot '../../scripts/25-WinGet-Config-Baseline-Runner.ps1'

    function Invoke-WinGetConfigBaselineCase {
      [CmdletBinding()]
      param(
        [Parameter(Mandatory)][string]$ConfigPath,
        [Parameter(Mandatory)][string]$SummaryJsonPath
      )

      $oldOS = $env:OS
      $oldComputerName = $env:COMPUTERNAME
      $oldUserName = $env:USERNAME
      try {
        $env:OS = 'Windows_NT'
        $env:COMPUTERNAME = 'TEST-HOST'
        $env:USERNAME = 'test-user'
        Set-Variable -Name WinGetConfigBaselineInvocations -Scope Global -Value ([System.Collections.ArrayList]::new())

        function global:Get-Command {
          [CmdletBinding()]
          param(
            [string]$Name,
            [System.Management.Automation.CommandTypes[]]$CommandType
          )

          if ($Name -eq 'winget.exe') {
            return [pscustomobject]@{
              Name = 'winget.exe'
              CommandType = 'Application'
              Source = 'mock'
            }
          }

          Microsoft.PowerShell.Core\Get-Command @PSBoundParameters
        }

        function global:winget.exe {
          $invocations = Get-Variable -Name WinGetConfigBaselineInvocations -Scope Global -ValueOnly
          [void]$invocations.Add(@($args))
          Set-Variable -Name LASTEXITCODE -Scope Global -Value 0
        }

        $output = & $script:WinGetRunnerScript `
          -ConfigPath $ConfigPath `
          -SummaryJsonPath $SummaryJsonPath `
          -OutputFormat None `
          -PassThru `
          -QuietConsole `
          -NoColor `
          -Confirm:$false 2>&1 3>&1 6>&1
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
        if ($null -eq $oldUserName) {
          Remove-Item -LiteralPath Env:USERNAME -ErrorAction SilentlyContinue
        } else {
          $env:USERNAME = $oldUserName
        }
        Remove-Item -LiteralPath Function:\Get-Command -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath Function:\winget.exe -ErrorAction SilentlyContinue
      }

      $result = @($output | Where-Object {
          $null -ne $_ -and
          $_.PSObject.Properties.Name -contains 'Result' -and
          $_.PSObject.Properties.Name -contains 'Findings'
        })[-1]

      [pscustomobject]@{
        ExitCode = $exitCode
        Result = $result
        Text = ($output | Out-String)
        Invocations = @((Get-Variable -Name WinGetConfigBaselineInvocations -Scope Global -ValueOnly).ToArray())
      }
    }
  }

  AfterEach {
    Remove-Item -LiteralPath Function:\Get-Command -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath Function:\winget.exe -ErrorAction SilentlyContinue
    Remove-Variable -Name WinGetConfigBaselineInvocations -Scope Global -ErrorAction SilentlyContinue
  }

  It 'reports invalid explicit summary JSON as WARN instead of clean OK' {
    $configPath = Join-Path $TestDrive 'baseline.dsc.yaml'
    Set-Content -LiteralPath $configPath -Value 'properties: {}' -Encoding UTF8
    $summaryJsonPath = Join-Path $TestDrive 'bad-summary.json'
    Set-Content -LiteralPath $summaryJsonPath -Value '{ not json' -Encoding UTF8

    $run = Invoke-WinGetConfigBaselineCase -ConfigPath $configPath -SummaryJsonPath $summaryJsonPath

    $run.ExitCode | Should -Be 0
    $run.Result.Result | Should -Be 'WARN'
    @($run.Result.Findings | Where-Object Code -eq 'WINGET-ConfigLoadFailed').Count | Should -Be 1
    @($run.Invocations).Count | Should -Be 2
  }
}
