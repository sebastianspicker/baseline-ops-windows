#requires -version 5.1

Describe '42-Client-SecurityBaseline-Report-IntuneRef partial result reporting' -Tag 'BaselineReport' {
  BeforeAll {
    $script:BaselineReportScript = Join-Path $PSScriptRoot '../../scripts/42-Client-SecurityBaseline-Report-IntuneRef.ps1'

    function Invoke-BaselineReportCase {
      param(
        [string]$ReferenceJsonPath,
        [switch]$FirewallSourceFails
      )

      $oldOS = $env:OS
      $oldComputerName = $env:COMPUTERNAME
      $createdHklmDrive = $false

      try {
        $env:OS = 'Windows_NT'
        $env:COMPUTERNAME = 'TEST-HOST'
        if (-not (Get-PSDrive -Name HKLM -ErrorAction SilentlyContinue)) {
          New-PSDrive -Name HKLM -PSProvider FileSystem -Root $TestDrive | Out-Null
          $createdHklmDrive = $true
        }

        if ($FirewallSourceFails) {
          function global:Get-NetFirewallProfile {
            [CmdletBinding()]
            param()
            throw 'firewall source failed'
          }
        } else {
          function global:Get-NetFirewallProfile {
            [CmdletBinding()]
            param()
            [pscustomobject]@{
              Name                = 'Domain'
              Enabled             = $true
              LogAllowed          = $false
              LogBlocked          = $true
              LogFileName         = 'pfirewall.log'
              LogMaxSizeKilobytes = 4096
            }
          }
        }

        $params = @{
          OutputFormat     = 'None'
          PassThru         = $true
          NoConsoleSummary = $true
          Quiet            = $true
          Confirm          = $false
        }
        if ($ReferenceJsonPath) { $params.ReferenceJsonPath = $ReferenceJsonPath }

        $output = & $script:BaselineReportScript @params 2>&1 3>&1 6>&1
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
        if ($createdHklmDrive) {
          Remove-PSDrive -Name HKLM -ErrorAction SilentlyContinue
        }
        Remove-Item -LiteralPath Function:\Get-NetFirewallProfile -ErrorAction SilentlyContinue
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
  }

  It 'Reports an invalid requested reference JSON as a partial baseline report' {
    $referencePath = Join-Path $TestDrive 'bad-reference.json'
    Set-Content -LiteralPath $referencePath -Value '{ not json' -Encoding UTF8

    $run = Invoke-BaselineReportCase -ReferenceJsonPath $referencePath

    $run.ExitCode | Should -Be 2
    $run.Result.Result | Should -Be 'WARN'
    $run.Result.Summary.Partial | Should -BeTrue
    $run.Result.Summary.ReferenceLoaded | Should -BeFalse
    $run.Result.Summary.ReferenceLoadError | Should -Not -BeNullOrEmpty
    @($run.Result.Findings | Where-Object { $_.Code -eq 'BASELINE-ReferenceLoadFailed' }).Count |
      Should -Be 1
  }

  It 'Reports firewall profile source failure as a partial baseline report' {
    $run = Invoke-BaselineReportCase -FirewallSourceFails

    $run.ExitCode | Should -Be 2
    $run.Result.Result | Should -Be 'WARN'
    $run.Result.Summary.Partial | Should -BeTrue
    $run.Result.Summary.SourceStatus.FirewallProfile.Succeeded | Should -BeFalse
    $run.Result.Summary.SourceStatus.FirewallProfile.Error | Should -Match 'firewall source failed'
    @($run.Result.Findings | Where-Object { $_.Code -eq 'BASELINE-SourceFailed' }).Count |
      Should -Be 1
  }
}
