#requires -version 5.1

Describe '09-SupportBundle record failure reporting' -Tag 'SupportBundle' {
  BeforeAll {
    $script:SupportBundleScript = Join-Path $PSScriptRoot '../../scripts/09-SupportBundle.ps1'
    . (Join-Path $PSScriptRoot '../../scripts/internal/09-SupportBundle.helpers.ps1')

    function Invoke-SupportBundleCase {
      param(
        [switch]$KbFailure,
        [switch]$SidecarSummaryFailure,
        [switch]$UseRealArchive
      )

      $oldOS = $env:OS
      $oldTemp = $env:TEMP
      $oldComputerName = $env:COMPUTERNAME
      $oldUserName = $env:USERNAME
      try {
        $env:OS = 'Windows_NT'
        $env:TEMP = $TestDrive
        $env:COMPUTERNAME = 'TEST-HOST'
        $env:USERNAME = 'tester'

        $proofDir = Join-Path $TestDrive 'proof'
        $configPath = Join-Path $TestDrive 'support-bundle.json'
        $config = [ordered]@{
          Paths = [ordered]@{
            ProofDir = $proofDir
          }
          ProofOutFiles = [ordered]@{
            SysmonState       = $null
            SysmonDriftState  = $null
            SoftwareInventory = $null
            FirewallAudit     = $null
            HardwareAudit     = $null
          }
        }
        $config | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $configPath -Encoding UTF8

        Set-Variable -Name __SupportBundleKbFailure -Scope Global -Value ([bool]$KbFailure)
        Set-Variable -Name __SupportBundleSidecarSummaryFailure -Scope Global -Value ([bool]$SidecarSummaryFailure)

        Mock -CommandName SB_WriteHealthEvent -MockWith { }
        Mock -CommandName SB_TestEventLogExists -MockWith { $false }
        Mock -CommandName SB_ExportKbStatus -MockWith {
          if (-not (Get-Variable -Name __SupportBundleKbFailure -Scope Global -ValueOnly)) {
            return (SB_NewRecord -Name 'KBFeed' -Ok $true -ArtifactPath $null -Note 'no pending KB data' -Error $null)
          }
          SB_NewRecord -Name 'KBFeed' -Ok $false -ArtifactPath $null -Note $null -Error 'kb export failed'
        }
        Mock -CommandName SB_ExportSystemReports -MockWith {
          @(SB_NewRecord -Name 'Report:systeminfo' -Ok $true -ArtifactPath $null -Note $null -Error $null)
        }
        Mock -CommandName SB_ExportDefenderStatus -MockWith {
          @(SB_NewRecord -Name 'Defender:status' -Ok $true -ArtifactPath $null -Note $null -Error $null)
        }
        Mock -CommandName SB_SaveJsonFile -MockWith {
          param(
            [string]$Path,
            $Object
          )
          if ((Get-Variable -Name __SupportBundleSidecarSummaryFailure -Scope Global -ValueOnly) -and $Path -like '*.summary.json') {
            throw 'sidecar summary failed'
          }
          $Object | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath $Path -Encoding UTF8
        }
        if (-not $UseRealArchive) {
          Mock -CommandName Compress-Archive -MockWith { }
        }

        $output = & $script:SupportBundleScript -Force -ConfigPath $configPath -OutputFormat None -PassThru -Confirm:$false 2>&1 3>&1 6>&1
        $exitCode = $LASTEXITCODE
      } finally {
        if ($null -eq $oldOS) {
          Remove-Item -LiteralPath Env:OS -ErrorAction SilentlyContinue
        } else {
          $env:OS = $oldOS
        }
        if ($null -eq $oldTemp) {
          Remove-Item -LiteralPath Env:TEMP -ErrorAction SilentlyContinue
        } else {
          $env:TEMP = $oldTemp
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
        Remove-Variable -Scope Global -Name __SupportBundleKbFailure -ErrorAction SilentlyContinue
        Remove-Variable -Scope Global -Name __SupportBundleSidecarSummaryFailure -ErrorAction SilentlyContinue
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

  It 'Reports failed bundle records as a non-success V2 result' {
    $run = Invoke-SupportBundleCase -KbFailure

    $run.ExitCode | Should -Be 2
    $run.Result.Result | Should -Be 'WARN'
    $run.Result.Summary.RecordsFailed | Should -BeGreaterThan 0
    $run.Result.Summary.RecordsOk | Should -BeGreaterThan 0
    @($run.Result.Summary.Records | Where-Object { -not $_.Ok -and $_.Error -match 'kb export failed' }).Count |
      Should -Be 1
    @($run.Result.Findings | Where-Object {
        $_.Code -eq 'SupportBundle-RecordFailed' -and
        $_.RecordName -eq 'KBFeed' -and
        $_.Error -match 'kb export failed'
      }).Count | Should -Be 1
  }

  It 'Reports sidecar summary JSON write failures without hiding the zip result' {
    $run = Invoke-SupportBundleCase -SidecarSummaryFailure

    $run.ExitCode | Should -Be 2
    $run.Result.Result | Should -Be 'WARN'
    $run.Result.Summary.ZipCreated | Should -BeTrue
    @($run.Result.Summary.Records | Where-Object {
        $_.Name -eq 'Bundle:SidecarSummaryJson' -and
        -not $_.Ok -and
        $_.Error -match 'sidecar summary failed'
      }).Count | Should -Be 1
    @($run.Result.Findings | Where-Object {
        $_.Code -eq 'SupportBundle-RecordFailed' -and
        $_.RecordName -eq 'Bundle:SidecarSummaryJson'
      }).Count | Should -Be 1
  }

  It 'Creates a support bundle archive with expected summary content on the happy path' {
    $run = Invoke-SupportBundleCase -UseRealArchive

    $run.ExitCode | Should -Be 0
    $run.Result.Result | Should -Be 'OK'
    $run.Result.Summary.ZipCreated | Should -BeTrue
    Test-Path -LiteralPath $run.Result.Summary.ZipPath | Should -BeTrue

    $extractPath = Join-Path $TestDrive ("support-extract-{0}" -f [guid]::NewGuid().ToString('N'))
    Expand-Archive -LiteralPath $run.Result.Summary.ZipPath -DestinationPath $extractPath
    $summaryPath = Join-Path $extractPath 'Summary.json'
    Test-Path -LiteralPath $summaryPath | Should -BeTrue

    $summary = Get-Content -LiteralPath $summaryPath -Raw | ConvertFrom-Json
    $summary.Hostname | Should -Be 'TEST-HOST'
    @($summary.Records | Where-Object { $_.Name -eq 'KBFeed' -and $_.Ok }).Count |
      Should -Be 1
  }
}
