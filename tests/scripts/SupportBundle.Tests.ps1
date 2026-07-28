#requires -version 5.1
<#
.SYNOPSIS
Pester coverage for security-script contracts.

.DESCRIPTION
Verifies safe, repeatable operator behavior and evidence.
#>

$script:SkipNonSystemWindowsIntegration = $false
if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) {
  try {
    $script:SkipNonSystemWindowsIntegration =
      [Security.Principal.WindowsIdentity]::GetCurrent().User.Value -ne 'S-1-5-18'
  } catch {
    $script:SkipNonSystemWindowsIntegration = $true
  }
}

Describe '09-SupportBundle record failure reporting' -Tag 'SupportBundle' -Skip:$script:SkipNonSystemWindowsIntegration {
  BeforeAll {
    $script:SupportBundleScript = Join-Path $PSScriptRoot '../../scripts/09-SupportBundle.ps1'
    . (Join-Path $PSScriptRoot '../../scripts/internal/09-SupportBundle.helpers.ps1')

    function Invoke-SupportBundleCase {
      param(
        [switch]$KbFailure,
        [switch]$SidecarSummaryFailure,
        [switch]$UseRealArchive,
        [switch]$CompressionFailure,
        [switch]$Triggered,
        [switch]$MissingTrigger,
        [switch]$IdleTrigger,
        [switch]$InvalidTrigger
      )

      $oldOS = $env:OS
      $oldTemp = $env:TEMP
      $oldProgramData = $env:ProgramData
      $oldComputerName = $env:COMPUTERNAME
      $oldUserName = $env:USERNAME
      try {
        $env:OS = 'Windows_NT'
        $env:TEMP = $TestDrive
        $env:ProgramData = $TestDrive
        $env:COMPUTERNAME = 'TEST-HOST'
        $env:USERNAME = 'tester'

        $proofDir = Join-Path (Join-Path $TestDrive 'BaselineOpsForWindows') 'SupportBundles'
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
        Mock -CommandName SB_GetDefaultTrustedOutputRoot -MockWith { $proofDir }
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
        if ($CompressionFailure) { Mock -CommandName Compress-Archive -MockWith { throw 'compression failed' } }
        if ($Triggered -or $MissingTrigger -or $IdleTrigger -or $InvalidTrigger) {
          Mock -CommandName SB_GetRegistryTrigger -MockWith {
            [pscustomobject]@{
              Ok = -not (Get-Variable -Name __SupportBundleMissingTrigger -Scope Global -ValueOnly)
              Error = $(if (Get-Variable -Name __SupportBundleMissingTrigger -Scope Global -ValueOnly) { 'trigger missing' } else { $null })
              Request = $(
                if (Get-Variable -Name __SupportBundleIdleTrigger -Scope Global -ValueOnly) { 0 }
                elseif (Get-Variable -Name __SupportBundleInvalidTrigger -Scope Global -ValueOnly) { 2 }
                else { 1 }
              )
              Days = $null
              IncludeSecurity = $null
              IncludeDefenderSupport = $null
              Reason = $null
            }
          }
        }

        Set-Variable -Name __SupportBundleMissingTrigger -Scope Global -Value ([bool]$MissingTrigger)
        Set-Variable -Name __SupportBundleIdleTrigger -Scope Global -Value ([bool]$IdleTrigger)
        Set-Variable -Name __SupportBundleInvalidTrigger -Scope Global -Value ([bool]$InvalidTrigger)
        if ($Triggered -or $MissingTrigger -or $IdleTrigger -or $InvalidTrigger) {
          $output = & $script:SupportBundleScript -ConfigPath $configPath -OutputFormat None -PassThru -Confirm:$false 2>&1 3>&1 6>&1
        } else {
          $output = & $script:SupportBundleScript -Force -ConfigPath $configPath -OutputFormat None -PassThru -Confirm:$false 2>&1 3>&1 6>&1
        }
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
        if ($null -eq $oldProgramData) {
          Remove-Item -LiteralPath Env:ProgramData -ErrorAction SilentlyContinue
        } else {
          $env:ProgramData = $oldProgramData
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
        Remove-Variable -Scope Global -Name __SupportBundleMissingTrigger -ErrorAction SilentlyContinue
        Remove-Variable -Scope Global -Name __SupportBundleIdleTrigger -ErrorAction SilentlyContinue
        Remove-Variable -Scope Global -Name __SupportBundleInvalidTrigger -ErrorAction SilentlyContinue
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

  It 'keeps a triggered request pending and does not publish a bundle path when compression fails' {
    $run = Invoke-SupportBundleCase -CompressionFailure -Triggered

    $run.ExitCode | Should -Be 1
    $run.Result.Result | Should -Be 'FAIL'
    $run.Result.Summary.ZipCreated | Should -BeFalse
    $run.Result.Summary.ZipPath | Should -BeNullOrEmpty
    @($run.Result.Summary.Records | Where-Object {
        $_.Name -eq 'RegistryReset' -and $_.Note -match 'Request left pending'
      }).Count | Should -Be 1
  }

  It 'returns a terminal V2 failure when the trigger cannot be read' {
    $run = Invoke-SupportBundleCase -MissingTrigger

    $run.ExitCode | Should -Be 1
    $run.Result.Result | Should -Be 'FAIL'
    $run.Result.Summary.WorkDir | Should -BeNullOrEmpty
    @($run.Result.Findings | Where-Object { $_.RecordName -eq 'Trigger' -and $_.Error -match 'trigger missing' }).Count | Should -Be 1
  }

  It 'returns a terminal V2 failure for an invalid trigger value' {
    $run = Invoke-SupportBundleCase -InvalidTrigger

    $run.ExitCode | Should -Be 1
    $run.Result.Result | Should -Be 'FAIL'
    $run.Result.Summary.WorkDir | Should -BeNullOrEmpty
    @($run.Result.Findings | Where-Object { $_.RecordName -eq 'Trigger' -and $_.Error -match 'must be 0 or 1' }).Count | Should -Be 1
  }

  It 'returns V2 OK without collecting when a valid trigger is idle' {
    $run = Invoke-SupportBundleCase -IdleTrigger

    $run.ExitCode | Should -Be 0
    $run.Result.Result | Should -Be 'OK'
    $run.Result.Summary.WorkDir | Should -BeNullOrEmpty
    $run.Result.Summary.ZipCreated | Should -BeFalse
    $run.Result.Summary.TriggerIdle | Should -BeTrue
    $run.Result.Summary.CollectionRequested | Should -BeFalse
    @($run.Result.Findings).Count | Should -Be 0
    @($run.Result.Summary.Records | Where-Object { $_.Name -eq 'Trigger' -and $_.Ok -and $_.Note -match 'Idle' }).Count | Should -Be 1
  }

  It 'returns a structured failure for an explicit invalid config path' {
    $oldOS = $env:OS
    $oldProgramData = $env:ProgramData
    $oldComputerName = $env:COMPUTERNAME
    $oldUserName = $env:USERNAME
    try {
      $env:OS = 'Windows_NT'
      $env:ProgramData = $TestDrive
      $env:COMPUTERNAME = 'TEST-HOST'
      $env:USERNAME = 'tester'
      $configPath = Join-Path $TestDrive 'invalid-support-bundle.json'
      '{"Paths":{},"Unexpected":true}' | Set-Content -LiteralPath $configPath -Encoding UTF8
      $result = & $script:SupportBundleScript -Force -ConfigPath $configPath -OutputFormat None -PassThru -Confirm:$false 6>$null
      $exitCode = $LASTEXITCODE
    } finally {
      $env:OS = $oldOS
      if ($null -eq $oldProgramData) {
        Remove-Item -LiteralPath Env:ProgramData -ErrorAction SilentlyContinue
      } else {
        $env:ProgramData = $oldProgramData
      }
      $env:COMPUTERNAME = $oldComputerName
      $env:USERNAME = $oldUserName
    }

    $exitCode | Should -Be 1
    $result.Result | Should -Be 'FAIL'
    @($result.Summary.Records | Where-Object { $_.Name -eq 'Config' -and -not $_.Ok }).Count | Should -Be 1
    $result.Summary.ZipPath | Should -BeNullOrEmpty
  }
}

Describe '09-SupportBundle bounded event-log fallback' -Tag 'SupportBundle', 'Security' {
  BeforeAll {
    . (Join-Path $PSScriptRoot '../../scripts/internal/09-SupportBundle.helpers.ps1')
    function Ensure-Directory { param([string]$Path) [void][System.IO.Directory]::CreateDirectory($Path); return $Path }
    function Get-WinEvent {
      param([string]$LogName, [string]$FilterXPath, [int]$MaxEvents, [string]$ErrorAction)
    }
  }

  It 'passes MaxEvents to Get-WinEvent before materializing fallback output' {
    Mock -CommandName Get-WinEvent -MockWith {
      [pscustomobject]@{ TimeCreated = Get-Date; Id = 1; LevelDisplayName = 'Information'; ProviderName = 'Pester'; LogName = 'Application'; Message = 'bounded' }
    } -ParameterFilter { $MaxEvents -eq 7 }
    $outBase = Join-Path $TestDrive 'eventlogs/Application'
    $record = SB_ExportEventLogFallback -LogName 'Application' -OutFileBase $outBase -DaysBack 1 -MaxEvents 7
    $record.Ok | Should -BeTrue
    Should -Invoke -CommandName Get-WinEvent -Times 1 -Exactly -ParameterFilter { $MaxEvents -eq 7 }
  }
}
