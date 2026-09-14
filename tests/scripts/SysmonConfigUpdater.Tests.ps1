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

Describe '16-Sysmon-Config-Updater channel failure reporting' -Tag 'Sysmon' -Skip:$script:SkipNonSystemWindowsIntegration {
  BeforeAll {
function Initialize-SysmonChannelMocks {
    Mock -CommandName Test-IsAdmin -MockWith { $true }
    Mock -CommandName Ensure-EventSource -MockWith { $true }
    Mock -CommandName Write-HealthEvent -MockWith {}
    function global:Test-TrustedSysmonExecutable { $true }
    Mock -CommandName Test-TrustedSysmonExecutable -MockWith { $true }
    function global:Get-SysmonStatePath { }
    Mock -CommandName Get-SysmonStatePath -MockWith { $statePath }
    function global:Get-Service {
      param([string]$Name)
      [pscustomobject]@{ Name = $Name }
    }
  Mock -CommandName Invoke-Wevtutil -MockWith {
    param([string[]]$Arguments, [switch]$ThrowOnError, [switch]$CaptureOutput)
    $null = $ThrowOnError, $CaptureOutput

    if ($Arguments[0] -eq 'gl') {
        return [pscustomobject]@{
          Output = @(
            'enabled: false',
            'maximum size: 1048576'
          )
          ExitCode = 0
          Success = $true
        }
      }
      if ($Arguments[0] -eq 'sl' -and $Arguments -contains '/e:true') {
        return $false
      }
      return $true
    }
    Mock -CommandName Invoke-NativeCommand -MockWith {
      [pscustomobject]@{ ExitCode = 0; Success = $true; TimedOut = $false; OutputTruncated = $false; StderrTruncated = $false; Output = '' }
    }

}

function Test-SysmonAddsASpecificFindingWhenWevtutilFailsToEnableTheSysmonChannel {
    $script:OldOS = $env:OS
    $script:OldComputerName = $env:COMPUTERNAME
    $env:OS = 'Windows_NT'
    $env:COMPUTERNAME = 'TEST-HOST'

    $configPath = Join-Path $TestDrive 'sysmon.xml'
    Set-Content -LiteralPath $configPath -Value '<Sysmon schemaversion="4.90"><EventFiltering /></Sysmon>' -Encoding UTF8
    $exePath = Join-Path $TestDrive 'Sysmon64.exe'
    Set-Content -LiteralPath $exePath -Value 'mock sysmon exe' -Encoding UTF8
    $configHash = (Get-FileHash -LiteralPath $configPath -Algorithm SHA256).Hash.ToLowerInvariant()
    $statePath = Join-Path $TestDrive 'state.json'
    @{
      Config = @{ Sha256 = $configHash }
      Runtime = @{ CurrentDumpSha256 = $null }
    } | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $statePath -Encoding UTF8

    . Initialize-SysmonChannelMocks

    $output = & $script:SysmonConfigUpdaterScript `
      -ConfigPath $configPath `
      -SysmonExePath $exePath `
      -EnsureChannel `
      -ChannelSizeMiB 1 `
      -Mode Remediate `
      -OutputFormat None `
      -PassThru `
      -NoConsoleSummary `
      -Quiet `
      -NoColor `
      -Confirm:$false 2>&1 3>&1 6>&1

    $result = @($output | Where-Object {
        $null -ne $_ -and
        $_.PSObject.Properties.Name -contains 'ScriptName' -and
        $_.PSObject.Properties.Name -contains 'Findings'
      })[-1]

    $result.Result | Should -Be 'WARN'
    $LASTEXITCODE | Should -Be 2
    @($result.Findings | Where-Object Code -eq 'Sysmon-ChannelEnableFailed').Count | Should -Be 1
  }


    $script:SysmonConfigUpdaterScript = Join-Path $PSScriptRoot '../../scripts/16-Sysmon-Config-Updater.ps1'

    Import-Module (Join-Path $PSScriptRoot '../../lib/Common.psm1') -Force
    Import-Module (Join-Path $PSScriptRoot '../../lib/EventLog.psm1') -Force
    Import-Module (Join-Path $PSScriptRoot '../../lib/External.psm1') -Force
    Import-Module (Join-Path $PSScriptRoot '../../lib/Results.psm1') -Force
    Import-Module (Join-Path $PSScriptRoot '../../lib/Serialization.psm1') -Force

  }



  AfterEach {
    if ($null -eq $script:OldOS) {
      Remove-Item -LiteralPath Env:OS -ErrorAction SilentlyContinue
    } else {
      $env:OS = $script:OldOS
    }
    if ($null -eq $script:OldComputerName) {
      Remove-Item -LiteralPath Env:COMPUTERNAME -ErrorAction SilentlyContinue
    } else {
      $env:COMPUTERNAME = $script:OldComputerName
    }
    Remove-Variable -Name OldOS -Scope Script -ErrorAction SilentlyContinue
    Remove-Variable -Name OldComputerName -Scope Script -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath Function:\Get-Service -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath Function:\Test-TrustedSysmonExecutable -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath Function:\Get-SysmonStatePath -ErrorAction SilentlyContinue
  }

  It 'adds a specific finding when wevtutil fails to enable the Sysmon channel' { Test-SysmonAddsASpecificFindingWhenWevtutilFailsToEnableTheSysmonChannel }
}
