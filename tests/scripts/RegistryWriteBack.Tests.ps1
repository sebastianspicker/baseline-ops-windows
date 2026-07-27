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

Describe 'Registry remediation write-back failure reporting' -Tag 'RegistryWriteBack' -Skip:$script:SkipNonSystemWindowsIntegration {
  BeforeAll {
    $script:PsLoggingScript = Join-Path $PSScriptRoot '../../scripts/31-PowerShell-Logging-Baseline.ps1'
    $script:CredentialGuardScript = Join-Path $PSScriptRoot '../../scripts/39-CredentialGuard-VBS-AuditRemediate.ps1'
    $script:LsaProtectionScript = Join-Path $PSScriptRoot '../../scripts/40-AddedLSAProtection-RunAsPPL-AuditRemediate.ps1'

    Import-Module (Join-Path $PSScriptRoot '../../lib/Common.psm1') -Force
    Import-Module (Join-Path $PSScriptRoot '../../lib/Registry.psm1') -Force
    Import-Module (Join-Path $PSScriptRoot '../../lib/Results.psm1') -Force

    Set-Variable -Name RegistryWriteBackRegValues -Scope Global -Value @{}

    Mock -CommandName Require-Admin -MockWith {}
    Mock -CommandName Ensure-RegistryKey -MockWith {}
    Mock -CommandName Join-Path -MockWith {
      param([string]$Path, [string]$ChildPath)
      if ($Path -like 'HKLM:*' -or $Path -like 'HKCU:*') { return "$Path\$ChildPath" }
      $normalizedChildPath = $ChildPath -replace '\\', [System.IO.Path]::DirectorySeparatorChar
      return [System.IO.Path]::GetFullPath([System.IO.Path]::Combine($Path, $normalizedChildPath))
    }
    Mock -CommandName Test-Path -MockWith {
      param([string]$Path, [string]$LiteralPath)
      $targetPath = if ($PSBoundParameters.ContainsKey('LiteralPath')) { $LiteralPath } else { $Path }
      if ($targetPath -like 'HKLM:*' -or $targetPath -like 'HKCU:*') { return $false }
      return ([System.IO.File]::Exists($targetPath) -or [System.IO.Directory]::Exists($targetPath))
    }
    Mock -CommandName Get-RegValue -MockWith {
      param([string]$Path, [string]$Name)
      [void]$Path
      $regValues = Get-Variable -Name RegistryWriteBackRegValues -Scope Global -ValueOnly
      if ($regValues -and $regValues.ContainsKey($Name)) {
        return $regValues[$Name]
      }
      return $null
    }
    Mock -CommandName Set-RegDword -MockWith { $false }
    Mock -CommandName Set-RegString -MockWith { $false }

    function Invoke-RegistryWriteBackScript {
      [CmdletBinding()]
      param(
        [Parameter(Mandatory)][string]$ScriptPath,
        [Parameter(Mandatory)][hashtable]$Parameters
      )

      $oldOS = $env:OS
      $oldComputerName = $env:COMPUTERNAME
      $oldProgramData = $env:ProgramData
      try {
        $env:OS = 'Windows_NT'
        $env:COMPUTERNAME = 'TEST-HOST'
        $env:ProgramData = Join-Path $TestDrive 'ProgramData'
        New-Item -ItemType Directory -Path $env:ProgramData -Force | Out-Null

        $output = & $ScriptPath @Parameters 2>&1 3>&1 6>&1
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
        if ($null -eq $oldProgramData) {
          Remove-Item -LiteralPath Env:ProgramData -ErrorAction SilentlyContinue
        } else {
          $env:ProgramData = $oldProgramData
        }
      }

      $result = @($output | Where-Object {
          $null -ne $_ -and
          $_.PSObject.Properties.Name -contains 'Result' -and
          $_.PSObject.Properties.Name -contains 'Findings'
        })[-1]

      return [pscustomobject]@{
        ExitCode = $exitCode
        Result = $result
        Text = ($output | Out-String)
      }
    }
  }

  AfterAll {
    Remove-Variable -Name RegistryWriteBackRegValues -Scope Global -ErrorAction SilentlyContinue
  }

  It '31-PowerShell-Logging-Baseline reports FAIL when registry writes fail' {
    Set-Variable -Name RegistryWriteBackRegValues -Scope Global -Value @{
      EnableTranscripting = 1
    }
    $transcriptDir = Join-Path (Join-Path $TestDrive 'ProgramData') 'PowerShellTranscripts'
    $run = Invoke-RegistryWriteBackScript -ScriptPath $script:PsLoggingScript -Parameters @{
      Mode = 'Remediate'
      TranscriptOutputDirectory = $transcriptDir
      EnableTranscription = $true
      EnableInvocationHeader = $false
      EnableScriptBlockLogging = $false
      EnableModuleLogging = $false
      OutputFormat = 'None'
      PassThru = $true
      Quiet = $true
      QuietConsole = $true
      NoColor = $true
      Confirm = $false
    }

    $run.Result.Result | Should -Be 'FAIL'
    $run.Result.Summary.RegistryWriteFailed | Should -BeTrue
    @($run.Result.Findings | Where-Object Code -eq 'PSLOG-RegWriteFailed').Count | Should -BeGreaterThan 0
  }

  It '39-CredentialGuard-VBS-AuditRemediate reports FAIL when registry writes fail' {
    Set-Variable -Name RegistryWriteBackRegValues -Scope Global -Value @{
      EnableVirtualizationBasedSecurity = 1
      RequirePlatformSecurityFeatures   = 3
      LsaCfgFlags                       = 1
    }
    $run = Invoke-RegistryWriteBackScript -ScriptPath $script:CredentialGuardScript -Parameters @{
      Mode = 'Remediate'
      OutputFormat = 'None'
      PassThru = $true
      Quiet = $true
      NoColor = $true
      Confirm = $false
    }

    $run.Result.Result | Should -Be 'FAIL'
    $run.Result.Summary.RegistryWriteFailed | Should -BeTrue
    @($run.Result.Findings | Where-Object Code -eq 'CG-RegWriteFailed').Count | Should -BeGreaterThan 0
  }

  It '40-AddedLSAProtection-RunAsPPL-AuditRemediate reports FAIL when registry writes fail' {
    Set-Variable -Name RegistryWriteBackRegValues -Scope Global -Value @{
      RunAsPPL     = 0
      RunAsPPLBoot = 0
    }
    $run = Invoke-RegistryWriteBackScript -ScriptPath $script:LsaProtectionScript -Parameters @{
      Mode = 'Remediate'
      OutputFormat = 'None'
      PassThru = $true
      Quiet = $true
      NoColor = $true
      Confirm = $false
    }

    $run.Result.Result | Should -Be 'FAIL'
    $run.Result.Summary.RegistryWriteFailed | Should -BeTrue
    @($run.Result.Findings | Where-Object Code -eq 'LSA-RegWriteFailed').Count | Should -BeGreaterThan 0
  }

  It '39-CredentialGuard-VBS-AuditRemediate reports explicit config parse failure as WARN' {
    Set-Variable -Name RegistryWriteBackRegValues -Scope Global -Value @{
      EnableVirtualizationBasedSecurity = 1
      RequirePlatformSecurityFeatures   = 3
      LsaCfgFlags                       = 2
    }
    $configPath = Join-Path $TestDrive 'bad-credential-guard-config.json'
    Set-Content -LiteralPath $configPath -Value '{ not json' -Encoding UTF8

    $run = Invoke-RegistryWriteBackScript -ScriptPath $script:CredentialGuardScript -Parameters @{
      Mode = 'Audit'
      ConfigPath = $configPath
      OutputFormat = 'None'
      PassThru = $true
      Quiet = $true
      NoColor = $true
      Confirm = $false
    }

    $run.Result.Result | Should -Be 'WARN'
    @($run.Result.Findings | Where-Object Code -eq 'CG-ConfigLoadFailed').Count | Should -Be 1
  }

  It '40-AddedLSAProtection-RunAsPPL-AuditRemediate reports explicit config parse failure as WARN' {
    Set-Variable -Name RegistryWriteBackRegValues -Scope Global -Value @{
      RunAsPPL = 1
    }
    $configPath = Join-Path $TestDrive 'bad-lsa-config.json'
    Set-Content -LiteralPath $configPath -Value '{ not json' -Encoding UTF8

    $run = Invoke-RegistryWriteBackScript -ScriptPath $script:LsaProtectionScript -Parameters @{
      Mode = 'Audit'
      ConfigPath = $configPath
      OutputFormat = 'None'
      PassThru = $true
      Quiet = $true
      NoColor = $true
      Confirm = $false
    }

    $run.Result.Result | Should -Be 'WARN'
    @($run.Result.Findings | Where-Object Code -eq 'LSA-ConfigLoadFailed').Count | Should -Be 1
  }
}
