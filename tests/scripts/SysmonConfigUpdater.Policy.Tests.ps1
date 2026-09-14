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

Describe '16-Sysmon-Config-Updater policy gates' -Tag 'Sysmon' -Skip:$script:SkipNonSystemWindowsIntegration {
  BeforeAll {
    foreach ($module in @('Common','EventLog','External','Results','Serialization')) {
      Import-Module (Join-Path $PSScriptRoot "../../lib/$module.psm1") -Force
    }

function Initialize-SysmonPolicyFixture {

    $script:OldOS = $env:OS
    $script:OldComputerName = $env:COMPUTERNAME
    $env:OS = 'Windows_NT'
    $env:COMPUTERNAME = 'TEST-HOST'
    $script:SysmonConfigUpdaterScript = Join-Path $PSScriptRoot '../../scripts/16-Sysmon-Config-Updater.ps1'
    $script:ConfigPath = Join-Path $TestDrive 'sysmon.xml'
    $script:SourceDir = Join-Path $TestDrive 'payload'
    $script:ExePath = Join-Path $TestDrive 'Sysmon64.exe'
    New-Item -ItemType Directory -Path $script:SourceDir -Force | Out-Null
    Set-Content -LiteralPath $script:ConfigPath -Value '<Sysmon schemaversion="4.90"><EventFiltering /></Sysmon>' -Encoding UTF8
    Copy-Item -LiteralPath $script:ConfigPath -Destination (Join-Path $script:SourceDir 'sysmon.xml')
    Set-Content -LiteralPath $script:ExePath -Value 'mock sysmon exe' -Encoding UTF8

    Mock -CommandName Test-IsAdmin -MockWith { $true }
    Mock -CommandName Ensure-EventSource -MockWith { $true }
    Mock -CommandName Write-HealthEvent -MockWith {}
    function global:Test-TrustedSysmonExecutable { $true }
    Mock -CommandName Test-TrustedSysmonExecutable -MockWith { $true }
    function global:Get-SysmonStatePath { }
    Mock -CommandName Get-SysmonStatePath -MockWith {
      Join-Path $TestDrive 'config-updater-state.json'
    }
    function global:Get-Service {
      param([string]$Name)
      [pscustomobject]@{ Name = $Name }
    }
    Mock -CommandName Invoke-NativeCommand -MockWith {
      [pscustomobject]@{ ExitCode = 0; Success = $true; TimedOut = $false; OutputTruncated = $false; StderrTruncated = $false; Output = '' }
    }
}

function Test-SysmonDoesNotLaunchSysmonWhenTheSelectedHashIsNotAllowlisted {
    $manifestPath = Join-Path $TestDrive 'manifest.json'
    @{ AllowedHashes = @(('0' * 64), ('1' * 64)) } | ConvertTo-Json | Set-Content -LiteralPath $manifestPath -Encoding UTF8

    $result = & $script:SysmonConfigUpdaterScript -ConfigPath $script:ConfigPath -ManifestPath $manifestPath -SysmonExePath $script:ExePath -Mode Remediate -OutputFormat None -PassThru -NoConsoleSummary -Quiet -NoColor -Confirm:$false

    $LASTEXITCODE | Should -Be 1
    $result.Result | Should -Be 'FAIL'
    $result.Summary.PolicyBlocked | Should -BeTrue
    Assert-MockCalled -CommandName Invoke-NativeCommand -Times 0 -Exactly
  }

function Test-SysmonDoesNotLaunchSysmonWhenItsEngineIsBelowTheRequiredMinimum {
    $manifestPath = Join-Path $TestDrive 'manifest.json'
    @{ MinEngine = '16.0' } | ConvertTo-Json | Set-Content -LiteralPath $manifestPath -Encoding UTF8

    & $script:SysmonConfigUpdaterScript -ConfigPath $script:ConfigPath -ManifestPath $manifestPath -SysmonExePath $script:ExePath -Mode Remediate -OutputFormat None -NoConsoleSummary -Quiet -NoColor -Confirm:$false

    Assert-MockCalled -CommandName Invoke-NativeCommand -Times 0 -Exactly
  }

function Test-SysmonDoesNotLaunchSysmonWhenManifestConfigFileEscapesSourceDir {
    $manifestPath = Join-Path $TestDrive 'manifest.json'
    @{ Config = @{ File = '../sysmon.xml' } } | ConvertTo-Json -Depth 3 | Set-Content -LiteralPath $manifestPath -Encoding UTF8

    & $script:SysmonConfigUpdaterScript -SourceDir $script:SourceDir -ManifestPath $manifestPath -SysmonExePath $script:ExePath -Mode Remediate -OutputFormat None -NoConsoleSummary -Quiet -NoColor -Confirm:$false

    Assert-MockCalled -CommandName Invoke-NativeCommand -Times 0 -Exactly
  }

function Test-SysmonDoesNotLaunchSysmonForAnExplicitlySuppliedInvalidManifest {
    $manifestPath = Join-Path $TestDrive 'manifest.json'
    Set-Content -LiteralPath $manifestPath -Value '{not json' -Encoding UTF8

    & $script:SysmonConfigUpdaterScript -ConfigPath $script:ConfigPath -ManifestPath $manifestPath -SysmonExePath $script:ExePath -Mode Remediate -OutputFormat None -NoConsoleSummary -Quiet -NoColor -Confirm:$false

    Assert-MockCalled -CommandName Invoke-NativeCommand -Times 0 -Exactly
  }

function Test-SysmonRejectsAnOversizedExplicitManifestBeforeParsingOrLaunchingSysmon {
    $manifestPath = Join-Path $TestDrive 'oversized-manifest.json'
    [System.IO.File]::WriteAllBytes($manifestPath, (New-Object byte[] 1048577))

    $result = & $script:SysmonConfigUpdaterScript -ConfigPath $script:ConfigPath -ManifestPath $manifestPath -SysmonExePath $script:ExePath -Mode Remediate -OutputFormat None -PassThru -NoConsoleSummary -Quiet -NoColor -Confirm:$false

    $LASTEXITCODE | Should -Be 1
    $result.Result | Should -Be 'FAIL'
    $result.Summary.PolicyBlocked | Should -BeTrue
    Assert-MockCalled -CommandName Invoke-NativeCommand -Times 0 -Exactly
  }

function Test-SysmonDoesNotFallBackWhenManifestConfigFileIsMissingBeneathSourceDir {
    $manifestPath = Join-Path $TestDrive 'manifest.json'
    @{ Config = @{ File = 'missing.xml' } } | ConvertTo-Json -Depth 3 | Set-Content -LiteralPath $manifestPath -Encoding UTF8

    $result = & $script:SysmonConfigUpdaterScript -SourceDir $script:SourceDir -ManifestPath $manifestPath -SysmonExePath $script:ExePath -Mode Remediate -OutputFormat None -PassThru -NoConsoleSummary -Quiet -NoColor -Confirm:$false

    $LASTEXITCODE | Should -Be 1
    $result.Result | Should -Be 'FAIL'
    $result.Summary.PolicyBlocked | Should -BeTrue
    Assert-MockCalled -CommandName Invoke-NativeCommand -Times 0 -Exactly
  }

function Test-SysmonRejectsAScalarManifestRootAsInvalidPolicyInput {
    $manifestPath = Join-Path $TestDrive 'manifest.json'
    Set-Content -LiteralPath $manifestPath -Value '42' -Encoding UTF8

    $result = & $script:SysmonConfigUpdaterScript -ConfigPath $script:ConfigPath -ManifestPath $manifestPath -SysmonExePath $script:ExePath -Mode Remediate -OutputFormat None -PassThru -NoConsoleSummary -Quiet -NoColor -Confirm:$false

    $LASTEXITCODE | Should -Be 1
    $result.Result | Should -Be 'FAIL'
    $result.Summary.PolicyBlocked | Should -BeTrue
    Assert-MockCalled -CommandName Invoke-NativeCommand -Times 0 -Exactly
  }

function Test-SysmonRejectsAnInvalidExplicitMinEngineValueInsteadOfDisablingTheRequirement {
    $result = & $script:SysmonConfigUpdaterScript -ConfigPath $script:ConfigPath -MinEngine 'not-a-version' -SysmonExePath $script:ExePath -Mode Remediate -OutputFormat None -PassThru -NoConsoleSummary -Quiet -NoColor -Confirm:$false

    $LASTEXITCODE | Should -Be 1
    $result.Result | Should -Be 'FAIL'
    $result.Summary.PolicyBlocked | Should -BeTrue
    Assert-MockCalled -CommandName Invoke-NativeCommand -Times 0 -Exactly
  }

function Test-SysmonRejectsPresentButEmptyAllowedHashesUnderTheClosedManifestSchema {
    $manifestPath = Join-Path $TestDrive 'manifest.json'
    @{ AllowedHashes = @() } | ConvertTo-Json | Set-Content -LiteralPath $manifestPath -Encoding UTF8

    $result = & $script:SysmonConfigUpdaterScript -ConfigPath $script:ConfigPath -ManifestPath $manifestPath -SysmonExePath $script:ExePath -Mode Remediate -OutputFormat None -PassThru -NoConsoleSummary -Quiet -NoColor -Confirm:$false

    $result.Result | Should -Be 'FAIL'
    $result.Summary.PolicyBlocked | Should -BeTrue
    Assert-MockCalled -CommandName Invoke-NativeCommand -Times 0 -Exactly
  }

function Test-SysmonRejectsUnknownManifestPropertiesCaseInsensitively {
    $manifestPath = Join-Path $TestDrive 'manifest.json'
    @{ allowedhashes = @('0' * 64); Unexpected = 'value' } | ConvertTo-Json | Set-Content -LiteralPath $manifestPath -Encoding UTF8

    $result = & $script:SysmonConfigUpdaterScript -ConfigPath $script:ConfigPath -ManifestPath $manifestPath -SysmonExePath $script:ExePath -Mode Remediate -OutputFormat None -PassThru -NoConsoleSummary -Quiet -NoColor -Confirm:$false

    $result.Result | Should -Be 'FAIL'
    $result.Summary.PolicyBlocked | Should -BeTrue
    Assert-MockCalled -CommandName Invoke-NativeCommand -Times 0 -Exactly
  }

function Test-SysmonRejectsDuplicateManifestPropertiesThatDifferOnlyByCase {
    $manifestPath = Join-Path $TestDrive 'manifest.json'
    Set-Content -LiteralPath $manifestPath -Value '{"MinEngine":"15.0","minengine":"16.0"}' -Encoding UTF8

    $result = & $script:SysmonConfigUpdaterScript -ConfigPath $script:ConfigPath -ManifestPath $manifestPath -SysmonExePath $script:ExePath -Mode Remediate -OutputFormat None -PassThru -NoConsoleSummary -Quiet -NoColor -Confirm:$false

    $result.Result | Should -Be 'FAIL'
    $result.Summary.PolicyBlocked | Should -BeTrue
    Assert-MockCalled -CommandName Invoke-NativeCommand -Times 0 -Exactly
  }

function Test-SysmonRejectsDTDBearingConfigurationXMLWithoutLaunchingSysmon {
    Set-Content -LiteralPath $script:ConfigPath -Value '<!DOCTYPE Sysmon [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><Sysmon schemaversion="4.90"><EventFiltering>&xxe;</EventFiltering></Sysmon>' -Encoding UTF8

    $result = & $script:SysmonConfigUpdaterScript -ConfigPath $script:ConfigPath -SysmonExePath $script:ExePath -Mode Remediate -OutputFormat None -PassThru -NoConsoleSummary -Quiet -NoColor -Confirm:$false

    $result.Result | Should -Be 'FAIL'
    @($result.Findings | Where-Object Message -Match 'DTD').Count | Should -BeGreaterThan 0
    Assert-MockCalled -CommandName Invoke-NativeCommand -Times 0 -Exactly
  }

function Test-SysmonDoesNotExecuteAnExplicitlySuppliedSysmonPathDuringAudit {
    & $script:SysmonConfigUpdaterScript -ConfigPath $script:ConfigPath -SysmonExePath $script:ExePath -Mode Audit -OutputFormat None -NoConsoleSummary -Quiet -NoColor -Confirm:$false

    Assert-MockCalled -CommandName Invoke-NativeCommand -Times 0 -Exactly
  }

function Test-SysmonGivesAnExplicitTrustedExecutablePrecedenceOverServiceDiscovery {
    $serviceExe = Join-Path $TestDrive 'service/Sysmon64.exe'
    New-Item -ItemType Directory -Path (Split-Path -Parent $serviceExe) -Force | Out-Null
    Set-Content -LiteralPath $serviceExe -Value 'service binary' -Encoding UTF8
    Mock -CommandName Get-ItemProperty -MockWith { [pscustomobject]@{ ImagePath = '"' + $serviceExe + '"' } }

    $result = & $script:SysmonConfigUpdaterScript -ConfigPath $script:ConfigPath -SysmonExePath $script:ExePath -Mode Audit -OutputFormat None -PassThru -NoConsoleSummary -Quiet -NoColor -Confirm:$false

    $result.Summary.SysmonExe | Should -Be (Get-Item -LiteralPath $script:ExePath).FullName
    Should -Invoke Get-ItemProperty -Times 0 -Scope It
  }

function Test-SysmonDoesNotLaunchAnExplicitlySuppliedUntrustedExecutableDuringAudit {
    $untrustedExe = Join-Path $TestDrive 'not-sysmon.exe'
    Set-Content -LiteralPath $untrustedExe -Value 'untrusted executable' -Encoding UTF8
    Mock -CommandName Test-TrustedSysmonExecutable -MockWith { $false }

    $result = & $script:SysmonConfigUpdaterScript -ConfigPath $script:ConfigPath -SysmonExePath $untrustedExe -Mode Audit -OutputFormat None -PassThru -NoConsoleSummary -Quiet -NoColor -Confirm:$false

    $result.Result | Should -Be 'FAIL'
    $result.Summary.PolicyBlocked | Should -BeTrue
    Assert-MockCalled -CommandName Invoke-NativeCommand -Times 0 -Exactly
  }

function Test-SysmonLaunchesSysmonToApplyAConfigOnlyWhenManifestPolicyMatches {
    $manifestPath = Join-Path $TestDrive 'manifest.json'
    $configHash = (Get-FileHash -LiteralPath $script:ConfigPath -Algorithm SHA256).Hash
    @{ AllowedHashes = @($configHash, $configHash) } | ConvertTo-Json -Depth 3 | Set-Content -LiteralPath $manifestPath -Encoding UTF8

    & $script:SysmonConfigUpdaterScript -ConfigPath $script:ConfigPath -ManifestPath $manifestPath -SysmonExePath $script:ExePath -Mode Remediate -OutputFormat None -NoConsoleSummary -Quiet -NoColor -Confirm:$false

    Assert-MockCalled -CommandName Invoke-NativeCommand -Times 1
  }

function Test-SysmonTreatsABoundedNativeCommandTimeoutAsAFailedApply {
    Mock -CommandName Invoke-NativeCommand -MockWith {
      [pscustomobject]@{ ExitCode = -1; Success = $false; TimedOut = $true; OutputTruncated = $false; StderrTruncated = $false; Output = '' }
    }

    $result = & $script:SysmonConfigUpdaterScript -ConfigPath $script:ConfigPath -SysmonExePath $script:ExePath -Mode Remediate -OutputFormat None -PassThru -NoConsoleSummary -Quiet -NoColor -Confirm:$false

    $result.Result | Should -Be 'WARN'
    $result.Summary.Warnings | Should -Contain 'Update failed: timed out'
  }

function Test-SysmonDoesNotLetAFailedApplySuppressTheNextRemediationAttempt {
    $script:SysmonApplyAttempt = 0
    Mock -CommandName Invoke-NativeCommand -MockWith {
      $script:SysmonApplyAttempt++
      $success = $script:SysmonApplyAttempt -ne 1
      [pscustomobject]@{ ExitCode = if ($success) { 0 } else { 5 }; Success = $success; TimedOut = $false; OutputTruncated = $false; StderrTruncated = $false; Output = '' }
    }

    & $script:SysmonConfigUpdaterScript -ConfigPath $script:ConfigPath -SysmonExePath $script:ExePath -Mode Remediate -OutputFormat None -NoConsoleSummary -Quiet -NoColor -Confirm:$false
    & $script:SysmonConfigUpdaterScript -ConfigPath $script:ConfigPath -SysmonExePath $script:ExePath -Mode Remediate -OutputFormat None -NoConsoleSummary -Quiet -NoColor -Confirm:$false

    Assert-MockCalled -CommandName Invoke-NativeCommand -Times 2 -Exactly
    Remove-Variable -Name SysmonApplyAttempt -Scope Script -ErrorAction SilentlyContinue
  }
  }

  BeforeEach { . Initialize-SysmonPolicyFixture }

  AfterEach {
    if ($null -eq $script:OldOS) { Remove-Item -LiteralPath Env:OS -ErrorAction SilentlyContinue } else { $env:OS = $script:OldOS }
    if ($null -eq $script:OldComputerName) { Remove-Item -LiteralPath Env:COMPUTERNAME -ErrorAction SilentlyContinue } else { $env:COMPUTERNAME = $script:OldComputerName }
    Remove-Item -LiteralPath Function:\Get-Service -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath Function:\Test-TrustedSysmonExecutable -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath Function:\Get-SysmonStatePath -ErrorAction SilentlyContinue
  }

  It 'does not launch Sysmon when the selected hash is not allowlisted' { Test-SysmonDoesNotLaunchSysmonWhenTheSelectedHashIsNotAllowlisted }

  It 'does not launch Sysmon when its engine is below the required minimum' { Test-SysmonDoesNotLaunchSysmonWhenItsEngineIsBelowTheRequiredMinimum }

  It 'does not launch Sysmon when manifest Config.File escapes SourceDir' { Test-SysmonDoesNotLaunchSysmonWhenManifestConfigFileEscapesSourceDir }

  It 'does not launch Sysmon for an explicitly supplied invalid manifest' { Test-SysmonDoesNotLaunchSysmonForAnExplicitlySuppliedInvalidManifest }

  It 'rejects an oversized explicit manifest before parsing or launching Sysmon' { Test-SysmonRejectsAnOversizedExplicitManifestBeforeParsingOrLaunchingSysmon }

  It 'does not fall back when manifest Config.File is missing beneath SourceDir' { Test-SysmonDoesNotFallBackWhenManifestConfigFileIsMissingBeneathSourceDir }

  It 'rejects a scalar manifest root as invalid policy input' { Test-SysmonRejectsAScalarManifestRootAsInvalidPolicyInput }

  It 'rejects an invalid explicit MinEngine value instead of disabling the requirement' { Test-SysmonRejectsAnInvalidExplicitMinEngineValueInsteadOfDisablingTheRequirement }

  It 'rejects present but empty AllowedHashes under the closed manifest schema' { Test-SysmonRejectsPresentButEmptyAllowedHashesUnderTheClosedManifestSchema }

  It 'rejects unknown manifest properties case-insensitively' { Test-SysmonRejectsUnknownManifestPropertiesCaseInsensitively }

  It 'rejects duplicate manifest properties that differ only by case' { Test-SysmonRejectsDuplicateManifestPropertiesThatDifferOnlyByCase }

  It 'rejects DTD-bearing configuration XML without launching Sysmon' { Test-SysmonRejectsDTDBearingConfigurationXMLWithoutLaunchingSysmon }

  It 'does not execute an explicitly supplied Sysmon path during Audit' { Test-SysmonDoesNotExecuteAnExplicitlySuppliedSysmonPathDuringAudit }

  It 'gives an explicit trusted executable precedence over service discovery' { Test-SysmonGivesAnExplicitTrustedExecutablePrecedenceOverServiceDiscovery }

  It 'does not launch an explicitly supplied untrusted executable during Audit' { Test-SysmonDoesNotLaunchAnExplicitlySuppliedUntrustedExecutableDuringAudit }

  It 'launches Sysmon to apply a config only when manifest policy matches' { Test-SysmonLaunchesSysmonToApplyAConfigOnlyWhenManifestPolicyMatches }

  It 'treats a bounded native-command timeout as a failed apply' { Test-SysmonTreatsABoundedNativeCommandTimeoutAsAFailedApply }

  It 'does not let a failed apply suppress the next remediation attempt' { Test-SysmonDoesNotLetAFailedApplySuppressTheNextRemediationAttempt }
}
