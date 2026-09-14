#requires -version 5.1
<#
.SYNOPSIS
Pester coverage for EmergencyKillSwitch input and host result contracts.

.DESCRIPTION
Verifies fail-closed V2 configuration reporting independently of mutation tests.
#>

Describe '21-EmergencyKillSwitch configuration rejection V2 reporting' -Tag 'EmergencyKillSwitch' {
  BeforeAll {
function Test-KillSwitchValidationReportsInvalidConfigurationAsAV2FAILResult {
    param($ConfigJsonRaw, $FindingCode, $Message)

    $oldOS = $env:OS
    try {
      $env:OS = 'Windows_NT'
      $output = & $script:KillSwitchScript -Mode Audit -ConfigJsonRaw $ConfigJsonRaw -OutputFormat None -PassThru -Confirm:$false 2>&1 3>&1 6>&1
      $result = @($output | Where-Object { $_ -and $_.PSObject.Properties.Name -contains 'Result' })[-1]

      $LASTEXITCODE | Should -Be 1
      $result.Result | Should -Be 'FAIL'
      @($result.Findings | Where-Object Code -eq $FindingCode).Count | Should -Be 1
      @($result.Findings | Where-Object Code -eq $FindingCode)[0].Message | Should -Match $Message
    } finally {
      if ($null -eq $oldOS) { Remove-Item -LiteralPath Env:OS -ErrorAction SilentlyContinue }
      else { $env:OS = $oldOS }
    }
  }

function Test-KillSwitchValidationFailsClosedWithOneV2ResultForMalformedOrWrongTypedJSON {
    param($Json, $Message)

    $oldOS = $env:OS
    try {
      $env:OS = 'Windows_NT'
      $output = & $script:KillSwitchScript -Mode Audit -ConfigJsonRaw $Json -OutputFormat None -PassThru -Confirm:$false 2>&1 3>&1 6>&1
      $results = @($output | Where-Object { $_ -and $_.PSObject.Properties.Name -contains 'Result' })

      $LASTEXITCODE | Should -Be 1
      $results | Should -HaveCount 1
      $results[0].Result | Should -Be 'FAIL'
      @($results[0].Findings | Where-Object Code -eq 'KS-InvalidConfig') | Should -HaveCount 1
      @($results[0].Findings | Where-Object Code -eq 'KS-InvalidConfig')[0].Message | Should -Match $Message
    } finally {
      if ($null -eq $oldOS) { Remove-Item -LiteralPath Env:OS -ErrorAction SilentlyContinue } else { $env:OS = $oldOS }
    }
  }


    $script:KillSwitchScript = Join-Path $PSScriptRoot '../../scripts/21-EmergencyKillSwitch.ps1'

  }



  It 'reports invalid configuration as a V2 FAIL result' -TestCases @(
    @{ Name = 'an unsafe registry key'; ConfigJsonRaw = '{"RegKey":"HKCU:\\Unsafe"}'; FindingCode = 'KS-InvalidRegKey'; Message = 'RegKey' }
    @{ Name = 'a wildcard registry key'; ConfigJsonRaw = '{"RegKey":"HKLM:\\SOFTWARE\\KillSwitch\\*"}'; FindingCode = 'KS-InvalidRegKey'; Message = 'wildcard' }
    @{ Name = 'a rule prefix with unsafe characters'; ConfigJsonRaw = '{"RulePrefix":"unsafe prefix"}'; FindingCode = 'KS-InvalidRulePrefix'; Message = 'contains invalid characters' }
    @{ Name = 'an overlong rule prefix'; ConfigJsonRaw = ('{"RulePrefix":"' + ('A' * 65) + '"}'); FindingCode = 'KS-InvalidRulePrefix'; Message = 'exceeds 64 characters' }
  ) { param($ConfigJsonRaw, $FindingCode, $Message) Test-KillSwitchValidationReportsInvalidConfigurationAsAV2FAILResult -ConfigJsonRaw $ConfigJsonRaw -FindingCode $FindingCode -Message $Message }

  It 'fails closed with one V2 result for malformed or wrong-typed JSON' -TestCases @(
    @{ Json = '{'; Message = 'invalid' },
    @{ Json = '42'; Message = 'root must be an object' },
    @{ Json = '{"DisableAdapters":"false"}'; Message = 'must be a boolean' },
    @{ Json = '{"EventId":"9001"}'; Message = 'must be an integer' },
    @{ Json = '{"AutoRollbackMinutes":4.5}'; Message = 'must be an integer' },
    @{ Json = '{"BreakGlassRemoteAddress":"10.0.0.1"}'; Message = 'must be an array' },
    @{ Json = '{"Unexpected":true}'; Message = 'unknown field' }
  ) { param($Json, $Message) Test-KillSwitchValidationFailsClosedWithOneV2ResultForMalformedOrWrongTypedJSON -Json $Json -Message $Message }
}

Describe '21-EmergencyKillSwitch Strict unsupported-host reporting' -Tag 'EmergencyKillSwitch' {
  BeforeAll {
function Test-KillSwitchValidationMapsTheUnsupportedHostWARNResultToV2FAILAndExitCode1 {
    $scriptPath = Join-Path $PSScriptRoot '../../scripts/21-EmergencyKillSwitch.ps1'
    $oldOS = $env:OS
    try {
      Remove-Item -LiteralPath Env:OS -ErrorAction SilentlyContinue
      $output = & $scriptPath -Mode Audit -OutputFormat None -PassThru -Strict 2>&1 3>&1 6>&1
      $exitCode = $LASTEXITCODE
      $result = @($output | Where-Object { $_ -and $_.PSObject.Properties.Name -contains 'Result' })[-1]

      $exitCode | Should -Be 1
      $result.Result | Should -Be 'FAIL'
      $result.Metadata.UnsupportedHost | Should -BeTrue
    } finally {
      if ($null -eq $oldOS) { Remove-Item -LiteralPath Env:OS -ErrorAction SilentlyContinue }
      else { $env:OS = $oldOS }
    }
  }
  }

  It 'maps the unsupported-host WARN result to V2 FAIL and exit code 1' { Test-KillSwitchValidationMapsTheUnsupportedHostWARNResultToV2FAILAndExitCode1 }
}
