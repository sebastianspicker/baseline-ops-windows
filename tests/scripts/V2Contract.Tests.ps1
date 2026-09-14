#requires -version 5.1
<#
.SYNOPSIS
  Verifies public v2 script contracts.
.DESCRIPTION
  Retains parameter, result, and process-exit assertions for public scripts.
#>

BeforeAll { . (Join-Path $PSScriptRoot 'V2Contract.Cases.ps1') }

Describe 'v2 parameter contract' {
  $scriptFiles = Get-ChildItem -LiteralPath (Join-Path $PSScriptRoot '../../scripts') -Filter '*.ps1' -File |
    Where-Object { $_.Name -match '^\d{2}-' }
  $cases = @($scriptFiles | ForEach-Object { [pscustomobject]@{ Name = $_.Name; FullName = $_.FullName } })

  It '<_.Name> exposes required v2 params' -ForEach $cases { Test-V2NameExposesRequiredV2Params }

  It '<_.Name> does not expose legacy Remediate parameter' -ForEach $cases { Test-V2NameDoesNotExposeLegacyRemediateParameter }

  It '<_.Name> does not use legacy AuditOnly mode value' -ForEach $cases { Test-V2NameDoesNotUseLegacyAuditOnlyModeValue }

  It '<_.Name> does not define parameter names that collide with parameter aliases' -ForEach $cases { Test-V2NameDoesNotDefineParameterNamesThatCollideWithParameterAliases }

  It '<_.Name> enforces ShouldProcess when Mode supports Remediate' -ForEach $cases { Test-V2NameEnforcesShouldProcessWhenModeSupportsRemediate }

  It 'Audited scripts do not expose stale legacy Remediate help text in the top comment block' { Test-V2AuditedScriptsDoNotExposeStaleLegacyRemediateHelpTextInTheTopCommentBlock }

  It 'Scripts with filtered finding counts force array semantics before reading Count' { Test-V2ScriptsWithFilteredFindingCountsForceArraySemanticsBeforeReadingCount }

  It '27-Defender-Health-Audit permits an omitted SettingsJsonPath during config load' { Test-V227DefenderHealthAuditPermitsAnOmittedSettingsJsonPathDuringConfigLoad }

  It '17-Sysmon-Rule-Drift-Sensor classifies runtime errors as FAIL' { Test-V217SysmonRuleDriftSensorClassifiesRuntimeErrorsAsFAIL }

  It '17-Sysmon-Rule-Drift-Sensor locks every platform implementation loaded by External.psm1' { Test-V217SysmonRuleDriftSensorLocksEveryPlatformImplementationLoadedByExternalPsm1 }

  It 'advertised Strict has terminal WARN-to-FAIL handling in audited scripts' { Test-V2AdvertisedStrictHasTerminalWARNToFAILHandlingInAuditedScripts }
}

Describe '00 control-plane v2 surface' {
  $controlPlaneCases = @(
    Get-ChildItem -LiteralPath (Join-Path $PSScriptRoot '../../scripts') -Filter '00-*.ps1' -File |
      Sort-Object Name |
      ForEach-Object { [pscustomobject]@{ Name = $_.Name; Path = $_.FullName } }
  )

  It '<_.Name> can construct a V2 result for its own terminal paths' -ForEach $controlPlaneCases { Test-V2NameCanConstructAV2ResultForItsOwnTerminalPaths }
}
