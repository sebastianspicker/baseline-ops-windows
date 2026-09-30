#requires -version 5.1
<#
.SYNOPSIS
Characterizes the 00-Validate-Profile.ps1 public contract.
.DESCRIPTION
Pins the PROFILE-* finding codes, severities, and exit codes emitted today by
the profile v2 validator so restructuring cannot change them silently. Cases
run the public entry point in a child process with crafted profiles under
$TestDrive. Known gaps are named as such and assert current behavior.
#>

BeforeDiscovery { . (Join-Path $PSScriptRoot 'ProfileValidation.Cases.ps1') }

BeforeAll {
  . (Join-Path $PSScriptRoot 'ProfileValidation.Cases.ps1')
  $script:dir = $TestDrive
  $script:asr = '01-ASR-Defender-Allowlist.ps1'
  $script:laps = '02-LAPS-Hygiene.ps1'
}

Describe 'valid profile' {
  It 'passes with OK, exit 0 and no findings' { Test-ValidProfilePassesWithOk }

  It 'emits the v2 result envelope' { Test-ValidProfileEmitsV2ResultEnvelope }

  It 'KNOWN GAP: Version value is not validated, 9.9 is accepted' { Test-KnownGapVersionValueIsNotValidated }

  It 'KNOWN GAP: a dependency cycle between existing steps is not detected' { Test-KnownGapDependencyCycleIsNotDetected }

  It 'KNOWN GAP: an empty Steps array is reported as PROFILE-VALIDATION-ERROR' { Test-KnownGapEmptyStepsIsValidationError }
}

Describe 'document-level failures' {
  It '<Name> yields <Codes> with exit 1' -ForEach (Get-ProfileValidationDocumentFailureCases) { Test-DocumentLevelFailureYieldsCodes -Raw $Raw -Codes $Codes }

  It 'reports a missing profile file as PROFILE-NOT-FOUND' { Test-MissingProfileFileIsNotFound }
}

Describe 'structural rules' {
  It '<Name> yields <Codes> (<Severity>) with exit <ExitCode>' -ForEach (Get-ProfileValidationStructuralCases) { Test-StructuralRuleYieldsCodes -Build $Build -Codes $Codes -Severity $Severity -ExitCode $ExitCode }

  It 'promotes a WARN-only finding to FAIL under -Strict' { Test-StrictPromotesWarnOnlyFindingToFail }
}

Describe 'step rules' {
  It '<Name> yields <Codes> with exit <ExitCode>' -ForEach (Get-ProfileValidationStepCases) { Test-StepRuleYieldsCodes -Steps $Steps -Codes $Codes -ExitCode $ExitCode }

  It 'reports the legacy -Remediate token as Medium and the Args rule as High' { Test-LegacyRemediateTokenSeverities }
}
