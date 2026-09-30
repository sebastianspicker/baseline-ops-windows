#requires -version 5.1
<#
.SYNOPSIS
Shared fixtures for profile-validation characterization tests.
.DESCRIPTION
Builds crafted profile documents and runs the public 00-Validate-Profile.ps1
entry point in a child pwsh process so exit codes and Json results are observed
exactly as an operator would observe them. Also holds the case tables and
Test-* behavior functions invoked by ProfileValidation.Tests.ps1 and pins the
PROFILE-* finding codes, severities, and exit codes.
#>

function Get-ProfileValidationRepositoryRoot {
  return (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
}

function New-ProfileValidationDocument {
  # Minimal profile that validates cleanly today. Overrides replace top-level keys.
  param([hashtable]$Override = @{})

  $document = [ordered]@{
    ProfileName = 'characterization'
    Version     = '2.0'
    Defaults    = [ordered]@{ Mode = 'Audit'; Strict = $false; OutputFormat = 'Console'; OutputPath = $null }
    Steps       = @([ordered]@{ Script = '01-ASR-Defender-Allowlist.ps1'; Args = @(); ContinueOnError = $true; DependsOn = @() })
    Integrity   = [ordered]@{ RequireSigned = $false; ExpectedHashes = @{} }
  }
  foreach ($key in $Override.Keys) { $document[$key] = $Override[$key] }
  return $document
}

function Invoke-ProfileValidation {
  # Returns ExitCode, Codes (finding codes), Result and the parsed result object.
  param(
    [Parameter(Mandatory)][string]$Directory,
    [string]$Name = 'profile.json',
    $Document,
    [string]$RawText,
    [switch]$Strict
  )

  $root = Get-ProfileValidationRepositoryRoot
  $profilePath = Join-Path $Directory $Name
  $outputPath = Join-Path $Directory ('result-{0}.json' -f [guid]::NewGuid().ToString('N'))
  if ($PSBoundParameters.ContainsKey('RawText')) {
    Set-Content -LiteralPath $profilePath -Value $RawText -Encoding UTF8
  } elseif ($null -ne $Document) {
    $Document | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $profilePath -Encoding UTF8
  }
  $arguments = @(
    '-NoProfile', '-File', (Join-Path $root 'scripts/00-Validate-Profile.ps1'),
    '-ProfilePath', $profilePath, '-RootPath', $root,
    '-OutputFormat', 'Json', '-OutputPath', $outputPath, '-Quiet', '-NoColor'
  )
  if ($Strict) { $arguments += '-Strict' }
  $null = & (Get-Process -Id $PID).Path @arguments 2>&1
  $exitCode = $LASTEXITCODE
  $result = $null
  if (Test-Path -LiteralPath $outputPath) { $result = Get-Content -LiteralPath $outputPath -Raw | ConvertFrom-Json }
  $codes = if ($null -ne $result) { @($result.Findings | ForEach-Object { [string]$_.Code }) } else { @() }
  return [pscustomobject]@{ ExitCode = $exitCode; Codes = $codes; Result = if ($null -ne $result) { [string]$result.Result } else { $null }; Object = $result }
}

function Get-ProfileValidationDocumentFailureCases {
  return @(
  @{ Name = 'empty file'; Raw = ''; Codes = @('PROFILE-EMPTY') }
  @{ Name = 'malformed JSON'; Raw = '{nope'; Codes = @('PROFILE-INVALID-JSON') }
  @{ Name = 'root object without properties'; Raw = '{}'; Codes = @('PROFILE-VALIDATION-ERROR') }
  @{ Name = 'root array'; Raw = '[1,2]'; Codes = @('PROFILE-ROOT-TYPE') + @('PROFILE-MISSING-FIELD') * 5 }
  )
}

function Get-ProfileValidationStructuralCases {
  return @(
  @{ Name = 'missing Integrity'; Build = { $d = New-ProfileValidationDocument; $d.Remove('Integrity'); $d }; Codes = @('PROFILE-MISSING-FIELD'); Severity = 'High'; ExitCode = 1 }
  @{ Name = 'missing Version and ProfileName'; Build = { $d = New-ProfileValidationDocument; $d.Remove('Version'); $d.Remove('ProfileName'); $d }; Codes = @('PROFILE-MISSING-FIELD', 'PROFILE-MISSING-FIELD'); Severity = 'High'; ExitCode = 1 }
  @{ Name = 'Defaults not an object'; Build = { New-ProfileValidationDocument @{ Defaults = 'x' } }; Codes = @('PROFILE-DEFAULTS-TYPE'); Severity = 'High'; ExitCode = 1 }
  @{ Name = 'Defaults.Mode absent'; Build = { New-ProfileValidationDocument @{ Defaults = @{ Strict = $true } } }; Codes = @('PROFILE-DEFAULTS-MODE'); Severity = 'High'; ExitCode = 1 }
  @{ Name = 'Defaults.Mode invalid'; Build = { New-ProfileValidationDocument @{ Defaults = @{ Mode = 'Fix' } } }; Codes = @('PROFILE-DEFAULTS-MODE-VALUE'); Severity = 'High'; ExitCode = 1 }
  @{ Name = 'Defaults.OutputFormat invalid'; Build = { New-ProfileValidationDocument @{ Defaults = @{ Mode = 'Audit'; OutputFormat = 'Xml' } } }; Codes = @('PROFILE-DEFAULTS-OUTPUTFORMAT'); Severity = 'High'; ExitCode = 1 }
  @{ Name = 'Defaults.Strict not boolean'; Build = { New-ProfileValidationDocument @{ Defaults = @{ Mode = 'Audit'; Strict = 'yes' } } }; Codes = @('PROFILE-DEFAULTS-STRICT-TYPE'); Severity = 'High'; ExitCode = 1 }
  @{ Name = 'Integrity not an object'; Build = { New-ProfileValidationDocument @{ Integrity = 'x' } }; Codes = @('PROFILE-INTEGRITY-TYPE'); Severity = 'High'; ExitCode = 1 }
  @{ Name = 'Integrity.RequireSigned not boolean'; Build = { New-ProfileValidationDocument @{ Integrity = @{ RequireSigned = 'true' } } }; Codes = @('PROFILE-INTEGRITY-SIGNED-TYPE'); Severity = 'High'; ExitCode = 1 }
  @{ Name = 'ExpectedHashes not an object'; Build = { New-ProfileValidationDocument @{ Integrity = @{ ExpectedHashes = 'x' } } }; Codes = @('PROFILE-HASHES-TYPE'); Severity = 'High'; ExitCode = 1 }
  @{ Name = 'ExpectedHashes unsafe key'; Build = { New-ProfileValidationDocument @{ Integrity = @{ ExpectedHashes = @{ '../evil.ps1' = 'abc' } } } }; Codes = @('PROFILE-HASH-KEY'); Severity = 'High'; ExitCode = 1 }
  @{ Name = 'ExpectedHashes empty value'; Build = { New-ProfileValidationDocument @{ Integrity = @{ ExpectedHashes = @{ '01-ASR-Defender-Allowlist.ps1' = '' } } } }; Codes = @('PROFILE-HASH-VALUE'); Severity = 'Medium'; ExitCode = 2 }
  @{ Name = 'Steps not an array'; Build = { New-ProfileValidationDocument @{ Steps = @{ a = 1 } } }; Codes = @('PROFILE-STEPS-TYPE'); Severity = 'High'; ExitCode = 1 }
  )
}

function Get-ProfileValidationStepCases {
  return @(
  @{ Name = 'step is not an object'; Steps = @('x'); Codes = @('PROFILE-VALIDATION-ERROR'); ExitCode = 1 }
  @{ Name = 'step without Script'; Steps = @(@{ Args = @() }); Codes = @('PROFILE-VALIDATION-ERROR'); ExitCode = 1 }
  @{ Name = 'unsafe script name'; Steps = @(@{ Script = '../x.ps1' }); Codes = @('PROFILE-STEP-SCRIPT-NAME'); ExitCode = 1 }
  @{ Name = '00-* control-plane script'; Steps = @(@{ Script = '00-Run-Batch.ps1' }); Codes = @('PROFILE-STEP-CONTROL-PLANE'); ExitCode = 1 }
  @{ Name = 'unknown script'; Steps = @(@{ Script = '99-Nope.ps1' }); Codes = @('PROFILE-STEP-SCRIPT-NOT-FOUND'); ExitCode = 1 }
  @{ Name = 'non-empty Args'; Steps = @(@{ Script = '01-ASR-Defender-Allowlist.ps1'; Args = @('-Foo') }); Codes = @('PROFILE-STEP-ARGS-NOT-ALLOWED'); ExitCode = 1 }
  @{ Name = 'legacy -Remediate arg'; Steps = @(@{ Script = '01-ASR-Defender-Allowlist.ps1'; Args = @('-Remediate') }); Codes = @('PROFILE-STEP-ARGS-NOT-ALLOWED', 'PROFILE-STEP-ARGS-LEGACY-REMEDIATE'); ExitCode = 1 }
  @{ Name = 'non-string Args value'; Steps = @(@{ Script = '01-ASR-Defender-Allowlist.ps1'; Args = @(5) }); Codes = @('PROFILE-STEP-ARGS-NOT-ALLOWED', 'PROFILE-STEP-ARGS-TYPE'); ExitCode = 1 }
  @{ Name = 'empty Args token'; Steps = @(@{ Script = '01-ASR-Defender-Allowlist.ps1'; Args = @('') }); Codes = @('PROFILE-STEP-ARGS-NOT-ALLOWED', 'PROFILE-STEP-ARGS-EMPTY'); ExitCode = 1 }
  @{ Name = 'Args not an array'; Steps = @(@{ Script = '01-ASR-Defender-Allowlist.ps1'; Args = '-x' }); Codes = @('PROFILE-STEP-ARGS-ARRAY'); ExitCode = 1 }
  @{ Name = 'ContinueOnError not boolean'; Steps = @(@{ Script = '01-ASR-Defender-Allowlist.ps1'; ContinueOnError = 'no' }); Codes = @('PROFILE-STEP-CONTINUE-TYPE'); ExitCode = 1 }
  @{ Name = 'DependsOn not an array'; Steps = @(@{ Script = '01-ASR-Defender-Allowlist.ps1'; DependsOn = 'x' }); Codes = @('PROFILE-STEP-DEPENDS-TYPE', 'PROFILE-STEP-DEPENDS-NOT-FOUND'); ExitCode = 1 }
  @{ Name = 'empty DependsOn value'; Steps = @(@{ Script = '01-ASR-Defender-Allowlist.ps1'; DependsOn = @('') }); Codes = @('PROFILE-STEP-DEPENDS-VALUE'); ExitCode = 1 }
  @{ Name = 'unknown DependsOn target'; Steps = @(@{ Script = '01-ASR-Defender-Allowlist.ps1'; DependsOn = @('02-LAPS-Hygiene.ps1') }); Codes = @('PROFILE-STEP-DEPENDS-NOT-FOUND'); ExitCode = 1 }
  @{ Name = 'duplicate step'; Steps = @(@{ Script = '01-ASR-Defender-Allowlist.ps1' }, @{ Script = '01-ASR-Defender-Allowlist.ps1' }); Codes = @('PROFILE-STEP-DUPLICATE'); ExitCode = 1 }
  )
}

function Test-ValidProfilePassesWithOk {
  $r = Invoke-ProfileValidation -Directory $script:dir -Document (New-ProfileValidationDocument)
  $r.ExitCode | Should -Be 0
  $r.Result | Should -Be 'OK'
  $r.Codes | Should -HaveCount 0
}

function Test-ValidProfileEmitsV2ResultEnvelope {
  $r = Invoke-ProfileValidation -Directory $script:dir -Document (New-ProfileValidationDocument)
  $names = @($r.Object.PSObject.Properties.Name)
  foreach ($field in 'SchemaVersion', 'ScriptName', 'Mode', 'ComputerName', 'TimestampUtc', 'Result', 'Findings', 'Summary', 'Metadata') {
    $names | Should -Contain $field
  }
  $r.Object.SchemaVersion | Should -Be '2.0'
  $r.Object.ScriptName | Should -Be '00-Validate-Profile.ps1'
  $r.Object.Metadata.Component | Should -Be 'ProfileValidation'
  $r.Object.Metadata.ProfileContentSha256 | Should -Match '^[0-9a-fA-F]{64}$'
  $r.Object.Summary.Issues | Should -Be 0
}

function Test-KnownGapVersionValueIsNotValidated {
  $r = Invoke-ProfileValidation -Directory $script:dir -Document (New-ProfileValidationDocument @{ Version = '9.9' })
  $r.ExitCode | Should -Be 0
  $r.Codes | Should -HaveCount 0
}

function Test-KnownGapDependencyCycleIsNotDetected {
  $steps = @(
    @{ Script = $script:asr; DependsOn = @($script:laps) }
    @{ Script = $script:laps; DependsOn = @($script:asr) }
  )
  $r = Invoke-ProfileValidation -Directory $script:dir -Document (New-ProfileValidationDocument @{ Steps = $steps })
  $r.ExitCode | Should -Be 0
  $r.Codes | Should -HaveCount 0
}

function Test-KnownGapEmptyStepsIsValidationError {
  $r = Invoke-ProfileValidation -Directory $script:dir -Document (New-ProfileValidationDocument @{ Steps = @() })
  $r.ExitCode | Should -Be 1
  $r.Codes | Should -Be @('PROFILE-VALIDATION-ERROR')
}

function Test-DocumentLevelFailureYieldsCodes {
  param([string]$Raw, [string[]]$Codes)
  $r = Invoke-ProfileValidation -Directory $script:dir -RawText $Raw
  $r.ExitCode | Should -Be 1
  $r.Result | Should -Be 'FAIL'
  $r.Codes | Should -Be $Codes
}

function Test-MissingProfileFileIsNotFound {
  $r = Invoke-ProfileValidation -Directory $script:dir -Name 'absent.json'
  $r.ExitCode | Should -Be 1
  $r.Codes | Should -Be @('PROFILE-NOT-FOUND')
}

function Test-StructuralRuleYieldsCodes {
  param([scriptblock]$Build, [string[]]$Codes, [string]$Severity, [int]$ExitCode)
  $r = Invoke-ProfileValidation -Directory $script:dir -Document (& $Build)
  $r.ExitCode | Should -Be $ExitCode
  $r.Codes | Should -Be $Codes
  @($r.Object.Findings.Severity | Select-Object -Unique) | Should -Be @($Severity)
}

function Test-StrictPromotesWarnOnlyFindingToFail {
  $document = New-ProfileValidationDocument @{ Integrity = @{ ExpectedHashes = @{ '01-ASR-Defender-Allowlist.ps1' = '' } } }
  $r = Invoke-ProfileValidation -Directory $script:dir -Document $document -Strict
  $r.ExitCode | Should -Be 1
  $r.Result | Should -Be 'FAIL'
  $r.Codes | Should -Be @('PROFILE-HASH-VALUE')
}

function Test-StepRuleYieldsCodes {
  param($Steps, [string[]]$Codes, [int]$ExitCode)
  $r = Invoke-ProfileValidation -Directory $script:dir -Document (New-ProfileValidationDocument @{ Steps = $Steps })
  $r.ExitCode | Should -Be $ExitCode
  $r.Result | Should -Be 'FAIL'
  $r.Codes | Should -Be $Codes
}

function Test-LegacyRemediateTokenSeverities {
  $steps = @(@{ Script = $script:asr; Args = @('-Remediate') })
  $r = Invoke-ProfileValidation -Directory $script:dir -Document (New-ProfileValidationDocument @{ Steps = $steps })
  ($r.Object.Findings | Where-Object Code -EQ 'PROFILE-STEP-ARGS-NOT-ALLOWED').Severity | Should -Be 'High'
  ($r.Object.Findings | Where-Object Code -EQ 'PROFILE-STEP-ARGS-LEGACY-REMEDIATE').Severity | Should -Be 'Medium'
}
