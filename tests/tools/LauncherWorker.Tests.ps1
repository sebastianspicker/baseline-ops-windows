#requires -Version 5.1
<#
.SYNOPSIS
Regression coverage for the launcher worker and manifest trust boundary.
.DESCRIPTION
Verifies worker command mapping, entry-point splatting and exit-code relay,
manifest validation, size caps, and launcher argument safety without the
Windows-only start gate, job object, or file locks.
#>

BeforeAll {
  $repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).ProviderPath
  Import-Module (Join-Path $repoRoot 'tools/Launcher.Core.psm1') -Force
  Import-Module (Join-Path $repoRoot 'lib/Validation.psm1') -Force
  . (Join-Path $PSScriptRoot 'LauncherWorker.Cases.ps1')

  . ([scriptblock]::Create((Get-LauncherWorkerFunctionSource -Path (Join-Path $repoRoot 'tools/Launcher-Worker.ps1'))))

  $script:kit = New-LauncherTestKit -Directory $TestDrive
  $script:profilePath = Join-Path $TestDrive 'profile.json'
  Set-Content -LiteralPath $script:profilePath -Value '{}'
}

Describe 'Invoke-LauncherEntryPoint' {
  BeforeEach { $script:stub = New-LauncherEntryPointStub }

  It 'splats the parameter table instead of passing it as one positional argument' { Test-EntryPointSplatsParameterTable -Stub $script:stub }

  It 'relays other streams as strings and propagates the exit code without polluting output' { Test-EntryPointRelaysStreamsAndExitCode -Stub $script:stub }

  It 'reports zero when the entry point sets no exit code' { Test-EntryPointReportsZeroWithoutExitCode }
}

Describe 'Get-LauncherWorkerCommand' {
  It 'maps validate-profile to 00-Validate-Profile.ps1' { Test-WorkerCommandMapsValidateProfile }

  It 'maps run-profile to 00-Run-Profile.ps1 with strict and signature switches only when set' { Test-WorkerCommandMapsRunProfile }

  It 'maps run-script to 00-Run-Local.ps1 with mode, tokens, and strict appended to ScriptArgs' { Test-WorkerCommandMapsRunScript }

  It 'passes ExpectedHash with its algorithm only when a hash is supplied' { Test-WorkerCommandPassesExpectedHashWithAlgorithm }

  It 'rejects script targets that are not safe numbered script names' { Test-WorkerCommandRejectsUnsafeScriptTargets }

  It 'rejects unknown operations' { Test-WorkerCommandRejectsUnknownOperations }
}

Describe 'Get-LauncherSelectedExecutionPath' {
  It 'resolves run-script under root/scripts and other operations to the target' { Test-SelectedExecutionPathResolvesTargets }
}

Describe 'Get-LauncherWorkerManifestJson' {
  It 'decodes an inherited base64 manifest' { Test-ManifestJsonDecodesInheritedBase64 }

  It 'rejects oversized or malformed base64' { Test-ManifestJsonRejectsOversizedOrMalformedBase64 }

  It 'accepts base64 at exactly the cap' { Test-ManifestJsonAcceptsBase64AtCap }

  It 'reads a manifest file within the byte cap' { Test-ManifestJsonReadsFileWithinCap }

  It 'rejects a manifest file over 16384 bytes, a directory, and a missing path argument' { Test-ManifestJsonRejectsOversizedFileDirectoryAndMissingPath }
}

Describe 'Assert-LauncherManifest' {
  It 'accepts a valid manifest for each operation' { Test-ManifestAcceptsValidOperations }

  It 'rejects a non-object root' { Test-ManifestRejectsNonObjectRoot }

  It 'rejects unknown and missing fields' { Test-ManifestRejectsUnknownAndMissingFields }

  It 'rejects unsupported schema versions and wrong field types' { Test-ManifestRejectsUnsupportedSchemaAndFieldTypes }

  It 'rejects unsupported operations, modes, and hash algorithms' { Test-ManifestRejectsUnsupportedOperationModeAndAlgorithm }

  It 'requires remediation approval for Remediate mode' { Test-ManifestRequiresRemediationApproval }

  It 'rejects an invalid kit root, script target, profile target, and hash length' { Test-ManifestRejectsInvalidRootTargetsAndHashLength }

  It 'restricts hash and argument tokens to single-script runs' { Test-ManifestRestrictsHashAndTokensToSingleScriptRuns }

  It 'rejects argument tokens that override launcher-owned options' { Test-ManifestRejectsLauncherOwnedArgumentTokens }
}

Describe 'Assert-LauncherArgumentsAllowed' {
  It 'accepts ordinary script arguments' { Test-ArgumentsAllowedAcceptsOrdinaryArguments }

  It 'rejects every launcher-owned name in dash, colon, and equals forms, case-insensitively' { Test-ArgumentsAllowedRejectsLauncherOwnedNames }
}
