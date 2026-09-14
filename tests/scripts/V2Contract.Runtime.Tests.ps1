#requires -version 5.1
<#
.SYNOPSIS
  Verifies public v2 script contracts.
.DESCRIPTION
  Retains parameter, result, and process-exit assertions for public scripts.
#>

BeforeAll { . (Join-Path $PSScriptRoot 'V2Contract.Cases.ps1') }

Describe 'migrated v2 initialization runtime smoke' {
  $migratedInitCases = @(
    @{ Name = '47-WDAG-Readiness-Audit.ps1'; Path = (Join-Path $PSScriptRoot '../../scripts/47-WDAG-Readiness-Audit.ps1') }
  )

  It '<_.Name> preserves v2 output switches after Initialize-V2Context migration' -ForEach $migratedInitCases { Test-V2NamePreservesV2OutputSwitchesAfterInitializeV2ContextMigration }
}

Describe 'v2 output configuration preflight' {
  It 'returns a terminal V2 FAIL before execution when <OutputFormat> lacks OutputPath' -TestCases @(
    @{ OutputFormat = 'Json' }
    @{ OutputFormat = 'Csv' }
  ) { param($OutputFormat) Test-V2ReturnsATerminalV2FAILBeforeExecutionWhenOutputFormatLacksOutputPath -OutputFormat $OutputFormat }
}

Describe 'unsupported-host v2 result contract' {
  $unsupportedHostCases = @(
    Get-ChildItem -LiteralPath (Join-Path $PSScriptRoot '../../scripts') -Filter '*.ps1' -File |
      Where-Object {
        $_.Name -match '^(?:0[1-9]|[1-4][0-9]|5[0-2])-'
      } |
      Sort-Object Name |
      ForEach-Object {
        [pscustomobject]@{
          Name = $_.Name
          Path = $_.FullName
        }
      }
  )

  It '<_.Name> reports unsupported host as WARN, not success' -ForEach $unsupportedHostCases { Test-V2NameReportsUnsupportedHostAsWARNNotSuccess }

  It '<_.Name> promotes unsupported host to FAIL when Strict is requested' -ForEach $unsupportedHostCases { Test-V2NamePromotesUnsupportedHostToFAILWhenStrictIsRequested }

  It '<_.Name> keeps its unsupported-host branch tied to Strict and Get-V2ExitCode' -ForEach $unsupportedHostCases { Test-V2NameKeepsItsUnsupportedHostBranchTiedToStrictAndGetV2ExitCode }
}

Describe '43 App Control disabled-config v2 contract' {
  It 'returns initialized disabled-config findings and a strict FAIL at runtime' { Test-V2ReturnsInitializedDisabledConfigFindingsAndAStrictFAILAtRuntime }

  It 'uses initialized findings and promotes its disabled-config result under Strict' { Test-V2UsesInitializedFindingsAndPromotesItsDisabledConfigResultUnderStrict }
}
