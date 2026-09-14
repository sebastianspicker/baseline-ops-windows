<#
.SYNOPSIS
  Verifies Serialization library contracts.
.DESCRIPTION
  Retains explicit contract cases and shared fixture setup for the library.
#>

BeforeAll {
  Import-Module (Join-Path $PSScriptRoot '../../lib/Serialization.psm1') -Force

  . (Join-Path $PSScriptRoot 'Serialization.Cases.ps1')
}

Describe 'Save-Json' {
  It 'Writes JSON file' { Test-SerializationWritesJSONFile }

  It 'Allows double dots inside JSON file name segment' { Test-SerializationAllowsDoubleDotsInsideJSONFileNameSegment }

  It 'Auto-creates parent directory' { Test-SerializationAutoCreatesParentDirectory }

  It 'Writes without BOM when NoBom switch is set' { Test-SerializationWritesWithoutBOMWhenNoBomSwitchIsSet }

  It 'Writes without BOM by default on every supported runtime' { Test-SerializationWritesWithoutBOMByDefaultOnEverySupportedRuntime }

  It 'Throws for empty path' {
    { Save-Json -InputObject @{ A = 1 } -Path '' } | Should -Throw '*Path*'
  }

  It 'Throws for path traversal attempt' {
    $tmpDir = Join-Path ([System.IO.Path]::GetTempPath()) 'ser-traversal-test'
    { Save-Json -InputObject @{ A = 1 } -Path (Join-Path $tmpDir '../../escape.json') } | Should -Throw '*path traversal*'
  }

  It 'Roundtrip: write then read returns same data' { Test-SerializationRoundtripWriteThenReadReturnsSameData }
}

Describe 'Save-Csv' {
  It 'Writes CSV file with header row' { Test-SerializationWritesCSVFileWithHeaderRow }

  It 'Writes an explicit UTF-8 BOM for operator-facing CSV output' { Test-SerializationWritesAnExplicitUTF8BOMForOperatorFacingCSVOutput }

  It 'Allows double dots inside CSV file name segment' { Test-SerializationAllowsDoubleDotsInsideCSVFileNameSegment }

  It 'Handles special characters in values' { Test-SerializationHandlesSpecialCharactersInValues }

  It 'neutralizes spreadsheet formulas after leading whitespace or control characters' { Test-SerializationNeutralizesSpreadsheetFormulasAfterLeadingWhitespaceOrControlCharacters }

  It 'keeps JSON values lossless' { Test-SerializationKeepsJSONValuesLossless }

  It 'Auto-creates parent directory for CSV' { Test-SerializationAutoCreatesParentDirectoryForCSV }
}
