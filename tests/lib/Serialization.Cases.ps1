<#
.SYNOPSIS
  Verifies Serialization library contracts.
.DESCRIPTION
  Retains explicit contract cases and shared fixture setup for the library.
#>

function Test-SerializationCreatesRequiredContractFields {
    $obj = Get-V2ResultObject -ScriptName 'x.ps1' -Mode 'Audit' -Result 'OK' -Findings @() -Summary @{ A = 1 } -Metadata @{}
    $obj.SchemaVersion | Should -Be '2.0'
    $obj.ScriptName | Should -Be 'x.ps1'
    $obj.Mode | Should -Be 'Audit'
    $obj.Result | Should -Be 'OK'
}

function Test-SerializationIncludesComputerNameAndTimestampUtc {
    $obj = Get-V2ResultObject -ScriptName 'y.ps1' -Mode 'Remediate' -Result 'WARN' -Findings @() -Summary @{} -Metadata @{}
    $obj.PSObject.Properties.Name | Should -Contain 'ComputerName'
    $obj.PSObject.Properties.Name | Should -Contain 'TimestampUtc'
}

function Test-SerializationStoresFindingsAsArray {
    $findings = @([pscustomobject]@{ Code = 'A'; Severity = 'High' })
    $obj = Get-V2ResultObject -ScriptName 'z.ps1' -Mode 'Audit' -Result 'FAIL' -Findings $findings -Summary @{} -Metadata @{}
    @($obj.Findings).Count | Should -Be 1
    $obj.Findings[0].Code | Should -Be 'A'
}

function Test-SerializationWritesJSONFile {
    $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("ser-{0}.json" -f [guid]::NewGuid().ToString('N'))
    try {
      Save-Json -InputObject @{ test = 1 } -Path $tmp -NoBom
      Test-Path -LiteralPath $tmp | Should -Be $true
      $raw = Get-Content -LiteralPath $tmp -Raw
      $raw | Should -Match '"test"'
    } finally {
      if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
    }
}

function Test-SerializationAllowsDoubleDotsInsideJSONFileNameSegment {
    $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("ser-name..dots-{0}.json" -f [guid]::NewGuid().ToString('N'))
    try {
      Save-Json -InputObject @{ test = 1 } -Path $tmp -NoBom
      Test-Path -LiteralPath $tmp | Should -Be $true
    } finally {
      if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
    }
}

function Test-SerializationAutoCreatesParentDirectory {
    $tmpDir = Join-Path ([System.IO.Path]::GetTempPath()) ("ser-dir-{0}" -f [guid]::NewGuid().ToString('N'))
    $tmp = Join-Path $tmpDir 'output.json'
    try {
      Save-Json -InputObject @{ auto = 'dir' } -Path $tmp -NoBom
      Test-Path -LiteralPath $tmp | Should -Be $true
    } finally {
      if (Test-Path -LiteralPath $tmpDir) { Remove-Item -LiteralPath $tmpDir -Recurse -Force -ErrorAction SilentlyContinue }
    }
}

function Test-SerializationWritesWithoutBOMWhenNoBomSwitchIsSet {
    $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("ser-nobom-{0}.json" -f [guid]::NewGuid().ToString('N'))
    try {
      Save-Json -InputObject @{ bom = 'test' } -Path $tmp -NoBom
      $bytes = [System.IO.File]::ReadAllBytes($tmp)
      # BOM for UTF-8 is 0xEF 0xBB 0xBF; verify it is NOT present
      if ($bytes.Length -ge 3) {
        ($bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) | Should -Be $false
      }
    } finally {
      if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
    }
}

function Test-SerializationWritesWithoutBOMByDefaultOnEverySupportedRuntime {
    $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("ser-default-nobom-{0}.json" -f [guid]::NewGuid().ToString('N'))
    try {
      Save-Json -InputObject @{ bom = 'test' } -Path $tmp
      $bytes = [System.IO.File]::ReadAllBytes($tmp)
      ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) |
        Should -BeFalse
    } finally {
      if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
    }
}

function Test-SerializationRoundtripWriteThenReadReturnsSameData {
    Import-Module (Join-Path $PSScriptRoot '../../lib/JsonCatalog.psm1') -Force
    $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("ser-rt-{0}.json" -f [guid]::NewGuid().ToString('N'))
    try {
      $original = [pscustomobject]@{ Name = 'Roundtrip'; Items = @(1, 2, 3) }
      Save-Json -InputObject $original -Path $tmp -NoBom
      $loaded = Read-JsonFileSafe -Path $tmp
      $loaded.Name | Should -Be 'Roundtrip'
      $loaded.Items.Count | Should -Be 3
    } finally {
      if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
    }
}

function Test-SerializationWritesCSVFileWithHeaderRow {
    $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("ser-csv-{0}.csv" -f [guid]::NewGuid().ToString('N'))
    try {
      $data = @(
        [pscustomobject]@{ Name = 'Alice'; Score = 95 }
        [pscustomobject]@{ Name = 'Bob'; Score = 87 }
      )
      Save-Csv -InputObject $data -Path $tmp
      Test-Path -LiteralPath $tmp | Should -Be $true
      $lines = Get-Content -LiteralPath $tmp
      # First line should be header
      $lines[0] | Should -Match 'Name'
      $lines[0] | Should -Match 'Score'
      # Should have header + 2 data rows
      $lines.Count | Should -BeGreaterOrEqual 3
    } finally {
      if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
    }
}

function Test-SerializationWritesAnExplicitUTF8BOMForOperatorFacingCSVOutput {
    $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("ser-bom-{0}.csv" -f [guid]::NewGuid().ToString('N'))
    try {
      Save-Csv -InputObject @([pscustomobject]@{ Name = 'Alice' }) -Path $tmp
      $bytes = [System.IO.File]::ReadAllBytes($tmp)
      $bytes[0] | Should -Be 0xEF
      $bytes[1] | Should -Be 0xBB
      $bytes[2] | Should -Be 0xBF
    } finally {
      if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
    }
}

function Test-SerializationAllowsDoubleDotsInsideCSVFileNameSegment {
    $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("ser-csv-name..dots-{0}.csv" -f [guid]::NewGuid().ToString('N'))
    try {
      Save-Csv -InputObject @([pscustomobject]@{ Name = 'Alice' }) -Path $tmp
      Test-Path -LiteralPath $tmp | Should -Be $true
    } finally {
      if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
    }
}

function Test-SerializationHandlesSpecialCharactersInValues {
    $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("ser-csv-special-{0}.csv" -f [guid]::NewGuid().ToString('N'))
    try {
      $data = @(
        [pscustomobject]@{ Name = 'O''Brien'; Message = 'Hello, "World"' }
      )
      Save-Csv -InputObject $data -Path $tmp
      Test-Path -LiteralPath $tmp | Should -Be $true
      $content = Get-Content -LiteralPath $tmp -Raw
      $content | Should -Match 'Brien'
    } finally {
      if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
    }
}

function Test-SerializationNeutralizesSpreadsheetFormulasAfterLeadingWhitespaceOrControlCharacters {
    $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("ser-csv-formula-{0}.csv" -f [guid]::NewGuid().ToString('N'))
    try {
      $controlPrefix = ([char]1) + '=HYPERLINK("https://example.test")'
      Save-Csv -InputObject @(
        [pscustomobject]@{ Value = '=1+1' },
        [pscustomobject]@{ Value = ' +SUM(A1:A2)' },
        [pscustomobject]@{ Value = $controlPrefix }
      ) -Path $tmp

      $values = @(Import-Csv -LiteralPath $tmp | ForEach-Object Value)
      $values | Should -Be @("'=1+1", "' +SUM(A1:A2)", ("'" + $controlPrefix))
    } finally {
      if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
    }
}

function Test-SerializationKeepsJSONValuesLossless {
    $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("ser-json-lossless-{0}.json" -f [guid]::NewGuid().ToString('N'))
    try {
      Save-Json -InputObject ([pscustomobject]@{ Value = '=1+1' }) -Path $tmp
      (Get-Content -LiteralPath $tmp -Raw | ConvertFrom-Json).Value | Should -Be '=1+1'
    } finally {
      if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
    }
}

function Test-SerializationAutoCreatesParentDirectoryForCSV {
    $tmpDir = Join-Path ([System.IO.Path]::GetTempPath()) ("ser-csvdir-{0}" -f [guid]::NewGuid().ToString('N'))
    $tmp = Join-Path $tmpDir 'output.csv'
    try {
      Save-Csv -InputObject @([pscustomobject]@{ A = 1 }) -Path $tmp
      Test-Path -LiteralPath $tmp | Should -Be $true
    } finally {
      if (Test-Path -LiteralPath $tmpDir) { Remove-Item -LiteralPath $tmpDir -Recurse -Force -ErrorAction SilentlyContinue }
    }
}

function Test-SerializationTreatsConsoleAndNoneFormatsAsIntentionalNoOps {
    $obj = Get-V2ResultObject -ScriptName 'x.ps1' -Mode 'Audit' -Result 'OK' -Findings @() -Summary @{} -Metadata @{}

    @(Write-ResultObject -ResultObject $obj -OutputFormat Console 6>&1) | Should -HaveCount 0
    @(Write-ResultObject -ResultObject $obj -OutputFormat None 6>&1) | Should -HaveCount 0
}

function Test-SerializationWritesJSONFileWhenOutputPathIsProvided {
    $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("wr-json-{0}.json" -f [guid]::NewGuid().ToString('N'))
    try {
      $obj = Get-V2ResultObject -ScriptName 'x.ps1' -Mode 'Audit' -Result 'OK' -Findings @() -Summary @{} -Metadata @{}
      Write-ResultObject -ResultObject $obj -OutputFormat Json -OutputPath $tmp
      Test-Path -LiteralPath $tmp | Should -Be $true
    } finally {
      if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
    }
}

function Test-SerializationWritesCSVFileWhenOutputPathIsProvided {
    $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("wr-csv-{0}.csv" -f [guid]::NewGuid().ToString('N'))
    try {
      $findings = @([pscustomobject]@{ Code = 'T1'; Severity = 'High'; Message = 'fail' })
      $obj = Get-V2ResultObject -ScriptName 'x.ps1' -Mode 'Audit' -Result 'FAIL' -Findings $findings -Summary @{} -Metadata @{}
      Write-ResultObject -ResultObject $obj -OutputFormat Csv -OutputPath $tmp
      Test-Path -LiteralPath $tmp | Should -Be $true
    } finally {
      if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
    }
  }
