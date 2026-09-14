#requires -version 5.1
<#
.SYNOPSIS
Refreshes deterministic structural v2 oracle bindings.

.DESCRIPTION
Recomputes each entry script and extracted companion source closure, then writes
data-only structural fixtures. It does not import or invoke a legacy capability
and does not create behavioral parity evidence.
#>
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$oracleRoot = $PSScriptRoot
. (Join-Path $oracleRoot 'Oracle.Common.ps1')
$repositoryRoot = (Resolve-Path -LiteralPath (Join-Path $oracleRoot '../..')).Path
$manifestPath = Join-Path $oracleRoot 'v2-capability-manifests.json'
$fixturePath = Join-Path $oracleRoot 'v2-neutral-fixtures.json'
$behavioralPath = Join-Path $oracleRoot 'v2-rust-behavioral-cases.json'
$manifestDocument = Get-Content -LiteralPath $manifestPath -Raw -Encoding UTF8 | ConvertFrom-Json
$ledgerPath = Join-Path $repositoryRoot 'rust/ledger/capability-parity.json'
$ledger = Get-Content -LiteralPath $ledgerPath -Raw -Encoding UTF8 | ConvertFrom-Json
$utf8 = New-Object System.Text.UTF8Encoding($false)

function Get-SourceClosure {
  [OutputType([pscustomobject])]
  param([Parameter(Mandatory)] [string]$LegacyScript)

  $sourcePaths = New-Object 'System.Collections.Generic.List[string]'
  $sourcePaths.Add($LegacyScript)
  $stem = [System.IO.Path]::GetFileNameWithoutExtension($LegacyScript)
  foreach ($suffix in @('helpers', 'runtime')) {
    $companion = 'scripts/internal/{0}.{1}.ps1' -f $stem, $suffix
    if (Test-Path -LiteralPath (Join-Path $repositoryRoot $companion) -PathType Leaf) {
      $sourcePaths.Add($companion)
    }
  }

  $sourceFiles = @(
    foreach ($relativePath in $sourcePaths) {
      $bytes = [System.IO.File]::ReadAllBytes((Join-Path $repositoryRoot $relativePath))
      [ordered]@{ path = $relativePath; sha256 = Get-RustV3OracleSha256 -Bytes $bytes }
    }
  )
  $closureIndex = -join @($sourceFiles | ForEach-Object { '{0}  {1}' -f $_.sha256, $_.path; "`n" })
  [pscustomobject]@{
    Files = $sourceFiles
    Digest = Get-RustV3OracleSha256 -Bytes $utf8.GetBytes($closureIndex)
  }
}

function Get-NeutralTypedInput {
  param($Manifest)
  return [ordered]@{
    mode = 'Audit'
    config_path = ('fixture://{0}/profile-v2.json' -f $Manifest.capability_id)
    output_format = 'Json'
    output_path = ('fixture://{0}/result.json' -f $Manifest.capability_id)
    pass_thru = $true
    strict = $false
    quiet = $true
    no_color = $true
  }
}

function Get-RustV3OracleManifestSet {
  @(
    foreach ($manifest in @($manifestDocument.manifests | Sort-Object number)) {
      $closure = Get-SourceClosure -LegacyScript $manifest.legacy_script
      $ledgerEntry = @($ledger.entries | Where-Object { $_.id -eq $manifest.capability_id })
      if ($ledgerEntry.Count -ne 1) { throw "Ledger binding is missing or duplicated for $($manifest.capability_id)." }
      [ordered]@{
        number = $manifest.number
        capability_id = $manifest.capability_id
        legacy_script = $manifest.legacy_script
        source_sha256 = $closure.Files[0].sha256
        source_files = $closure.Files
        source_closure_sha256 = $closure.Digest
        fixture_id = $manifest.fixture_id
        rust_maturity = $ledgerEntry[0].status
      }
    }
  )
}

function Get-RustV3OracleFixtureSet {
  param($Manifests)
  @(
    foreach ($manifest in $Manifests) {
      [ordered]@{
        fixture_id = $manifest.fixture_id
        fixture_kind = 'structural_binding'
        proof_scope = 'structure_only'
        capability_id = $manifest.capability_id
        source_sha256 = $manifest.source_sha256
        source_closure_sha256 = $manifest.source_closure_sha256
        typed_input = Get-NeutralTypedInput -Manifest $manifest
        normalized_observation = [ordered]@{
          kind = 'neutral'
          complete = $false
          evidence = @()
          values = [ordered]@{ capability_number = $manifest.number }
        }
        limitations = @(
          'This structural fixture does not execute either implementation.',
          'It is not behavioral parity or Windows runtime evidence.'
        )
        intentional_safe_parity_differences = @(
          'The fixture never grants legacy paths, commands, native output, or mutation authority.'
        )
      }
    }
  )
}

function Write-RustV3OracleJson {
  param([string]$Path, $Document)
  [System.IO.File]::WriteAllText($Path, ($Document | ConvertTo-Json -Depth 10) + "`n", $utf8)
}

function Update-RustV3OracleBehavioralBindings {
  param($Manifests)
  $document = Get-Content -LiteralPath $behavioralPath -Raw -Encoding UTF8 | ConvertFrom-Json
  foreach ($case in @($document.cases)) {
    $manifest = @($Manifests | Where-Object { $_.capability_id -eq $case.capability_id })
    if ($manifest.Count -ne 1) { throw "Behavioral source binding is missing or duplicated for $($case.id)." }
    if ($case.PSObject.Properties['source_closure_sha256']) {
      $case.source_closure_sha256 = $manifest[0].source_closure_sha256
    }
    else {
      $case | Add-Member -NotePropertyName source_closure_sha256 -NotePropertyValue $manifest[0].source_closure_sha256
    }
  }
  Write-RustV3OracleJson -Path $behavioralPath -Document $document
}

$manifests = Get-RustV3OracleManifestSet
$fixtures = Get-RustV3OracleFixtureSet -Manifests $manifests
Write-RustV3OracleJson -Path $manifestPath -Document ([ordered]@{
  schema_version = 2
  purpose = 'Tracked v2 source closures and structural bindings for Rust v3 capability work. Behavioral proof is stored separately.'
  manifests = $manifests
})
Write-RustV3OracleJson -Path $fixturePath -Document ([ordered]@{
  schema_version = 2
  purpose = 'Deterministic structural bindings. Executable comparisons are stored in v2-rust-behavioral-cases.json.'
  fixtures = $fixtures
})
Update-RustV3OracleBehavioralBindings -Manifests $manifests
