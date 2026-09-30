#requires -version 5.1
<#
.SYNOPSIS
Case tables and assertions for the examples characterization tests.
.DESCRIPTION
Holds the reviewed example inventory tables and the Test-Example* behavior functions
invoked by Examples.Tests.ps1.
#>

function Get-ExampleProfileCases {
  return @(
    @{ File = 'baseline-audit.json'; Mode = 'Audit'; Steps = 3 }
    @{ File = 'compliance-full.json'; Mode = 'Audit'; Steps = 12 }
    @{ File = 'endpoint-health-check.json'; Mode = 'Audit'; Steps = 10 }
    @{ File = 'full-audit.json'; Mode = 'Audit'; Steps = 42 }
    @{ File = 'hardening-remediate.json'; Mode = 'Remediate'; Steps = 3 }
    @{ File = 'incident-response.json'; Mode = 'Audit'; Steps = 7 }
    @{ File = 'rapid-triage.json'; Mode = 'Audit'; Steps = 3 }
  )
}

function Get-ExampleConfigCases {
  return @(
    @{ File = 'asr-defender-allowlist.json'; Keys = @('Defender', 'ASR', 'CFA') }
    @{ File = 'firewall-baseline.json'; Keys = @('Profiles', 'DisableInboundByNameLike', 'EnsureRules') }
    @{ File = 'local-admins-allowlist.json'; Keys = @('LocalAdmins') }
    @{ File = 'wufb-proofing.json'; Keys = @('UpdateSource', 'WSUS', 'AllowMU', 'Deferrals', 'TargetRelease', 'ActiveHours', 'DeliveryOptimization', 'Proof') }
  )
}

function Test-ExampleShipsExactlyTheSevenDocumentedProfiles {
  $names = @(Get-ChildItem -LiteralPath (Join-Path $script:root 'examples/profiles') -Filter '*.json' | Select-Object -ExpandProperty Name | Sort-Object)
  $names | Should -Be @('baseline-audit.json', 'compliance-full.json', 'endpoint-health-check.json', 'full-audit.json', 'hardening-remediate.json', 'incident-response.json', 'rapid-triage.json')
}

function Test-ExampleShipsExactlyTheFourDocumentedCapabilityInputs {
  $names = @(Get-ChildItem -LiteralPath (Join-Path $script:root 'examples/configs') -Filter '*.json' | Select-Object -ExpandProperty Name | Sort-Object)
  $names | Should -Be @('asr-defender-allowlist.json', 'firewall-baseline.json', 'local-admins-allowlist.json', 'wufb-proofing.json')
}

function Test-ExampleReadmeListsEveryExampleFile {
  $readme = Get-Content -LiteralPath (Join-Path $script:root 'examples/README.md') -Raw
  $files = Get-ChildItem -LiteralPath (Join-Path $script:root 'examples') -Recurse -Filter '*.json' | Select-Object -ExpandProperty Name
  $files | Should -HaveCount 11
  foreach ($file in $files) { $readme | Should -Match ([regex]::Escape($file)) }
}

function Test-ExampleProfileValidatesCleanly {
  param([string]$File)
  $path = Join-Path $script:root "examples/profiles/$File"
  $output = Join-Path $TestDrive "result-$File"
  $null = & (Get-Process -Id $PID).Path -NoProfile -File (Join-Path $script:root 'scripts/00-Validate-Profile.ps1') -ProfilePath $path -RootPath $script:root -OutputFormat Json -OutputPath $output -Quiet -NoColor 2>&1
  $LASTEXITCODE | Should -Be 0
  $result = Get-Content -LiteralPath $output -Raw | ConvertFrom-Json
  $result.Result | Should -Be 'OK'
  @($result.Findings) | Should -HaveCount 0
}

function Test-ExampleProfileDeclaresModeAndSteps {
  param([string]$File, [string]$Mode, [int]$Steps)
  $doc = Get-Content -LiteralPath (Join-Path $script:root "examples/profiles/$File") -Raw | ConvertFrom-Json
  $doc.Version | Should -Be '2.0'
  $doc.Defaults.Mode | Should -Be $Mode
  @($doc.Steps) | Should -HaveCount $Steps
  foreach ($step in $doc.Steps) { @($step.Args) | Should -HaveCount 0 }
  $doc.Integrity.RequireSigned | Should -BeFalse
  @($doc.Integrity.ExpectedHashes.PSObject.Properties) | Should -HaveCount 0
}

function Test-ExampleProfileHasV2TopLevelShape {
  param([string]$File)
  $doc = Get-Content -LiteralPath (Join-Path $script:root "examples/profiles/$File") -Raw | ConvertFrom-Json
  @($doc.PSObject.Properties.Name) | Should -Be @('_NOTE', 'ProfileName', 'Version', 'Defaults', 'Steps', 'Integrity')
}

function Test-ExampleConfigParsesAsBoundedJson {
  param([string]$File, [string[]]$Keys)
  $read = Read-BoundedUtf8JsonInput -Path (Join-Path $script:root "examples/configs/$File")
  $read.ParseError | Should -BeNullOrEmpty
  $read.Text | Should -Not -BeNullOrEmpty
  @($read.Data.PSObject.Properties.Name) | Should -Be $Keys
}

function Test-ExampleBoundedReaderRejectsOversizedFile {
  $big = Join-Path $TestDrive 'big.json'
  Set-Content -LiteralPath $big -Value ('{"a":"' + ('x' * 2048) + '"}') -Encoding UTF8
  { Read-BoundedUtf8JsonInput -Path $big -MaximumBytes 1024 } | Should -Throw
}
