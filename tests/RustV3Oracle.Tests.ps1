#requires -version 5.1
<#
.SYNOPSIS
Pester coverage for data-only Rust v3 oracle fixtures.

.DESCRIPTION
Checks every structural binding and the bounded executable DoH, Windows Update,
Security Options, and PowerShell Logging policy corpus.
#>

Describe 'Rust v3 legacy oracle manifests' {
  BeforeAll {
    . (Join-Path $PSScriptRoot 'RustV3Oracle.Adapter.ps1')
  }

  It 'binds all 52 manifests and structural fixtures to live v2 source closures' {
    $result = Test-RustV3OracleDocuments
    $result.Errors | Should -BeNullOrEmpty
    $result.IsValid | Should -BeTrue
    $result.Manifests.Count | Should -Be 52
    $result.Fixtures.Count | Should -Be 52
    @($result.Manifests | Where-Object { $_.source_files.Count -gt 1 }).Count | Should -BeGreaterThan 0
    @($result.Fixtures | Where-Object { $_.proof_scope -ne 'structure_only' }).Count | Should -Be 0
  }

  It 'executes shared policy cases through the actual v2 policy functions' {
    $result = Test-RustV3OracleV2BehavioralCases
    $result.Errors | Should -BeNullOrEmpty
    $result.IsValid | Should -BeTrue
    $result.CaseCount | Should -Be 21
  }

  It 'normalizes a mocked v2 result without treating it as parity evidence' {
    $mockedResult = [pscustomobject]@{
      ScriptName = '52-DoH-Audit.ps1'
      Mode = 'Audit'
      Result = 'WARN'
      Findings = @([pscustomobject]@{ Code = 'DOH-NotConfigured'; Severity = 'Medium'; Message = 'DoH is not configured.' })
      Summary = [pscustomobject]@{ FindingsCount = 1 }
      Metadata = [pscustomobject]@{ UnsupportedHost = $false }
    }
    $normalized = ConvertTo-RustV3OracleNormalizedObservation -V2Result $mockedResult -CapabilityId 'v3.doh.audit'
    $normalized.capability_id | Should -Be 'v3.doh.audit'
    $normalized.normalized_observation.script_name | Should -Be '52-DoH-Audit.ps1'
    $normalized.normalized_observation.result | Should -Be 'WARN'
    $normalized.PSObject.Properties.Name | Should -Not -Contain 'expected'
  }
}
