#requires -version 5.1
<#
.SYNOPSIS
Pester coverage for data-only Rust v3 oracle fixtures.

.DESCRIPTION
Executes the bounded DoH, Windows Update, Security Options, and PowerShell
Logging policy corpus through the actual v2 policy functions. Structural
manifest, fixture, and source-closure bindings are verified only by
`cargo run -p xtask -- verify` in the Rust workspace.
#>

Describe 'Rust v3 legacy oracle manifests' {
  BeforeAll {
    . (Join-Path $PSScriptRoot 'RustV3Oracle.Adapter.ps1')
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
