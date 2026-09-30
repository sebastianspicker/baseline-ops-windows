#requires -version 5.1
<#
.SYNOPSIS
Portable regression tests for Windows-only capability code paths.
.DESCRIPTION
Drives the remediation and presentation paths of capabilities 07, 18, 24, and
32 that previously failed under Set-StrictMode -Version Latest with unbound
parameters or never-assigned variables. Windows cmdlets are stubbed and mocked.
#>

BeforeAll {
  . (Join-Path $PSScriptRoot 'CapabilityRegression.Cases.ps1')
  $script:repoRoot = Get-CapabilityRegressionRoot
}

Describe '18-Firewall-Baseline remediation' -Tag 'FirewallBaseline' {
  BeforeAll {
    Register-FirewallBaselineStub
    Import-Module (Join-Path $script:repoRoot 'lib/Results.psm1') -Force
    . (Join-Path $script:repoRoot 'scripts/internal/18-Firewall-Baseline.helpers.ps1')
    . (Get-CapabilityFunctionSource -RelativePath 'scripts/18-Firewall-Baseline.ps1')
  }
  BeforeEach { Set-FirewallBaselineMock }
  AfterAll { Remove-FirewallStub }

  It 'remediates profile logging settings instead of failing on unset values' { Test-FirewallBaselineProfileRemediation }
  It 'disables risky inbound rules and creates missing rules in Remediate mode' { Test-FirewallBaselineRuleRemediation }
  It 'leaves rules untouched in Audit mode' { Test-FirewallBaselineAuditLeavesRulesUntouched }
}

Describe '32-Firewall-Logging-Audit remediation' -Tag 'FirewallLogging' {
  BeforeAll {
    Register-FirewallLoggingStub
    . (Get-CapabilityFunctionSource -RelativePath 'scripts/32-Firewall-Logging-Audit.ps1')
  }
  BeforeEach { Set-FirewallLoggingMock }
  AfterAll { Remove-FirewallStub }

  It 'applies each drifted logging setting through ShouldProcess' { Test-FirewallLoggingAppliesDriftedSettings }
  It 'honors -WhatIf without changing the profile' { Test-FirewallLoggingHonorsWhatIf }
}

Describe '24-Cert-AutoEnrollment-Health console summary' -Tag 'CertAutoEnrollment' {
  BeforeAll {
    Import-Module (Join-Path $script:repoRoot 'lib/Output.psm1') -Force
    . (Get-CapabilityFunctionSource -RelativePath 'scripts/24-Cert-AutoEnrollment-Health.ps1')
  }

  It 'renders every summary field through Write-KeyValue' { Test-CertAutoEnrollmentSummaryRendersFields }
}

Describe '07-ScheduledTasks-Hygiene catalog normalization' -Tag 'ScheduledTasksHygiene' {
  BeforeAll {
    . (Join-Path $script:repoRoot 'scripts/internal/07-ScheduledTasks-Hygiene.helpers.ps1')
    . (Join-Path $script:repoRoot 'scripts/internal/07-ScheduledTasks-Hygiene.catalog.ps1')
  }

  It 'fills omitted output settings from the fallback catalog' { Test-ScheduledTaskCatalogFillsOutputDefaults }
}
