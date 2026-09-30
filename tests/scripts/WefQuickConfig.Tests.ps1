#requires -version 5.1
<#
.SYNOPSIS
Regression tests for the WEF readiness quick-config check.
.DESCRIPTION
Proves 45-WEF-Client-Forwarding-Readiness-Audit runs `wecutil qc /q` only when
ShouldProcess approves, reports non-zero exits, and keeps output streams apart.
#>

BeforeAll {
  . (Join-Path $PSScriptRoot 'CapabilityRegression.Cases.ps1')
  $script:repoRoot = Get-CapabilityRegressionRoot
}

Describe '45-WEF-Client-Forwarding-Readiness-Audit quick-config' -Tag 'WefReadiness' {
  BeforeAll {
    Import-Module (Join-Path $script:repoRoot 'lib/Results.psm1') -Force
    . (Get-CapabilityFunctionSource -RelativePath 'scripts/45-WEF-Client-Forwarding-Readiness-Audit.ps1')
  }

  It 'does not run wecutil qc under -WhatIf' { Test-WecutilQuickConfigHonorsWhatIf }
  It 'reports a non-zero wecutil exit code as a failed check' { Test-WecutilQuickConfigReportsNonZeroExit }
  It 'keeps stdout and stderr on separate lines' { Test-WecutilQuickConfigSeparatesStreams }
}
