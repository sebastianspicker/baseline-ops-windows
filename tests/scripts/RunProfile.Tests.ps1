#requires -version 5.1
<#
.SYNOPSIS
Direct profile authority-boundary check.
.DESCRIPTION
Verifies elevated orchestration trusts inputs before repository module loading.
#>
Describe '00-Run-Profile authority boundary' -Tag 'Security' {
  It 'trusts every elevated bootstrap path before repository modules can load' {
    $source = Get-Content -LiteralPath (Join-Path $PSScriptRoot '../../scripts/00-Run-Profile.ps1') -Raw
    $gate = $source.IndexOf('if ($isElevatedWindows)')
    $firstImport = $source.IndexOf("Import-Module (Join-Path `$script:LibPath 'Output.psm1')")

    $gate | Should -BeGreaterThan -1
    $firstImport | Should -BeGreaterThan $gate
    $source | Should -Match '\$trustedBootstrapPaths'
    $source | Should -Match 'Assert-RunProfileTrustedWindowsAcl -Path \$trustedPath'
    $source | Should -Match 'Join-Path \$RootPath ''scripts'''
    $source | Should -Match 'Join-Path \$RootPath ''lib'''
  }
}
