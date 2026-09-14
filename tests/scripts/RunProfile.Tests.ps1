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
    $gate = $source.LastIndexOf('Assert-RunProfileBootstrapTrust $bootstrap $PSScriptRoot')
    $firstImport = $source.LastIndexOf('Import-Module $leaseModulePath -DisableNameChecking')

    $gate | Should -BeGreaterThan -1
    $firstImport | Should -BeGreaterThan $gate
    $source | Should -Match 'Get-RunProfileControlFiles'
    $source | Should -Match 'Assert-RunProfileTrustedWindowsAcl -Path \$trustedPath'
    $source | Should -Match ([regex]::Escape("Join-Path `$Context.RootPath 'scripts'"))
    $source | Should -Match ([regex]::Escape("Join-Path `$Context.RootPath 'lib'"))
  }
}
