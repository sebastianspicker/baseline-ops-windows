#requires -version 5.1
<#
.SYNOPSIS
Regression coverage for the public-surface verifier.

.DESCRIPTION
Verifies that sensitive local artifact names remain ignored and are rejected
by the tracked public-surface policy.
#>

BeforeAll {
  $verifyPath = Join-Path $PSScriptRoot '../../tools/verify.ps1'
  $tokens = $null
  $parseErrors = $null
  $ast = [System.Management.Automation.Language.Parser]::ParseFile($verifyPath, [ref]$tokens, [ref]$parseErrors)
  $parseErrors.Count | Should -Be 0
  $publicSurfaceFunctions = $ast.FindAll({
    param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst]
  }, $true)
  $script:VerifyTestModule = New-Module -Name VerifyPublicSurfaceContract -ScriptBlock ([scriptblock]::Create(
    (($publicSurfaceFunctions | ForEach-Object { $_.Extent.Text }) -join "`n") + "`nExport-ModuleMember -Function Test-PublicSurfacePath"
  ))
  Import-Module $script:VerifyTestModule -Force
  $script:GitIgnoreLines = @(Get-Content -LiteralPath (Join-Path $PSScriptRoot '../../.gitignore'))
}

AfterAll {
  Remove-Module VerifyPublicSurfaceContract -Force -ErrorAction SilentlyContinue
}

Describe 'tools/verify.ps1 secret and evidence filename policy' -Tag 'Security' {
  It 'retains every secret and evidence ignore pattern' -ForEach @(
    '*.local', '*.local.*', '*.db', '*.sqlite', '*.sqlite3', '*.keystore',
    '.npmrc', '.pypirc', 'client_secret*.json', 'service-account*.json', '*.pvk', '*.snk'
  ) {
    $script:GitIgnoreLines | Should -Contain $_
  }

  It 'rejects secret and evidence filenames even when they are tracked' -ForEach @(
    'settings.local',
    'settings.local.production',
    'evidence.db',
    'cache.sqlite',
    'cache.sqlite3',
    'release.keystore'
  ) {
    Test-PublicSurfacePath -RelativePath $_ | Should -Be 'local secret, database, or keystore file'
  }

  It 'rejects credential filenames even when they are tracked' -ForEach @(
    '.npmrc',
    '.pypirc',
    'client_secret-production.json',
    'service-account-production.json',
    'signing.pvk',
    'signing.snk'
  ) {
    Test-PublicSurfacePath -RelativePath $_ | Should -Be 'environment, credential, key, or certificate file'
  }
}
