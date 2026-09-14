<#
.SYNOPSIS
  Checks the browser tour's reviewed publication paths.
.DESCRIPTION
  Accepts only named demo assets and rejects adjacent unreviewed documentation.
#>

BeforeAll {
  $source = Join-Path $PSScriptRoot '../../tools/verify.ps1'
  $ast = [System.Management.Automation.Language.Parser]::ParseFile($source, [ref]$null, [ref]$null)
  $function = $ast.Find({
    param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
      $node.Name -eq 'Test-ReviewedPublicDocumentationPath'
  }, $true)
  . ([scriptblock]::Create($function.Extent.Text))
}

Describe 'Reviewed browser documentation surface' {
  It 'accepts the reviewed demo assets' -ForEach @(
    'docs/demo.md', 'docs/demo/index.html', 'docs/demo/styles.css',
    'docs/demo/app.js', 'docs/demo/profiles.json',
    'docs/screenshots/01-profiles.png', 'docs/screenshots/02-command.png',
    'docs/screenshots/03-result.png'
  ) {
    Test-ReviewedPublicDocumentationPath -Path $_ -Segments $_.Split('/') | Should -BeNullOrEmpty
  }

  It 'rejects unreviewed files alongside the demo' -ForEach @(
    'docs/demo/endpoint-results.json', 'docs/demo/unreviewed.js',
    'docs/screenshots/real-endpoint.png'
  ) {
    Test-ReviewedPublicDocumentationPath -Path $_ -Segments $_.Split('/') | Should -Be 'documentation path is not in the reviewed public allowlist'
  }
}
