#requires -version 5.1
<#
.SYNOPSIS
Pester coverage for security-script contracts.

.DESCRIPTION
Verifies safe, repeatable operator behavior and evidence.
#>

Describe 'Advanced audit policy evidence boundary' {
  BeforeAll {
    $scriptPath = Join-Path $PSScriptRoot '../../scripts/33-AdvancedAuditPolicy-Audit.ps1'
    $tokens = $null
    $errors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$tokens, [ref]$errors)
    $errors | Should -BeNullOrEmpty
    foreach ($name in @('Get-AuditPolText','Parse-AuditPolText')) {
      $definition = @($ast.Find({
          param($node)
          $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name
        }, $true))[0]
      $definition | Should -Not -BeNullOrEmpty
      . ([scriptblock]::Create($definition.Extent.Text))
    }
    function Invoke-Auditpol { throw 'test stub must be mocked' }
  }

  It 'rejects timeout and truncated native evidence' {
    Mock Invoke-Auditpol {
      [pscustomobject]@{ Success = $false; ExitCode = -1; TimedOut = $true; OutputTruncated = $false; StderrTruncated = $false; Stdout = ''; Output = '' }
    }
    { Get-AuditPolText } | Should -Throw '*timed out*'

    Mock Invoke-Auditpol {
      [pscustomobject]@{ Success = $true; ExitCode = 0; TimedOut = $false; OutputTruncated = $true; StderrTruncated = $false; Stdout = 'partial'; Output = 'partial' }
    }
    { Get-AuditPolText } | Should -Throw '*truncated*'
  }

  It 'parses complete positional CSV rows and preserves GUID identity' {
    $header = 'Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting'
    $rows = for ($index = 1; $index -le 10; $index++) {
      $guid = [guid]::NewGuid().ToString('B')
      "host,System,Subcategory $index,$guid,Success and Failure,"
    }

    $parsed = @(Parse-AuditPolText -Text (($header + "`n" + ($rows -join "`n"))))

    $parsed | Should -HaveCount 10
    $parsed[0].SubcategoryGuid | Should -Match '^[a-f0-9-]{36}$'
    $parsed[0].Category | Should -Be '(NotReported)'
  }

  It 'rejects duplicate or implausibly short CSV evidence' {
    $guid = [guid]::NewGuid().ToString('B')
    $header = 'Machine Name,Policy Target,Subcategory,Subcategory GUID,Inclusion Setting,Exclusion Setting'
    $duplicate = @(
      "host,System,Duplicate,$guid,Success,"
      "host,System,Duplicate,$guid,Success,"
    ) -join "`n"

    { Parse-AuditPolText -Text ($header + "`n" + $duplicate) } | Should -Throw '*duplicate*'
    { Parse-AuditPolText -Text ($header + "`nhost,System,Only One,$guid,Success,") } | Should -Throw '*too few*'
  }

  It 'maps incomplete terminal evidence to FAIL in the script source' {
    $source = Get-Content -LiteralPath $scriptPath -Raw
    $source | Should -Match 'resultToken = if \(-not \$auditEvidenceComplete\) \{ ''FAIL'' \}'
    $source | Should -Not -Match 'if \(\$r -and \$r\.Output\)'
  }
}
