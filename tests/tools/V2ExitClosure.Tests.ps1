#requires -version 5.1
<#
.SYNOPSIS
  Verifies static v2 exit checks follow only called capability helpers.
.DESCRIPTION
  Protects the early-exit output assertion from accepting an unrelated serializer definition.
#>

BeforeAll {
  . (Join-Path $PSScriptRoot '../scripts/V2Contract.Cases.ps1')
  function New-ExitClosureFixture {
    param([string]$Source)
    $tokens = $null
    $errors = $null
    $ast = [Management.Automation.Language.Parser]::ParseInput($Source, [ref]$tokens, [ref]$errors)
    @($errors) | Should -HaveCount 0
    $functions = @{}
    foreach ($definition in @($ast.FindAll({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] }, $true))) {
      $functions[$definition.Name] = $definition.Body
    }
    $branch = $ast.Find({ param($node) $node -is [Management.Automation.Language.IfStatementAst] }, $true)
    return @{ Block = $branch.Clauses[0].Item2; Functions = $functions }
  }
}

Describe 'V2 early exit helper closure' {
  It 'does not accept an unrelated serializer definition as early-exit output' {
    $fixture = New-ExitClosureFixture 'function Write-Unused { Get-V2ResultObject }; if ($true) { exit 2 }'
    Get-V2CalledClosureText @fixture | Should -Not -Match 'Get-V2ResultObject'
  }

  It 'follows the actual helper chain while bounding recursive calls' {
    $fixture = New-ExitClosureFixture 'function Write-First { Write-Second }; function Write-Second { Get-V2ResultObject; Write-First }; if ($true) { Write-First; exit 2 }'
    $source = Get-V2CalledClosureText @fixture
    $source | Should -Match 'Get-V2ResultObject'
    ([regex]::Matches($source, 'Get-V2ResultObject')).Count | Should -Be 1
  }
}
