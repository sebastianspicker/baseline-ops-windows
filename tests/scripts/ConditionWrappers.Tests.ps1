#requires -version 5.1
<#
.SYNOPSIS
Guards capabilities against scriptblock condition wrappers.
.DESCRIPTION
Parses every scripts/**/*.ps1 file and fails when it defines or calls
Test-AllConditions or Test-AnyCondition. Those wrappers evaluated boolean
conditions through dot-sourced scriptblocks only to hide -and/-or from the
cyclomatic-complexity metric; capabilities use native boolean operators and
extract named predicate functions instead. Sites that must keep a wrapper are
listed in the allowlist below with the reason; the list is currently empty.
#>

BeforeAll {
  $script:root = Resolve-Path (Join-Path $PSScriptRoot '../..')
  $script:wrapperNames = @('Test-AllConditions', 'Test-AnyCondition')
  # Keys are 'relative/path.ps1:WrapperName'; values state why the site is kept.
  $script:allowlist = @{}

  function Get-ConditionWrapperSite {
    $scriptsRoot = Join-Path $script:root 'scripts'
    foreach ($file in @(Get-ChildItem -LiteralPath $scriptsRoot -Recurse -File -Filter '*.ps1')) {
      $tokens = $null
      $errors = $null
      $ast = [System.Management.Automation.Language.Parser]::ParseFile($file.FullName, [ref]$tokens, [ref]$errors)
      $relative = $file.FullName.Substring(([string]$script:root).Length + 1).Replace('\', '/')
      $nodes = $ast.FindAll({
          param($node)
          ($node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $script:wrapperNames -contains $node.Name) -or
          ($node -is [System.Management.Automation.Language.CommandAst] -and $script:wrapperNames -contains $node.GetCommandName())
        }, $true)
      foreach ($node in @($nodes)) {
        $name = if ($node -is [System.Management.Automation.Language.FunctionDefinitionAst]) { $node.Name } else { $node.GetCommandName() }
        [pscustomobject]@{ Key = "${relative}:$name"; Line = $node.Extent.StartLineNumber }
      }
    }
  }
}

Describe 'capability condition wrappers' {
  It 'no script defines or calls Test-AllConditions or Test-AnyCondition outside the allowlist' {
    $violations = @(Get-ConditionWrapperSite | Where-Object { -not $script:allowlist.ContainsKey($_.Key) } |
        ForEach-Object { '{0} (line {1})' -f $_.Key, $_.Line })
    ($violations -join [Environment]::NewLine) | Should -BeNullOrEmpty
  }

  It 'every allowlist entry still matches a site and states a reason' {
    $keys = @(Get-ConditionWrapperSite | ForEach-Object { $_.Key })
    foreach ($entry in $script:allowlist.GetEnumerator()) {
      $keys | Should -Contain $entry.Key
      [string]$entry.Value | Should -Not -BeNullOrEmpty
    }
  }
}
