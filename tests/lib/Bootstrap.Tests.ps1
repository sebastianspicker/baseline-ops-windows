<#
.SYNOPSIS
  Verifies the import order contract of scripts/_lib/Bootstrap.ps1.
.DESCRIPTION
  Bootstrap.ps1 calls Get-V2ResultObject and Get-V2ExitCode (from
  Serialization.psm1) when Initialize-V2Context rejects the output
  configuration, but it never imports that module itself. Each entry script must
  therefore import Serialization.psm1 before its first Initialize-V2Context call.
#>

BeforeAll {
  $script:ScriptsRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../../scripts'))

  function Get-OwnCommandAst {
    param([Parameter(Mandatory)][System.Management.Automation.Language.Ast]$Statement)

    # Commands inside function definitions run only when the function is called.
    $Statement.FindAll({
        param($node)
        if ($node -isnot [System.Management.Automation.Language.CommandAst]) { return $false }
        for ($parent = $node.Parent; $null -ne $parent -and $parent -ne $Statement.Parent; $parent = $parent.Parent) {
          if ($parent -is [System.Management.Automation.Language.FunctionDefinitionAst]) { return $false }
        }
        return $true
      }, $true)
  }

  function Get-DotSourcedRelativePath {
    param([Parameter(Mandatory)][System.Management.Automation.Language.Ast]$Statement)

    foreach ($command in @(Get-OwnCommandAst -Statement $Statement)) {
      if ($command.InvocationOperator -ne [System.Management.Automation.Language.TokenKind]::Dot) { continue }
      $literals = @($command.CommandElements[0].FindAll({
            param($node) $node -is [System.Management.Automation.Language.StringConstantExpressionAst]
          }, $true))
      if ($literals.Count -gt 0) { return [string]$literals[-1].Value }
    }
    return $null
  }

  function Expand-EntryStatement {
    param(
      [Parameter(Mandatory)][string]$Path,
      [Parameter(Mandatory)][AllowEmptyCollection()][System.Collections.Generic.List[object]]$Statements,
      [Parameter(Mandatory)][AllowEmptyCollection()][System.Collections.Generic.List[object]]$Functions
    )

    $tokens = $null
    $errors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$tokens, [ref]$errors)
    @($errors).Count | Should -Be 0 -Because "$Path must parse"
    foreach ($function in $ast.FindAll({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)) {
      $Functions.Add($function)
    }

    # Top-level dot-sourced internal files run inline, so expand them in place.
    foreach ($statement in $ast.EndBlock.Statements) {
      $relative = Get-DotSourcedRelativePath -Statement $statement
      if ($relative -and $relative -ne '_lib/Bootstrap.ps1') {
        # Dot-sourced paths are relative to the file that contains them.
        $target = [System.IO.Path]::GetFullPath((Join-Path (Split-Path -Parent $Path) $relative))
        if ($target.StartsWith((Join-Path $script:ScriptsRoot 'internal'), [System.StringComparison]::Ordinal) -and
          (Test-Path -LiteralPath $target -PathType Leaf)) {
          Expand-EntryStatement -Path $target -Statements $Statements -Functions $Functions
          continue
        }
      }
      $Statements.Add([pscustomobject]@{ Ast = $statement; Bootstrap = ($relative -eq '_lib/Bootstrap.ps1') })
    }
  }

  function Add-CommandEvent {
    param(
      [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Commands,
      [Parameter(Mandatory)][hashtable]$FunctionBodies,
      [Parameter(Mandatory)][AllowEmptyCollection()][System.Collections.Generic.List[string]]$Events,
      [AllowEmptyCollection()][string[]]$Active = @()
    )

    # Commands are visited in source order; a call to a script-defined function
    # is expanded in place so events inside it are ordered at the call site.
    foreach ($command in $Commands) {
      $name = [string]$command.GetCommandName()
      if ($name -eq 'Import-Module' -and $command.Extent.Text -match 'Serialization\.psm1') {
        $Events.Add('Import')
      } elseif ($name -eq 'Initialize-V2Context') {
        $Events.Add('Reach')
      } elseif ($FunctionBodies.ContainsKey($name) -and $Active -notcontains $name) {
        $bodyCommands = @($FunctionBodies[$name].FindAll({ param($node) $node -is [System.Management.Automation.Language.CommandAst] }, $true))
        Add-CommandEvent -Commands $bodyCommands -FunctionBodies $FunctionBodies -Events $Events -Active (@($Active) + $name)
      }
    }
  }

  function Get-EntryOrderFacts {
    param([Parameter(Mandatory)][string]$Path)

    $statements = New-Object 'System.Collections.Generic.List[object]'
    $functions = New-Object 'System.Collections.Generic.List[object]'
    Expand-EntryStatement -Path $Path -Statements $statements -Functions $functions
    $functionBodies = @{}
    foreach ($function in $functions) { $functionBodies[$function.Name] = $function.Body }

    $events = New-Object 'System.Collections.Generic.List[string]'
    foreach ($entry in $statements) {
      if ($entry.Bootstrap) { $events.Add('Bootstrap') }
      Add-CommandEvent -Commands @(Get-OwnCommandAst -Statement $entry.Ast) -FunctionBodies $functionBodies -Events $events
    }
    return [pscustomobject]@{
      Bootstrap = $events.IndexOf('Bootstrap')
      Import = $events.IndexOf('Import')
      Reach = $events.IndexOf('Reach')
    }
  }
}

Describe 'Bootstrap.ps1 Serialization dependency' {
  It 'calls Get-V2ResultObject and Get-V2ExitCode without importing Serialization.psm1' {
    $source = Get-Content -LiteralPath (Join-Path $script:ScriptsRoot '_lib/Bootstrap.ps1') -Raw
    $source | Should -Match 'Get-V2ResultObject'
    $source | Should -Match 'Get-V2ExitCode'
    $source | Should -Not -Match 'Serialization\.psm1'
  }

  It 'imports Serialization.psm1 before the first Initialize-V2Context call in every Bootstrap entry script' {
    $checked = 0
    foreach ($script in Get-ChildItem -LiteralPath $script:ScriptsRoot -Filter '*.ps1' -File) {
      $facts = Get-EntryOrderFacts -Path $script.FullName
      if ($facts.Bootstrap -lt 0 -or $facts.Reach -lt 0) { continue }
      $checked++
      $facts.Import | Should -BeGreaterOrEqual 0 -Because "$($script.Name) must import Serialization.psm1"
      $facts.Bootstrap | Should -BeLessThan $facts.Reach -Because "$($script.Name) dot-sources Bootstrap.ps1 first"
      $facts.Import | Should -BeLessThan $facts.Reach -Because (
        "$($script.Name) must import Serialization.psm1 before it reaches Initialize-V2Context")
    }
    # 01-52 plus 00-Report-Aggregate, 00-Run-Batch, and 00-Validate-Profile.
    $checked | Should -BeGreaterOrEqual 55
  }
}
