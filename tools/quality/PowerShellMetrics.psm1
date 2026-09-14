<#
.SYNOPSIS
  Measures PowerShell source against the repository quality ceilings.
.DESCRIPTION
  Uses the PowerShell parser so comments and nested function bodies are handled deterministically.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Test-OffsetInRanges {
  param([int]$Offset, [object[]]$Ranges)

  foreach ($range in $Ranges) {
    if ($Offset -ge $range.Start -and $Offset -le $range.End) { return $true }
  }
  return $false
}

function Get-NestedFunctionRanges {
  param(
    [Parameter(Mandatory)]$ScopeAst,
    [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Functions
  )

  $ranges = @()
  foreach ($functionAst in $Functions) {
    $body = $functionAst.Body
    if ($body -eq $ScopeAst) { continue }
    if (
      $body.Extent.StartOffset -ge $ScopeAst.Extent.StartOffset -and
      $body.Extent.EndOffset -le $ScopeAst.Extent.EndOffset
    ) {
      $ranges += [pscustomobject]@{
        Start = $functionAst.Extent.StartOffset
        End = $functionAst.Extent.EndOffset
      }
    }
  }
  return @($ranges)
}

function Get-TokenNloc {
  param(
    [Parameter(Mandatory)][object[]]$Tokens,
    [Parameter(Mandatory)][int]$StartOffset,
    [Parameter(Mandatory)][int]$EndOffset,
    [object[]]$ExcludedRanges = @()
  )

  $ignoredKinds = @('Comment', 'NewLine', 'LineContinuation', 'EndOfInput')
  $lines = @{}
  foreach ($token in $Tokens) {
    $offset = $token.Extent.StartOffset
    if ($offset -lt $StartOffset -or $offset -gt $EndOffset) { continue }
    if ($ignoredKinds -contains [string]$token.Kind) { continue }
    if (Test-OffsetInRanges -Offset $offset -Ranges $ExcludedRanges) { continue }
    $lines[[int]$token.Extent.StartLineNumber] = $true
  }
  return $lines.Count
}

function Get-BranchIncrement {
  param([Parameter(Mandatory)]$Ast)

  $typeName = $Ast.GetType().Name
  if ($typeName -eq 'IfStatementAst' -or $typeName -eq 'SwitchStatementAst') { return $Ast.Clauses.Count }
  $singleBranches = @(
    'ForStatementAst', 'ForEachStatementAst', 'WhileStatementAst', 'DoWhileStatementAst',
    'DoUntilStatementAst', 'CatchClauseAst', 'TrapStatementAst', 'TernaryExpressionAst'
  )
  if ($singleBranches -contains $typeName) { return 1 }
  if ($typeName -eq 'BinaryExpressionAst' -and @('And', 'Or', 'AndAnd', 'OrOr') -contains [string]$Ast.Operator) {
    return 1
  }
  return 0
}

function Get-ScopeComplexity {
  param(
    [Parameter(Mandatory)]$ScopeAst,
    [object[]]$ExcludedRanges = @()
  )

  $complexity = 1
  $nodes = @($ScopeAst.FindAll({ param($node) $null -ne $node }, $true))
  foreach ($node in $nodes) {
    if (Test-OffsetInRanges -Offset $node.Extent.StartOffset -Ranges $ExcludedRanges) { continue }
    $complexity += Get-BranchIncrement -Ast $node
  }
  return $complexity
}

function New-MetricFinding {
  param(
    [string]$Kind,
    [string]$Path,
    [string]$Symbol,
    [int]$Line,
    [int]$Actual,
    [int]$Limit
  )

  return [pscustomobject]@{
    Kind = $Kind
    Path = $Path
    Symbol = $Symbol
    Line = $Line
    Actual = $Actual
    Limit = $Limit
  }
}

function Get-RelativeQualityPath {
  param([string]$Path, [string]$RootPath)

  $root = [System.IO.Path]::GetFullPath($RootPath).TrimEnd([char[]]@([char]'/', [char]92))
  $full = [System.IO.Path]::GetFullPath($Path)
  if (-not $full.StartsWith($root + [System.IO.Path]::DirectorySeparatorChar, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "Quality target is outside the repository root: $Path"
  }
  return $full.Substring($root.Length + 1).Replace([char]92, [char]47)
}

function Get-ScopeRecords {
  param([Parameter(Mandatory)]$Ast)

  $functions = @($Ast.FindAll({
        param($node)
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst]
      }, $true))
  $records = @([pscustomobject]@{
      Name = '<script>'
      Ast = $Ast.EndBlock
      Parameters = 0
      IsScript = $true
    })
  foreach ($functionAst in $functions) {
    $parameterCount = 0
    if ($functionAst.Parameters) {
      $parameterCount = $functionAst.Parameters.Count
    } elseif ($functionAst.Body.ParamBlock) {
      $parameterCount = $functionAst.Body.ParamBlock.Parameters.Count
    }
    $records += [pscustomobject]@{
      Name = $functionAst.Name
      Ast = $functionAst.Body
      Parameters = $parameterCount
      IsScript = $false
    }
  }
  return [pscustomobject]@{ Functions = $functions; Scopes = $records }
}

function Add-ScopeFindings {
  param(
    [System.Collections.Generic.List[object]]$Findings,
    [object]$Scope,
    [object[]]$Functions,
    [object[]]$Tokens,
    [string]$RelativePath
  )

  $excluded = Get-NestedFunctionRanges -ScopeAst $Scope.Ast -Functions $Functions
  $nloc = Get-TokenNloc -Tokens $Tokens -StartOffset $Scope.Ast.Extent.StartOffset `
    -EndOffset $Scope.Ast.Extent.EndOffset -ExcludedRanges $excluded
  $complexity = Get-ScopeComplexity -ScopeAst $Scope.Ast -ExcludedRanges $excluded
  $line = [int]$Scope.Ast.Extent.StartLineNumber
  if ($nloc -gt 49) {
    $Findings.Add((New-MetricFinding function_nloc $RelativePath $Scope.Name $line $nloc 49))
  }
  if ($complexity -gt 7) {
    $Findings.Add((New-MetricFinding function_ccn $RelativePath $Scope.Name $line $complexity 7))
  }
  if (-not $Scope.IsScript -and $Scope.Parameters -gt 8) {
    $Findings.Add((New-MetricFinding function_parameters $RelativePath $Scope.Name $line $Scope.Parameters 8))
  }
}

function Get-PowerShellMetricFindings {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$RootPath,
    [Parameter(Mandatory)][string[]]$Paths
  )

  if ($Paths.Count -eq 0) { throw 'PowerShell metric scan matched zero files.' }
  $findings = New-Object System.Collections.Generic.List[object]
  foreach ($path in @($Paths | Sort-Object -Unique)) {
    $tokens = $null
    $errors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$tokens, [ref]$errors)
    if ($errors -and $errors.Count -gt 0) { throw "PowerShell parse failure: $path" }
    $relativePath = Get-RelativeQualityPath -Path $path -RootPath $RootPath
    $fileNloc = Get-TokenNloc -Tokens $tokens -StartOffset 0 -EndOffset ([int]::MaxValue)
    if ($fileNloc -gt 499) {
      $findings.Add((New-MetricFinding file_nloc $relativePath '<file>' 1 $fileNloc 499))
    }
    $records = Get-ScopeRecords -Ast $ast
    foreach ($scope in $records.Scopes) {
      Add-ScopeFindings -Findings $findings -Scope $scope -Functions $records.Functions `
        -Tokens $tokens -RelativePath $relativePath
    }
  }
  return @($findings | Sort-Object Path, Line, Kind, Symbol)
}

Export-ModuleMember -Function Get-PowerShellMetricFindings
