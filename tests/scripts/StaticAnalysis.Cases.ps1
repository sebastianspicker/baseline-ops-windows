#requires -version 5.1
<#
.SYNOPSIS
Parser-only scans that find unbound parameters and never-assigned variables.
.DESCRIPTION
Builds each public script's dot-sourced closure (entry script, matching
scripts/internal helpers, and scripts/_lib/Bootstrap.ps1) and inspects it with
the PowerShell AST without executing it. Shared lib modules are imported into
a private runspace only to read exported command metadata. Findings name the
file, line, and symbol; reviewed exceptions live in the allowlists below and
each entry states its reason.
#>

# Keys: '<relative path>|<command>|<parameter>'. Value: reason.
$script:StaticAnalysisParameterAllowlist = @{}

# Keys: '<relative path>|<variable>'. Value: reason.
$script:StaticAnalysisVariableAllowlist = @{}

# Add-Finding declares these in a dynamicparam block (lib/Results.psm1).
$script:StaticAnalysisDynamicParameters = @{ 'Add-Finding' = @('TimeUtc', 'TimestampLocal', 'PassThru') }

$script:StaticAnalysisCommonParameters = @{
  Verbose = 'vb'; Debug = 'db'; ErrorAction = 'ea'; WarningAction = 'wa'; InformationAction = 'infa'
  ProgressAction = 'proga'; ErrorVariable = 'ev'; WarningVariable = 'wv'; InformationVariable = 'iv'
  OutVariable = 'ov'; OutBuffer = 'ob'; PipelineVariable = 'pv'
}

$script:StaticAnalysisAutomaticVariables = @(
  '_', 'args', 'ConfirmPreference', 'ConsoleFileName', 'DebugPreference', 'Error', 'ErrorActionPreference',
  'ErrorView', 'Event', 'EventArgs', 'EventSubscriber', 'ExecutionContext', 'false', 'foreach',
  'FormatEnumerationLimit', 'HOME', 'Host', 'InformationPreference', 'input', 'IsCoreCLR', 'IsLinux',
  'IsMacOS', 'IsWindows', 'LASTEXITCODE', 'Matches', 'MaximumHistoryCount', 'MyInvocation',
  'NestedPromptLevel', 'null', 'OFS', 'OutputEncoding', 'PID', 'ProgressPreference', 'PSBoundParameters',
  'PSCmdlet', 'PSCommandPath', 'PSCulture', 'PSDebugContext', 'PSDefaultParameterValues', 'PSEdition',
  'PSHOME', 'PSItem', 'PSModuleAutoLoadingPreference', 'PSNativeCommandArgumentPassing',
  'PSNativeCommandUseErrorActionPreference', 'PSScriptRoot', 'PSSenderInfo', 'PSStyle', 'PSUICulture',
  'PSVersionTable', 'PWD', 'Sender', 'ShellId', 'SourceArgs', 'SourceEventArgs', 'StackTrace', 'switch',
  'this', 'true', 'VerbosePreference', 'WarningPreference', 'WhatIfPreference'
)

$script:StaticAnalysisVariableParameters = @(
  'OutVariable', 'ov', 'ErrorVariable', 'ev', 'WarningVariable', 'wv', 'InformationVariable', 'iv',
  'PipelineVariable', 'pv', 'BindingVariable'
)

function Get-StaticAnalysisRoot {
  return (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
}

function Get-StaticAnalysisRelativePath {
  param([string]$Path, [string]$RootPath)
  return $Path.Substring($RootPath.Length).TrimStart('\', '/').Replace('\', '/')
}

function Get-StaticAnalysisEntryCases {
  $root = Get-StaticAnalysisRoot
  foreach ($entry in @(Get-ChildItem -LiteralPath (Join-Path $root 'scripts') -Filter '*.ps1' -File | Sort-Object Name)) {
    @{ Name = $entry.Name; Path = $entry.FullName }
  }
}

function New-StaticAnalysisFixture {
  # Writes a synthetic entry script under <Directory>/scripts for detector self-tests.
  param([Parameter(Mandatory)][string]$Directory, [Parameter(Mandatory)][string]$Name, [Parameter(Mandatory)][string[]]$Lines)
  $scripts = Join-Path $Directory 'scripts'
  $null = New-Item -ItemType Directory -Path $scripts -Force
  $path = Join-Path $scripts $Name
  Set-Content -LiteralPath $path -Value $Lines
  return $path
}

function Get-StaticAnalysisClosure {
  # Entry script, its scripts/internal/<stem>.*.ps1 helpers, and the runner bootstrap.
  param([Parameter(Mandatory)][string]$EntryPath)
  $scripts = Split-Path -Parent $EntryPath
  $stem = [System.IO.Path]::GetFileNameWithoutExtension($EntryPath)
  $helpers = @(Get-ChildItem -LiteralPath (Join-Path $scripts 'internal') -Filter "$stem.*.ps1" -File | Sort-Object Name | ForEach-Object { $_.FullName })
  return @($EntryPath) + $helpers + @(Join-Path $scripts '_lib/Bootstrap.ps1')
}

function Get-StaticAnalysisAst {
  param([Parameter(Mandatory)][string]$Path)
  $errors = $null
  $ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$null, [ref]$errors)
  if ($errors -and $errors.Count -gt 0) { throw "Parse failure in ${Path}: $($errors[0].Message)" }
  return $ast
}

function Find-StaticAnalysisNode {
  param([Parameter(Mandatory)]$Ast, [Parameter(Mandatory)][type]$Type)
  $wanted = $Type
  return @($Ast.FindAll({ param($node) $node -is $wanted }, $true))
}

function Get-StaticAnalysisImportedModuleNames {
  # Module leaf names such as 'Output.psm1' referenced by string literals in the closure.
  param([Parameter(Mandatory)][object[]]$Asts)
  $names = foreach ($ast in $Asts) {
    foreach ($literal in (Find-StaticAnalysisNode -Ast $ast -Type ([System.Management.Automation.Language.StringConstantExpressionAst]))) {
      $leaf = ($literal.Value -split '[\\/]')[-1]
      if ($leaf -match '^[A-Za-z]+\.psm1$') { $leaf }
    }
  }
  return @($names | Sort-Object -Unique)
}

function New-StaticAnalysisParameter {
  param([string]$Name, [string[]]$Aliases = @())
  return [pscustomobject]@{ Name = $Name; Aliases = @($Aliases | Where-Object { $_ }) }
}

function Add-StaticAnalysisCommonParameters {
  param([System.Collections.Generic.List[object]]$Parameters, [bool]$SupportsShouldProcess)
  foreach ($name in $script:StaticAnalysisCommonParameters.Keys) {
    $Parameters.Add((New-StaticAnalysisParameter -Name $name -Aliases @($script:StaticAnalysisCommonParameters[$name])))
  }
  if ($SupportsShouldProcess) {
    $Parameters.Add((New-StaticAnalysisParameter -Name 'WhatIf' -Aliases @('wi')))
    $Parameters.Add((New-StaticAnalysisParameter -Name 'Confirm' -Aliases @('cf')))
  }
}

function ConvertFrom-StaticAnalysisCommandInfo {
  # Signature from live command metadata; dynamic parameters are already included.
  param([Parameter(Mandatory)]$Command)
  $parameters = New-Object System.Collections.Generic.List[object]
  $remaining = $false
  foreach ($parameter in $Command.Parameters.Values) {
    $parameters.Add((New-StaticAnalysisParameter -Name $parameter.Name -Aliases @($parameter.Aliases)))
    if (@($parameter.Attributes | Where-Object { $_ -is [System.Management.Automation.ParameterAttribute] -and $_.ValueFromRemainingArguments }).Count -gt 0) { $remaining = $true }
  }
  foreach ($name in @($script:StaticAnalysisDynamicParameters[$Command.Name])) {
    if ($name) { $parameters.Add((New-StaticAnalysisParameter -Name $name)) }
  }
  return [pscustomobject]@{ Parameters = $parameters.ToArray(); AcceptsAny = $remaining }
}

function Get-StaticAnalysisAttribute {
  param($ParamBlock, [string]$Name)
  if ($null -eq $ParamBlock) { return @() }
  return @($ParamBlock.Attributes | Where-Object { $_.TypeName.Name -eq $Name })
}

function Test-StaticAnalysisShouldProcess {
  param([object[]]$CmdletBinding)
  foreach ($argument in @($CmdletBinding | ForEach-Object { $_.NamedArguments })) {
    if ($argument.ArgumentName -ne 'SupportsShouldProcess') { continue }
    return ($argument.ExpressionOmitted -or $argument.Argument.Extent.Text -eq '$true')
  }
  return $false
}

function Get-StaticAnalysisParameterAsts {
  param([Parameter(Mandatory)]$Function)
  if ($Function.Body.ParamBlock) { return @($Function.Body.ParamBlock.Parameters) }
  return @($Function.Parameters)
}

function Test-StaticAnalysisAdvancedFunction {
  param([Parameter(Mandatory)]$Function, [object[]]$ParameterAsts)
  if (@(Get-StaticAnalysisAttribute -ParamBlock $Function.Body.ParamBlock -Name 'CmdletBinding').Count -gt 0) { return $true }
  return (@($ParameterAsts | ForEach-Object { $_.Attributes } | Where-Object { $_.TypeName.Name -eq 'Parameter' }).Count -gt 0)
}

function ConvertFrom-StaticAnalysisFunctionAst {
  # Signature from a closure function definition, mirroring PowerShell binding rules.
  param([Parameter(Mandatory)]$Function)
  $parameterAsts = @(Get-StaticAnalysisParameterAsts -Function $Function | Where-Object { $_ })
  $parameters = New-Object System.Collections.Generic.List[object]
  foreach ($parameterAst in $parameterAsts) {
    $aliases = @($parameterAst.Attributes | Where-Object { $_.TypeName.Name -eq 'Alias' } | ForEach-Object { $_.PositionalArguments } | ForEach-Object { $_.SafeGetValue() })
    $parameters.Add((New-StaticAnalysisParameter -Name $parameterAst.Name.VariablePath.UserPath -Aliases $aliases))
  }
  if (Test-StaticAnalysisAdvancedFunction -Function $Function -ParameterAsts $parameterAsts) {
    $cmdletBinding = Get-StaticAnalysisAttribute -ParamBlock $Function.Body.ParamBlock -Name 'CmdletBinding'
    Add-StaticAnalysisCommonParameters -Parameters $parameters -SupportsShouldProcess (Test-StaticAnalysisShouldProcess -CmdletBinding $cmdletBinding)
  }
  $remaining = @($parameterAsts | ForEach-Object { $_.Attributes } | Where-Object { $_.Extent.Text -match 'ValueFromRemainingArguments' }).Count -gt 0
  return [pscustomobject]@{ Parameters = $parameters.ToArray(); AcceptsAny = ($remaining -or $null -ne $Function.Body.DynamicParamBlock) }
}

function Get-StaticAnalysisLibScriptVariables {
  # Names assigned at module script scope, or through $script:/$global: anywhere in the module.
  param([Parameter(Mandatory)]$Ast)
  foreach ($target in (Get-StaticAnalysisAssignmentTargets -Ast $Ast)) {
    if ($target.VariablePath.IsScript -or $target.VariablePath.IsGlobal -or -not (Test-StaticAnalysisInsideFunction -Ast $target)) {
      Get-StaticAnalysisVariableName -Path $target.VariablePath
    }
  }
}

function Get-StaticAnalysisLibCatalog {
  # Imports each lib module into a private runspace and records exported command signatures.
  $libPath = Join-Path (Get-StaticAnalysisRoot) 'lib'
  $shell = [powershell]::Create()
  try {
    $null = $shell.AddScript({
        param($Path)
        foreach ($file in @(Get-ChildItem -LiteralPath $Path -Filter '*.psm1' -File)) {
          $module = Import-Module -Name $file.FullName -Force -DisableNameChecking -PassThru
          [pscustomobject]@{ File = $file; Functions = @($module.ExportedFunctions.Values); Aliases = @($module.ExportedAliases.Values) }
        }
      }).AddArgument($libPath)
    $modules = @($shell.Invoke())
    if ($shell.Streams.Error.Count -gt 0) { throw "Lib module import failed: $($shell.Streams.Error[0])" }
  } finally {
    $shell.Dispose()
  }
  $catalog = @{}
  foreach ($module in $modules) { $catalog[$module.File.Name] = ConvertTo-StaticAnalysisModuleEntry -Module $module }
  return $catalog
}

function ConvertTo-StaticAnalysisModuleEntry {
  param([Parameter(Mandatory)]$Module)
  $commands = @{}
  foreach ($function in $Module.Functions) { $commands[$function.Name] = ConvertFrom-StaticAnalysisCommandInfo -Command $function }
  foreach ($alias in $Module.Aliases) {
    if ($alias.ResolvedCommand) { $commands[$alias.Name] = ConvertFrom-StaticAnalysisCommandInfo -Command $alias.ResolvedCommand }
  }
  $variables = @(Get-StaticAnalysisLibScriptVariables -Ast (Get-StaticAnalysisAst -Path $Module.File.FullName))
  return [pscustomobject]@{ Commands = $commands; Variables = $variables }
}

function Get-StaticAnalysisCommandTable {
  # Imported lib exports first; closure-defined functions shadow them, as at runtime.
  param([Parameter(Mandatory)][object[]]$Asts, [Parameter(Mandatory)][hashtable]$LibCatalog, [string[]]$ModuleNames)
  $table = @{}
  foreach ($moduleName in @($ModuleNames | Where-Object { $_ -and $LibCatalog.ContainsKey($_) })) {
    foreach ($name in $LibCatalog[$moduleName].Commands.Keys) { $table[$name] = $LibCatalog[$moduleName].Commands[$name] }
  }
  $closure = @{}
  foreach ($function in @($Asts | ForEach-Object { Find-StaticAnalysisNode -Ast $_ -Type ([System.Management.Automation.Language.FunctionDefinitionAst]) })) {
    $signature = ConvertFrom-StaticAnalysisFunctionAst -Function $function
    if ($closure.ContainsKey($function.Name)) { $signature = Merge-StaticAnalysisSignature -Left $closure[$function.Name] -Right $signature }
    $closure[$function.Name] = $signature
  }
  foreach ($name in $closure.Keys) { $table[$name] = $closure[$name] }
  return $table
}

function Merge-StaticAnalysisSignature {
  # Duplicate definitions in one closure: accept a name bound by either definition.
  param($Left, $Right)
  return [pscustomobject]@{ Parameters = @($Left.Parameters) + @($Right.Parameters); AcceptsAny = ($Left.AcceptsAny -or $Right.AcceptsAny) }
}

function Get-StaticAnalysisBindingProblem {
  # Returns $null when -Name binds (exact name/alias, or a prefix unique to one parameter).
  param([Parameter(Mandatory)]$Signature, [Parameter(Mandatory)][string]$Name)
  if ($Signature.AcceptsAny) { return $null }
  $exact = @($Signature.Parameters | Where-Object { $_.Name -eq $Name -or $_.Aliases -contains $Name })
  if ($exact.Count -gt 0) { return $null }
  $prefix = @($Signature.Parameters | Where-Object { $_.Name -like "$Name*" -or @($_.Aliases | Where-Object { $_ -like "$Name*" }).Count -gt 0 } | ForEach-Object { $_.Name } | Sort-Object -Unique)
  if ($prefix.Count -eq 1) { return $null }
  if ($prefix.Count -gt 1) { return "ambiguous ($($prefix -join ', '))" }
  return 'no such parameter'
}

function Get-StaticAnalysisCommandName {
  param([Parameter(Mandatory)]$CommandAst)
  $name = $CommandAst.GetCommandName()
  if ($name -and $name.Contains('\')) { $name = ($name -split '\\')[-1] }
  return $name
}

function Find-StaticAnalysisUnboundParameter {
  # Returns '<path>:<line> <command> -<parameter> (<problem>)' for each named argument that cannot bind.
  param([Parameter(Mandatory)][string[]]$Files, [Parameter(Mandatory)][hashtable]$LibCatalog, [Parameter(Mandatory)][string]$RootPath)
  $asts = @($Files | ForEach-Object { Get-StaticAnalysisAst -Path $_ })
  $table = Get-StaticAnalysisCommandTable -Asts $asts -LibCatalog $LibCatalog -ModuleNames (Get-StaticAnalysisImportedModuleNames -Asts $asts)
  for ($index = 0; $index -lt $asts.Count; $index++) {
    $relative = Get-StaticAnalysisRelativePath -Path $Files[$index] -RootPath $RootPath
    foreach ($command in (Find-StaticAnalysisNode -Ast $asts[$index] -Type ([System.Management.Automation.Language.CommandAst]))) {
      Get-StaticAnalysisCommandProblems -CommandAst $command -Table $table -RelativePath $relative
    }
  }
}

function Get-StaticAnalysisCommandProblems {
  param([Parameter(Mandatory)]$CommandAst, [Parameter(Mandatory)][hashtable]$Table, [string]$RelativePath)
  $name = Get-StaticAnalysisCommandName -CommandAst $CommandAst
  if (-not $name -or -not $Table.ContainsKey($name)) { return }
  foreach ($element in @($CommandAst.CommandElements | Where-Object { $_ -is [System.Management.Automation.Language.CommandParameterAst] })) {
    $problem = Get-StaticAnalysisBindingProblem -Signature $Table[$name] -Name $element.ParameterName
    $key = '{0}|{1}|{2}' -f $RelativePath, $name, $element.ParameterName
    if ($problem -and -not $script:StaticAnalysisParameterAllowlist.ContainsKey($key)) {
      '{0}:{1} {2} -{3} ({4})' -f $RelativePath, $element.Extent.StartLineNumber, $name, $element.ParameterName, $problem
    }
  }
}

function Get-StaticAnalysisVariableName {
  # '$script:Foo' and '$Foo' name the same variable for this scan.
  param([Parameter(Mandatory)][System.Management.Automation.VariablePath]$Path)
  return ($Path.UserPath -replace '^(script|global|local|private|using):', '')
}

function Test-StaticAnalysisInsideFunction {
  param([Parameter(Mandatory)]$Ast)
  for ($node = $Ast.Parent; $null -ne $node; $node = $node.Parent) {
    if ($node -is [System.Management.Automation.Language.FunctionDefinitionAst]) { return $true }
  }
  return $false
}

function Get-StaticAnalysisTargetVariables {
  # Variables directly written by an assignment target: $x, [type]$x, and $a, $b.
  param($Target)
  if ($Target -is [System.Management.Automation.Language.VariableExpressionAst]) { return $Target }
  if ($Target -is [System.Management.Automation.Language.ConvertExpressionAst]) { return (Get-StaticAnalysisTargetVariables -Target $Target.Child) }
  if ($Target -is [System.Management.Automation.Language.ArrayLiteralAst]) {
    foreach ($element in $Target.Elements) { Get-StaticAnalysisTargetVariables -Target $element }
  }
}

function Get-StaticAnalysisAssignmentTargets {
  param([Parameter(Mandatory)]$Ast)
  foreach ($assignment in (Find-StaticAnalysisNode -Ast $Ast -Type ([System.Management.Automation.Language.AssignmentStatementAst]))) {
    Get-StaticAnalysisTargetVariables -Target $assignment.Left
  }
}

function Test-StaticAnalysisAssigningParameter {
  # -OutVariable style parameters, and -Name of Set-Variable/New-Variable.
  param($Element, [bool]$IsVariableCommand)
  if ($Element -isnot [System.Management.Automation.Language.CommandParameterAst]) { return $false }
  if ($Element.ParameterName -in $script:StaticAnalysisVariableParameters) { return $true }
  return ($IsVariableCommand -and $Element.ParameterName -eq 'Name')
}

function Get-StaticAnalysisParameterValue {
  # Value of '-Name:value' or '-Name value'.
  param([object[]]$Elements, [int]$Index)
  if ($Elements[$Index].Argument) { return $Elements[$Index].Argument }
  if ($Index + 1 -lt $Elements.Count) { return $Elements[$Index + 1] }
}

function Get-StaticAnalysisCommandAssignedNames {
  # Names bound by variable parameters and by Set-Variable/New-Variable (named or first positional).
  param([Parameter(Mandatory)]$CommandAst)
  $elements = @($CommandAst.CommandElements)
  $isVariableCommand = (Get-StaticAnalysisCommandName -CommandAst $CommandAst) -in @('Set-Variable', 'New-Variable')
  for ($index = 1; $index -lt $elements.Count; $index++) {
    if (-not (Test-StaticAnalysisAssigningParameter -Element $elements[$index] -IsVariableCommand $isVariableCommand)) { continue }
    $value = Get-StaticAnalysisParameterValue -Elements $elements -Index $index
    if ($value -is [System.Management.Automation.Language.StringConstantExpressionAst]) { $value.Value.TrimStart('+') }
  }
  if ($isVariableCommand -and $elements.Count -gt 1 -and $elements[1] -is [System.Management.Automation.Language.StringConstantExpressionAst]) { $elements[1].Value }
}

function Get-StaticAnalysisReferenceNames {
  # [ref]$name hands the variable to a callee that may assign it.
  param([Parameter(Mandatory)]$Ast)
  foreach ($convert in (Find-StaticAnalysisNode -Ast $Ast -Type ([System.Management.Automation.Language.ConvertExpressionAst]))) {
    if ($convert.Type.TypeName.Name -eq 'ref' -and $convert.Child -is [System.Management.Automation.Language.VariableExpressionAst]) { Get-StaticAnalysisVariableName -Path $convert.Child.VariablePath }
  }
}

function Get-StaticAnalysisAssignedNames {
  # Every name a closure file binds: assignments, parameters, foreach, [ref], and variable parameters.
  param([Parameter(Mandatory)]$Ast)
  foreach ($target in (Get-StaticAnalysisAssignmentTargets -Ast $Ast)) { Get-StaticAnalysisVariableName -Path $target.VariablePath }
  foreach ($parameter in (Find-StaticAnalysisNode -Ast $Ast -Type ([System.Management.Automation.Language.ParameterAst]))) { Get-StaticAnalysisVariableName -Path $parameter.Name.VariablePath }
  foreach ($loop in (Find-StaticAnalysisNode -Ast $Ast -Type ([System.Management.Automation.Language.ForEachStatementAst]))) { Get-StaticAnalysisVariableName -Path $loop.Variable.VariablePath }
  Get-StaticAnalysisReferenceNames -Ast $Ast
  foreach ($command in (Find-StaticAnalysisNode -Ast $Ast -Type ([System.Management.Automation.Language.CommandAst]))) { Get-StaticAnalysisCommandAssignedNames -CommandAst $command }
}

function Get-StaticAnalysisKnownNames {
  param([Parameter(Mandatory)][object[]]$Asts, [Parameter(Mandatory)][hashtable]$LibCatalog)
  $known = @{}
  foreach ($name in $script:StaticAnalysisAutomaticVariables) { $known[$name] = $true }
  foreach ($ast in $Asts) { foreach ($name in @(Get-StaticAnalysisAssignedNames -Ast $ast)) { $known[$name] = $true } }
  foreach ($moduleName in @(Get-StaticAnalysisImportedModuleNames -Asts $Asts | Where-Object { $LibCatalog.ContainsKey($_) })) {
    foreach ($name in $LibCatalog[$moduleName].Variables) { $known[$name] = $true }
  }
  return $known
}

function Find-StaticAnalysisUnassignedVariable {
  # Returns '<path>:<line> $<name>' for each read of a variable that nothing in the closure assigns.
  param([Parameter(Mandatory)][string[]]$Files, [Parameter(Mandatory)][hashtable]$LibCatalog, [Parameter(Mandatory)][string]$RootPath)
  $asts = @($Files | ForEach-Object { Get-StaticAnalysisAst -Path $_ })
  $known = Get-StaticAnalysisKnownNames -Asts $asts -LibCatalog $LibCatalog
  for ($index = 0; $index -lt $asts.Count; $index++) {
    $relative = Get-StaticAnalysisRelativePath -Path $Files[$index] -RootPath $RootPath
    foreach ($variable in (Find-StaticAnalysisNode -Ast $asts[$index] -Type ([System.Management.Automation.Language.VariableExpressionAst]))) {
      Get-StaticAnalysisVariableProblem -Variable $variable -Known $known -RelativePath $relative
    }
  }
}

function Get-StaticAnalysisVariableProblem {
  param([Parameter(Mandatory)]$Variable, [Parameter(Mandatory)][hashtable]$Known, [string]$RelativePath)
  $path = $Variable.VariablePath
  if ($path.IsDriveQualified) { return }
  $name = Get-StaticAnalysisVariableName -Path $path
  if ($Known.ContainsKey($name) -or $script:StaticAnalysisVariableAllowlist.ContainsKey("$RelativePath|$name")) { return }
  '{0}:{1} ${2}' -f $RelativePath, $Variable.Extent.StartLineNumber, $name
}
