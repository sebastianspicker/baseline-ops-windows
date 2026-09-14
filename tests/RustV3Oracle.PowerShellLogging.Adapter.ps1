#requires -version 5.1
<#
.SYNOPSIS
Runs bounded PowerShell Logging comparisons for the Rust v3 oracle.

.DESCRIPTION
Extracts the maintained capability 31 policy functions and invokes them with
finite mocked registry evidence. No endpoint registry operation is performed.
#>

Set-StrictMode -Version Latest

function Get-RustV3OraclePowerShellLoggingFunctionDefinition {
  param([string]$RepositoryRoot)

  $scriptPath = Join-Path $RepositoryRoot 'scripts/31-PowerShell-Logging-Baseline.ps1'
  $tokens = $null
  $parseErrors = $null
  $ast = [Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$tokens, [ref]$parseErrors)
  if ($parseErrors.Count -gt 0) { throw 'PowerShell Logging v2 policy source does not parse.' }
  $names = @(
    'Get-CleanModuleNames', 'Get-DistinctModuleNames', 'Normalize-ModuleNames',
    'Get-SettingsForBase', 'Invoke-Capability31MainPhase05',
    'Invoke-Capability31MainPhase06', 'Invoke-Capability31MainPhase07'
  )
  foreach ($name in $names) {
    $functions = @($ast.FindAll({
      param($Node)
      $Node -is [Management.Automation.Language.FunctionDefinitionAst] -and $Node.Name -eq $name
    }, $true))
    if ($functions.Count -ne 1) { throw "PowerShell Logging v2 policy function is missing or duplicated: $name" }
    $functions[0].Extent.Text
  }
}

function Get-RustV3OraclePowerShellLoggingSnapshotValue {
  param($Hive, [string]$Name)

  $snapshot = Get-RustV3OracleProperty $Hive $Name
  if ($null -eq $snapshot -or $snapshot.status -ne 'value') { return $null }
  return $snapshot.value
}

function ConvertTo-RustV3OraclePowerShellLoggingRunState {
  param($Case)

  $hive = $Case.observation.hklm
  return @{
    Findings = [Collections.Generic.List[object]]::new()
    targetEnableTranscription = $true
    targetEnableInvocationHeader = $true
    targetEnableScriptBlockLogging = $true
    targetEnableScriptBlockInvocationLogging = $false
    targetEnableModuleLogging = $true
    effectiveBefore = [pscustomobject]@{
      Transcription_EnableTranscripting = Get-RustV3OraclePowerShellLoggingSnapshotValue $hive 'enable_transcription'
      Transcription_EnableInvocationHeader = Get-RustV3OraclePowerShellLoggingSnapshotValue $hive 'enable_invocation_header'
      ScriptBlock_EnableScriptBlockLogging = Get-RustV3OraclePowerShellLoggingSnapshotValue $hive 'enable_script_block_logging'
      ScriptBlock_EnableScriptBlockInvocationLogging = Get-RustV3OraclePowerShellLoggingSnapshotValue $hive 'enable_script_block_invocation_logging'
      Module_EnableModuleLogging = Get-RustV3OraclePowerShellLoggingSnapshotValue $hive 'enable_module_logging'
    }
  }
}

function Invoke-RustV3OraclePowerShellLoggingDeniedRead {
  function Get-RegValue { throw [UnauthorizedAccessException]::new('mocked denied registry read') }
  function Get-ModuleNamesConfigured { return $null }
  $state = @{}
  $errorType = $null
  try { $null = Get-SettingsForBase -BasePath '/mock/HKLM/PowerShell' -RunState $state }
  catch { $errorType = $_.Exception.GetType().FullName }
  [pscustomobject]@{
    Outcome = $(if ($errorType) { 'error' } else { 'completed' })
    ErrorType = $errorType
    FindingCodes = @()
    ModuleNames = @()
  }
}

function Invoke-RustV3OracleV2PowerShellLoggingPolicy {
  [OutputType([pscustomobject])]
  param([Parameter(Mandatory)] $Case, [string]$RepositoryRoot = (Join-Path $PSScriptRoot '..'))

  $definitions = @(Get-RustV3OraclePowerShellLoggingFunctionDefinition -RepositoryRoot $RepositoryRoot)
  . ([scriptblock]::Create(($definitions -join "`n")))
  if ((Get-RustV3OracleProperty $Case 'v2_read_error') -eq 'access_denied') {
    return Invoke-RustV3OraclePowerShellLoggingDeniedRead
  }
  function Add-Finding {
    param($FindingList, $Code, $Severity, $Message)
    [void]$FindingList.Add([pscustomobject]@{ Code = $Code; Severity = $Severity; Message = $Message })
  }
  $Mode = 'Audit'
  $null = $Mode
  $state = ConvertTo-RustV3OraclePowerShellLoggingRunState -Case $Case
  Invoke-Capability31MainPhase05 -RunState $state
  Invoke-Capability31MainPhase06 -RunState $state
  Invoke-Capability31MainPhase07 -RunState $state
  $moduleInput = Get-RustV3OracleProperty $Case 'v2_module_names'
  if ($null -eq $moduleInput) { $moduleInput = @('*') }
  [pscustomobject]@{
    Outcome = 'completed'
    ErrorType = $null
    FindingCodes = @($state.Findings | ForEach-Object Code)
    ModuleNames = @(Normalize-ModuleNames -Names $moduleInput)
  }
}

function Add-RustV3OraclePowerShellLoggingCaseError {
  param($Case, $RepositoryRoot, $Errors)

  $actual = Invoke-RustV3OracleV2PowerShellLoggingPolicy -Case $Case -RepositoryRoot $RepositoryRoot
  $actualFindings = ConvertTo-Json @($actual.FindingCodes) -Compress
  $expectedFindings = ConvertTo-Json @($Case.expected.v2_finding_codes) -Compress
  $actualModules = ConvertTo-Json @($actual.ModuleNames) -Compress
  $expectedModules = ConvertTo-Json @($Case.expected.v2_normalized_module_names) -Compress
  $expectedError = Get-RustV3OracleProperty $Case.expected 'v2_error_type'
  if ($actual.Outcome -ne $Case.expected.v2_outcome -or $actual.ErrorType -ne $expectedError -or
      $actualFindings -ne $expectedFindings -or $actualModules -ne $expectedModules) {
    [void]$Errors.Add(('PowerShell v2 PowerShell Logging policy diverges for {0}.' -f $Case.id))
  }
}
