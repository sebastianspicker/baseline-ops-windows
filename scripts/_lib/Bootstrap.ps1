<#
.SYNOPSIS
Resolves shared modules and initializes the repository v2 script contract.

.DESCRIPTION
Locates the fixed lib directory relative to the calling script and provides the
common context builder used by entry scripts. Centralizing this bootstrap keeps
mode, output, strictness, and quiet-state handling consistent across the kit.
#>

# Resolve only fixed locations relative to this file, without command lookup or
# the caller's working directory. This file executes before most module imports.
if ([string]::IsNullOrWhiteSpace($PSScriptRoot)) {
  throw "Bootstrap must be invoked from a script file, not interactively. `$PSScriptRoot is empty."
}
$script:LibPath = $null
foreach ($candidatePath in @(
  [System.IO.Path]::Combine($PSScriptRoot, '..', '..', 'lib')
  [System.IO.Path]::Combine($PSScriptRoot, '..', 'lib')
  [System.IO.Path]::Combine($PSScriptRoot, 'lib')
)) {
  $candidate = [System.IO.Path]::GetFullPath($candidatePath)
  if ([System.IO.Directory]::Exists($candidate)) { $script:LibPath = $candidate; break }
}
if ([string]::IsNullOrWhiteSpace($script:LibPath)) {
  throw 'Bootstrap could not resolve the repository lib directory.'
}

<#
.SYNOPSIS
  Common v2 initialization logic extracted from the per-script boilerplate.

.DESCRIPTION
  Call this function immediately after importing modules and setting StrictMode
  to replace the inline "# v2-init" block. It returns a context built only from
  explicitly supplied values. The caller owns assigning the returned context
  and applying any requested preference or remediation state.

  Migration path (per-script):
    1. Keep the existing param() block and Bootstrap dot-source unchanged.
    2. Replace the inline "# v2-init" block (from '$null = $Mode,...' through
       the NoColor / Quiet preference lines) with a single call using a grouped
       values hashtable:
         $script:__V2Context = Initialize-V2Context `
           -ScriptName 'NN-Script.ps1' `
           -BoundParameters $PSBoundParameters `
           -Values @{ Mode = $Mode; ConfigPath = $ConfigPath; OutputFormat = $OutputFormat; OutputPath = $OutputPath; PassThru = $PassThru; Strict = $Strict; Quiet = $Quiet; NoColor = $NoColor }
    3. Apply caller-owned state from the returned context.
    4. Set $ErrorActionPreference = 'Stop' after the call.

.PARAMETER BoundParameters
  Pass $PSBoundParameters from the calling script so the function can detect
  which parameters were explicitly supplied.

.PARAMETER ScriptName
  Required script file name to store in the v2 context.

.PARAMETER Values
  A hashtable carrying the caller-owned v2 values: Mode, ConfigPath,
  OutputFormat, OutputPath, PassThru, Strict, Quiet, NoColor, and optionally
  DeriveRemediate. Grouping those values preserves the stable context contract
  without expanding this shared bootstrap function's public parameter surface.
#>
function Get-V2ContextValue {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][hashtable]$Values,
    [Parameter(Mandatory)][string]$Name,
    [AllowNull()]$Default
  )

  if ($Values.ContainsKey($Name)) { return $Values[$Name] }
  return $Default
}

function Get-V2BootstrapOutputConfigurationError {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$OutputFormat,
    [AllowNull()][string]$OutputPath
  )

  $outputValidator = Get-Command -Name Get-V2OutputConfigurationError -ErrorAction SilentlyContinue
  if ($outputValidator) {
    return (Get-V2OutputConfigurationError -OutputFormat $OutputFormat -OutputPath $OutputPath)
  }
  if ($OutputFormat -in @('Json', 'Csv') -and [string]::IsNullOrWhiteSpace([string]$OutputPath)) {
    return "OutputPath is required when OutputFormat is $OutputFormat."
  }
  return $null
}

function Write-V2OutputConfigurationFailure {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$ScriptName,
    [Parameter(Mandatory)][string]$Mode,
    [Parameter(Mandatory)][string]$OutputFormat,
    [AllowNull()][string]$OutputPath,
    [Parameter(Mandatory)][string]$Message
  )

  $failureResult = Get-V2ResultObject `
    -ScriptName $ScriptName `
    -Mode $Mode `
    -Result 'FAIL' `
    -Findings @([pscustomobject]@{ Code = 'V2-OutputConfigurationInvalid'; Severity = 'High'; Message = $Message }) `
    -Summary ([pscustomobject]@{ OutputFormat = $OutputFormat; OutputPath = $OutputPath; Error = $Message }) `
    -Metadata @{}
  $failureResult
  exit (Get-V2ExitCode -Result 'FAIL')
}

function New-V2ContextRecord {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$ScriptName,
    [Parameter(Mandatory)][string]$ScriptVersion,
    [Parameter(Mandatory)][System.Collections.IDictionary]$BoundParameters,
    [Parameter(Mandatory)][hashtable]$Values
  )

  return [ordered]@{
    ScriptName = $ScriptName; ScriptVersion = $ScriptVersion; Mode = $Values.Mode
    ConfigPath = $Values.ConfigPath; OutputFormat = $Values.OutputFormat; OutputPath = $Values.OutputPath
    PassThru = [bool]$Values.PassThru; Strict = [bool]$Values.Strict; Quiet = [bool]$Values.Quiet
    NoColor = [bool]$Values.NoColor; ExplicitParameters = @($BoundParameters.Keys)
    DeriveRemediate = [bool]$Values.DeriveRemediate
    Remediate = [bool]($Values.DeriveRemediate -and $Values.Mode -eq 'Remediate')
  }
}

function Initialize-V2Context {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$ScriptName,
    [string]$ScriptVersion = '1.0',
    [Parameter(Mandatory)]
    [System.Collections.IDictionary]$BoundParameters,
    [Parameter(Mandatory)]
    [hashtable]$Values
  )

  $Mode = [string](Get-V2ContextValue -Values $Values -Name 'Mode' -Default 'Audit')
  $ConfigPath = Get-V2ContextValue -Values $Values -Name 'ConfigPath' -Default $null
  $OutputFormat = [string](Get-V2ContextValue -Values $Values -Name 'OutputFormat' -Default 'Console')
  $OutputPath = Get-V2ContextValue -Values $Values -Name 'OutputPath' -Default $null
  $PassThru = [bool](Get-V2ContextValue -Values $Values -Name 'PassThru' -Default $false)
  $Strict = [bool](Get-V2ContextValue -Values $Values -Name 'Strict' -Default $false)
  $Quiet = [bool](Get-V2ContextValue -Values $Values -Name 'Quiet' -Default $false)
  $NoColor = [bool](Get-V2ContextValue -Values $Values -Name 'NoColor' -Default $false)
  $DeriveRemediate = [bool](Get-V2ContextValue -Values $Values -Name 'DeriveRemediate' -Default $false)
  if ($Mode -notin @('Audit', 'Remediate')) { throw "Mode must be Audit or Remediate: $Mode" }
  if ($OutputFormat -notin @('Console', 'Json', 'Csv', 'None')) { throw "OutputFormat is invalid: $OutputFormat" }

  $contextValues = @{ Mode = $Mode; ConfigPath = $ConfigPath; OutputFormat = $OutputFormat; OutputPath = $OutputPath; PassThru = $PassThru; Strict = $Strict; Quiet = $Quiet; NoColor = $NoColor; DeriveRemediate = $DeriveRemediate }
  $context = New-V2ContextRecord -ScriptName $ScriptName -ScriptVersion $ScriptVersion -BoundParameters $BoundParameters -Values $contextValues

  # File output is a run-level contract. Reject deterministic configuration
  # errors before a script can inspect or mutate host state, and still return a
  # terminal V2 object instead of letting the final serializer throw.
  $effectiveOutputFormat = if ([string]::IsNullOrWhiteSpace([string]$OutputFormat)) {
    'Console'
  } else {
    [string]$OutputFormat
  }
  $outputConfigurationError = Get-V2BootstrapOutputConfigurationError -OutputFormat $effectiveOutputFormat -OutputPath $OutputPath
  if ($outputConfigurationError) {
    $effectiveMode = if ($Mode -eq 'Remediate') { 'Remediate' } else { 'Audit' }
    Write-V2OutputConfigurationFailure -ScriptName $ScriptName -Mode $effectiveMode `
      -OutputFormat $effectiveOutputFormat -OutputPath $OutputPath -Message $outputConfigurationError
  }

  return $context
}
