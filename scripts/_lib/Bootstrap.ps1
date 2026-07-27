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
       the NoColor / Quiet preference lines) with a single call:
         $script:__V2Context = Initialize-V2Context `
           -ScriptName 'NN-Script.ps1' `
           -BoundParameters $PSBoundParameters `
           -Mode $Mode -ConfigPath $ConfigPath `
           -OutputFormat $OutputFormat -OutputPath $OutputPath `
           -PassThru:$PassThru -Strict:$Strict -Quiet:$Quiet -NoColor:$NoColor
    3. Apply caller-owned state from the returned context.
    4. Set $ErrorActionPreference = 'Stop' after the call.

.PARAMETER BoundParameters
  Pass $PSBoundParameters from the calling script so the function can detect
  which parameters were explicitly supplied.

.PARAMETER ScriptName
  Required script file name to store in the v2 context.

.PARAMETER DeriveRemediate
  When set, includes a Remediate value derived from Mode in the returned
  context.
#>
function Initialize-V2Context {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$ScriptName,
    [string]$ScriptVersion = '1.0',
    [Parameter(Mandatory)]
    [System.Collections.IDictionary]$BoundParameters,
    [ValidateSet('Audit', 'Remediate')]
    [string]$Mode = 'Audit',
    [AllowNull()][string]$ConfigPath,
    [ValidateSet('Console', 'Json', 'Csv', 'None')]
    [string]$OutputFormat = 'Console',
    [AllowNull()][string]$OutputPath,
    [switch]$PassThru,
    [switch]$Strict,
    [switch]$Quiet,
    [switch]$NoColor,
    [switch]$DeriveRemediate
  )

  $context = [ordered]@{
    ScriptName       = $ScriptName
    ScriptVersion    = $ScriptVersion
    Mode             = $Mode
    ConfigPath       = $ConfigPath
    OutputFormat     = $OutputFormat
    OutputPath       = $OutputPath
    PassThru         = [bool]$PassThru
    Strict           = [bool]$Strict
    Quiet            = [bool]$Quiet
    NoColor          = [bool]$NoColor
    ExplicitParameters = @($BoundParameters.Keys)
    DeriveRemediate  = [bool]$DeriveRemediate
    Remediate        = [bool]($DeriveRemediate -and $Mode -eq 'Remediate')
  }

  # File output is a run-level contract. Reject deterministic configuration
  # errors before a script can inspect or mutate host state, and still return a
  # terminal V2 object instead of letting the final serializer throw.
  $effectiveOutputFormat = if ([string]::IsNullOrWhiteSpace([string]$OutputFormat)) {
    'Console'
  } else {
    [string]$OutputFormat
  }
  $outputValidator = Get-Command -Name Get-V2OutputConfigurationError -ErrorAction SilentlyContinue
  $outputConfigurationError = if ($outputValidator) {
    Get-V2OutputConfigurationError -OutputFormat $effectiveOutputFormat -OutputPath $OutputPath
  } elseif ($effectiveOutputFormat -in @('Json', 'Csv') -and [string]::IsNullOrWhiteSpace([string]$OutputPath)) {
    "OutputPath is required when OutputFormat is $effectiveOutputFormat."
  } else {
    $null
  }
  if ($outputConfigurationError) {
    $effectiveMode = if ($Mode -eq 'Remediate') { 'Remediate' } else { 'Audit' }
    $failureResult = Get-V2ResultObject `
      -ScriptName $ScriptName `
      -Mode $effectiveMode `
      -Result 'FAIL' `
      -Findings @([pscustomobject]@{
          Code     = 'V2-OutputConfigurationInvalid'
          Severity = 'High'
          Message  = $outputConfigurationError
        }) `
      -Summary ([pscustomobject]@{
          OutputFormat = $effectiveOutputFormat
          OutputPath   = $OutputPath
          Error        = $outputConfigurationError
        }) `
      -Metadata @{}

    $failureResult
    exit (Get-V2ExitCode -Result 'FAIL')
  }

  return $context
}
