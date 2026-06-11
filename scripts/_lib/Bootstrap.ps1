# Resolve lib path relative to script directory only (not CWD) so Import-Module works regardless of current location
$script:LibPath = Join-Path $PSScriptRoot '..\..\lib'
if (-not (Test-Path -LiteralPath $script:LibPath)) {
  $script:LibPath = Join-Path $PSScriptRoot '..\lib'
}
if (-not (Test-Path -LiteralPath $script:LibPath)) {
  $script:LibPath = Join-Path $PSScriptRoot 'lib'
}

$scriptDir = $PSScriptRoot
if (-not [string]::IsNullOrWhiteSpace($scriptDir) -and (Test-Path -LiteralPath $scriptDir -PathType Container)) {
  Push-Location -LiteralPath $scriptDir
  try {
    $resolved = Resolve-Path -LiteralPath $script:LibPath -ErrorAction Stop
    $script:LibPath = $resolved.Path
  } catch {
    $abs = [System.IO.Path]::GetFullPath((Join-Path $scriptDir $script:LibPath))
    if (Test-Path -LiteralPath $abs) { $script:LibPath = $abs }
  } finally {
    Pop-Location
  }
} else {
  # PSScriptRoot is null/empty - this means Bootstrap.ps1 was invoked interactively
  # (e.g. dot-sourced from the console), which is not a supported execution path.
  throw "Bootstrap must be invoked from a script file, not interactively. `$PSScriptRoot is empty."
}

<#
.SYNOPSIS
  Common v2 initialization logic extracted from the per-script boilerplate.

.DESCRIPTION
  Call this function immediately after importing modules and setting StrictMode
  to replace the inline "# v2-init" block. It builds $script:__V2Context,
  wires up $Quiet / $NoColor preferences, and optionally derives $Remediate
  from $Mode.

  Migration path (per-script):
    1. Keep the existing param() block and Bootstrap dot-source unchanged.
    2. Replace the inline "# v2-init" block (from '$null = $Mode,...' through
       the NoColor / Quiet preference lines) with a single call:
         Initialize-V2Context -ScriptName 'NN-Script.ps1' -BoundParameters $PSBoundParameters
    3. If the script uses a $Remediate variable, add -DeriveRemediate after
       the call or set it yourself from $Mode.
    4. Set $ErrorActionPreference = 'Stop' after the call (not included in
       the function to keep caller control explicit).

.PARAMETER BoundParameters
  Pass $PSBoundParameters from the calling script so the function can detect
  which parameters were explicitly supplied.

.PARAMETER ScriptName
  Required script file name to store in the v2 context.

.PARAMETER DeriveRemediate
  When set, creates/updates a script-scope $Remediate variable derived from
  the caller-scope $Mode variable ($Mode -eq 'Remediate').
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
    [switch]$DeriveRemediate
  )

  # Read variables from the caller scope (set via param() block)
  $callerMode         = Get-Variable -Name Mode         -Scope 1 -ValueOnly -ErrorAction SilentlyContinue
  $callerConfigPath   = Get-Variable -Name ConfigPath   -Scope 1 -ValueOnly -ErrorAction SilentlyContinue
  $callerOutputFormat = Get-Variable -Name OutputFormat -Scope 1 -ValueOnly -ErrorAction SilentlyContinue
  $callerOutputPath   = Get-Variable -Name OutputPath   -Scope 1 -ValueOnly -ErrorAction SilentlyContinue
  $callerPassThru     = Get-Variable -Name PassThru     -Scope 1 -ValueOnly -ErrorAction SilentlyContinue
  $callerStrict       = Get-Variable -Name Strict       -Scope 1 -ValueOnly -ErrorAction SilentlyContinue
  $callerQuiet        = Get-Variable -Name Quiet        -Scope 1 -ValueOnly -ErrorAction SilentlyContinue
  $callerNoColor      = Get-Variable -Name NoColor      -Scope 1 -ValueOnly -ErrorAction SilentlyContinue

  # Suppress PSUseDeclaredVarsMoreThanAssignments for the null-touch
  $null = $callerMode, $callerConfigPath, $callerOutputFormat, $callerOutputPath,
          $callerPassThru, $callerStrict, $callerQuiet, $callerNoColor

  $script:__V2Context = @{
    ScriptName   = $ScriptName
    ScriptVersion= $ScriptVersion
    Mode         = $callerMode
    ConfigPath   = $callerConfigPath
    OutputFormat = $callerOutputFormat
    OutputPath   = $callerOutputPath
    PassThru     = [bool]$callerPassThru
    Strict       = [bool]$callerStrict
    Quiet        = [bool]$callerQuiet
    NoColor      = [bool]$callerNoColor
  }

  if ($BoundParameters.ContainsKey('Mode')) {
    $existingRemediate = Get-Variable -Name Remediate -Scope 1 -ErrorAction SilentlyContinue
    if ($existingRemediate) {
      Set-Variable -Name Remediate -Scope 1 -Value ($callerMode -eq 'Remediate') -WhatIf:$false
    }
  }

  if ($DeriveRemediate) {
    Set-Variable -Name Remediate -Scope 1 -Value ($callerMode -eq 'Remediate') -WhatIf:$false
  }

  if ($callerQuiet) {
    Set-Variable -Name InformationPreference -Scope 1 -Value 'SilentlyContinue' -WhatIf:$false
    Set-Variable -Name VerbosePreference     -Scope 1 -Value 'SilentlyContinue' -WhatIf:$false
  }

  if ($callerNoColor) {
    $script:NoColor = $true
  }
}
