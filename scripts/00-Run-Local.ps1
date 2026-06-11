#requires -version 5.1
<#
.SYNOPSIS
Run a script from C:\install\mdm\ps1\scripts on the local machine.

.DESCRIPTION
Looks up the script file in C:\install\mdm\ps1\scripts (or an override)
and executes it. Optional -ScriptArgs are passed through to the script.

Supports optional integrity verification via signature check or hash comparison.

.PARAMETER ScriptName
Script file name to run (for example: 18-Firewall-Baseline.ps1).

.PARAMETER ScriptNumber
Script number only (for example: 18). Matches "18-*.ps1".

.PARAMETER ScriptArgs
Optional arguments to pass to the target script.

.PARAMETER RootPath
Override root path (default: C:\install\mdm\ps1).

.PARAMETER RequireSigned
If set, verifies the script has a valid Authenticode signature before execution.

.PARAMETER ExpectedHash
Expected hash value for the script. Format: "ALGORITHM:HASH" or just "HASH" (defaults to SHA256).
Example: "SHA256:ABC123..." or just "ABC123..."

.PARAMETER HashAlgorithm
Hash algorithm to use for verification (default: SHA256).
Valid values: SHA256, SHA384, SHA512

.EXAMPLE
.\00-Run-Local.ps1 -ScriptName 18-Firewall-Baseline.ps1

.EXAMPLE
.\00-Run-Local.ps1 -ScriptNumber 18

.EXAMPLE
.\00-Run-Local.ps1 -ScriptName 31-PowerShell-Logging-Baseline.ps1 -ScriptArgs @('-Mode','Audit')

.EXAMPLE
.\00-Run-Local.ps1 -ScriptNumber 18 -RequireSigned

.EXAMPLE
.\00-Run-Local.ps1 -ScriptName 18-Firewall-Baseline.ps1 -ExpectedHash "SHA256:ABC123DEF456..."

.EXAMPLE
# Verify hash from a hash file
$hash = (Get-Content .\hashes.txt | Where-Object { $_ -like "18-Firewall-Baseline.ps1=*" }).Split('=')[1]
.\00-Run-Local.ps1 -ScriptNumber 18 -ExpectedHash $hash
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
  [Parameter(Mandatory, ParameterSetName = 'ByName')]
  [ValidateNotNullOrEmpty()]
  [string]$ScriptName,

  [Parameter(Mandatory, ParameterSetName = 'ByNumber')]
  [ValidatePattern('^\d{1,2}$')]
  [string]$ScriptNumber,

  [string[]]$ScriptArgs,

  # Default deployment path. Override with -RootPath to use a different location
  # (e.g., -RootPath 'D:\mdm\ps1' or via environment variable in your deployment pipeline).
  [string]$RootPath = 'C:\install\mdm\ps1',

  [switch]$RequireSigned,

  [string]$ExpectedHash,

  [ValidateSet('SHA256','SHA384','SHA512')]
  [string]$HashAlgorithm = 'SHA256'

,
  [ValidateSet('Audit','Remediate')][string]$Mode = 'Audit',
  [string]$ConfigPath,
  [ValidateSet('Console','Json','Csv','None')][string]$OutputFormat = 'Console',
  [string]$OutputPath,
  [switch]$PassThru,
  [switch]$Strict,
  [switch]$Quiet,
  [switch]$NoColor
)

. (Join-Path $PSScriptRoot '_lib/Bootstrap.ps1')
Import-Module (Join-Path $script:LibPath 'Output.psm1') -Force
Import-Module (Join-Path $script:LibPath 'Execution.psm1') -Force

Set-StrictMode -Version Latest
# v2-init (migrated to Initialize-V2Context)
Initialize-V2Context -ScriptName '00-Run-Local.ps1' -BoundParameters $PSBoundParameters
$ErrorActionPreference = 'Stop'

if ($RootPath -eq 'C:\install\mdm\ps1') {
  # Preserve the documented deployment default, but make local repo smoke tests
  # work when the Windows deployment drive is not present.
  $repoRootCandidate = Split-Path -Parent $PSScriptRoot
  if (Test-Path -LiteralPath (Join-Path $repoRootCandidate 'scripts') -PathType Container) {
    $RootPath = $repoRootCandidate
  }
}

$scriptsRoot = Join-Path $RootPath 'scripts'

if (-not (Test-Path -LiteralPath $scriptsRoot)) {
  throw "Scripts root not found: $scriptsRoot"
}

function Test-ResolvedPathUnderScriptsRoot {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][string]$ScriptsRootPath
  )

  # Resolve both sides before comparison so relative paths and symlinks cannot
  # escape the deployment scripts directory by string-shape tricks.
  try {
    $resolvedPath = (Resolve-Path -LiteralPath $Path -ErrorAction Stop).Path
    $resolvedRoot = (Resolve-Path -LiteralPath $ScriptsRootPath -ErrorAction Stop).Path
  } catch {
    return $false
  }

  $sepChars = @([System.IO.Path]::DirectorySeparatorChar, [System.IO.Path]::AltDirectorySeparatorChar)
  $rootPrefix = $resolvedRoot.TrimEnd($sepChars) + [System.IO.Path]::DirectorySeparatorChar
  return $resolvedPath.StartsWith($rootPrefix, [System.StringComparison]::OrdinalIgnoreCase)
}

function Test-PathIsSymlink {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Path
  )

  try {
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
  } catch {
    return $false
  }

  return [bool]($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint)
}

if ($PSCmdlet.ParameterSetName -eq 'ByNumber') {
  $num = [int]$ScriptNumber
  $prefix = '{0:D2}-' -f $num
  $scriptMatches = Get-ChildItem -Path $scriptsRoot -Filter "$prefix*.ps1" -File
  if ($scriptMatches.Count -eq 0) {
    throw "No script found for number $prefix in $scriptsRoot"
  }
  if ($scriptMatches.Count -gt 1) {
    $names = ($scriptMatches | Select-Object -ExpandProperty Name) -join ', '
    throw "Multiple scripts match number ${prefix}: $names"
  }
  $scriptPath = $scriptMatches[0].FullName
  if (Test-PathIsSymlink -Path $scriptPath) {
    throw "Refusing to execute reparse-point script path: $scriptPath"
  }
  if (-not (Test-ResolvedPathUnderScriptsRoot -Path $scriptPath -ScriptsRootPath $scriptsRoot)) {
    throw "Resolved script path is outside scripts root or invalid."
  }
  $scriptPath = (Resolve-Path -LiteralPath $scriptPath).Path
} else {
  # Constrain to basename only to prevent path traversal (§11/§10)
  if ($ScriptName -match '[/\\]' -or $ScriptName -match '\.\.') {
    throw "ScriptName must be a script file name without path components (e.g. 18-Firewall-Baseline.ps1)."
  }
  $baseName = [System.IO.Path]::GetFileName($ScriptName)
  if ([string]::IsNullOrWhiteSpace($baseName)) {
    throw "ScriptName must be a script file name (e.g. 18-Firewall-Baseline.ps1)."
  }
  if ([System.IO.Path]::GetExtension($baseName) -ne '.ps1') {
    throw "ScriptName must reference a .ps1 file."
  }
  $scriptPath = Join-Path $scriptsRoot $baseName
  if (-not (Test-Path -LiteralPath $scriptPath -PathType Leaf)) {
    throw "Script not found: $scriptPath"
  }
  if (Test-PathIsSymlink -Path $scriptPath) {
    throw "Refusing to execute reparse-point script path: $scriptPath"
  }
  if (-not (Test-ResolvedPathUnderScriptsRoot -Path $scriptPath -ScriptsRootPath $scriptsRoot)) {
    throw "Resolved script path is outside scripts root or invalid."
  }
  $scriptPath = (Resolve-Path -LiteralPath $scriptPath).Path
}

# Integrity verification (fixes #25)
if ($RequireSigned) {
  $signature = Get-AuthenticodeSignature -FilePath $scriptPath
  if ($signature.Status -ne 'Valid') {
    throw "Script signature verification failed for $scriptPath : $($signature.Status)"
  }
  Write-UiLine "Signature verified: $($signature.SignerCertificate.Subject)" -Style Success
}

if (-not [string]::IsNullOrWhiteSpace($ExpectedHash)) {
  # Parse expected hash - format can be "ALGORITHM:HASH" or just "HASH"
  $allowedHashAlgorithms = @('SHA256','SHA384','SHA512')
  $expectedAlg = $HashAlgorithm
  $expectedHashValue = $ExpectedHash.Trim()
  
  if ($expectedHashValue -match '^(\w+):([A-Fa-f0-9]+)$') {
    $expectedAlg = $Matches[1].ToUpperInvariant()
    $expectedHashValue = $Matches[2]
  }

  if ($allowedHashAlgorithms -notcontains $expectedAlg) {
    throw "Unsupported hash algorithm '$expectedAlg'. Allowed algorithms: $($allowedHashAlgorithms -join ', ')."
  }
  
  $actualHashObj = Get-FileHash -Path $scriptPath -Algorithm $expectedAlg
  $actualHash = $actualHashObj.Hash
  
  if (-not [string]::Equals($actualHash, $expectedHashValue, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "Hash mismatch for $scriptPath. Expected ($expectedAlg): $expectedHashValue, Actual: $actualHash"
  }
  Write-UiLine "Hash verified ($expectedAlg)" -Style Success
}

function Invoke-TargetScript {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Path,
    [string[]]$Arguments = @(),
    [switch]$CaptureV2Result
  )

  # ScriptArgs arrives from profile JSON or CLI token arrays. Parse it once and
  # splat typed named arguments so child scripts see normal PowerShell binding.
  $parsed = Convert-ArgumentTokens -Arguments @($Arguments)
  $namedArgs = $parsed.Named
  $positionalArgs = @($parsed.Positional)

  if ($CaptureV2Result) {
    $namedArgs['PassThru'] = $true
    $namedArgs['OutputFormat'] = 'None'
    if ($namedArgs.ContainsKey('OutputPath')) {
      $namedArgs.Remove('OutputPath')
    }
  }

  if ($positionalArgs.Count -gt 0) {
    & $Path @namedArgs @positionalArgs
  } else {
    & $Path @namedArgs
  }
}

if ($WhatIfPreference) {
  Write-UiLine ("[SKIP] {0} (WhatIf/Confirm)" -f (Split-Path -Leaf $scriptPath)) -Style 'Muted'
  exit 0
}

$targetOutput = @(Invoke-TargetScript -Path $scriptPath -Arguments $ScriptArgs -CaptureV2Result:$PassThru)
$targetExitCode = if ($null -eq $LASTEXITCODE) { 0 } else { [int]$LASTEXITCODE }

if ($PassThru) {
  $v2Results = @(
    $targetOutput | Where-Object {
      $null -ne $_ -and
      $_.PSObject.Properties.Name -contains 'Result' -and
      @('OK','WARN','FAIL') -contains [string]$_.Result
    }
  )

  if ($v2Results.Count -gt 0) {
    $targetResult = $v2Results[-1]
    $expectedTargetExitCode = switch ([string]$targetResult.Result) {
      'OK' { 0 }
      'WARN' { 2 }
      'FAIL' { 1 }
    }
    if ($targetExitCode -ne $expectedTargetExitCode) {
      $targetResult | Add-Member -NotePropertyName RunnerExitMismatch -NotePropertyValue $true -Force
      $targetResult | Add-Member -NotePropertyName RunnerExpectedExitCode -NotePropertyValue $expectedTargetExitCode -Force
      $targetResult | Add-Member -NotePropertyName RunnerActualExitCode -NotePropertyValue $targetExitCode -Force
      Write-Warning "Target V2 result '$($targetResult.Result)' does not match process exit code $targetExitCode. Expected $expectedTargetExitCode."
    }
    $targetResult
    switch ([string]$targetResult.Result) {
      'OK' { exit 0 }
      'WARN' { exit 2 }
      'FAIL' { exit 1 }
    }
  }

  if ($targetOutput.Count -gt 0) {
    Write-Warning "Target script emitted output but no valid V2 result."
  } else {
    Write-Warning "Target script did not emit a V2 result."
  }
  exit 1
}

exit $targetExitCode
