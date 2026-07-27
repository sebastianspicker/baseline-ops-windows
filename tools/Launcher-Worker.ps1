#requires -Version 5.1
<#
.SYNOPSIS
  Executes a validated BaselineOps for Windows launcher manifest.
.DESCRIPTION
  Runs requested scripts inside the launcher's trusted, bounded worker process.
#>
[CmdletBinding()]
param(
  [string]$ManifestPath = $env:BASELINEOPS_LAUNCHER_MANIFEST,
  [string]$ManifestBase64 = $env:BASELINEOPS_LAUNCHER_MANIFEST_B64
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$InformationPreference = 'Continue'
$VerbosePreference = 'Continue'
$WarningPreference = 'Continue'

try {
  $trustedClosure = $null
  $bootstrapLocks = New-Object System.Collections.Generic.List[System.IO.FileStream]
  $startGateName = [string]$env:BASELINEOPS_LAUNCHER_START_GATE
  if (-not [string]::IsNullOrWhiteSpace($startGateName)) {
    $startGate = $null
    try {
      $startGate = [System.Threading.EventWaitHandle]::OpenExisting($startGateName)
      if (-not $startGate.WaitOne(15000)) {
        throw 'Launcher process-tree initialization did not complete within 15 seconds.'
      }
    } finally {
      if ($null -ne $startGate) { $startGate.Dispose() }
    }
  }

  # Lock the worker and its bootstrap modules before importing them.  The GUI
  # takes the same locks before creating this process; this local guard also
  # protects direct worker invocation used by automation and diagnostics.
  foreach ($bootstrapPath in @(
      $PSCommandPath,
      (Join-Path $PSScriptRoot 'Launcher.Core.psm1'),
      (Join-Path $PSScriptRoot '../lib/Validation.psm1')
    )) {
    $bootstrapItem = Get-Item -LiteralPath $bootstrapPath -Force -ErrorAction Stop
    if ($bootstrapItem.PSIsContainer -or ($bootstrapItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) {
      throw "Launcher bootstrap component is not a regular file: $bootstrapPath"
    }
    $bootstrapLocks.Add([System.IO.File]::Open($bootstrapItem.FullName, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read))
  }

  Import-Module (Join-Path $PSScriptRoot 'Launcher.Core.psm1') -Force
  Import-Module (Join-Path $PSScriptRoot '../lib/Validation.psm1')

  if (-not [string]::IsNullOrWhiteSpace($ManifestBase64)) {
    if ($ManifestBase64.Length -gt 24000 -or $ManifestBase64 -notmatch '^[a-zA-Z0-9+/]*={0,2}$') { throw 'Inherited launcher manifest encoding is invalid or oversized.' }
    $strictUtf8 = New-Object System.Text.UTF8Encoding($false, $true)
    $manifestJson = $strictUtf8.GetString([Convert]::FromBase64String($ManifestBase64))
  } else {
    if ([string]::IsNullOrWhiteSpace($ManifestPath)) { throw 'Launcher manifest data was not provided.' }
    $manifestItem = Get-Item -LiteralPath $ManifestPath -Force -ErrorAction Stop
    if ($manifestItem.PSIsContainer -or $manifestItem.Length -gt 16384 -or ($manifestItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) { throw 'Launcher manifest file is invalid or oversized.' }
    $manifestJson = Get-BoundedUtf8FileContent -Path $manifestItem.FullName -MaximumBytes 16384
  }
  $manifest = $manifestJson | ConvertFrom-Json -ErrorAction Stop
  Assert-LauncherManifest -Manifest $manifest | Out-Null
  $selectedExecutionPath = if ($manifest.operation -eq 'run-script') {
    Join-Path (Join-Path ([string]$manifest.root) 'scripts') ([string]$manifest.target)
  } else {
    [string]$manifest.target
  }
  $trustedClosure = Enter-LauncherTrustedClosure -RootPath ([string]$manifest.root) -AdditionalPaths @(
    $PSCommandPath,
    (Join-Path $PSScriptRoot 'Launcher.Core.psm1'),
    (Join-Path $PSScriptRoot '../lib/Validation.psm1'),
    $(if ($manifest.operation -in @('validate-profile', 'run-profile')) { [string]$manifest.target })
  ) -Operation ([string]$manifest.operation) -SelectedExecutionPath $selectedExecutionPath

  $scriptsPath = Join-Path ([string]$manifest.root) 'scripts'
  $parameters = @{}
  switch ([string]$manifest.operation) {
    'validate-profile' {
      $entryPoint = Join-Path $scriptsPath '00-Validate-Profile.ps1'
      $parameters = @{ ProfilePath = [string]$manifest.target; RootPath = [string]$manifest.root; OutputFormat = 'Console' }
    }
    'run-script' {
      $entryPoint = Join-Path $scriptsPath '00-Run-Local.ps1'
      $scriptName = [System.IO.Path]::GetFileName([string]$manifest.target)
      if ($scriptName -ne [string]$manifest.target -or $scriptName -notmatch '^\d{2}-[^\\/]+\.ps1$') { throw 'Manifest target is not a safe numbered script name.' }
      $scriptArguments = @('-Mode', [string]$manifest.mode) + @($manifest.argumentTokens)
      if ([bool]$manifest.strict) { $scriptArguments += '-Strict' }
      $parameters = @{
        ScriptName = $scriptName; RootPath = [string]$manifest.root; ScriptArgs = $scriptArguments;
        OutputFormat = 'Console'; Confirm = $false
      }
      if ([bool]$manifest.requireSigned) { $parameters.RequireSigned = $true }
      if (-not [string]::IsNullOrWhiteSpace([string]$manifest.expectedHash)) {
        $parameters.ExpectedHash = [string]$manifest.expectedHash
        $parameters.HashAlgorithm = [string]$manifest.hashAlgorithm
      }
    }
    'run-profile' {
      $entryPoint = Join-Path $scriptsPath '00-Run-Profile.ps1'
      $parameters = @{
        ProfilePath = [string]$manifest.target; RootPath = [string]$manifest.root;
        Mode = [string]$manifest.mode; OutputFormat = 'Console'; Confirm = $false
      }
      if ([bool]$manifest.strict) { $parameters.Strict = $true }
      if ([bool]$manifest.requireSigned) { $parameters.RequireSigned = $true }
    }
  }

  if (-not (Test-Path -LiteralPath $entryPoint -PathType Leaf)) { throw "Launcher entry point not found: $entryPoint" }
  & $entryPoint @parameters *>&1 | ForEach-Object { Write-Output ([string]$_) }
  if ($null -eq $LASTEXITCODE) { exit 0 }
  exit [int]$LASTEXITCODE
} catch {
  [Console]::Error.WriteLine("Launcher worker failed: {0}" -f $_.Exception.Message)
  exit 1
} finally {
  if ($null -ne $trustedClosure) { Exit-LauncherTrustedClosure -Closure $trustedClosure }
  if ($null -ne $bootstrapLocks) {
    foreach ($bootstrapLock in $bootstrapLocks) { try { $bootstrapLock.Dispose() } catch { Write-Verbose 'Launcher bootstrap lock cleanup failed.' } }
  }
}
