#requires -Version 5.1
[CmdletBinding()]
param([string]$ManifestPath = $env:WIN_MDM_LAUNCHER_MANIFEST)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$InformationPreference = 'Continue'
$VerbosePreference = 'Continue'
$WarningPreference = 'Continue'

Import-Module (Join-Path $PSScriptRoot 'Launcher.Core.psm1') -Force

try {
  if ([string]::IsNullOrWhiteSpace($ManifestPath)) { throw 'Launcher manifest path was not provided.' }
  if (-not (Test-Path -LiteralPath $ManifestPath -PathType Leaf)) { throw "Launcher manifest not found: $ManifestPath" }
  $manifest = Get-Content -LiteralPath $ManifestPath -Raw -Encoding UTF8 | ConvertFrom-Json -ErrorAction Stop
  Assert-LauncherManifest -Manifest $manifest | Out-Null

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
}
