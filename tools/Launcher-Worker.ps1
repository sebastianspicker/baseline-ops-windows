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

function Wait-LauncherStartGate {
  param([string]$Name)
  if ([string]::IsNullOrWhiteSpace($Name)) { return }
  $gate = $null
  try { $gate = [System.Threading.EventWaitHandle]::OpenExisting($Name); if (-not $gate.WaitOne(15000)) { throw 'Launcher process-tree initialization did not complete within 15 seconds.' } }
  finally { if ($null -ne $gate) { $gate.Dispose() } }
}

function Open-LauncherBootstrapLocks {
  $locks = New-Object System.Collections.Generic.List[System.IO.FileStream]
  foreach ($path in @($PSCommandPath, (Join-Path $PSScriptRoot 'Launcher.Core.psm1'), (Join-Path $PSScriptRoot '../lib/Validation.psm1'))) {
    $item = Get-Item -LiteralPath $path -Force -ErrorAction Stop
    if ($item.PSIsContainer -or ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) { throw "Launcher bootstrap component is not a regular file: $path" }
    $locks.Add([System.IO.File]::Open($item.FullName, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read))
  }
  return ,$locks
}

function Get-LauncherWorkerManifestJson {
  param([string]$Base64, [string]$Path)
  if (-not [string]::IsNullOrWhiteSpace($Base64)) {
    if ($Base64.Length -gt 24000 -or $Base64 -notmatch '^[a-zA-Z0-9+/]*={0,2}$') { throw 'Inherited launcher manifest encoding is invalid or oversized.' }
    return (New-Object System.Text.UTF8Encoding($false, $true)).GetString([Convert]::FromBase64String($Base64))
  }
  return Get-LauncherWorkerManifestFileJson -Path $Path
}

function Get-LauncherWorkerManifestFileJson {
  param([string]$Path)
  if ([string]::IsNullOrWhiteSpace($Path)) { throw 'Launcher manifest data was not provided.' }
  $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
  if ($item.PSIsContainer -or $item.Length -gt 16384 -or ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) { throw 'Launcher manifest file is invalid or oversized.' }
  return Get-BoundedUtf8FileContent -Path $item.FullName -MaximumBytes 16384
}

function Get-LauncherSelectedExecutionPath {
  param($Manifest)
  if ($Manifest.operation -eq 'run-script') { return Join-Path (Join-Path ([string]$Manifest.root) 'scripts') ([string]$Manifest.target) }
  return [string]$Manifest.target
}

function Close-LauncherWorkerResources {
  param($Closure, $Locks)
  if ($null -ne $Closure) { Exit-LauncherTrustedClosure -Closure $Closure }
  foreach ($lock in @($Locks)) { try { $lock.Dispose() } catch { Write-Verbose 'Launcher bootstrap lock cleanup failed.' } }
}

function Get-LauncherWorkerCommand {
  param($Manifest)
  $scripts = Join-Path ([string]$Manifest.root) 'scripts'
  switch ([string]$Manifest.operation) {
    'validate-profile' { return @{ Path = (Join-Path $scripts '00-Validate-Profile.ps1'); Parameters = @{ ProfilePath = [string]$Manifest.target; RootPath = [string]$Manifest.root; OutputFormat = 'Console' } } }
    'run-script' { return Get-LauncherWorkerScriptCommand -Manifest $Manifest -ScriptsPath $scripts }
    'run-profile' { return Get-LauncherWorkerProfileCommand -Manifest $Manifest -ScriptsPath $scripts }
  }
}

function Get-LauncherWorkerScriptCommand {
  param($Manifest, [string]$ScriptsPath)
  $name = [System.IO.Path]::GetFileName([string]$Manifest.target)
  if ($name -ne [string]$Manifest.target -or $name -notmatch '^\d{2}-[^\\/]+\.ps1$') { throw 'Manifest target is not a safe numbered script name.' }
  $parameters = @{ ScriptName = $name; RootPath = [string]$Manifest.root; ScriptArgs = (@('-Mode', [string]$Manifest.mode) + @($Manifest.argumentTokens)); OutputFormat = 'Console'; Confirm = $false }
  if ([bool]$Manifest.strict) { $parameters.ScriptArgs += '-Strict' }
  if ([bool]$Manifest.requireSigned) { $parameters.RequireSigned = $true }
  if (-not [string]::IsNullOrWhiteSpace([string]$Manifest.expectedHash)) { $parameters.ExpectedHash = [string]$Manifest.expectedHash; $parameters.HashAlgorithm = [string]$Manifest.hashAlgorithm }
  return @{ Path = (Join-Path $ScriptsPath '00-Run-Local.ps1'); Parameters = $parameters }
}

function Get-LauncherWorkerProfileCommand {
  param($Manifest, [string]$ScriptsPath)
  $parameters = @{ ProfilePath = [string]$Manifest.target; RootPath = [string]$Manifest.root; Mode = [string]$Manifest.mode; OutputFormat = 'Console'; Confirm = $false }
  if ([bool]$Manifest.strict) { $parameters.Strict = $true }
  if ([bool]$Manifest.requireSigned) { $parameters.RequireSigned = $true }
  return @{ Path = (Join-Path $ScriptsPath '00-Run-Profile.ps1'); Parameters = $parameters }
}

function Invoke-LauncherWorker {
  param([string]$WorkerManifestPath, [string]$WorkerManifestBase64)
  $closure = $null; $locks = $null
  try {
    Wait-LauncherStartGate -Name ([string]$env:BASELINEOPS_LAUNCHER_START_GATE)
    $locks = Open-LauncherBootstrapLocks
    Import-Module (Join-Path $PSScriptRoot 'Launcher.Core.psm1') -Force; Import-Module (Join-Path $PSScriptRoot '../lib/Validation.psm1')
    $manifest = (Get-LauncherWorkerManifestJson -Base64 $WorkerManifestBase64 -Path $WorkerManifestPath) | ConvertFrom-Json -ErrorAction Stop
    Assert-LauncherManifest -Manifest $manifest | Out-Null
    $selected = Get-LauncherSelectedExecutionPath -Manifest $manifest
    $closure = Enter-LauncherTrustedClosure -RootPath ([string]$manifest.root) -AdditionalPaths @($PSCommandPath, (Join-Path $PSScriptRoot 'Launcher.Core.psm1'), (Join-Path $PSScriptRoot '../lib/Validation.psm1'), $(if ($manifest.operation -in @('validate-profile', 'run-profile')) { [string]$manifest.target })) -Operation ([string]$manifest.operation) -SelectedExecutionPath $selected
    $command = Get-LauncherWorkerCommand -Manifest $manifest
    if (-not (Test-Path -LiteralPath $command.Path -PathType Leaf)) { throw "Launcher entry point not found: $($command.Path)" }
    & $command.Path @($command.Parameters) *>&1 | ForEach-Object { Write-Output ([string]$_) }
    return $(if ($null -eq $LASTEXITCODE) { 0 } else { [int]$LASTEXITCODE })
  } finally {
    Close-LauncherWorkerResources -Closure $closure -Locks $locks
  }
}

try { exit (Invoke-LauncherWorker -WorkerManifestPath $ManifestPath -WorkerManifestBase64 $ManifestBase64) }
catch { [Console]::Error.WriteLine("Launcher worker failed: {0}" -f $_.Exception.Message); exit 1 }
