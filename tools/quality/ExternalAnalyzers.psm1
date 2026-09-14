<#
.SYNOPSIS
  Installs and invokes pinned repository quality analyzers.
.DESCRIPTION
  Keeps analyzer dependencies in the ignored .cache/quality directory and validates exact versions.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Invoke-QualityNative {
  param(
    [Parameter(Mandatory)][string]$Command,
    [Parameter(Mandatory)][string[]]$Arguments,
    [switch]$AllowFindings
  )

  $output = @(& $Command @Arguments 2>&1)
  $exitCode = $LASTEXITCODE
  if ($exitCode -ne 0 -and -not ($AllowFindings -and $exitCode -eq 1)) {
    throw "Quality tool failed ($exitCode): $Command $($Arguments -join ' ')`n$($output -join [Environment]::NewLine)"
  }
  return @($output)
}

function Get-QualityToolPaths {
  param([Parameter(Mandatory)][string]$RootPath)

  $qualityRoot = Join-Path $RootPath 'tools/quality'
  $cacheRoot = Join-Path $RootPath '.cache/quality'
  $isWindowsHost = [System.IO.Path]::DirectorySeparatorChar -eq [char]92
  $lizard = if ($isWindowsHost) {
    Join-Path $cacheRoot 'lizard/.venv/Scripts/lizard.exe'
  } else {
    Join-Path $cacheRoot 'lizard/.venv/bin/lizard'
  }
  $jscpd = if ($isWindowsHost) {
    Join-Path $cacheRoot 'jscpd/node_modules/.bin/jscpd.cmd'
  } else {
    Join-Path $cacheRoot 'jscpd/node_modules/.bin/jscpd'
  }
  return [pscustomobject]@{
    QualityRoot = $qualityRoot
    CacheRoot = $cacheRoot
    Lizard = $lizard
    Jscpd = $jscpd
    AnalyzerRoot = Join-Path $cacheRoot 'powershell'
  }
}

function Install-LizardTool {
  param([object]$Paths)

  if (Test-Path -LiteralPath $Paths.Lizard -PathType Leaf) { return }
  $toolRoot = Join-Path $Paths.CacheRoot 'lizard'
  [void](New-Item -ItemType Directory -Path $toolRoot -Force)
  $python = Get-Command python3 -ErrorAction SilentlyContinue
  if (-not $python) { $python = Get-Command python -ErrorAction SilentlyContinue }
  if (-not $python) { throw 'Python 3 with venv support is required to install Lizard.' }
  Invoke-QualityNative -Command $python.Source -Arguments @('-m', 'venv', (Join-Path $toolRoot '.venv')) | Out-Null
  $pip = if ([System.IO.Path]::DirectorySeparatorChar -eq [char]92) {
    Join-Path $toolRoot '.venv/Scripts/pip.exe'
  } else {
    Join-Path $toolRoot '.venv/bin/pip'
  }
  $requirements = Join-Path $Paths.QualityRoot 'requirements-lizard.txt'
  Invoke-QualityNative -Command $pip -Arguments @(
    'install', '--disable-pip-version-check', '--require-hashes', '-r', $requirements
  ) | Out-Null
}

function Install-JscpdTool {
  param([object]$Paths)

  if (Test-Path -LiteralPath $Paths.Jscpd -PathType Leaf) { return }
  $toolRoot = Join-Path $Paths.CacheRoot 'jscpd'
  [void](New-Item -ItemType Directory -Path $toolRoot -Force)
  Copy-Item -LiteralPath (Join-Path $Paths.QualityRoot 'jscpd/package.json') -Destination $toolRoot -Force
  Copy-Item -LiteralPath (Join-Path $Paths.QualityRoot 'jscpd/package-lock.json') -Destination $toolRoot -Force
  $npm = Get-Command npm -ErrorAction SilentlyContinue
  if (-not $npm) { throw 'npm is required to install jscpd.' }
  Invoke-QualityNative -Command $npm.Source -Arguments @(
    'ci', '--ignore-scripts', '--no-audit', '--no-fund', '--prefix', $toolRoot
  ) | Out-Null
}

function Install-AnalyzerModule {
  param([object]$Paths, [string]$Version)

  $manifest = Join-Path $Paths.AnalyzerRoot "PSScriptAnalyzer/$Version/PSScriptAnalyzer.psd1"
  if (-not (Test-Path -LiteralPath $manifest -PathType Leaf)) {
    [void](New-Item -ItemType Directory -Path $Paths.AnalyzerRoot -Force)
    Save-Module -Name PSScriptAnalyzer -RequiredVersion $Version -Path $Paths.AnalyzerRoot -Force
  }
  Import-Module $manifest -Global -Force
  $actual = (Get-Module PSScriptAnalyzer).Version.ToString()
  if ($actual -cne $Version) { throw "PSScriptAnalyzer version drift: $actual" }
  return $manifest
}

function Assert-QualityToolVersions {
  param([object]$Paths, [hashtable]$Versions)

  $lizardOutput = @(Invoke-QualityNative -Command $Paths.Lizard -Arguments @('--version'))
  $lizardVersion = $lizardOutput[-1].ToString().Trim()
  if ($lizardVersion -cne $Versions.Lizard) { throw "Lizard version drift: $lizardVersion" }
  $jscpdOutput = @(Invoke-QualityNative -Command $Paths.Jscpd -Arguments @('--version'))
  $jscpdVersion = $jscpdOutput[-1].ToString().Trim()
  if ($jscpdVersion -notmatch [regex]::Escape($Versions.Jscpd) + '$') {
    throw "jscpd version drift: $jscpdVersion"
  }
}

function Initialize-QualityTools {
  [CmdletBinding()]
  param([Parameter(Mandatory)][string]$RootPath)

  $paths = Get-QualityToolPaths -RootPath $RootPath
  [void](New-Item -ItemType Directory -Path $paths.CacheRoot -Force)
  $versions = Import-PowerShellDataFile (Join-Path $paths.QualityRoot 'tool-versions.psd1')
  Install-LizardTool -Paths $paths
  Install-JscpdTool -Paths $paths
  $paths | Add-Member NoteProperty AnalyzerManifest (
    Install-AnalyzerModule -Paths $paths -Version $versions.PSScriptAnalyzer
  )
  Assert-QualityToolVersions -Paths $paths -Versions $versions
  return [pscustomobject]@{ Paths = $paths; Versions = $versions }
}

Export-ModuleMember -Function Initialize-QualityTools, Invoke-QualityNative
