<#
.SYNOPSIS
  Runs deterministic code-quality gates for either BaselineOps release line.
.DESCRIPTION
  Enforces PowerShell lint, PowerShell and Rust metrics, and reviewed clone baselines.
#>

#requires -version 5.1

[CmdletBinding()]
param(
  [Parameter(Mandatory)]
  [ValidateSet('PowerShell', 'Rust', 'All')]
  [string]$ReleaseLine,
  [switch]$UpdateDuplicationBaseline,
  [switch]$SkipAnalyzer
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$qualityRoot = $PSScriptRoot
$rootPath = (Resolve-Path (Join-Path $qualityRoot '../..')).Path
Import-Module (Join-Path $qualityRoot 'ExternalAnalyzers.psm1') -Force
Import-Module (Join-Path $qualityRoot 'PowerShellMetrics.psm1') -Force
Import-Module (Join-Path $qualityRoot 'QualityScans.psm1') -Force
Import-Module (Join-Path $qualityRoot 'CloneBaseline.psm1') -Force

function Get-RequestedLines {
  param([string]$Requested)

  if ($Requested -eq 'All') { return @('PowerShell', 'Rust') }
  return @($Requested)
}

function Get-BaselinePath {
  param([string]$Line)

  return Join-Path $qualityRoot ("baselines/{0}.json" -f $Line.ToLowerInvariant())
}

function Read-UnvalidatedBaseline {
  param([string]$Path)

  if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $null }
  return Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
}

function Get-CurrentCloneEntries {
  param([string]$Line, [object]$Tools)

  $report = Invoke-JscpdScan -RootPath $rootPath -JscpdPath $Tools.Paths.Jscpd -ReleaseLine $Line
  return @(ConvertFrom-JscpdReport -Report $report -ReleaseLine $Line -Version $Tools.Versions.Jscpd)
}

function Update-RequestedBaseline {
  param([string]$Line, [object]$Tools)

  $current = Get-CurrentCloneEntries -Line $Line -Tools $Tools
  $path = Get-BaselinePath $Line
  $parent = Split-Path -Parent $path
  [void](New-Item -ItemType Directory -Path $parent -Force)
  Update-CloneBaseline -Path $path -Current $current -Existing (Read-UnvalidatedBaseline $path)
  Write-Output ("Updated {0} clone baseline with {1} fingerprint(s)." -f $Line, $current.Count)
}

function Get-CloneFindings {
  param([string]$Line, [object]$Tools)

  $current = Get-CurrentCloneEntries -Line $Line -Tools $Tools
  $baseline = Read-CloneBaseline -Path (Get-BaselinePath $Line) -ReleaseLine $Line `
    -Version $Tools.Versions.Jscpd
  return @(Compare-CloneBaseline -Current $current -Baseline $baseline -ReleaseLine $Line)
}

function Get-LineFindings {
  param([string]$Line, [object]$Tools, [switch]$SkipAnalyzer)

  $findings = @()
  if ($Line -eq 'PowerShell') {
    $paths = Get-QualitySourceFiles -RootPath $rootPath -ReleaseLine PowerShell
    if (-not ($SkipAnalyzer -or $env:CI_SKIP_ANALYZER)) {
      $findings += Invoke-PowerShellAnalyzerScan -RootPath $rootPath -Paths $paths
    }
    $findings += Get-PowerShellMetricFindings -RootPath $rootPath -Paths $paths
  } else {
    $paths = Get-QualitySourceFiles -RootPath $rootPath -ReleaseLine Rust
    $findings += Invoke-RustMetricScan -RootPath $rootPath -LizardPath $Tools.Paths.Lizard -Paths $paths
    $oraclePaths = Get-RustOraclePowerShellFiles -RootPath $rootPath
    if (-not ($SkipAnalyzer -or $env:CI_SKIP_ANALYZER)) {
      $findings += Invoke-PowerShellAnalyzerScan -RootPath $rootPath -Paths $oraclePaths
    }
    $findings += Get-PowerShellMetricFindings -RootPath $rootPath -Paths $oraclePaths
  }
  $findings += Get-CloneFindings -Line $Line -Tools $Tools
  return @($findings | Sort-Object Path, Line, Kind, Symbol)
}

function Write-Findings {
  param([object[]]$Findings)

  foreach ($finding in $Findings) {
    if ($finding.PSObject.Properties['Fingerprint']) {
      Write-Output ("{0} {1} fingerprint={2}" -f $finding.Path, $finding.Kind, $finding.Fingerprint)
      continue
    }
    $detail = "actual=$($finding.Actual) limit=$($finding.Limit)"
    Write-Output ("{0}:{1} {2} {3} {4}" -f $finding.Path, $finding.Line, $finding.Kind, $finding.Symbol, $detail)
  }
}

function Write-QualitySuccess {
  param([string[]]$Lines, [switch]$SkipAnalyzer)
  if ($SkipAnalyzer -or $env:CI_SKIP_ANALYZER) {
    Write-Output 'PSScriptAnalyzer: SKIPPED (explicit request); metrics and duplication: PASS'
    Write-Output ("Code quality: PARTIAL ({0})" -f ($lines -join ', '))
  } else {
    Write-Output ("Code quality: PASS ({0})" -f ($lines -join ', '))
  }
}

try {
  $tools = Initialize-QualityTools -RootPath $rootPath
  $lines = Get-RequestedLines $ReleaseLine
  if ($UpdateDuplicationBaseline) {
    foreach ($line in $lines) { Update-RequestedBaseline -Line $line -Tools $tools }
    Write-Output 'Review every REVIEW REQUIRED rationale before running the normal gate.'
    exit 0
  }
  $findings = @()
  foreach ($line in $lines) { $findings += Get-LineFindings -Line $line -Tools $tools -SkipAnalyzer:$SkipAnalyzer }
  if ($findings.Count -gt 0) {
    Write-Findings -Findings $findings
    [Console]::Error.WriteLine("Code quality failed with {0} finding(s).", $findings.Count)
    exit 1
  }
  Write-QualitySuccess -Lines $lines -SkipAnalyzer:$SkipAnalyzer
  exit 0
} catch {
  [Console]::Error.WriteLine($_.Exception.Message)
  exit 2
}
