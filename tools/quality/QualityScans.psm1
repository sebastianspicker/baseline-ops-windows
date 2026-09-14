<#
.SYNOPSIS
  Enumerates maintained source and runs repository quality scans.
.DESCRIPTION
  Provides deterministic PowerShell lint, Rust Lizard metrics, and jscpd report generation.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-QualitySourceFiles {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$RootPath,
    [ValidateSet('PowerShell', 'Rust')][string]$ReleaseLine
  )

  if ($ReleaseLine -eq 'Rust') {
    return @(Get-ChildItem -LiteralPath (Join-Path $RootPath 'rust') -Recurse -File -Filter '*.rs' |
        Where-Object { $_.FullName -notmatch '[/\\]target[/\\]' } |
        ForEach-Object FullName | Sort-Object -Unique)
  }
  $files = @()
  foreach ($directory in @('scripts', 'lib', 'tools', 'tests')) {
    $path = Join-Path $RootPath $directory
    if (-not (Test-Path -LiteralPath $path -PathType Container)) { continue }
    $files += Get-ChildItem -LiteralPath $path -Recurse -File |
      Where-Object {
        $_.Extension -in @('.ps1', '.psm1') -and
        $_.FullName -notmatch '[/\\]rust[/\\]' -and
        $_.FullName -notmatch '[/\\]tests[/\\]RustV3Oracle[^/\\]*\.ps1$'
      } |
      ForEach-Object FullName
  }
  return @($files | Sort-Object -Unique)
}

function Get-RustOraclePowerShellFiles {
  param([Parameter(Mandatory)][string]$RootPath)

  $files = @()
  $oraclePath = Join-Path $RootPath 'rust/oracles'
  if (Test-Path -LiteralPath $oraclePath) {
    $files += Get-ChildItem -LiteralPath $oraclePath -File -Recurse |
      Where-Object { $_.Extension -in @('.ps1', '.psm1') } | ForEach-Object FullName
  }
  $files += Get-ChildItem -LiteralPath (Join-Path $RootPath 'tests') -File -Filter 'RustV3Oracle*.ps1' |
    ForEach-Object FullName
  return @($files | Sort-Object -Unique)
}

function Get-QualityRelativePath {
  param([string]$RootPath, [string]$Path)

  $root = [System.IO.Path]::GetFullPath($RootPath).TrimEnd([char[]]@([char]'/', [char]92))
  return ([System.IO.Path]::GetFullPath($Path)).Substring($root.Length + 1).Replace([char]92, [char]47)
}

function Invoke-PowerShellAnalyzerScan {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$RootPath,
    [Parameter(Mandatory)][string[]]$Paths
  )

  if ($Paths.Count -eq 0) { throw 'PSScriptAnalyzer scan matched zero files.' }
  $settings = Join-Path $RootPath 'PSScriptAnalyzerSettings.psd1'
  $findings = @()
  foreach ($path in @($Paths | Sort-Object -Unique)) {
    try {
      $items = @(Invoke-ScriptAnalyzer -Path $path -Settings $settings -ErrorAction Stop)
    } catch {
      $findings += [pscustomobject]@{
        Kind = 'analyzer_error'; Path = Get-QualityRelativePath $RootPath $path
        Symbol = ''; Line = 0; Actual = 1; Limit = 0; Message = $_.Exception.Message
      }
      continue
    }
    foreach ($item in $items) {
      $findings += [pscustomobject]@{
        Kind = [string]$item.RuleName
        Path = Get-QualityRelativePath $RootPath $path
        Symbol = ''
        Line = [int]$item.Line
        Actual = 1
        Limit = 0
        Message = [string]$item.Message
      }
    }
  }
  return @($findings | Sort-Object Path, Line, Kind)
}

function New-RustMetricFinding {
  param([string]$Kind, [string]$Path, [string]$Symbol, [int]$Line, [int]$Actual, [int]$Limit)

  return [pscustomobject]@{
    Kind = $Kind; Path = $Path.Replace([char]92, [char]47); Symbol = $Symbol
    Line = $Line; Actual = $Actual; Limit = $Limit; Message = ''
  }
}

function Read-LizardFunctionFindings {
  param([string]$CsvPath)

  $headers = @('Nloc', 'Ccn', 'Tokens', 'Parameters', 'Length', 'LongName', 'Path', 'Name', 'Signature', 'Start', 'End')
  $rows = @(Get-Content -LiteralPath $CsvPath | ConvertFrom-Csv -Header $headers)
  $findings = @()
  foreach ($row in $rows) {
    if ([int]$row.Nloc -gt 49) {
      $findings += New-RustMetricFinding function_nloc $row.Path $row.Name ([int]$row.Start) ([int]$row.Nloc) 49
    }
    if ([int]$row.Ccn -gt 7) {
      $findings += New-RustMetricFinding function_ccn $row.Path $row.Name ([int]$row.Start) ([int]$row.Ccn) 7
    }
    if ([int]$row.Parameters -gt 8) {
      $findings += New-RustMetricFinding function_parameters $row.Path $row.Name ([int]$row.Start) ([int]$row.Parameters) 8
    }
  }
  return @($findings)
}

function Read-LizardFileFindings {
  param([string]$XmlPath)

  [xml]$xml = Get-Content -LiteralPath $XmlPath -Raw
  $fileMeasure = @($xml.cppncss.measure | Where-Object { $_.type -eq 'File' })[0]
  if (-not $fileMeasure) { throw 'Lizard XML omitted file metrics.' }
  $findings = @()
  foreach ($item in @($fileMeasure.item)) {
    $nloc = [int]$item.value[1]
    if ($nloc -gt 499) { $findings += New-RustMetricFinding file_nloc $item.name '<file>' 1 $nloc 499 }
  }
  return @($findings)
}

function Invoke-RustMetricScan {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$RootPath,
    [Parameter(Mandatory)][string]$LizardPath,
    [Parameter(Mandatory)][string[]]$Paths
  )

  if ($Paths.Count -eq 0) { throw 'Lizard Rust scan matched zero files.' }
  $reportRoot = Join-Path $RootPath '.cache/quality/reports/rust-lizard'
  [void](New-Item -ItemType Directory -Path $reportRoot -Force)
  $manifest = Join-Path $reportRoot 'files.txt'
  @($Paths | Sort-Object -Unique | ForEach-Object {
      Get-QualityRelativePath -RootPath $RootPath -Path $_
    }) | Set-Content -LiteralPath $manifest -Encoding UTF8
  $csv = Join-Path $reportRoot 'lizard.csv'
  $xml = Join-Path $reportRoot 'lizard.xml'
  Push-Location $RootPath
  try {
    & $LizardPath '-l' 'rust' '--csv' '-f' $manifest | Set-Content -LiteralPath $csv -Encoding UTF8
    if ($LASTEXITCODE -ne 0) { throw 'Lizard CSV scan failed.' }
    & $LizardPath '-l' 'rust' '--xml' '-o' $xml '-f' $manifest | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Lizard XML scan failed.' }
  } finally {
    Pop-Location
  }
  $findings = @(Read-LizardFunctionFindings $csv)
  $findings += Read-LizardFileFindings $xml
  return @($findings | Sort-Object Path, Line, Kind, Symbol)
}

function Get-JscpdScanRoots {
  param(
    [Parameter(Mandatory)][string]$RootPath,
    [ValidateSet('PowerShell', 'Rust')][string]$ReleaseLine
  )

  if ($ReleaseLine -eq 'PowerShell') { return ,([string]$RootPath) }
  $roots = @((Join-Path $RootPath 'rust'))
  $roots += @(
    Get-ChildItem -LiteralPath (Join-Path $RootPath 'tests') -File -Filter 'RustV3Oracle*.ps1' |
      ForEach-Object FullName
  )
  return @($roots)
}

function Invoke-JscpdScan {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$RootPath,
    [Parameter(Mandatory)][string]$JscpdPath,
    [ValidateSet('PowerShell', 'Rust')][string]$ReleaseLine
  )

  $qualityRoot = Join-Path $RootPath 'tools/quality'
  $slug = $ReleaseLine.ToLowerInvariant()
  $config = Join-Path $qualityRoot ".jscpd-$slug.json"
  $output = Join-Path $RootPath ".cache/quality/reports/jscpd-$slug"
  [void](New-Item -ItemType Directory -Path $output -Force)
  # The array subexpression prevents a single root from being unwrapped into
  # a scalar whose characters native-command splatting would pass separately.
  $scanRoots = @(Get-JscpdScanRoots -RootPath $RootPath -ReleaseLine $ReleaseLine)
  & $JscpdPath '--config' $config '--reporters' 'json,silent' '--output' $output `
    '--no-colors' '--no-tips' '--exit-code' '0' @scanRoots | Out-Null
  if ($LASTEXITCODE -ne 0) { throw "jscpd $ReleaseLine scan failed." }
  $reportPath = Join-Path $output 'jscpd-report.json'
  if (-not (Test-Path -LiteralPath $reportPath -PathType Leaf)) { throw 'jscpd did not write its JSON report.' }
  return Get-Content -LiteralPath $reportPath -Raw | ConvertFrom-Json
}

Export-ModuleMember -Function Get-QualitySourceFiles, Get-RustOraclePowerShellFiles, `
  Invoke-PowerShellAnalyzerScan, Invoke-RustMetricScan, Invoke-JscpdScan
