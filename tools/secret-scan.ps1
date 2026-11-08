#requires -version 5.1
<#
.SYNOPSIS
Basic secret scan for common patterns.

.DESCRIPTION
Scans tracked and untracked non-ignored files for common secret patterns without
printing secret values. Outputs file path, line number, and pattern label. Fails
with exit code 1 if any matches are found (default).

.PARAMETER RootPath
Root path to scan (default: repo root).

.PARAMETER NoFail
Report matches without exiting with code 1.

.PARAMETER Exclude
Folder names to exclude from scanning.
#>

[CmdletBinding()]
param(
  [string]$RootPath = '',
  [switch]$NoFail,
  [string[]]$Exclude = @('.git','node_modules','bin','obj','dist','_extracted')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot '../lib/External.psm1') -Force -DisableNameChecking
Import-Module (Join-Path $PSScriptRoot '../lib/Validation.psm1')
Import-Module (Join-Path $PSScriptRoot '../lib/Common.psm1')

$RootPath = Resolve-ToolRepositoryRoot -RootPath $RootPath -InvocationPath $MyInvocation.MyCommand.Path -FallbackPath $PSCommandPath

$patterns = @(
  @{ Name = 'AWS Access Key'; Regex = 'AKIA[0-9A-Z]{16}' },
  @{ Name = 'Private Key'; Regex = '-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----' },
  @{ Name = 'GitHub Token'; Regex = 'ghp_[0-9A-Za-z]{36}' },
  @{ Name = 'Slack Token'; Regex = 'xox[baprs]-[0-9A-Za-z-]{10,48}' },
  # Generic patterns: tuned to reduce false positives while catching likely hardcoded secrets.
  # Negative lookbehind (?<!\$) excludes PowerShell variable names like $password or $token.
  @{ Name = 'Generic Password'; Regex = '(?i)(?<!\$)\bpassword\b\s*[:=]\s*(?!\$)(?:"[^"\r\n]{6,}"|''[^''\r\n]{6,}''|[^\s#]{6,})' },
  @{ Name = 'Generic Token'; Regex = '(?i)(?<!\$)\btoken\b\s*[:=]\s*(?!\$)(?:"[^"\r\n]{10,}"|''[^''\r\n]{10,}''|(?=[A-Za-z0-9._~+/-]*[0-9])[A-Za-z0-9._~+/-]{10,})' }
)

$allowedExt = @(
  '.ps1','.psm1','.psd1',
  '.md','.txt','.json','.yml','.yaml','.xml','.cfg','.ini','.toml','.csv','.log',
  '.sh','.js','.mjs','.cjs','.rs','.lock','.svg','.html','.css','.properties'
)

<#
.SYNOPSIS
Tests whether a candidate path contains an excluded directory segment.
.DESCRIPTION
Matches complete path segments so similarly named files are not silently skipped.
#>
function Test-ExcludedPath {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Path,
    [string[]]$ExcludedSegments
  )

  $segments = [regex]::Split($Path, '[\\/]+') | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
  foreach ($segment in $segments) {
    if ($ExcludedSegments -contains $segment) {
      return $true
    }
  }

  return $false
}

function Get-SecretScanFiles {
  <# .SYNOPSIS Discovers candidate scan files. .DESCRIPTION Uses bounded Git discovery before a recursive fallback. #>
  param([Parameter(Mandatory)][string]$Path)
  $gitFiles = Get-GitWorkingTreeFiles -Path $Path
  if ($null -ne $gitFiles) { return $gitFiles }
  Write-Warning 'git tracked-file list unavailable; falling back to recursive file scan.'
  $global:LASTEXITCODE = 0
  return @(Get-ChildItem -Path $Path -File -Recurse | ForEach-Object { $_.FullName })
}

function Select-SecretScanFiles {
  <# .SYNOPSIS Filters candidate scan files. .DESCRIPTION Keeps only allowed extensions outside excluded segments. #>
  param([string[]]$Files, [string[]]$ExcludedSegments, [string[]]$AllowedExtensions)
  return @($Files | Where-Object { Test-Path -LiteralPath $_ } | Where-Object { -not (Test-ExcludedPath -Path $_ -ExcludedSegments $ExcludedSegments) } | Where-Object {
      $extension = [System.IO.Path]::GetExtension($_)
      -not $extension -or $AllowedExtensions -contains $extension
    })
}

function Find-SecretScanMatches {
  <# .SYNOPSIS Finds configured secret patterns. .DESCRIPTION Produces metadata without echoing matched content. #>
  param([object[]]$Patterns, [string[]]$Files)
  $findings = New-Object System.Collections.Generic.List[object]
  $unreadable = @{}
  foreach ($pattern in $Patterns) {
    $readErrors = $null
    foreach ($match in @(Select-String -LiteralPath $Files -Pattern $pattern.Regex -AllMatches -ErrorAction SilentlyContinue -ErrorVariable readErrors)) {
      $findings.Add([pscustomobject]@{ File = $match.Path; Line = $match.LineNumber; Pattern = $pattern.Name }) | Out-Null
    }
    foreach ($readError in @($readErrors)) {
      # Select-String leaves TargetObject empty; recover the path from the message.
      $message = $readError.Exception.Message
      $path = @($Files | Where-Object { $message.Contains($_) } | Select-Object -First 1)
      $unreadable[$(if ($path.Count) { $path[0] } else { $message })] = $true
    }
  }
  # A file the scan cannot read is a finding: skipping it would hide secrets.
  foreach ($path in @($unreadable.Keys | Sort-Object)) {
    $findings.Add([pscustomobject]@{ File = $path; Line = 0; Pattern = 'Unreadable file' }) | Out-Null
  }
  return ,$findings
}

function Write-SecretScanResult {
  <# .SYNOPSIS Reports scan findings. .DESCRIPTION Returns the compatible process exit code. #>
  param($Findings, [switch]$DoNotFail)
  if ($Findings.Count -eq 0) { Write-Information -MessageData 'Secret scan: no matches found.' -InformationAction Continue; return 0 }
  Write-Information -MessageData "Secret scan: potential matches found: $($Findings.Count)" -InformationAction Continue
  $Findings | Sort-Object File,Line | ForEach-Object { Write-Information -MessageData ("- {0}:{1} ({2})" -f $_.File, $_.Line, $_.Pattern) -InformationAction Continue }
  return $(if ($DoNotFail) { 0 } else { 1 })
}

function Invoke-SecretScan {
  <# .SYNOPSIS Runs the configured secret scan. .DESCRIPTION Resolves the scan root and returns its status. #>
  param([string]$RequestedRoot, [switch]$DoNotFail, [string[]]$ExcludedSegments, [string[]]$AllowedExtensions, [object[]]$Patterns)
  $resolvedRoot = if ([string]::IsNullOrWhiteSpace($RequestedRoot)) { Split-Path -Parent $PSScriptRoot } else { $RequestedRoot }
  $resolvedRoot = (Resolve-Path -LiteralPath $resolvedRoot -ErrorAction Stop).Path
  if (-not (Test-Path -LiteralPath $resolvedRoot -PathType Container)) { throw "Secret scan root is not a directory: $resolvedRoot" }
  $files = Get-SecretScanFiles -Path $resolvedRoot
  $filtered = Select-SecretScanFiles -Files $files -ExcludedSegments $ExcludedSegments -AllowedExtensions $AllowedExtensions
  return Write-SecretScanResult -Findings (Find-SecretScanMatches -Patterns $Patterns -Files $filtered) -DoNotFail:$DoNotFail
}

exit (Invoke-SecretScan -RequestedRoot $RootPath -DoNotFail:$NoFail -ExcludedSegments $Exclude -AllowedExtensions $allowedExt -Patterns $patterns)
