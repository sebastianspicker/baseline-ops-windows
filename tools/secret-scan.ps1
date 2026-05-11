#requires -version 5.1
<#!
.SYNOPSIS
Basic secret scan for common patterns.

.DESCRIPTION
Scans tracked files for common secret patterns without printing secret values.
Outputs file path, line number, and pattern label. Fails with exit code 1 if any
matches are found (default).

.PARAMETER RootPath
Root path to scan (default: repo root).

.PARAMETER FailOnMatch
If set (default), exits with code 1 when matches are found.

.PARAMETER Exclude
Folder names to exclude from scanning.
#>

[CmdletBinding()]
param(
  [string]$RootPath = '',
  [switch]$FailOnMatch = $true,
  [string[]]$Exclude = @('.git','node_modules','bin','obj','dist','_extracted')
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ([string]::IsNullOrWhiteSpace($RootPath)) {
  $scriptPath = $MyInvocation.MyCommand.Path
  if (-not $scriptPath) { $scriptPath = $PSCommandPath }
  if (-not $scriptPath) { $scriptPath = (Get-Location).Path }

  if (Test-Path -LiteralPath $scriptPath -PathType Container) {
    $scriptDir = $scriptPath
  } else {
    $scriptDir = Split-Path -Parent $scriptPath
  }

  $RootPath = (Resolve-Path (Join-Path $scriptDir '..')).Path
}

$patterns = @(
  @{ Name = 'AWS Access Key'; Regex = 'AKIA[0-9A-Z]{16}' },
  @{ Name = 'Private Key'; Regex = '-----BEGIN (RSA|EC|OPENSSH|PRIVATE) PRIVATE KEY-----' },
  @{ Name = 'GitHub Token'; Regex = 'ghp_[0-9A-Za-z]{36}' },
  @{ Name = 'Slack Token'; Regex = 'xox[baprs]-[0-9A-Za-z-]{10,48}' },
  # Generic patterns: tuned to reduce false positives while catching likely hardcoded secrets.
  # Negative lookbehind (?<!\$) excludes PowerShell variable names like $password or $token.
  @{ Name = 'Generic Password'; Regex = '(?i)(?<!\$)\bpassword\b\s*[:=]\s*(?!\$)(?:"[^"\r\n]{6,}"|''[^''\r\n]{6,}''|[^\s#]{6,})' },
  @{ Name = 'Generic Token'; Regex = '(?i)(?<!\$)\btoken\b\s*[:=]\s*(?!\$)(?:"[^"\r\n]{10,}"|''[^''\r\n]{10,}''|[^\s#]{10,})' }
)

$allowedExt = @(
  '.ps1','.psm1','.psd1',
  '.md','.txt','.json','.yml','.yaml','.xml','.cfg','.ini','.toml','.csv','.log'
)

$files = @()
if (Get-Command -Name git -ErrorAction SilentlyContinue) {
  $gitRootCheck = & git -C $RootPath rev-parse --is-inside-work-tree 2>$null
  if ($LASTEXITCODE -eq 0 -and [string]$gitRootCheck -eq 'true') {
    $files = & git -C $RootPath ls-files
    $files = $files | ForEach-Object { Join-Path $RootPath $_ }
  }

  if (-not $files -or @($files).Count -eq 0) {
    $global:LASTEXITCODE = 0
  }
}

if (-not $files -or @($files).Count -eq 0) {
  Write-Warning 'git tracked-file list unavailable; falling back to recursive file scan.'
  $files = Get-ChildItem -Path $RootPath -File -Recurse | ForEach-Object { $_.FullName }
}

$filtered = @()
foreach ($f in $files) {
  if (-not (Test-Path -LiteralPath $f)) { continue }
  $skip = $false
  foreach ($ex in $Exclude) {
    if ($f -match ([regex]::Escape("${ex}"))) { $skip = $true; break }
  }
  if ($skip) { continue }
  $ext = [System.IO.Path]::GetExtension($f)
  if ($ext -and ($allowedExt -notcontains $ext)) { continue }
  $filtered += $f
}

$findings = New-Object System.Collections.Generic.List[object]

foreach ($p in $patterns) {
  if (-not $filtered -or @($filtered).Count -eq 0) { break }
  $patternMatches = Select-String -Path $filtered -Pattern $p.Regex -AllMatches -ErrorAction SilentlyContinue
  foreach ($m in $patternMatches) {
    $findings.Add([pscustomobject]@{
      File     = $m.Path
      Line     = $m.LineNumber
      Pattern  = $p.Name
    }) | Out-Null
  }
}

if ($findings.Count -gt 0) {
  Write-Host "Secret scan: potential matches found: $($findings.Count)" -ForegroundColor Yellow
  $findings | Sort-Object File,Line | ForEach-Object {
    Write-Host ("- {0}:{1} ({2})" -f $_.File, $_.Line, $_.Pattern) -ForegroundColor Yellow
  }
  if ($FailOnMatch) { exit 1 }
} else {
  Write-Host 'Secret scan: no matches found.' -ForegroundColor Green
}
