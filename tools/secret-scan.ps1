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
$RootPath = (Resolve-Path -LiteralPath $RootPath -ErrorAction Stop).Path
if (-not (Test-Path -LiteralPath $RootPath -PathType Container)) {
  throw "Secret scan root is not a directory: $RootPath"
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
  '.md','.txt','.json','.yml','.yaml','.xml','.cfg','.ini','.toml','.csv','.log',
  '.sh','.js','.mjs','.cjs','.svg','.html','.css','.properties'
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

<#
.SYNOPSIS
Runs a Git discovery command with bounded output and duration.
.DESCRIPTION
Prevents repository metadata enumeration from blocking or exhausting the scan.
#>
function Invoke-BoundedGitCommand {
  [CmdletBinding()]
  param([Parameter(Mandatory)][string[]]$Arguments)

  return Invoke-NativeCommand -Command 'git' -Arguments $Arguments -CaptureOutput -Quiet `
    -TimeoutSeconds 30 -MaxOutputBytes 1048576
}

<#
.SYNOPSIS
Converts one Git-reported path to a validated absolute scan path.
.DESCRIPTION
Rejects rooted, control-character, and escaping paths before any file is read.
#>
function ConvertTo-RootedGitFilePath {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$RelativePath,
    [Parameter(Mandatory)][string]$Root
  )

  if ([string]::IsNullOrWhiteSpace($RelativePath) -or
      [System.IO.Path]::IsPathRooted($RelativePath) -or
      $RelativePath -match '[\x00-\x1F\x7F]') {
    throw 'git returned an unsafe repository-relative path.'
  }

  $rootFull = [System.IO.Path]::GetFullPath($Root).TrimEnd([char[]]@([System.IO.Path]::DirectorySeparatorChar, [System.IO.Path]::AltDirectorySeparatorChar))
  $candidateFull = [System.IO.Path]::GetFullPath((Join-Path $rootFull $RelativePath))
  if (-not (Test-PathUnderRoot -Path $candidateFull -Root $rootFull)) {
    throw 'git returned a path outside the requested scan root.'
  }

  return $candidateFull
}

$files = @()
if (Test-CommandExists -Name 'git') {
  $gitRootCheck = Invoke-BoundedGitCommand -Arguments @('-C', $RootPath, 'rev-parse', '--is-inside-work-tree')
  if ($gitRootCheck -and $gitRootCheck.Success -and -not $gitRootCheck.TimedOut -and -not $gitRootCheck.OutputTruncated -and
      -not $gitRootCheck.StderrTruncated -and $gitRootCheck.Stdout.Trim() -eq 'true') {
    $gitFiles = Invoke-BoundedGitCommand -Arguments @('-C', $RootPath, 'ls-files', '-z', '--cached', '--others', '--exclude-standard')
    if ($gitFiles -and $gitFiles.Success -and -not $gitFiles.TimedOut -and -not $gitFiles.OutputTruncated -and -not $gitFiles.StderrTruncated) {
      $files = @($gitFiles.Stdout.Split([char]0) |
        Where-Object { $_ -ne '' } |
        ForEach-Object { ConvertTo-RootedGitFilePath -RelativePath $_ -Root $RootPath })
    }
  }
}

if (-not $files -or @($files).Count -eq 0) {
  Write-Warning 'git tracked-file list unavailable; falling back to recursive file scan.'
  $files = Get-ChildItem -Path $RootPath -File -Recurse | ForEach-Object { $_.FullName }
  $global:LASTEXITCODE = 0
}

$filtered = @()
foreach ($f in $files) {
  if (-not (Test-Path -LiteralPath $f)) { continue }
  $skip = Test-ExcludedPath -Path $f -ExcludedSegments $Exclude
  if ($skip) { continue }
  $ext = [System.IO.Path]::GetExtension($f)
  if ($ext -and ($allowedExt -notcontains $ext)) { continue }
  $filtered += $f
}

$findings = New-Object System.Collections.Generic.List[object]

foreach ($p in $patterns) {
  if (-not $filtered -or @($filtered).Count -eq 0) { break }
  # Git paths are data, not wildcard expressions. LiteralPath keeps hostile
  # untracked names in scope instead of silently skipping them.
  $patternMatches = Select-String -LiteralPath $filtered -Pattern $p.Regex -AllMatches -ErrorAction SilentlyContinue
  foreach ($m in $patternMatches) {
    $findings.Add([pscustomobject]@{
      File     = $m.Path
      Line     = $m.LineNumber
      Pattern  = $p.Name
    }) | Out-Null
  }
}

if ($findings.Count -gt 0) {
  Write-Information -MessageData "Secret scan: potential matches found: $($findings.Count)" -InformationAction Continue
  $findings | Sort-Object File,Line | ForEach-Object {
    Write-Information -MessageData ("- {0}:{1} ({2})" -f $_.File, $_.Line, $_.Pattern) -InformationAction Continue
  }
  if (-not $NoFail) { exit 1 }
} else {
  Write-Information -MessageData 'Secret scan: no matches found.' -InformationAction Continue
}
