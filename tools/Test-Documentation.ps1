#requires -version 5.1
<#
.SYNOPSIS
Validates maintained documentation and PowerShell help contracts.

.DESCRIPTION
Prevents broken repository links and undocumented maintained PowerShell entry points.
#>

[CmdletBinding()]
param(
  [string]$RootPath = '',
  [string[]]$Files = @()
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ([string]::IsNullOrWhiteSpace($RootPath)) {
  $RootPath = Split-Path -Parent $PSScriptRoot
}
$RootPath = (Resolve-Path -LiteralPath $RootPath).Path
$rootPrefix = $RootPath.TrimEnd([char[]]@(
    [System.IO.Path]::DirectorySeparatorChar,
    [System.IO.Path]::AltDirectorySeparatorChar
  )) + [System.IO.Path]::DirectorySeparatorChar

function Test-PathWithinRoot {
  <#
  .SYNOPSIS
  Checks whether a path remains inside the repository root.

  .DESCRIPTION
  Prevents documentation checks from resolving targets outside the supplied root.
  #>
  [CmdletBinding()]
  param([Parameter(Mandatory)][string]$Path)

  $fullPath = [System.IO.Path]::GetFullPath($Path)
  return $fullPath.Equals($RootPath, [System.StringComparison]::OrdinalIgnoreCase) -or
    $fullPath.StartsWith($rootPrefix, [System.StringComparison]::OrdinalIgnoreCase)
}

function Test-PathCaseExact {
  <#
  .SYNOPSIS
  Checks a repository path against its exact on-disk casing.

  .DESCRIPTION
  Detects links that work on case-insensitive hosts but fail in other environments.
  #>
  [CmdletBinding()]
  param([Parameter(Mandatory)][string]$Path)

  if (-not (Test-PathWithinRoot -Path $Path)) { return $false }

  $fullPath = [System.IO.Path]::GetFullPath($Path)
  if ($fullPath.Equals($RootPath, [System.StringComparison]::OrdinalIgnoreCase)) {
    return $true
  }

  $relativePath = $fullPath.Substring($rootPrefix.Length)
  $currentPath = $RootPath
  foreach ($segment in $relativePath.Split([char[]]@(
        [System.IO.Path]::DirectorySeparatorChar,
        [System.IO.Path]::AltDirectorySeparatorChar
      ), [System.StringSplitOptions]::RemoveEmptyEntries)) {
    $exactChild = Get-ChildItem -LiteralPath $currentPath -Force |
      Where-Object { $_.Name -ceq $segment } |
      Select-Object -First 1
    if (-not $exactChild) { return $false }
    $currentPath = $exactChild.FullName
  }

  return $true
}

function Test-PathTraversalHasReparsePoint {
  <#
  .SYNOPSIS
  Checks whether a repository path traverses a reparse point.

  .DESCRIPTION
  Prevents documentation links from silently escaping through symbolic links.
  #>
  [CmdletBinding()]
  param([Parameter(Mandatory)][string]$Path)

  if (-not (Test-PathWithinRoot -Path $Path)) { return $false }

  $fullPath = [System.IO.Path]::GetFullPath($Path)
  if ($fullPath.Equals($RootPath, [System.StringComparison]::OrdinalIgnoreCase)) {
    return $false
  }

  $relativePath = $fullPath.Substring($rootPrefix.Length)
  $currentPath = $RootPath
  foreach ($segment in $relativePath.Split([char[]]@(
        [System.IO.Path]::DirectorySeparatorChar,
        [System.IO.Path]::AltDirectorySeparatorChar
      ), [System.StringSplitOptions]::RemoveEmptyEntries)) {
    $currentPath = Join-Path $currentPath $segment
    $item = Get-Item -LiteralPath $currentPath -Force
    $isReparsePoint = ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0
    $isLink = $item.PSObject.Properties.Match('LinkType').Count -gt 0 -and
      -not [string]::IsNullOrWhiteSpace([string]$item.LinkType)
    if ($isReparsePoint -or $isLink) { return $true }
  }

  return $false
}

$isScopedRun = $Files.Count -gt 0
if ($Files.Count -eq 0) {
  $gitMetadataPath = Join-Path $RootPath '.git'
  if (Test-Path -LiteralPath $gitMetadataPath) {
    $git = Get-Command -Name git -ErrorAction SilentlyContinue
    if (-not $git) {
      throw 'git is required for Markdown discovery when .git metadata is present.'
    }

    # Discover the whole public working set, then inspect only supported source
    # formats. This keeps path filtering in one deterministic code path.
    $Files = @(& $git.Source -C $RootPath ls-files --cached --others --exclude-standard)
    if ($LASTEXITCODE -ne 0) {
      throw 'git ls-files failed while discovering Markdown files from a repository root.'
    }
  } else {
    $Files = @(Get-ChildItem -LiteralPath $RootPath -Recurse -File -Force |
        Where-Object {
          $_.Extension -in @('.md', '.ps1', '.psm1', '.psd1', '.sh', '.mjs', '.yaml', '.yml') -or
          $_.Name -eq 'Dockerfile'
        } |
        ForEach-Object { $_.FullName })
  }
}

$issues = New-Object System.Collections.Generic.List[string]
$checkedFiles = 0
$checkedPowerShellFiles = 0
$checkedCommentSourceFiles = 0
$localReferences = 0
$imageReferences = 0
$imagePattern = [regex]'!\[(?<label>[^\]]*)\]\((?<destination><[^>]+>|[^\s\)]+)(?:\s+(?:"[^"]*"|''[^'']*''|\([^\)]*\)))?\)'
$linkPattern = [regex]'(?<image>!)?\[(?<label>[^\]]*)\]\((?<destination><[^>]+>|[^\s\)]+)(?:\s+(?:"[^"]*"|''[^'']*''|\([^\)]*\)))?\)'

foreach ($file in @($Files | Sort-Object -Unique)) {
  if ([string]::IsNullOrWhiteSpace($file)) { continue }
  $candidatePath = if ([System.IO.Path]::IsPathRooted($file)) {
    [System.IO.Path]::GetFullPath($file)
  } else {
    [System.IO.Path]::GetFullPath((Join-Path $RootPath $file))
  }

  if (-not (Test-PathWithinRoot -Path $candidatePath)) {
    [void]$issues.Add("$file`: documentation file is outside the repository root")
    continue
  }
  if (-not (Test-Path -LiteralPath $candidatePath -PathType Leaf)) {
    continue
  }

  $relativePath = $candidatePath.Substring($rootPrefix.Length).Replace([char]92, [char]47)
  $extension = [System.IO.Path]::GetExtension($candidatePath).ToLowerInvariant()
  $fileName = [System.IO.Path]::GetFileName($candidatePath)
  $isMaintainedPowerShell = $extension -in @('.ps1', '.psm1') -and
    $relativePath -match '^(lib|scripts|tools|tests)/'
  $shouldCheckPowerShell = $extension -in @('.ps1', '.psm1') -and ($isScopedRun -or $isMaintainedPowerShell)
  $shouldCheckCommentSource = $extension -in @('.psd1', '.sh', '.mjs', '.yaml', '.yml') -or
    $fileName -eq 'Dockerfile'
  if ($extension -notin @('.md', '.ps1', '.psm1') -and -not $shouldCheckCommentSource) {
    continue
  }

  if ($shouldCheckPowerShell) {
    $checkedPowerShellFiles++
    $source = Get-Content -LiteralPath $candidatePath -Raw -Encoding UTF8
    $leadingHelpPattern = '(?s)\A(?:\uFEFF)?(?:[ \t]*#requires[^\r\n]*(?:\r?\n|$))*[ \t\r\n]*<#[ \t\r\n]*\.SYNOPSIS(?:\s).*?\.DESCRIPTION(?:\s).*?#>'
    if ($source -notmatch $leadingHelpPattern) {
      [void]$issues.Add("$relativePath`: missing leading comment-based help with .SYNOPSIS and .DESCRIPTION")
    }
    continue
  }

  if ($shouldCheckCommentSource) {
    $checkedCommentSourceFiles++
    $source = Get-Content -LiteralPath $candidatePath -Raw -Encoding UTF8
    $hasPurposeComment = switch ($extension) {
      '.sh' {
        $source -match '(?s)\A(?:\uFEFF)?#![^\r\n]*(?:\r?\n)[ \t]*#(?!\s*shellcheck\b)[^\r\n]+'
        break
      }
      '.mjs' {
        $source -match '(?s)\A(?:\uFEFF)?[ \t\r\n]*(?://|/\*)'
        break
      }
      { $_ -in @('.yaml', '.yml') } {
        $source -match '(?s)\A(?:\uFEFF)?(?:---[ \t]*(?:\r?\n))?[ \t]*#'
        break
      }
      '.psd1' {
        $source -match '(?s)\A(?:\uFEFF)?[ \t]*#'
        break
      }
      default {
        $head = (@(Get-Content -LiteralPath $candidatePath -TotalCount 20 -Encoding UTF8) -join "`n")
        $head -match '(?m)^#(?!\s*(?:syntax=|checkov:))\s+\S'
      }
    }
    if (-not $hasPurposeComment) {
      [void]$issues.Add("$relativePath`: missing a leading purpose comment")
    }
    continue
  }

  if ($extension -ne '.md') { continue }

  $checkedFiles++
  $relativeMarkdownPath = $relativePath
  $insideFence = $false
  $lineNumber = 0
  foreach ($line in Get-Content -LiteralPath $candidatePath -Encoding UTF8) {
    $lineNumber++
    if ($line -match '^\s*(```|~~~)') {
      $insideFence = -not $insideFence
      continue
    }
    if ($insideFence) { continue }

    $scanLine = $line -replace '`+[^`]*`+', ''
    foreach ($imageMatch in $imagePattern.Matches($scanLine)) {
      $imageReferences++
      if ([string]::IsNullOrWhiteSpace($imageMatch.Groups['label'].Value)) {
        [void]$issues.Add("$relativeMarkdownPath`:$lineNumber`: image alt text is empty")
      }
    }
    foreach ($match in $linkPattern.Matches($scanLine)) {
      $destination = $match.Groups['destination'].Value.Trim('<', '>')
      if (
        [string]::IsNullOrWhiteSpace($destination) -or
        $destination.StartsWith('#') -or
        $destination.StartsWith('//') -or
        $destination -match '^[A-Za-z][A-Za-z0-9+.-]*:'
      ) {
        continue
      }

      $destination = ($destination -split '[?#]', 2)[0]
      if ([string]::IsNullOrWhiteSpace($destination)) { continue }
      try {
        $destination = [System.Uri]::UnescapeDataString($destination)
      } catch {
        [void]$issues.Add("$relativeMarkdownPath`:$lineNumber`: invalid escaped link '$destination'")
        continue
      }

      $localReferences++
      $targetPath = if ($destination.StartsWith('/')) {
        Join-Path $RootPath $destination.TrimStart('/')
      } else {
        Join-Path (Split-Path -Parent $candidatePath) $destination
      }
      $targetPath = [System.IO.Path]::GetFullPath($targetPath)

      if (-not (Test-PathWithinRoot -Path $targetPath)) {
        [void]$issues.Add("$relativeMarkdownPath`:$lineNumber`: link escapes the repository root: $destination")
      } elseif (-not (Test-Path -LiteralPath $targetPath)) {
        [void]$issues.Add("$relativeMarkdownPath`:$lineNumber`: local target does not exist: $destination")
      } elseif (Test-PathTraversalHasReparsePoint -Path $targetPath) {
        [void]$issues.Add("$relativeMarkdownPath`:$lineNumber`: local target traverses a symlink or reparse point: $destination")
      } elseif (-not (Test-PathCaseExact -Path $targetPath)) {
        [void]$issues.Add("$relativeMarkdownPath`:$lineNumber`: local target uses incorrect path casing: $destination")
      }
    }
  }
}

if ($issues.Count -gt 0) {
  Write-Information -MessageData ("Documentation checks: FAILED ({0} issue(s))" -f $issues.Count) -InformationAction Continue
  $issues | Sort-Object -Unique | ForEach-Object {
    Write-Information -MessageData "- $_" -InformationAction Continue
  }
  exit 1
}

Write-Information `
  -MessageData ("Documentation checks: PASS ({0} Markdown files, {1} PowerShell files, {2} commented source files, {3} local references, {4} images)" -f $checkedFiles, $checkedPowerShellFiles, $checkedCommentSourceFiles, $localReferences, $imageReferences) `
  -InformationAction Continue
exit 0
