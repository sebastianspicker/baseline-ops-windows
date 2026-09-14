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

function Get-DocumentationRelativePath {
  <#
  .SYNOPSIS
  Gets a validated repository-relative path.
  .DESCRIPTION
  Returns null for paths outside the documentation root and an empty value for
  the root itself so link checks share one containment calculation.
  #>
  [CmdletBinding()]
  param([Parameter(Mandatory)][string]$Path)

  if (-not (Test-PathWithinRoot -Path $Path)) { return $null }
  $fullPath = [System.IO.Path]::GetFullPath($Path)
  if ($fullPath.Equals($RootPath, [System.StringComparison]::OrdinalIgnoreCase)) { return '' }
  return $fullPath.Substring($rootPrefix.Length)
}

function Get-DocumentationPathSegments {
  <#
  .SYNOPSIS
  Splits a validated relative documentation path.
  .DESCRIPTION
  Keeps separator handling identical for casing and reparse-point traversal.
  #>
  param([string]$RelativePath)
  return $RelativePath.Split([char[]]@(
      [System.IO.Path]::DirectorySeparatorChar,
      [System.IO.Path]::AltDirectorySeparatorChar
    ), [System.StringSplitOptions]::RemoveEmptyEntries)
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

  $relativePath = Get-DocumentationRelativePath -Path $Path
  if ($null -eq $relativePath) { return $false }
  if ($relativePath -eq '') { return $true }
  $currentPath = $RootPath
  foreach ($segment in (Get-DocumentationPathSegments -RelativePath $relativePath)) {
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

  $relativePath = Get-DocumentationRelativePath -Path $Path
  if ([string]::IsNullOrEmpty($relativePath)) { return $false }
  $currentPath = $RootPath
  foreach ($segment in (Get-DocumentationPathSegments -RelativePath $relativePath)) {
    $currentPath = Join-Path $currentPath $segment
    $item = Get-Item -LiteralPath $currentPath -Force
    $isReparsePoint = ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0
    $isLink = $item.PSObject.Properties.Match('LinkType').Count -gt 0 -and
      -not [string]::IsNullOrWhiteSpace([string]$item.LinkType)
    if ($isReparsePoint -or $isLink) { return $true }
  }

  return $false
}

function Get-DocumentationCheckFiles {
  <#
  .SYNOPSIS
  Gets the selected documentation contract files.
  .DESCRIPTION
  Uses Git when present and otherwise discovers supported source files locally.
  #>
  param([string[]]$RequestedFiles)

  if ($RequestedFiles.Count -gt 0) { return $RequestedFiles }
  $gitMetadataPath = Join-Path $RootPath '.git'
  if (Test-Path -LiteralPath $gitMetadataPath) {
    $git = Get-Command -Name git -ErrorAction SilentlyContinue
    if (-not $git) {
      throw 'git is required for Markdown discovery when .git metadata is present.'
    }

    # Discover the whole public working set, then inspect only supported source
    # formats. This keeps path filtering in one deterministic code path.
    $files = @(& $git.Source -C $RootPath ls-files --cached --others --exclude-standard)
    if ($LASTEXITCODE -ne 0) {
      throw 'git ls-files failed while discovering Markdown files from a repository root.'
    }
    return $files
  } else {
    return @(Get-ChildItem -LiteralPath $RootPath -Recurse -File -Force |
        Where-Object {
          $_.Extension -in @('.md', '.ps1', '.psm1', '.psd1', '.sh', '.mjs', '.yaml', '.yml') -or
          $_.Name -eq 'Dockerfile'
        } |
        ForEach-Object { $_.FullName })
  }
}

function New-DocumentationCheckState {
  <#
  .SYNOPSIS
  Creates mutable documentation check counters.
  .DESCRIPTION
  Keeps issue collection and compatible summary counters together.
  #>
  [CmdletBinding()]
  param()

  [pscustomobject]@{
    Issues = New-Object System.Collections.Generic.List[string]
    CheckedFiles = 0; CheckedPowerShellFiles = 0; CheckedCommentSourceFiles = 0
    LocalReferences = 0; ImageReferences = 0
  }
}

function Get-DocumentationCandidatePath {
  <#
  .SYNOPSIS
  Resolves one selected file below the repository root.
  .DESCRIPTION
  Returns null and records an issue when a selected path escapes the root.
  #>
  [CmdletBinding()]
  param([Parameter(Mandatory)][string]$File, [Parameter(Mandatory)]$State)

  $candidatePath = if ([System.IO.Path]::IsPathRooted($File)) {
    [System.IO.Path]::GetFullPath($File)
  } else {
    [System.IO.Path]::GetFullPath((Join-Path $RootPath $File))
  }
  if (Test-PathWithinRoot -Path $candidatePath) { return $candidatePath }
  [void]$State.Issues.Add("$File`: documentation file is outside the repository root")
  return $null
}

function Test-DocumentationPowerShellHelp {
  <#
  .SYNOPSIS
  Validates leading comment-based help for maintained PowerShell files.
  .DESCRIPTION
  Adds the existing compatible issue when the help contract is missing.
  #>
  [CmdletBinding()]
  param([string]$CandidatePath, [string]$RelativePath, [Parameter(Mandatory)]$State)

  $State.CheckedPowerShellFiles++
  $source = Get-Content -LiteralPath $CandidatePath -Raw -Encoding UTF8
  $leadingHelpPattern = '(?s)\A(?:\uFEFF)?(?:[ \t]*#requires[^\r\n]*(?:\r?\n|$))*[ \t\r\n]*<#[ \t\r\n]*\.SYNOPSIS(?:\s).*?\.DESCRIPTION(?:\s).*?#>'
  if ($source -notmatch $leadingHelpPattern) {
    [void]$State.Issues.Add("$RelativePath`: missing leading comment-based help with .SYNOPSIS and .DESCRIPTION")
  }
}

function Test-DocumentationPurposeComment {
  <#
  .SYNOPSIS
  Validates a leading purpose comment for maintained non-PowerShell sources.
  .DESCRIPTION
  Applies the format-specific purpose-comment contract.
  #>
  [CmdletBinding()]
  param([string]$CandidatePath, [string]$RelativePath, [string]$Extension, [Parameter(Mandatory)]$State)

  $State.CheckedCommentSourceFiles++
  $source = Get-Content -LiteralPath $CandidatePath -Raw -Encoding UTF8
  $hasPurposeComment = switch ($Extension) {
    '.sh' { $source -match '(?s)\A(?:\uFEFF)?#![^\r\n]*(?:\r?\n)[ \t]*#(?!\s*shellcheck\b)[^\r\n]+'; break }
    '.mjs' { $source -match '(?s)\A(?:\uFEFF)?[ \t\r\n]*(?://|/\*)'; break }
    { $_ -in @('.yaml', '.yml') } { $source -match '(?s)\A(?:\uFEFF)?(?:---[ \t]*(?:\r?\n))?[ \t]*#'; break }
    '.psd1' { $source -match '(?s)\A(?:\uFEFF)?[ \t]*#'; break }
    default {
      $head = (@(Get-Content -LiteralPath $CandidatePath -TotalCount 20 -Encoding UTF8) -join "`n")
      $head -match '(?m)^#(?!\s*(?:syntax=|checkov:))\s+\S'
    }
  }
  if (-not $hasPurposeComment) { [void]$State.Issues.Add("$RelativePath`: missing a leading purpose comment") }
}

function Test-DocumentationLinkTarget {
  <#
  .SYNOPSIS
  Validates one resolved local documentation target.
  .DESCRIPTION
  Retains containment, existence, reparse-point, and case checks.
  #>
  [CmdletBinding()]
  param([string]$TargetPath, [string]$Destination, [string]$RelativePath, [int]$LineNumber, [Parameter(Mandatory)]$State)

  if (-not (Test-PathWithinRoot -Path $TargetPath)) {
    [void]$State.Issues.Add("$RelativePath`:$LineNumber`: link escapes the repository root: $Destination"); return
  }
  if (-not (Test-Path -LiteralPath $TargetPath)) {
    [void]$State.Issues.Add("$RelativePath`:$LineNumber`: local target does not exist: $Destination"); return
  }
  if (Test-PathTraversalHasReparsePoint -Path $TargetPath) {
    [void]$State.Issues.Add("$RelativePath`:$LineNumber`: local target traverses a symlink or reparse point: $Destination"); return
  }
  if (-not (Test-PathCaseExact -Path $TargetPath)) {
    [void]$State.Issues.Add("$RelativePath`:$LineNumber`: local target uses incorrect path casing: $Destination")
  }
}

function Test-DocumentationExternalDestination {
  <#
  .SYNOPSIS
  Checks whether a Markdown destination does not require a local lookup.
  .DESCRIPTION
  Matches empty, fragment, protocol-relative, and URI-scheme destinations.
  #>
  [CmdletBinding()]
  param([string]$Destination)

  if ([string]::IsNullOrWhiteSpace($Destination)) { return $true }
  if ($Destination.StartsWith('#')) { return $true }
  if ($Destination.StartsWith('//')) { return $true }
  return $Destination -match '^[A-Za-z][A-Za-z0-9+.-]*:'
}

function Test-DocumentationLocalLink {
  <#
  .SYNOPSIS
  Resolves and validates one Markdown link destination.
  .DESCRIPTION
  Skips external and fragment links before checking supported local targets.
  #>
  [CmdletBinding()]
  param([string]$Destination, [string]$CandidatePath, [string]$RelativePath, [int]$LineNumber, [Parameter(Mandatory)]$State)

  if (Test-DocumentationExternalDestination -Destination $Destination) { return }
  $Destination = ($Destination -split '[?#]', 2)[0]
  if ([string]::IsNullOrWhiteSpace($Destination)) { return }
  try { $Destination = [System.Uri]::UnescapeDataString($Destination) } catch {
    [void]$State.Issues.Add("$RelativePath`:$LineNumber`: invalid escaped link '$Destination'"); return
  }
  $State.LocalReferences++
  $targetPath = if ($Destination.StartsWith('/')) {
    Join-Path $RootPath $Destination.TrimStart('/')
  } else { Join-Path (Split-Path -Parent $CandidatePath) $Destination }
  Test-DocumentationLinkTarget -TargetPath ([System.IO.Path]::GetFullPath($targetPath)) -Destination $Destination -RelativePath $RelativePath -LineNumber $LineNumber -State $State
}

function Get-DocumentationSourceDescriptor {
  <#
  .SYNOPSIS
  Gets source metadata for an existing selected file.
  .DESCRIPTION
  Converts one candidate path into the fields needed by source checks.
  #>
  [CmdletBinding()]
  param([string]$CandidatePath)

  if (-not (Test-Path -LiteralPath $CandidatePath -PathType Leaf)) { return $null }
  return [pscustomobject]@{
    CandidatePath = $CandidatePath
    RelativePath = (Get-DocumentationRelativePath -Path $CandidatePath).Replace([char]92, [char]47)
    Extension = [System.IO.Path]::GetExtension($CandidatePath).ToLowerInvariant()
    FileName = [System.IO.Path]::GetFileName($CandidatePath)
  }
}

function Test-DocumentationCommentSource {
  <#
  .SYNOPSIS
  Checks whether a source format needs a leading purpose comment.
  .DESCRIPTION
  Identifies maintained script, manifest, and container source formats.
  #>
  [CmdletBinding()]
  param([string]$Extension, [string]$FileName)

  if ($Extension -in @('.psd1', '.sh', '.mjs', '.yaml', '.yml')) { return $true }
  return $FileName -eq 'Dockerfile'
}

function Test-DocumentationSource {
  <#
  .SYNOPSIS
  Dispatches one selected source file to its documentation contract check.
  .DESCRIPTION
  Preserves scoped PowerShell, maintained PowerShell, and Markdown behavior.
  #>
  [CmdletBinding()]
  param([Parameter(Mandatory)]$Source, [bool]$IsScopedRun, [Parameter(Mandatory)]$State)

  $isMaintainedPowerShell = $Source.Extension -in @('.ps1', '.psm1') -and $Source.RelativePath -match '^(lib|scripts|tools|tests)/'
  if ($Source.Extension -in @('.ps1', '.psm1') -and ($IsScopedRun -or $isMaintainedPowerShell)) {
    Test-DocumentationPowerShellHelp -CandidatePath $Source.CandidatePath -RelativePath $Source.RelativePath -State $State; return
  }
  if (Test-DocumentationCommentSource -Extension $Source.Extension -FileName $Source.FileName) {
    Test-DocumentationPurposeComment -CandidatePath $Source.CandidatePath -RelativePath $Source.RelativePath -Extension $Source.Extension -State $State; return
  }
  if ($Source.Extension -eq '.md') { Test-DocumentationMarkdownFile -CandidatePath $Source.CandidatePath -RelativePath $Source.RelativePath -State $State }
}

function Test-DocumentationMarkdownFile {
  <#
  .SYNOPSIS
  Checks Markdown image and local-link contracts.
  .DESCRIPTION
  Ignores fenced and inline-code links while preserving summary counters.
  #>
  [CmdletBinding()]
  param([string]$CandidatePath, [string]$RelativePath, [Parameter(Mandatory)]$State)

  $State.CheckedFiles++
  $imagePattern = [regex]'!\[(?<label>[^\]]*)\]\((?<destination><[^>]+>|[^\s\)]+)(?:\s+(?:"[^"]*"|''[^'']*''|\([^\)]*\)))?\)'
  $linkPattern = [regex]'(?<image>!)?\[(?<label>[^\]]*)\]\((?<destination><[^>]+>|[^\s\)]+)(?:\s+(?:"[^"]*"|''[^'']*''|\([^\)]*\)))?\)'
  $insideFence = $false; $lineNumber = 0
  foreach ($line in Get-Content -LiteralPath $CandidatePath -Encoding UTF8) {
    $lineNumber++
    if ($line -match '^\s*(```|~~~)') { $insideFence = -not $insideFence; continue }
    if ($insideFence) { continue }
    $scanLine = $line -replace '`+[^`]*`+', ''
    foreach ($imageMatch in $imagePattern.Matches($scanLine)) {
      $State.ImageReferences++
      if ([string]::IsNullOrWhiteSpace($imageMatch.Groups['label'].Value)) {
        [void]$State.Issues.Add("$RelativePath`:$lineNumber`: image alt text is empty")
      }
    }
    foreach ($match in $linkPattern.Matches($scanLine)) {
      Test-DocumentationLocalLink -Destination $match.Groups['destination'].Value.Trim('<', '>') -CandidatePath $CandidatePath -RelativePath $RelativePath -LineNumber $lineNumber -State $State
    }
  }
}

function Invoke-DocumentationCheck {
  <#
  .SYNOPSIS
  Runs the documentation and maintained-source contract check.
  .DESCRIPTION
  Discovers the selected source set, validates documentation links, and writes
  the compatible summary before returning a process exit code.
  #>
  [CmdletBinding()]
  param([string[]]$RequestedFiles)

  $isScopedRun = $RequestedFiles.Count -gt 0
  $state = New-DocumentationCheckState
  foreach ($file in @(Get-DocumentationCheckFiles -RequestedFiles $RequestedFiles | Sort-Object -Unique)) {
    if ([string]::IsNullOrWhiteSpace($file)) { continue }
    $candidatePath = Get-DocumentationCandidatePath -File $file -State $state
    if ($null -eq $candidatePath) { continue }
    $source = Get-DocumentationSourceDescriptor -CandidatePath $candidatePath
    if ($null -ne $source) { Test-DocumentationSource -Source $source -IsScopedRun $isScopedRun -State $state }
  }
  if ($state.Issues.Count -gt 0) {
    Write-Information -MessageData ("Documentation checks: FAILED ({0} issue(s))" -f $state.Issues.Count) -InformationAction Continue
    $state.Issues | Sort-Object -Unique | ForEach-Object { Write-Information -MessageData "- $_" -InformationAction Continue }
    return 1
  }
  Write-Information -MessageData ("Documentation checks: PASS ({0} Markdown files, {1} PowerShell files, {2} commented source files, {3} local references, {4} images)" -f $state.CheckedFiles, $state.CheckedPowerShellFiles, $state.CheckedCommentSourceFiles, $state.LocalReferences, $state.ImageReferences) -InformationAction Continue
  return 0
}

exit (Invoke-DocumentationCheck -RequestedFiles $Files)
