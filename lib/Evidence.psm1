<#
.SYNOPSIS
Shared evidence and hashing helpers for IOC/artifact scripts.

.DESCRIPTION
Get-FileSha256, Copy-ToEvidence (with optional size/total limits), Expand-Env.
Used by 11-IOC-Sweep-Defender, 12-Suspicious-Artifact-Grabber, 16-Sysmon-Config-Updater.
#>

Set-StrictMode -Version Latest
Microsoft.PowerShell.Core\Import-Module ([System.IO.Path]::Combine($PSScriptRoot, 'Validation.psm1'))

<#
.SYNOPSIS
  Expands environment variables in a path string.
.PARAMETER Path
  Path string containing environment variable references.
#>
function Expand-Env {
  [CmdletBinding()]
  param(
    [AllowNull()]
    [string]$Path
  )
  if ([string]::IsNullOrWhiteSpace($Path)) { return $Path }
  try {
    return [Environment]::ExpandEnvironmentVariables($Path)
  } catch {
    return $Path
  }
}

<#
.SYNOPSIS
  Computes the SHA-256 hash of a file.
.PARAMETER Path
  Path to the file to hash.
#>
function Get-FileSha256 {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]
    [string]$Path
  )
  if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $null }
  try {
    $hash = Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop
    return $hash.Hash
  } catch {
    return $null
  }
}

<#
.SYNOPSIS
  Tests source and destination paths for traversal after expansion.
#>
function Test-EvidencePathSafety {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$SourcePath,
    [Parameter(Mandatory)][string]$EvidenceBaseDir
  )

  $expandedSource = [Environment]::ExpandEnvironmentVariables($SourcePath)
  $expandedBase = [Environment]::ExpandEnvironmentVariables($EvidenceBaseDir)
  $expandedUnsafe = (Validation\Test-PathTraversal -Path $expandedSource) -or
    (Validation\Test-PathTraversal -Path $expandedBase)
  $originalUnsafe = (Validation\Test-PathTraversal -Path $SourcePath) -or
    (Validation\Test-PathTraversal -Path $EvidenceBaseDir)
  return -not ($expandedUnsafe -or $originalUnsafe)
}

<#
.SYNOPSIS
  Gets a copyable evidence file or its rejection reason.
#>
function Get-EvidenceFileItem {
  [CmdletBinding()]
  param([Parameter(Mandatory)][string]$SourcePath)

  if (-not (Test-Path -LiteralPath $SourcePath)) { return $null, 'missing' }
  $item = Get-Item -LiteralPath $SourcePath -ErrorAction Stop
  if ($item.PSIsContainer) { return $null, 'is-directory' }
  return $item, $null
}

<#
.SYNOPSIS
  Enforces evidence size limits and updates a permitted running total.
#>
function Test-EvidenceSizeLimits {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][int64]$SizeBytes,
    [int]$MaxFileSizeMB,
    [int]$MaxTotalMB,
    [ref]$RunningTotalBytes
  )

  if ($MaxFileSizeMB -gt 0 -and $SizeBytes -gt ([int64]$MaxFileSizeMB * 1MB)) { return 'file-too-large' }
  if (-not $RunningTotalBytes -or $MaxTotalMB -le 0) { return $null }
  $newTotal = $RunningTotalBytes.Value + $SizeBytes
  if ($newTotal -gt ([int64]$MaxTotalMB * 1MB)) { return 'quota-exceeded' }
  $RunningTotalBytes.Value = $newTotal
  return $null
}

<#
.SYNOPSIS
  Creates the safe evidence destination path.
#>
function New-EvidenceDestination {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$SourcePath,
    [Parameter(Mandatory)][string]$EvidenceBaseDir
  )

  $expandedSource = [Environment]::ExpandEnvironmentVariables($SourcePath)
  $safeName = $expandedSource.Replace(':', '').TrimStart('\') -replace '[\\/:*?"<>|]', '_'
  $destinationPath = Join-Path $EvidenceBaseDir $safeName
  $destinationDirectory = Split-Path -Parent $destinationPath
  if (-not [string]::IsNullOrWhiteSpace($destinationDirectory) -and -not (Test-Path -LiteralPath $destinationDirectory)) {
    New-Item -ItemType Directory -Path $destinationDirectory -Force | Out-Null
  }
  return $destinationPath
}

<#
.SYNOPSIS
  Copies a file to an evidence directory with optional size limits.
.PARAMETER SourcePath
  Path to the source file.
.PARAMETER EvidenceBaseDir
  Base directory where evidence files are stored.
.PARAMETER MaxFileSizeMB
  Maximum allowed file size in MB (0 = unlimited).
.PARAMETER MaxTotalMB
  Maximum total evidence size in MB (0 = unlimited).
.PARAMETER RunningTotalBytes
  Reference to a running byte total for quota tracking.
#>
function Copy-ToEvidence {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]
    [string]$SourcePath,
    [Parameter(Mandatory)]
    [string]$EvidenceBaseDir,
    [int]$MaxFileSizeMB = 0,
    [int]$MaxTotalMB = 0,
    [ref]$RunningTotalBytes
  )
  if (-not (Test-EvidencePathSafety -SourcePath $SourcePath -EvidenceBaseDir $EvidenceBaseDir)) {
    return $false, 'path-traversal-not-allowed'
  }
  try {
    $item, $itemError = Get-EvidenceFileItem -SourcePath $SourcePath
    if ($itemError) { return $false, $itemError }
    $sizeError = Test-EvidenceSizeLimits -SizeBytes ([int64]$item.Length) -MaxFileSizeMB $MaxFileSizeMB `
      -MaxTotalMB $MaxTotalMB -RunningTotalBytes $RunningTotalBytes
    if ($sizeError) { return $false, $sizeError }
    $destPath = New-EvidenceDestination -SourcePath $SourcePath -EvidenceBaseDir $EvidenceBaseDir
    Copy-Item -LiteralPath $SourcePath -Destination $destPath -Force -ErrorAction Stop
    return $true, $destPath
  } catch {
    return $false, $_.Exception.Message
  }
}

Export-ModuleMember -Function Expand-Env, Get-FileSha256, Copy-ToEvidence
