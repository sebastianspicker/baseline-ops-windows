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
  # S15 fix: expand environment variables before traversal check so that paths
  # like %TEMP%\..\..\..\Windows are correctly detected after expansion
  $expandedSource = [System.Environment]::ExpandEnvironmentVariables($SourcePath)
  $expandedBase   = [System.Environment]::ExpandEnvironmentVariables($EvidenceBaseDir)
  if ((Validation\Test-PathTraversal -Path $expandedSource) -or (Validation\Test-PathTraversal -Path $expandedBase)) {
    return $false, 'path-traversal-not-allowed'
  }
  if ((Validation\Test-PathTraversal -Path $SourcePath) -or (Validation\Test-PathTraversal -Path $EvidenceBaseDir)) {
    return $false, 'path-traversal-not-allowed'
  }
  try {
    if (-not (Test-Path -LiteralPath $SourcePath)) { return $false, 'missing' }
    $item = Get-Item -LiteralPath $SourcePath -ErrorAction Stop
    if ($item.PSIsContainer) { return $false, 'is-directory' }

    $sizeBytes = [int64]$item.Length
    if ($MaxFileSizeMB -gt 0 -and $sizeBytes -gt ([int64]$MaxFileSizeMB * 1MB)) {
      return $false, 'file-too-large'
    }
    if ($RunningTotalBytes -and $MaxTotalMB -gt 0) {
      $newTotal = $RunningTotalBytes.Value + $sizeBytes
      if ($newTotal -gt ([int64]$MaxTotalMB * 1MB)) { return $false, 'quota-exceeded' }
      $RunningTotalBytes.Value = $newTotal
    }

    $safeName = $expandedSource.Replace(':', '').TrimStart('\') -replace '[\\/:*?"<>|]', '_'
    $destPath = Join-Path $EvidenceBaseDir $safeName
    $destDir = Split-Path -Parent $destPath
    if (-not [string]::IsNullOrWhiteSpace($destDir) -and -not (Test-Path -LiteralPath $destDir)) {
      New-Item -ItemType Directory -Path $destDir -Force | Out-Null
    }
    Copy-Item -LiteralPath $SourcePath -Destination $destPath -Force -ErrorAction Stop
    return $true, $destPath
  } catch {
    return $false, $_.Exception.Message
  }
}

Export-ModuleMember -Function Expand-Env, Get-FileSha256, Copy-ToEvidence
