#requires -version 5.1
<#
.SYNOPSIS
Provides shared hashing for Rust v3 oracle tooling.

.DESCRIPTION
Computes lowercase SHA-256 values for byte arrays without changing external
state. The fixture updater and Pester validator use the same implementation.
#>

function Get-RustV3OracleSha256 {
  [OutputType([string])]
  param([Parameter(Mandatory)] [byte[]]$Bytes)

  $sha256 = [System.Security.Cryptography.SHA256]::Create()
  try {
    return (($sha256.ComputeHash($Bytes) | ForEach-Object { $_.ToString('x2') }) -join '')
  } finally {
    $sha256.Dispose()
  }
}
