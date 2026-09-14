#requires -version 5.1
<#
.SYNOPSIS
  Provides private artifact collection phases.
.DESCRIPTION
  Preserves protected evidence paths, bounded observations, trigger decisions, and artifact proof ordering within this capability.
#>


function Collect-Processes {
  param([string]$outDir, $cat, [switch]$hashAll)

  $res = Get-ResultObject 'Processes'
  $csv = Join-Path $outDir 'processes.csv'

  try {
    [void](Ensure-Directory $outDir)

    $rxList = @()
    try {
      $rxList = @($cat.Process.__UserPathsRegex)
    }
    catch {
      Write-Verbose ("Process UserPathsRegex lookup failed: {0}" -f $_.Exception.Message)
    }
    $hashUserlandOnly = Safe-ToBool $cat.Process.HashUserlandOnly $true

    $procs = Get-CimInstance Win32_Process
    $rows = foreach ($p in $procs) {
      Get-ArtifactProcessRow -p $p -rxList $rxList -hashAll:$hashAll -hashUserlandOnly:$hashUserlandOnly
    }

    $rows | Export-Csv -NoTypeInformation -Encoding UTF8 -Path $csv
    $res.Counts.Count = @($rows).Count
  }
  catch [System.Text.RegularExpressions.RegexMatchTimeoutException] {
    throw
  }
  catch {
    Add-Error $res ("process: " + $_.Exception.Message)
    $res.Counts.Count = 0
  }

  return $res
}
function Get-ArtifactProcessRow {
  param($p, $rxList, [bool]$hashAll, [bool]$hashUserlandOnly)
  $path = $null
  try {
    $path = [string]$p.ExecutablePath
  }
  catch {
    Write-Verbose ("Process path lookup failed for PID {0}: {1}" -f $p.ProcessId, $_.Exception.Message)
  }

  $userlandMatch = $false
  if ($path) {
    $userlandMatch = Test-ArtifactRegexMatch -Value $path -RegexList $rxList
  }

  $doHash = $false
  if ($hashAll) {
    $doHash = $true
  }
  elseif (-not $hashUserlandOnly) {
    $doHash = $true
  }
  elseif ($userlandMatch) {
    $doHash = $true
  }

  $image = Get-ArtifactProcessImage -Path $path -DoHash:$doHash
  $sha = $image.Sha256
  $sig = $image.Signature

  [pscustomobject]@{
    ProcessId = $p.ProcessId
    Name = $p.Name
    CommandLine = $p.CommandLine
    Path = $path
    UserlandPath = $userlandMatch
    Sha256 = $sha
    Signed = [string]$sig.Signed
    Publisher = $sig.Publisher
    SigStatus = $sig.SignatureStatus
  }

}

function Get-ArtifactProcessImage {
  param([string]$Path, [bool]$DoHash)
  $sha = $null
  $sig = [pscustomobject]@{ Signed = $false
    Publisher = $null
    SignatureStatus = $null
  }
  if ($path) {
    if ($doHash) {
      $sha = Get-FileSha256 -Path $path
    }
    $sig = Get-FileSignatureInfo $path
  }

  return @{Sha256 = $sha
    Signature = $sig
  }
}

function Get-FileSignatureInfo([string]$File) {
  $o = [pscustomobject]@{
    Path = $File
    SignatureStatus = $null
    Signed = $false
    Publisher = $null
  }
  try {
    if (-not (Test-Path -LiteralPath $File)) {
      return $o
    }
    $sig = Get-AuthenticodeSignature -FilePath $File -ErrorAction Stop
    $o.SignatureStatus = [string]$sig.Status
    $o.Signed = ($sig.Status -eq 'Valid')
    if ($sig.SignerCertificate) {
      $o.Publisher = $sig.SignerCertificate.Subject
    }
  }
  catch {
    Write-Verbose ("Authenticode check failed for '{0}': {1}" -f $File, $_.Exception.Message)
  }
  return $o
}
function Test-ArtifactRegexMatch {
  param($Value, $RegexList)
  foreach ($regex in $RegexList) {
    if ($regex.IsMatch($Value)) {
      return $true
    }
  }
  return $false
}
