<#
.SYNOPSIS
  Converts jscpd reports into reviewed clone-baseline records.
.DESCRIPTION
  Enforces stable normalized content, occurrences, multiplicity, configuration, and rationale.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-TextSha256 {
  param([Parameter(Mandatory)][string]$Text)

  $sha = [System.Security.Cryptography.SHA256]::Create()
  try {
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Text)
    return ([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-', '').ToLowerInvariant()
  } finally {
    $sha.Dispose()
  }
}

function Get-DetectorRecord {
  param([ValidateSet('PowerShell', 'Rust')][string]$ReleaseLine, [string]$Version)

  [string[]]$languages = if ($ReleaseLine -eq 'PowerShell') { @('powershell') } else { @('rust', 'powershell') }
  return [ordered]@{
    Name = 'jscpd'
    Version = $Version
    Mode = 'mild'
    MinTokens = 50
    MinLines = 5
    ScanRoot = if ($ReleaseLine -eq 'PowerShell') { '.' } else { 'rust + tests/RustV3Oracle*.ps1' }
    Languages = $languages
  }
}

function ConvertTo-Occurrence {
  param([object]$File, [ValidateSet('PowerShell', 'Rust')][string]$ReleaseLine)

  $path = ([string]$File.Name).Replace([char]92, [char]47).TrimStart([char]47)
  if (
    $ReleaseLine -eq 'Rust' -and
    -not $path.StartsWith('rust/') -and
    -not $path.StartsWith('tests/RustV3Oracle')
  ) {
    $path = "rust/$path"
  }
  return [ordered]@{ Path = $path; StartLine = [int]$File.Start; EndLine = [int]$File.End }
}

function Get-EntryFingerprint {
  param([string]$ContentHash, [object[]]$Occurrences)

  $parts = @($Occurrences | ForEach-Object {
      '{0}:{1}:{2}' -f $_.Path, $_.StartLine, $_.EndLine
    })
  return Get-TextSha256 -Text ($ContentHash + '|' + ($parts -join '|'))
}

function Add-CloneOccurrences {
  param([hashtable]$Groups, [object]$Clone, [string]$ReleaseLine)

  $normalized = ([string]$Clone.Fragment -replace '\s+', ' ').Trim()
  $contentHash = Get-TextSha256 -Text $normalized
  if (-not $Groups.ContainsKey($contentHash)) {
    $Groups[$contentHash] = [System.Collections.Generic.List[object]]::new()
  }
  $Groups[$contentHash].Add((ConvertTo-Occurrence $Clone.FirstFile $ReleaseLine))
  $Groups[$contentHash].Add((ConvertTo-Occurrence $Clone.SecondFile $ReleaseLine))
}

function Get-UniqueOccurrences {
  param([object[]]$Occurrences)

  $seen = @{}
  $unique = foreach ($occurrence in $Occurrences) {
    $key = '{0}:{1}:{2}' -f $occurrence.Path, $occurrence.StartLine, $occurrence.EndLine
    if (-not $seen.ContainsKey($key)) { $seen[$key] = $true; $occurrence }
  }
  return @($unique | Sort-Object Path, StartLine, EndLine)
}

function ConvertFrom-JscpdReport {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]$Report,
    [ValidateSet('PowerShell', 'Rust')][string]$ReleaseLine,
    [Parameter(Mandatory)][string]$Version
  )

  if (-not $Report.Statistics -or [int]$Report.Statistics.Total.Sources -eq 0) {
    throw "jscpd $ReleaseLine scan matched zero files."
  }
  $detector = Get-DetectorRecord -ReleaseLine $ReleaseLine -Version $Version
  $groups = @{}
  foreach ($clone in @($Report.Duplicates)) {
    Add-CloneOccurrences -Groups $groups -Clone $clone -ReleaseLine $ReleaseLine
  }
  $entries = foreach ($contentHash in @($groups.Keys | Sort-Object)) {
    $occurrences = Get-UniqueOccurrences -Occurrences $groups[$contentHash]
    [ordered]@{
      SchemaVersion = 1
      Detector = $detector
      Language = $ReleaseLine
      NormalizedContentHash = $contentHash
      Fingerprint = Get-EntryFingerprint $contentHash $occurrences
      Rationale = ''
      Occurrences = $occurrences
      Multiplicity = $occurrences.Count
    }
  }
  return @($entries)
}

function Test-OccurrenceScope {
  param([object]$Occurrence, [ValidateSet('PowerShell', 'Rust')][string]$ReleaseLine)

  $path = [string]$Occurrence.Path
  if ($path.Contains('..') -or [System.IO.Path]::IsPathRooted($path)) { return $false }
  if ($ReleaseLine -eq 'Rust') {
    return $path.StartsWith('rust/') -or $path.StartsWith('tests/RustV3Oracle')
  }
  return @('scripts/', 'lib/', 'tools/', 'tests/') | Where-Object { $path.StartsWith($_) } | Select-Object -First 1
}

function Assert-BaselineIdentity {
  param([object]$Entry, [string]$ReleaseLine, [object]$Detector)

  if ([int]$Entry.SchemaVersion -ne 1) { throw 'Clone baseline entry has an unsupported schema version.' }
  if (-not $Entry.NormalizedContentHash -or -not $Entry.Fingerprint) { throw 'Clone baseline entry is malformed.' }
  if ([string]$Entry.Language -cne $ReleaseLine) { throw 'Clone baseline entry has the wrong language scope.' }
  if (($Entry.Detector | ConvertTo-Json -Compress) -cne ($Detector | ConvertTo-Json -Compress)) {
    throw 'Clone baseline detector configuration drifted.'
  }
}

function Assert-BaselineOccurrences {
  param([object]$Entry, [string]$ReleaseLine)

  if ([int]$Entry.Multiplicity -ne @($Entry.Occurrences).Count -or [int]$Entry.Multiplicity -lt 2) {
    throw 'Clone baseline multiplicity does not match its occurrences.'
  }
  foreach ($occurrence in @($Entry.Occurrences)) {
    if (-not (Test-OccurrenceScope $occurrence $ReleaseLine)) { throw 'Clone baseline entry is out of scope.' }
  }
  $expected = Get-EntryFingerprint $Entry.NormalizedContentHash @($Entry.Occurrences)
  if ($expected -cne [string]$Entry.Fingerprint) { throw 'Clone baseline fingerprint is malformed.' }
}

function Assert-BaselineEntry {
  param([object]$Entry, [ValidateSet('PowerShell', 'Rust')][string]$ReleaseLine, [object]$Detector)

  Assert-BaselineIdentity -Entry $Entry -ReleaseLine $ReleaseLine -Detector $Detector
  $rationale = ([string]$Entry.Rationale).Trim()
  if (-not $rationale -or $rationale.StartsWith('REVIEW REQUIRED')) { throw 'Clone baseline entry lacks a reviewed rationale.' }
  Assert-BaselineOccurrences -Entry $Entry -ReleaseLine $ReleaseLine
}

function Get-NewCloneFindings {
  param([hashtable]$Current, [hashtable]$Baseline, [object[]]$BaselineEntries, [string]$ReleaseLine)

  $findings = @()
  foreach ($fingerprint in $Current.Keys) {
    if ($Baseline.ContainsKey($fingerprint)) { continue }
    $sameContent = @($BaselineEntries | Where-Object {
        $_.NormalizedContentHash -eq $Current[$fingerprint].NormalizedContentHash
      }).Count
    $kind = if ($sameContent) { 'moved_clone' } else { 'new_clone' }
    $findings += [pscustomobject]@{ Kind = $kind; Path = $ReleaseLine; Fingerprint = $fingerprint }
  }
  return @($findings)
}

function Get-StaleCloneFindings {
  param([hashtable]$Current, [hashtable]$Baseline, [string]$ReleaseLine)

  $findings = @()
  foreach ($fingerprint in $Baseline.Keys) {
    if (-not $Current.ContainsKey($fingerprint)) {
      $findings += [pscustomobject]@{ Kind = 'stale_clone'; Path = $ReleaseLine; Fingerprint = $fingerprint }
    }
  }
  return @($findings)
}

function Read-CloneBaseline {
  param(
    [string]$Path,
    [ValidateSet('PowerShell', 'Rust')][string]$ReleaseLine,
    [string]$Version
  )

  if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "Clone baseline is missing: $Path" }
  $baseline = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
  if ([int]$baseline.SchemaVersion -ne 1) { throw 'Clone baseline has an unsupported schema version.' }
  $detector = Get-DetectorRecord -ReleaseLine $ReleaseLine -Version $Version
  foreach ($entry in @($baseline.Entries)) { Assert-BaselineEntry $entry $ReleaseLine $detector }
  return $baseline
}

function Compare-CloneBaseline {
  [CmdletBinding()]
  param(
    [object[]]$Current,
    [object]$Baseline,
    [ValidateSet('PowerShell', 'Rust')][string]$ReleaseLine
  )

  $currentByFingerprint = @{}; foreach ($entry in $Current) { $currentByFingerprint[$entry.Fingerprint] = $entry }
  $baselineByFingerprint = @{}; foreach ($entry in @($Baseline.Entries)) { $baselineByFingerprint[$entry.Fingerprint] = $entry }
  $findings = @(Get-NewCloneFindings $currentByFingerprint $baselineByFingerprint @($Baseline.Entries) $ReleaseLine)
  $findings += Get-StaleCloneFindings $currentByFingerprint $baselineByFingerprint $ReleaseLine
  return @($findings | Sort-Object Kind, Fingerprint)
}

function Update-CloneBaseline {
  param([string]$Path, [object[]]$Current, [object]$Existing)

  $known = @{}; if ($Existing) { foreach ($entry in @($Existing.Entries)) { $known[$entry.Fingerprint] = $entry.Rationale } }
  foreach ($entry in $Current) {
    $entry.Rationale = if ($known.ContainsKey($entry.Fingerprint)) { $known[$entry.Fingerprint] } else { 'REVIEW REQUIRED' }
  }
  $document = [ordered]@{ SchemaVersion = 1; Entries = @($Current | Sort-Object Fingerprint) }
  $document | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $Path -Encoding UTF8
}

Export-ModuleMember -Function ConvertFrom-JscpdReport, Read-CloneBaseline, Compare-CloneBaseline, Update-CloneBaseline
