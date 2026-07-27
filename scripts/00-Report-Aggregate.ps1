#requires -version 5.1
<#
.SYNOPSIS
Aggregate v2 JSON result objects into one report.

.DESCRIPTION
Validates individual v2 result files before combining their findings and
summary data. Keeping aggregation schema-aware prevents malformed or unrelated
JSON from being presented as trusted security evidence.
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
  [Parameter(Mandatory)]
  [string[]]$InputPath,

  [ValidateSet('Console','Json','Csv','None')]
  [string]$OutputFormat = 'Console',

  [string]$OutputPath,

  [switch]$PassThru

,
  [ValidateSet('Audit','Remediate')][string]$Mode = 'Audit',
  [string]$ConfigPath,
  [switch]$Strict,
  [switch]$Quiet,
  [switch]$NoColor
)

. (Join-Path $PSScriptRoot '_lib/Bootstrap.ps1')
Import-Module (Join-Path $script:LibPath 'Output.psm1') -Force
Import-Module (Join-Path $script:LibPath 'Serialization.psm1') -Force
Import-Module (Join-Path $script:LibPath 'Validation.psm1')

Set-StrictMode -Version Latest
# v2-init (migrated to Initialize-V2Context)
$script:__V2Context = Initialize-V2Context -ScriptName '00-Report-Aggregate.ps1' -BoundParameters $PSBoundParameters `
  -Mode $Mode -ConfigPath $ConfigPath -OutputFormat $OutputFormat -OutputPath $OutputPath `
  -PassThru:$PassThru -Strict:$Strict -Quiet:$Quiet -NoColor:$NoColor
if ($script:__V2Context.Quiet) { $InformationPreference = 'SilentlyContinue'; $VerbosePreference = 'SilentlyContinue' }
$script:NoColor = [bool]$script:__V2Context.NoColor
$ErrorActionPreference = 'Stop'

function Get-CanonicalResultFilePath {
  param(
    [Parameter(Mandatory)]
    [string]$Path
  )

  $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
  $fullPath = [System.IO.Path]::GetFullPath($item.FullName)
  $rootPath = [System.IO.Path]::GetPathRoot($fullPath)
  $currentPath = (Get-Item -LiteralPath $rootPath -Force -ErrorAction Stop).FullName
  $segments = $fullPath.Substring($rootPath.Length).Split(
    [char[]]@(
      [System.IO.Path]::DirectorySeparatorChar,
      [System.IO.Path]::AltDirectorySeparatorChar
    ),
    [System.StringSplitOptions]::RemoveEmptyEntries
  )

  foreach ($segment in $segments) {
    $children = @(Get-ChildItem -LiteralPath $currentPath -Force -ErrorAction Stop)
    $match = @($children | Where-Object {
        [System.StringComparer]::Ordinal.Equals($_.Name, $segment)
      })
    if ($match.Count -ne 1) {
      $match = @($children | Where-Object {
          [System.StringComparer]::OrdinalIgnoreCase.Equals($_.Name, $segment)
        })
    }
    if ($match.Count -ne 1) {
      throw "Unable to resolve one canonical filesystem path for '$Path'."
    }
    $currentPath = $match[0].FullName
  }

  return $currentPath
}

$outputCanonicalPath = if ([string]::IsNullOrWhiteSpace($OutputPath)) {
  $null
} elseif (Test-Path -LiteralPath $OutputPath -PathType Leaf) {
  Get-CanonicalResultFilePath -Path $OutputPath
} else {
  $outputFullPath = [System.IO.Path]::GetFullPath($OutputPath)
  $outputParentPath = Get-CanonicalResultFilePath -Path (Split-Path -Path $outputFullPath -Parent)
  Join-Path -Path $outputParentPath -ChildPath (Split-Path -Path $outputFullPath -Leaf)
}
$seenFiles = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
$files = New-Object System.Collections.ArrayList
foreach ($p in $InputPath) {
  if (Test-Path -LiteralPath $p -PathType Leaf) {
    $filePath = Get-CanonicalResultFilePath -Path $p
    if (($null -eq $outputCanonicalPath -or -not [System.StringComparer]::Ordinal.Equals($filePath, $outputCanonicalPath)) -and $seenFiles.Add($filePath)) {
      [void]$files.Add($filePath)
    }
  } elseif (Test-Path -LiteralPath $p -PathType Container) {
    foreach ($f in Get-ChildItem -LiteralPath $p -Filter '*.json' -File) {
      $filePath = Get-CanonicalResultFilePath -Path $f.FullName
      if (($null -eq $outputCanonicalPath -or -not [System.StringComparer]::Ordinal.Equals($filePath, $outputCanonicalPath)) -and $seenFiles.Add($filePath)) {
        [void]$files.Add($filePath)
      }
    }
  }
}

if ($files.Count -eq 0) {
  $message = 'No JSON result files found in InputPath.'
  $finding = [pscustomobject]@{
    Code     = 'Aggregate-NoInputFiles'
    Severity = 'High'
    Message  = $message
  }
  $report = Get-V2ResultObject `
    -ScriptName '00-Report-Aggregate.ps1' `
    -Mode $Mode `
    -Result 'FAIL' `
    -Findings @($finding) `
    -Summary ([pscustomobject]@{ Files = 0; RejectedFiles = 0; OK = 0; WARN = 0; FAIL = 0; Error = $message }) `
    -Metadata @{ Items = @() }
  Write-ResultObject -ResultObject $report -OutputFormat $OutputFormat -OutputPath $OutputPath
  if ($PassThru) { $report }
  exit (Get-V2ExitCode -Result 'FAIL')
}

$items = New-Object System.Collections.ArrayList
$rejectionFindings = New-Object System.Collections.ArrayList
$rejectedFiles = 0
foreach ($file in $files) {
  try {
    $obj = Get-BoundedUtf8FileContent -Path $file -MaximumBytes 16777216 | ConvertFrom-Json -ErrorAction Stop
    # Validate that parsed JSON has required v2 result properties before including
    $props = if ($null -ne $obj) { @($obj.PSObject.Properties.Name) } else { @() }
    $shapeValid = $props -contains 'ScriptName' -and $props -contains 'Result' -and $props -contains 'Mode'
    $valuesValid = $shapeValid `
      -and -not [string]::IsNullOrWhiteSpace([string]$obj.ScriptName) `
      -and @('OK','WARN','FAIL') -contains [string]$obj.Result `
      -and @('Audit','Remediate') -contains [string]$obj.Mode
    if (-not $valuesValid) {
      $message = "Skipping '$file': invalid v2 result shape or values (ScriptName, Result, Mode)."
      Write-Warning $message
      $rejectedFiles++
      [void]$rejectionFindings.Add([pscustomobject]@{
          Code     = 'Aggregate-InvalidResult'
          Severity = 'Medium'
          Message  = $message
          File     = $file
        })
      continue
    }
    [void]$items.Add([pscustomobject]@{
        File   = $file
        Result = [string]$obj.Result
        Script = [string]$obj.ScriptName
        Mode   = [string]$obj.Mode
      })
  } catch {
    $message = "Skipping '$file': failed to parse JSON - $($_.Exception.Message)"
    Write-Warning $message
    $rejectedFiles++
    [void]$rejectionFindings.Add([pscustomobject]@{
        Code     = 'Aggregate-InvalidJson'
        Severity = 'Medium'
        Message  = $message
        File     = $file
      })
  }
}

$arr = @($items)
$ok = @($arr | Where-Object { $_.Result -eq 'OK' }).Count
$warn = @($arr | Where-Object { $_.Result -eq 'WARN' }).Count
$fail = @($arr | Where-Object { $_.Result -eq 'FAIL' }).Count

$token = if ($arr.Count -eq 0 -and $rejectedFiles -gt 0) { 'FAIL' } elseif ($fail -gt 0) { 'FAIL' } elseif ($warn -gt 0 -or $rejectedFiles -gt 0) { 'WARN' } else { 'OK' }
if ($Strict -and $token -eq 'WARN') { $token = 'FAIL' }
$summary = [pscustomobject]@{
  Files         = $arr.Count
  RejectedFiles = $rejectedFiles
  OK            = $ok
  WARN          = $warn
  FAIL          = $fail
}

$report = Get-V2ResultObject `
  -ScriptName '00-Report-Aggregate.ps1' `
  -Mode $Mode `
  -Result $token `
  -Findings @($rejectionFindings) `
  -Summary $summary `
  -Metadata @{ Items = $arr }

if ($OutputFormat -eq 'Console') {
  Write-Section -Title 'Aggregate Report'
  Write-KeyValue -Key 'Files' -Value $summary.Files
  Write-KeyValue -Key 'OK' -Value $summary.OK
  Write-KeyValue -Key 'WARN' -Value $summary.WARN
  Write-KeyValue -Key 'FAIL' -Value $summary.FAIL
}

Write-ResultObject -ResultObject $report -OutputFormat $OutputFormat -OutputPath $OutputPath

if ($PassThru) { $report }

exit (Get-V2ExitCode -Result $token)
