#requires -version 5.1
<#
.SYNOPSIS
Private runtime helpers for 00-Report-Aggregate.ps1.

.DESCRIPTION
Contains result-file collection and aggregation logic loaded after the public
entrypoint has loaded its bootstrap and v2 service modules.
#>

function New-ReportAggregateDirectoryNameCache {
  [CmdletBinding()]
  param()

  return ,([System.Collections.Generic.Dictionary[string, object]]::new([System.StringComparer]::Ordinal))
}

function Get-ReportAggregateDirectoryChildren {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$ParentPath,
    [Parameter(Mandatory)][AllowEmptyCollection()][System.Collections.Generic.Dictionary[string, object]]$DirectoryNameCache
  )

  if (-not $DirectoryNameCache.ContainsKey($ParentPath)) {
    $DirectoryNameCache[$ParentPath] = @(Get-ChildItem -LiteralPath $ParentPath -Force -ErrorAction Stop)
  }
  return @($DirectoryNameCache[$ParentPath])
}

function Get-CanonicalResultFilePath {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Path,
    [AllowEmptyCollection()][System.Collections.Generic.Dictionary[string, object]]$DirectoryNameCache
  )

  if ($null -eq $DirectoryNameCache) { $DirectoryNameCache = New-ReportAggregateDirectoryNameCache }
  $fullPath = [System.IO.Path]::GetFullPath($Path)
  $rootPath = [System.IO.Path]::GetPathRoot($fullPath)
  $currentPath = (Get-Item -LiteralPath $rootPath -Force -ErrorAction Stop).FullName
  $segments = $fullPath.Substring($rootPath.Length).Split([char[]]@([System.IO.Path]::DirectorySeparatorChar, [System.IO.Path]::AltDirectorySeparatorChar), [System.StringSplitOptions]::RemoveEmptyEntries)
  foreach ($segment in $segments) {
    $children = @(Get-ReportAggregateDirectoryChildren -ParentPath $currentPath -DirectoryNameCache $DirectoryNameCache)
    $match = @($children | Where-Object { [System.StringComparer]::Ordinal.Equals($_.Name, $segment) })
    if ($match.Count -ne 1) { $match = @($children | Where-Object { [System.StringComparer]::OrdinalIgnoreCase.Equals($_.Name, $segment) }) }
    if ($match.Count -ne 1) { throw "Unable to resolve one canonical filesystem path for '$Path'." }
    $currentPath = $match[0].FullName
  }
  return $currentPath
}

function Get-ReportAggregateOutputPath {
  [CmdletBinding()]
  param(
    [string]$OutputPath,
    [AllowEmptyCollection()][System.Collections.Generic.Dictionary[string, object]]$DirectoryNameCache
  )

  if ([string]::IsNullOrWhiteSpace($OutputPath)) { return $null }
  if ($null -eq $DirectoryNameCache) { $DirectoryNameCache = New-ReportAggregateDirectoryNameCache }
  if (Test-Path -LiteralPath $OutputPath -PathType Leaf) { return Get-CanonicalResultFilePath -Path $OutputPath -DirectoryNameCache $DirectoryNameCache }
  $outputFullPath = [System.IO.Path]::GetFullPath($OutputPath)
  $outputParent = Get-CanonicalResultFilePath -Path (Split-Path -Path $outputFullPath -Parent) -DirectoryNameCache $DirectoryNameCache
  return Join-Path -Path $outputParent -ChildPath (Split-Path -Path $outputFullPath -Leaf)
}

function Add-ReportAggregateFile {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Path,
    [string]$OutputCanonicalPath,
    [Parameter(Mandatory)][AllowEmptyCollection()][System.Collections.Generic.HashSet[string]]$SeenFiles,
    [Parameter(Mandatory)][AllowEmptyCollection()][System.Collections.ArrayList]$Files,
    [Parameter(Mandatory)][AllowEmptyCollection()][System.Collections.Generic.Dictionary[string, object]]$DirectoryNameCache
  )

  $filePath = Get-CanonicalResultFilePath -Path $Path -DirectoryNameCache $DirectoryNameCache
  $isOutput = $null -ne $OutputCanonicalPath -and [System.StringComparer]::Ordinal.Equals($filePath, $OutputCanonicalPath)
  if (-not $isOutput -and $SeenFiles.Add($filePath)) { [void]$Files.Add($filePath) }
}

function Get-ReportAggregateInputFiles {
  [CmdletBinding()]
  [OutputType([object[]])]
  param(
    [Parameter(Mandatory)][string[]]$InputPath,
    [string]$OutputCanonicalPath,
    [AllowEmptyCollection()][System.Collections.Generic.Dictionary[string, object]]$DirectoryNameCache
  )

  if ($null -eq $DirectoryNameCache) { $DirectoryNameCache = New-ReportAggregateDirectoryNameCache }
  $seenFiles = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
  $files = New-Object System.Collections.ArrayList
  foreach ($path in $InputPath) {
    if (Test-Path -LiteralPath $path -PathType Leaf) { Add-ReportAggregateFile -Path $path -OutputCanonicalPath $OutputCanonicalPath -SeenFiles $seenFiles -Files $files -DirectoryNameCache $DirectoryNameCache; continue }
    if (Test-Path -LiteralPath $path -PathType Container) {
      foreach ($file in Get-ChildItem -LiteralPath $path -Filter '*.json' -File) { Add-ReportAggregateFile -Path $file.FullName -OutputCanonicalPath $OutputCanonicalPath -SeenFiles $seenFiles -Files $files -DirectoryNameCache $DirectoryNameCache }
    }
  }
  return @($files)
}

function Test-ReportAggregateResult {
  [CmdletBinding()]
  [OutputType([bool])]
  param([AllowNull()]$Result)

  $properties = if ($null -ne $Result) { @($Result.PSObject.Properties.Name) } else { @() }
  $shapeValid = $properties -contains 'ScriptName' -and $properties -contains 'Result' -and $properties -contains 'Mode'
  return $shapeValid -and -not [string]::IsNullOrWhiteSpace([string]$Result.ScriptName) -and @('OK', 'WARN', 'FAIL') -contains [string]$Result.Result -and @('Audit', 'Remediate') -contains [string]$Result.Mode
}

function Read-ReportAggregateItems {
  [CmdletBinding()]
  [OutputType([object])]
  param([Parameter(Mandatory)][object[]]$Files)

  $items = New-Object System.Collections.ArrayList
  $findings = New-Object System.Collections.ArrayList
  foreach ($file in $Files) {
    try {
      $result = Get-BoundedUtf8FileContent -Path $file -MaximumBytes 16777216 | ConvertFrom-Json -ErrorAction Stop
      if (-not (Test-ReportAggregateResult -Result $result)) { throw [System.FormatException]::new('invalid v2 result shape or values (ScriptName, Result, Mode).') }
      [void]$items.Add([pscustomobject]@{ File = $file; Result = [string]$result.Result; Script = [string]$result.ScriptName; Mode = [string]$result.Mode })
    } catch {
      $isShapeFailure = $_.Exception -is [System.FormatException]
      $message = if ($isShapeFailure) { "Skipping '$file': $($_.Exception.Message)." } else { "Skipping '$file': failed to parse JSON - $($_.Exception.Message)" }
      Write-Warning $message
      $code = if ($isShapeFailure) { 'Aggregate-InvalidResult' } else { 'Aggregate-InvalidJson' }
      [void]$findings.Add([pscustomobject]@{ Code = $code; Severity = 'Medium'; Message = $message; File = $file })
    }
  }
  return [pscustomobject]@{ Items = @($items); Findings = @($findings) }
}

function Get-ReportAggregateBaseToken {
  [CmdletBinding()]
  [OutputType([string])]
  param([Parameter(Mandatory)][object[]]$Items, [Parameter(Mandatory)][int]$RejectedFiles)

  $failed = @($Items | Where-Object { $_.Result -eq 'FAIL' }).Count
  $warned = @($Items | Where-Object { $_.Result -eq 'WARN' }).Count
  if ($Items.Count -eq 0 -and $RejectedFiles -gt 0) { return 'FAIL' }
  if ($failed -gt 0) { return 'FAIL' }
  if ($warned -gt 0 -or $RejectedFiles -gt 0) { return 'WARN' }
  return 'OK'
}

function Get-ReportAggregateToken {
  [CmdletBinding()]
  [OutputType([string])]
  param([Parameter(Mandatory)][object[]]$Items, [Parameter(Mandatory)][int]$RejectedFiles, [switch]$Strict)

  $token = Get-ReportAggregateBaseToken -Items $Items -RejectedFiles $RejectedFiles
  if ($Strict -and $token -eq 'WARN') { return 'FAIL' }
  return $token
}

function Invoke-ReportAggregate {
  [CmdletBinding()]
  param()

  $directoryNameCache = New-ReportAggregateDirectoryNameCache
  $outputCanonicalPath = Get-ReportAggregateOutputPath -OutputPath $OutputPath -DirectoryNameCache $directoryNameCache
  $files = @(Get-ReportAggregateInputFiles -InputPath $InputPath -OutputCanonicalPath $outputCanonicalPath -DirectoryNameCache $directoryNameCache)
  if ($files.Count -eq 0) {
    $message = 'No JSON result files found in InputPath.'
    $finding = [pscustomobject]@{ Code = 'Aggregate-NoInputFiles'; Severity = 'High'; Message = $message }
    $report = Get-V2ResultObject -ScriptName '00-Report-Aggregate.ps1' -Mode $Mode -Result 'FAIL' -Findings @($finding) -Summary ([pscustomobject]@{ Files = 0; RejectedFiles = 0; OK = 0; WARN = 0; FAIL = 0; Error = $message }) -Metadata @{ Items = @() }
    Write-ResultObject -ResultObject $report -OutputFormat $OutputFormat -OutputPath $OutputPath
    if ($PassThru) { $report }
    exit (Get-V2ExitCode -Result 'FAIL')
  }
  $parsed = Read-ReportAggregateItems -Files $files
  $items = @($parsed.Items); $findings = @($parsed.Findings)
  $summary = [pscustomobject]@{ Files = $items.Count; RejectedFiles = $findings.Count; OK = @($items | Where-Object { $_.Result -eq 'OK' }).Count; WARN = @($items | Where-Object { $_.Result -eq 'WARN' }).Count; FAIL = @($items | Where-Object { $_.Result -eq 'FAIL' }).Count }
  $token = Get-ReportAggregateToken -Items $items -RejectedFiles $findings.Count -Strict:$Strict
  $report = Get-V2ResultObject -ScriptName '00-Report-Aggregate.ps1' -Mode $Mode -Result $token -Findings $findings -Summary $summary -Metadata @{ Items = $items }
  if ($OutputFormat -eq 'Console') { Write-Section -Title 'Aggregate Report'; Write-KeyValue -Key 'Files' -Value $summary.Files; Write-KeyValue -Key 'OK' -Value $summary.OK; Write-KeyValue -Key 'WARN' -Value $summary.WARN; Write-KeyValue -Key 'FAIL' -Value $summary.FAIL }
  Write-ResultObject -ResultObject $report -OutputFormat $OutputFormat -OutputPath $OutputPath
  if ($PassThru) { $report }
  exit (Get-V2ExitCode -Result $token)
}
