Set-StrictMode -Version Latest

<#
.SYNOPSIS
Console output helper functions for consistent formatting across scripts.

.DESCRIPTION
This module provides consolidated console output functions that were previously
duplicated across multiple scripts. It includes severity-based coloring,
ranking, and summary output functions.

.NOTES
Consolidated from 15+ duplicate implementations across scripts:
- Get-SeverityColor / Get-StatusColor / Get-ColorForLevel / Get-ConsoleColor
- Get-SeverityRank
- Write-ConsoleSummary variants
#>

# Standard severity levels with their display properties
$script:SeverityConfig = @{
  'Critical' = @{ Color = 'Red'; Rank = 4; Prefix = '[CRIT] ' }
  'High'     = @{ Color = 'Red'; Rank = 3; Prefix = '[HIGH] ' }
  'Medium'   = @{ Color = 'Yellow'; Rank = 2; Prefix = '[MED]  ' }
  'Low'      = @{ Color = 'Cyan'; Rank = 1; Prefix = '[LOW]  ' }
  'Info'     = @{ Color = 'Gray'; Rank = 0; Prefix = '[INFO] ' }
  'Warning'  = @{ Color = 'Yellow'; Rank = 2; Prefix = '[WARN] ' }
  'Error'    = @{ Color = 'Red'; Rank = 3; Prefix = '[ERR]  ' }
  'OK'       = @{ Color = 'Green'; Rank = -1; Prefix = '[OK]   ' }
  'Pass'     = @{ Color = 'Green'; Rank = -1; Prefix = '[PASS] ' }
  'Fail'     = @{ Color = 'Red'; Rank = 3; Prefix = '[FAIL] ' }
  'Skip'     = @{ Color = 'DarkGray'; Rank = -2; Prefix = '[SKIP] ' }
  'Debug'    = @{ Color = 'DarkGray'; Rank = -3; Prefix = '[DEBUG]' }
}

<#
.SYNOPSIS
  Returns the console color for a severity level.
.PARAMETER Severity
  Severity name (e.g. Critical, High, Medium, Low, Info, OK).
#>
function Get-SeverityColor {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]
    [ValidateSet('Critical', 'High', 'Medium', 'Low', 'Info', 'Warning', 'Error', 'OK', 'Pass', 'Fail', 'Skip', 'Debug')]
    [string]$Severity
  )

  if ($script:SeverityConfig.ContainsKey($Severity)) {
    return $script:SeverityConfig[$Severity].Color
  }
  return 'Gray'
}

<#
.SYNOPSIS
  Returns the console color for a status keyword (e.g. OK, Warn, Fail).
.PARAMETER Status
  Status keyword to map to a color.
#>
function Get-StatusColor {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]
    [string]$Status
  )

  # Normalize status to standard severity
  $normalized = switch -Regex ($Status) {
    '^(Critical|Crit)$' { 'Critical' }
    '^(High|Error|Err|Fail|Failed|Failure|Bad|Danger)$' { 'High' }
    '^(Medium|Warn|Warning|Drift|Changed)$' { 'Medium' }
    '^(Low)$' { 'Low' }
    '^(OK|Pass|Passed|Good|Success)$' { 'OK' }
    '^(Skip|Skipped|Note)$' { 'Skip' }
    default { 'Info' }
  }

  return Get-SeverityColor -Severity $normalized
}

function Get-ColorForLevel {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]
    [ValidateSet('Critical', 'High', 'Medium', 'Low', 'Info')]
    [string]$Level
  )

  return Get-SeverityColor -Severity $Level
}

function Get-ConsoleColor {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]
    [ValidateSet('OK', 'WARN', 'ERR', 'INFO', 'DIM', 'CRIT', 'HIGH', 'MED', 'LOW', 'DEBUG')]
    [string]$Kind
  )

  $severity = switch ($Kind) {
    'OK'    { 'OK' }
    'WARN'  { 'Warning' }
    'ERR'   { 'Error' }
    'INFO'  { 'Info' }
    'DIM'   { 'Debug' }
    'CRIT'  { 'Critical' }
    'HIGH'  { 'High' }
    'MED'   { 'Medium' }
    'LOW'   { 'Low' }
    'DEBUG' { 'Debug' }
  }

  return Get-SeverityColor -Severity $severity
}

<#
.SYNOPSIS
  Returns the numeric rank for a severity level (higher = more severe).
.PARAMETER Severity
  Severity keyword to rank.
#>
function Get-SeverityRank {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]
    [string]$Severity
  )

  # Normalize input
  $normalized = switch -Regex ($Severity) {
    '^(Critical|Crit)$' { 'Critical' }
    '^(High|Error|Err|Fail|Failed|Failure)$' { 'High' }
    '^(Medium|Warn|Warning|Drift|Changed)$' { 'Medium' }
    '^(Low)$' { 'Low' }
    '^(OK|Pass|Passed|Good|Success)$' { 'OK' }
    '^(Skip|Skipped)$' { 'Skip' }
    '^(Debug)$' { 'Debug' }
    default { 'Info' }
  }

  if ($script:SeverityConfig.ContainsKey($normalized)) {
    return $script:SeverityConfig[$normalized].Rank
  }
  return 0
}

function Get-SeverityPrefix {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]
    [string]$Severity
  )

  # Normalize input
  $normalized = switch -Regex ($Severity) {
    '^(Critical|Crit)$' { 'Critical' }
    '^(High|Error|Err|Fail|Failed|Failure)$' { 'High' }
    '^(Medium|Warn|Warning|Drift|Changed)$' { 'Medium' }
    '^(Low)$' { 'Low' }
    '^(OK|Pass|Passed|Good|Success)$' { 'OK' }
    '^(Skip|Skipped)$' { 'Skip' }
    '^(Debug)$' { 'Debug' }
    default { 'Info' }
  }

  if ($script:SeverityConfig.ContainsKey($normalized)) {
    return $script:SeverityConfig[$normalized].Prefix
  }
  return '[INFO] '
}

function Write-ColoredLine {
  [CmdletBinding()]
  param(
    [Parameter(Position = 0)]
    [AllowEmptyString()]
    [string]$Text = '',
    [Parameter(Position = 1)]
    [object]$Color,
    [switch]$NoNewLine
  )

  $fg = if ($Color -is [ConsoleColor]) { $Color } elseif ($Color -is [string]) { 
    try { [ConsoleColor]$Color } catch { $null }
  } else { $null }

  if ($null -ne $fg) {
    Write-Host $Text -ForegroundColor $fg -NoNewline:$NoNewLine
  } else {
    Write-Host $Text -NoNewline:$NoNewLine
  }
}

function Write-DecorativeRule {
  [CmdletBinding()]
  param(
    [string]$Title,
    [string]$Char = '=',
    [int]$Width = 70,
    [object]$Color = 'DarkGray'
  )

  $line = $Char * $Width
  Write-ColoredLine -Text $line -Color $Color
  if ($Title) {
    Write-ColoredLine -Text $Title -Color 'White'
    Write-ColoredLine -Text $line -Color $Color
  }
}

function Write-SectionHeader {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]
    [string]$Title,
    [int]$Width = 70
  )

  Write-DecorativeRule -Title $Title -Width $Width
}

function Write-SummaryHeader {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]
    [string]$Title,
    [string]$ComputerName,
    [string]$Timestamp,
    [int]$FindingsCount,
    [int]$Width = 70
  )

  Write-DecorativeRule -Title $Title -Width $Width
  Write-ColoredLine -Text " Computer : $ComputerName" -Color 'Gray'
  Write-ColoredLine -Text " Time     : $Timestamp" -Color 'Gray'
  
  $findingsColor = if ($FindingsCount -gt 0) { 'Yellow' } else { 'Green' }
  Write-ColoredLine -Text " Findings : $FindingsCount" -Color $findingsColor
  Write-ColoredLine -Text '' -Color 'Gray'
}

function Write-FindingLine {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]
    [string]$Severity,
    [Parameter(Mandatory)]
    [string]$Code,
    [string]$Message
  )

  $color = Get-SeverityColor -Severity $Severity
  $prefix = Get-SeverityPrefix -Severity $Severity
  $text = "$prefix$Code"
  if ($Message) { $text += " - $Message" }
  
  Write-ColoredLine -Text $text -Color $color
}

<#
.SYNOPSIS
  Writes a formatted audit summary with findings to the console.
.PARAMETER Summary
  Summary object with ComputerName, Timestamp, etc.
.PARAMETER Findings
  List of finding objects to display.
.PARAMETER Title
  Header title for the summary section.
.PARAMETER Width
  Width of the decorative rule lines.
.PARAMETER CustomFields
  Optional hashtable of additional key-value pairs to render after the
  standard fields (Computer, Time, Findings count). Keys are used as labels,
  values as display text. Ordered dictionaries ([ordered]@{}) are supported
  to control rendering order.
#>
function Write-ConsoleSummary {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]
    [psobject]$Summary,
    [Parameter(Mandatory)]
    [AllowEmptyCollection()]
    [System.Collections.ArrayList]$Findings,
    [string]$Title = 'Audit Summary',
    [int]$Width = 70,
    [hashtable]$CustomFields
  )

  # Header
  Write-DecorativeRule -Title $Title -Width $Width

  # Summary properties
  if ($Summary.PSObject.Properties['ComputerName']) {
    Write-ColoredLine -Text " Computer : $($Summary.ComputerName)" -Color 'Gray'
  }
  if ($Summary.PSObject.Properties['Timestamp']) {
    Write-ColoredLine -Text " Time     : $($Summary.Timestamp)" -Color 'Gray'
  }
  if ($Summary.PSObject.Properties['EndTime']) {
    $duration = if ($Summary.PSObject.Properties['StartTime']) {
      $Summary.EndTime - $Summary.StartTime
    } else { $null }
    if ($duration) {
      Write-ColoredLine -Text " Duration : $($duration.ToString('hh\:mm\:ss'))" -Color 'Gray'
    }
  }

  # Findings count
  $findingsCount = if ($Findings) { $Findings.Count } else { 0 }
  $findingsColor = if ($findingsCount -gt 0) { 'Yellow' } else { 'Green' }
  Write-ColoredLine -Text " Findings : $findingsCount" -Color $findingsColor

  # Custom fields (rendered after standard fields)
  if ($CustomFields -and $CustomFields.Count -gt 0) {
    foreach ($key in $CustomFields.Keys) {
      $value = $CustomFields[$key]
      $padded = $key.PadRight(9)
      Write-ColoredLine -Text " $padded : $value" -Color 'Gray'
    }
  }

  # Findings list
  if ($Findings -and $Findings.Count -gt 0) {
    Write-ColoredLine -Text '' -Color 'Gray'
    Write-ColoredLine -Text ' Findings:' -Color 'White'

    foreach ($finding in $Findings) {
      $sev = if ($finding.PSObject.Properties['Severity']) { $finding.Severity } else { 'Info' }
      $code = if ($finding.PSObject.Properties['Code']) { $finding.Code } else { 'UNKNOWN' }
      $msg = if ($finding.PSObject.Properties['Message']) { $finding.Message } else { '' }
      Write-FindingLine -Severity $sev -Code $code -Message $msg
    }
  }

  # Severity breakdown line
  if ($Findings -and $Findings.Count -gt 0) {
    $stats = Get-FindingStats -Findings $Findings
    $parts = [System.Collections.ArrayList]::new()
    if ($stats.High -gt 0) { [void]$parts.Add("High=$($stats.High)") }
    if ($stats.Medium -gt 0) { [void]$parts.Add("Med=$($stats.Medium)") }
    if ($stats.Low -gt 0) { [void]$parts.Add("Low=$($stats.Low)") }
    if ($stats.Info -gt 0) { [void]$parts.Add("Info=$($stats.Info)") }
    if ($stats.Skip -gt 0) { [void]$parts.Add("Skip=$($stats.Skip)") }
    if ($parts.Count -gt 0) {
      Write-ColoredLine -Text '' -Color 'Gray'
      Write-ColoredLine -Text (" Breakdown: " + ($parts -join ' | ')) -Color 'Gray'
    }
  }

  # Overall result indicator
  $overallResult = if ($Findings -and $Findings.Count -gt 0) {
    $maxRank = ($Findings | ForEach-Object {
      $s = if ($_.PSObject.Properties['Severity']) { $_.Severity } else { 'Info' }
      Get-SeverityRank -Severity $s
    } | Measure-Object -Maximum).Maximum
    if ($maxRank -ge 3) { 'FAIL' } elseif ($maxRank -ge 2) { 'WARN' } else { 'PASS' }
  } else { 'PASS' }
  $resultColor = switch ($overallResult) { 'FAIL' { 'Red' }; 'WARN' { 'Yellow' }; default { 'Green' } }
  Write-ColoredLine -Text " Result   : $overallResult" -Color $resultColor

  Write-DecorativeRule -Width $Width
}

<#
.SYNOPSIS
  Computes finding counts by severity level.
.PARAMETER Findings
  Collection of finding objects to aggregate.
#>
function Get-FindingStats {
  [CmdletBinding()]
  param(
    [AllowNull()]
    [System.Collections.IEnumerable]$Findings = @()
  )

  $findingsList = @()
  if ($null -ne $Findings) {
    $findingsList = @($Findings)
  }

  $stats = @{
    Total   = $findingsList.Count
    High    = 0
    Medium  = 0
    Low     = 0
    Info    = 0
    Warning = 0
    Error   = 0
    Skip    = 0
    Debug   = 0
  }

  foreach ($finding in $findingsList) {
    $sev = if ($finding.PSObject.Properties['Severity']) { $finding.Severity } else { 'Info' }
    switch -Regex ($sev) {
      '^(Critical|High)$' { $stats.High++; break }
      '^(Medium|Warning|Warn)$' { $stats.Medium++; break }
      '^(Low)$' { $stats.Low++; break }
      '^(Error|Err|Fail)$' { $stats.Error++; break }
      '^(Skip|Skipped)$' { $stats.Skip++; break }
      '^(Debug)$' { $stats.Debug++; break }
      default { $stats.Info++ }
    }
  }

  return [pscustomobject]$stats
}

Set-Alias -Name Write-PrettyLine -Value Write-ColoredLine

$script:ConsoleExportedFunctions = @(
  'Get-SeverityColor'
  'Get-StatusColor'
  'Get-ColorForLevel'
  'Get-ConsoleColor'
  'Get-SeverityRank'
  'Get-SeverityPrefix'
  'Write-ColoredLine'
  'Write-DecorativeRule'
  'Write-SectionHeader'
  'Write-SummaryHeader'
  'Write-FindingLine'
  'Write-ConsoleSummary'
  'Get-FindingStats'
)

$script:ConsoleExportedAliases = @(
  'Write-PrettyLine'
)

Export-ModuleMember -Function $script:ConsoleExportedFunctions -Alias $script:ConsoleExportedAliases
