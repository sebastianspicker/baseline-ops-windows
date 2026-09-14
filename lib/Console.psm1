<#
.SYNOPSIS
Console output helper functions for consistent formatting across scripts.

.DESCRIPTION
This module provides consolidated console output functions that were previously
duplicated across multiple scripts. It includes severity-based coloring,
ranking, and summary output functions.

.NOTES
Consolidated from 15+ duplicate implementations across scripts:
- Get-SeverityColor / Get-StatusColor / Get-ConsoleColor
- Get-SeverityRank
- Write-ConsoleSummary variants
#>

Set-StrictMode -Version Latest

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

$script:SeverityAliases = @{
  'critical' = 'Critical'; 'crit' = 'Critical'; 'high' = 'High'; 'error' = 'Error'; 'err' = 'Error'
  'fail' = 'Fail'; 'failed' = 'Fail'; 'failure' = 'Fail'; 'bad' = 'Fail'; 'danger' = 'Fail'
  'medium' = 'Medium'; 'med' = 'Medium'; 'warning' = 'Warning'; 'warn' = 'Warning'; 'drift' = 'Warning'; 'changed' = 'Warning'
  'low' = 'Low'; 'ok' = 'OK'; 'good' = 'OK'; 'success' = 'OK'; 'pass' = 'OK'; 'passed' = 'OK'
  'skip' = 'Skip'; 'skipped' = 'Skip'; 'debug' = 'Debug'; 'dim' = 'Debug'; 'muted' = 'Debug'
}

$script:SeverityStatFields = @{
  'Critical' = 'Critical'; 'High' = 'High'; 'Medium' = 'Medium'; 'Warning' = 'Medium'; 'Low' = 'Low'
  'Error' = 'Error'; 'Fail' = 'Error'; 'OK' = 'OK'; 'Skip' = 'Skip'; 'Debug' = 'Debug'; 'Info' = 'Info'
}

<#
.SYNOPSIS
  Normalizes severity and status aliases to a configured severity name.
.PARAMETER Severity
  Severity or status keyword to normalize.
#>
function Resolve-Severity {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]
    [AllowNull()]
    [AllowEmptyString()]
    [string]$Severity
  )

  if ([string]::IsNullOrWhiteSpace($Severity)) { return 'Info' }

  $alias = $Severity.Trim().ToLowerInvariant()
  if ($script:SeverityAliases.ContainsKey($alias)) { return $script:SeverityAliases[$alias] }
  return 'Info'
}

<#
.SYNOPSIS
  Converts a display color value to a console color.
#>
function Resolve-ConsoleColorValue {
  [CmdletBinding()]
  param([object]$Color)

  if ($Color -is [ConsoleColor]) { return $Color }
  if ($Color -is [string]) {
    try { return [ConsoleColor]$Color } catch { return $null }
  }
  return $null
}

<#
.SYNOPSIS
  Writes a line through the host UI.
#>
function Write-HostConsoleLine {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][object]$HostUi,
    [AllowNull()][ConsoleColor]$Color,
    [Parameter(Mandatory)][string]$BackgroundColor,
    [Parameter(Mandatory)][Alias('Message')][string]$Text,
    [switch]$NoNewLine
  )

  if ($NoNewLine) {
    if ($null -ne $Color) { $HostUi.Write($Color, $BackgroundColor, $Text) } else { $HostUi.Write($Text) }
    return
  }
  if ($null -ne $Color) { $HostUi.WriteLine($Color, $BackgroundColor, $Text) } else { $HostUi.WriteLine($Text) }
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

  $normalized = Resolve-Severity -Severity $Status
  return Get-SeverityColor -Severity $normalized
}

<#
.SYNOPSIS
  Gets the display color for a legacy console status token.
.DESCRIPTION
  Routes the constrained status vocabulary through the shared severity mapping.
#>
function Get-ConsoleColor {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]
    [ValidateSet('OK', 'WARN', 'ERR', 'INFO', 'DIM', 'CRIT', 'HIGH', 'MED', 'LOW', 'DEBUG')]
    [string]$Kind
  )

  return Get-StatusColor -Status $Kind
}

<#
.SYNOPSIS
  Gets one configured display property for a normalized severity.
#>
function Get-SeverityDisplayProperty {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Severity,
    [Parameter(Mandatory)][string]$Property,
    [Parameter(Mandatory)][object]$Default
  )

  $normalized = Resolve-Severity -Severity $Severity
  if ($script:SeverityConfig.ContainsKey($normalized)) { return $script:SeverityConfig[$normalized][$Property] }
  return $Default
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

  return Get-SeverityDisplayProperty -Severity $Severity -Property 'Rank' -Default 0
}

<#
.SYNOPSIS
  Gets the display prefix for a severity value.
.DESCRIPTION
  Normalizes severity aliases before reading the shared presentation mapping.
#>
function Get-SeverityPrefix {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]
    [string]$Severity
  )

  return Get-SeverityDisplayProperty -Severity $Severity -Property 'Prefix' -Default '[INFO] '
}

<#
.SYNOPSIS
  Writes one console line with an optional foreground color.
.DESCRIPTION
  Uses the host UI when available and falls back to the information stream.
#>
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

  $fg = Resolve-ConsoleColorValue -Color $Color

  try {
    Write-HostConsoleLine -HostUi $PSCmdlet.Host.UI -Color $fg `
      -BackgroundColor $PSCmdlet.Host.UI.RawUI.BackgroundColor -Text $Text -NoNewLine:$NoNewLine
  } catch {
    Write-Information -MessageData $Text -InformationAction Continue
  }
}

<#
.SYNOPSIS
  Writes standard summary properties.
#>
function Write-ConsoleSummaryProperties {
  [CmdletBinding()]
  param([Parameter(Mandatory)][psobject]$Summary)

  if ($Summary.PSObject.Properties['ComputerName']) { Write-ColoredLine -Text " Computer : $($Summary.ComputerName)" -Color 'Gray' }
  if ($Summary.PSObject.Properties['Timestamp']) { Write-ColoredLine -Text " Time     : $($Summary.Timestamp)" -Color 'Gray' }
  if ($Summary.PSObject.Properties['EndTime'] -and $Summary.PSObject.Properties['StartTime']) {
    $duration = $Summary.EndTime - $Summary.StartTime
    if ($duration) { Write-ColoredLine -Text " Duration : $($duration.ToString('hh\:mm\:ss'))" -Color 'Gray' }
  }
}

<#
.SYNOPSIS
  Writes optional summary fields.
#>
function Write-ConsoleSummaryCustomFields {
  [CmdletBinding()]
  param([hashtable]$CustomFields)

  if ($CustomFields -and $CustomFields.Count -gt 0) {
    foreach ($key in $CustomFields.Keys) {
      Write-ColoredLine -Text (" {0} : {1}" -f $key.PadRight(9), $CustomFields[$key]) -Color 'Gray'
    }
  }
}

<#
.SYNOPSIS
  Writes the finding list portion of a summary.
#>
function Write-ConsoleSummaryFindings {
  [CmdletBinding()]
  param([System.Collections.ArrayList]$Findings)

  if (-not $Findings -or $Findings.Count -eq 0) { return }
  Write-ColoredLine -Text '' -Color 'Gray'
  Write-ColoredLine -Text ' Findings:' -Color 'White'
  foreach ($finding in $Findings) {
    $severity = if ($finding.PSObject.Properties['Severity']) { $finding.Severity } else { 'Info' }
    $code = if ($finding.PSObject.Properties['Code']) { $finding.Code } else { 'UNKNOWN' }
    $message = if ($finding.PSObject.Properties['Message']) { $finding.Message } else { '' }
    Write-FindingLine -Severity $severity -Code $code -Message $message
  }
}

<#
.SYNOPSIS
  Writes a compact severity breakdown.
#>
function Write-ConsoleSeverityBreakdown {
  [CmdletBinding()]
  param([System.Collections.ArrayList]$Findings)

  if (-not $Findings -or $Findings.Count -eq 0) { return }
  $stats = Get-FindingStats -Findings $Findings
  $labels = [ordered]@{ Critical = 'Critical'; High = 'High'; Medium = 'Med'; Low = 'Low'; Info = 'Info'; Error = 'Error'; OK = 'OK'; Skip = 'Skip'; Debug = 'Debug' }
  $parts = foreach ($name in $labels.Keys) {
    if ($stats.$name -gt 0) { '{0}={1}' -f $labels[$name], $stats.$name }
  }
  if (@($parts).Count -gt 0) {
    Write-ColoredLine -Text '' -Color 'Gray'
    Write-ColoredLine -Text (' Breakdown: ' + ($parts -join ' | ')) -Color 'Gray'
  }
}

<#
.SYNOPSIS
  Gets the overall result for a collection of findings.
#>
function Get-ConsoleSummaryResult {
  [CmdletBinding()]
  param([System.Collections.ArrayList]$Findings)

  if (-not $Findings -or $Findings.Count -eq 0) { return 'PASS' }
  $maxRank = ($Findings | ForEach-Object {
      $severity = if ($_.PSObject.Properties['Severity']) { $_.Severity } else { 'Info' }
      Get-SeverityRank -Severity $severity
    } | Measure-Object -Maximum).Maximum
  if ($maxRank -ge 3) { return 'FAIL' }
  if ($maxRank -ge 2) { return 'WARN' }
  return 'PASS'
}

<#
.SYNOPSIS
  Writes a decorative rule with an optional title.
.DESCRIPTION
  Provides a consistent visual section boundary for console reports.
#>
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

<#
.SYNOPSIS
  Writes the common audit summary header.
.DESCRIPTION
  Displays title, host, time, and finding count with consistent formatting.
#>
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

<#
.SYNOPSIS
  Writes a single severity-colored finding line.
.DESCRIPTION
  Combines the configured prefix, finding code, and optional message.
#>
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

  Write-ConsoleSummaryProperties -Summary $Summary

  # Findings count
  $findingsCount = if ($Findings) { $Findings.Count } else { 0 }
  $findingsColor = if ($findingsCount -gt 0) { 'Yellow' } else { 'Green' }
  Write-ColoredLine -Text " Findings : $findingsCount" -Color $findingsColor

  Write-ConsoleSummaryCustomFields -CustomFields $CustomFields
  Write-ConsoleSummaryFindings -Findings $Findings
  Write-ConsoleSeverityBreakdown -Findings $Findings
  $overallResult = Get-ConsoleSummaryResult -Findings $Findings
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
    Total    = $findingsList.Count
    Critical = 0
    High     = 0
    Medium   = 0
    Low      = 0
    Info     = 0
    Warning  = 0
    Error    = 0
    OK       = 0
    Skip     = 0
    Debug    = 0
  }

  foreach ($finding in $findingsList) {
    $severity = if ($finding.PSObject.Properties['Severity']) { $finding.Severity } else { 'Info' }
    $field = $script:SeverityStatFields[(Resolve-Severity -Severity $severity)]
    if ($field) { $stats[$field]++ } else { $stats.Info++ }
  }

  return [pscustomobject]$stats
}

Set-Alias -Name Write-PrettyLine -Value Write-ColoredLine -WhatIf:$false

$script:ConsoleExportedFunctions = @(
  'Resolve-Severity'
  'Get-SeverityColor'
  'Get-StatusColor'
  'Get-ConsoleColor'
  'Get-SeverityRank'
  'Get-SeverityPrefix'
  'Write-ColoredLine'
  'Write-HostConsoleLine'
  'Write-DecorativeRule'
  'Write-SummaryHeader'
  'Write-FindingLine'
  'Write-ConsoleSummary'
  'Get-FindingStats'
)

$script:ConsoleExportedAliases = @(
  'Write-PrettyLine'
)

Export-ModuleMember -Function $script:ConsoleExportedFunctions -Alias $script:ConsoleExportedAliases
