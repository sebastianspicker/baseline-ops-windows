<#
.SYNOPSIS
Capture-friendly UI output functions for human-readable script output.

.DESCRIPTION
Provides a unified set of Write-* functions for information-stream status
prefixes, section headers, key-value displays, and bullet lists. Style
parameters are kept for call compatibility and `-NoNewLine` host coloring; full
host-colored summaries live in Console.psm1.
#>

Set-StrictMode -Version Latest

Microsoft.PowerShell.Core\Import-Module ([System.IO.Path]::Combine($PSScriptRoot, 'Common.psm1')) -DisableNameChecking
Microsoft.PowerShell.Core\Import-Module ([System.IO.Path]::Combine($PSScriptRoot, 'Console.psm1')) -DisableNameChecking

$script:UiDefaults = [ordered]@{
  SectionWidth = 70
  KeyWidth     = 22
  PrefixWidth  = 7
}

<#
.SYNOPSIS
  Resolves a UI style to a console color.
.DESCRIPTION
  Maps supported presentation names to the color used for console output.
#>
function Resolve-UiColor {
  [CmdletBinding()]
  param([object]$Style)

  if ($null -eq $Style) { return $null }
  if ($Style -is [ConsoleColor]) { return $Style }

  $s = [string]$Style
  if ([string]::IsNullOrWhiteSpace($s)) { return $null }

  $name = $s.Trim()
  switch ($name.ToLowerInvariant()) {
    'default' { return $null }
    'key' { return [ConsoleColor]::Gray }
    'value' { return [ConsoleColor]::White }
    'accent' { return [ConsoleColor]::White }
    'header' { return [ConsoleColor]::Cyan }
    'title' { return [ConsoleColor]::Cyan }
    'section' { return [ConsoleColor]::Cyan }
    'darkcyan' { return [ConsoleColor]::Cyan }
    'darkyellow' { return [ConsoleColor]::Yellow }
    'darkgreen' { return [ConsoleColor]::Green }
    'darkred' { return [ConsoleColor]::Red }
    'darkgrey' { return [ConsoleColor]::DarkGray }
    'grey' { return [ConsoleColor]::Gray }
  }

  try {
    return [ConsoleColor]$name
  } catch {
    $severityColor = Console\Get-StatusColor -Status $name
    return [ConsoleColor]$severityColor
  }
}

<#
.SYNOPSIS
  Writes a styled line to the console, respecting Quiet/NoColor/NoConsole.
.PARAMETER Message
  Text to display.
.PARAMETER Style
  Color or semantic style name (e.g. 'Success', 'Warn', 'Error', 'Muted').
#>
function Write-UiLine {
  [CmdletBinding()]
  param(
    [Parameter(Position=0)][Alias('Text')][AllowNull()][AllowEmptyString()][string]$Message = '',
    [Parameter(Position=1)][Alias('Color','ForegroundColor','Role')][object]$Style,
    [switch]$NoNewLine,
    [switch]$UseWriteInformation,
    [switch]$UseInformationStream,
    [switch]$NoConsole,
    [switch]$NoColor,
    [switch]$Quiet
  )

  if (-not $PSBoundParameters.ContainsKey('NoConsole')) {
    # Compatibility behavior: omitted values are inherited from caller scope.
    $NoConsole = [bool](Get-CallerValue -Name 'NoConsole')
  }
  if (-not $PSBoundParameters.ContainsKey('Quiet')) {
    # Compatibility behavior: omitted values are inherited from caller scope.
    $Quiet = [bool](Get-CallerValue -Name 'Quiet')
  }
  if ($NoConsole -or $Quiet) { return }

  $useInfo = $UseWriteInformation -or $UseInformationStream
  if (-not $PSBoundParameters.ContainsKey('UseWriteInformation') -and -not $PSBoundParameters.ContainsKey('UseInformationStream')) {
    # Compatibility behavior: omitted values are inherited from caller scope.
    $useInfo = [bool](Get-CallerValue -Name 'UseWriteInformation')
    if (-not $useInfo) { $useInfo = [bool](Get-CallerValue -Name 'UseInformationStream') }
  }

  if ($useInfo) {
    if ([string]::IsNullOrEmpty($Message)) {
      Write-Information -MessageData '' -InformationAction Continue
      return
    }
    Write-Information -MessageData $Message -InformationAction Continue
    return
  }

  if (-not $PSBoundParameters.ContainsKey('NoColor')) {
    # Compatibility behavior: omitted color controls are inherited from caller scope.
    $NoColor = [bool](Get-CallerValue -Name 'NoColor')
  }
  if (-not $NoColor) {
    # Compatibility behavior: omitted color controls are inherited from caller scope.
    $callerUseColor = Get-CallerValue -Name 'UseColor'
    if ($null -eq $callerUseColor) { $callerUseColor = $true }
    if (-not $callerUseColor) { $NoColor = $true }
  }

  $fg = if ($NoColor) { $null } else { Resolve-UiColor -Style $Style }
  if ($NoNewLine) {
    if ($null -ne $fg) {
      $PSCmdlet.Host.UI.Write($fg, $PSCmdlet.Host.UI.RawUI.BackgroundColor, $Message)
    } else {
      $PSCmdlet.Host.UI.Write($Message)
    }
    return
  }
  Write-Information -MessageData $Message -InformationAction Continue
}

<#
.SYNOPSIS
  Writes one legacy console line.
.DESCRIPTION
  Preserves the compatibility output surface through the shared UI writer.
#>
function Write-ConsoleLine {
  [CmdletBinding()]
  param(
    [Parameter(Position=0)][Alias('Text')][AllowNull()][AllowEmptyString()][string]$Message = '',
    [Parameter(Position=1)][Alias('Color','ForegroundColor','Role')][object]$Style,
    [switch]$NoNewLine,
    [pscustomobject]$Config,
    [switch]$NoConsole,
    [switch]$NoColor,
    [switch]$Quiet
  )

  $lineParams = @{}
  foreach ($key in $PSBoundParameters.Keys) {
    $lineParams[$key] = $PSBoundParameters[$key]
  }
  [void]$lineParams.Remove('Config')

  if ($Config -and $Config.PSObject.Properties['ConsoleUseInformation'] -and [bool]$Config.ConsoleUseInformation) {
    $lineParams['UseWriteInformation'] = $true
  }

  Write-UiLine @lineParams
}

<#
.SYNOPSIS
  Writes a legacy console section header.
.DESCRIPTION
  Preserves existing callers while using the shared UI header formatting.
#>
function Write-ConsoleHeader {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Title,
    [int]$Width = $script:UiDefaults.SectionWidth,
    [string]$Right,
    [pscustomobject]$Config
  )

  $useInfo = $false
  if ($Config -and $Config.PSObject.Properties['ConsoleUseInformation']) {
    $useInfo = [bool]$Config.ConsoleUseInformation
  }
  $line = ('=' * $Width)
  Write-UiLine -Message $line -Style 'Dim' -UseWriteInformation:$useInfo
  Write-UiLine -Message $Title -Style 'Header' -UseWriteInformation:$useInfo
  if ($Right) { Write-UiLine -Message ("  " + $Right) -Style 'Muted' -UseWriteInformation:$useInfo }
  Write-UiLine -Message $line -Style 'Dim' -UseWriteInformation:$useInfo
}

<#
.SYNOPSIS
  Writes a section header with decorative rule lines.
.PARAMETER Title
  Section title text.
.PARAMETER Width
  Width of the decorative rule.
#>
function Write-Section {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Title,
    [int]$Width = $script:UiDefaults.SectionWidth
  )

  $line = ('=' * $Width)
  Write-UiLine -Message $line -Style 'Dim'
  Write-UiLine -Message $Title -Style 'Header'
  Write-UiLine -Message $line -Style 'Dim'
}

<#
.SYNOPSIS
  Resolves a status token to a UI style.
.DESCRIPTION
  Normalizes status aliases for consistent colored console output.
#>
function Resolve-StatusStyle {
  [CmdletBinding()]
  param([Parameter(Mandatory)][string]$Status)

  $rank = Console\Get-SeverityRank -Severity $Status
  if ($rank -ge 3) { return 'Error' }
  if ($rank -eq 2) { return 'Warn' }
  if ($rank -eq -1) { return 'Success' }
  if ($rank -le -2) { return 'Muted' }
  return 'Info'
}

<#
.SYNOPSIS
  Gets the display prefix for a status token.
.DESCRIPTION
  Uses the normalized UI status vocabulary for consistent report labels.
#>
function Get-StatusPrefix {
  [CmdletBinding()]
  param([Parameter(Mandatory)][string]$Status)

  return Console\Get-SeverityPrefix -Severity $Status
}

<#
.SYNOPSIS
  Writes a blank console line.
.DESCRIPTION
  Provides a common spacing primitive for report output.
#>
function Write-BlankLine {
  [CmdletBinding()]
  param()
  Write-UiLine -Message ''
}

<#
.SYNOPSIS
  Writes an informational console message.
.DESCRIPTION
  Applies the standard informational UI style.
#>
function Write-Info {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][AllowEmptyString()][string]$Message,
    [switch]$NoPrefix
  )
  $text = if ($NoPrefix) { $Message } else { (Get-StatusPrefix -Status 'Info') + $Message }
  Write-UiLine -Message $text -Style 'Info'
}

<#
.SYNOPSIS
  Writes a warning console message.
.DESCRIPTION
  Applies the standard warning UI style.
#>
function Write-Warn {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][AllowEmptyString()][string]$Message,
    [switch]$NoPrefix
  )
  $text = if ($NoPrefix) { $Message } else { (Get-StatusPrefix -Status 'Warn') + $Message }
  Write-UiLine -Message $text -Style 'Warn'
}

<#
.SYNOPSIS
  Writes an error console message.
.DESCRIPTION
  Applies the standard error UI style.
#>
function Write-ErrorLine {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][AllowEmptyString()][string]$Message,
    [switch]$NoPrefix
  )
  $text = if ($NoPrefix) { $Message } else { (Get-StatusPrefix -Status 'Fail') + $Message }
  Write-UiLine -Message $text -Style 'Error'
}

<#
.SYNOPSIS
  Writes a success console message.
.DESCRIPTION
  Applies the standard success UI style.
#>
function Write-Success {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][AllowEmptyString()][string]$Message,
    [switch]$NoPrefix
  )
  $text = if ($NoPrefix) { $Message } else { (Get-StatusPrefix -Status 'OK') + $Message }
  Write-UiLine -Message $text -Style 'Success'
}

<#
.SYNOPSIS
  Writes a status-prefixed message line (e.g. [OK], [WARN], [FAIL]).
.PARAMETER Status
  Status keyword that determines prefix and color.
.PARAMETER Message
  Message text to display after the status prefix.
#>
function Write-StatusLine {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Status,
    [Parameter(Mandatory)][AllowEmptyString()][string]$Message,
    [AllowEmptyString()][string]$Detail = '',
    [switch]$NoPrefix
  )
  $style = Resolve-StatusStyle -Status $Status
  $prefix = if ($NoPrefix) { '' } else { Get-StatusPrefix -Status $Status }
  $text = $prefix + $Message
  if (-not [string]::IsNullOrWhiteSpace($Detail)) { $text += " - $Detail" }
  Write-UiLine -Message $text -Style $style
}

<#
.SYNOPSIS
  Writes a UI rule with an optional title.
.DESCRIPTION
  Creates a consistent visual separator for console sections.
#>
function Write-UiRule {
  [CmdletBinding()]
  param(
    [string]$Title,
    [string]$Char = '=',
    [int]$Width = $script:UiDefaults.SectionWidth,
    [object]$Style = 'Dim'
  )
  $line = ($Char * $Width)
  Write-UiLine -Message $line -Style $Style
  if ($Title) { Write-UiLine -Message $Title -Style $Style }
  Write-UiLine -Message $line -Style $Style
}

<#
.SYNOPSIS
  Writes a UI header and optional subtitle.
.DESCRIPTION
  Formats the common heading surface for interactive console output.
#>
function Write-UiHeader {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][Alias('Text')][string]$Title,
    [string]$Subtitle,
    [int]$Width = $script:UiDefaults.SectionWidth
  )
  Write-BlankLine
  Write-Section -Title $Title -Width $Width
  if ($Subtitle) { Write-UiLine -Message ("  " + $Subtitle) -Style 'Muted' }
}

<#
.SYNOPSIS
  Writes a compact UI separator.
.DESCRIPTION
  Provides a reusable visual boundary between console output groups.
#>
function Write-UiSeparator {
  [CmdletBinding()]
  param(
    [Alias('Text')][string]$Title,
    [string]$Char = '-',
    [int]$Width = $script:UiDefaults.SectionWidth,
    [object]$Style = 'Dim'
  )
  if ($Title) {
    Write-UiRule -Title $Title -Char $Char -Width $Width -Style $Style
    return
  }
  Write-UiLine -Message ($Char * $Width) -Style $Style
}

<#
.SYNOPSIS
  Writes a formatted key-value pair to the console.
.PARAMETER Key
  Label for the value.
.PARAMETER Value
  Value text to display next to the key.
#>
function Write-KeyValue {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Key,
    [AllowNull()][AllowEmptyString()][string]$Value,
    [object]$KeyWidth = $script:UiDefaults.KeyWidth,
    [Alias('KeyColor')][object]$KeyStyle = 'Muted',
    [Alias('ValueColor','ValueRole','Color','Level','Style')][object]$ValueStyle = 'Info',
    [int]$Indent = 0,
    [string]$EmptyValueText = '(empty)'
  )

  if ($KeyWidth -isnot [int]) {
    if ($null -ne $KeyWidth) { $ValueStyle = $KeyWidth }
    $KeyWidth = $script:UiDefaults.KeyWidth
  }

  $prefix = if ($Indent -gt 0) { ' ' * $Indent } else { '' }
  $valueText = if ([string]::IsNullOrWhiteSpace($Value)) { $EmptyValueText } else { $Value }
  [void]$KeyStyle

  # Compatibility behavior: stream selection is inherited from caller scope.
  $useInfo = [bool](Get-CallerValue -Name 'UseWriteInformation')
  if (-not $useInfo) { $useInfo = [bool](Get-CallerValue -Name 'UseInformationStream') }

  $line = $prefix + ("{0,-$KeyWidth}: {1}" -f $Key, $valueText)
  Write-UiLine -Message $line -Style $ValueStyle -UseWriteInformation:$useInfo
}

<#
.SYNOPSIS
  Writes a labeled UI status message.
.DESCRIPTION
  Formats status, label, and detail through the common status writer.
#>
function Write-UiStatus {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Label,
    [Parameter(Mandatory)][string]$State,
    [Alias('Text')][AllowEmptyString()][string]$Detail = ''
  )
  if ($Label -and $Detail -and ($Label.Trim().ToUpperInvariant() -eq $State.Trim().ToUpperInvariant())) {
    Write-StatusLine -Status $State -Message $Detail
    return
  }
  Write-StatusLine -Status $State -Message $Label -Detail $Detail
}

<#
.SYNOPSIS
  Writes one UI bullet item.
.DESCRIPTION
  Indents the supplied text using the shared console output style.
#>
function Write-UiBullet {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][AllowEmptyString()][string]$Text,
    [object]$Style = 'Info'
  )
  Write-UiLine -Message ("  - " + $Text) -Style $Style
}

<#
.SYNOPSIS
  Writes a collection as UI bullet items.
.DESCRIPTION
  Handles empty collections and emits each item with consistent indentation.
#>
function Write-UiList {
  [CmdletBinding()]
  param(
    [string]$Header,
    [AllowNull()][AllowEmptyString()][string[]]$Items,
    [Alias('Color','ItemColor')][object]$Style = 'Info',
    [object]$HeaderColor = 'Info'
  )
  if ($null -eq $Items -or @($Items).Count -eq 0) { return }
  if (-not [string]::IsNullOrWhiteSpace($Header)) {
    Write-UiLine -Message $Header -Style $HeaderColor
  }
  foreach ($item in @($Items)) {
    Write-UiLine -Message ("  - " + $item) -Style $Style
  }
}

<#
.SYNOPSIS
  Writes a blank line through the UI output surface.
.DESCRIPTION
  Supports direct information-stream output when requested by callers.
#>
function Write-UiBlankLine {
  [CmdletBinding()]
  param(
    [switch]$UseWriteInformation,
    [switch]$UseInformationStream
  )
  if ($UseWriteInformation -or $UseInformationStream) {
    Write-UiLine -Message '' -UseWriteInformation:$UseWriteInformation -UseInformationStream:$UseInformationStream
    return
  }
  Write-BlankLine
}

<#
.SYNOPSIS
  Writes a Boolean value as a styled key-value pair.
.DESCRIPTION
  Uses success or muted styling to make the value easy to scan.
#>
function Write-UiBool {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Key,
    [Parameter(Mandatory)][bool]$Value
  )
  $style = if ($Value) { 'Success' } else { 'Muted' }
  Write-KeyValue -Key $Key -Value $Value -ValueStyle $style
}

<#
.SYNOPSIS
  Writes a legacy console banner.
.DESCRIPTION
  Retains the established banner surface for existing script callers.
#>
function Write-ConsoleBanner {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Title,
    [int]$Width = $script:UiDefaults.SectionWidth,
    [Alias('Style')][object]$Color = 'Header'
  )
  Write-BlankLine
  $line = ('=' * $Width)
  Write-UiLine -Message $line -Style 'Dim'
  Write-UiLine -Message $Title -Style $Color
  Write-UiLine -Message $line -Style 'Dim'
}

<#
.SYNOPSIS
  Writes a legacy informational console message.
.DESCRIPTION
  Retains the compatibility surface using information-stream output.
#>
function Write-ConsoleInfo {
  [CmdletBinding()]
  param([Parameter(Mandatory)][AllowEmptyString()][string]$Message)
  Write-UiLine -Message $Message -Style 'Info' -UseWriteInformation
}

<#
.SYNOPSIS
  Writes a legacy console list.
.DESCRIPTION
  Preserves existing list callers through the shared UI list formatter.
#>
function Write-ConsoleList {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Header,
    [AllowEmptyCollection()][string[]]$Items,
    [object]$HeaderColor = 'Info',
    [object]$ItemColor = 'Info',
    [int]$MaxItems = 20
  )

  if (-not $Items -or $Items.Count -eq 0) { return }

  Write-UiLine -Message $Header -Style $HeaderColor
  $take = [Math]::Min($Items.Count, $MaxItems)
  for ($i = 0; $i -lt $take; $i++) {
    Write-UiLine -Message ("  - " + [string]$Items[$i]) -Style $ItemColor
  }
  if ($Items.Count -gt $MaxItems) {
    Write-UiLine -Message ("  ... ({0} more)" -f ($Items.Count - $MaxItems)) -Style 'Muted'
  }
}

<#
.SYNOPSIS
  Displays a step progress indicator (e.g. "[3/10] Checking Defender health...").
.PARAMETER Current
  Current step number (1-based).
.PARAMETER Total
  Total number of steps.
.PARAMETER Message
  Description of the current step.
#>
function Write-UiProgress {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][int]$Current,
    [Parameter(Mandatory)][int]$Total,
    [Parameter(Mandatory)][string]$Message
  )

  $pct = if ($Total -gt 0) { [math]::Round(($Current / $Total) * 100) } else { 0 }
  $prefix = "[{0}/{1}]" -f $Current, $Total
  $text = "{0} {1} ({2}%)" -f $prefix, $Message, $pct
  Write-UiLine -Message $text -Style 'Header'
}

<#
.SYNOPSIS
  Writes a formatted summary table of finding counts by severity.
.PARAMETER Findings
  Collection of finding objects to summarize.
.PARAMETER Title
  Optional title above the table (default: 'Findings Summary').
.PARAMETER Width
  Width of the decorative rule (default: 70).
#>
function Write-UiSummaryTable {
  [CmdletBinding()]
  param(
    [AllowNull()][System.Collections.IEnumerable]$Findings = @(),
    [string]$Title = 'Findings Summary',
    [int]$Width = $script:UiDefaults.SectionWidth
  )

  $findingsList = @()
  if ($null -ne $Findings) { $findingsList = @($Findings) }

  $stats = Console\Get-FindingStats -Findings $findingsList
  $counts = [ordered]@{
    Critical = $stats.Critical
    High     = $stats.High
    Error    = $stats.Error
    Medium   = $stats.Medium
    Low      = $stats.Low
    Info     = $stats.Info
    Skipped  = $stats.Skip
    Debug    = $stats.Debug
    OK       = $stats.OK
  }

  Write-Section -Title $Title -Width $Width
  $total = $findingsList.Count
  $totalStyle = if ($counts.Critical -gt 0 -or $counts.High -gt 0 -or $counts.Error -gt 0) { 'Error' }
                elseif ($counts.Medium -gt 0) { 'Warn' }
                elseif ($total -eq 0 -or $counts.OK -gt 0) { 'Success' }
                else { 'Info' }

  Write-KeyValue -Key 'Total findings' -Value ([string]$total) -ValueStyle $totalStyle
  if ($counts.Critical -gt 0) { Write-KeyValue -Key '  Critical' -Value ([string]$counts.Critical) -ValueStyle 'Error' }
  if ($counts.High -gt 0)     { Write-KeyValue -Key '  High'     -Value ([string]$counts.High)     -ValueStyle 'Error' }
  if ($counts.Error -gt 0)    { Write-KeyValue -Key '  Error'    -Value ([string]$counts.Error)    -ValueStyle 'Error' }
  if ($counts.Medium -gt 0)   { Write-KeyValue -Key '  Medium'   -Value ([string]$counts.Medium)   -ValueStyle 'Warn' }
  if ($counts.Low -gt 0)      { Write-KeyValue -Key '  Low'      -Value ([string]$counts.Low)      -ValueStyle 'Info' }
  if ($counts.Info -gt 0)     { Write-KeyValue -Key '  Info'     -Value ([string]$counts.Info)     -ValueStyle 'Muted' }
  if ($counts.Skipped -gt 0)  { Write-KeyValue -Key '  Skipped'  -Value ([string]$counts.Skipped)  -ValueStyle 'Muted' }
  if ($counts.Debug -gt 0)    { Write-KeyValue -Key '  Debug'    -Value ([string]$counts.Debug)    -ValueStyle 'Muted' }
  if ($counts.OK -gt 0)       { Write-KeyValue -Key '  OK'       -Value ([string]$counts.OK)       -ValueStyle 'Success' }

  $overallResult = if ($counts.Critical -gt 0 -or $counts.High -gt 0 -or $counts.Error -gt 0) { 'FAIL' }
                   elseif ($counts.Medium -gt 0) { 'WARN' }
                   else { 'PASS' }
  $resultStyle = if ($overallResult -eq 'FAIL') { 'Error' }
                 elseif ($overallResult -eq 'WARN') { 'Warn' }
                 else { 'Success' }
  Write-KeyValue -Key 'Overall result' -Value $overallResult -ValueStyle $resultStyle
  Write-UiLine -Message ('=' * $Width) -Style 'Dim'
}

Set-Alias -Name Write-UiSection -Value Write-Section -WhatIf:$false
Set-Alias -Name Write-ColorLine -Value Write-UiLine -WhatIf:$false
Set-Alias -Name Write-InfoLine -Value Write-Info -WhatIf:$false
Set-Alias -Name Write-WarnLine -Value Write-Warn -WhatIf:$false

$script:OutputExportedFunctions = @(
  'Write-UiLine'
  'Write-ConsoleLine'
  'Write-ConsoleHeader'
  'Write-Section'
  'Write-BlankLine'
  'Write-Info'
  'Write-Warn'
  'Write-ErrorLine'
  'Write-Success'
  'Write-StatusLine'
  'Write-UiRule'
  'Write-UiHeader'
  'Write-UiSeparator'
  'Write-KeyValue'
  'Write-UiStatus'
  'Write-UiBullet'
  'Write-UiList'
  'Write-UiBlankLine'
  'Write-UiBool'
  'Write-ConsoleBanner'
  'Write-ConsoleInfo'
  'Write-ConsoleList'
  'Write-UiSummaryTable'
)

$script:OutputExportedAliases = @(
  'Write-UiSection'
  'Write-ColorLine'
  'Write-InfoLine'
  'Write-WarnLine'
)

Export-ModuleMember -Function $script:OutputExportedFunctions -Alias $script:OutputExportedAliases
