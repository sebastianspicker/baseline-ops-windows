Set-StrictMode -Version Latest

<#
.SYNOPSIS
Console UI output functions for human-readable script output.

.DESCRIPTION
Provides a unified set of Write-* functions for colored console output, section
headers, key-value displays, status lines, and bullet lists. All functions
respect the caller-scope NoColor, Quiet, and NoConsole switches.
#>

$script:UiDefaults = [ordered]@{
  SectionWidth = 70
  KeyWidth     = 22
  PrefixWidth  = 7
}

function Get-CallerSwitchValue {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Name,
    [bool]$Default = $false
  )

  foreach ($scope in 1..3) {
    try {
      $var = Get-Variable -Name $Name -Scope $scope -ErrorAction Stop
      return [bool]$var.Value
    } catch {
      # continue
    }
  }
  return $Default
}

function Resolve-UiColor {
  [CmdletBinding()]
  param([object]$Style)

  if ($null -eq $Style) { return $null }
  if ($Style -is [ConsoleColor]) { return $Style }

  $s = [string]$Style
  if ([string]::IsNullOrWhiteSpace($s)) { return $null }

  $name = $s.Trim()
  switch -Regex ($name) {
    '^Default$' { return $null }
    '^(Info|Note|Key)$' { return [ConsoleColor]::Gray }
    '^(Value|Accent)$' { return [ConsoleColor]::White }
    '^(Ok|Good|Success|Pass)$' { return [ConsoleColor]::Green }
    '^(Warn|Warning|Drift|Changed)$' { return [ConsoleColor]::Yellow }
    '^(Err|Error|Bad|Fail|Failure|Danger)$' { return [ConsoleColor]::Red }
    '^(Dim|Muted)$' { return [ConsoleColor]::DarkGray }
    '^(Header|Title|Section)$' { return [ConsoleColor]::Cyan }
    default {
      $lower = $name.ToLowerInvariant()
      switch ($lower) {
        'cyan' { return [ConsoleColor]::Cyan }
        'darkcyan' { return [ConsoleColor]::Cyan }
        'darkyellow' { return [ConsoleColor]::Yellow }
        'yellow' { return [ConsoleColor]::Yellow }
        'darkgreen' { return [ConsoleColor]::Green }
        'green' { return [ConsoleColor]::Green }
        'darkred' { return [ConsoleColor]::Red }
        'red' { return [ConsoleColor]::Red }
        'darkgray' { return [ConsoleColor]::DarkGray }
        'darkgrey' { return [ConsoleColor]::DarkGray }
        'gray' { return [ConsoleColor]::Gray }
        'grey' { return [ConsoleColor]::Gray }
        'white' { return [ConsoleColor]::White }
        default {
          try { return [ConsoleColor]::$name } catch { return $null }
        }
      }
    }
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
    $NoConsole = Get-CallerSwitchValue -Name 'NoConsole'
  }
  if (-not $PSBoundParameters.ContainsKey('Quiet')) {
    $Quiet = Get-CallerSwitchValue -Name 'Quiet'
  }
  if ($NoConsole -or $Quiet) { return }

  $useInfo = $UseWriteInformation -or $UseInformationStream
  if (-not $PSBoundParameters.ContainsKey('UseWriteInformation') -and -not $PSBoundParameters.ContainsKey('UseInformationStream')) {
    $useInfo = Get-CallerSwitchValue -Name 'UseWriteInformation'
    if (-not $useInfo) { $useInfo = Get-CallerSwitchValue -Name 'UseInformationStream' }
  }

  if ($useInfo) {
    if ([string]::IsNullOrEmpty($Message)) {
      Write-Host ''
      return
    }
    Write-Information -MessageData $Message -InformationAction Continue
    return
  }

  if (-not $PSBoundParameters.ContainsKey('NoColor')) {
    $NoColor = Get-CallerSwitchValue -Name 'NoColor'
  }
  if (-not $NoColor) {
    $callerUseColor = Get-CallerSwitchValue -Name 'UseColor' -Default $true
    if (-not $callerUseColor) { $NoColor = $true }
  }

  $fg = if ($NoColor) { $null } else { Resolve-UiColor -Style $Style }
  if ($null -ne $fg) {
    Write-Host $Message -ForegroundColor $fg -NoNewline:$NoNewLine
  } else {
    Write-Host $Message -NoNewline:$NoNewLine
  }
}

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

  if ($Config -and $Config.PSObject.Properties['ConsoleUseInformation'] -and [bool]$Config.ConsoleUseInformation) {
    Write-UiLine -Message $Message -Style $Style -NoNewLine:$NoNewLine -UseWriteInformation
    return
  }

  if (-not $PSBoundParameters.ContainsKey('NoConsole')) {
    $NoConsole = Get-CallerSwitchValue -Name 'NoConsole'
  }
  if (-not $PSBoundParameters.ContainsKey('Quiet')) {
    $Quiet = Get-CallerSwitchValue -Name 'Quiet'
  }
  if ($NoConsole -or $Quiet) { return }

  if (-not $PSBoundParameters.ContainsKey('NoColor')) {
    $NoColor = Get-CallerSwitchValue -Name 'NoColor'
  }
  if (-not $NoColor) {
    $callerUseColor = Get-CallerSwitchValue -Name 'UseColor' -Default $true
    if (-not $callerUseColor) { $NoColor = $true }
  }

  $fg = if ($NoColor) { $null } else { Resolve-UiColor -Style $Style }
  if ($null -ne $fg) {
    Write-Host $Message -ForegroundColor $fg -NoNewline:$NoNewLine
  } else {
    Write-Host $Message -NoNewline:$NoNewLine
  }
}

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

function Resolve-StatusStyle {
  [CmdletBinding()]
  param([Parameter(Mandatory)][string]$Status)

  switch -Regex ($Status) {
    '^(OK|Pass|Passed|Good)$' { return 'Success' }
    '^(Warn|Warning|Drift|Changed)$' { return 'Warn' }
    '^(Fail|Failed|Error|Err|Critical)$' { return 'Error' }
    '^(Info|Note)$' { return 'Info' }
    '^(Skip|Skipped)$' { return 'Muted' }
    default { return 'Info' }
  }
}

function Get-StatusPrefix {
  [CmdletBinding()]
  param([Parameter(Mandatory)][string]$Status)

  switch -Regex ($Status) {
    '^(OK|Pass|Passed|Good)$' { return '[OK]   ' }
    '^(Warn|Warning|Drift|Changed)$' { return '[WARN] ' }
    '^(Fail|Failed|Error|Err|Critical)$' { return '[FAIL] ' }
    '^(Info|Note)$' { return '[INFO] ' }
    '^(Skip|Skipped)$' { return '[SKIP] ' }
    default { return '[INFO] ' }
  }
}

function Write-BlankLine {
  [CmdletBinding()]
  param()
  Write-UiLine -Message ''
}

function Write-Info {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][AllowEmptyString()][string]$Message,
    [switch]$NoPrefix
  )
  $text = if ($NoPrefix) { $Message } else { (Get-StatusPrefix -Status 'Info') + $Message }
  Write-UiLine -Message $text -Style 'Info'
}

function Write-Warn {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][AllowEmptyString()][string]$Message,
    [switch]$NoPrefix
  )
  $text = if ($NoPrefix) { $Message } else { (Get-StatusPrefix -Status 'Warn') + $Message }
  Write-UiLine -Message $text -Style 'Warn'
}

function Write-ErrorLine {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][AllowEmptyString()][string]$Message,
    [switch]$NoPrefix
  )
  $text = if ($NoPrefix) { $Message } else { (Get-StatusPrefix -Status 'Fail') + $Message }
  Write-UiLine -Message $text -Style 'Error'
}

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

function Write-UiSection {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Title,
    [int]$Width = $script:UiDefaults.SectionWidth
  )
  Write-Section -Title $Title -Width $Width
}

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
    [int]$KeyWidth = $script:UiDefaults.KeyWidth,
    [Alias('KeyColor')][object]$KeyStyle = 'Muted',
    [Alias('ValueColor','ValueRole')][object]$ValueStyle = 'Info',
    [int]$Indent = 0,
    [string]$EmptyValueText = '(empty)'
  )

  $prefix = if ($Indent -gt 0) { ' ' * $Indent } else { '' }
  $valueText = if ([string]::IsNullOrWhiteSpace($Value)) { $EmptyValueText } else { $Value }

  $useInfo = Get-CallerSwitchValue -Name 'UseWriteInformation' -Default $false
  if (-not $useInfo) { $useInfo = Get-CallerSwitchValue -Name 'UseInformationStream' -Default $false }

  if ($useInfo) {
    $line = $prefix + ("{0,-$KeyWidth}: {1}" -f $Key, $valueText)
    Write-UiLine -Message $line -Style $ValueStyle -UseWriteInformation
    return
  }

  Write-ConsoleLine -Message ($prefix + ("{0,-$KeyWidth}: " -f $Key)) -Style $KeyStyle -NoNewLine
  Write-ConsoleLine -Message $valueText -Style $ValueStyle
}

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

function Write-UiBullet {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][AllowEmptyString()][string]$Text,
    [object]$Style = 'Info'
  )
  Write-UiLine -Message ("  - " + $Text) -Style $Style
}

function Write-UiList {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][AllowEmptyString()][string[]]$Items,
    [object]$Style = 'Info'
  )
  foreach ($item in @($Items)) {
    Write-UiLine -Message ("  - " + $item) -Style $Style
  }
}

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

function Write-UiBool {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Key,
    [Parameter(Mandatory)][bool]$Value
  )
  $style = if ($Value) { 'Success' } else { 'Muted' }
  Write-KeyValue -Key $Key -Value $Value -ValueStyle $style
}

function Write-ColorLine {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][AllowEmptyString()][string]$Text,
    [object]$Color = 'Info',
    [switch]$NoNewLine
  )
  Write-UiLine -Message $Text -Style $Color -NoNewLine:$NoNewLine
}

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

function Write-ConsoleInfo {
  [CmdletBinding()]
  param([Parameter(Mandatory)][AllowEmptyString()][string]$Message)
  Write-UiLine -Message $Message -Style 'Info' -UseWriteInformation
}

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

function Write-Rule {
  [CmdletBinding()]
  param(
    [string]$Title,
    [object]$Color = 'Header'
  )
  Write-UiRule -Title $Title -Style $Color
}

function Write-ConsoleRule {
  [CmdletBinding()]
  param(
    [string]$Title,
    [object]$Color = 'Header'
  )
  Write-UiRule -Title $Title -Style $Color
}

function Write-ConsoleSeparator {
  [CmdletBinding()]
  param(
    [string]$Char = '-',
    [int]$Width = $script:UiDefaults.SectionWidth,
    [object]$Color = 'Dim'
  )
  Write-UiSeparator -Char $Char -Width $Width -Style $Color
}

function Write-InfoLine {
  [CmdletBinding()]
  param([Parameter(Mandatory)][AllowEmptyString()][string]$Message)
  Write-Info -Message $Message
}

function Write-Title {
  [CmdletBinding()]
  param([Parameter(Mandatory)][AllowEmptyString()][string]$Text)
  Write-UiLine -Message $Text -Style 'Header'
}

function Write-Good {
  [CmdletBinding()]
  param([Parameter(Mandatory)][AllowEmptyString()][string]$Text)
  Write-UiLine -Message $Text -Style 'Success'
}

function Write-Bad {
  [CmdletBinding()]
  param([Parameter(Mandatory)][AllowEmptyString()][string]$Text)
  Write-UiLine -Message $Text -Style 'Error'
}

function Write-WarnLine {
  [CmdletBinding()]
  param([Parameter(Mandatory)][AllowEmptyString()][string]$Message)
  Write-Warn -Message $Message
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

  $counts = [ordered]@{ Critical = 0; High = 0; Medium = 0; Low = 0; Info = 0; OK = 0 }
  foreach ($f in $findingsList) {
    $sev = if ($f.PSObject.Properties['Severity']) { $f.Severity } else { 'Info' }
    switch -Regex ($sev) {
      '^(Critical|Crit)$' { $counts.Critical++; break }
      '^(High|Error|Err|Fail|Failed)$' { $counts.High++; break }
      '^(Medium|Warn|Warning|Drift)$' { $counts.Medium++; break }
      '^(Low)$' { $counts.Low++; break }
      '^(OK|Pass|Passed|Good|Success)$' { $counts.OK++; break }
      default { $counts.Info++ }
    }
  }

  Write-Section -Title $Title -Width $Width
  $total = $findingsList.Count
  $totalStyle = if ($counts.Critical -gt 0 -or $counts.High -gt 0) { 'Error' }
                elseif ($counts.Medium -gt 0) { 'Warn' }
                elseif ($total -eq 0 -or $counts.OK -gt 0) { 'Success' }
                else { 'Info' }

  Write-KeyValue -Key 'Total findings' -Value ([string]$total) -ValueStyle $totalStyle
  if ($counts.Critical -gt 0) { Write-KeyValue -Key '  Critical' -Value ([string]$counts.Critical) -ValueStyle 'Error' }
  if ($counts.High -gt 0)     { Write-KeyValue -Key '  High'     -Value ([string]$counts.High)     -ValueStyle 'Error' }
  if ($counts.Medium -gt 0)   { Write-KeyValue -Key '  Medium'   -Value ([string]$counts.Medium)   -ValueStyle 'Warn' }
  if ($counts.Low -gt 0)      { Write-KeyValue -Key '  Low'      -Value ([string]$counts.Low)      -ValueStyle 'Info' }
  if ($counts.Info -gt 0)     { Write-KeyValue -Key '  Info'     -Value ([string]$counts.Info)     -ValueStyle 'Muted' }
  if ($counts.OK -gt 0)       { Write-KeyValue -Key '  OK'       -Value ([string]$counts.OK)       -ValueStyle 'Success' }

  $overallResult = if ($counts.Critical -gt 0 -or $counts.High -gt 0) { 'FAIL' }
                   elseif ($counts.Medium -gt 0) { 'WARN' }
                   else { 'PASS' }
  $resultStyle = if ($overallResult -eq 'FAIL') { 'Error' }
                 elseif ($overallResult -eq 'WARN') { 'Warn' }
                 else { 'Success' }
  Write-KeyValue -Key 'Overall result' -Value $overallResult -ValueStyle $resultStyle
  Write-UiLine -Message ('=' * $Width) -Style 'Dim'
}

Export-ModuleMember -Function `
  Write-UiLine, `
  Write-ConsoleLine, `
  Write-ConsoleHeader, `
  Write-Section, `
  Write-BlankLine, `
  Write-Info, `
  Write-InfoLine, `
  Write-Warn, `
  Write-WarnLine, `
  Write-ErrorLine, `
  Write-Success, `
  Write-StatusLine, `
  Write-UiRule, `
  Write-UiHeader, `
  Write-UiSection, `
  Write-UiSeparator, `
  Write-KeyValue, `
  Write-UiStatus, `
  Write-UiBullet, `
  Write-UiList, `
  Write-UiBlankLine, `
  Write-UiBool, `
  Write-ColorLine, `
  Write-ConsoleBanner, `
  Write-ConsoleInfo, `
  Write-ConsoleList, `
  Write-Rule, `
  Write-ConsoleRule, `
  Write-ConsoleSeparator, `
  Write-Title, `
  Write-Good, `
  Write-Bad, `
  Write-UiProgress, `
  Write-UiSummaryTable
