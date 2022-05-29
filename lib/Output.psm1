Set-StrictMode -Version Latest

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

  switch ($s) {
    'Default' { return $null }
    'Info' { return [ConsoleColor]::Gray }
    'Ok' { return [ConsoleColor]::Green }
    'Good' { return [ConsoleColor]::Green }
    'Warn' { return [ConsoleColor]::Yellow }
    'Warning' { return [ConsoleColor]::Yellow }
    'Err' { return [ConsoleColor]::Red }
    'Error' { return [ConsoleColor]::Red }
    'Bad' { return [ConsoleColor]::Red }
    'Dim' { return [ConsoleColor]::DarkGray }
    'Muted' { return [ConsoleColor]::DarkGray }
    'Header' { return [ConsoleColor]::Cyan }
    'Title' { return [ConsoleColor]::Cyan }
    'Success' { return [ConsoleColor]::Green }
    'Danger' { return [ConsoleColor]::Red }
    default {
      try { return [ConsoleColor]::$s } catch { return $null }
    }
  }
}

function Write-UiLine {
  [CmdletBinding()]
  param(
    [Parameter(Position=0)][Alias('Text','Message')][AllowNull()][AllowEmptyString()][string]$Message = '',
    [Parameter(Position=1)][Alias('Color')][object]$Style,
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
    [Parameter(Position=0)][Alias('Text','Message')][AllowNull()][AllowEmptyString()][string]$Message = '',
    [Parameter(Position=1)][Alias('Color')][object]$Style,
    [switch]$NoNewLine,
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
    [int]$Width = 60
  )

  $line = ('=' * $Width)
  Write-ConsoleLine -Message $line -Style 'Dim'
  Write-ConsoleLine -Message $Title -Style 'Header'
  Write-ConsoleLine -Message $line -Style 'Dim'
}

function Write-ConsoleKV {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Key,
    [AllowEmptyString()][string]$Value,
    [object]$ValueColor
  )

  Write-ConsoleLine -Message ("{0}: " -f $Key) -Style 'Dim' -NoNewLine
  Write-ConsoleLine -Message ("" + $Value) -Style $ValueColor
}

function Write-Section {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Title,
    [int]$Width = 70
  )

  $line = ('=' * $Width)
  Write-ConsoleLine -Message $line -Style 'Dim'
  Write-ConsoleLine -Message $Title -Style 'Header'
  Write-ConsoleLine -Message $line -Style 'Dim'
}

Export-ModuleMember -Function Write-UiLine,Write-ConsoleLine,Write-ConsoleHeader,Write-ConsoleKV,Write-Section
