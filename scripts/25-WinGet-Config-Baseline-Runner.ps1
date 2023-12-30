#requires -version 5.1
<#
.SYNOPSIS
Runs WinGet Configuration "validate", "test" and (optionally) "apply" with preflight checks, optional logging,
a human-friendly console summary, and a reliable process exit code (PowerShell 5.1).

.DESCRIPTION
Best-practice output model:
- Pipeline output: structured objects only (safe for Export-Csv / ConvertTo-Json / Where-Object).
- Console output: all separators/pretty formatting via Write-Host / Write-Information only. [web:61]

JSON sidecar (optional):
- If -SummaryJsonPath is not provided, the script tries:
  PATH/TO/SCRIPT/25-WinGet-Config-Baseline-Runner.json
- If JSON is missing or invalid, internal defaults are used.

.PARAMETER ConfigPath
Path to a WinGet configuration file (.yaml/.yml/.json).

.PARAMETER TestOnly
Run validate/test only; skip apply.

.PARAMETER AcceptAgreements
Auto-accept source/package agreements when running WinGet.

.PARAMETER LogPath
Optional log file path for command output.

.PARAMETER DisableInteractivity
Run WinGet in non-interactive mode.

.PARAMETER FailFast
Stop on first failing command.

.PARAMETER PassThru
Return structured objects to the pipeline.

.PARAMETER SummaryJsonPath
Optional JSON path for summary settings/overrides.

.PARAMETER QuietConsole
Suppress console summary output.

.PARAMETER ExtraArgs
Additional raw arguments passed to WinGet (alias: Args).

.EXAMPLE
  .\25-WinGet-Config-Baseline-Runner.ps1

#>

[CmdletBinding()]
param(
  [Parameter(Mandatory = $false)]
  [string]$ConfigPath,

  [switch]$TestOnly,

  [bool]$AcceptAgreements = $true,

  [string]$LogPath,

  [switch]$DisableInteractivity,

  [switch]$FailFast,

  # Best practice: default is NO pipeline output. Use -PassThru when you want objects.
  [switch]$PassThru,

  [string]$SummaryJsonPath,

  [switch]$QuietConsole,

  [Alias('Args')]
  [string[]]$ExtraArgs
)

$script:LibPath = Join-Path $PSScriptRoot 'lib'
Import-Module (Join-Path $script:LibPath 'Config.psm1') -Force


Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Ensure-File {
  param([Parameter(Mandatory = $true)][string]$Path)
  if (-not (Test-Path -LiteralPath $Path)) { throw "File not found: $Path" }
}

function Ensure-Exe {
  param([Parameter(Mandatory = $true)][string]$Name)
  if (-not (Get-Command -Name $Name -ErrorAction SilentlyContinue)) {
    throw "Executable not found: $Name (is WinGet/App Installer installed and available?)"
  }
}

function Ensure-NotSystemContext {
  if ($env:USERNAME -eq 'SYSTEM') {
    throw "SYSTEM context detected: WinGet CLI is not supported; use Microsoft.WinGet.Client instead."
  }
}

function Ensure-LogDirectory {
  param([Parameter(Mandatory = $true)][string]$FilePath)
  $dir = Split-Path -Path $FilePath -Parent
  if ($dir -and -not (Test-Path -LiteralPath $dir)) {
    New-Item -Path $dir -ItemType Directory -Force | Out-Null
  }
}

function To-BoolOrDefault {
  param($Value, [Parameter(Mandatory = $true)][bool]$Default)

  if ($null -eq $Value) { return $Default }
  if ($Value -is [bool]) { return [bool]$Value }

  $s = [string]$Value
  if ([string]::IsNullOrWhiteSpace($s)) { return $Default }

  switch ($s.Trim().ToLowerInvariant()) {
    'true'  { return $true }
    'false' { return $false }
    '1'     { return $true }
    '0'     { return $false }
    default { return $Default }
  }
}

function To-StringOrNull {
  param($Value)
  if ($null -eq $Value) { return $null }
  $s = [string]$Value
  if ([string]::IsNullOrWhiteSpace($s)) { return $null }
  return $s
}

function Get-EffectiveSetting {
  param(
    [Parameter(Mandatory = $true)][string]$Name,
    [Parameter(Mandatory = $true)][hashtable]$Json,
    [AllowNull()] $DefaultValue
  )

  if ($PSBoundParameters.ContainsKey($Name)) {
    return (Get-Variable -Name $Name -ValueOnly)
  }
  if ($Json -and $Json.ContainsKey($Name)) { return $Json[$Name] }
  return $DefaultValue
}

function Write-Info {
  param([Parameter(Mandatory = $true)][string]$Message)
  Write-Information -MessageData $Message -InformationAction Continue  # [web:61]
}

function Write-Title { param([string]$Text) Write-Host $Text -ForegroundColor Cyan }
function Write-Good  { param([string]$Text) Write-Host $Text -ForegroundColor Green }
function Write-Warn  { param([string]$Text) Write-Host $Text -ForegroundColor Yellow }
function Write-Bad   { param([string]$Text) Write-Host $Text -ForegroundColor Red }

function Write-KeyValue {
  param(
    [Parameter(Mandatory = $true)][string]$Key,
    [AllowNull()][string]$Value,
    [System.ConsoleColor]$KeyColor = [System.ConsoleColor]::Gray,
    [System.ConsoleColor]$ValueColor = [System.ConsoleColor]::White
  )

  Write-Host ("{0,-22}: " -f $Key) -ForegroundColor $KeyColor -NoNewline
  if ([string]::IsNullOrWhiteSpace($Value)) {
    Write-Host "(empty)" -ForegroundColor DarkGray
  } else {
    Write-Host $Value -ForegroundColor $ValueColor
  }
}

function Get-BoolColor {
  param(
    [Parameter(Mandatory = $true)][bool]$Value,
    [System.ConsoleColor]$TrueColor = [System.ConsoleColor]::Green,
    [System.ConsoleColor]$FalseColor = [System.ConsoleColor]::Yellow
  )
  if ($Value) { return $TrueColor }
  return $FalseColor
}

function Invoke-WinGet {
  param(
    [Parameter(Mandatory = $true)][string[]]$ArgsWinget,
    [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$Phase,
    [string]$LogPathEffective
  )

  $started = Get-Date

  if ($LogPathEffective) {
    Ensure-LogDirectory -FilePath $LogPathEffective
    & winget.exe @ArgsWinget *>&1 | Tee-Object -FilePath $LogPathEffective -Append
  } else {
    & winget.exe @ArgsWinget
  }

  $code = [int]$LASTEXITCODE
  $ended = Get-Date

  [pscustomobject]@{
    Phase     = $Phase
    ExitCode  = $code
    Started   = $started
    Ended     = $ended
    DurationS = [math]::Round((New-TimeSpan -Start $started -End $ended).TotalSeconds, 3)
    Args      = ($ArgsWinget -join ' ')
  }
}

function New-SummaryObject {
  param(
    [string]$ConfigPathResolved,
    [System.Collections.Generic.List[object]]$Results,
    [int]$FinalExitCode,
    [bool]$TestOnlyEffective,
    [bool]$AcceptAgreementsEffective,
    [bool]$DisableInteractivityEffective,
    [bool]$FailFastEffective,
    [bool]$PassThruEffective,
    [bool]$QuietConsoleEffective,
    [string]$LogPathEffective,
    [string]$SummaryJsonPathEffective,
    [string[]]$ExtraArgsEffective,
    [string]$ErrorMessage
  )

  [pscustomobject]@{
    ComputerName         = $env:COMPUTERNAME
    ConfigPath           = $ConfigPathResolved
    TestOnly             = $TestOnlyEffective
    AcceptAgreements     = $AcceptAgreementsEffective
    DisableInteractivity = $DisableInteractivityEffective
    FailFast             = $FailFastEffective
    PassThru             = $PassThruEffective
    QuietConsole         = $QuietConsoleEffective
    SummaryJsonPath      = (To-StringOrNull $SummaryJsonPathEffective)
    LogPath              = $LogPathEffective
    ExtraArgs            = @($ExtraArgsEffective)
    Timestamp            = Get-Date
    Results              = @($Results.ToArray())
    FinalExitCode        = $FinalExitCode
    ErrorMessage         = (To-StringOrNull $ErrorMessage)
  }
}

function Write-ConsoleSummary {
  param([Parameter(Mandatory = $true)][pscustomobject]$Summary)

  if ($Summary.QuietConsole) { return }

  $colorTestOnly   = Get-BoolColor -Value $Summary.TestOnly -TrueColor Yellow -FalseColor White
  $colorAccept     = Get-BoolColor -Value $Summary.AcceptAgreements -TrueColor Green -FalseColor Yellow
  $colorNoInteract = Get-BoolColor -Value $Summary.DisableInteractivity -TrueColor Green -FalseColor Yellow
  $colorFailFast   = Get-BoolColor -Value $Summary.FailFast -TrueColor Yellow -FalseColor White

  Write-Host ''
  Write-Title '=== WinGet Configuration Summary ==='

  Write-KeyValue -Key 'ComputerName'    -Value $Summary.ComputerName
  Write-KeyValue -Key 'ConfigPath'      -Value $Summary.ConfigPath
  Write-KeyValue -Key 'SummaryJsonPath' -Value $Summary.SummaryJsonPath
  Write-KeyValue -Key 'LogPath'         -Value $Summary.LogPath
  Write-KeyValue -Key 'Timestamp'       -Value ($Summary.Timestamp.ToString('s'))

  Write-Host ''
  Write-KeyValue -Key 'TestOnly'             -Value ([string]$Summary.TestOnly)             -ValueColor $colorTestOnly
  Write-KeyValue -Key 'AcceptAgreements'     -Value ([string]$Summary.AcceptAgreements)     -ValueColor $colorAccept
  Write-KeyValue -Key 'DisableInteractivity' -Value ([string]$Summary.DisableInteractivity) -ValueColor $colorNoInteract
  Write-KeyValue -Key 'FailFast'             -Value ([string]$Summary.FailFast)             -ValueColor $colorFailFast

  Write-Host ''
  if ($Summary.ExtraArgs -and $Summary.ExtraArgs.Count -gt 0) {
    Write-KeyValue -Key 'ExtraArgs' -Value ($Summary.ExtraArgs -join ' ')
  } else {
    Write-KeyValue -Key 'ExtraArgs' -Value $null
  }

  if ($Summary.ErrorMessage) {
    Write-Host ''
    Write-Bad ("ERROR: {0}" -f $Summary.ErrorMessage)
  }

  Write-Host ''
  Write-Title 'Phases'
  if ($Summary.Results -and $Summary.Results.Count -gt 0) {
    foreach ($r in $Summary.Results) {
      $line = ("- {0,-8} ExitCode={1,-5} DurationS={2,-8}" -f $r.Phase, $r.ExitCode, $r.DurationS)
      if ($r.ExitCode -eq 0) { Write-Good $line } else { Write-Bad $line }
    }
  } else {
    Write-Warn "- (no phases executed)"
  }

  Write-Host ''
  if ($Summary.FinalExitCode -eq 0) { Write-Good ("FinalExitCode: {0}" -f $Summary.FinalExitCode) }
  else { Write-Bad ("FinalExitCode: {0}" -f $Summary.FinalExitCode) }

  Write-Title '==================================='
  Write-Host ''
}

function Stop-UserFriendly {
  param(
    [Parameter(Mandatory = $true)][string]$Message,
    [Parameter(Mandatory = $true)][int]$ExitCode,
    [System.Collections.Generic.List[object]]$Results,
    [string]$ConfigPathResolved,
    [bool]$TestOnlyEffective,
    [bool]$AcceptAgreementsEffective,
    [bool]$DisableInteractivityEffective,
    [bool]$FailFastEffective,
    [bool]$PassThruEffective,
    [bool]$QuietConsoleEffective,
    [string]$LogPathEffective,
    [string]$SummaryJsonPathEffective,
    [string[]]$ExtraArgsEffective
  )

  if (-not $QuietConsoleEffective) {
    Write-Bad ("ERROR: {0}" -f $Message)
    Write-Host "Hint: Provide -ConfigPath 'PATH/TO/config.dsc.yaml' or set 'ConfigPath' in PATH/TO/JSON." -ForegroundColor DarkYellow
  }

  $safeResults = $Results
  if (-not $safeResults) { $safeResults = New-Object System.Collections.Generic.List[object] }

  $summary = New-SummaryObject -ConfigPathResolved $ConfigPathResolved -Results $safeResults -FinalExitCode $ExitCode `
    -TestOnlyEffective $TestOnlyEffective -AcceptAgreementsEffective $AcceptAgreementsEffective -DisableInteractivityEffective $DisableInteractivityEffective `
    -FailFastEffective $FailFastEffective -PassThruEffective $PassThruEffective -QuietConsoleEffective $QuietConsoleEffective `
    -LogPathEffective $LogPathEffective -SummaryJsonPathEffective $SummaryJsonPathEffective -ExtraArgsEffective $ExtraArgsEffective -ErrorMessage $Message

  Write-ConsoleSummary -Summary $summary

  # Pipeline output only when explicitly requested via -PassThru (no "double output" by default).
  if ($PassThruEffective) { $summary }

  exit $ExitCode
}

# Defaults
$defaultSettings = @{
  ConfigPath           = $null
  LogPath              = $null
  AcceptAgreements     = $true
  DisableInteractivity = $true
  FailFast             = $false

  # IMPORTANT: default is no pipeline output
  PassThru             = $false

  TestOnly             = $false
  QuietConsole         = $false
  Args                 = @()
}

# Default JSON sidecar path
if (-not $PSBoundParameters.ContainsKey('SummaryJsonPath')) {
  $SummaryJsonPath = Join-Path -Path $PSScriptRoot -ChildPath '25-WinGet-Config-Baseline-Runner.json'
}

$cfgResult = Read-ConfigWithDefaults -Path $SummaryJsonPath -Defaults @{} -AsHashtable -ReturnNullWhenMissing -ReturnNullOnError
$jsonSettings = $cfgResult.Config
if (-not $jsonSettings) { $jsonSettings = @{} }

# Effective settings
$ConfigPathEffective = To-StringOrNull (Get-EffectiveSetting -Name 'ConfigPath' -Json $jsonSettings -DefaultValue $defaultSettings.ConfigPath)
if ($PSBoundParameters.ContainsKey('ConfigPath')) { $ConfigPathEffective = To-StringOrNull $ConfigPath }

$LogPathEffective = To-StringOrNull (Get-EffectiveSetting -Name 'LogPath' -Json $jsonSettings -DefaultValue $defaultSettings.LogPath)
if ($PSBoundParameters.ContainsKey('LogPath')) { $LogPathEffective = To-StringOrNull $LogPath }

$AcceptAgreementsEffective = To-BoolOrDefault (Get-EffectiveSetting -Name 'AcceptAgreements' -Json $jsonSettings -DefaultValue $defaultSettings.AcceptAgreements) -Default $defaultSettings.AcceptAgreements
if ($PSBoundParameters.ContainsKey('AcceptAgreements')) { $AcceptAgreementsEffective = [bool]$AcceptAgreements }

$DisableInteractivityEffective = To-BoolOrDefault (Get-EffectiveSetting -Name 'DisableInteractivity' -Json $jsonSettings -DefaultValue $defaultSettings.DisableInteractivity) -Default $defaultSettings.DisableInteractivity
if ($PSBoundParameters.ContainsKey('DisableInteractivity')) { $DisableInteractivityEffective = [bool]$DisableInteractivity }

$FailFastEffective = To-BoolOrDefault (Get-EffectiveSetting -Name 'FailFast' -Json $jsonSettings -DefaultValue $defaultSettings.FailFast) -Default $defaultSettings.FailFast
if ($PSBoundParameters.ContainsKey('FailFast')) { $FailFastEffective = [bool]$FailFast }

# PassThru can be enabled via JSON, but only if CLI didn't specify it.
$PassThruEffective = To-BoolOrDefault (Get-EffectiveSetting -Name 'PassThru' -Json $jsonSettings -DefaultValue $defaultSettings.PassThru) -Default $defaultSettings.PassThru
if ($PSBoundParameters.ContainsKey('PassThru')) { $PassThruEffective = [bool]$PassThru }

$TestOnlyEffective = To-BoolOrDefault (Get-EffectiveSetting -Name 'TestOnly' -Json $jsonSettings -DefaultValue $defaultSettings.TestOnly) -Default $defaultSettings.TestOnly
if ($PSBoundParameters.ContainsKey('TestOnly')) { $TestOnlyEffective = [bool]$TestOnly }

$QuietConsoleEffective = To-BoolOrDefault (Get-EffectiveSetting -Name 'QuietConsole' -Json $jsonSettings -DefaultValue $defaultSettings.QuietConsole) -Default $defaultSettings.QuietConsole
if ($PSBoundParameters.ContainsKey('QuietConsole')) { $QuietConsoleEffective = [bool]$QuietConsole }

# Extra args
$ExtraArgsEffective = @()
if ($PSBoundParameters.ContainsKey('Args') -and $ExtraArgs) { $ExtraArgsEffective = @($ExtraArgs) }
elseif ($jsonSettings.ContainsKey('Args')) {
  $j = $jsonSettings['Args']
  if ($j -is [string]) { $ExtraArgsEffective = @($j) }
  elseif ($j -is [System.Collections.IEnumerable]) { $ExtraArgsEffective = @($j) }
}

if ((-not $ExtraArgsEffective) -or ($ExtraArgsEffective.Count -eq 0)) {
  if (-not $QuietConsoleEffective) { Write-Info "Info: No extra -Args provided. Continuing without additional winget arguments." }
}

$results = New-Object System.Collections.Generic.List[object]

if ([string]::IsNullOrWhiteSpace($ConfigPathEffective)) {
  Stop-UserFriendly -Message "ConfigPath is missing. Provide -ConfigPath 'PATH/TO/config.dsc.yaml' or set 'ConfigPath' in PATH/TO/JSON." `
    -ExitCode 2 -Results $results -ConfigPathResolved $null -TestOnlyEffective $TestOnlyEffective -AcceptAgreementsEffective $AcceptAgreementsEffective `
    -DisableInteractivityEffective $DisableInteractivityEffective -FailFastEffective $FailFastEffective -PassThruEffective $PassThruEffective `
    -QuietConsoleEffective $QuietConsoleEffective -LogPathEffective $LogPathEffective -SummaryJsonPathEffective $SummaryJsonPath -ExtraArgsEffective $ExtraArgsEffective
}

Ensure-File -Path $ConfigPathEffective
Ensure-Exe  -Name 'winget.exe'
Ensure-NotSystemContext

$resolvedConfigPath = (Resolve-Path -LiteralPath $ConfigPathEffective).Path

$argsCommon = @('configure')
if ($AcceptAgreementsEffective)     { $argsCommon += '--accept-configuration-agreements' } # [web:3]
if ($DisableInteractivityEffective) { $argsCommon += '--disable-interactivity' }           # [web:3]
if ($ExtraArgsEffective -and $ExtraArgsEffective.Count -gt 0) { $argsCommon += $ExtraArgsEffective }

$argsValidate = @($argsCommon + @('validate', '-f', $resolvedConfigPath))
$argsTest     = @($argsCommon + @('test',     '-f', $resolvedConfigPath))
$argsApply    = @($argsCommon + @('-f', $resolvedConfigPath))

$rValidate = Invoke-WinGet -ArgsWinget $argsValidate -Phase 'validate' -LogPathEffective $LogPathEffective
$results.Add($rValidate) | Out-Null

if ($FailFastEffective -and $rValidate.ExitCode -ne 0) {
  $summary = New-SummaryObject -ConfigPathResolved $resolvedConfigPath -Results $results -FinalExitCode $rValidate.ExitCode `
    -TestOnlyEffective $TestOnlyEffective -AcceptAgreementsEffective $AcceptAgreementsEffective -DisableInteractivityEffective $DisableInteractivityEffective `
    -FailFastEffective $FailFastEffective -PassThruEffective $PassThruEffective -QuietConsoleEffective $QuietConsoleEffective `
    -LogPathEffective $LogPathEffective -SummaryJsonPathEffective $SummaryJsonPath -ExtraArgsEffective $ExtraArgsEffective -ErrorMessage "Validate failed."
  Write-ConsoleSummary -Summary $summary
  if ($PassThruEffective) { $summary }
  exit $summary.FinalExitCode
}

$rTest = Invoke-WinGet -ArgsWinget $argsTest -Phase 'test' -LogPathEffective $LogPathEffective
$results.Add($rTest) | Out-Null

if ($FailFastEffective -and $rTest.ExitCode -ne 0) {
  $summary = New-SummaryObject -ConfigPathResolved $resolvedConfigPath -Results $results -FinalExitCode $rTest.ExitCode `
    -TestOnlyEffective $TestOnlyEffective -AcceptAgreementsEffective $AcceptAgreementsEffective -DisableInteractivityEffective $DisableInteractivityEffective `
    -FailFastEffective $FailFastEffective -PassThruEffective $PassThruEffective -QuietConsoleEffective $QuietConsoleEffective `
    -LogPathEffective $LogPathEffective -SummaryJsonPathEffective $SummaryJsonPath -ExtraArgsEffective $ExtraArgsEffective -ErrorMessage "Test failed."
  Write-ConsoleSummary -Summary $summary
  if ($PassThruEffective) { $summary }
  exit $summary.FinalExitCode
}

$rApply = $null
if (-not $TestOnlyEffective) {
  $rApply = Invoke-WinGet -ArgsWinget $argsApply -Phase 'apply' -LogPathEffective $LogPathEffective
  $results.Add($rApply) | Out-Null
}

$finalExitCode = if (-not $TestOnlyEffective -and $rApply) { [int]$rApply.ExitCode } else { [int]$rTest.ExitCode }

$summary = New-SummaryObject -ConfigPathResolved $resolvedConfigPath -Results $results -FinalExitCode $finalExitCode `
  -TestOnlyEffective $TestOnlyEffective -AcceptAgreementsEffective $AcceptAgreementsEffective -DisableInteractivityEffective $DisableInteractivityEffective `
  -FailFastEffective $FailFastEffective -PassThruEffective $PassThruEffective -QuietConsoleEffective $QuietConsoleEffective `
  -LogPathEffective $LogPathEffective -SummaryJsonPathEffective $SummaryJsonPath -ExtraArgsEffective $ExtraArgsEffective `
  -ErrorMessage (if ($finalExitCode -ne 0) { "WinGet finished with a non-zero exit code." } else { $null })

Write-ConsoleSummary -Summary $summary
if ($PassThruEffective) { $summary }
exit $finalExitCode
