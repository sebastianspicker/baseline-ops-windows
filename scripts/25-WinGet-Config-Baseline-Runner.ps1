#requires -version 5.1
<#
.SYNOPSIS
Runs WinGet Configuration "validate", "test" and (optionally) "apply" with preflight checks, optional logging,
a human-friendly console summary, and a reliable process exit code (PowerShell 5.1).

.DESCRIPTION
Best-practice output model:
- Pipeline output: structured objects only (safe for Export-Csv / ConvertTo-Json / Where-Object).
- Console output: all separators/pretty formatting via Write-UiLine / Write-Information only. [web:61]

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


.PARAMETER Mode
  Execution mode. 'Audit' reports only; 'Remediate' applies changes.

.PARAMETER OutputFormat
  Output format: Console, Json, Csv, or None.

.PARAMETER OutputPath
  File path for Json/Csv output.

.PARAMETER Strict
  Treat warnings as failures.

.PARAMETER Quiet
  Suppress console output.

.PARAMETER NoColor
  Disable colored output.


.OUTPUTS
  None by default.
  When -PassThru is used, emits a PSCustomObject v2 result with Script, Mode, Result, Findings, Summary, and Metadata properties.

.EXAMPLE
  .\25-WinGet-Config-Baseline-Runner.ps1

#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
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

,
  [ValidateSet('Audit','Remediate')][string]$Mode = 'Audit',
  [ValidateSet('Console','Json','Csv','None')][string]$OutputFormat = 'Console',
  [string]$OutputPath,
  [switch]$Strict,
  [switch]$Quiet,
  [switch]$NoColor
)

. (Join-Path $PSScriptRoot '_lib/Bootstrap.ps1')
Import-Module (Join-Path $script:LibPath 'Output.psm1') -Force
Import-Module (Join-Path $script:LibPath 'Config.psm1') -Force
Import-Module (Join-Path $script:LibPath 'Results.psm1') -Force
Import-Module (Join-Path $script:LibPath Serialization.psm1) -Force


Set-StrictMode -Version Latest
# v2-init
$null = $Mode, $ConfigPath, $OutputFormat, $OutputPath, $PassThru, $Strict, $Quiet, $NoColor
$script:__V2Context = @{
  Mode = $Mode
  ConfigPath = $ConfigPath
  OutputFormat = $OutputFormat
  OutputPath = $OutputPath
  PassThru = [bool]$PassThru
  Strict = [bool]$Strict
  Quiet = [bool]$Quiet
  NoColor = [bool]$NoColor
}
if ($PSBoundParameters.ContainsKey('Mode')) {
  if (Get-Variable -Name Remediate -ErrorAction SilentlyContinue) {
    Set-Variable -Name Remediate -Scope Script -Value ($Mode -eq 'Remediate')
  }
}
if ($Quiet) {
  $InformationPreference = 'SilentlyContinue'
  $VerbosePreference = 'SilentlyContinue'
}
if ($NoColor) {
  $script:NoColor = $true
}
$ErrorActionPreference = 'Stop'

$isWindowsHost = ($env:OS -eq 'Windows_NT')
if (-not $isWindowsHost) {
  $summary = [pscustomobject]@{
    ComputerName = $env:COMPUTERNAME
    Timestamp    = Get-Date
    Mode         = $Mode
    Supported    = $false
    Notes        = @('Skipped: this script is only supported on Windows hosts.')
  }
  $result = New-V2ResultObject -ScriptName '25-WinGet-Config-Baseline-Runner.ps1' -Mode $Mode -Result 'OK' -Findings @() -Summary $summary -Metadata @{ UnsupportedHost = $true }
  Write-ResultObject -ResultObject $result -OutputFormat $OutputFormat -OutputPath $OutputPath
  if ($PassThru) { $result }
  exit 0
}

# C10: canonical findings list
$script:Findings = New-FindingsList

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

function Invoke-WinGetConsoleSummary {
  param([Parameter(Mandatory = $true)][pscustomobject]$Summary)

  if ($Summary.QuietConsole) { return }

  $fields = [ordered]@{
    TestOnly             = [string]$Summary.TestOnly
    AcceptAgreements     = [string]$Summary.AcceptAgreements
    DisableInteractivity = [string]$Summary.DisableInteractivity
    FailFast             = [string]$Summary.FailFast
    FinalExitCode        = [string]$Summary.FinalExitCode
  }
  if ($Summary.ErrorMessage) { $fields['ErrorMessage'] = $Summary.ErrorMessage }

  Write-ConsoleSummary -Summary $Summary -Findings ([System.Collections.ArrayList]::new()) -CustomFields $fields

  # Phases list
  if ($Summary.Results -and $Summary.Results.Count -gt 0) {
    Write-UiLine ''
    Write-Title 'Phases'
    foreach ($r in $Summary.Results) {
      $line = ("- {0,-8} ExitCode={1,-5} DurationS={2,-8}" -f $r.Phase, $r.ExitCode, $r.DurationS)
      if ($r.ExitCode -eq 0) { Write-Good $line } else { Write-Bad $line }
    }
  } else {
    Write-UiLine ''
    Write-Title 'Phases'
    Write-Warn "- (no phases executed)"
  }
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
    Write-UiLine "Hint: Provide -ConfigPath 'PATH/TO/config.dsc.yaml' or set 'ConfigPath' in PATH/TO/JSON." -Style 'Warning'
  }

  $safeResults = $Results
  if (-not $safeResults) { $safeResults = New-Object System.Collections.Generic.List[object] }

  $summary = New-SummaryObject -ConfigPathResolved $ConfigPathResolved -Results $safeResults -FinalExitCode $ExitCode `
    -TestOnlyEffective $TestOnlyEffective -AcceptAgreementsEffective $AcceptAgreementsEffective -DisableInteractivityEffective $DisableInteractivityEffective `
    -FailFastEffective $FailFastEffective -PassThruEffective $PassThruEffective -QuietConsoleEffective $QuietConsoleEffective `
    -LogPathEffective $LogPathEffective -SummaryJsonPathEffective $SummaryJsonPathEffective -ExtraArgsEffective $ExtraArgsEffective -ErrorMessage $Message

  Invoke-WinGetConsoleSummary -Summary $summary

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

# S12 fix: validate ExtraArgs against a blocklist of dangerous winget flags
if ($ExtraArgsEffective -and $ExtraArgsEffective.Count -gt 0) {
  $blockedFlags = @('--override', '--custom', '--ignore-security-hash', '--location',
                     '--log', '-o', '-h', '--header', '--authentication-account',
                     '--authentication-mode')
  foreach ($arg in $ExtraArgsEffective) {
    $argStr = [string]$arg
    # Block shell metacharacters
    if ($argStr -match '[;&|`$(){}<>]') {
      throw "ExtraArgs contains shell metacharacters: '$argStr'. Aborting."
    }
    # Block dangerous flags (case-insensitive, matching the flag portion before any '=' or space)
    $flagPart = ($argStr -split '[= ]', 2)[0]
    foreach ($blocked in $blockedFlags) {
      if ($flagPart -ieq $blocked) {
        throw "ExtraArgs contains blocked flag '$argStr'. The flag '$blocked' is not allowed for safety reasons."
      }
    }
  }
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
  Invoke-WinGetConsoleSummary -Summary $summary
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
  Invoke-WinGetConsoleSummary -Summary $summary
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

Invoke-WinGetConsoleSummary -Summary $summary

# C10: populate findings from phase results
foreach ($phaseResult in @($results.ToArray())) {
  if ($phaseResult.ExitCode -ne 0) {
    $sev = if ($phaseResult.Phase -eq 'apply') { 'High' } else { 'Medium' }
    Add-Finding -FindingList $script:Findings -Code ("WINGET-{0}Failed" -f $phaseResult.Phase) -Severity $sev `
      -Message ("WinGet phase '{0}' failed with exit code {1}" -f $phaseResult.Phase, $phaseResult.ExitCode) `
      -Extra @{ Phase = $phaseResult.Phase; ExitCode = $phaseResult.ExitCode; DurationS = $phaseResult.DurationS }
  }
}

# V2 output contract
$resultToken = if ($finalExitCode -ne 0) { 'FAIL' } else { 'OK' }
$v2Result = New-V2ResultObject -ScriptName '25-WinGet-Config-Baseline-Runner.ps1' -Mode $Mode -Result $resultToken -Findings @($script:Findings) -Summary $summary -Metadata @{}
Write-ResultObject -ResultObject $v2Result -OutputFormat $OutputFormat -OutputPath $OutputPath
if ($PassThru) { $v2Result }
exit $finalExitCode




