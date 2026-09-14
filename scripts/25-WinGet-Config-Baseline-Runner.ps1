#requires -version 5.1
<#
.SYNOPSIS
Runs WinGet Configuration "validate", "test" and (optionally) "apply" with preflight checks, optional logging,
a console summary, and a reliable process exit code (PowerShell 5.1).

.DESCRIPTION
Best-practice output model:
- Pipeline output: structured objects only (safe for Export-Csv / ConvertTo-Json / Where-Object).
- Console output: separators and formatting use Write-UiLine / Write-Information only.

JSON sidecar (optional):
- If -SummaryJsonPath is not provided, the script tries:
  $PSScriptRoot\25-WinGet-Config-Baseline-Runner.json
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

  [ValidateRange(1, 86400)]
  [int]$TimeoutSeconds = 300,

  [ValidateRange(1024, 10485760)]
  [int]$MaxOutputBytes = 1048576,

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
function Initialize-Capability25Runtime {
  param($EntryBoundParameters)
  $RunState = @{
    SummaryJsonPath = $SummaryJsonPath
  }
Import-Module (Join-Path $script:LibPath 'Output.psm1') -Force
Import-Module (Join-Path $script:LibPath 'Common.psm1') -Force -DisableNameChecking
Import-Module (Join-Path $script:LibPath 'Console.psm1') -Force
Import-Module (Join-Path $script:LibPath 'Config.psm1') -Force
Import-Module (Join-Path $script:LibPath 'External.psm1') -Force -DisableNameChecking
Import-Module (Join-Path $script:LibPath 'Results.psm1') -Force
Import-Module (Join-Path $script:LibPath Serialization.psm1) -Force
Import-Module (Join-Path $script:LibPath 'Validation.psm1') -Force
. (Join-Path $PSScriptRoot 'internal/25-WinGet-Config-Baseline-Runner.helpers.ps1')


Set-StrictMode -Version Latest
$script:__V2Context = Initialize-V2Context -ScriptName '25-WinGet-Config-Baseline-Runner.ps1' -BoundParameters $EntryBoundParameters `
  -Values @{ Mode = $Mode; ConfigPath = $ConfigPath; OutputFormat = $OutputFormat; OutputPath = $OutputPath; PassThru = $PassThru; Strict = $Strict; Quiet = $Quiet; NoColor = $NoColor; DeriveRemediate = $false }
if ($script:__V2Context.Quiet) { $InformationPreference = 'SilentlyContinue'; $VerbosePreference = 'SilentlyContinue' }
$script:NoColor = [bool]$script:__V2Context.NoColor
$ErrorActionPreference = 'Stop'

$RunState.isWindowsHost = ($env:OS -eq 'Windows_NT')
  $script:RunState = $RunState
}

. Initialize-Capability25Runtime -EntryBoundParameters $PSBoundParameters
function Get-Capability25UnsupportedState {
  param([hashtable]$RunState)
$summary = [pscustomobject]@{
  ComputerName = $env:COMPUTERNAME
  Timestamp    = Get-Date
  Mode         = $Mode
  Supported    = $false
  Notes        = @('Skipped: this script is only supported on Windows hosts.')
}
$RunState.unsupportedResult = if ($Strict) { 'FAIL' } else { 'WARN' }
$RunState.result = Get-V2ResultObject -ScriptName '25-WinGet-Config-Baseline-Runner.ps1' -Mode $Mode -Result $RunState.unsupportedResult -Findings @() -Summary $summary -Metadata @{ UnsupportedHost = $true }
  [pscustomobject]@{ Result = $RunState.result; Token = $RunState.unsupportedResult }
}
function Set-Capability25UnsupportedState {
  param([hashtable]$RunState)
  $unsupportedState = Get-Capability25UnsupportedState -RunState $RunState
  $RunState.result = $unsupportedState.Result
  $RunState.unsupportedResult = $unsupportedState.Token
}
if (-not $RunState.isWindowsHost) {
  . Set-Capability25UnsupportedState -RunState $RunState
  Write-ResultObject -ResultObject $RunState.result -OutputFormat $OutputFormat -OutputPath $OutputPath
  if ($PassThru) { $RunState.result }
  exit (Get-V2ExitCode -Result $RunState.unsupportedResult)
}

$script:Findings = Get-FindingsList

function Ensure-NotSystemContext {
  if ([System.Environment]::OSVersion.Platform -eq [System.PlatformID]::Win32NT) {
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    try {
      if ($identity.IsSystem) {
        throw "SYSTEM context detected: WinGet CLI is not supported; use Microsoft.WinGet.Client instead."
      }
    } finally {
      $identity.Dispose()
    }
  }
}

function Ensure-LogDirectory {
  param([Parameter(Mandatory = $true)][string]$FilePath)
  $dir = Split-Path -Path $FilePath -Parent
  if ($dir -and -not (Test-Path -LiteralPath $dir)) {
    New-Item -Path $dir -ItemType Directory -Force | Out-Null
  }
}

function Add-BoundedUtf8Log {
  [OutputType([bool])]
  param(
    [Parameter(Mandatory = $true)][string]$Path,
    [AllowEmptyString()][string]$Text,
    [Parameter(Mandatory = $true)][int]$MaximumBytes
  )

  Ensure-LogDirectory -FilePath $Path
  $stream = [System.IO.File]::Open($Path, [System.IO.FileMode]::OpenOrCreate, [System.IO.FileAccess]::Write, [System.IO.FileShare]::Read)
  try {
    $remaining = [math]::Max(0, $MaximumBytes - $stream.Length)
    if ($remaining -eq 0) { return (-not [string]::IsNullOrEmpty($Text)) }
    $encoding = New-Object System.Text.UTF8Encoding($false)
    $bytes = $encoding.GetBytes($Text)
    $truncated = ($bytes.Length -gt $remaining)
    if ($truncated) {
      $low = 0
      $high = $Text.Length
      while ($low -lt $high) {
        $mid = [int](($low + $high + 1) / 2)
        if ($encoding.GetByteCount($Text.Substring(0, $mid)) -le $remaining) { $low = $mid } else { $high = $mid - 1 }
      }
      $bytes = $encoding.GetBytes($Text.Substring(0, $low))
    }
    $stream.Position = $stream.Length
    if ($bytes.Length -gt 0) { $stream.Write($bytes, 0, $bytes.Length) }
    $stream.Flush($true)
    return $truncated
  } finally {
    $stream.Dispose()
  }
}

function Add-WinGetPhaseFindingsSection01 {
  param([hashtable]$RunState)
if ($RunState.PhaseResult.TimedOut) {
    [void](Add-Finding -FindingList $script:Findings -Code 'WINGET-Timeout' -Severity 'High' -Message ("WinGet phase '{0}' timed out." -f $RunState.PhaseResult.Phase) -Extra @{ Phase = $RunState.PhaseResult.Phase; DurationS = $RunState.PhaseResult.DurationS })
  }
  if ($RunState.PhaseResult.OutputTruncated -or $RunState.PhaseResult.StderrTruncated -or $RunState.PhaseResult.LogTruncated) {
    [void](Add-Finding -FindingList $script:Findings -Code 'WINGET-OutputTruncated' -Severity 'Medium' -Message ("WinGet phase '{0}' output was truncated; evidence is partial." -f $RunState.PhaseResult.Phase) -Extra @{ Phase = $RunState.PhaseResult.Phase })
  }
  if (-not [string]::IsNullOrWhiteSpace([string]$RunState.PhaseResult.LogError)) {
    [void](Add-Finding -FindingList $script:Findings -Code 'WINGET-LogFailed' -Severity 'Medium' `
        -Message ("WinGet phase '{0}' completed, but its requested log could not be written: {1}" -f $RunState.PhaseResult.Phase, $RunState.PhaseResult.LogError) `
        -Extra @{ Phase = $RunState.PhaseResult.Phase })
  }
}

function Add-WinGetPhaseFindingsSection02 {
  param([hashtable]$RunState)
if ($RunState.PhaseResult.ExitCode -ne 0) {
    $severity = if ($RunState.PhaseResult.Phase -eq 'apply') { 'High' } else { 'Medium' }
    [void](Add-Finding -FindingList $script:Findings -Code ("WINGET-{0}Failed" -f $RunState.PhaseResult.Phase) -Severity $severity `
        -Message ("WinGet phase '{0}' failed with exit code {1}" -f $RunState.PhaseResult.Phase, $RunState.PhaseResult.ExitCode) `
        -Extra @{ Phase = $RunState.PhaseResult.Phase; ExitCode = $RunState.PhaseResult.ExitCode; DurationS = $RunState.PhaseResult.DurationS })
  }
}

function Add-WinGetPhaseFindings {
  param([Parameter(Mandatory = $true)]$PhaseResult, [hashtable]$RunState)
  $RunState.PhaseResult = $PhaseResult

    . Add-WinGetPhaseFindingsSection01 -RunState $RunState
    . Add-WinGetPhaseFindingsSection02 -RunState $RunState
}

function Complete-WinGetStagingCleanup {
  [CmdletBinding()]
  param([AllowNull()]$StagedConfiguration)

  if ($null -eq $StagedConfiguration) {
    return [pscustomobject]@{ Succeeded = $true; Error = $null }
  }
  try {
    Remove-WinGetStagedConfiguration -StagedConfiguration $StagedConfiguration
    return [pscustomobject]@{ Succeeded = $true; Error = $null }
  } catch {
    $message = $_.Exception.Message
    if ($message.Length -gt 1024) { $message = $message.Substring(0, 1024) + '...' }
    [void](Add-Finding -FindingList $script:Findings -Code 'WINGET-StagingCleanupFailed' -Severity 'Medium' `
        -Message ("Protected WinGet staging cleanup failed: {0}" -f $message))
    return [pscustomobject]@{ Succeeded = $false; Error = $message }
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




function Invoke-WinGet {
  param(
    [Parameter(Mandatory = $true)][string[]]$ArgsWinget,
    [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$Phase,
    [string]$LogPathEffective,
    [int]$TimeoutSecondsEffective,
    [int]$MaxOutputBytesEffective
  )

  $started = Get-Date

  if ([string]::IsNullOrWhiteSpace($script:WingetExecutablePath)) {
    throw 'Trusted WinGet executable path is unavailable.'
  }
  $native = Invoke-NativeCommand -Command $script:WingetExecutablePath -Arguments $ArgsWinget -CaptureOutput -Quiet `
    -TimeoutSeconds $TimeoutSecondsEffective -MaxOutputBytes $MaxOutputBytesEffective
  if ($null -eq $native) {
    $native = [pscustomobject]@{ ExitCode = -1; Output = ''; Stdout = ''; Stderr = ''; TimedOut = $false; OutputTruncated = $false; StderrTruncated = $false }
  }
  $logTruncated = $false
  $logError = $null
  if ($LogPathEffective -and $native) {
    $logText = ([string]$native.Stdout + [string]$native.Stderr)
    try {
      $logTruncated = Add-BoundedUtf8Log -Path $LogPathEffective -Text $logText -MaximumBytes $MaxOutputBytesEffective
    } catch {
      $logError = $_.Exception.Message
      if ($logError.Length -gt 1024) { $logError = $logError.Substring(0, 1024) + '...' }
    }
  }
  $ended = Get-Date

  [pscustomobject]@{
    Phase     = $Phase
    ExitCode  = [int]$native.ExitCode
    Started   = $started
    Ended     = $ended
    DurationS = [math]::Round((New-TimeSpan -Start $started -End $ended).TotalSeconds, 3)
    Args      = ($ArgsWinget -join ' ')
    TimedOut  = [bool]$native.TimedOut
    OutputTruncated = [bool]$native.OutputTruncated
    StderrTruncated = [bool]$native.StderrTruncated
    LogTruncated = [bool]$logTruncated
    LogError   = $logError
  }
}

# Defaults
function Initialize-WinGetBaselineState {
  param([hashtable]$RunState)
  . Initialize-Capability25Defaults -RunState $RunState
  . Initialize-Capability25JsonSettings -RunState $RunState
  . Initialize-Capability25EffectiveSettings -RunState $RunState
  . Initialize-Capability25ExtraArgs -RunState $RunState
  . Initialize-Capability25RunState -RunState $RunState
}
function Initialize-Capability25Defaults {
  param([hashtable]$RunState)
  $RunState.defaultSettings = @{
    ConfigPath = $null
    LogPath = $null
    AcceptAgreements = $true
    DisableInteractivity = $true
    FailFast = $false
    PassThru = $false
    TestOnly = $false
    QuietConsole = $false
    Args = @()
  }
  if (-not $EntryBoundParameters.ContainsKey('SummaryJsonPath')) {
    $RunState.SummaryJsonPath = Join-Path -Path $PSScriptRoot -ChildPath '25-WinGet-Config-Baseline-Runner.json'
  }
}
function Initialize-Capability25JsonSettings {
  param([hashtable]$RunState)
  $cfgResult = Read-ConfigWithDefaults -Path $RunState.SummaryJsonPath -Defaults @{} -AsHashtable -ReturnNullWhenMissing -ReturnNullOnError
  $jsonSettings = $cfgResult.Config
  if ($cfgResult.Meta.Error) {
    [void](Add-Finding -FindingList $script:Findings -Code 'WINGET-ConfigLoadFailed' -Severity 'Medium' -Message ("Summary JSON could not be loaded; using defaults. Error: {0}" -f $cfgResult.Meta.Error))
  }
  if (-not $jsonSettings) { $jsonSettings = @{} }
}
function Get-Capability25EffectiveString {
  param([string]$Name, [AllowNull()]$ParameterValue, [hashtable]$RunState)
  if ($EntryBoundParameters.ContainsKey($Name)) { return To-StringOrNull $ParameterValue }
  return To-StringOrNull (Get-EffectiveSetting -Name $Name -Json $jsonSettings -DefaultValue $RunState.defaultSettings[$Name])
}
function Get-Capability25EffectiveBool {
  param([string]$Name, [bool]$ParameterValue, [hashtable]$RunState)
  if ($EntryBoundParameters.ContainsKey($Name)) { return $ParameterValue }
  return To-BoolOrDefault (Get-EffectiveSetting -Name $Name -Json $jsonSettings -DefaultValue $RunState.defaultSettings[$Name]) -Default $RunState.defaultSettings[$Name]
}
function Initialize-Capability25EffectiveSettings {
  param([hashtable]$RunState)
  $RunState.ConfigPathEffective = Get-Capability25EffectiveString -Name 'ConfigPath' -ParameterValue $ConfigPath -RunState $RunState
  $RunState.LogPathEffective = Get-Capability25EffectiveString -Name 'LogPath' -ParameterValue $LogPath -RunState $RunState
  $RunState.AcceptAgreementsEffective = Get-Capability25EffectiveBool -Name 'AcceptAgreements' -ParameterValue ([bool]$AcceptAgreements) -RunState $RunState
  $RunState.DisableInteractivityEffective = Get-Capability25EffectiveBool -Name 'DisableInteractivity' -ParameterValue ([bool]$DisableInteractivity) -RunState $RunState
  $RunState.FailFastEffective = Get-Capability25EffectiveBool -Name 'FailFast' -ParameterValue ([bool]$FailFast) -RunState $RunState
  $RunState.PassThruEffective = Get-Capability25EffectiveBool -Name 'PassThru' -ParameterValue ([bool]$PassThru) -RunState $RunState
  $RunState.TestOnlyEffective = Get-Capability25EffectiveBool -Name 'TestOnly' -ParameterValue ([bool]$TestOnly) -RunState $RunState
  if ($Mode -eq 'Audit') { $RunState.TestOnlyEffective = $true }
  $RunState.QuietConsoleEffective = Get-Capability25EffectiveBool -Name 'QuietConsole' -ParameterValue ([bool]$QuietConsole) -RunState $RunState
}
function Initialize-Capability25ExtraArgs {
  param([hashtable]$RunState)
  $ExtraArgsEffective = @(Get-Capability25ExtraArgs)
  $RunState.initializationError = Test-WinGetExtraArgs -ExtraArgs $ExtraArgsEffective
  if ($ExtraArgsEffective.Count -eq 0 -and -not $RunState.QuietConsoleEffective) {
    Write-Info 'Info: No extra -Args provided. Continuing without additional winget arguments.'
  }
}
function Get-Capability25ExtraArgs {
  $argsWereBound = $EntryBoundParameters.ContainsKey('Args') -or $EntryBoundParameters.ContainsKey('ExtraArgs')
  if ($argsWereBound -and $ExtraArgs) { return @($ExtraArgs) }
  if (-not $jsonSettings.ContainsKey('Args')) { return @() }
  $jsonArgs = $jsonSettings['Args']
  if ($jsonArgs -is [string]) { return @($jsonArgs) }
  if ($jsonArgs -is [System.Collections.IEnumerable]) { return @($jsonArgs) }
  return @()
}
function Test-WinGetExtraArgs {
  param([AllowEmptyCollection()][object[]]$ExtraArgs)
  $blockedFlags = @('--override','--custom','--ignore-security-hash','--location','--log','-o','-h','--header','--authentication-account','--authentication-mode')
  foreach ($argument in $ExtraArgs) {
    $argString = [string]$argument
    if ($argString -match '[;&|`$(){}<>]') { return "ExtraArgs contains shell metacharacters: '$argString'. Aborting." }
    $flagPart = ($argString -split '[= ]', 2)[0]
    foreach ($blocked in $blockedFlags) {
      if ($flagPart -ieq $blocked) { return "ExtraArgs contains blocked flag '$argString'. The flag '$blocked' is not allowed for safety reasons." }
    }
  }
  return $null
}
function Initialize-Capability25RunState {
  param([hashtable]$RunState)
  $RunState.results = New-Object System.Collections.Generic.List[object]
  $script:WingetExecutablePath = $null
  if (-not $RunState.initializationError -and [string]::IsNullOrWhiteSpace($RunState.ConfigPathEffective)) {
    $RunState.initializationError = "ConfigPath is missing. Provide a configuration file with -ConfigPath, or set 'ConfigPath' in the summary JSON passed with -SummaryJsonPath."
  }
}
. Initialize-WinGetBaselineState -RunState $RunState

function Get-Capability25SummaryData {
  param($Results, [int]$FinalExitCode, [AllowNull()][string]$ConfigPathResolved, [AllowNull()][string]$ErrorMessage, [hashtable]$RunState)
  return [pscustomobject]@{
    ConfigPathResolved = $ConfigPathResolved
    Results = $Results
    FinalExitCode = $FinalExitCode
    TestOnlyEffective = $RunState.TestOnlyEffective
    AcceptAgreementsEffective = $RunState.AcceptAgreementsEffective
    DisableInteractivityEffective = $RunState.DisableInteractivityEffective
    FailFastEffective = $RunState.FailFastEffective
    PassThruEffective = $RunState.PassThruEffective
    QuietConsoleEffective = $RunState.QuietConsoleEffective
    LogPathEffective = $RunState.LogPathEffective
    SummaryJsonPathEffective = $RunState.SummaryJsonPath
    ExtraArgsEffective = $ExtraArgsEffective
    ErrorMessage = $ErrorMessage
  }
}
function New-Capability25FailureState {
  param([string]$Message, [int]$ExitCode, $Results, [AllowNull()][string]$ConfigPathResolved, [hashtable]$RunState)
  $data = Get-Capability25SummaryData -Results $Results -FinalExitCode $ExitCode -ConfigPathResolved $ConfigPathResolved -ErrorMessage $Message -RunState $RunState
  $data | Add-Member -NotePropertyName Message -NotePropertyValue $Message
  $data | Add-Member -NotePropertyName ExitCode -NotePropertyValue $ExitCode
  return Write-UserFriendlyFailure -Data $data
}
function Get-Capability25Arguments {
  param([string]$ExecutionConfigPath, [hashtable]$RunState)
  $common = @('configure')
  if ($RunState.AcceptAgreementsEffective) { $common += '--accept-configuration-agreements' }
  if ($RunState.DisableInteractivityEffective) { $common += '--disable-interactivity' }
  if ($ExtraArgsEffective -and $ExtraArgsEffective.Count -gt 0) { $common += $ExtraArgsEffective }
  return [pscustomobject]@{
    Validate = @($common + @('validate', '-f', $ExecutionConfigPath))
    Test = @($common + @('test', '-f', $ExecutionConfigPath))
    Apply = @($common + @('-f', $ExecutionConfigPath))
  }
}
function Invoke-Capability25Phase {
  param([string[]]$Arguments, [string]$Phase, $Results, [hashtable]$RunState)
  $RunState.phaseResult = Invoke-WinGet -ArgsWinget $Arguments -Phase $Phase -LogPathEffective $RunState.LogPathEffective -TimeoutSecondsEffective $TimeoutSeconds -MaxOutputBytesEffective $MaxOutputBytes
  $Results.Add($RunState.phaseResult) | Out-Null
  Add-WinGetPhaseFindings -PhaseResult $RunState.phaseResult -RunState $RunState
  return $RunState.phaseResult
}
function Complete-Capability25FailedPhase {
  param([string]$Phase, $PhaseResult, $Results, [string]$ResolvedConfigPath, $StagedConfiguration, [hashtable]$RunState)
  $exitCode = Get-WinGetAggregateExitCode -PhaseResults @($PhaseResult)
  $cleanup = Complete-WinGetStagingCleanup -StagedConfiguration $StagedConfiguration
  $data = Get-Capability25SummaryData -Results $Results -FinalExitCode $exitCode -ConfigPathResolved $ResolvedConfigPath -ErrorMessage "$Phase failed." -RunState $RunState
  $summary = Get-SummaryObject -Data $data
  $summary | Add-Member -NotePropertyName StagingCleanupSucceeded -NotePropertyValue $cleanup.Succeeded -Force
  $summary | Add-Member -NotePropertyName StagingCleanupError -NotePropertyValue $cleanup.Error -Force
  return [pscustomobject]@{ Summary = $summary; Token = 'FAIL'; CleanupSucceeded = $cleanup.Succeeded }
}
function Invoke-Capability25Apply {
  param($Arguments, $Results, [bool]$PreflightSucceeded, $DecisionContext, [string]$ResolvedConfigPath, [hashtable]$RunState)
  $applyRequested = $Mode -eq 'Remediate' -and -not $RunState.TestOnlyEffective
  if ($applyRequested -and $PreflightSucceeded) {
    if ($DecisionContext.ShouldProcess($ResolvedConfigPath, 'Run winget configure apply')) {
      [void](Invoke-Capability25Phase -Arguments $Arguments.Apply -Phase 'apply' -Results $Results -RunState $RunState)
    }
  } elseif ($applyRequested) {
    [void](Add-Finding -FindingList $script:Findings -Code 'WINGET-ApplyBlocked' -Severity 'High' -Message 'WinGet apply was blocked because validate or test did not complete successfully.')
  }
}
function Complete-Capability25Run {
  param($Results, [string]$ResolvedConfigPath, $StagedConfiguration, [hashtable]$RunState)
  $failedPhases = @($Results.ToArray() | Where-Object { $_.TimedOut -or $_.ExitCode -ne 0 })
  $finalExitCode = Get-WinGetAggregateExitCode -PhaseResults $Results.ToArray()
  $errorMessage = if ($failedPhases.Count -gt 0) { 'One or more WinGet phases failed or timed out.' } else { $null }
  $cleanup = Complete-WinGetStagingCleanup -StagedConfiguration $StagedConfiguration
  $data = Get-Capability25SummaryData -Results $Results -FinalExitCode $finalExitCode -ConfigPathResolved $ResolvedConfigPath -ErrorMessage $errorMessage -RunState $RunState
  $summary = Get-SummaryObject -Data $data
  $summary | Add-Member -NotePropertyName StagingCleanupSucceeded -NotePropertyValue $cleanup.Succeeded -Force
  $summary | Add-Member -NotePropertyName StagingCleanupError -NotePropertyValue $cleanup.Error -Force
  $token = Get-WinGetResultToken -FinalExitCode $finalExitCode -FindingsCount $script:Findings.Count -StrictMode ([bool]$Strict)
  return [pscustomobject]@{ Summary = $summary; Token = $token; CleanupSucceeded = $cleanup.Succeeded }
}
function Invoke-Capability25Workflow {
  param($DecisionContext, [hashtable]$RunState)
  $stagedConfiguration = $null
  try {
    $failure = Get-Capability25InitializationFailure -RunState $RunState
    if ($failure) { return $failure }
    $preflight = Start-Capability25Preflight -RunState $RunState
    if ($preflight.Error) { return New-Capability25FailureState -Message $preflight.Error -ExitCode 1 -Results $RunState.results -ConfigPathResolved $RunState.ConfigPathEffective -RunState $RunState }
    $stagedConfiguration = $preflight.StagedConfiguration
    $phaseState = Invoke-Capability25ValidatedPhases -Arguments $preflight.Arguments -Results $RunState.results -ResolvedConfigPath $preflight.ResolvedConfigPath -StagedConfiguration $stagedConfiguration -RunState $RunState
    if ($phaseState.Terminal) {
      if ($phaseState.State.CleanupSucceeded) { $stagedConfiguration = $null }
      return $phaseState.State
    }
    Invoke-Capability25Apply -Arguments $preflight.Arguments -Results $RunState.results -PreflightSucceeded $phaseState.PreflightSucceeded -DecisionContext $DecisionContext -ResolvedConfigPath $preflight.ResolvedConfigPath -RunState $RunState
    $state = Complete-Capability25Run -Results $RunState.results -ResolvedConfigPath $preflight.ResolvedConfigPath -StagedConfiguration $stagedConfiguration -RunState $RunState
    if ($state.CleanupSucceeded) { $stagedConfiguration = $null }
    return $state
  } finally {
    Remove-Capability25UnfinishedStaging -StagedConfiguration $stagedConfiguration
  }
}
function Get-Capability25InitializationFailure {
  param([hashtable]$RunState)
  if (-not $RunState.initializationError) { return $null }
  if ($RunState.initializationError -like 'ExtraArgs*') {
    [void](Add-Finding -FindingList $script:Findings -Code 'WINGET-UnsafeExtraArgs' -Severity 'High' -Message $RunState.initializationError)
  }
  $exitCode = if ($RunState.initializationError -like 'ConfigPath*') { 2 } else { 1 }
  return New-Capability25FailureState -Message $RunState.initializationError -ExitCode $exitCode -Results $RunState.results -ConfigPathResolved $RunState.ConfigPathEffective -RunState $RunState
}
function Start-Capability25Preflight {
  param([hashtable]$RunState)
  try {
    $script:WingetExecutablePath = Resolve-TrustedWingetPath
    if ([string]::IsNullOrWhiteSpace($script:WingetExecutablePath)) { throw 'Trusted WinGet executable not found.' }
    Ensure-NotSystemContext
    $staged = New-WinGetStagedConfiguration -SourcePath $RunState.ConfigPathEffective
    return [pscustomobject]@{ Error = $null; StagedConfiguration = $staged; ResolvedConfigPath = $staged.SourcePath; Arguments = (Get-Capability25Arguments -ExecutionConfigPath $staged.Path -RunState $RunState) }
  } catch {
    return [pscustomobject]@{ Error = $_.Exception.Message; StagedConfiguration = $null; ResolvedConfigPath = $null; Arguments = $null }
  }
}
function Invoke-Capability25ValidatedPhases {
  param($Arguments, $Results, [string]$ResolvedConfigPath, $StagedConfiguration, [hashtable]$RunState)
  $validate = Invoke-Capability25Phase -Arguments $Arguments.Validate -Phase 'validate' -Results $Results -RunState $RunState
  if ($RunState.FailFastEffective -and -not (Test-WinGetPhaseSuccess -PhaseResult $validate)) {
    $state = Complete-Capability25FailedPhase -Phase 'Validate' -PhaseResult $validate -Results $Results -ResolvedConfigPath $ResolvedConfigPath -StagedConfiguration $StagedConfiguration -RunState $RunState
    return [pscustomobject]@{ Terminal = $true; State = $state; PreflightSucceeded = $false }
  }
  $test = Invoke-Capability25Phase -Arguments $Arguments.Test -Phase 'test' -Results $Results -RunState $RunState
  if ($RunState.FailFastEffective -and -not (Test-WinGetPhaseSuccess -PhaseResult $test)) {
    $state = Complete-Capability25FailedPhase -Phase 'Test' -PhaseResult $test -Results $Results -ResolvedConfigPath $ResolvedConfigPath -StagedConfiguration $StagedConfiguration -RunState $RunState
    return [pscustomobject]@{ Terminal = $true; State = $state; PreflightSucceeded = $false }
  }
  $succeeded = (Test-WinGetPhaseSuccess -PhaseResult $validate) -and (Test-WinGetPhaseSuccess -PhaseResult $test)
  return [pscustomobject]@{ Terminal = $false; State = $null; PreflightSucceeded = $succeeded }
}
function Remove-Capability25UnfinishedStaging {
  param([AllowNull()]$StagedConfiguration)
  if ($null -eq $StagedConfiguration) { return }
  try { Remove-WinGetStagedConfiguration -StagedConfiguration $StagedConfiguration }
  catch { Write-Warning "Failed to remove protected WinGet staging directory: $($_.Exception.Message)" }
}

$terminalState = Invoke-Capability25Workflow -DecisionContext $PSCmdlet -RunState $RunState
$summary = $terminalState.Summary
$resultToken = $terminalState.Token
Invoke-WinGetConsoleSummary -Summary $summary
$v2Result = Get-V2ResultObject -ScriptName '25-WinGet-Config-Baseline-Runner.ps1' -Mode $Mode -Result $resultToken -Findings (ConvertTo-ObjectArray -InputObject $script:Findings.ToArray()) -Summary $summary -Metadata @{}
Write-ResultObject -ResultObject $v2Result -OutputFormat $OutputFormat -OutputPath $OutputPath
if ($RunState.PassThruEffective) { $v2Result }
exit (Get-V2ExitCode -Result $resultToken)
