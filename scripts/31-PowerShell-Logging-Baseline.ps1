#Requires -RunAsAdministrator
#requires -version 5.1
<#
.SYNOPSIS
Audit/remediate Windows PowerShell 5.1 logging policies via registry policy keys.

.DESCRIPTION
Targets policy keys under:
HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell

Optionally reads a JSON config. If JSON is missing/unreadable/invalid, safe defaults are used.
Computer Configuration policies (HKLM) take precedence over User Configuration (HKCU). [page:1]

.PARAMETER Mode
Audit | Remediate

.PARAMETER ConfigJsonPath
Optional JSON path supplied with $ConfigJsonPath.
If missing/unreadable/invalid, defaults are used.

.PARAMETER IncludeHKCU
Also read HKCU policy keys for informational purposes (HKLM still wins).

.PARAMETER TranscriptOutputDirectory
Transcript output directory (overrides JSON/defaults when explicitly provided).

.PARAMETER EnableTranscription
Enable transcription policy (accepts: $true/$false, true/false, 1/0).

.PARAMETER EnableInvocationHeader
Enable invocation header policy for transcription (accepts: $true/$false, true/false, 1/0).

.PARAMETER EnableScriptBlockLogging
Enable Script Block Logging policy (accepts: $true/$false, true/false, 1/0).

.PARAMETER EnableScriptBlockInvocationLogging
Enable Script Block Invocation Logging (accepts: $true/$false, true/false, 1/0).

.PARAMETER EnableModuleLogging
Enable Module Logging policy (accepts: $true/$false, true/false, 1/0).

.PARAMETER ModuleNames
Modules to log (ModuleNames subkey values 1..N). Use @('*') for all.

.PARAMETER ExportPath
Optional CSV export of the Summary object.

.PARAMETER QuietConsole
If set, suppresses formatted console output (no Write-UiLine summary).


.PARAMETER ConfigPath
  Path to JSON configuration file.

.PARAMETER OutputFormat
  Output format: Console, Json, Csv, or None.

.PARAMETER OutputPath
  File path for Json/Csv output.

.PARAMETER PassThru
  Emit structured v2 result object to pipeline.

.PARAMETER Strict
  Treat warnings as failures.

.PARAMETER Quiet
  Suppress console output.

.PARAMETER NoColor
  Disable colored output.

.OUTPUTS
Exactly one structured object to the pipeline:
PSCustomObject with properties:
- Summary
- Findings (array)
- Current (HKLM/HKCU/Effective) Before/After

.NOTES
PowerShell 5.1 compatible.
ConvertFrom-Json in Windows PowerShell 5.1 fails on JSON comments.
.EXAMPLE
  .\31-PowerShell-Logging-Baseline.ps1

#>


[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
  [ValidateSet('Audit', 'Remediate')]
  [string]$Mode = 'Audit',

  [string]$ConfigJsonPath,

  [switch]$IncludeHKCU,

  [string]$TranscriptOutputDirectory,

  [object]$EnableTranscription,
  [object]$EnableInvocationHeader,
  [object]$EnableScriptBlockLogging,
  [object]$EnableScriptBlockInvocationLogging,
  [object]$EnableModuleLogging,

  [string[]]$ModuleNames,

  [string]$ExportPath,

  [switch]$QuietConsole

,
  [string]$ConfigPath,
  [ValidateSet('Console','Json','Csv','None')][string]$OutputFormat = 'Console',
  [string]$OutputPath,
  [switch]$PassThru,
  [switch]$Strict,
  [switch]$Quiet,
  [switch]$NoColor
)

. (Join-Path $PSScriptRoot '_lib/Bootstrap.ps1')
function Test-AllConditions {
  param([scriptblock[]]$Conditions)
  foreach ($condition in $Conditions) {
    if (-not (. $condition)) { return $false }
  }
  return $true
}
function Test-AnyCondition {
  param([scriptblock[]]$Conditions)
  foreach ($condition in $Conditions) {
    if (. $condition) { return $true }
  }
  return $false
}
function Initialize-Capability31Runtime {
  param($EntryBoundParameters)
  $RunState = @{

  }
Import-Module (Join-Path $script:LibPath 'Output.psm1') -Force
Import-Module (Join-Path $script:LibPath 'Common.psm1') -Force -DisableNameChecking
Import-Module (Join-Path $script:LibPath 'Console.psm1') -Force
Import-Module (Join-Path $script:LibPath 'Registry.psm1') -Force -DisableNameChecking
Import-Module (Join-Path $script:LibPath 'Config.psm1') -Force
Import-Module (Join-Path $script:LibPath 'Results.psm1') -Force
Import-Module (Join-Path $script:LibPath Serialization.psm1) -Force


Set-StrictMode -Version Latest
$script:__V2Context = Initialize-V2Context -ScriptName '31-PowerShell-Logging-Baseline.ps1' -BoundParameters $EntryBoundParameters `
  -Values @{ Mode = $Mode; ConfigPath = $ConfigPath; OutputFormat = $OutputFormat; OutputPath = $OutputPath; PassThru = $PassThru; Strict = $Strict; Quiet = $Quiet; NoColor = $NoColor; DeriveRemediate = $false }
if ($script:__V2Context.Quiet) { $InformationPreference = 'SilentlyContinue'; $VerbosePreference = 'SilentlyContinue' }
$script:NoColor = [bool]$script:__V2Context.NoColor
$ErrorActionPreference = 'Stop'
  $script:RunState = $RunState
}

. Initialize-Capability31Runtime -EntryBoundParameters $PSBoundParameters

# ---------------------------
# Helpers (no pipeline output)
# ---------------------------


# Ensure-Key replaced by Ensure-RegistryKey from lib/Registry.psm1
# Set-RegString replaced by lib/Registry.psm1::Set-RegString (has full error handling and validation)

function Get-ModuleNamesConfigured {
  param([string]$ModuleNamesKeyPath)

  if (-not (Test-Path -LiteralPath $ModuleNamesKeyPath)) { return $null }

  $obj = Get-ItemProperty -Path $ModuleNamesKeyPath
  $props = $obj | Get-Member -MemberType NoteProperty | Select-Object -ExpandProperty Name

  $result = [ordered]@{}
  foreach ($p in $props) { $result[$p] = $obj.$p }

  if ($result.Count -eq 0) { return $null }
  return [pscustomobject]$result
}

function Remove-AllModuleNames {
  [CmdletBinding(SupportsShouldProcess = $true)]
  param([string]$ModuleNamesKeyPath)

  if (-not (Test-Path -LiteralPath $ModuleNamesKeyPath)) { return }

  $obj = Get-ItemProperty -Path $ModuleNamesKeyPath
  $props = $obj | Get-Member -MemberType NoteProperty | Select-Object -ExpandProperty Name
  foreach ($p in $props) {
    try {
      Remove-ItemProperty -Path $ModuleNamesKeyPath -Name $p -ErrorAction Stop
    } catch {
      Write-Warning "Could not remove module name property '$p': $($_.Exception.Message)"
    }
  }
}

function Test-IsSafeTranscriptPath {
  param([string]$Path)

  if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
  $commonData = [Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)
  if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) { $commonData = [IO.Path]::GetTempPath() }
  if ([string]::IsNullOrWhiteSpace($commonData)) { return $false }
  try { $full = [System.IO.Path]::GetFullPath($Path) } catch { return $false }

  $pd = [System.IO.Path]::GetFullPath($commonData)
  return (Test-PathUnderRoot -Path $full -Root $pd)
}

function Normalize-ModuleNames {
  param([object]$Names)
  $arr = @()
  if ($Names -is [string]) { $arr = @([string]$Names) }
  elseif ($Names -is [System.Collections.IEnumerable]) { $arr = @($Names) }
  $clean = @(Get-CleanModuleNames -Names $arr)
  if ($clean.Count -eq 0) { return @('*') }
  return @(Get-DistinctModuleNames -Names $clean)
}
function Get-CleanModuleNames {
  param([object[]]$Names)
  foreach ($name in $Names) {
    $value = ([string]$name).Trim()
    if ($value.Length -gt 0) { $value }
  }
}
function Get-DistinctModuleNames {
  param([string[]]$Names)
  $seen = @{}
  $out = @()
  foreach ($name in $Names) {
    $k = $name.ToLowerInvariant()
    if (-not $seen.ContainsKey($k)) {
      $seen[$k] = $true
      $out += $name
    }
  }
  return $out
}

function Try-ParseBool {
  param(
    [AllowNull()][object]$Value,
    [ref]$Parsed
  )

  $Parsed.Value = $null
  if ($null -eq $Value) { return $false }

  if ($Value -is [bool]) { $Parsed.Value = [bool]$Value; return $true }

  if (@([int], [long], [byte]) -contains $Value.GetType()) {
    return Set-ParsedNumericBool -Value $Value -Parsed $Parsed
  }

  $s = ([string]$Value).Trim()
  if ($s.Length -eq 0) { return $false }

  $normalized = $s.ToLowerInvariant()
  if (@('true','$true','yes','y','on','enable','enabled','1') -contains $normalized) { $Parsed.Value = $true; return $true }
  if (@('false','$false','no','n','off','disable','disabled','0') -contains $normalized) { $Parsed.Value = $false; return $true }
  return $false
}
function Set-ParsedNumericBool {
  param($Value, [ref]$Parsed)
  if ([int]$Value -eq 1) { $Parsed.Value = $true; return $true }
  if ([int]$Value -eq 0) { $Parsed.Value = $false; return $true }
  return $false
}

function Resolve-Bool {
  param(
    [object]$ParameterValue,
    [bool]$ParameterWasBound,
    [object]$ConfigValue,
    [bool]$DefaultValue,
    [string]$NameForFinding,
    [System.Collections.Generic.List[object]]$Findings
  )

  $tmp = $null

  if ($ParameterWasBound) {
    if (Try-ParseBool -Value $ParameterValue -Parsed ([ref]$tmp)) { return [bool]$tmp }
    Add-Finding -FindingList $Findings -Code 'PSLOG-InvalidBoolParameter' -Severity 'Info' -Message ("Invalid boolean parameter '{0}'; using JSON/defaults." -f $NameForFinding)
  }

  if (Try-ParseBool -Value $ConfigValue -Parsed ([ref]$tmp)) { return [bool]$tmp }
  return $DefaultValue
}

function Get-SettingsForBase {
  param([string]$BasePath, [hashtable]$RunState)

  $RunState.transPath = Join-Path $BasePath 'Transcription'
  $RunState.sbPath    = Join-Path $BasePath 'ScriptBlockLogging'
  $modPath   = Join-Path $BasePath 'ModuleLogging'
  $RunState.modNames  = Join-Path $modPath 'ModuleNames'

  [pscustomobject]@{
    PolicyBasePath                                = $BasePath

    Transcription_EnableTranscripting              = Get-RegValue -Path $RunState.transPath -Name 'EnableTranscripting'
    Transcription_OutputDirectory                  = Get-RegValue -Path $RunState.transPath -Name 'OutputDirectory'
    Transcription_EnableInvocationHeader           = Get-RegValue -Path $RunState.transPath -Name 'EnableInvocationHeader'

    ScriptBlock_EnableScriptBlockLogging           = Get-RegValue -Path $RunState.sbPath -Name 'EnableScriptBlockLogging'
    ScriptBlock_EnableScriptBlockInvocationLogging = Get-RegValue -Path $RunState.sbPath -Name 'EnableScriptBlockInvocationLogging'

    Module_EnableModuleLogging                     = Get-RegValue -Path $modPath -Name 'EnableModuleLogging'
    ModuleNames_Configured                         = Get-ModuleNamesConfigured -ModuleNamesKeyPath $RunState.modNames
  }
}

function Get-EffectiveSettings {
  param(
    [pscustomobject]$HKLM,
    [pscustomobject]$HKCU
  )
  # HKLM wins when present. [page:1]
  [pscustomobject]@{
    PolicyBasePath                                = $HKLM.PolicyBasePath

    Transcription_EnableTranscripting              = Get-PreferredPolicyValue $HKLM.Transcription_EnableTranscripting $HKCU.Transcription_EnableTranscripting
    Transcription_OutputDirectory                  = Get-PreferredPolicyValue $HKLM.Transcription_OutputDirectory $HKCU.Transcription_OutputDirectory
    Transcription_EnableInvocationHeader           = Get-PreferredPolicyValue $HKLM.Transcription_EnableInvocationHeader $HKCU.Transcription_EnableInvocationHeader

    ScriptBlock_EnableScriptBlockLogging           = Get-PreferredPolicyValue $HKLM.ScriptBlock_EnableScriptBlockLogging $HKCU.ScriptBlock_EnableScriptBlockLogging
    ScriptBlock_EnableScriptBlockInvocationLogging = Get-PreferredPolicyValue $HKLM.ScriptBlock_EnableScriptBlockInvocationLogging $HKCU.ScriptBlock_EnableScriptBlockInvocationLogging

    Module_EnableModuleLogging                     = Get-PreferredPolicyValue $HKLM.Module_EnableModuleLogging $HKCU.Module_EnableModuleLogging
    ModuleNames_Configured                         = Get-PreferredPolicyValue $HKLM.ModuleNames_Configured $HKCU.ModuleNames_Configured -UseTruthiness
  }
}
function Get-PreferredPolicyValue {
  param([AllowNull()]$MachineValue, [AllowNull()]$UserValue, [switch]$UseTruthiness)
  if ($UseTruthiness -and $MachineValue) { return $MachineValue }
  if (-not $UseTruthiness -and $null -ne $MachineValue) { return $MachineValue }
  return $UserValue
}

function Format-PolicyValue {
  param([object]$Value)
  if ($null -eq $Value) { return 'NotConfigured' }
  return [string]$Value
}


# Severity-ToColor replaced by Get-SeverityColor from lib/Console.psm1
# Write-ConsoleSummary imported from lib/Console.psm1

# ---------------------------
# Main
# ---------------------------
$isWindowsHost = ($env:OS -eq 'Windows_NT')
if (-not $isWindowsHost) {
  $RunState.summary = [pscustomobject]@{
    ComputerName = $env:COMPUTERNAME
    Timestamp    = Get-Date
    Mode         = $Mode
    Supported    = $false
    Notes        = @('Skipped: PowerShell logging baseline auditing is only supported on Windows hosts.')
  }

  $unsupportedResult = if ($Strict) { 'FAIL' } else { 'WARN' }
  $result = Get-V2ResultObject -ScriptName '31-PowerShell-Logging-Baseline.ps1' -Mode $Mode -Result $unsupportedResult -Findings @() -Summary $RunState.summary -Metadata @{ UnsupportedHost = $true }
  Write-ResultObject -ResultObject $result -OutputFormat $OutputFormat -OutputPath $OutputPath
  if ($PassThru) { $result }
  exit (Get-V2ExitCode -Result $unsupportedResult)
}

function Initialize-PowerShellLoggingAuditState {
  param([hashtable]$RunState)
Require-Admin

$RunState.Findings = Get-FindingsList
$RunState.registryWriteFailed = $false
}
. Initialize-PowerShellLoggingAuditState -RunState $RunState

function Add-RegistryWriteFailureFinding {
  param(
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][string]$Name,
    [Parameter(Mandatory)][object]$Value
  , [hashtable]$RunState)

  $null = Add-Finding -FindingList $RunState.Findings -Code 'PSLOG-RegWriteFailed' -Severity 'High' `
    -Message ("Failed to write PowerShell logging registry value '{0}' at '{1}'. Hardening not applied." -f $Name, $Path) `
    -Extra @{ Path = $Path; Name = $Name; Value = $Value }
}

# Defaults (used when JSON missing/invalid)
function Invoke-Capability31MainPhase01 {
  param([hashtable]$RunState)
  $commonApplicationData = [Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)
  if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) { $commonApplicationData = [IO.Path]::GetTempPath() }
  if ([string]::IsNullOrWhiteSpace($commonApplicationData)) { throw 'CommonApplicationData could not be resolved.' }
  $defaultTranscriptDirectory = Join-Path $commonApplicationData 'PowerShellTranscripts'
  $defaults = @{
    TranscriptOutputDirectory           = $defaultTranscriptDirectory
    EnableTranscription                = $true
    EnableInvocationHeader             = $true
    EnableScriptBlockLogging           = $true
    EnableScriptBlockInvocationLogging = $false
    EnableModuleLogging                = $true
    ModuleNames                        = @('*')
  }

  $sanitized = if ([string]::IsNullOrWhiteSpace($ConfigJsonPath)) { $null } else { Sanitize-Path -Path $ConfigJsonPath -MustExist }
  if (-not $sanitized -and -not [string]::IsNullOrWhiteSpace($ConfigJsonPath)) {
    Add-Finding -FindingList $RunState.Findings -Code 'PSLOG-ConfigJsonMissing' -Severity 'Info' -Message 'Config JSON not found; using defaults.'
  }
  $cfgResult = Read-ConfigWithDefaults -Path $sanitized -Defaults $defaults
  $RunState.config = $cfgResult.Config
}
function Invoke-Capability31MainPhase02 {
  param([hashtable]$RunState)
  if ($cfgResult.Meta.Provided -and -not $cfgResult.Meta.Loaded) {
    $code = 'PSLOG-ConfigJsonInvalid'
    $msg = 'Config JSON could not be loaded/parsed; using defaults.'
    if ($cfgResult.Meta.Error -eq 'ConfigPath not found or invalid.') {
      $code = 'PSLOG-ConfigJsonMissing'
      $msg = 'Config JSON not found; using defaults.'
    } elseif ($cfgResult.Meta.Error -eq 'Config file is empty.') {
      $code = 'PSLOG-ConfigJsonEmpty'
      $msg = 'Config JSON is empty; using defaults.'
    }
    Add-Finding -FindingList $RunState.Findings -Code $code -Severity 'Info' -Message $msg
  }
}
function Invoke-Capability31MainPhase03 {
  param([hashtable]$RunState)
  $RunState.targetTranscriptDir = if ($script:__EntryBoundParameters.ContainsKey('TranscriptOutputDirectory') -and -not [string]::IsNullOrWhiteSpace($TranscriptOutputDirectory)) {
    $TranscriptOutputDirectory
  } elseif (-not [string]::IsNullOrWhiteSpace([string]$RunState.config.TranscriptOutputDirectory)) {
    [string]$RunState.config.TranscriptOutputDirectory
  } else {
    $defaultTranscriptDirectory
  }

  $RunState.targetEnableTranscription = Resolve-Bool -ParameterValue $EnableTranscription -ParameterWasBound $script:__EntryBoundParameters.ContainsKey('EnableTranscription') -ConfigValue $RunState.config.EnableTranscription -DefaultValue $true -NameForFinding 'EnableTranscription' -Findings $RunState.Findings
  $RunState.targetEnableInvocationHeader = Resolve-Bool -ParameterValue $EnableInvocationHeader -ParameterWasBound $script:__EntryBoundParameters.ContainsKey('EnableInvocationHeader') -ConfigValue $RunState.config.EnableInvocationHeader -DefaultValue $true -NameForFinding 'EnableInvocationHeader' -Findings $RunState.Findings
  $RunState.targetEnableScriptBlockLogging = Resolve-Bool -ParameterValue $EnableScriptBlockLogging -ParameterWasBound $script:__EntryBoundParameters.ContainsKey('EnableScriptBlockLogging') -ConfigValue $RunState.config.EnableScriptBlockLogging -DefaultValue $true -NameForFinding 'EnableScriptBlockLogging' -Findings $RunState.Findings
  $RunState.targetEnableScriptBlockInvocationLogging = Resolve-Bool -ParameterValue $EnableScriptBlockInvocationLogging -ParameterWasBound $script:__EntryBoundParameters.ContainsKey('EnableScriptBlockInvocationLogging') -ConfigValue $RunState.config.EnableScriptBlockInvocationLogging -DefaultValue $false -NameForFinding 'EnableScriptBlockInvocationLogging' -Findings $RunState.Findings
  $RunState.targetEnableModuleLogging = Resolve-Bool -ParameterValue $EnableModuleLogging -ParameterWasBound $script:__EntryBoundParameters.ContainsKey('EnableModuleLogging') -ConfigValue $RunState.config.EnableModuleLogging -DefaultValue $true -NameForFinding 'EnableModuleLogging' -Findings $RunState.Findings

  $targetModuleNames = if ($script:__EntryBoundParameters.ContainsKey('ModuleNames')) { $ModuleNames } else { $RunState.config.ModuleNames }
  $targetModuleNames = Normalize-ModuleNames -Names $targetModuleNames
}
function Invoke-Capability31MainPhase04 {
  param([hashtable]$RunState)
  if ($RunState.targetEnableTranscription -and -not (Test-IsSafeTranscriptPath -Path $RunState.targetTranscriptDir)) {
    Add-Finding -FindingList $RunState.Findings -Code 'PSLOG-TranscriptPathNotProgramData' -Severity 'Info' -Message 'Transcript output directory is not under ProgramData (review ACLs and data exposure risk).'
  }

  $hklmBase = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell'
  $hkcuBase = 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\PowerShell'

  $currentHKLM = Get-SettingsForBase -BasePath $hklmBase -RunState $RunState
  $currentHKCU = if ($IncludeHKCU) { Get-SettingsForBase -BasePath $hkcuBase -RunState $RunState } else { $null }
  $RunState.effectiveBefore = if ($IncludeHKCU -and $currentHKCU) { Get-EffectiveSettings -HKLM $currentHKLM -HKCU $currentHKCU } else { $currentHKLM }
}
function Invoke-Capability31MainPhase05 {
  param([hashtable]$RunState)
  if ($RunState.targetEnableTranscription -and $RunState.effectiveBefore.Transcription_EnableTranscripting -ne 1) {
    Add-Finding -FindingList $RunState.Findings -Code 'PSLOG-TranscriptionOff' -Severity 'Medium' -Message 'Transcription is not enabled (effective policy).'
  }
  if ($RunState.targetEnableInvocationHeader -and $RunState.targetEnableTranscription -and $RunState.effectiveBefore.Transcription_EnableInvocationHeader -ne 1) {
    Add-Finding -FindingList $RunState.Findings -Code 'PSLOG-InvocationHeaderOff' -Severity 'Low' -Message 'Invocation Header is not enabled (effective policy).'
  }
}
function Invoke-Capability31MainPhase06 {
  param([hashtable]$RunState)
  if ($RunState.targetEnableScriptBlockLogging -and $RunState.effectiveBefore.ScriptBlock_EnableScriptBlockLogging -ne 1) {
    Add-Finding -FindingList $RunState.Findings -Code 'PSLOG-ScriptBlockOff' -Severity 'Medium' -Message 'Script Block Logging is not enabled (effective policy).'
  }
  if ($RunState.targetEnableScriptBlockInvocationLogging -and $RunState.targetEnableScriptBlockLogging -and $RunState.effectiveBefore.ScriptBlock_EnableScriptBlockInvocationLogging -ne 1) {
    Add-Finding -FindingList $RunState.Findings -Code 'PSLOG-ScriptBlockInvocationOff' -Severity 'Low' -Message 'Script Block Invocation Logging is not enabled (effective policy).'
  }
}
function Invoke-Capability31MainPhase07 {
  param([hashtable]$RunState)
  if ($RunState.targetEnableModuleLogging -and $RunState.effectiveBefore.Module_EnableModuleLogging -ne 1) {
    Add-Finding -FindingList $RunState.Findings -Code 'PSLOG-ModuleLoggingOff' -Severity 'Low' -Message 'Module Logging is not enabled (effective policy).'
  }

  if ($RunState.targetEnableScriptBlockLogging -and $Mode -eq 'Audit') {
    Add-Finding -FindingList $RunState.Findings -Code 'PSLOG-Recommend-ProtectedEventLogging' -Severity 'Info' -Message 'Consider enabling Protected Event Logging when using Script Block Logging beyond diagnostics.'
  }
}
function Invoke-Capability31MainPhase08Step01 {
  param([hashtable]$RunState)
$RunState.transPath = Join-Path $hklmBase 'Transcription'
    $RunState.sbPath    = Join-Path $hklmBase 'ScriptBlockLogging'
    $modPath   = Join-Path $hklmBase 'ModuleLogging'
    $RunState.modNames  = Join-Path $modPath 'ModuleNames'
}

function Invoke-Capability31MainPhase08Step02 {
  param([hashtable]$RunState)
if ($RunState.targetEnableTranscription) {
      if ($script:__EntryCmdlet.ShouldProcess($env:COMPUTERNAME, 'Configure PowerShell transcription policy keys (HKLM)')) {
        Ensure-RegistryKey -Path $hklmBase
        Ensure-RegistryKey -Path $RunState.transPath
        if (-not (Set-RegDword -Path $RunState.transPath -Name 'EnableTranscripting' -Value 1)) {
          Add-RegistryWriteFailureFinding -Path $RunState.transPath -Name 'EnableTranscripting' -Value 1 -RunState $RunState
          $RunState.registryWriteFailed = $true
        }
        if (-not (Set-RegString -Path $RunState.transPath -Name 'OutputDirectory' -Value $RunState.targetTranscriptDir)) {
          Add-RegistryWriteFailureFinding -Path $RunState.transPath -Name 'OutputDirectory' -Value $RunState.targetTranscriptDir -RunState $RunState
          $RunState.registryWriteFailed = $true
        }
        . Set-PowerShellInvocationHeaderPolicy -RunState $RunState
        if (-not (Test-Path -LiteralPath $RunState.targetTranscriptDir)) {
          $null = New-Item -Path $RunState.targetTranscriptDir -ItemType Directory -Force
        }
      }
    }
}
function Set-PowerShellInvocationHeaderPolicy {
  param([hashtable]$RunState)
  if (-not $RunState.targetEnableInvocationHeader) { return }
  if (-not (Set-RegDword -Path $RunState.transPath -Name 'EnableInvocationHeader' -Value 1)) {
    Add-RegistryWriteFailureFinding -Path $RunState.transPath -Name 'EnableInvocationHeader' -Value 1 -RunState $RunState
    $RunState.registryWriteFailed = $true
  }
}

function Invoke-Capability31MainPhase08Step03 {
  param([hashtable]$RunState)
if ($RunState.targetEnableScriptBlockLogging) {
      if ($script:__EntryCmdlet.ShouldProcess($env:COMPUTERNAME, 'Configure PowerShell script block logging policy keys (HKLM)')) {
        Ensure-RegistryKey -Path $hklmBase
        Ensure-RegistryKey -Path $RunState.sbPath
        if (-not (Set-RegDword -Path $RunState.sbPath -Name 'EnableScriptBlockLogging' -Value 1)) {
          Add-RegistryWriteFailureFinding -Path $RunState.sbPath -Name 'EnableScriptBlockLogging' -Value 1 -RunState $RunState
          $RunState.registryWriteFailed = $true
        }
        if ($RunState.targetEnableScriptBlockInvocationLogging) {
          if (-not (Set-RegDword -Path $RunState.sbPath -Name 'EnableScriptBlockInvocationLogging' -Value 1)) {
            Add-RegistryWriteFailureFinding -Path $RunState.sbPath -Name 'EnableScriptBlockInvocationLogging' -Value 1 -RunState $RunState
            $RunState.registryWriteFailed = $true
          }
        }
      }
    }
}

function Invoke-Capability31MainPhase08Step04 {
  param([hashtable]$RunState)
if ($RunState.targetEnableModuleLogging) {
      if ($script:__EntryCmdlet.ShouldProcess($env:COMPUTERNAME, 'Configure PowerShell module logging policy keys (HKLM)')) {
        Ensure-RegistryKey -Path $hklmBase
        Ensure-RegistryKey -Path $modPath
        Ensure-RegistryKey -Path $RunState.modNames

        if (-not (Set-RegDword -Path $modPath -Name 'EnableModuleLogging' -Value 1)) {
          Add-RegistryWriteFailureFinding -Path $modPath -Name 'EnableModuleLogging' -Value 1 -RunState $RunState
          $RunState.registryWriteFailed = $true
        }
        Remove-AllModuleNames -ModuleNamesKeyPath $RunState.modNames

        $i = 1
        foreach ($m in $targetModuleNames) {
          $null = New-ItemProperty -Path $RunState.modNames -Name ([string]$i) -PropertyType String -Value $m -Force
          $i++
        }
      }
    }
}

function Invoke-Capability31MainPhase08 {
  param([hashtable]$RunState)
  if ($Mode -eq 'Remediate') {
    . Invoke-Capability31MainPhase08Step01 -RunState $RunState
. Invoke-Capability31MainPhase08Step02 -RunState $RunState
. Invoke-Capability31MainPhase08Step03 -RunState $RunState
. Invoke-Capability31MainPhase08Step04 -RunState $RunState
  }
}
function Invoke-Capability31MainPhase09 {
  param([hashtable]$RunState)
  $afterHKLM = Get-SettingsForBase -BasePath $hklmBase -RunState $RunState
  $afterHKCU = if ($IncludeHKCU) { Get-SettingsForBase -BasePath $hkcuBase -RunState $RunState } else { $null }
  $RunState.effectiveAfter = if ($IncludeHKCU -and $afterHKCU) { Get-EffectiveSettings -HKLM $afterHKLM -HKCU $afterHKCU } else { $afterHKLM }

  $RunState.summary = [pscustomobject]@{
    ComputerName  = $env:COMPUTERNAME
    Mode          = $Mode
    FindingsCount = ($RunState.Findings | Measure-Object).Count
    RegistryWriteFailed = $RunState.registryWriteFailed
    Timestamp     = Get-Date

    Target_TranscriptOutputDirectory          = $RunState.targetTranscriptDir
    Target_EnableTranscription                = $RunState.targetEnableTranscription
    Target_EnableInvocationHeader             = $RunState.targetEnableInvocationHeader
    Target_EnableScriptBlockLogging           = $RunState.targetEnableScriptBlockLogging
    Target_EnableScriptBlockInvocationLogging = $RunState.targetEnableScriptBlockInvocationLogging
    Target_EnableModuleLogging                = $RunState.targetEnableModuleLogging
    Target_ModuleNames                        = @($targetModuleNames)

    ConfigJsonPath                            = if ($ConfigJsonPath) { '[configured path]' } else { $null }
    PolicyBasePath                            = $hklmBase
    IncludeHKCU                               = [bool]$IncludeHKCU
  }
}
function Invoke-Capability31MainPhase10 {
  param([hashtable]$RunState)
  if ($ExportPath) {
    $dir = Split-Path -Path $ExportPath -Parent
    if ($dir -and -not (Test-Path -LiteralPath $dir)) { $null = New-Item -Path $dir -ItemType Directory -Force }
    $RunState.summary | Export-Csv -Path $ExportPath -NoTypeInformation -Encoding UTF8
  }
}
function Invoke-Capability31MainPhase11 {
  param([hashtable]$RunState)
  if (-not $QuietConsole) {
    $t  = Format-PolicyValue $RunState.effectiveAfter.Transcription_EnableTranscripting
    $sb = Format-PolicyValue $RunState.effectiveAfter.ScriptBlock_EnableScriptBlockLogging
    $ml = Format-PolicyValue $RunState.effectiveAfter.Module_EnableModuleLogging
    $modNamesStr = if ($RunState.effectiveAfter.ModuleNames_Configured) {
      $vals = @(); foreach ($p in $RunState.effectiveAfter.ModuleNames_Configured.PSObject.Properties) { $vals += ("{0}={1}" -f $p.Name, $p.Value) }; $vals -join '; '
    } else { 'NotConfigured' }

    $customFields = [ordered]@{
      'Mode'          = $RunState.summary.Mode
      'Transcript'    = ("{0} (target={1})" -f $t, $RunState.summary.Target_EnableTranscription)
      'SBLogging'     = ("{0} (target={1})" -f $sb, $RunState.summary.Target_EnableScriptBlockLogging)
      'ModuleLog'     = ("{0} (target={1})" -f $ml, $RunState.summary.Target_EnableModuleLogging)
      'ModuleNames'   = $modNamesStr
      'TranscriptDir' = Format-PolicyValue $RunState.effectiveAfter.Transcription_OutputDirectory
    }
    $findingsAL = ConvertTo-ArrayList -InputObject $RunState.Findings
    Write-ConsoleSummary -Summary $RunState.summary -Findings $findingsAL `
      -Title 'PowerShell Logging Baseline' `
      -CustomFields $customFields
  }
}
function Invoke-Capability31Main {
  param($EntryBoundParameters, $EntryCmdlet, $EntryInvocation, [hashtable]$RunState)
  $script:__EntryBoundParameters = $EntryBoundParameters
  $script:__EntryCmdlet = $EntryCmdlet
  $script:__EntryInvocation = $EntryInvocation
  . Invoke-Capability31MainPhase01 -RunState $RunState
  . Invoke-Capability31MainPhase02 -RunState $RunState
  . Invoke-Capability31MainPhase03 -RunState $RunState
  . Invoke-Capability31MainPhase04 -RunState $RunState
  . Invoke-Capability31MainPhase05 -RunState $RunState
  . Invoke-Capability31MainPhase06 -RunState $RunState
  . Invoke-Capability31MainPhase07 -RunState $RunState
  . Invoke-Capability31MainPhase08 -RunState $RunState
  . Invoke-Capability31MainPhase09 -RunState $RunState
  . Invoke-Capability31MainPhase10 -RunState $RunState
  . Invoke-Capability31MainPhase11 -RunState $RunState
}
. Invoke-Capability31Main -EntryBoundParameters $PSBoundParameters -EntryCmdlet $PSCmdlet -EntryInvocation $MyInvocation -RunState $RunState

# V2 output contract
function Get-Capability31ResultToken {
  param([hashtable]$RunState)
  $resultToken = if ($RunState.registryWriteFailed) { 'FAIL' } elseif ($Strict -and $RunState.Findings.Count -gt 0) { 'FAIL' } elseif ($RunState.Findings.Count -gt 0) { 'WARN' } else { 'OK' }
  return $resultToken
}
$resultToken = Get-Capability31ResultToken -RunState $RunState
$v2Result = Get-V2ResultObject -ScriptName '31-PowerShell-Logging-Baseline.ps1' -Mode $Mode -Result $resultToken -Findings (ConvertTo-ObjectArray -InputObject $RunState.Findings.ToArray()) -Summary $RunState.summary -Metadata @{ Current = [pscustomobject]@{ HKLM = [pscustomobject]@{ Before = $currentHKLM; After = $afterHKLM }; HKCU = if ($IncludeHKCU) { [pscustomobject]@{ Before = $currentHKCU; After = $afterHKCU } } else { $null }; Effective = [pscustomobject]@{ Before = $RunState.effectiveBefore; After = $RunState.effectiveAfter } } }
Write-ResultObject -ResultObject $v2Result -OutputFormat $OutputFormat -OutputPath $OutputPath
if ($PassThru) { $v2Result }
exit (Get-V2ExitCode -Result $resultToken)
