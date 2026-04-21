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
Optional JSON path, e.g. "PATH/TO/JSON/powershell-logging.json".
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
If set, suppresses pretty console output (no Write-UiLine summary).


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
ConvertFrom-Json in Windows PowerShell 5.1 fails on JSON comments. [web:55]
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
Import-Module (Join-Path $script:LibPath 'Output.psm1') -Force
Import-Module (Join-Path $script:LibPath 'Common.psm1') -Force
Import-Module (Join-Path $script:LibPath 'Console.psm1') -Force
Import-Module (Join-Path $script:LibPath 'Registry.psm1') -Force
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
  if ([string]::IsNullOrWhiteSpace($env:ProgramData)) { return $false }
  try { $full = [System.IO.Path]::GetFullPath($Path) } catch { return $false }

  $pd = [System.IO.Path]::GetFullPath($env:ProgramData)
  return $full.StartsWith($pd, [System.StringComparison]::OrdinalIgnoreCase)
}

function Normalize-ModuleNames {
  param([object]$Names)

  $arr = @()
  if ($Names -is [string]) { $arr = @([string]$Names) }
  elseif ($Names -is [System.Collections.IEnumerable]) { $arr = @($Names) }

  $clean = @()
  foreach ($n in $arr) {
    $s = ([string]$n).Trim()
    if ($s.Length -gt 0) { $clean += $s }
  }
  if (-not $clean -or $clean.Count -eq 0) { return @('*') }

  $seen = @{}
  $out = @()
  foreach ($s in $clean) {
    $k = $s.ToLowerInvariant()
    if (-not $seen.ContainsKey($k)) {
      $seen[$k] = $true
      $out += $s
    }
  }

  if ($out.Count -eq 0) { return @('*') }
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

  if ($Value -is [int] -or $Value -is [long] -or $Value -is [byte]) {
    if ([int]$Value -eq 1) { $Parsed.Value = $true; return $true }
    if ([int]$Value -eq 0) { $Parsed.Value = $false; return $true }
    return $false
  }

  $s = ([string]$Value).Trim()
  if ($s.Length -eq 0) { return $false }

  switch -Regex ($s.ToLowerInvariant()) {
    '^(true|\$true|yes|y|on|enable|enabled)$'        { $Parsed.Value = $true; return $true }
    '^(false|\$false|no|n|off|disable|disabled)$'   { $Parsed.Value = $false; return $true }
    '^(1)$'                                         { $Parsed.Value = $true; return $true }
    '^(0)$'                                         { $Parsed.Value = $false; return $true }
    default                                         { return $false }
  }
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
  param([string]$BasePath)

  $transPath = Join-Path $BasePath 'Transcription'
  $sbPath    = Join-Path $BasePath 'ScriptBlockLogging'
  $modPath   = Join-Path $BasePath 'ModuleLogging'
  $modNames  = Join-Path $modPath 'ModuleNames'

  [pscustomobject]@{
    PolicyBasePath                                = $BasePath

    Transcription_EnableTranscripting              = Get-RegValue -Path $transPath -Name 'EnableTranscripting'
    Transcription_OutputDirectory                  = Get-RegValue -Path $transPath -Name 'OutputDirectory'
    Transcription_EnableInvocationHeader           = Get-RegValue -Path $transPath -Name 'EnableInvocationHeader'

    ScriptBlock_EnableScriptBlockLogging           = Get-RegValue -Path $sbPath -Name 'EnableScriptBlockLogging'
    ScriptBlock_EnableScriptBlockInvocationLogging = Get-RegValue -Path $sbPath -Name 'EnableScriptBlockInvocationLogging'

    Module_EnableModuleLogging                     = Get-RegValue -Path $modPath -Name 'EnableModuleLogging'
    ModuleNames_Configured                         = Get-ModuleNamesConfigured -ModuleNamesKeyPath $modNames
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

    Transcription_EnableTranscripting              = if ($null -ne $HKLM.Transcription_EnableTranscripting) { $HKLM.Transcription_EnableTranscripting } else { $HKCU.Transcription_EnableTranscripting }
    Transcription_OutputDirectory                  = if ($null -ne $HKLM.Transcription_OutputDirectory)     { $HKLM.Transcription_OutputDirectory }     else { $HKCU.Transcription_OutputDirectory }
    Transcription_EnableInvocationHeader           = if ($null -ne $HKLM.Transcription_EnableInvocationHeader) { $HKLM.Transcription_EnableInvocationHeader } else { $HKCU.Transcription_EnableInvocationHeader }

    ScriptBlock_EnableScriptBlockLogging           = if ($null -ne $HKLM.ScriptBlock_EnableScriptBlockLogging) { $HKLM.ScriptBlock_EnableScriptBlockLogging } else { $HKCU.ScriptBlock_EnableScriptBlockLogging }
    ScriptBlock_EnableScriptBlockInvocationLogging = if ($null -ne $HKLM.ScriptBlock_EnableScriptBlockInvocationLogging) { $HKLM.ScriptBlock_EnableScriptBlockInvocationLogging } else { $HKCU.ScriptBlock_EnableScriptBlockInvocationLogging }

    Module_EnableModuleLogging                     = if ($null -ne $HKLM.Module_EnableModuleLogging) { $HKLM.Module_EnableModuleLogging } else { $HKCU.Module_EnableModuleLogging }
    ModuleNames_Configured                         = if ($HKLM.ModuleNames_Configured) { $HKLM.ModuleNames_Configured } else { $HKCU.ModuleNames_Configured }
  }
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
  $summary = [pscustomobject]@{
    ComputerName = $env:COMPUTERNAME
    Timestamp    = Get-Date
    Mode         = $Mode
    Supported    = $false
    Notes        = @('Skipped: PowerShell logging baseline auditing is only supported on Windows hosts.')
  }

  $result = New-V2ResultObject -ScriptName '31-PowerShell-Logging-Baseline.ps1' -Mode $Mode -Result 'OK' -Findings @() -Summary $summary -Metadata @{ UnsupportedHost = $true }
  Write-ResultObject -ResultObject $result -OutputFormat $OutputFormat -OutputPath $OutputPath
  if ($PassThru) { $result }
  exit 0
}

Require-Admin

$Findings = New-FindingsList

# Defaults (used when JSON missing/invalid)
$defaults = @{
  TranscriptOutputDirectory           = "$env:ProgramData\PowerShellTranscripts"
  EnableTranscription                = $true
  EnableInvocationHeader             = $true
  EnableScriptBlockLogging           = $true
  EnableScriptBlockInvocationLogging = $false
  EnableModuleLogging                = $true
  ModuleNames                        = @('*')
}

$sanitized = if ([string]::IsNullOrWhiteSpace($ConfigJsonPath)) { $null } else { Sanitize-Path -Path $ConfigJsonPath -MustExist }
if (-not $sanitized -and -not [string]::IsNullOrWhiteSpace($ConfigJsonPath)) {
  Add-Finding -FindingList $Findings -Code 'PSLOG-ConfigJsonMissing' -Severity 'Info' -Message 'Config JSON not found; using defaults.'
}
$cfgResult = Read-ConfigWithDefaults -Path $sanitized -Defaults $defaults
$config = $cfgResult.Config
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
  Add-Finding -FindingList $Findings -Code $code -Severity 'Info' -Message $msg
}

$targetTranscriptDir = if ($PSBoundParameters.ContainsKey('TranscriptOutputDirectory') -and -not [string]::IsNullOrWhiteSpace($TranscriptOutputDirectory)) {
  $TranscriptOutputDirectory
} elseif (-not [string]::IsNullOrWhiteSpace([string]$config.TranscriptOutputDirectory)) {
  [string]$config.TranscriptOutputDirectory
} else {
  "$env:ProgramData\PowerShellTranscripts"
}

$targetEnableTranscription = Resolve-Bool -ParameterValue $EnableTranscription -ParameterWasBound $PSBoundParameters.ContainsKey('EnableTranscription') -ConfigValue $config.EnableTranscription -DefaultValue $true -NameForFinding 'EnableTranscription' -Findings $Findings
$targetEnableInvocationHeader = Resolve-Bool -ParameterValue $EnableInvocationHeader -ParameterWasBound $PSBoundParameters.ContainsKey('EnableInvocationHeader') -ConfigValue $config.EnableInvocationHeader -DefaultValue $true -NameForFinding 'EnableInvocationHeader' -Findings $Findings
$targetEnableScriptBlockLogging = Resolve-Bool -ParameterValue $EnableScriptBlockLogging -ParameterWasBound $PSBoundParameters.ContainsKey('EnableScriptBlockLogging') -ConfigValue $config.EnableScriptBlockLogging -DefaultValue $true -NameForFinding 'EnableScriptBlockLogging' -Findings $Findings
$targetEnableScriptBlockInvocationLogging = Resolve-Bool -ParameterValue $EnableScriptBlockInvocationLogging -ParameterWasBound $PSBoundParameters.ContainsKey('EnableScriptBlockInvocationLogging') -ConfigValue $config.EnableScriptBlockInvocationLogging -DefaultValue $false -NameForFinding 'EnableScriptBlockInvocationLogging' -Findings $Findings
$targetEnableModuleLogging = Resolve-Bool -ParameterValue $EnableModuleLogging -ParameterWasBound $PSBoundParameters.ContainsKey('EnableModuleLogging') -ConfigValue $config.EnableModuleLogging -DefaultValue $true -NameForFinding 'EnableModuleLogging' -Findings $Findings

$targetModuleNames = if ($PSBoundParameters.ContainsKey('ModuleNames')) { $ModuleNames } else { $config.ModuleNames }
$targetModuleNames = Normalize-ModuleNames -Names $targetModuleNames

if ($targetEnableTranscription -and -not (Test-IsSafeTranscriptPath -Path $targetTranscriptDir)) {
  Add-Finding -FindingList $Findings -Code 'PSLOG-TranscriptPathNotProgramData' -Severity 'Info' -Message 'Transcript output directory is not under ProgramData (review ACLs and data exposure risk).'
}

$hklmBase = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell'
$hkcuBase = 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\PowerShell'

$currentHKLM = Get-SettingsForBase -BasePath $hklmBase
$currentHKCU = if ($IncludeHKCU) { Get-SettingsForBase -BasePath $hkcuBase } else { $null }
$effectiveBefore = if ($IncludeHKCU -and $currentHKCU) { Get-EffectiveSettings -HKLM $currentHKLM -HKCU $currentHKCU } else { $currentHKLM }

# Audit findings (effective)
if ($targetEnableTranscription -and $effectiveBefore.Transcription_EnableTranscripting -ne 1) {
  Add-Finding -Code 'PSLOG-TranscriptionOff' -Severity 'Medium' -Message 'Transcription is not enabled (effective policy).'
}
if ($targetEnableInvocationHeader -and $targetEnableTranscription -and $effectiveBefore.Transcription_EnableInvocationHeader -ne 1) {
  Add-Finding -Code 'PSLOG-InvocationHeaderOff' -Severity 'Low' -Message 'Invocation Header is not enabled (effective policy).'
}
if ($targetEnableScriptBlockLogging -and $effectiveBefore.ScriptBlock_EnableScriptBlockLogging -ne 1) {
  Add-Finding -Code 'PSLOG-ScriptBlockOff' -Severity 'Medium' -Message 'Script Block Logging is not enabled (effective policy).'
}
if ($targetEnableScriptBlockInvocationLogging -and $targetEnableScriptBlockLogging -and $effectiveBefore.ScriptBlock_EnableScriptBlockInvocationLogging -ne 1) {
  Add-Finding -Code 'PSLOG-ScriptBlockInvocationOff' -Severity 'Low' -Message 'Script Block Invocation Logging is not enabled (effective policy).'
}
if ($targetEnableModuleLogging -and $effectiveBefore.Module_EnableModuleLogging -ne 1) {
  Add-Finding -Code 'PSLOG-ModuleLoggingOff' -Severity 'Low' -Message 'Module Logging is not enabled (effective policy).'
}

if ($targetEnableScriptBlockLogging -and $Mode -eq 'Audit') {
  Add-Finding -Code 'PSLOG-Recommend-ProtectedEventLogging' -Severity 'Info' -Message 'Consider enabling Protected Event Logging when using Script Block Logging beyond diagnostics.'
}

# Remediate (HKLM only)
if ($Mode -eq 'Remediate') {
  if ($PSCmdlet.ShouldProcess($env:COMPUTERNAME, 'Configure PowerShell logging policy keys (HKLM)')) {

    $transPath = Join-Path $hklmBase 'Transcription'
    $sbPath    = Join-Path $hklmBase 'ScriptBlockLogging'
    $modPath   = Join-Path $hklmBase 'ModuleLogging'
    $modNames  = Join-Path $modPath 'ModuleNames'

    Ensure-RegistryKey -Path $hklmBase
    Ensure-RegistryKey -Path $transPath
    Ensure-RegistryKey -Path $sbPath
    Ensure-RegistryKey -Path $modPath
    Ensure-RegistryKey -Path $modNames

    if ($targetEnableTranscription) {
      Set-RegDword  -Path $transPath -Name 'EnableTranscripting' -Value 1
      Set-RegString -Path $transPath -Name 'OutputDirectory'     -Value $targetTranscriptDir
      if ($targetEnableInvocationHeader) { Set-RegDword -Path $transPath -Name 'EnableInvocationHeader' -Value 1 }
    }

    if ($targetEnableScriptBlockLogging) {
      Set-RegDword -Path $sbPath -Name 'EnableScriptBlockLogging' -Value 1
      if ($targetEnableScriptBlockInvocationLogging) { Set-RegDword -Path $sbPath -Name 'EnableScriptBlockInvocationLogging' -Value 1 }
    }

    if ($targetEnableModuleLogging) {
      Set-RegDword -Path $modPath -Name 'EnableModuleLogging' -Value 1
      Remove-AllModuleNames -ModuleNamesKeyPath $modNames

      $i = 1
      foreach ($m in $targetModuleNames) {
        $null = New-ItemProperty -Path $modNames -Name ([string]$i) -PropertyType String -Value $m -Force
        $i++
      }
    }

    if ($targetEnableTranscription -and -not (Test-Path -LiteralPath $targetTranscriptDir)) {
      $null = New-Item -Path $targetTranscriptDir -ItemType Directory -Force
    }
  }
}

$afterHKLM = Get-SettingsForBase -BasePath $hklmBase
$afterHKCU = if ($IncludeHKCU) { Get-SettingsForBase -BasePath $hkcuBase } else { $null }
$effectiveAfter = if ($IncludeHKCU -and $afterHKCU) { Get-EffectiveSettings -HKLM $afterHKLM -HKCU $afterHKCU } else { $afterHKLM }

$summary = [pscustomobject]@{
  ComputerName  = $env:COMPUTERNAME
  Mode          = $Mode
  FindingsCount = ($Findings | Measure-Object).Count
  Timestamp     = Get-Date

  Target_TranscriptOutputDirectory          = $targetTranscriptDir
  Target_EnableTranscription                = $targetEnableTranscription
  Target_EnableInvocationHeader             = $targetEnableInvocationHeader
  Target_EnableScriptBlockLogging           = $targetEnableScriptBlockLogging
  Target_EnableScriptBlockInvocationLogging = $targetEnableScriptBlockInvocationLogging
  Target_EnableModuleLogging                = $targetEnableModuleLogging
  Target_ModuleNames                        = @($targetModuleNames)

  ConfigJsonPath                            = if ($ConfigJsonPath) { 'PATH/TO/JSON' } else { $null }
  PolicyBasePath                            = $hklmBase
  IncludeHKCU                               = [bool]$IncludeHKCU
}

if ($ExportPath) {
  $dir = Split-Path -Path $ExportPath -Parent
  if ($dir -and -not (Test-Path -LiteralPath $dir)) { $null = New-Item -Path $dir -ItemType Directory -Force }
  $summary | Export-Csv -Path $ExportPath -NoTypeInformation -Encoding UTF8
}

if (-not $QuietConsole) {
  $t  = Format-PolicyValue $effectiveAfter.Transcription_EnableTranscripting
  $sb = Format-PolicyValue $effectiveAfter.ScriptBlock_EnableScriptBlockLogging
  $ml = Format-PolicyValue $effectiveAfter.Module_EnableModuleLogging
  $modNamesStr = if ($effectiveAfter.ModuleNames_Configured) {
    $vals = @(); foreach ($p in $effectiveAfter.ModuleNames_Configured.PSObject.Properties) { $vals += ("{0}={1}" -f $p.Name, $p.Value) }; $vals -join '; '
  } else { 'NotConfigured' }

  $customFields = [ordered]@{
    'Mode'          = $summary.Mode
    'Transcript'    = ("{0} (target={1})" -f $t, $summary.Target_EnableTranscription)
    'SBLogging'     = ("{0} (target={1})" -f $sb, $summary.Target_EnableScriptBlockLogging)
    'ModuleLog'     = ("{0} (target={1})" -f $ml, $summary.Target_EnableModuleLogging)
    'ModuleNames'   = $modNamesStr
    'TranscriptDir' = Format-PolicyValue $effectiveAfter.Transcription_OutputDirectory
  }
  $findingsAL = [System.Collections.ArrayList]@($Findings)
  Write-ConsoleSummary -Summary $summary -Findings $findingsAL `
    -Title 'PowerShell Logging Baseline' `
    -CustomFields $customFields
}

# V2 output contract
$resultToken = if ($Strict -and $Findings.Count -gt 0) { 'FAIL' } elseif ($Findings.Count -gt 0) { 'WARN' } else { 'OK' }
$v2Result = New-V2ResultObject -ScriptName '31-PowerShell-Logging-Baseline.ps1' -Mode $Mode -Result $resultToken -Findings @($Findings) -Summary $summary -Metadata @{ Current = [pscustomobject]@{ HKLM = [pscustomobject]@{ Before = $currentHKLM; After = $afterHKLM }; HKCU = if ($IncludeHKCU) { [pscustomobject]@{ Before = $currentHKCU; After = $afterHKCU } } else { $null }; Effective = [pscustomobject]@{ Before = $effectiveBefore; After = $effectiveAfter } } }
Write-ResultObject -ResultObject $v2Result -OutputFormat $OutputFormat -OutputPath $OutputPath
if ($PassThru) { $v2Result }
exit 0
