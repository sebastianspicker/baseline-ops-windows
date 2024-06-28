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
AuditOnly | Remediate

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
If set, suppresses pretty console output (no Write-Host summary).

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
  [ValidateSet('AuditOnly', 'Remediate')]
  [string]$Mode = 'AuditOnly',

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
)

$script:LibPath = Join-Path $PSScriptRoot 'lib'
Import-Module (Join-Path $script:LibPath 'Common.psm1') -Force
Import-Module (Join-Path $script:LibPath 'Registry.psm1') -Force
Import-Module (Join-Path $script:LibPath 'Config.psm1') -Force
Import-Module (Join-Path $script:LibPath 'Results.psm1') -Force


Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ---------------------------
# Helpers (no pipeline output)
# ---------------------------


function Ensure-Key {
  param([string]$Path)
  if (-not (Test-Path -LiteralPath $Path)) { $null = New-Item -Path $Path -Force }
}


function Set-RegString {
  param([string]$Path, [string]$Name, [string]$Value)
  $null = New-ItemProperty -Path $Path -Name $Name -PropertyType String -Value $Value -Force
}

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
    Remove-ItemProperty -Path $ModuleNamesKeyPath -Name $p -ErrorAction SilentlyContinue
  }
}

function Test-IsSafeTranscriptPath {
  param([string]$Path)

  if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
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

function Write-ColorLine {
  param(
    [string]$Text,
    [ValidateSet('Gray','White','Green','Yellow','Red','Cyan','Magenta')]
    [string]$Color = 'Gray'
  )
  Write-Host $Text -ForegroundColor $Color
}

function Severity-ToColor {
  param([string]$Severity)
  switch ($Severity) {
    'High'   { 'Red' }
    'Medium' { 'Yellow' }
    'Low'    { 'Cyan' }
    'Info'   { 'Gray' }
    default  { 'Gray' }
  }
}

function Write-ConsoleSummary {
  param(
    [pscustomobject]$Summary,
    [object[]]$Findings,
    [pscustomobject]$EffectiveAfter
  )

  Write-Host ''
  Write-ColorLine '=== PowerShell Logging Baseline ===' 'White'
  Write-ColorLine ("ComputerName : {0}" -f $Summary.ComputerName) 'Gray'
  Write-ColorLine ("Mode         : {0}" -f $Summary.Mode) 'Gray'
  Write-ColorLine ("Timestamp    : {0}" -f $Summary.Timestamp) 'Gray'
  Write-Host ''

  $statusColor = if ($Summary.FindingsCount -gt 0) { 'Yellow' } else { 'Green' }
  Write-ColorLine ("Findings     : {0}" -f $Summary.FindingsCount) $statusColor
  Write-Host ''

  Write-ColorLine 'Configured (target) settings:' 'White'
  Write-ColorLine ("- Transcription            : {0}" -f $Summary.Target_EnableTranscription) 'Gray'
  Write-ColorLine ("- InvocationHeader         : {0}" -f $Summary.Target_EnableInvocationHeader) 'Gray'
  Write-ColorLine ("- ScriptBlockLogging       : {0}" -f $Summary.Target_EnableScriptBlockLogging) 'Gray'
  Write-ColorLine ("- ScriptBlockInvocationLog : {0}" -f $Summary.Target_EnableScriptBlockInvocationLogging) 'Gray'
  Write-ColorLine ("- ModuleLogging            : {0}" -f $Summary.Target_EnableModuleLogging) 'Gray'
  Write-ColorLine ("- TranscriptDirectory      : {0}" -f $Summary.Target_TranscriptOutputDirectory) 'Gray'
  Write-ColorLine ("- ModuleNames              : {0}" -f ($Summary.Target_ModuleNames -join ', ')) 'Gray'
  Write-Host ''

  Write-ColorLine 'Effective policy (after run):' 'White'
  $t = Format-PolicyValue $EffectiveAfter.Transcription_EnableTranscripting
  $sb = Format-PolicyValue $EffectiveAfter.ScriptBlock_EnableScriptBlockLogging
  $ml = Format-PolicyValue $EffectiveAfter.Module_EnableModuleLogging

  Write-ColorLine ("- Transcription enabled    : {0}" -f $t) ($(if ($t -eq '1') { 'Green' } elseif ($t -eq 'NotConfigured') { 'Yellow' } else { 'Red' }))
  Write-ColorLine ("- Transcript directory     : {0}" -f (Format-PolicyValue $EffectiveAfter.Transcription_OutputDirectory)) 'Gray'
  Write-ColorLine ("- InvocationHeader         : {0}" -f (Format-PolicyValue $EffectiveAfter.Transcription_EnableInvocationHeader)) 'Gray'
  Write-ColorLine ("- ScriptBlockLogging       : {0}" -f $sb) ($(if ($sb -eq '1') { 'Green' } elseif ($sb -eq 'NotConfigured') { 'Yellow' } else { 'Red' }))
  Write-ColorLine ("- ScriptBlockInvocationLog : {0}" -f (Format-PolicyValue $EffectiveAfter.ScriptBlock_EnableScriptBlockInvocationLogging)) 'Gray'
  Write-ColorLine ("- ModuleLogging            : {0}" -f $ml) ($(if ($ml -eq '1') { 'Green' } elseif ($ml -eq 'NotConfigured') { 'Yellow' } else { 'Red' }))

  if ($EffectiveAfter.ModuleNames_Configured) {
    $vals = @()
    foreach ($p in $EffectiveAfter.ModuleNames_Configured.PSObject.Properties) {
      $vals += ("{0}={1}" -f $p.Name, $p.Value)
    }
    Write-ColorLine ("- ModuleNames              : {0}" -f ($vals -join '; ')) 'Gray'
  } else {
    Write-ColorLine '- ModuleNames              : NotConfigured' 'Yellow'
  }

  Write-Host ''
  if ($Findings.Count -gt 0) {
    Write-ColorLine 'Findings (top 10):' 'White'
    $top = $Findings | Select-Object -First 10
    foreach ($f in $top) {
      $c = Severity-ToColor $f.Severity
      Write-ColorLine ("- [{0}] {1}: {2}" -f $f.Severity, $f.Code, $f.Message) $c
    }
    if ($Findings.Count -gt 10) {
      Write-ColorLine ("(Only first 10 shown; total: {0})" -f $Findings.Count) 'Gray'
    }
  } else {
    Write-ColorLine 'Findings: none' 'Green'
  }

  Write-Host ''
  Write-ColorLine '================================' 'White'
  Write-Host ''
}

# ---------------------------
# Main
# ---------------------------
if (-not (Test-IsAdmin)) { throw 'Administrative privileges required.' }

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

$cfgResult = Read-ConfigWithDefaults -Path $ConfigJsonPath -Defaults $defaults
$config = $cfgResult.Config
if ($cfgResult.Meta.Provided -and -not $cfgResult.Meta.Loaded) {
  $code = 'PSLOG-ConfigJsonInvalid'
  $msg = 'Config JSON could not be loaded/parsed; using defaults.'
  if ($cfgResult.Meta.Error -eq 'ConfigPath not found.') {
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
  Add-Finding -FindingList $Findings -Code 'PSLOG-TranscriptionOff' -Severity 'Medium' -Message 'Transcription is not enabled (effective policy).'
}
if ($targetEnableInvocationHeader -and $targetEnableTranscription -and $effectiveBefore.Transcription_EnableInvocationHeader -ne 1) {
  Add-Finding -FindingList $Findings -Code 'PSLOG-InvocationHeaderOff' -Severity 'Low' -Message 'Invocation Header is not enabled (effective policy).'
}
if ($targetEnableScriptBlockLogging -and $effectiveBefore.ScriptBlock_EnableScriptBlockLogging -ne 1) {
  Add-Finding -FindingList $Findings -Code 'PSLOG-ScriptBlockOff' -Severity 'Medium' -Message 'Script Block Logging is not enabled (effective policy).'
}
if ($targetEnableScriptBlockInvocationLogging -and $targetEnableScriptBlockLogging -and $effectiveBefore.ScriptBlock_EnableScriptBlockInvocationLogging -ne 1) {
  Add-Finding -FindingList $Findings -Code 'PSLOG-ScriptBlockInvocationOff' -Severity 'Low' -Message 'Script Block Invocation Logging is not enabled (effective policy).'
}
if ($targetEnableModuleLogging -and $effectiveBefore.Module_EnableModuleLogging -ne 1) {
  Add-Finding -FindingList $Findings -Code 'PSLOG-ModuleLoggingOff' -Severity 'Low' -Message 'Module Logging is not enabled (effective policy).'
}

if ($targetEnableScriptBlockLogging -and $Mode -eq 'AuditOnly') {
  Add-Finding -FindingList $Findings -Code 'PSLOG-Recommend-ProtectedEventLogging' -Severity 'Info' -Message 'Consider enabling Protected Event Logging when using Script Block Logging beyond diagnostics.'
}

# Remediate (HKLM only)
if ($Mode -eq 'Remediate') {
  if ($PSCmdlet.ShouldProcess($env:COMPUTERNAME, 'Configure PowerShell logging policy keys (HKLM)')) {

    $transPath = Join-Path $hklmBase 'Transcription'
    $sbPath    = Join-Path $hklmBase 'ScriptBlockLogging'
    $modPath   = Join-Path $hklmBase 'ModuleLogging'
    $modNames  = Join-Path $modPath 'ModuleNames'

    Ensure-Key -Path $hklmBase
    Ensure-Key -Path $transPath
    Ensure-Key -Path $sbPath
    Ensure-Key -Path $modPath
    Ensure-Key -Path $modNames

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
  Write-ConsoleSummary -Summary $summary -Findings @($Findings) -EffectiveAfter $effectiveAfter
}

# Pipeline output: exactly one object, no "pretty" strings.
#[pscustomobject]@{
#  Summary  = $summary
#  Findings = @($Findings)
#  Current  = [pscustomobject]@{
#    HKLM      = [pscustomobject]@{ Before = $currentHKLM; After = $afterHKLM }
#    HKCU      = if ($IncludeHKCU) { [pscustomobject]@{ Before = $currentHKCU; After = $afterHKCU } } else { $null }
#    Effective = [pscustomobject]@{ Before = $effectiveBefore; After = $effectiveAfter }
#  }
#}
