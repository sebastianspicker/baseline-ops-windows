#requires -version 5.1
<#
.SYNOPSIS
Audit NTLM / LAN Manager Authentication Level (LmCompatibilityLevel) with quick findings (Windows PowerShell 5.1).

.DESCRIPTION
Reads HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\LmCompatibilityLevel, evaluates it against a minimum level,
creates findings, optionally exports CSV, and prints a console summary.

Design goals:
- Pipeline output: structured objects only (works cleanly with Export-Csv / ConvertTo-Json / Where-Object).
- Console output: display-only formatting via Write-UiLine / Write-Information (never via pipeline strings).

.PARAMETER MinimumLevel
Minimum accepted level (0..5). Default is 3.

.PARAMETER ExportPath
Optional CSV path for the summary. Findings are exported as "<base>_findings.csv" in the same folder.

.PARAMETER ConfigPath
Optional JSON config file path supplied with $ConfigPath.
If present, settings override defaults; if missing/invalid, defaults are used.

.JSON (optional)
Supported properties (all optional):
{
  "MinimumLevel": 3,
  "SeverityTooLow": "High",
  "SeverityLmAllowed": "High",
  "SeverityNtlmv1": "Medium",
  "EmitInfoFindings": true,
  "ConsoleMode": "Pretty"   // Pretty|Plain
}


.PARAMETER Mode
  Execution mode. 'Audit' reports only; 'Remediate' applies changes.

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
Pipeline emits:
- Summary (1 object)
- Findings (0..n objects)
.EXAMPLE
  .\41-NTLM-Audit-Client.ps1

#>


[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
  [ValidateRange(0,5)]
  [int]$MinimumLevel = 3,

  [string]$ExportPath,

  [string]$ConfigPath

,
  [ValidateSet('Audit','Remediate')][string]$Mode = 'Audit',
  [ValidateSet('Console','Json','Csv','None')][string]$OutputFormat = 'Console',
  [string]$OutputPath,
  [switch]$PassThru,
  [switch]$Strict,
  [switch]$Quiet,
  [switch]$NoColor
)

. (Join-Path $PSScriptRoot '_lib/Bootstrap.ps1')
Import-Module (Join-Path $script:LibPath 'Output.psm1') -Force
Import-Module (Join-Path $script:LibPath 'Common.psm1') -Force -DisableNameChecking
Import-Module (Join-Path $script:LibPath 'Console.psm1') -Force
Import-Module (Join-Path $script:LibPath 'Registry.psm1') -Force -DisableNameChecking
Import-Module (Join-Path $script:LibPath 'Results.psm1') -Force
Import-Module (Join-Path $script:LibPath Serialization.psm1) -Force


Set-StrictMode -Version Latest
$script:__V2Context = Initialize-V2Context -ScriptName '41-NTLM-Audit-Client.ps1' -BoundParameters $PSBoundParameters `
  -Values @{ Mode = $Mode; ConfigPath = $ConfigPath; OutputFormat = $OutputFormat; OutputPath = $OutputPath; PassThru = $PassThru; Strict = $Strict; Quiet = $Quiet; NoColor = $NoColor; DeriveRemediate = $false }
if ($script:__V2Context.Quiet) { $InformationPreference = 'SilentlyContinue'; $VerbosePreference = 'SilentlyContinue' }
$script:NoColor = [bool]$script:__V2Context.NoColor
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
  $unsupportedResult = if ($Strict) { 'FAIL' } else { 'WARN' }
  $result = Get-V2ResultObject -ScriptName '41-NTLM-Audit-Client.ps1' -Mode $Mode -Result $unsupportedResult -Findings @() -Summary $summary -Metadata @{ UnsupportedHost = $true }
  Write-ResultObject -ResultObject $result -OutputFormat $OutputFormat -OutputPath $OutputPath
  if ($PassThru) { $result }
  exit (Get-V2ExitCode -Result $unsupportedResult)
}

#region Helpers

function Convert-LmCompatibilityLevelToText {
  [CmdletBinding()]
  param([Nullable[int]]$Value)

  if ($null -eq $Value) { return 'Not defined (registry value missing)' }
  $labels = @('Send LM & NTLM responses', 'Send LM & NTLM - use NTLMv2 session security if negotiated', 'Send NTLM responses only', 'Send NTLMv2 responses only', 'Send NTLMv2 responses only. Refuse LM', 'Send NTLMv2 responses only. Refuse LM & NTLM')
  if ($Value -ge 0 -and $Value -lt $labels.Count) { return $labels[[int]$Value] }
  return "Unknown($Value)"
}

function Get-DefaultConfig {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)] [int]$CliMinimumLevel
  )

  # Conservative defaults (safe for most environments; override via parameters/JSON as needed).
  [pscustomobject]@{
    MinimumLevel      = $CliMinimumLevel
    SeverityTooLow    = 'High'
    SeverityLmAllowed = 'High'
    SeverityNtlmv1    = 'Medium'
    EmitInfoFindings  = $true
    ConsoleMode       = 'Pretty' # Pretty|Plain
  }
}

function Merge-ConfigSection01 {
  param([hashtable]$RunState)
$cfg = [pscustomobject]@{
    MinimumLevel      = $RunState.Base.MinimumLevel
    SeverityTooLow    = $RunState.Base.SeverityTooLow
    SeverityLmAllowed = $RunState.Base.SeverityLmAllowed
    SeverityNtlmv1    = $RunState.Base.SeverityNtlmv1
    EmitInfoFindings  = $RunState.Base.EmitInfoFindings
    ConsoleMode       = $RunState.Base.ConsoleMode
  }

  if ($null -ne $RunState.Override.MinimumLevel -and $RunState.Override.MinimumLevel -is [int] -and $RunState.Override.MinimumLevel -ge 0 -and $RunState.Override.MinimumLevel -le 5) {
    $cfg.MinimumLevel = [int]$RunState.Override.MinimumLevel
  }
}

function Merge-ConfigSection02 {
  param([hashtable]$RunState)
foreach ($k in 'SeverityTooLow','SeverityLmAllowed','SeverityNtlmv1') {
    if ($null -ne $RunState.Override.$k) {
      $sv = [string]$RunState.Override.$k
      if ($sv -in @('Info','Low','Medium','High')) { $cfg.$k = $sv }
    }
  }

  if ($null -ne $RunState.Override.EmitInfoFindings) {
    $cfg.EmitInfoFindings = [bool]$RunState.Override.EmitInfoFindings
  }
}

function Merge-ConfigSection03 {
  param([hashtable]$RunState)
if ($null -ne $RunState.Override.ConsoleMode) {
    $cm = [string]$RunState.Override.ConsoleMode
    if ($cm -in @('Pretty','Plain')) { $cfg.ConsoleMode = $cm }
  }

  $cfg
}

function Merge-Config {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)] [pscustomobject]$Base,
    [Parameter(Mandatory)] [pscustomobject]$Override
  , [hashtable]$RunState)
  $RunState.Base = $Base
  $RunState.Override = $Override

    . Merge-ConfigSection01 -RunState $RunState
    . Merge-ConfigSection02 -RunState $RunState
    . Merge-ConfigSection03 -RunState $RunState
}

function Import-JsonConfigOrDefault {
  [CmdletBinding()]
  param(
    [string]$Path,
    [Parameter(Mandatory)] [pscustomobject]$DefaultConfig
  , [hashtable]$RunState)

  if ([string]::IsNullOrWhiteSpace($Path)) { return $DefaultConfig }
  if (-not (Test-Path -LiteralPath $Path)) { return $DefaultConfig }

  try {
    $raw = Get-BoundedUtf8FileContent -Path $Path -MaximumBytes 1048576
    if ([string]::IsNullOrWhiteSpace($raw)) { return $DefaultConfig }

    # Use try/catch so invalid JSON produces a controlled fallback.
    $j = $raw | ConvertFrom-Json
    if ($null -eq $j) { return $DefaultConfig }

    Merge-Config -Base $DefaultConfig -Override $j -RunState $RunState
  } catch {
    $DefaultConfig
  }
}


# Write-ConsoleSummary imported from lib/Console.psm1

#endregion Helpers

#region Config
function Invoke-Capability41MainPhase01 {
  param([hashtable]$RunState)
  $defaultConfig = Get-DefaultConfig -CliMinimumLevel $MinimumLevel
  $config        = Import-JsonConfigOrDefault -Path $ConfigPath -DefaultConfig $defaultConfig -RunState $RunState
  $MinimumLevel  = $config.MinimumLevel

  # Track whether a config file was successfully loaded (without leaking internal paths).
  $RunState.configLoaded = $false
  if (-not [string]::IsNullOrWhiteSpace($ConfigPath) -and (Test-Path -LiteralPath $ConfigPath)) {
    try {
      $raw = Get-BoundedUtf8FileContent -Path $ConfigPath -MaximumBytes 1048576
      if (-not [string]::IsNullOrWhiteSpace($raw)) {
        $null = $raw | ConvertFrom-Json
        $RunState.configLoaded = $true
      }
    } catch {
      $RunState.configLoaded = $false
    }
  }
  #endregion Config

  #region Audit
  $RunState.findings = Get-FindingsList

  $lsaPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
  $val     = Get-RegDwordOrNull -Path $lsaPath -Name 'LmCompatibilityLevel'
  $RunState.valText = Convert-LmCompatibilityLevelToText -Value $val
}
function Invoke-Capability41MainPhase02Step01 {
  param([hashtable]$RunState)
if ($val -lt $MinimumLevel) {
      Add-Finding -FindingList $RunState.findings -Code 'NTLM-LmCompatibilityTooLow' -Severity $config.SeverityTooLow -Message `
        ('LmCompatibilityLevel={0} ({1}) is below MinimumLevel={2}.' -f $val, $RunState.valText, $MinimumLevel)
    }
}

function Invoke-Capability41MainPhase02Step02 {
  param([hashtable]$RunState)
if ($val -le 1) {
      Add-Finding -FindingList $RunState.findings -Code 'NTLM-LMAllowed' -Severity $config.SeverityLmAllowed -Message `
        ('LmCompatibilityLevel={0} ({1}) allows LM/NTLM. Recommended minimum is 3 (NTLMv2 only), if compatible.' -f $val, $RunState.valText)
    } elseif ($val -eq 2) {
      Add-Finding -FindingList $RunState.findings -Code 'NTLM-NTLMv1ClientAuth' -Severity $config.SeverityNtlmv1 -Message `
        'LmCompatibilityLevel=2 implies NTLMv1 for client auth (Send NTLM response only). Recommended minimum is 3 (NTLMv2), if compatible.'
    } else {
      if ($config.EmitInfoFindings) {
        if ($val -ge 3 -and $val -lt 5) {
          Add-Finding -FindingList $RunState.findings -Code 'NTLM-NTLMv2ClientOnly' -Severity 'Info' -Message `
            ('LmCompatibilityLevel={0} ({1}). Client uses NTLMv2; depending on level, LM/NTLM may still be accepted.' -f $val, $RunState.valText)
        } elseif ($val -eq 5) {
          Add-Finding -FindingList $RunState.findings -Code 'NTLM-Strictest' -Severity 'Info' -Message `
            'LmCompatibilityLevel=5 is the strictest setting (refuse LM and NTLM). Verify legacy compatibility before enforcing broadly.'
        }
      }
    }
}

function Invoke-Capability41MainPhase02 {
  param([hashtable]$RunState)
  if ($null -eq $val) {
    Add-Finding -FindingList $RunState.findings -Code 'NTLM-LmCompatibilityNotDefined' -Severity 'Info' -Message `
      'LmCompatibilityLevel is not set (policy not defined). Effective defaults may still apply; validate via GPO/RSOP if needed.'
  } else {
    . Invoke-Capability41MainPhase02Step01 -RunState $RunState
. Invoke-Capability41MainPhase02Step02 -RunState $RunState
  }
}
function Invoke-Capability41MainPhase03 {
  param([hashtable]$RunState)
  $summary = [pscustomobject]@{
    ComputerName         = $env:COMPUTERNAME
    LmCompatibilityLevel = $val
    LmCompatibilityText  = $RunState.valText
    MinimumLevel         = $MinimumLevel
    FindingsCount        = $RunState.findings.Count
    Timestamp            = Get-Date
    ConfigLoaded         = $RunState.configLoaded
    ConfigPath           = $(if ([string]::IsNullOrWhiteSpace($ConfigPath)) { $null } else { '[configured path]' })
  }
  #endregion Output objects (pipeline-safe)

  #region Export
  if ($ExportPath) {
    [void](Ensure-DirectoryForFile -FilePath $ExportPath)

    # Windows PowerShell 5.1 writes UTF-8 with BOM for -Encoding UTF8; keep for broad CSV/tool compatibility.
    $summary | Export-Csv -Path $ExportPath -NoTypeInformation -Encoding UTF8

    $RunState.base   = [IO.Path]::GetFileNameWithoutExtension($ExportPath)
    $folder = Split-Path -Path $ExportPath -Parent
    if (-not $folder) { $folder = (Get-Location).Path }

    $RunState.findings | Export-Csv -Path (Join-Path $folder ($RunState.base + '_findings.csv')) -NoTypeInformation -Encoding UTF8
  }
  #endregion Export

  #region Console-only output (no pipeline pollution)
  $lvlValue = if ($null -eq $summary.LmCompatibilityLevel) { '<not set>' } else { [string]$summary.LmCompatibilityLevel }
  $customFields = [ordered]@{
    'LmLevel'    = ("{0} ({1})" -f $lvlValue, $summary.LmCompatibilityText)
    'MinLevel'   = [string]$summary.MinimumLevel
    'ConfigLoad' = [string]$summary.ConfigLoaded
  }
  $findingsAL = ConvertTo-ArrayList -InputObject $RunState.findings
  Write-ConsoleSummary -Summary $summary -Findings $findingsAL `
    -Title 'NTLM Audit (LmCompatibilityLevel)' `
    -CustomFields $customFields
}
function Invoke-Capability41Main {
  param($EntryBoundParameters, $EntryCmdlet, $EntryInvocation)
  $RunState = @{

  }
  $script:__EntryBoundParameters = $EntryBoundParameters
  $script:__EntryCmdlet = $EntryCmdlet
  $script:__EntryInvocation = $EntryInvocation
  . Invoke-Capability41MainPhase01 -RunState $RunState
  . Invoke-Capability41MainPhase02 -RunState $RunState
  . Invoke-Capability41MainPhase03 -RunState $RunState
  $script:RunState = $RunState
}

. Invoke-Capability41Main -EntryBoundParameters $PSBoundParameters -EntryCmdlet $PSCmdlet -EntryInvocation $MyInvocation
#endregion Console-only output

# V2 output contract
function Get-Capability41ResultToken {
  param([hashtable]$RunState)
  $resultToken = if ($Strict -and $RunState.findings.Count -gt 0) { 'FAIL' } elseif ($RunState.findings.Count -gt 0) { 'WARN' } else { 'OK' }
  return $resultToken
}
$resultToken = Get-Capability41ResultToken -RunState $RunState
$v2Result = Get-V2ResultObject -ScriptName '41-NTLM-Audit-Client.ps1' -Mode $Mode -Result $resultToken -Findings (ConvertTo-ObjectArray -InputObject $RunState.findings) -Summary $summary -Metadata @{}
Write-ResultObject -ResultObject $v2Result -OutputFormat $OutputFormat -OutputPath $OutputPath
if ($PassThru) { $v2Result }
exit (Get-V2ExitCode -Result $resultToken)
