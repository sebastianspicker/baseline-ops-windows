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
# v2-init (migrated to Initialize-V2Context)
$script:__V2Context = Initialize-V2Context -ScriptName '41-NTLM-Audit-Client.ps1' -BoundParameters $PSBoundParameters `
  -Mode $Mode -ConfigPath $ConfigPath -OutputFormat $OutputFormat -OutputPath $OutputPath `
  -PassThru:$PassThru -Strict:$Strict -Quiet:$Quiet -NoColor:$NoColor
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

  switch ($Value) {
    0 { 'Send LM & NTLM responses' }
    1 { 'Send LM & NTLM - use NTLMv2 session security if negotiated' }
    2 { 'Send NTLM responses only' }
    3 { 'Send NTLMv2 responses only' }
    4 { 'Send NTLMv2 responses only. Refuse LM' }
    5 { 'Send NTLMv2 responses only. Refuse LM & NTLM' }
    $null { 'Not defined (registry value missing)' }
    default { "Unknown($Value)" }
  }
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

function Merge-Config {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)] [pscustomobject]$Base,
    [Parameter(Mandatory)] [pscustomobject]$Override
  )

  $cfg = [pscustomobject]@{
    MinimumLevel      = $Base.MinimumLevel
    SeverityTooLow    = $Base.SeverityTooLow
    SeverityLmAllowed = $Base.SeverityLmAllowed
    SeverityNtlmv1    = $Base.SeverityNtlmv1
    EmitInfoFindings  = $Base.EmitInfoFindings
    ConsoleMode       = $Base.ConsoleMode
  }

  if ($null -ne $Override.MinimumLevel -and $Override.MinimumLevel -is [int] -and $Override.MinimumLevel -ge 0 -and $Override.MinimumLevel -le 5) {
    $cfg.MinimumLevel = [int]$Override.MinimumLevel
  }

  foreach ($k in 'SeverityTooLow','SeverityLmAllowed','SeverityNtlmv1') {
    if ($null -ne $Override.$k) {
      $sv = [string]$Override.$k
      if ($sv -in @('Info','Low','Medium','High')) { $cfg.$k = $sv }
    }
  }

  if ($null -ne $Override.EmitInfoFindings) {
    $cfg.EmitInfoFindings = [bool]$Override.EmitInfoFindings
  }

  if ($null -ne $Override.ConsoleMode) {
    $cm = [string]$Override.ConsoleMode
    if ($cm -in @('Pretty','Plain')) { $cfg.ConsoleMode = $cm }
  }

  $cfg
}

function Import-JsonConfigOrDefault {
  [CmdletBinding()]
  param(
    [string]$Path,
    [Parameter(Mandatory)] [pscustomobject]$DefaultConfig
  )

  if ([string]::IsNullOrWhiteSpace($Path)) { return $DefaultConfig }
  if (-not (Test-Path -LiteralPath $Path)) { return $DefaultConfig }

  try {
    $raw = Get-BoundedUtf8FileContent -Path $Path -MaximumBytes 1048576
    if ([string]::IsNullOrWhiteSpace($raw)) { return $DefaultConfig }

    # Use try/catch so invalid JSON produces a controlled fallback.
    $j = $raw | ConvertFrom-Json
    if ($null -eq $j) { return $DefaultConfig }

    Merge-Config -Base $DefaultConfig -Override $j
  } catch {
    $DefaultConfig
  }
}


# Write-ConsoleSummary imported from lib/Console.psm1

#endregion Helpers

#region Config
$defaultConfig = Get-DefaultConfig -CliMinimumLevel $MinimumLevel
$config        = Import-JsonConfigOrDefault -Path $ConfigPath -DefaultConfig $defaultConfig
$MinimumLevel  = $config.MinimumLevel

# Track whether a config file was successfully loaded (without leaking internal paths).
$configLoaded = $false
if (-not [string]::IsNullOrWhiteSpace($ConfigPath) -and (Test-Path -LiteralPath $ConfigPath)) {
  try {
    $raw = Get-BoundedUtf8FileContent -Path $ConfigPath -MaximumBytes 1048576
    if (-not [string]::IsNullOrWhiteSpace($raw)) {
      $null = $raw | ConvertFrom-Json
      $configLoaded = $true
    }
  } catch {
    $configLoaded = $false
  }
}
#endregion Config

#region Audit
$findings = Get-FindingsList

$lsaPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
$val     = Get-RegDwordOrNull -Path $lsaPath -Name 'LmCompatibilityLevel'
$valText = Convert-LmCompatibilityLevelToText -Value $val

if ($null -eq $val) {
  Add-Finding -FindingList $findings -Code 'NTLM-LmCompatibilityNotDefined' -Severity 'Info' -Message `
    'LmCompatibilityLevel is not set (policy not defined). Effective defaults may still apply; validate via GPO/RSOP if needed.'
} else {
  if ($val -lt $MinimumLevel) {
    Add-Finding -FindingList $findings -Code 'NTLM-LmCompatibilityTooLow' -Severity $config.SeverityTooLow -Message `
      ('LmCompatibilityLevel={0} ({1}) is below MinimumLevel={2}.' -f $val, $valText, $MinimumLevel)
  }

  if ($val -le 1) {
    Add-Finding -FindingList $findings -Code 'NTLM-LMAllowed' -Severity $config.SeverityLmAllowed -Message `
      ('LmCompatibilityLevel={0} ({1}) allows LM/NTLM. Recommended minimum is 3 (NTLMv2 only), if compatible.' -f $val, $valText)
  } elseif ($val -eq 2) {
    Add-Finding -FindingList $findings -Code 'NTLM-NTLMv1ClientAuth' -Severity $config.SeverityNtlmv1 -Message `
      'LmCompatibilityLevel=2 implies NTLMv1 for client auth (Send NTLM response only). Recommended minimum is 3 (NTLMv2), if compatible.'
  } else {
    if ($config.EmitInfoFindings) {
      if ($val -ge 3 -and $val -lt 5) {
        Add-Finding -FindingList $findings -Code 'NTLM-NTLMv2ClientOnly' -Severity 'Info' -Message `
          ('LmCompatibilityLevel={0} ({1}). Client uses NTLMv2; depending on level, LM/NTLM may still be accepted.' -f $val, $valText)
      } elseif ($val -eq 5) {
        Add-Finding -FindingList $findings -Code 'NTLM-Strictest' -Severity 'Info' -Message `
          'LmCompatibilityLevel=5 is the strictest setting (refuse LM and NTLM). Verify legacy compatibility before enforcing broadly.'
      }
    }
  }
}
#endregion Audit

#region Output objects (pipeline-safe)
$summary = [pscustomobject]@{
  ComputerName         = $env:COMPUTERNAME
  LmCompatibilityLevel = $val
  LmCompatibilityText  = $valText
  MinimumLevel         = $MinimumLevel
  FindingsCount        = $findings.Count
  Timestamp            = Get-Date
  ConfigLoaded         = $configLoaded
  ConfigPath           = $(if ([string]::IsNullOrWhiteSpace($ConfigPath)) { $null } else { '[configured path]' })
}
#endregion Output objects (pipeline-safe)

#region Export
if ($ExportPath) {
  [void](Ensure-DirectoryForFile -FilePath $ExportPath)

  # Windows PowerShell 5.1 writes UTF-8 with BOM for -Encoding UTF8; keep for broad CSV/tool compatibility.
  $summary | Export-Csv -Path $ExportPath -NoTypeInformation -Encoding UTF8

  $base   = [IO.Path]::GetFileNameWithoutExtension($ExportPath)
  $folder = Split-Path -Path $ExportPath -Parent
  if (-not $folder) { $folder = (Get-Location).Path }

  $findings | Export-Csv -Path (Join-Path $folder ($base + '_findings.csv')) -NoTypeInformation -Encoding UTF8
}
#endregion Export

#region Console-only output (no pipeline pollution)
$lvlValue = if ($null -eq $summary.LmCompatibilityLevel) { '<not set>' } else { [string]$summary.LmCompatibilityLevel }
$customFields = [ordered]@{
  'LmLevel'    = ("{0} ({1})" -f $lvlValue, $summary.LmCompatibilityText)
  'MinLevel'   = [string]$summary.MinimumLevel
  'ConfigLoad' = [string]$summary.ConfigLoaded
}
$findingsAL = ConvertTo-ArrayList -InputObject $findings
Write-ConsoleSummary -Summary $summary -Findings $findingsAL `
  -Title 'NTLM Audit (LmCompatibilityLevel)' `
  -CustomFields $customFields
#endregion Console-only output

# V2 output contract
$resultToken = if ($Strict -and $findings.Count -gt 0) { 'FAIL' } elseif ($findings.Count -gt 0) { 'WARN' } else { 'OK' }
$v2Result = Get-V2ResultObject -ScriptName '41-NTLM-Audit-Client.ps1' -Mode $Mode -Result $resultToken -Findings (ConvertTo-ObjectArray -InputObject $findings) -Summary $summary -Metadata @{}
Write-ResultObject -ResultObject $v2Result -OutputFormat $OutputFormat -OutputPath $OutputPath
if ($PassThru) { $v2Result }
exit (Get-V2ExitCode -Result $resultToken)
