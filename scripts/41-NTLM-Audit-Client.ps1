#requires -version 5.1
<#
.SYNOPSIS
Audit NTLM / LAN Manager Authentication Level (LmCompatibilityLevel) with quick findings (Windows PowerShell 5.1).

.DESCRIPTION
Reads HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\LmCompatibilityLevel, evaluates it against a minimum level,
creates findings, optionally exports CSV, and prints a human-friendly console summary.

Design goals:
- Pipeline output: structured objects only (works cleanly with Export-Csv / ConvertTo-Json / Where-Object).
- Console output: display-only formatting via Write-Host / Write-Information (never via pipeline strings). [web:102][web:106]

.PARAMETER MinimumLevel
Minimum accepted level (0..5). Default is 3.

.PARAMETER ExportPath
Optional CSV path for the summary. Findings are exported as "<base>_findings.csv" in the same folder.

.PARAMETER ConfigPath
Optional JSON config file path (example: "PATH/TO/JSON/ntlm-audit.json").
If present, settings override defaults; if missing/invalid, defaults are used. [web:62][web:65]

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

.OUTPUTS
Pipeline emits:
- Summary (1 object)
- Findings (0..n objects)
.EXAMPLE
  .\41-NTLM-Audit-Client.ps1

#>


[CmdletBinding()]
param(
  [ValidateRange(0,5)]
  [int]$MinimumLevel = 3,

  [string]$ExportPath,

  [string]$ConfigPath
)

$script:LibPath = Join-Path $PSScriptRoot 'lib'
Import-Module (Join-Path $script:LibPath 'Common.psm1') -Force
Import-Module (Join-Path $script:LibPath 'Results.psm1') -Force


Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

#region Helpers

function Get-RegDword {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)] [string]$Path,
    [Parameter(Mandatory)] [string]$Name
  )
  try {
    $p = Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop
    $v = $p.$Name
    if ($null -ne $v) { [int]$v } else { $null }
  } catch {
    $null
  }
}


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
    $raw = Get-Content -LiteralPath $Path -Raw -ErrorAction Stop
    if ([string]::IsNullOrWhiteSpace($raw)) { return $DefaultConfig }

    # ConvertFrom-Json can behave unexpectedly with errors; try/catch is the robust approach. [web:65][web:62]
    $j = $raw | ConvertFrom-Json
    if ($null -eq $j) { return $DefaultConfig }

    Merge-Config -Base $DefaultConfig -Override $j
  } catch {
    $DefaultConfig
  }
}


function Get-SeverityRank {
  [CmdletBinding()]
  param([Parameter(Mandatory)] [ValidateSet('Info','Low','Medium','High')] [string]$Severity)

  switch ($Severity) {
    'High'   { 3 }
    'Medium' { 2 }
    'Low'    { 1 }
    'Info'   { 0 }
  }
}

function Get-SeverityColor {
  [CmdletBinding()]
  param([Parameter(Mandatory)] [ValidateSet('Info','Low','Medium','High')] [string]$Severity)

  switch ($Severity) {
    'High'   { 'Red' }
    'Medium' { 'Yellow' }
    'Low'    { 'Cyan' }
    'Info'   { 'Gray' }
  }
}

function Write-KvLine {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)] [string]$Key,
    [Parameter(Mandatory)] [string]$Value,
    [ConsoleColor]$ValueColor = [ConsoleColor]::Gray
  )

  Write-Host ("{0,-22}: " -f $Key) -NoNewline
  Write-Host $Value -ForegroundColor $ValueColor
}

function Write-ConsoleSummary {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)] [pscustomobject]$Summary,
    [Parameter(Mandatory)] [System.Collections.Generic.List[object]]$Findings,
    [Parameter(Mandatory)] [pscustomobject]$Config
  )

  $sorted = @($Findings | Sort-Object @{ Expression = { Get-SeverityRank $_.Severity }; Descending = $true }, Code)
  $top    = $sorted | Select-Object -First 1

  $bannerColor = 'Green'
  if ($Summary.FindingsCount -gt 0 -and $null -ne $top) {
    if ($top.Severity -eq 'High') { $bannerColor = 'Red' }
    elseif ($top.Severity -eq 'Medium') { $bannerColor = 'Yellow' }
    elseif ($top.Severity -eq 'Low') { $bannerColor = 'Cyan' }
  }

  Write-Host ''
  Write-Host ('=' * 34) -ForegroundColor DarkGray
  Write-Host 'NTLM Audit (LmCompatibilityLevel)' -ForegroundColor $bannerColor
  Write-Host ('=' * 34) -ForegroundColor DarkGray

  Write-KvLine -Key 'ComputerName' -Value $Summary.ComputerName -ValueColor White
  Write-KvLine -Key 'Timestamp' -Value ($Summary.Timestamp.ToString('s')) -ValueColor Gray

  $lvlValue = if ($null -eq $Summary.LmCompatibilityLevel) { '<not set>' } else { [string]$Summary.LmCompatibilityLevel }
  $lvlColor = if ($null -eq $Summary.LmCompatibilityLevel) { 'Yellow' } elseif ($Summary.LmCompatibilityLevel -lt $Summary.MinimumLevel) { 'Red' } else { 'Green' }

  Write-KvLine -Key 'LmCompatibilityLevel' -Value $lvlValue -ValueColor $lvlColor
  Write-KvLine -Key 'LmCompatibilityText' -Value $Summary.LmCompatibilityText -ValueColor Gray
  Write-KvLine -Key 'MinimumLevel' -Value ([string]$Summary.MinimumLevel) -ValueColor Gray
  Write-KvLine -Key 'FindingsCount' -Value ([string]$Summary.FindingsCount) -ValueColor $(if ($Summary.FindingsCount -gt 0) { 'Yellow' } else { 'Green' })
  Write-KvLine -Key 'ConfigLoaded' -Value ([string]$Summary.ConfigLoaded) -ValueColor $(if ($Summary.ConfigLoaded) { 'Green' } else { 'DarkGray' })

  if ($null -ne $top) {
    $c = Get-SeverityColor -Severity $top.Severity
    Write-KvLine -Key 'TopFinding' -Value ("{0} ({1})" -f $top.Severity, $top.Code) -ValueColor $c
  } else {
    Write-KvLine -Key 'TopFinding' -Value 'None' -ValueColor Green
  }

  $counts = @{ High = 0; Medium = 0; Low = 0; Info = 0 }
  foreach ($g in ($Findings | Group-Object Severity)) {
    if ($counts.ContainsKey($g.Name)) { $counts[$g.Name] = [int]$g.Count }
  }

  Write-Host ''
  Write-Host 'Findings by severity:' -ForegroundColor DarkGray
  Write-Host ("  High  : {0}" -f $counts.High)   -ForegroundColor (Get-SeverityColor -Severity 'High')
  Write-Host ("  Medium: {0}" -f $counts.Medium) -ForegroundColor (Get-SeverityColor -Severity 'Medium')
  Write-Host ("  Low   : {0}" -f $counts.Low)    -ForegroundColor (Get-SeverityColor -Severity 'Low')
  Write-Host ("  Info  : {0}" -f $counts.Info)   -ForegroundColor (Get-SeverityColor -Severity 'Info')

  if ($sorted.Count -gt 0 -and $Config.ConsoleMode -eq 'Pretty') {
    Write-Host ''
    Write-Host 'Top findings:' -ForegroundColor DarkGray
    foreach ($f in ($sorted | Select-Object -First 5)) {
      $color = Get-SeverityColor -Severity $f.Severity
      Write-Host ("- [{0}] {1}: {2}" -f $f.Severity, $f.Code, $f.Message) -ForegroundColor $color
    }
  }

  Write-Host ''
}

#endregion Helpers

#region Config
$defaultConfig = Get-DefaultConfig -CliMinimumLevel $MinimumLevel
$config        = Import-JsonConfigOrDefault -Path $ConfigPath -DefaultConfig $defaultConfig
$MinimumLevel  = $config.MinimumLevel

# Track whether a config file was successfully loaded (without leaking internal paths).
$configLoaded = $false
if (-not [string]::IsNullOrWhiteSpace($ConfigPath) -and (Test-Path -LiteralPath $ConfigPath)) {
  try {
    $raw = Get-Content -LiteralPath $ConfigPath -Raw -ErrorAction Stop
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
$findings = New-FindingsList

$lsaPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
$val     = Get-RegDword -Path $lsaPath -Name 'LmCompatibilityLevel'
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
  ConfigPath           = $(if ([string]::IsNullOrWhiteSpace($ConfigPath)) { $null } else { 'PATH/TO/JSON/ntlm-audit.json' })
}
#endregion Output objects (pipeline-safe)

#region Export
if ($ExportPath) {
  Ensure-DirectoryForFile -FilePath $ExportPath

  # Windows PowerShell 5.1 writes UTF-8 with BOM for -Encoding UTF8; keep for broad CSV/tool compatibility. [web:66]
  $summary | Export-Csv -Path $ExportPath -NoTypeInformation -Encoding UTF8

  $base   = [IO.Path]::GetFileNameWithoutExtension($ExportPath)
  $folder = Split-Path -Path $ExportPath -Parent
  if (-not $folder) { $folder = (Get-Location).Path }

  $findings | Export-Csv -Path (Join-Path $folder ($base + '_findings.csv')) -NoTypeInformation -Encoding UTF8
}
#endregion Export

#region Console-only output (no pipeline pollution)
Write-ConsoleSummary -Summary $summary -Findings $findings -Config $config
#endregion Console-only output

#region Pipeline output (structured objects only)
#$summary
#$findings
#endregion Pipeline output
