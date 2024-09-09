#requires -version 5.1
<#
.SYNOPSIS
Audit + optional remediation for Credential Guard / VBS via registry (client-focused).

.DESCRIPTION
Microsoft notes that deleting the registry values may not disable Credential Guard; values must be set to 0, and a reboot is required. [web:35]

Best-practice output model (PowerShell 5.1):
- Pipeline: exactly one structured object (safe for Export-Csv / ConvertTo-Json / Where-Object).
- Console: pretty output only via Write-Host (host output) so the pipeline stays clean. [web:86]

.PARAMETER Mode
AuditOnly | Remediate

.PARAMETER ConfigPath
Optional JSON config path, e.g. "PATH/TO/JSON/config.json".
If missing/empty/invalid: continues with parameter defaults (non-fatal).

Supported JSON properties:
{
  "RequirePlatformSecurityFeatures": 1,
  "LsaCfgFlags": 1,
  "ExportPath": "PATH/TO/JSON/output.json",
  "ExportCsvBasePath": "PATH/TO/JSON/csv",
  "ShowSummary": true
}

.PARAMETER RequirePlatformSecurityFeatures
1 = Secure Boot, 3 = Secure Boot + DMA protection.

.PARAMETER LsaCfgFlags
0 = Disabled, 1 = Enabled with UEFI lock, 2 = Enabled without lock.

.PARAMETER ExportPath
Optional JSON export path.

.PARAMETER ExportCsvBasePath
Optional CSV export directory (summary.csv and findings.csv).

.PARAMETER ShowSummary
Write a human-friendly console summary at the end (default: $true).

.OUTPUTS
PSCustomObject with Summary, Current, After, Findings, Config.
.EXAMPLE
  .\39-CredentialGuard-VBS-AuditRemediate.ps1

#>


[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
  [ValidateSet('AuditOnly', 'Remediate')]
  [string]$Mode = 'AuditOnly',

  [string]$ConfigPath,

  [ValidateSet(1, 3)]
  [int]$RequirePlatformSecurityFeatures = 1,

  [ValidateSet(0, 1, 2)]
  [int]$LsaCfgFlags = 1,

  [string]$ExportPath,

  [string]$ExportCsvBasePath,

  [bool]$ShowSummary = $true
)

$script:LibPath = Join-Path $PSScriptRoot 'lib'
Import-Module (Join-Path $script:LibPath 'Common.psm1') -Force
Import-Module (Join-Path $script:LibPath 'Registry.psm1') -Force
Import-Module (Join-Path $script:LibPath 'Config.psm1') -Force
Import-Module (Join-Path $script:LibPath 'Results.psm1') -Force


Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# -----------------------------
# Helpers (PS 5.1 compatible)
# -----------------------------


function Ensure-Key {
  param([Parameter(Mandatory)][string]$Path)
  if (-not (Test-Path -LiteralPath $Path)) {
    New-Item -Path $Path -Force | Out-Null
  }
}



function Apply-ConfigOverrides {
  param(
    [Parameter(Mandatory)][object]$Config,
    [Parameter(Mandatory)][hashtable]$Effective,
    [Parameter(Mandatory)][System.Collections.Generic.List[string]]$Warnings
  )

  if ($null -ne $Config.RequirePlatformSecurityFeatures) {
    if ($Config.RequirePlatformSecurityFeatures -in 1, 3) {
      $Effective.RequirePlatformSecurityFeatures = [int]$Config.RequirePlatformSecurityFeatures
    } else {
      $Warnings.Add("Config: RequirePlatformSecurityFeatures invalid ($($Config.RequirePlatformSecurityFeatures)); keeping defaults/parameters.") | Out-Null
    }
  }

  if ($null -ne $Config.LsaCfgFlags) {
    if ($Config.LsaCfgFlags -in 0, 1, 2) {
      $Effective.LsaCfgFlags = [int]$Config.LsaCfgFlags
    } else {
      $Warnings.Add("Config: LsaCfgFlags invalid ($($Config.LsaCfgFlags)); keeping defaults/parameters.") | Out-Null
    }
  }

  if ($null -ne $Config.ExportPath -and -not [string]::IsNullOrWhiteSpace([string]$Config.ExportPath)) {
    $Effective.ExportPath = [string]$Config.ExportPath
  }

  if ($null -ne $Config.ExportCsvBasePath -and -not [string]::IsNullOrWhiteSpace([string]$Config.ExportCsvBasePath)) {
    $Effective.ExportCsvBasePath = [string]$Config.ExportCsvBasePath
  }

  if ($null -ne $Config.ShowSummary) {
    try {
      $Effective.ShowSummary = [bool]$Config.ShowSummary
    } catch {
      $Warnings.Add("Config: ShowSummary invalid ($($Config.ShowSummary)); keeping defaults/parameters.") | Out-Null
    }
  }
}

function Write-PrettySummary {
  param([Parameter(Mandatory)][object]$Result)

  # Host-only output. Do NOT use Write-Output here (keeps pipeline clean). [web:86]
  $cGood   = 'Green'
  $cWarn   = 'Yellow'
  $cBad    = 'Red'
  $cInfo   = 'Cyan'
  $cDim    = 'DarkGray'
  $cHeader = 'White'

  function Write-Rule { Write-Host ('=' * 60) -ForegroundColor $cDim }

  function Show-Section {
    param([string]$Title)
    Write-Host ''
    Write-Rule
    Write-Host $Title -ForegroundColor $cHeader
    Write-Rule
  }

  function Show-Kv {
    param(
      [string]$Key,
      [string]$Value,
      [string]$Color
    )
    if (-not $Color) { $Color = 'Gray' }
    Write-Host ("{0,-30}: " -f $Key) -NoNewline -ForegroundColor $cDim
    Write-Host $Value -ForegroundColor $Color
  }

  function Get-SeverityColor {
    param([string]$Severity)
    switch ($Severity) {
      'High'   { return $cBad }
      'Medium' { return $cWarn }
      'Low'    { return $cInfo }
      default  { return 'Gray' }
    }
  }

  # Precompute colors/strings (avoid inline if-expressions in argument position in PS 5.1).
  $compliant = [bool]$Result.Summary.Compliant
  $reboot    = [bool]$Result.Summary.RebootRequired

  $compliantColor = if ($compliant) { $cGood } else { $cBad }
  $rebootColor    = if ($reboot) { $cWarn } else { $cGood }
  $modeColor      = if ($Result.Summary.Mode -eq 'Remediate') { $cWarn } else { $cInfo }

  $findingsCount = [int]$Result.Summary.FindingsCount
  $findingsColor = if ($findingsCount -gt 0) { $cWarn } else { $cGood }

  Show-Section -Title 'Credential Guard / VBS'
  Show-Kv -Key 'ComputerName' -Value ([string]$Result.Summary.ComputerName) -Color $cInfo
  Show-Kv -Key 'Mode' -Value ([string]$Result.Summary.Mode) -Color $modeColor
  Show-Kv -Key 'Compliant (registry)' -Value ([string]$compliant) -Color $compliantColor
  Show-Kv -Key 'Reboot required' -Value ([string]$reboot) -Color $rebootColor
  Show-Kv -Key 'Findings count' -Value ([string]$findingsCount) -Color $findingsColor

  Show-Section -Title 'Target (effective)'
  Show-Kv -Key 'EnableVBS' -Value '1' -Color $cInfo
  Show-Kv -Key 'RequirePlatformSecurityFeatures' -Value ([string]$Result.Summary.Target.RequirePlatformSecurityFeatures) -Color $cInfo
  Show-Kv -Key 'LsaCfgFlags' -Value ([string]$Result.Summary.Target.LsaCfgFlags) -Color $cInfo

  Show-Section -Title 'State (before -> after)'
  $b = $Result.Current
  $a = $Result.After

  $enableLine = ("{0} -> {1}" -f $b.EnableVirtualizationBasedSecurity, $a.EnableVirtualizationBasedSecurity)
  $rpsfLine   = ("{0} -> {1}" -f $b.RequirePlatformSecurityFeatures,   $a.RequirePlatformSecurityFeatures)
  $lsaLine    = ("{0} -> {1}" -f $b.LsaCfgFlags,                       $a.LsaCfgFlags)

  $enableColor = if ($a.EnableVirtualizationBasedSecurity -eq 1) { $cGood } else { $cBad }
  $rpsfColor   = if ($a.RequirePlatformSecurityFeatures -in 1, 3) { $cGood } else { $cBad }
  $lsaColor    = if ($a.LsaCfgFlags -in 1, 2) { $cGood } else { $cBad }

  Show-Kv -Key 'EnableVBS' -Value $enableLine -Color $enableColor
  Show-Kv -Key 'RequirePlatformSecurityFeatures' -Value $rpsfLine -Color $rpsfColor
  Show-Kv -Key 'LsaCfgFlags' -Value $lsaLine -Color $lsaColor

  if ($Result.Config -and $Result.Config.Warnings -and $Result.Config.Warnings.Count -gt 0) {
    Show-Section -Title 'Config warnings'
    foreach ($w in $Result.Config.Warnings) {
      Write-Host ("- {0}" -f $w) -ForegroundColor $cWarn
    }
  }

  if ($Result.Summary.Changes -and $Result.Summary.Changes.Count -gt 0) {
    Show-Section -Title 'Changes'
    foreach ($c in $Result.Summary.Changes) {
      Write-Host ("- {0}" -f $c) -ForegroundColor $cInfo
    }
  }

  if ($Result.Findings -and $Result.Findings.Count -gt 0) {
    Show-Section -Title 'Findings'
    foreach ($f in $Result.Findings) {
      $sevColor = Get-SeverityColor -Severity ([string]$f.Severity)
      Write-Host ("- [{0}] {1}: {2}" -f $f.Severity, $f.Code, $f.Message) -ForegroundColor $sevColor
    }
  }

  Write-Host ''
}

# -----------------------------
# Start
# -----------------------------

if (-not (Test-IsAdmin)) { throw "Administrative rights required." }

$Findings       = New-FindingsList
$Changes        = New-Object System.Collections.Generic.List[string]
$ConfigWarnings = New-Object System.Collections.Generic.List[string]

# Effective settings start with parameters (sensible defaults).
$effective = @{
  RequirePlatformSecurityFeatures = $RequirePlatformSecurityFeatures
  LsaCfgFlags                     = $LsaCfgFlags
  ExportPath                      = $ExportPath
  ExportCsvBasePath               = $ExportCsvBasePath
  ShowSummary                     = $ShowSummary
}

# Optional JSON overrides (never fatal).
$cfgResult = Read-ConfigWithDefaults -Path $ConfigPath -Defaults @{} -ReturnNullWhenMissing -ReturnNullOnError
$cfg     = $cfgResult.Config
$cfgMeta = $cfgResult.Meta

if ($cfgMeta.Loaded -and $null -ne $cfg) {
  Apply-ConfigOverrides -Config $cfg -Effective $effective -Warnings $ConfigWarnings
}

$dgPath  = 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard'
$lsaPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'

$current = [pscustomobject]@{
  EnableVirtualizationBasedSecurity = Get-RegValue -Path $dgPath  -Name 'EnableVirtualizationBasedSecurity'
  RequirePlatformSecurityFeatures   = Get-RegValue -Path $dgPath  -Name 'RequirePlatformSecurityFeatures'
  LsaCfgFlags                       = Get-RegValue -Path $lsaPath -Name 'LsaCfgFlags'
}

# -----------------------------
# Audit
# -----------------------------

if ($current.EnableVirtualizationBasedSecurity -ne 1) {
  Add-Finding -Code 'CG-VBS-NotEnabled' -Severity 'High' -Message 'EnableVirtualizationBasedSecurity is not 1.'
}

if ($current.RequirePlatformSecurityFeatures -notin 1, 3) {
  Add-Finding -Code 'CG-PlatformSecurityFeatures-Invalid' -Severity 'Medium' -Message 'RequirePlatformSecurityFeatures is not 1 or 3.'
}

if ($null -eq $current.LsaCfgFlags) {
  Add-Finding -Code 'CG-LsaCfgFlags-Missing' -Severity 'Medium' -Message 'LsaCfgFlags is missing (Credential Guard not configured via registry).'
} elseif ($current.LsaCfgFlags -notin 0, 1, 2) {
  Add-Finding -Code 'CG-LsaCfgFlags-Invalid' -Severity 'Medium' -Message ("LsaCfgFlags has an unexpected value: {0}" -f $current.LsaCfgFlags)
} elseif ($current.LsaCfgFlags -eq 0) {
  Add-Finding -Code 'CG-LsaCfgFlags-Disabled' -Severity 'High' -Message 'LsaCfgFlags=0 (Credential Guard configured as disabled).'
}

if ($current.LsaCfgFlags -eq 1 -and $Mode -eq 'Remediate' -and $effective.LsaCfgFlags -ne 1) {
  Add-Finding -Code 'CG-UEFI-Lock-Note' -Severity 'Low' -Message 'LsaCfgFlags=1 (UEFI lock) may prevent changing/disabling it via registry.'
}

# -----------------------------
# Remediation (idempotent)
# -----------------------------

$rebootRequired = $false

if ($Mode -eq 'Remediate') {

  if ($current.EnableVirtualizationBasedSecurity -ne 1) {
    $action = 'Set EnableVirtualizationBasedSecurity=1 (reboot required)'
    if ($PSCmdlet.ShouldProcess($env:COMPUTERNAME, $action)) {
      Set-RegDword -Path $dgPath -Name 'EnableVirtualizationBasedSecurity' -Value 1
      $rebootRequired = $true
      $Changes.Add(("EnableVirtualizationBasedSecurity: {0} -> 1" -f $current.EnableVirtualizationBasedSecurity)) | Out-Null
    }
  }

  if ($current.RequirePlatformSecurityFeatures -ne $effective.RequirePlatformSecurityFeatures) {
    $action = "Set RequirePlatformSecurityFeatures=$($effective.RequirePlatformSecurityFeatures) (reboot required)"
    if ($PSCmdlet.ShouldProcess($env:COMPUTERNAME, $action)) {
      Set-RegDword -Path $dgPath -Name 'RequirePlatformSecurityFeatures' -Value $effective.RequirePlatformSecurityFeatures
      $rebootRequired = $true
      $Changes.Add(("RequirePlatformSecurityFeatures: {0} -> {1}" -f $current.RequirePlatformSecurityFeatures, $effective.RequirePlatformSecurityFeatures)) | Out-Null
    }
  }

  if ($current.LsaCfgFlags -ne $effective.LsaCfgFlags) {
    $action = "Set LsaCfgFlags=$($effective.LsaCfgFlags) (reboot required)"
    if ($PSCmdlet.ShouldProcess($env:COMPUTERNAME, $action)) {
      Set-RegDword -Path $lsaPath -Name 'LsaCfgFlags' -Value $effective.LsaCfgFlags
      $rebootRequired = $true
      $Changes.Add(("LsaCfgFlags: {0} -> {1}" -f $current.LsaCfgFlags, $effective.LsaCfgFlags)) | Out-Null
    }
  }
}

$after = [pscustomobject]@{
  EnableVirtualizationBasedSecurity = Get-RegValue -Path $dgPath  -Name 'EnableVirtualizationBasedSecurity'
  RequirePlatformSecurityFeatures   = Get-RegValue -Path $dgPath  -Name 'RequirePlatformSecurityFeatures'
  LsaCfgFlags                       = Get-RegValue -Path $lsaPath -Name 'LsaCfgFlags'
}

# Registry-only compliance (effective behavior requires reboot). [web:35]
$compliant = ($after.EnableVirtualizationBasedSecurity -eq 1) -and
             ($after.RequirePlatformSecurityFeatures -in 1, 3) -and
             ($after.LsaCfgFlags -in 1, 2)

# -----------------------------
# Build result (structured pipeline output only)
# -----------------------------

$publicConfigPath = $null
if ($ConfigPath) { $publicConfigPath = 'PATH/TO/JSON/config.json' }

$result = [pscustomobject]@{
  Summary = [pscustomobject]@{
    ComputerName   = $env:COMPUTERNAME
    Mode           = $Mode
    Target         = [pscustomobject]@{
      EnableVirtualizationBasedSecurity = 1
      RequirePlatformSecurityFeatures   = $effective.RequirePlatformSecurityFeatures
      LsaCfgFlags                       = $effective.LsaCfgFlags
    }
    RebootRequired = $rebootRequired
    Compliant      = $compliant
    FindingsCount  = $Findings.Count
    Changes        = $Changes
    Timestamp      = Get-Date
  }
  Current  = $current
  After    = $after
  Findings = $Findings
  Config   = [pscustomobject]@{
    ConfigPath = $publicConfigPath
    Meta       = $cfgMeta
    Warnings   = $ConfigWarnings
    Effective  = [pscustomobject]@{
      RequirePlatformSecurityFeatures = $effective.RequirePlatformSecurityFeatures
      LsaCfgFlags                     = $effective.LsaCfgFlags
      ExportPath                      = $effective.ExportPath
      ExportCsvBasePath               = $effective.ExportCsvBasePath
      ShowSummary                     = $effective.ShowSummary
    }
  }
}

# -----------------------------
# Export (does not pollute pipeline)
# -----------------------------

if ($effective.ExportPath) {
  $dir = Split-Path -Path $effective.ExportPath -Parent
  if ($dir -and -not (Test-Path -LiteralPath $dir)) { Ensure-Directory -Path $dir }
  $result | ConvertTo-Json -Depth 6 | Set-Content -Path $effective.ExportPath -Encoding UTF8
}

if ($effective.ExportCsvBasePath) {
  if (-not (Test-Path -LiteralPath $effective.ExportCsvBasePath)) {
    Ensure-Directory -Path $effective.ExportCsvBasePath
  }

  ($result.Summary | Select-Object * ) |
    Export-Csv -Path (Join-Path $effective.ExportCsvBasePath 'summary.csv') -NoTypeInformation -Encoding UTF8

  ($result.Findings) |
    Export-Csv -Path (Join-Path $effective.ExportCsvBasePath 'findings.csv') -NoTypeInformation -Encoding UTF8
}

# -----------------------------
# Console summary (host-only) + return object (pipeline)
# -----------------------------

if ($effective.ShowSummary) {
  Write-PrettySummary -Result $result
}

# $result
