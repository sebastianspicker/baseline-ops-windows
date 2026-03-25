#requires -version 5.1
<#
.SYNOPSIS
Audits common remote administration surfaces on Windows: WinRM, SSH, RDP, SMB.

.DESCRIPTION
Audit-only (no remediation). Safe for support bundles/collections.

Target design:
- Pipeline output: structured objects only (Export-Csv / ConvertTo-Json / Where-Object).
- Console output: pretty, human-friendly, colorized, using Write-UiLine only (host stream). [web:192]

.PARAMETER ExportPath
Optional base path for CSV export. Creates *_summary.csv, *_surfaces.csv, *_findings.csv.

.PARAMETER ConfigPath
Optional JSON config path (e.g. "PATH/TO/JSON"). If missing/invalid/unreadable, safe defaults are used.
Note: ConvertFrom-Json error handling should be done with try/catch. [web:52]

.PARAMETER NoConsoleSummary
Suppress console summary output.


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
A single PSCustomObject:
@{ Summary = <pscustomobject>; Surfaces = <pscustomobject>; Findings = <object[]> }
.EXAMPLE
  .\37-Remote-Surface-Audit.ps1

#>


[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
  [string]$ExportPath,
  [string]$ConfigPath,
  [switch]$NoConsoleSummary

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
Import-Module (Join-Path $script:LibPath 'Console.psm1') -Force
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

# -------------------------
# Defaults + config loading
# -------------------------
$DefaultConfig = [pscustomobject]@{
  Findings = [pscustomobject]@{
    WinRMServiceNotRunningSeverity = 'Low'
    WinRMRunningSeverity           = 'Info'
    WinRMListenerPresentSeverity   = 'Info'

    OpenSSHCapabilitySeverity      = 'Info'
    SSHDRunningSeverity            = 'Info'
    SSHDNotRunningSeverity         = 'Low'

    RDPEnabledSeverity             = 'Info'
    RDPDisabledSeverity            = 'Info'
    RDPUnknownSeverity             = 'Info'

    SMBServerCfgSeverity           = 'Info'
    SMBClientCfgSeverity           = 'Info'
  }

  Console = [pscustomobject]@{
    ShowTopFindings = 10
    ShowSurfaces    = $true
  }
}

function Get-AuditConfig {
  [CmdletBinding()]
  param(
    [Parameter()][string]$Path,
    [Parameter(Mandatory)][psobject]$Defaults
  )

  if ([string]::IsNullOrWhiteSpace($Path)) { return $Defaults }
  if (-not (Test-Path -LiteralPath $Path)) { return $Defaults }

  try {
    $raw = Get-Content -LiteralPath $Path -Raw -Encoding UTF8 -ErrorAction Stop
    if ([string]::IsNullOrWhiteSpace($raw)) { return $Defaults }

    $cfg = $raw | ConvertFrom-Json
    if ($null -eq $cfg) { return $Defaults }

    return $cfg
  } catch {
    return $Defaults
  }
}

function Get-ConfigValue {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][psobject]$ConfigObject,
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][object]$DefaultValue
  )

  $current = $ConfigObject
  foreach ($part in ($Path -split '\.')) {
    if ($null -eq $current) { return $DefaultValue }

    $prop = $current.PSObject.Properties[$part]
    if ($null -eq $prop) { return $DefaultValue }

    $current = $prop.Value
  }

  if ($null -eq $current) { return $DefaultValue }
  return $current
}

$Config = Get-AuditConfig -Path $ConfigPath -Defaults $DefaultConfig

# -------------------------
# Findings helpers (Get-SeverityColor, Get-SeverityRank from lib/Console.psm1)
# -------------------------
$Findings = New-FindingsList

# -------------------------
# WinRM: service + listeners (best-effort)
# -------------------------
$winrmSvc = Get-Service -Name 'WinRM' -ErrorAction SilentlyContinue

$winrmListenersRaw = $null
try {
  $winrmListenersRaw = (& winrm.cmd enumerate winrm/config/listener 2>$null | Out-String).Trim()
} catch {
  $winrmListenersRaw = $null
}

if ($winrmSvc) {
  if ($winrmSvc.Status -ne 'Running') {
    $sev = Get-ConfigValue -ConfigObject $Config -Path 'Findings.WinRMServiceNotRunningSeverity' -DefaultValue $DefaultConfig.Findings.WinRMServiceNotRunningSeverity
    Add-Finding -Code 'REMOTE-WinRMNotRunning' -Severity $sev -Message ("WinRM service is {0}." -f $winrmSvc.Status)
  } else {
    $sev = Get-ConfigValue -ConfigObject $Config -Path 'Findings.WinRMRunningSeverity' -DefaultValue $DefaultConfig.Findings.WinRMRunningSeverity
    Add-Finding -Code 'REMOTE-WinRMRunning' -Severity $sev -Message 'WinRM service is running.'
  }
} else {
  Add-Finding -Code 'REMOTE-WinRMServiceMissing' -Severity 'Info' -Message 'WinRM service not found (edition/component/hardening).'
}

if ($winrmListenersRaw -and $winrmListenersRaw.Length -gt 0) {
  $sev = Get-ConfigValue -ConfigObject $Config -Path 'Findings.WinRMListenerPresentSeverity' -DefaultValue $DefaultConfig.Findings.WinRMListenerPresentSeverity
  Add-Finding -Code 'REMOTE-WinRMListenerPresent' -Severity $sev -Message 'WinRM listener configuration is present/readable.'
}

# -------------------------
# SSH: capability + sshd service
# -------------------------
$sshCap = $null
if (Get-Command -Name Get-WindowsCapability -ErrorAction SilentlyContinue) {
  try {
    $sshCap = Get-WindowsCapability -Online -Name 'OpenSSH.Server*' -ErrorAction Stop | Select-Object -First 1
  } catch {
    $sshCap = $null
  }
}

$sshdSvc = Get-Service -Name 'sshd' -ErrorAction SilentlyContinue

if ($sshCap) {
  $sev = Get-ConfigValue -ConfigObject $Config -Path 'Findings.OpenSSHCapabilitySeverity' -DefaultValue $DefaultConfig.Findings.OpenSSHCapabilitySeverity
  Add-Finding -Code 'REMOTE-OpenSSHCapability' -Severity $sev -Message ("OpenSSH.Server capability state: {0}" -f $sshCap.State)
}

if ($sshdSvc) {
  if ($sshdSvc.Status -eq 'Running') {
    $sev = Get-ConfigValue -ConfigObject $Config -Path 'Findings.SSHDRunningSeverity' -DefaultValue $DefaultConfig.Findings.SSHDRunningSeverity
    Add-Finding -Code 'REMOTE-SSHDRunning' -Severity $sev -Message 'sshd service is running.'
  } else {
    $sev = Get-ConfigValue -ConfigObject $Config -Path 'Findings.SSHDNotRunningSeverity' -DefaultValue $DefaultConfig.Findings.SSHDNotRunningSeverity
    Add-Finding -Code 'REMOTE-SSHDNotRunning' -Severity $sev -Message ("sshd service is {0}." -f $sshdSvc.Status)
  }
}

# -------------------------
# RDP: registry (fDenyTSConnections)
# -------------------------
$rdpKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
$rdpEnabled = $null
$rdpDenyRaw = $null

if (Test-Path -LiteralPath $rdpKey) {
  $rdpDenyRaw = (Get-ItemProperty -Path $rdpKey -Name 'fDenyTSConnections' -ErrorAction SilentlyContinue).fDenyTSConnections
  if ($null -ne $rdpDenyRaw) { $rdpEnabled = ($rdpDenyRaw -eq 0) }
}

if ($rdpEnabled -eq $true) {
  $sev = Get-ConfigValue -ConfigObject $Config -Path 'Findings.RDPEnabledSeverity' -DefaultValue $DefaultConfig.Findings.RDPEnabledSeverity
  Add-Finding -Code 'REMOTE-RDPEnabled' -Severity $sev -Message 'RDP is enabled (fDenyTSConnections=0).'
} elseif ($rdpEnabled -eq $false) {
  $sev = Get-ConfigValue -ConfigObject $Config -Path 'Findings.RDPDisabledSeverity' -DefaultValue $DefaultConfig.Findings.RDPDisabledSeverity
  Add-Finding -Code 'REMOTE-RDPDisabled' -Severity $sev -Message 'RDP is disabled (fDenyTSConnections=1).'
} else {
  $sev = Get-ConfigValue -ConfigObject $Config -Path 'Findings.RDPUnknownSeverity' -DefaultValue $DefaultConfig.Findings.RDPUnknownSeverity
  Add-Finding -Code 'REMOTE-RDPUnknown' -Severity $sev -Message 'RDP status could not be determined (missing registry key/value or access denied).'
}

# -------------------------
# SMB: server/client configuration
# -------------------------
$smbServerCfg = $null
$smbClientCfg = $null

if (Get-Command -Name Get-SmbServerConfiguration -ErrorAction SilentlyContinue) {
  try { $smbServerCfg = Get-SmbServerConfiguration -ErrorAction Stop } catch { $smbServerCfg = $null }
}
if (Get-Command -Name Get-SmbClientConfiguration -ErrorAction SilentlyContinue) {
  try { $smbClientCfg = Get-SmbClientConfiguration -ErrorAction Stop } catch { $smbClientCfg = $null }
}

if ($smbServerCfg) {
  $sev = Get-ConfigValue -ConfigObject $Config -Path 'Findings.SMBServerCfgSeverity' -DefaultValue $DefaultConfig.Findings.SMBServerCfgSeverity
  Add-Finding -Code 'REMOTE-SMBServerCfg' -Severity $sev -Message ("SMB server: EncryptData={0}, RejectUnencryptedAccess={1}" -f $smbServerCfg.EncryptData, $smbServerCfg.RejectUnencryptedAccess)
}
if ($smbClientCfg) {
  $sev = Get-ConfigValue -ConfigObject $Config -Path 'Findings.SMBClientCfgSeverity' -DefaultValue $DefaultConfig.Findings.SMBClientCfgSeverity
  Add-Finding -Code 'REMOTE-SMBClientCfg' -Severity $sev -Message ("SMB client: RequireEncryption={0}" -f $smbClientCfg.RequireEncryption)
}

# -------------------------
# Structured outputs (pipeline-safe)
# -------------------------
$surfaces = [pscustomobject]@{
  WinRM_ServiceStatus               = if ($winrmSvc) { [string]$winrmSvc.Status } else { $null }
  WinRM_ListenersRaw                = $winrmListenersRaw
  OpenSSH_ServerCapabilityState     = if ($sshCap) { [string]$sshCap.State } else { $null }
  SSHD_ServiceStatus                = if ($sshdSvc) { [string]$sshdSvc.Status } else { $null }
  RDP_fDenyTSConnections            = $rdpDenyRaw
  RDP_Enabled                       = $rdpEnabled
  SMB_ServerEncryptData             = if ($smbServerCfg) { [bool]$smbServerCfg.EncryptData } else { $null }
  SMB_ServerRejectUnencryptedAccess = if ($smbServerCfg) { [bool]$smbServerCfg.RejectUnencryptedAccess } else { $null }
  SMB_ClientRequireEncryption       = if ($smbClientCfg) { [bool]$smbClientCfg.RequireEncryption } else { $null }
}

$summary = [pscustomobject]@{
  ComputerName  = $env:COMPUTERNAME
  FindingsCount = $Findings.Count
  Timestamp     = Get-Date
  ConfigPath    = if ([string]::IsNullOrWhiteSpace($ConfigPath)) { $null } else { $ConfigPath }
}

$findingsOut = $Findings.ToArray()

$result = [pscustomobject]@{
  Summary  = $summary
  Surfaces = $surfaces
  Findings = $findingsOut
}

# -------------------------
# Export (optional)
# -------------------------
if ($ExportPath) {
  $dir = Split-Path -Path $ExportPath -Parent
  if ($dir -and -not (Test-Path -LiteralPath $dir)) {
    New-Item -Path $dir -ItemType Directory -Force | Out-Null
  }

  $base = [IO.Path]::GetFileNameWithoutExtension($ExportPath)
  $folder = Split-Path -Path $ExportPath -Parent
  if (-not $folder) { $folder = (Get-Location).Path }

  $result.Summary  | Export-Csv -Path (Join-Path $folder ($base + "_summary.csv"))  -NoTypeInformation -Encoding UTF8
  $result.Surfaces | Export-Csv -Path (Join-Path $folder ($base + "_surfaces.csv")) -NoTypeInformation -Encoding UTF8
  $result.Findings | Export-Csv -Path (Join-Path $folder ($base + "_findings.csv")) -NoTypeInformation -Encoding UTF8
}

# -------------------------
# Pretty console summary (host stream only)
# -------------------------
if (-not $NoConsoleSummary) {
  Write-UiSection "Remote Surface Audit"
  Write-UiLine ("Computer  : {0}" -f $result.Summary.ComputerName) ([ConsoleColor]::Gray)
  Write-UiLine ("Timestamp : {0}" -f $result.Summary.Timestamp) ([ConsoleColor]::Gray)
  Write-UiLine ("Findings  : {0}" -f $result.Summary.FindingsCount) (if ($result.Summary.FindingsCount -gt 0) { [ConsoleColor]::Yellow } else { [ConsoleColor]::Green })

  $sevOrder = @('High','Medium','Low','Info')
  Write-UiSection "Severity counts"
  foreach ($s in $sevOrder) {
    $c = ($result.Findings | Where-Object { $_.Severity -eq $s } | Measure-Object).Count
    Write-UiLine ("{0,-6} : {1}" -f $s, $c) (Get-SeverityColor -Severity $s)
  }

  $showSurfaces = [bool](Get-ConfigValue -ConfigObject $Config -Path 'Console.ShowSurfaces' -DefaultValue $DefaultConfig.Console.ShowSurfaces)
  if ($showSurfaces) {
    Write-UiSection "Surfaces"
    foreach ($p in $result.Surfaces.PSObject.Properties) {
      $val = $p.Value
      if ($null -eq $val) { $val = '<null>' }

      $color = [ConsoleColor]::Gray
      if ($val -is [bool]) {
        $color = if ($val) { [ConsoleColor]::Yellow } else { [ConsoleColor]::Green }
      }
      Write-UiLine ("{0,-30} {1}" -f ($p.Name + ':'), $val) $color
    }
  }

  $maxTop = [int](Get-ConfigValue -ConfigObject $Config -Path 'Console.ShowTopFindings' -DefaultValue $DefaultConfig.Console.ShowTopFindings)
  if ($maxTop -lt 0) { $maxTop = 0 }
  if ($maxTop -gt 50) { $maxTop = 50 }

  if ($maxTop -gt 0 -and $result.Findings.Count -gt 0) {
    Write-UiSection ("Top findings (max {0})" -f $maxTop)

    $top = $result.Findings |
      Sort-Object @{ Expression = { [int](Get-SeverityRank -Severity ([string]$_.Severity)) }; Descending = $true }, Code |
      Select-Object -First $maxTop

    foreach ($f in $top) {
      $color = Get-SeverityColor -Severity ([string]$f.Severity)
      Write-UiLine ("[{0}] {1} - {2}" -f $f.Severity, $f.Code, $f.Message) $color
    }
  }
}

# V2 output contract
$resultToken = if ($Strict -and $findingsOut.Count -gt 0) { 'FAIL' } elseif ($findingsOut.Count -gt 0) { 'WARN' } else { 'OK' }
$v2Result = New-V2ResultObject -ScriptName '37-Remote-Surface-Audit.ps1' -Mode $Mode -Result $resultToken -Findings $findingsOut -Summary $result.Summary -Metadata @{ Surfaces = $result.Surfaces }
Write-ResultObject -ResultObject $v2Result -OutputFormat $OutputFormat -OutputPath $OutputPath
if ($PassThru) { $v2Result }
exit 0
