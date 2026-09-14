#requires -version 5.1
<#
.SYNOPSIS
Audits common remote administration surfaces on Windows: WinRM, SSH, RDP, SMB.

.DESCRIPTION
Audit-only (no remediation). Safe for support bundles/collections.

Target design:
- Pipeline output: structured objects only (Export-Csv / ConvertTo-Json / Where-Object).
- Console output: formatted and colorized using Write-UiLine only (host stream).

.PARAMETER ExportPath
Optional base path for CSV export. Creates *_summary.csv, *_surfaces.csv, *_findings.csv.

.PARAMETER ConfigPath
Optional JSON config path supplied with $ConfigPath. If missing, invalid, or unreadable, safe defaults are used.
Note: ConvertFrom-Json error handling should be done with try/catch.

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
function Initialize-Capability37Runtime {
  param($EntryBoundParameters)
  $RunState = @{

  }
Import-Module (Join-Path $script:LibPath 'Output.psm1') -Force
Import-Module (Join-Path $script:LibPath 'Console.psm1') -Force
Import-Module (Join-Path $script:LibPath 'Results.psm1') -Force
Import-Module (Join-Path $script:LibPath 'External.psm1') -Force
Import-Module (Join-Path $script:LibPath Serialization.psm1) -Force
Import-Module (Join-Path $script:LibPath 'Validation.psm1')


Set-StrictMode -Version Latest
$script:__V2Context = Initialize-V2Context -ScriptName '37-Remote-Surface-Audit.ps1' -BoundParameters $EntryBoundParameters `
  -Values @{ Mode = $Mode; ConfigPath = $ConfigPath; OutputFormat = $OutputFormat; OutputPath = $OutputPath; PassThru = $PassThru; Strict = $Strict; Quiet = $Quiet; NoColor = $NoColor; DeriveRemediate = $false }
if ($script:__V2Context.Quiet) { $InformationPreference = 'SilentlyContinue'; $VerbosePreference = 'SilentlyContinue' }
$script:NoColor = [bool]$script:__V2Context.NoColor
$ErrorActionPreference = 'Stop'

$RunState.isWindowsHost = ($env:OS -eq 'Windows_NT')
  $script:RunState = $RunState
}

. Initialize-Capability37Runtime -EntryBoundParameters $PSBoundParameters
function Get-Capability37UnsupportedState {
  param([hashtable]$RunState)
$summary = [pscustomobject]@{
  ComputerName = $env:COMPUTERNAME
  Timestamp    = Get-Date
  Mode         = $Mode
  Supported    = $false
  Notes        = @('Skipped: this script is only supported on Windows hosts.')
}
$RunState.unsupportedResult = if ($Strict) { 'FAIL' } else { 'WARN' }
$RunState.result = Get-V2ResultObject -ScriptName '37-Remote-Surface-Audit.ps1' -Mode $Mode -Result $RunState.unsupportedResult -Findings @() -Summary $summary -Metadata @{ UnsupportedHost = $true }
  [pscustomobject]@{ Result = $RunState.result; Token = $RunState.unsupportedResult }
}
function Set-Capability37UnsupportedState {
  param([hashtable]$RunState)
  $unsupportedState = Get-Capability37UnsupportedState -RunState $RunState
  $RunState.result = $unsupportedState.Result
  $RunState.unsupportedResult = $unsupportedState.Token
}
if (-not $RunState.isWindowsHost) {
  . Set-Capability37UnsupportedState -RunState $RunState
  Write-ResultObject -ResultObject $RunState.result -OutputFormat $OutputFormat -OutputPath $OutputPath
  if ($PassThru) { $RunState.result }
  exit (Get-V2ExitCode -Result $RunState.unsupportedResult)
}

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
    $raw = Get-BoundedUtf8FileContent -Path $Path -MaximumBytes 1048576
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

function Invoke-Capability37MainPhase01 {
  param([hashtable]$RunState)
  $RunState.Config = Get-AuditConfig -Path $ConfigPath -Defaults $DefaultConfig

  # -------------------------
  # Findings helpers (Get-SeverityColor, Get-SeverityRank from lib/Console.psm1)
  # -------------------------
  $RunState.Findings = Get-FindingsList

  # -------------------------
  # WinRM: service + listeners (best-effort)
  # -------------------------
  $RunState.winrmSvc = Get-Service -Name 'WinRM' -ErrorAction SilentlyContinue

  $RunState.winrmListenersRaw = $null
  $winrmListenerEvidence = Invoke-WinrmCommand -Arguments @('enumerate','winrm/config/listener') -CaptureOutput -Quiet -TimeoutSeconds 30 -MaxOutputBytes 262144
  $winrmListenerEvidenceComplete = ($null -ne $winrmListenerEvidence -and $winrmListenerEvidence.Success -and -not $winrmListenerEvidence.TimedOut -and -not $winrmListenerEvidence.OutputTruncated -and -not $winrmListenerEvidence.StderrTruncated)
  if ($winrmListenerEvidenceComplete) {
    $RunState.winrmListenersRaw = ([string]$winrmListenerEvidence.Output).Trim()
  }
}
function Invoke-Capability37MainPhase02 {
  param([hashtable]$RunState)
  if ($RunState.winrmSvc) {
    if ($RunState.winrmSvc.Status -ne 'Running') {
      $sev = Get-ConfigValue -ConfigObject $RunState.Config -Path 'Findings.WinRMServiceNotRunningSeverity' -DefaultValue $DefaultConfig.Findings.WinRMServiceNotRunningSeverity
      Add-Finding -FindingList $RunState.Findings -Code 'REMOTE-WinRMNotRunning' -Severity $sev -Message ("WinRM service is {0}." -f $RunState.winrmSvc.Status)
    } else {
      $sev = Get-ConfigValue -ConfigObject $RunState.Config -Path 'Findings.WinRMRunningSeverity' -DefaultValue $DefaultConfig.Findings.WinRMRunningSeverity
      Add-Finding -FindingList $RunState.Findings -Code 'REMOTE-WinRMRunning' -Severity $sev -Message 'WinRM service is running.'
    }
  } else {
    Add-Finding -FindingList $RunState.Findings -Code 'REMOTE-WinRMServiceMissing' -Severity 'Info' -Message 'WinRM service not found (edition/component/hardening).'
  }
}
function Invoke-Capability37MainPhase03 {
  param([hashtable]$RunState)
  if (-not $winrmListenerEvidenceComplete) {
    $reason = if ($null -eq $winrmListenerEvidence) {
      'command did not start'
    } elseif ($winrmListenerEvidence.TimedOut) {
      'command timed out'
    } elseif ($winrmListenerEvidence.OutputTruncated -or $winrmListenerEvidence.StderrTruncated) {
      'command output was truncated'
    } else {
      "command exited with code $($winrmListenerEvidence.ExitCode)"
    }
    $data = if ($null -ne $winrmListenerEvidence) { [string]$winrmListenerEvidence.Output } else { '' }
    Add-Finding -FindingList $RunState.Findings -Code 'REMOTE-WinRMListenerEvidenceIncomplete' -Severity 'Medium' -Message ("WinRM listener evidence is incomplete: {0}." -f $reason) -Extra @{ Data = $data }
  }
}
function Invoke-Capability37MainPhase04 {
  param([hashtable]$RunState)
  if ($RunState.winrmListenersRaw -and $RunState.winrmListenersRaw.Length -gt 0) {
    $sev = Get-ConfigValue -ConfigObject $RunState.Config -Path 'Findings.WinRMListenerPresentSeverity' -DefaultValue $DefaultConfig.Findings.WinRMListenerPresentSeverity
    Add-Finding -FindingList $RunState.Findings -Code 'REMOTE-WinRMListenerPresent' -Severity $sev -Message 'WinRM listener configuration is present/readable.'
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

  $RunState.sshdSvc = Get-Service -Name 'sshd' -ErrorAction SilentlyContinue

  if ($sshCap) {
    $sev = Get-ConfigValue -ConfigObject $RunState.Config -Path 'Findings.OpenSSHCapabilitySeverity' -DefaultValue $DefaultConfig.Findings.OpenSSHCapabilitySeverity
    Add-Finding -FindingList $RunState.Findings -Code 'REMOTE-OpenSSHCapability' -Severity $sev -Message ("OpenSSH.Server capability state: {0}" -f $sshCap.State)
  }
}
function Invoke-Capability37MainPhase05 {
  param([hashtable]$RunState)
  if ($RunState.sshdSvc) {
    if ($RunState.sshdSvc.Status -eq 'Running') {
      $sev = Get-ConfigValue -ConfigObject $RunState.Config -Path 'Findings.SSHDRunningSeverity' -DefaultValue $DefaultConfig.Findings.SSHDRunningSeverity
      Add-Finding -FindingList $RunState.Findings -Code 'REMOTE-SSHDRunning' -Severity $sev -Message 'sshd service is running.'
    } else {
      $sev = Get-ConfigValue -ConfigObject $RunState.Config -Path 'Findings.SSHDNotRunningSeverity' -DefaultValue $DefaultConfig.Findings.SSHDNotRunningSeverity
      Add-Finding -FindingList $RunState.Findings -Code 'REMOTE-SSHDNotRunning' -Severity $sev -Message ("sshd service is {0}." -f $RunState.sshdSvc.Status)
    }
  }

  # -------------------------
  # RDP: registry (fDenyTSConnections)
  # -------------------------
  $rdpKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
  $RunState.rdpEnabled = $null
  $rdpDenyRaw = $null

  if (Test-Path -LiteralPath $rdpKey) {
    $rdpDenyRaw = (Get-ItemProperty -Path $rdpKey -Name 'fDenyTSConnections' -ErrorAction SilentlyContinue).fDenyTSConnections
    if ($null -ne $rdpDenyRaw) { $RunState.rdpEnabled = ($rdpDenyRaw -eq 0) }
  }
}
function Invoke-Capability37MainPhase06 {
  param([hashtable]$RunState)
  if ($RunState.rdpEnabled -eq $true) {
    $sev = Get-ConfigValue -ConfigObject $RunState.Config -Path 'Findings.RDPEnabledSeverity' -DefaultValue $DefaultConfig.Findings.RDPEnabledSeverity
    Add-Finding -FindingList $RunState.Findings -Code 'REMOTE-RDPEnabled' -Severity $sev -Message 'RDP is enabled (fDenyTSConnections=0).'
  } elseif ($RunState.rdpEnabled -eq $false) {
    $sev = Get-ConfigValue -ConfigObject $RunState.Config -Path 'Findings.RDPDisabledSeverity' -DefaultValue $DefaultConfig.Findings.RDPDisabledSeverity
    Add-Finding -FindingList $RunState.Findings -Code 'REMOTE-RDPDisabled' -Severity $sev -Message 'RDP is disabled (fDenyTSConnections=1).'
  } else {
    $sev = Get-ConfigValue -ConfigObject $RunState.Config -Path 'Findings.RDPUnknownSeverity' -DefaultValue $DefaultConfig.Findings.RDPUnknownSeverity
    Add-Finding -FindingList $RunState.Findings -Code 'REMOTE-RDPUnknown' -Severity $sev -Message 'RDP status could not be determined (missing registry key/value or access denied).'
  }

  # -------------------------
  # SMB: server/client configuration
  # -------------------------
  $RunState.smbServerCfg = $null
  $RunState.smbClientCfg = $null

  if (Get-Command -Name Get-SmbServerConfiguration -ErrorAction SilentlyContinue) {
    try { $RunState.smbServerCfg = Get-SmbServerConfiguration -ErrorAction Stop } catch { $RunState.smbServerCfg = $null }
  }
}
function Invoke-Capability37MainPhase07 {
  param([hashtable]$RunState)
  if (Get-Command -Name Get-SmbClientConfiguration -ErrorAction SilentlyContinue) {
    try { $RunState.smbClientCfg = Get-SmbClientConfiguration -ErrorAction Stop } catch { $RunState.smbClientCfg = $null }
  }

  if ($RunState.smbServerCfg) {
    $sev = Get-ConfigValue -ConfigObject $RunState.Config -Path 'Findings.SMBServerCfgSeverity' -DefaultValue $DefaultConfig.Findings.SMBServerCfgSeverity
    Add-Finding -FindingList $RunState.Findings -Code 'REMOTE-SMBServerCfg' -Severity $sev -Message ("SMB server: EncryptData={0}, RejectUnencryptedAccess={1}" -f $RunState.smbServerCfg.EncryptData, $RunState.smbServerCfg.RejectUnencryptedAccess)
  }
  if ($RunState.smbClientCfg) {
    $sev = Get-ConfigValue -ConfigObject $RunState.Config -Path 'Findings.SMBClientCfgSeverity' -DefaultValue $DefaultConfig.Findings.SMBClientCfgSeverity
    Add-Finding -FindingList $RunState.Findings -Code 'REMOTE-SMBClientCfg' -Severity $sev -Message ("SMB client: RequireEncryption={0}" -f $RunState.smbClientCfg.RequireEncryption)
  }
}
function Invoke-Capability37MainPhase08 {
  param([hashtable]$RunState)
  $RunState.surfaces = [pscustomobject]@{
    WinRM_ServiceStatus               = if ($RunState.winrmSvc) { [string]$RunState.winrmSvc.Status } else { $null }
    WinRM_ListenersRaw                = $RunState.winrmListenersRaw
    WinRM_ListenerEvidenceComplete    = [bool]$winrmListenerEvidenceComplete
    OpenSSH_ServerCapabilityState     = if ($sshCap) { [string]$sshCap.State } else { $null }
    SSHD_ServiceStatus                = if ($RunState.sshdSvc) { [string]$RunState.sshdSvc.Status } else { $null }
    RDP_fDenyTSConnections            = $rdpDenyRaw
    RDP_Enabled                       = $RunState.rdpEnabled
    SMB_ServerEncryptData             = if ($RunState.smbServerCfg) { [bool]$RunState.smbServerCfg.EncryptData } else { $null }
    SMB_ServerRejectUnencryptedAccess = if ($RunState.smbServerCfg) { [bool]$RunState.smbServerCfg.RejectUnencryptedAccess } else { $null }
    SMB_ClientRequireEncryption       = if ($RunState.smbClientCfg) { [bool]$RunState.smbClientCfg.RequireEncryption } else { $null }
  }
}
function Invoke-Capability37MainPhase09 {
  param([hashtable]$RunState)
  $summary = [pscustomobject]@{
    ComputerName  = $env:COMPUTERNAME
    FindingsCount = $RunState.Findings.Count
    Timestamp     = Get-Date
    ConfigPath    = if ([string]::IsNullOrWhiteSpace($ConfigPath)) { $null } else { $ConfigPath }
  }

  $findingsOut = $RunState.Findings.ToArray()

  $RunState.result = [pscustomobject]@{
    Summary  = $summary
    Surfaces = $RunState.surfaces
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

    $RunState.result.Summary  | Export-Csv -Path (Join-Path $folder ($base + "_summary.csv"))  -NoTypeInformation -Encoding UTF8
    $RunState.result.Surfaces | Export-Csv -Path (Join-Path $folder ($base + "_surfaces.csv")) -NoTypeInformation -Encoding UTF8
    $RunState.result.Findings | Export-Csv -Path (Join-Path $folder ($base + "_findings.csv")) -NoTypeInformation -Encoding UTF8
  }
}
function Invoke-Capability37MainPhase10Step01 {
  param([hashtable]$RunState)
Write-Section "Remote Surface Audit"
    Write-UiLine ("Computer  : {0}" -f $RunState.result.Summary.ComputerName) ([ConsoleColor]::Gray)
    Write-UiLine ("Timestamp : {0}" -f $RunState.result.Summary.Timestamp) ([ConsoleColor]::Gray)
    Write-UiLine ("Findings  : {0}" -f $RunState.result.Summary.FindingsCount) $(if ($RunState.result.Summary.FindingsCount -gt 0) { [ConsoleColor]::Yellow } else { [ConsoleColor]::Green })

    $sevOrder = @('High','Medium','Low','Info')
    Write-Section "Severity counts"
    foreach ($s in $sevOrder) {
      $c = ($RunState.result.Findings | Where-Object { $_.Severity -eq $s } | Measure-Object).Count
      Write-UiLine ("{0,-6} : {1}" -f $s, $c) (Get-SeverityColor -Severity $s)
    }

    $RunState.showSurfaces = [bool](Get-ConfigValue -ConfigObject $RunState.Config -Path 'Console.ShowSurfaces' -DefaultValue $DefaultConfig.Console.ShowSurfaces)
}

function Invoke-Capability37MainPhase10Step02 {
  param([hashtable]$RunState)
if ($RunState.showSurfaces) {
      Write-Section "Surfaces"
      foreach ($p in $RunState.result.Surfaces.PSObject.Properties) {
        $val = $p.Value
        if ($null -eq $val) { $val = '<null>' }

        $color = [ConsoleColor]::Gray
        if ($val -is [bool]) {
          $color = if ($val) { [ConsoleColor]::Yellow } else { [ConsoleColor]::Green }
        }
        Write-UiLine ("{0,-30} {1}" -f ($p.Name + ':'), $val) $color
      }
    }

    $RunState.maxTop = [int](Get-ConfigValue -ConfigObject $RunState.Config -Path 'Console.ShowTopFindings' -DefaultValue $DefaultConfig.Console.ShowTopFindings)
}

function Invoke-Capability37MainPhase10Step03 {
  param([hashtable]$RunState)
if ($RunState.maxTop -lt 0) { $RunState.maxTop = 0 }
    if ($RunState.maxTop -gt 50) { $RunState.maxTop = 50 }

    if ($RunState.maxTop -gt 0 -and $RunState.result.Findings.Count -gt 0) {
      Write-Section ("Top findings (max {0})" -f $RunState.maxTop)

      $top = $RunState.result.Findings |
        Sort-Object @{ Expression = { [int](Get-SeverityRank -Severity ([string]$_.Severity)) }; Descending = $true }, Code |
        Select-Object -First $RunState.maxTop

      foreach ($f in $top) {
        $color = Get-SeverityColor -Severity ([string]$f.Severity)
        Write-UiLine ("[{0}] {1} - {2}" -f $f.Severity, $f.Code, $f.Message) $color
      }
    }
}

function Invoke-Capability37MainPhase10 {
  param([hashtable]$RunState)
  if (-not $NoConsoleSummary) {
    . Invoke-Capability37MainPhase10Step01 -RunState $RunState
. Invoke-Capability37MainPhase10Step02 -RunState $RunState
. Invoke-Capability37MainPhase10Step03 -RunState $RunState
  }
}
function Invoke-Capability37Main {
  param($EntryBoundParameters, $EntryCmdlet, $EntryInvocation, [hashtable]$RunState)
  $script:__EntryBoundParameters = $EntryBoundParameters
  $script:__EntryCmdlet = $EntryCmdlet
  $script:__EntryInvocation = $EntryInvocation
  . Invoke-Capability37MainPhase01 -RunState $RunState
  . Invoke-Capability37MainPhase02 -RunState $RunState
  . Invoke-Capability37MainPhase03 -RunState $RunState
  . Invoke-Capability37MainPhase04 -RunState $RunState
  . Invoke-Capability37MainPhase05 -RunState $RunState
  . Invoke-Capability37MainPhase06 -RunState $RunState
  . Invoke-Capability37MainPhase07 -RunState $RunState
  . Invoke-Capability37MainPhase08 -RunState $RunState
  . Invoke-Capability37MainPhase09 -RunState $RunState
  . Invoke-Capability37MainPhase10 -RunState $RunState
}
. Invoke-Capability37Main -EntryBoundParameters $PSBoundParameters -EntryCmdlet $PSCmdlet -EntryInvocation $MyInvocation -RunState $RunState

# V2 output contract
function Get-Capability37ResultToken {
  $resultToken = if ($Strict -and $findingsOut.Count -gt 0) { 'FAIL' } elseif ($findingsOut.Count -gt 0) { 'WARN' } else { 'OK' }
  return $resultToken
}
$resultToken = Get-Capability37ResultToken
$v2Result = Get-V2ResultObject -ScriptName '37-Remote-Surface-Audit.ps1' -Mode $Mode -Result $resultToken -Findings $findingsOut -Summary $RunState.result.Summary -Metadata @{ Surfaces = $RunState.result.Surfaces }
Write-ResultObject -ResultObject $v2Result -OutputFormat $OutputFormat -OutputPath $OutputPath
if ($PassThru) { $v2Result }
exit (Get-V2ExitCode -Result $resultToken)
