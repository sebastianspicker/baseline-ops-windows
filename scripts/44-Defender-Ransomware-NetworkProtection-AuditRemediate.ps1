#Requires -RunAsAdministrator
#requires -version 5.1
<#
.SYNOPSIS
Audit + optional remediation for Microsoft Defender (PowerShell 5.1):
- Controlled Folder Access (CFA)
- Network Protection (NP)

.DESCRIPTION
- Pipeline outputs ONLY structured objects (one final result object).
- Human-friendly console output uses Write-UiLine only (colors, sections).
- Optional JSON config; safe defaults if JSON is missing/invalid/empty.
- Optional CSV export of the summary object.


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
Defender.AuditResult with properties:
- Summary
- Findings[]
- Before
- After

.PARAMETER Mode
Audit only or remediate.

.PARAMETER EnableControlledFolderAccess
Target state for Controlled Folder Access.

.PARAMETER EnableNetworkProtection
Target state for Network Protection.

.PARAMETER ApplyNetworkProtectionServerPrereqs
Apply server prerequisites for Network Protection when needed.

.PARAMETER DisableDatagramProcessingOnWinServer
Disable datagram processing on Windows Server when applying prerequisites.

.PARAMETER ConfigJsonPath
Optional JSON config path for overrides.

.PARAMETER ExportPath
Optional CSV export path.

.EXAMPLE
  .\44-Defender-Ransomware-NetworkProtection-AuditRemediate.ps1

#>


[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
  [ValidateSet('Audit','Remediate')]
  [string]$Mode = 'Audit',

  [ValidateSet('Disabled','Enabled','AuditMode','BlockDiskModificationOnly','AuditDiskModificationOnly')]
  [string]$EnableControlledFolderAccess = 'Enabled',

  [ValidateSet('Disabled','Enabled','AuditMode')]
  [string]$EnableNetworkProtection = 'Enabled',

  [switch]$ApplyNetworkProtectionServerPrereqs,

  [switch]$DisableDatagramProcessingOnWinServer = $true,

  [string]$ConfigJsonPath,

  [string]$ExportPath

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
Import-Module (Join-Path $script:LibPath 'Results.psm1') -Force
Import-Module (Join-Path $script:LibPath 'External.psm1') -Force
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

$isWindowsHost = ($env:OS -eq 'Windows_NT')
if (-not $isWindowsHost) {
  $summary = [pscustomobject]@{
    ComputerName = $env:COMPUTERNAME
    Timestamp    = Get-Date
    Mode         = $Mode
    Supported    = $false
    Notes        = @('Skipped: this script is only supported on Windows hosts.')
  }
  $result = New-V2ResultObject -ScriptName '44-Defender-Ransomware-NetworkProtection-AuditRemediate.ps1' -Mode $Mode -Result 'OK' -Findings @() -Summary $summary -Metadata @{ UnsupportedHost = $true }
  Write-ResultObject -ResultObject $result -OutputFormat $OutputFormat -OutputPath $OutputPath
  if ($PassThru) { $result }
  exit 0
}

# -----------------------------
# Helpers
# -----------------------------


# Ensure-Cmdlet imported from lib/External.psm1

function Normalize-OptionalPath {
  param([string]$Path)
  if ([string]::IsNullOrWhiteSpace($Path)) { return $null }
  return $Path.Trim()
}

function Get-OsInfo {
  try { Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop }
  catch { Get-WmiObject -Class Win32_OperatingSystem }
}

function Convert-CfaStateToToken {
  param([Parameter(Mandatory)]$Value)
  switch ([string]$Value) {
    '0' { 'Disabled' }
    '1' { 'Enabled' }
    '2' { 'AuditMode' }
    '3' { 'BlockDiskModificationOnly' }
    '4' { 'AuditDiskModificationOnly' }
    'Disabled' { 'Disabled' }
    'Enabled'  { 'Enabled' }
    'AuditMode' { 'AuditMode' }
    'BlockDiskModificationOnly' { 'BlockDiskModificationOnly' }
    'AuditDiskModificationOnly' { 'AuditDiskModificationOnly' }
    default { [string]$Value }
  }
}

function Convert-NpStateToToken {
  param([Parameter(Mandatory)]$Value)
  switch ([string]$Value) {
    '0' { 'Disabled' }
    '1' { 'Enabled' }
    '2' { 'AuditMode' }
    'Disabled' { 'Disabled' }
    'Enabled'  { 'Enabled' }
    'AuditMode' { 'AuditMode' }
    default { [string]$Value }
  }
}

function Get-SafeBool {
  param(
    [Parameter(Mandatory)]$Value,
    [Parameter(Mandatory)][bool]$Default
  )
  if ($null -eq $Value) { return $Default }
  if ($Value -is [bool]) { return $Value }
  switch -Regex ([string]$Value) {
    '^(1|true|yes|y|on)$'  { $true }
    '^(0|false|no|n|off)$' { $false }
    default { $Default }
  }
}

function Get-SafeToken {
  param(
    [Parameter(Mandatory)]$Value,
    [Parameter(Mandatory)][string[]]$Allowed,
    [Parameter(Mandatory)][string]$Default
  )
  if ($null -eq $Value) { return $Default }
  $v = [string]$Value
  if ($Allowed -contains $v) { return $v }
  return $Default
}

function Load-ConfigFromJson {
  param(
    [string]$Path,
    [System.Collections.Generic.List[object]]$FindingList
  )

  $sanitized = Sanitize-Path -Path $Path -MustExist
  if (-not $sanitized) { return @{ Config = $null; FindingList = $FindingList } }

  try {
    if (-not $sanitized) { return @{ Config = $null; FindingList = $FindingList } }

    $raw = Get-Content -LiteralPath $sanitized -Raw -Encoding UTF8 -ErrorAction Stop
    if ([string]::IsNullOrWhiteSpace($raw)) { return @{ Config = $null; FindingList = $FindingList } }

    $cfg = ($raw | ConvertFrom-Json)
    return @{ Config = $cfg; FindingList = $FindingList }
  }
  catch {
    $FindingList = Add-Finding -FindingList $FindingList -Code 'CFG-JSON-LoadFailed' -Severity 'Low' -Message (
      "JSON config could not be loaded; using safe defaults/CLI. Path='{0}'. Error='{1}'" -f 'PATH/TO/JSON', $_.Exception.Message
    )
    return @{ Config = $null; FindingList = $FindingList }
  }
}


function Write-ConsoleReport {
  param(
    [Parameter(Mandatory)]$Summary,
    [Parameter(Mandatory)]$Before,
    [Parameter(Mandatory)]$After,
    [object[]]$FindingList = @()
  )

  $findings = @($FindingList)

  $cTitle = [ConsoleColor]::Cyan
  $cInfo  = [ConsoleColor]::Gray
  $cOk    = [ConsoleColor]::Green
  $cWarn  = [ConsoleColor]::Yellow
  $cBad   = [ConsoleColor]::Red
  $cDim   = [ConsoleColor]::DarkGray

  $headerLine = ("=" * 54)

  Write-ColorLine -Text "" -Color $cInfo
  Write-ColorLine -Text $headerLine -Color $cDim
  Write-ColorLine -Text "Defender Audit/Remediation" -Color $cTitle
  Write-ColorLine -Text $headerLine -Color $cDim

  Write-ColorLine -Text ("Computer : {0}" -f $Summary.ComputerName) -Color $cInfo
  Write-ColorLine -Text ("OS       : {0}" -f $Summary.OS) -Color $cInfo
  Write-ColorLine -Text ("Mode     : {0}" -f $Summary.Mode) -Color $cInfo
  Write-ColorLine -Text ("Time     : {0}" -f $Summary.Timestamp) -Color $cInfo

  $findColor = if ($Summary.FindingsCount -eq 0) { $cOk } elseif ($Summary.FindingsCount -lt 3) { $cWarn } else { $cBad }
  Write-ColorLine -Text ("Findings : {0}" -f $Summary.FindingsCount) -Color $findColor

  Write-ColorLine -Text "" -Color $cInfo
  Write-ColorLine -Text "Desired configuration:" -Color $cTitle
  Write-ColorLine -Text ("  CFA            : {0}" -f $Summary.DesiredCFA) -Color $cInfo
  Write-ColorLine -Text ("  NP             : {0}" -f $Summary.DesiredNP) -Color $cInfo
  Write-ColorLine -Text ("  NP prereqs     : {0}" -f $Summary.ApplyNPPrereqs) -Color $cInfo
  Write-ColorLine -Text ("  Disable UDP srv: {0}" -f $(if ($Summary.IsServer) { $Summary.DisableDatagram } else { "n/a" })) -Color $cInfo

  Write-ColorLine -Text "" -Color $cInfo
  Write-ColorLine -Text "Before -> After:" -Color $cTitle

  function Write-StateDelta {
    param([string]$Name, [string]$From, [string]$To)
    $color = if ($From -eq $To) { $cOk } else { $cWarn }
    Write-ColorLine -Text ("  {0,-14}: {1} -> {2}" -f $Name, $From, $To) -Color $color
  }

  Write-StateDelta -Name 'CFA' -From $Before.ControlledFolderAccess -To $After.ControlledFolderAccess
  Write-StateDelta -Name 'NP'  -From $Before.NetworkProtection      -To $After.NetworkProtection

  if ($Summary.IsServer) {
    Write-StateDelta -Name 'NP OnServer'  -From ([string]$Before.AllowNPOnWinServer)   -To ([string]$After.AllowNPOnWinServer)
    Write-StateDelta -Name 'NP DownLevel' -From ([string]$Before.AllowNPDownLevel)     -To ([string]$After.AllowNPDownLevel)
    Write-StateDelta -Name 'Datagrams'    -From ([string]$Before.AllowDatagramOnServer)-To ([string]$After.AllowDatagramOnServer)
  }

  if ($findings.Count -gt 0) {
    Write-ColorLine -Text "" -Color $cInfo
    Write-ColorLine -Text "Findings (top 20):" -Color $cTitle

    foreach ($f in ($findings | Select-Object -First 20)) {
      $sevColor = switch ($f.Severity) {
        'High'   { $cBad }
        'Medium' { $cWarn }
        default  { $cInfo }
      }
      Write-ColorLine -Text ("  [{0}] {1}: {2}" -f $f.Severity, $f.Code, $f.Message) -Color $sevColor
    }

    if ($findings.Count -gt 20) {
      Write-ColorLine -Text ("  (Only first 20 shown; total findings: {0})" -f $findings.Count) -Color $cDim
    }
  }

  if ($Summary.ExportPath) {
    Write-ColorLine -Text "" -Color $cInfo
    Write-ColorLine -Text ("CSV export : {0}" -f $Summary.ExportPath) -Color $cDim
  }

  Write-ColorLine -Text "" -Color $cInfo
}

# -----------------------------
# Preconditions
# -----------------------------

Require-Admin

Ensure-Cmdlet -Name 'Get-MpPreference'
Ensure-Cmdlet -Name 'Set-MpPreference'

# -----------------------------
# Init + safe defaults
# -----------------------------

$findingList = New-FindingsList

$ConfigJsonPath = Normalize-OptionalPath -Path $ConfigJsonPath
$ExportPath     = Normalize-OptionalPath -Path $ExportPath

$defaults = [pscustomobject]@{
  EnableControlledFolderAccess          = 'Enabled'
  EnableNetworkProtection               = 'Enabled'
  ApplyNetworkProtectionServerPrereqs   = $false
  DisableDatagramProcessingOnWinServer  = $true
  ExportPath                            = $null
}

# -----------------------------
# JSON optional (CLI wins)
# -----------------------------

$cfgResult   = Load-ConfigFromJson -Path $ConfigJsonPath -FindingList $findingList
$config      = $cfgResult.Config
$findingList = $cfgResult.FindingList

$allowedCfa = @('Disabled','Enabled','AuditMode','BlockDiskModificationOnly','AuditDiskModificationOnly')
$allowedNp  = @('Disabled','Enabled','AuditMode')

if ($config) {
  if (-not $PSBoundParameters.ContainsKey('EnableControlledFolderAccess')) {
    $EnableControlledFolderAccess = Get-SafeToken -Value $config.EnableControlledFolderAccess -Allowed $allowedCfa -Default $defaults.EnableControlledFolderAccess
  }
  if (-not $PSBoundParameters.ContainsKey('EnableNetworkProtection')) {
    $EnableNetworkProtection = Get-SafeToken -Value $config.EnableNetworkProtection -Allowed $allowedNp -Default $defaults.EnableNetworkProtection
  }
  if (-not $PSBoundParameters.ContainsKey('ApplyNetworkProtectionServerPrereqs')) {
    $ApplyNetworkProtectionServerPrereqs = Get-SafeBool -Value $config.ApplyNetworkProtectionServerPrereqs -Default $defaults.ApplyNetworkProtectionServerPrereqs
  }
  if (-not $PSBoundParameters.ContainsKey('DisableDatagramProcessingOnWinServer')) {
    $DisableDatagramProcessingOnWinServer = Get-SafeBool -Value $config.DisableDatagramProcessingOnWinServer -Default $defaults.DisableDatagramProcessingOnWinServer
  }
  if (-not $PSBoundParameters.ContainsKey('ExportPath')) {
    $ExportPath = Normalize-OptionalPath -Path ([string]$config.ExportPath)
  }
}

# -----------------------------
# State (before)
# -----------------------------

$os = Get-OsInfo
$isServer = ($os.ProductType -ne 1)

$pref = Get-MpPreference

$before = [pscustomobject]@{
  PSTypeName             = 'Defender.State'
  Phase                  = 'Before'
  ControlledFolderAccess = Convert-CfaStateToToken $pref.EnableControlledFolderAccess
  NetworkProtection      = Convert-NpStateToToken  $pref.EnableNetworkProtection
  AllowNPOnWinServer     = $pref.AllowNetworkProtectionOnWinServer
  AllowNPDownLevel       = $pref.AllowNetworkProtectionDownLevel
  AllowDatagramOnServer  = $pref.AllowDatagramProcessingOnWinServer
}

# -----------------------------
# Audit findings
# -----------------------------

if ($EnableControlledFolderAccess -ne $before.ControlledFolderAccess) {
  $findingList = Add-Finding -FindingList $findingList -Code 'DEF-CFA-NotDesired' -Severity 'Medium' -Message (
    "ControlledFolderAccess is '{0}', desired '{1}'." -f $before.ControlledFolderAccess, $EnableControlledFolderAccess
  ) -Extra @{ Current = $before.ControlledFolderAccess; Desired = $EnableControlledFolderAccess }
}

if ($EnableNetworkProtection -ne $before.NetworkProtection) {
  $findingList = Add-Finding -FindingList $findingList -Code 'DEF-NP-NotDesired' -Severity 'Medium' -Message (
    "NetworkProtection is '{0}', desired '{1}'." -f $before.NetworkProtection, $EnableNetworkProtection
  ) -Extra @{ Current = $before.NetworkProtection; Desired = $EnableNetworkProtection }
}

if ($isServer -and $ApplyNetworkProtectionServerPrereqs) {
  if ($pref.AllowNetworkProtectionOnWinServer -ne $true) {
    $findingList = Add-Finding -FindingList $findingList -Code 'DEF-NP-ServerPrereq-Missing' -Severity 'High' -Message (
      "Windows Server: AllowNetworkProtectionOnWinServer is '{0}', desired '$true'." -f $pref.AllowNetworkProtectionOnWinServer
    ) -TypeName 'Defender.AuditFinding'
  }
  if ($null -ne $pref.AllowNetworkProtectionDownLevel -and $pref.AllowNetworkProtectionDownLevel -ne $true) {
    $findingList = Add-Finding -FindingList $findingList -Code 'DEF-NP-DownLevelPrereq-Missing' -Severity 'High' -Message (
      "Windows Server: AllowNetworkProtectionDownLevel is '{0}', desired '$true'." -f $pref.AllowNetworkProtectionDownLevel
    ) -TypeName 'Defender.AuditFinding'
  }
}

if ($isServer -and $DisableDatagramProcessingOnWinServer) {
  if ($null -ne $pref.AllowDatagramProcessingOnWinServer -and $pref.AllowDatagramProcessingOnWinServer -ne $false) {
    $findingList = Add-Finding -FindingList $findingList -Code 'DEF-NP-DatagramProcessing-NotRecommended' -Severity 'Medium' -Message (
      "Windows Server: AllowDatagramProcessingOnWinServer is '{0}', recommended '$false'." -f $pref.AllowDatagramProcessingOnWinServer
    ) -TypeName 'Defender.AuditFinding'
  }
}

# -----------------------------
# Remediation
# -----------------------------

if ($Mode -eq 'Remediate') {
  if ($PSCmdlet.ShouldProcess($env:COMPUTERNAME, "Configure Defender: CFA + NP")) {

    $setParams = @{
      EnableControlledFolderAccess = $EnableControlledFolderAccess
      EnableNetworkProtection      = $EnableNetworkProtection
    }

    if ($isServer -and $ApplyNetworkProtectionServerPrereqs) {
      $setParams['AllowNetworkProtectionOnWinServer'] = $true
      $setParams['AllowNetworkProtectionDownLevel']   = $true
    }

    if ($isServer -and $DisableDatagramProcessingOnWinServer) {
      $setParams['AllowDatagramProcessingOnWinServer'] = $false
    }

    Set-MpPreference @setParams
  }
}

# -----------------------------
# State (after)
# -----------------------------

$prefAfter = Get-MpPreference

$after = [pscustomobject]@{
  PSTypeName             = 'Defender.State'
  Phase                  = 'After'
  ControlledFolderAccess = Convert-CfaStateToToken $prefAfter.EnableControlledFolderAccess
  NetworkProtection      = Convert-NpStateToToken  $prefAfter.EnableNetworkProtection
  AllowNPOnWinServer     = $prefAfter.AllowNetworkProtectionOnWinServer
  AllowNPDownLevel       = $prefAfter.AllowNetworkProtectionDownLevel
  AllowDatagramOnServer  = $prefAfter.AllowDatagramProcessingOnWinServer
}

# -----------------------------
# Summary + export
# -----------------------------

$summary = [pscustomobject]@{
  PSTypeName      = 'Defender.AuditSummary'
  ComputerName    = $env:COMPUTERNAME
  OS              = $os.Caption
  Version         = $os.Version
  IsServer        = $isServer
  Mode            = $Mode
  Timestamp       = (Get-Date)
  FindingsCount   = $findingList.Count
  DesiredCFA      = $EnableControlledFolderAccess
  DesiredNP       = $EnableNetworkProtection
  ApplyNPPrereqs  = [bool]$ApplyNetworkProtectionServerPrereqs
  DisableDatagram = [bool]$DisableDatagramProcessingOnWinServer
  ConfigJsonPath  = $(if ($ConfigJsonPath) { 'PATH/TO/JSON' } else { $null })
  ExportPath      = $ExportPath
}

if ($ExportPath) {
  $dir = Split-Path -Path $ExportPath -Parent
  if ($dir -and -not (Test-Path -LiteralPath $dir)) {
    New-Item -Path $dir -ItemType Directory -Force | Out-Null
  }
  $summary | Export-Csv -Path $ExportPath -NoTypeInformation -Encoding UTF8
}

# -----------------------------
# Pretty console output (no pipeline pollution)
# -----------------------------

Write-ConsoleReport -Summary $summary -Before $before -After $after -FindingList $findingList

# -----------------------------
# Pipeline output (objects only)
# -----------------------------

# V2 output contract
$resultToken = if ($Strict -and $findingList.Count -gt 0) { 'FAIL' } elseif ($findingList.Count -gt 0) { 'WARN' } else { 'OK' }
$v2Result = New-V2ResultObject -ScriptName '44-Defender-Ransomware-NetworkProtection-AuditRemediate.ps1' -Mode $Mode -Result $resultToken -Findings @($findingList) -Summary $summary -Metadata @{ Before = $before; After = $after }
Write-ResultObject -ResultObject $v2Result -OutputFormat $OutputFormat -OutputPath $OutputPath
if ($PassThru) { $v2Result }
exit 0
