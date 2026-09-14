#Requires -RunAsAdministrator
#requires -version 5.1
<#
.SYNOPSIS
Audit + optional remediation for Microsoft Defender (PowerShell 5.1):
- Controlled Folder Access (CFA)
- Network Protection (NP)

.DESCRIPTION
- Pipeline outputs ONLY structured objects (one final result object).
- Colorized, sectioned console output uses Write-UiLine only.
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

  [bool]$DisableDatagramProcessingOnWinServer = $true,

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
function Initialize-Capability44Runtime {
  param($EntryBoundParameters)
  $RunState = @{
    ApplyNetworkProtectionServerPrereqs = $ApplyNetworkProtectionServerPrereqs
    DisableDatagramProcessingOnWinServer = $DisableDatagramProcessingOnWinServer
    EnableControlledFolderAccess = $EnableControlledFolderAccess
    EnableNetworkProtection = $EnableNetworkProtection
    ExportPath = $ExportPath
  }
Import-Module (Join-Path $script:LibPath 'Output.psm1') -Force
Import-Module (Join-Path $script:LibPath 'Common.psm1') -Force -DisableNameChecking
Import-Module (Join-Path $script:LibPath 'Results.psm1') -Force
Import-Module (Join-Path $script:LibPath 'External.psm1') -Force -DisableNameChecking
Import-Module (Join-Path $script:LibPath Serialization.psm1) -Force


Set-StrictMode -Version Latest
$script:__V2Context = Initialize-V2Context -ScriptName '44-Defender-Ransomware-NetworkProtection-AuditRemediate.ps1' -BoundParameters $EntryBoundParameters `
  -Values @{ Mode = $Mode; ConfigPath = $ConfigPath; OutputFormat = $OutputFormat; OutputPath = $OutputPath; PassThru = $PassThru; Strict = $Strict; Quiet = $Quiet; NoColor = $NoColor; DeriveRemediate = $false }
if ($script:__V2Context.Quiet) { $InformationPreference = 'SilentlyContinue'; $VerbosePreference = 'SilentlyContinue' }
$script:NoColor = [bool]$script:__V2Context.NoColor
$ErrorActionPreference = 'Stop'

$RunState.isWindowsHost = ($env:OS -eq 'Windows_NT')
  $script:RunState = $RunState
}

. Initialize-Capability44Runtime -EntryBoundParameters $PSBoundParameters
if (-not $RunState.isWindowsHost) {
  $RunState.summary = [pscustomobject]@{
    ComputerName = $env:COMPUTERNAME
    Timestamp    = Get-Date
    Mode         = $Mode
    Supported    = $false
    Notes        = @('Skipped: this script is only supported on Windows hosts.')
  }
  $unsupportedResult = if ($Strict) { 'FAIL' } else { 'WARN' }
  $result = Get-V2ResultObject -ScriptName '44-Defender-Ransomware-NetworkProtection-AuditRemediate.ps1' -Mode $Mode -Result $unsupportedResult -Findings @() -Summary $RunState.summary -Metadata @{ UnsupportedHost = $true }
  Write-ResultObject -ResultObject $result -OutputFormat $OutputFormat -OutputPath $OutputPath
  if ($PassThru) { $result }
  exit (Get-V2ExitCode -Result $unsupportedResult)
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
  catch { throw "Failed to query Win32_OperatingSystem via CIM: $($_.Exception.Message)" }
}

function Convert-CfaStateToToken {
  param([Parameter(Mandatory)]$Value)
  $tokens = @{ '0' = 'Disabled'; '1' = 'Enabled'; '2' = 'AuditMode'; '3' = 'BlockDiskModificationOnly'; '4' = 'AuditDiskModificationOnly' }
  $text = [string]$Value
  if ($tokens.ContainsKey($text)) { return $tokens[$text] }
  return $text
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

    $raw = Get-BoundedUtf8FileContent -Path $sanitized -MaximumBytes 1048576
    if ([string]::IsNullOrWhiteSpace($raw)) { return @{ Config = $null; FindingList = $FindingList } }

    $cfg = ($raw | ConvertFrom-Json)
    return @{ Config = $cfg; FindingList = $FindingList }
  }
  catch {
    $FindingList = Add-Finding -FindingList $FindingList -Code 'CFG-JSON-LoadFailed' -Severity 'Low' -Message (
      "JSON config could not be loaded; using safe defaults/CLI. Path='{0}'. Error='{1}'" -f '[configured path]', $_.Exception.Message
    ) -PassThru
    return @{ Config = $null; FindingList = $FindingList }
  }
}


function Write-ConsoleReportSection01 {
  param([hashtable]$RunState)
$RunState.findings = @($RunState.FindingList)

  $cTitle = [ConsoleColor]::Cyan
  $cInfo  = [ConsoleColor]::Gray
  $cOk    = [ConsoleColor]::Green
  $cWarn  = [ConsoleColor]::Yellow
  $cBad   = [ConsoleColor]::Red
  $cDim   = [ConsoleColor]::DarkGray

  $headerLine = ("=" * 54)

  Write-UiLine -Text "" -Color $cInfo
  Write-UiLine -Text $headerLine -Color $cDim
  Write-UiLine -Text "Defender Audit/Remediation" -Color $cTitle
  Write-UiLine -Text $headerLine -Color $cDim

  Write-UiLine -Text ("Computer : {0}" -f $RunState.Summary.ComputerName) -Color $cInfo
  Write-UiLine -Text ("OS       : {0}" -f $RunState.Summary.OS) -Color $cInfo
  Write-UiLine -Text ("Mode     : {0}" -f $RunState.Summary.Mode) -Color $cInfo
  Write-UiLine -Text ("Time     : {0}" -f $RunState.Summary.Timestamp) -Color $cInfo

  $findColor = if ($RunState.Summary.FindingsCount -eq 0) { $cOk } elseif ($RunState.Summary.FindingsCount -lt 3) { $cWarn } else { $cBad }
  Write-UiLine -Text ("Findings : {0}" -f $RunState.Summary.FindingsCount) -Color $findColor

  Write-UiLine -Text "" -Color $cInfo
  Write-UiLine -Text "Desired configuration:" -Color $cTitle
  Write-UiLine -Text ("  CFA            : {0}" -f $RunState.Summary.DesiredCFA) -Color $cInfo
  Write-UiLine -Text ("  NP             : {0}" -f $RunState.Summary.DesiredNP) -Color $cInfo
  Write-UiLine -Text ("  NP prereqs     : {0}" -f $RunState.Summary.ApplyNPPrereqs) -Color $cInfo
  Write-UiLine -Text ("  Disable UDP srv: {0}" -f $(if ($RunState.Summary.IsServer) { $RunState.Summary.DisableDatagram } else { "n/a" })) -Color $cInfo

  Write-UiLine -Text "" -Color $cInfo
  Write-UiLine -Text "Before -> After:" -Color $cTitle

  function Write-StateDelta {
    param([string]$Name, [string]$From, [string]$To)
    $color = if ($From -eq $To) { $cOk } else { $cWarn }
    Write-UiLine -Text ("  {0,-14}: {1} -> {2}" -f $Name, $From, $To) -Color $color
  }

  Write-StateDelta -Name 'CFA' -From $RunState.Before.ControlledFolderAccess -To $RunState.After.ControlledFolderAccess
}

function Write-ConsoleReportSection02 {
  param([hashtable]$RunState)
Write-StateDelta -Name 'NP'  -From $RunState.Before.NetworkProtection      -To $RunState.After.NetworkProtection

  if ($RunState.Summary.IsServer) {
    Write-StateDelta -Name 'NP OnServer'  -From ([string]$RunState.Before.AllowNPOnWinServer)   -To ([string]$RunState.After.AllowNPOnWinServer)
    Write-StateDelta -Name 'NP DownLevel' -From ([string]$RunState.Before.AllowNPDownLevel)     -To ([string]$RunState.After.AllowNPDownLevel)
    Write-StateDelta -Name 'Datagrams'    -From ([string]$RunState.Before.AllowDatagramOnServer)-To ([string]$RunState.After.AllowDatagramOnServer)
  }
}

function Write-ConsoleReportSection03 {
  param([hashtable]$RunState)
if ($RunState.findings.Count -gt 0) {
    Write-UiLine -Text "" -Color $cInfo
    Write-UiLine -Text "Findings (top 20):" -Color $cTitle

    foreach ($f in ($RunState.findings | Select-Object -First 20)) {
      $sevColor = switch ($f.Severity) {
        'High'   { $cBad }
        'Medium' { $cWarn }
        default  { $cInfo }
      }
      Write-UiLine -Text ("  [{0}] {1}: {2}" -f $f.Severity, $f.Code, $f.Message) -Color $sevColor
    }

    if ($RunState.findings.Count -gt 20) {
      Write-UiLine -Text ("  (Only first 20 shown; total findings: {0})" -f $RunState.findings.Count) -Color $cDim
    }
  }
}

function Write-ConsoleReportSection04 {
  param([hashtable]$RunState)
if ($RunState.Summary.ExportPath) {
    Write-UiLine -Text "" -Color $cInfo
    Write-UiLine -Text ("CSV export : {0}" -f $RunState.Summary.ExportPath) -Color $cDim
  }

  Write-UiLine -Text "" -Color $cInfo
}

function Write-ConsoleReport {
  param(
    [Parameter(Mandatory)]$Summary,
    [Parameter(Mandatory)]$Before,
    [Parameter(Mandatory)]$After,
    [object[]]$FindingList = @()
  , [hashtable]$RunState)
  $RunState.After = $After
  $RunState.Before = $Before
  $RunState.FindingList = $FindingList
  $RunState.Summary = $Summary

    . Write-ConsoleReportSection01 -RunState $RunState
    . Write-ConsoleReportSection02 -RunState $RunState
    . Write-ConsoleReportSection03 -RunState $RunState
    . Write-ConsoleReportSection04 -RunState $RunState
}

# -----------------------------
# Preconditions
# -----------------------------

function Invoke-Capability44MainPhase01 {
  param([hashtable]$RunState)
  Require-Admin

  Ensure-Cmdlet -Name 'Get-MpPreference'
  Ensure-Cmdlet -Name 'Set-MpPreference'

  # -----------------------------
  # Init + safe defaults
  # -----------------------------

  $RunState.findingList = Get-FindingsList

  $ConfigJsonPath = Normalize-OptionalPath -Path $ConfigJsonPath
  $RunState.ExportPath     = Normalize-OptionalPath -Path $RunState.ExportPath

  $RunState.defaults = [pscustomobject]@{
    EnableControlledFolderAccess          = 'Enabled'
    EnableNetworkProtection               = 'Enabled'
    ApplyNetworkProtectionServerPrereqs   = $false
    DisableDatagramProcessingOnWinServer  = $true
    ExportPath                            = $null
  }

  # -----------------------------
  # JSON optional (CLI wins)
  # -----------------------------

  $cfgResult   = Load-ConfigFromJson -Path $ConfigJsonPath -FindingList $RunState.findingList
  $RunState.config      = $cfgResult.Config
  $RunState.findingList = $cfgResult.FindingList

  $RunState.allowedCfa = @('Disabled','Enabled','AuditMode','BlockDiskModificationOnly','AuditDiskModificationOnly')
  $RunState.allowedNp  = @('Disabled','Enabled','AuditMode')
}
function Invoke-Capability44MainPhase02 {
  param([hashtable]$RunState)
  if ($RunState.config) {
    if (-not $script:__EntryBoundParameters.ContainsKey('EnableControlledFolderAccess')) {
      $RunState.EnableControlledFolderAccess = Get-SafeToken -Value $RunState.config.EnableControlledFolderAccess -Allowed $RunState.allowedCfa -Default $RunState.defaults.EnableControlledFolderAccess
    }
    if (-not $script:__EntryBoundParameters.ContainsKey('EnableNetworkProtection')) {
      $RunState.EnableNetworkProtection = Get-SafeToken -Value $RunState.config.EnableNetworkProtection -Allowed $RunState.allowedNp -Default $RunState.defaults.EnableNetworkProtection
    }
    if (-not $script:__EntryBoundParameters.ContainsKey('ApplyNetworkProtectionServerPrereqs')) {
      $RunState.ApplyNetworkProtectionServerPrereqs = Get-SafeBool -Value $RunState.config.ApplyNetworkProtectionServerPrereqs -Default $RunState.defaults.ApplyNetworkProtectionServerPrereqs
    }
    if (-not $script:__EntryBoundParameters.ContainsKey('DisableDatagramProcessingOnWinServer')) {
      $RunState.DisableDatagramProcessingOnWinServer = Get-SafeBool -Value $RunState.config.DisableDatagramProcessingOnWinServer -Default $RunState.defaults.DisableDatagramProcessingOnWinServer
    }
    if (-not $script:__EntryBoundParameters.ContainsKey('ExportPath')) {
      $RunState.ExportPath = Normalize-OptionalPath -Path ([string]$RunState.config.ExportPath)
    }
  }
}
function Invoke-Capability44MainPhase03 {
  param([hashtable]$RunState)
  $os = Get-OsInfo
  $RunState.isServer = ($os.ProductType -ne 1)

  $pref = Get-MpPreference

  $RunState.before = [pscustomobject]@{
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

  if ($RunState.EnableControlledFolderAccess -ne $RunState.before.ControlledFolderAccess) {
    $RunState.findingList = Add-Finding -FindingList $RunState.findingList -Code 'DEF-CFA-NotDesired' -Severity 'Medium' -Message (
      "ControlledFolderAccess is '{0}', desired '{1}'." -f $RunState.before.ControlledFolderAccess, $RunState.EnableControlledFolderAccess
    ) -Extra @{ Current = $RunState.before.ControlledFolderAccess; Desired = $RunState.EnableControlledFolderAccess } -PassThru
  }

  if ($RunState.EnableNetworkProtection -ne $RunState.before.NetworkProtection) {
    $RunState.findingList = Add-Finding -FindingList $RunState.findingList -Code 'DEF-NP-NotDesired' -Severity 'Medium' -Message (
      "NetworkProtection is '{0}', desired '{1}'." -f $RunState.before.NetworkProtection, $RunState.EnableNetworkProtection
    ) -Extra @{ Current = $RunState.before.NetworkProtection; Desired = $RunState.EnableNetworkProtection } -PassThru
  }
}
function Invoke-Capability44MainPhase04 {
  param([hashtable]$RunState)
  if ($RunState.isServer -and $RunState.ApplyNetworkProtectionServerPrereqs) {
    if ($pref.AllowNetworkProtectionOnWinServer -ne $true) {
      $RunState.findingList = Add-Finding -FindingList $RunState.findingList -Code 'DEF-NP-ServerPrereq-Missing' -Severity 'High' -Message (
        "Windows Server: AllowNetworkProtectionOnWinServer is '{0}', desired '$true'." -f $pref.AllowNetworkProtectionOnWinServer
      ) -TypeName 'Defender.AuditFinding' -PassThru
    }
    if ($null -ne $pref.AllowNetworkProtectionDownLevel -and $pref.AllowNetworkProtectionDownLevel -ne $true) {
      $RunState.findingList = Add-Finding -FindingList $RunState.findingList -Code 'DEF-NP-DownLevelPrereq-Missing' -Severity 'High' -Message (
        "Windows Server: AllowNetworkProtectionDownLevel is '{0}', desired '$true'." -f $pref.AllowNetworkProtectionDownLevel
      ) -TypeName 'Defender.AuditFinding' -PassThru
    }
  }
}
function Invoke-Capability44MainPhase05 {
  param([hashtable]$RunState)
  if ($RunState.isServer -and $RunState.DisableDatagramProcessingOnWinServer) {
    if ($null -ne $pref.AllowDatagramProcessingOnWinServer -and $pref.AllowDatagramProcessingOnWinServer -ne $false) {
      $RunState.findingList = Add-Finding -FindingList $RunState.findingList -Code 'DEF-NP-DatagramProcessing-NotRecommended' -Severity 'Medium' -Message (
        "Windows Server: AllowDatagramProcessingOnWinServer is '{0}', recommended '$false'." -f $pref.AllowDatagramProcessingOnWinServer
      ) -TypeName 'Defender.AuditFinding' -PassThru
    }
  }
}
function Invoke-Capability44MainPhase06 {
  param([hashtable]$RunState)
  if ($Mode -eq 'Remediate') {
    if ($script:__EntryCmdlet.ShouldProcess($env:COMPUTERNAME, "Configure Defender: CFA + NP")) {

      $setParams = @{
        EnableControlledFolderAccess = $RunState.EnableControlledFolderAccess
        EnableNetworkProtection      = $RunState.EnableNetworkProtection
      }

      if ($RunState.isServer -and $RunState.ApplyNetworkProtectionServerPrereqs) {
        $setParams['AllowNetworkProtectionOnWinServer'] = $true
        $setParams['AllowNetworkProtectionDownLevel']   = $true
      }

      if ($RunState.isServer -and $RunState.DisableDatagramProcessingOnWinServer) {
        $setParams['AllowDatagramProcessingOnWinServer'] = $false
      }

      Set-MpPreference @setParams
    }
  }
}
function Invoke-Capability44MainPhase07 {
  param([hashtable]$RunState)
  $prefAfter = Get-MpPreference

  $RunState.after = [pscustomobject]@{
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

  $RunState.summary = [pscustomobject]@{
    PSTypeName      = 'Defender.AuditSummary'
    ComputerName    = $env:COMPUTERNAME
    OS              = $os.Caption
    Version         = $os.Version
    IsServer        = $RunState.isServer
    Mode            = $Mode
    Timestamp       = (Get-Date)
    FindingsCount   = $RunState.findingList.Count
    DesiredCFA      = $RunState.EnableControlledFolderAccess
    DesiredNP       = $RunState.EnableNetworkProtection
    ApplyNPPrereqs  = [bool]$RunState.ApplyNetworkProtectionServerPrereqs
    DisableDatagram = [bool]$RunState.DisableDatagramProcessingOnWinServer
    ConfigJsonPath  = $(if ($ConfigJsonPath) { '[configured path]' } else { $null })
    ExportPath      = $RunState.ExportPath
  }

  if ($RunState.ExportPath) {
    $dir = Split-Path -Path $RunState.ExportPath -Parent
    if ($dir -and -not (Test-Path -LiteralPath $dir)) {
      New-Item -Path $dir -ItemType Directory -Force | Out-Null
    }
    $RunState.summary | Export-Csv -Path $RunState.ExportPath -NoTypeInformation -Encoding UTF8
  }

  # -----------------------------
  # Formatted console output (no pipeline output)
  # -----------------------------

  Write-ConsoleReport -Summary $RunState.summary -Before $RunState.before -After $RunState.after -FindingList $RunState.findingList -RunState $RunState
}
function Invoke-Capability44Main {
  param($EntryBoundParameters, $EntryCmdlet, $EntryInvocation, [hashtable]$RunState)
  $script:__EntryBoundParameters = $EntryBoundParameters
  $script:__EntryCmdlet = $EntryCmdlet
  $script:__EntryInvocation = $EntryInvocation
  . Invoke-Capability44MainPhase01 -RunState $RunState
  . Invoke-Capability44MainPhase02 -RunState $RunState
  . Invoke-Capability44MainPhase03 -RunState $RunState
  . Invoke-Capability44MainPhase04 -RunState $RunState
  . Invoke-Capability44MainPhase05 -RunState $RunState
  . Invoke-Capability44MainPhase06 -RunState $RunState
  . Invoke-Capability44MainPhase07 -RunState $RunState
}
. Invoke-Capability44Main -EntryBoundParameters $PSBoundParameters -EntryCmdlet $PSCmdlet -EntryInvocation $MyInvocation -RunState $RunState

# -----------------------------
# Pipeline output (objects only)
# -----------------------------

# V2 output contract
function Get-Capability44ResultToken {
  param([hashtable]$RunState)
  $resultToken = if ($Strict -and $RunState.findingList.Count -gt 0) { 'FAIL' } elseif ($RunState.findingList.Count -gt 0) { 'WARN' } else { 'OK' }
  return $resultToken
}
$resultToken = Get-Capability44ResultToken -RunState $RunState
$v2Result = Get-V2ResultObject -ScriptName '44-Defender-Ransomware-NetworkProtection-AuditRemediate.ps1' -Mode $Mode -Result $resultToken -Findings (ConvertTo-ObjectArray -InputObject $RunState.findingList) -Summary $RunState.summary -Metadata @{ Before = $RunState.before; After = $RunState.after }
Write-ResultObject -ResultObject $v2Result -OutputFormat $OutputFormat -OutputPath $OutputPath
if ($PassThru) { $v2Result }
exit (Get-V2ExitCode -Result $resultToken)
