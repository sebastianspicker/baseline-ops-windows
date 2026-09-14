#Requires -RunAsAdministrator
#requires -version 5.1
<#
.SYNOPSIS
Enforces SMB encryption on a Windows host (server-wide or per share) and optionally enforces encrypted outbound SMB connections on the client.

.DESCRIPTION
This script is a safe-by-default SMB encryption enforcer and auditor designed for interactive use and automation.

It supports two v2 execution modes:
- Audit: Reads current SMB server/client/share settings and produces a single structured result object. No changes are made.
- Remediate: Applies SMB encryption changes. The remediation target is controlled by -RemediationScope.

Optional enforcement/hardening:
- ApplyClientRequireEncryption forces outbound SMB connections from this client to require encryption. This can break access to SMB targets
  that do not support SMB encryption.
- EnableRejectUnencryptedAccess hardens the SMB server so that clients that do not support encryption are denied access to encrypted shares.

Configuration can be supplied through an optional JSON file. Parameters explicitly passed to the script always override JSON values.

Output behavior (important):
- Pipeline output: The script emits exactly one structured object at the end (ideal for Export-Csv / ConvertTo-Json / Where-Object).
- Console output: A human-readable summary is printed separately (no pipeline pollution).

.PARAMETER Mode
Selects v2 execution mode:
- Audit     : No changes. Report-only.
- Remediate : Applies changes based on -RemediationScope.

Default: Audit

.PARAMETER RemediationScope
Selects what remediation should target when -Mode Remediate is used:
- ServerGlobal : Enforce server-wide SMB encryption. Optionally also enables encryption on the specified shares.
- ShareOnly    : Enforce SMB encryption only on the specified shares.

Default: ServerGlobal

.PARAMETER ShareName
One or more SMB share names to target.

Behavior depends on Mode/RemediationScope:
- Mode Audit: If provided, those shares are included in the report.
- Mode Remediate + RemediationScope ServerGlobal: If provided, those shares are additionally set to EncryptData=True (optional but recommended for clarity).
- Mode Remediate + RemediationScope ShareOnly: Required. Those shares are set to EncryptData=True.

If a specified share does not exist, the script stops with an error.

.PARAMETER ApplyClientRequireEncryption
When set, configures the SMB client so that outbound SMB connections require encryption.

Warning: This may prevent connections to SMB servers/NAS devices that cannot negotiate SMB encryption.

.PARAMETER EnableRejectUnencryptedAccess
When set, configures the SMB server to reject clients that cannot use encryption when accessing encrypted shares.

Warning: This can block legacy clients or devices that do not support SMB encryption.

.PARAMETER Force
Suppresses additional prompts on SMB configuration changes (in addition to the script’s standard -Confirm / -WhatIf behavior).

Use this for unattended execution, but prefer testing with -WhatIf first.

.PARAMETER JsonPath
Path to an optional JSON configuration file supplied with $JsonPath.

Supported JSON keys:
- Mode (string): Audit | Remediate
- RemediationScope (string): ServerGlobal | ShareOnly
- ShareName (string or array of strings)
- ApplyClientRequireEncryption (boolean or string: true/false/yes/no/1/0)
- EnableRejectUnencryptedAccess (boolean or string)
- Force (boolean or string)

If the JSON file is missing, empty, or invalid, the script continues with safe defaults.

.INPUTS
None. This script does not accept pipeline input.


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
System.Management.Automation.PSCustomObject

The script outputs one object with (at minimum) the following high-level fields:
- ComputerName
- Mode
- ShareName
- ServerEncryptData_Before / After
- ServerRejectUnencryptedAccess_Before / After (if supported)
- ClientRequireEncryption_Before / After (if supported)
- ShareEncryptData_Before / After (arrays of Name/EncryptData pairs when ShareName is specified)
- Changes (Status, what changed, which shares changed)
- Started / Finished (timestamps)

.NOTES
Requirements and assumptions:
- Must be run elevated (Administrator), because SMB configuration changes require administrative privileges.
- Uses -WhatIf / -Confirm (SupportsShouldProcess) to support safe execution and change simulation.
- Console formatting is produced via Write-UiLine / Write-Information and is intentionally separated from pipeline output.

.EXAMPLE
# Report current SMB encryption settings (no changes)
.\22-SMB-Encryption-Enforcer.ps1

.EXAMPLE
# Audit only, but include specific shares in the report
.\22-SMB-Encryption-Enforcer.ps1 -Mode Audit -ShareName 'Public','Finance'

.EXAMPLE
# Enforce server-wide SMB encryption (preview changes)
.\22-SMB-Encryption-Enforcer.ps1 -Mode Remediate -RemediationScope ServerGlobal -WhatIf

.EXAMPLE
# Enforce server-wide SMB encryption and harden server to reject unencrypted-capability clients
.\22-SMB-Encryption-Enforcer.ps1 -Mode Remediate -RemediationScope ServerGlobal -EnableRejectUnencryptedAccess -Force

.EXAMPLE
# Enforce encryption only for selected shares (staged rollout)
.\22-SMB-Encryption-Enforcer.ps1 -Mode Remediate -RemediationScope ShareOnly -ShareName 'Finance','HR' -Force

.EXAMPLE
# Enforce share encryption and require encryption for outbound SMB from this machine (high impact; test first)
.\22-SMB-Encryption-Enforcer.ps1 -Mode Remediate -RemediationScope ShareOnly -ShareName 'Finance' -ApplyClientRequireEncryption -WhatIf

.EXAMPLE
# Use a JSON config as defaults (script parameters override JSON when specified)
.\22-SMB-Encryption-Enforcer.ps1 -JsonPath $JsonPath -Mode Audit
#>


[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
  [ValidateSet('Audit','Remediate')]
  [string]$Mode = 'Audit',

  [ValidateSet('ServerGlobal','ShareOnly')]
  [string]$RemediationScope = 'ServerGlobal',

  [string[]]$ShareName,

  [switch]$ApplyClientRequireEncryption,

  [switch]$EnableRejectUnencryptedAccess,

  [switch]$Force,

  [string]$JsonPath

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
function Test-AllConditions {
  param([scriptblock[]]$Conditions)
  foreach ($condition in $Conditions) {
    if (-not (. $condition)) { return $false }
  }
  return $true
}
function Test-AnyCondition {
  param([scriptblock[]]$Conditions)
  foreach ($condition in $Conditions) {
    if (. $condition) { return $true }
  }
  return $false
}
function Initialize-Capability22Runtime {
  param($EntryBoundParameters)
  $RunState = @{
    ApplyClientRequireEncryption = $ApplyClientRequireEncryption
    EnableRejectUnencryptedAccess = $EnableRejectUnencryptedAccess
    Force = $Force
    Mode = $Mode
    RemediationScope = $RemediationScope
    ShareName = $ShareName
  }
Import-Module (Join-Path $script:LibPath 'Output.psm1') -Force
Import-Module (Join-Path $script:LibPath 'Common.psm1') -Force -DisableNameChecking
Import-Module (Join-Path $script:LibPath 'Results.psm1') -Force
Import-Module (Join-Path $script:LibPath 'External.psm1') -Force -DisableNameChecking
Import-Module (Join-Path $script:LibPath Serialization.psm1) -Force
. (Join-Path $PSScriptRoot 'internal/22-SMB-Encryption-Enforcer.failures.ps1')


Set-StrictMode -Version Latest
$script:__V2Context = Initialize-V2Context -ScriptName '22-SMB-Encryption-Enforcer.ps1' -BoundParameters $EntryBoundParameters `
  -Values @{ Mode = $RunState.Mode; ConfigPath = $ConfigPath; OutputFormat = $OutputFormat; OutputPath = $OutputPath; PassThru = $PassThru; Strict = $Strict; Quiet = $Quiet; NoColor = $NoColor; DeriveRemediate = $false }
if ($script:__V2Context.Quiet) { $InformationPreference = 'SilentlyContinue'; $VerbosePreference = 'SilentlyContinue' }
$script:NoColor = [bool]$script:__V2Context.NoColor
$ErrorActionPreference = 'Stop'

$RunState.isWindowsHost = ($env:OS -eq 'Windows_NT')
  $script:RunState = $RunState
}

. Initialize-Capability22Runtime -EntryBoundParameters $PSBoundParameters
if (-not $RunState.isWindowsHost) {
  $summary = [pscustomobject]@{
    ComputerName = $env:COMPUTERNAME
    Timestamp    = Get-Date
    Mode         = $RunState.Mode
    Supported    = $false
    Notes        = @('Skipped: this script is only supported on Windows hosts.')
  }
  $unsupportedResult = if ($Strict) { 'FAIL' } else { 'WARN' }
  $RunState.result = Get-V2ResultObject -ScriptName '22-SMB-Encryption-Enforcer.ps1' -Mode $RunState.Mode -Result $unsupportedResult -Findings @() -Summary $summary -Metadata @{ UnsupportedHost = $true }
  Write-ResultObject -ResultObject $RunState.result -OutputFormat $OutputFormat -OutputPath $OutputPath
  if ($PassThru) { $RunState.result }
  exit (Get-V2ExitCode -Result $unsupportedResult)
}

# -------------------------
# Helpers
# -------------------------

# Ensure-Cmdlet imported from lib/External.psm1

function Get-Prop {
  param(
    [Parameter(Mandatory)]$Object,
    [Parameter(Mandatory)][string]$Name
  )
  if ($null -eq $Object) { return $null }
  if ($Object.PSObject.Properties.Name -contains $Name) { return $Object.$Name }
  return $null
}

function ConvertTo-BoolOrNull {
  param($Value)
  if ($null -eq $Value) { return $null }
  if ($Value -is [bool]) { return $Value }
  $s = ([string]$Value).Trim()
  if ($s -match '^(?i:true|1|yes|y|on|enable|enabled)$') { return $true }
  if ($s -match '^(?i:false|0|no|n|off|disable|disabled)$') { return $false }
  return $null
}

function Load-JsonConfigOrDefault {
  param([string]$Path, [hashtable]$RunState)
  $defaults = Get-SmbDefaultConfig
  if ([string]::IsNullOrWhiteSpace($Path)) { return $defaults }
  if (-not (Test-Path -LiteralPath $Path)) {
    Write-Verbose -Message ('Config JSON not found at {0}. Using defaults.' -f $Path)
    return $defaults
  }
  try {
    $raw = Get-BoundedUtf8FileContent -Path $Path -MaximumBytes 1048576
    if ([string]::IsNullOrWhiteSpace($raw)) {
      Write-Verbose -Message ('Config JSON is empty at {0}. Using defaults.' -f $Path)
      return $defaults
    }
    $cfg = $raw | ConvertFrom-Json
    if ($null -eq $cfg) { return $defaults }
    Merge-SmbConfig -Defaults $defaults -Config $cfg -RunState $RunState
    return $defaults
  } catch {
    Write-Warning -Message ('Failed to load/parse config JSON at {0}. Using defaults. Error: {1}' -f $Path, $_.Exception.Message)
    return $defaults
  }
}
function Get-SmbDefaultConfig {
  return [pscustomobject]@{
    Mode                         = 'Audit'
    RemediationScope             = 'ServerGlobal'
    ShareName                     = @()
    ApplyClientRequireEncryption  = $false
    EnableRejectUnencryptedAccess = $false
    Force                         = $false
  }
}
function Merge-SmbConfig {
  param($Defaults, $Config, [hashtable]$RunState)
  $RunState.mode = [string](Get-Prop -Object $Config -Name 'Mode')
  if (@('Audit','Remediate') -contains $RunState.mode) { $Defaults.Mode = $RunState.mode }
  elseif (@('ServerGlobal','ShareOnly') -contains $RunState.mode) {
    $Defaults.Mode = 'Remediate'
    $Defaults.RemediationScope = $RunState.mode
  } elseif ($RunState.mode -eq 'AuditOnly') { $Defaults.Mode = 'Audit' }
  $scope = [string](Get-Prop -Object $Config -Name 'RemediationScope')
  if (@('ServerGlobal','ShareOnly') -contains $scope) { $Defaults.RemediationScope = $scope }
  $RunState.shareName = Get-Prop -Object $Config -Name 'ShareName'
  if ($null -ne $RunState.shareName) { $Defaults.ShareName = @($RunState.shareName) }
  Set-SmbBooleanConfig -Defaults $Defaults -Config $Config
}
function Set-SmbBooleanConfig {
  param($Defaults, $Config)
  foreach ($name in @('ApplyClientRequireEncryption','EnableRejectUnencryptedAccess','Force')) {
    $value = ConvertTo-BoolOrNull (Get-Prop -Object $Config -Name $name)
    if ($null -ne $value) { $Defaults.$name = $value }
  }
}

function Resolve-Shares {
  param([string[]]$Names)

  if (-not $Names -or $Names.Count -eq 0) { return @() }

  $resolved = New-Object System.Collections.Generic.List[object]
  foreach ($n in $Names) {
    if ([string]::IsNullOrWhiteSpace($n)) { continue }
    try {
      $resolved.Add((Get-SmbShare -Name $n -ErrorAction Stop))
    } catch {
      $all = (Get-SmbShare | Select-Object -ExpandProperty Name) -join ', '
      throw ('Share not found: ''{0}''. Available shares: {1}' -f $n, $all)
    }
  }

  return ,$resolved.ToArray()
}

function Invoke-SetSmbServerConfiguration {
  param([hashtable]$Params, [hashtable]$RunState)
  $Params['Confirm'] = $false
  if ($RunState.Force) { $Params['Force'] = $true }
  Set-SmbServerConfiguration @Params
}

function Invoke-SetSmbShare {
  param([hashtable]$Params, [hashtable]$RunState)
  $Params['Confirm'] = $false
  if ($RunState.Force) { $Params['Force'] = $true }
  Set-SmbShare @Params
}
# Encryption per share uses Set-SmbShare -EncryptData.

function Invoke-SetSmbClientConfiguration {
  param([hashtable]$Params, [hashtable]$RunState)
  $Params['Confirm'] = $false
  if ($RunState.Force) { $Params['Force'] = $true }
  Set-SmbClientConfiguration @Params
}

function Set-IfDifferent {
  [CmdletBinding(SupportsShouldProcess = $true)]
  param(
    [Parameter(Mandatory)][bool]$Current,
    [Parameter(Mandatory)][bool]$Desired,
    [Parameter(Mandatory)][string]$Target,
    [Parameter(Mandatory)][string]$Action,
    [Parameter(Mandatory)][scriptblock]$Setter
  )

  if ($Current -eq $Desired) { return $false }

  if ($PSCmdlet.ShouldProcess($Target, $Action)) {
    & $Setter
    return $true
  }

  return $false
}

function Format-Bool {
  param($Value)
  if ($null -eq $Value) { return 'n/a' }
  if ([bool]$Value) { return 'True' }
  return 'False'
}


function Write-PrettySettingChange {
  param(
    [Parameter(Mandatory)][string]$Label,
    $Before,
    $After,
    [switch]$Supported
  )

  if (-not $Supported) {
    Write-KeyValue -Key $Label -Value 'n/a (not supported on this OS/build)' -ValueColor 'Warning'
    return
  }

  $b = Format-Bool $Before
  $a = Format-Bool $After

  $changed = ($b -ne $a)
  $color = if ($changed) { [ConsoleColor]::Yellow } else { [ConsoleColor]::Gray }

  Write-UiLine -Text ('{0,-32}: ' -f $Label) -Color ([ConsoleColor]::DarkGray) -NoNewline
  Write-UiLine -Text ('{0} -> {1}' -f $b, $a) -Color $color
}

# -------------------------
# Apply JSON defaults (only when parameters not explicitly provided)
# -------------------------
function Invoke-Capability22MainPhase01 {
  param([hashtable]$RunState)
  $sanitized = Sanitize-Path -Path $JsonPath -MustExist
  $cfg = Load-JsonConfigOrDefault -Path $sanitized -RunState $RunState

  if (-not $script:__EntryBoundParameters.ContainsKey('Mode')) { $RunState.Mode = $cfg.Mode }
  if (-not $script:__EntryBoundParameters.ContainsKey('RemediationScope')) { $RunState.RemediationScope = $cfg.RemediationScope }
  if (-not $script:__EntryBoundParameters.ContainsKey('ShareName')) { $RunState.ShareName = @($cfg.ShareName) }

  if (-not $script:__EntryBoundParameters.ContainsKey('ApplyClientRequireEncryption') -and $cfg.ApplyClientRequireEncryption) {
    $RunState.ApplyClientRequireEncryption = $true
  }
}
function Invoke-Capability22MainPhase02 {
  param([hashtable]$RunState)
  if (-not $script:__EntryBoundParameters.ContainsKey('EnableRejectUnencryptedAccess') -and $cfg.EnableRejectUnencryptedAccess) {
    $RunState.EnableRejectUnencryptedAccess = $true
  }
  if (-not $script:__EntryBoundParameters.ContainsKey('Force') -and $cfg.Force) {
    $RunState.Force = $true
  }

  # -------------------------
  # Preconditions
  # -------------------------
  Require-Admin

  Ensure-Cmdlet 'Get-SmbServerConfiguration'
  Ensure-Cmdlet 'Set-SmbServerConfiguration'
  Ensure-Cmdlet 'Get-SmbShare'
  Ensure-Cmdlet 'Set-SmbShare'
  Ensure-Cmdlet 'Get-SmbClientConfiguration'
  Ensure-Cmdlet 'Set-SmbClientConfiguration'

  # Probe for optional properties to avoid StrictMode "property not found".
  $serverCfgProbe = Get-SmbServerConfiguration
  $clientCfgProbe = Get-SmbClientConfiguration

  $RunState.hasRejectUnencryptedAccess = ($serverCfgProbe.PSObject.Properties.Name -contains 'RejectUnencryptedAccess')
  $RunState.hasClientRequireEncryption = ($clientCfgProbe.PSObject.Properties.Name -contains 'RequireEncryption')

  # -------------------------
  # Main
  # -------------------------
  $script:Findings = Get-FindingsList
}
function Invoke-Capability22MainPhase03 {
  param([hashtable]$RunState)
  if ($RunState.EnableRejectUnencryptedAccess -and -not $RunState.hasRejectUnencryptedAccess) {
    $message = 'RejectUnencryptedAccess is not available on this OS/build. Cannot enable it.'
    $failure = New-SmbUnsupportedFeatureFailure -Message $message -Mode $RunState.Mode -FindingList $script:Findings
    Write-ResultObject -ResultObject $failure.Result -OutputFormat $OutputFormat -OutputPath $OutputPath
    if ($PassThru) { $failure.Result }
    exit (Get-V2ExitCode -Result $failure.Token)
  }
}
function Invoke-Capability22MainPhase04 {
  param([hashtable]$RunState)
  if ($RunState.ApplyClientRequireEncryption -and -not $RunState.hasClientRequireEncryption) {
    $message = 'Client RequireEncryption is not available on this OS/build. Cannot enable it.'
    $failure = New-SmbUnsupportedFeatureFailure -Message $message -Mode $RunState.Mode -FindingList $script:Findings
    Write-ResultObject -ResultObject $failure.Result -OutputFormat $OutputFormat -OutputPath $OutputPath
    if ($PassThru) { $failure.Result }
    exit (Get-V2ExitCode -Result $failure.Token)
  }

  $RunState.start = Get-Date

  $RunState.serverCfgBefore = Get-SmbServerConfiguration
  $RunState.clientCfgBefore = Get-SmbClientConfiguration
  $RunState.sharesBefore    = @(Resolve-Shares -Names $RunState.ShareName)

  $RunState.changes = [ordered]@{
    ServerEncryptDataChanged             = $false
    ServerRejectUnencryptedAccessChanged = $false
    ClientRequireEncryptionChanged       = $false
    SharesChanged                        = New-Object System.Collections.Generic.List[string]
    ShareCountTargeted                   = @($RunState.ShareName).Count
    Status                               = 'OK'
  }
}
function Invoke-Capability22MainPhase05Step01 {
  param([hashtable]$RunState)
$RunState.serverCfgAfter = Get-SmbServerConfiguration
    $RunState.clientCfgAfter = Get-SmbClientConfiguration
    $RunState.sharesAfter    = @(Resolve-Shares -Names $RunState.ShareName)
}

function Invoke-Capability22MainPhase05Step02 {
  param([hashtable]$RunState)
$shareNames = Get-ArrayOrEmpty -Value $RunState.ShareName
$serverRejectBefore = Get-ValueWhenSupported -Supported $RunState.hasRejectUnencryptedAccess -Value (Get-Prop $RunState.serverCfgBefore 'RejectUnencryptedAccess')
$serverRejectAfter = Get-ValueWhenSupported -Supported $RunState.hasRejectUnencryptedAccess -Value (Get-Prop $RunState.serverCfgAfter 'RejectUnencryptedAccess')
$clientRequireBefore = Get-ValueWhenSupported -Supported $RunState.hasClientRequireEncryption -Value (Get-Prop $RunState.clientCfgBefore 'RequireEncryption')
$clientRequireAfter = Get-ValueWhenSupported -Supported $RunState.hasClientRequireEncryption -Value (Get-Prop $RunState.clientCfgAfter 'RequireEncryption')
$RunState.result = [pscustomobject]@{
      ComputerName                          = $env:COMPUTERNAME
      Mode                                  = $RunState.Mode
      RemediationScope                      = $RunState.RemediationScope
      ShareName                             = $shareNames

      ApplyClientRequireEncryption          = [bool]$RunState.ApplyClientRequireEncryption
      EnableRejectUnencryptedAccess         = [bool]$RunState.EnableRejectUnencryptedAccess
      Force                                 = [bool]$RunState.Force
      WhatIf                                = [bool]$WhatIfPreference
      JsonPath                              = $JsonPath

      Started                               = $RunState.start
      Finished                              = Get-Date

      ServerEncryptData_Before              = Get-Prop $RunState.serverCfgBefore 'EncryptData'
      ServerEncryptData_After               = Get-Prop $RunState.serverCfgAfter  'EncryptData'

      ServerRejectUnencryptedAccess_Before  = $serverRejectBefore
      ServerRejectUnencryptedAccess_After   = $serverRejectAfter

      ShareEncryptData_Before               = @($RunState.sharesBefore | Select-Object Name, EncryptData)
      ShareEncryptData_After                = @($RunState.sharesAfter | Select-Object Name, EncryptData)

      ClientRequireEncryption_Before        = $clientRequireBefore
      ClientRequireEncryption_After         = $clientRequireAfter

      Changes                               = [pscustomobject]@{
        Status                               = $RunState.changes.Status
        ServerEncryptDataChanged             = [bool]$RunState.changes.ServerEncryptDataChanged
        ServerRejectUnencryptedAccessChanged = [bool]$RunState.changes.ServerRejectUnencryptedAccessChanged
        ClientRequireEncryptionChanged       = [bool]$RunState.changes.ClientRequireEncryptionChanged
        SharesChanged                        = @($RunState.changes.SharesChanged)
        ShareCountTargeted                   = [int]$RunState.changes.ShareCountTargeted
      }
    }
}
function Get-ValueWhenSupported {
  param([bool]$Supported, $Value)
  if ($Supported) { return $Value }
  return $null
}
function Get-ArrayOrEmpty {
  param([AllowNull()]$Value)
  if ($null -eq $Value) { return @() }
  return @($Value)
}

function Invoke-Capability22MainPhase05Step03 {
  param([hashtable]$RunState)
$summaryObj = [pscustomobject]@{ ComputerName = $RunState.result.ComputerName; StartTime = $RunState.result.Started; EndTime = $RunState.result.Finished }
    $findingsAL = ConvertTo-ArrayList -InputObject $script:Findings
    Write-ConsoleSummary -Summary $summaryObj -Findings $findingsAL `
      -CustomFields ([ordered]@{
        Mode             = $RunState.result.Mode
        WhatIf           = (Format-Bool $RunState.result.WhatIf)
        Force            = (Format-Bool $RunState.result.Force)
        Status           = $RunState.result.Changes.Status
        'Shares targeted' = $RunState.result.Changes.ShareCountTargeted
      })
    # Server / Client section
    Write-UiLine ''
    Write-UiLine -Text 'Server / Client' -Color ([ConsoleColor]::Cyan)
    Write-UiLine -Text ('-' * 46) -Color ([ConsoleColor]::DarkGray)
    Write-PrettySettingChange -Label 'Server EncryptData' `
      -Before $RunState.result.ServerEncryptData_Before -After $RunState.result.ServerEncryptData_After -Supported:$true
    Write-PrettySettingChange -Label 'Server RejectUnencryptedAccess' `
      -Before $RunState.result.ServerRejectUnencryptedAccess_Before -After $RunState.result.ServerRejectUnencryptedAccess_After -Supported:$RunState.hasRejectUnencryptedAccess
    Write-PrettySettingChange -Label 'Client RequireEncryption' `
      -Before $RunState.result.ClientRequireEncryption_Before -After $RunState.result.ClientRequireEncryption_After -Supported:$RunState.hasClientRequireEncryption
    # Shares changed
    if (@($RunState.result.Changes.SharesChanged).Count -gt 0) {
      Write-KeyValue -Key 'Shares changed' -Value (@($RunState.result.Changes.SharesChanged) -join ', ') -ValueColor ([ConsoleColor]::Yellow)
    } else {
      Write-KeyValue -Key 'Shares changed' -Value 'none' -ValueColor ([ConsoleColor]::Gray)
    }
}

function Invoke-Capability22MainPhase05Stage01 {
  param([hashtable]$RunState)
switch ($RunState.Mode) {

      'Audit' {
        Invoke-SmbEncryptionAudit -RunState $RunState
      }

      'Remediate' {
        Invoke-SmbEncryptionRemediation -RunState $RunState
      }
    }
}
function Invoke-SmbEncryptionAudit {
  param([hashtable]$RunState)
  if (-not $RunState.serverCfgBefore.EncryptData) {
    Add-Finding -FindingList $script:Findings -Code 'SMB-Encryption-Disabled' -Severity 'Medium' -Message 'Server-wide SMB encryption is disabled.'
  }
  if ($RunState.hasRejectUnencryptedAccess -and -not $RunState.serverCfgBefore.RejectUnencryptedAccess) {
    Add-Finding -FindingList $script:Findings -Code 'SMB-RejectUnencrypted-Disabled' -Severity 'Low' -Message 'SMB server RejectUnencryptedAccess is disabled.'
  }
  foreach ($share in $RunState.sharesBefore) {
    if (-not $share.EncryptData) {
      Add-Finding -FindingList $script:Findings -Code 'SMB-Share-NotEncrypted' -Severity 'Low' -Message "Share '$($share.Name)' encryption is disabled." -Extra @{ Share = $share.Name }
    }
  }
}
function Set-SmbSharesEncrypted {
  param([hashtable]$RunState)
  foreach ($share in $RunState.sharesBefore) {
    $did = Set-IfDifferent -Current ([bool](Get-Prop $share 'EncryptData')) -Desired $true `
      -Target $share.Name -Action ('Set-SmbShare EncryptData=True ({0})' -f $share.Name) `
      -Setter { Invoke-SetSmbShare @{ Name = $share.Name; EncryptData = $true } -RunState $RunState }
    if ($did) { $null = $RunState.changes.SharesChanged.Add($share.Name) }
  }
}
function Invoke-SmbEncryptionRemediation {
  param([hashtable]$RunState)
  switch ($RunState.RemediationScope) {
    'ServerGlobal' {
            $RunState.changes.ServerEncryptDataChanged =
              Set-IfDifferent -Current ([bool](Get-Prop $RunState.serverCfgBefore 'EncryptData')) -Desired $true `
                -Target $env:COMPUTERNAME `
                -Action 'Set-SmbServerConfiguration EncryptData=True' `
                -Setter { Invoke-SetSmbServerConfiguration @{ EncryptData = $true } -RunState $RunState }

            if ($RunState.EnableRejectUnencryptedAccess) {
              $RunState.changes.ServerRejectUnencryptedAccessChanged =
                Set-IfDifferent -Current ([bool](Get-Prop $RunState.serverCfgBefore 'RejectUnencryptedAccess')) -Desired $true `
                  -Target $env:COMPUTERNAME `
                  -Action 'Set-SmbServerConfiguration RejectUnencryptedAccess=True' `
                  -Setter { Invoke-SetSmbServerConfiguration @{ RejectUnencryptedAccess = $true } -RunState $RunState }
              # Microsoft documents RejectUnencryptedAccess behavior/parameter.
            }

            Set-SmbSharesEncrypted -RunState $RunState
    }

          'ShareOnly' {

            if ((Test-AnyCondition -Conditions @({ -not $RunState.ShareName }, { $RunState.ShareName.Count -eq 0 }))) {
              throw 'Mode Remediate with RemediationScope=ShareOnly requires at least one -ShareName.'
            }

            Set-SmbSharesEncrypted -RunState $RunState

            if ($RunState.EnableRejectUnencryptedAccess) {
              $serverNow = Get-SmbServerConfiguration
              $RunState.changes.ServerRejectUnencryptedAccessChanged =
                Set-IfDifferent -Current ([bool](Get-Prop $serverNow 'RejectUnencryptedAccess')) -Desired $true `
                  -Target $env:COMPUTERNAME `
                  -Action 'Set-SmbServerConfiguration RejectUnencryptedAccess=True' `
                  -Setter { Invoke-SetSmbServerConfiguration @{ RejectUnencryptedAccess = $true } -RunState $RunState }
            }
    }
  }
}

function Invoke-Capability22MainPhase05Stage02 {
  param([hashtable]$RunState)
if ($RunState.ApplyClientRequireEncryption) {
      $clientNow = Get-SmbClientConfiguration
      $RunState.changes.ClientRequireEncryptionChanged =
        Set-IfDifferent -Current ([bool](Get-Prop $clientNow 'RequireEncryption')) -Desired $true `
          -Target $env:COMPUTERNAME `
          -Action 'Set-SmbClientConfiguration RequireEncryption=True' `
          -Setter { Invoke-SetSmbClientConfiguration @{ RequireEncryption = $true } -RunState $RunState }
    }
}

function Invoke-Capability22MainPhase05 {
  param([hashtable]$RunState)
  try {

    . Invoke-Capability22MainPhase05Stage01 -RunState $RunState
. Invoke-Capability22MainPhase05Stage02 -RunState $RunState

  } catch {
    $RunState.changes.Status = 'FAILED'
    Add-Finding -FindingList $script:Findings -Code 'SMB-RemediationFailed' -Severity 'Critical' -Message ("SMB remediation failed: {0}" -f $_.Exception.Message)
  } finally {

    . Invoke-Capability22MainPhase05Step01 -RunState $RunState
. Invoke-Capability22MainPhase05Step02 -RunState $RunState
. Invoke-Capability22MainPhase05Step03 -RunState $RunState

  }
}
function Invoke-Capability22Main {
  param($EntryBoundParameters, $EntryCmdlet, $EntryInvocation, [hashtable]$RunState)
  $script:__EntryBoundParameters = $EntryBoundParameters
  $script:__EntryCmdlet = $EntryCmdlet
  $script:__EntryInvocation = $EntryInvocation
  . Invoke-Capability22MainPhase01 -RunState $RunState
  . Invoke-Capability22MainPhase02 -RunState $RunState
  . Invoke-Capability22MainPhase03 -RunState $RunState
  . Invoke-Capability22MainPhase04 -RunState $RunState
  . Invoke-Capability22MainPhase05 -RunState $RunState
}
. Invoke-Capability22Main -EntryBoundParameters $PSBoundParameters -EntryCmdlet $PSCmdlet -EntryInvocation $MyInvocation -RunState $RunState

# V2 output contract
function Get-Capability22ResultToken {
  $resultToken = if ($Strict -and $script:Findings.Count -gt 0) { 'FAIL' } elseif ($script:Findings.Count -gt 0) { 'WARN' } else { 'OK' }
  return $resultToken
}
$resultToken = Get-Capability22ResultToken
$v2Result = Get-V2ResultObject -ScriptName '22-SMB-Encryption-Enforcer.ps1' -Mode $RunState.Mode -Result $resultToken -Findings (ConvertTo-ObjectArray -InputObject $script:Findings) -Summary $RunState.result -Metadata @{}
Write-ResultObject -ResultObject $v2Result -OutputFormat $OutputFormat -OutputPath $OutputPath
if ($PassThru) { $v2Result }
exit (Get-V2ExitCode -Result $resultToken)
