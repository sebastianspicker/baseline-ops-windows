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
Path to an optional JSON configuration file (example placeholder: PATH/TO/JSON/config.json).

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
.\22-SMB-Encryption-Enforcer.ps1 -JsonPath 'PATH/TO/JSON/config.json' -Mode Audit
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
  $result = New-V2ResultObject -ScriptName '22-SMB-Encryption-Enforcer.ps1' -Mode $Mode -Result 'OK' -Findings @() -Summary $summary -Metadata @{ UnsupportedHost = $true }
  Write-ResultObject -ResultObject $result -OutputFormat $OutputFormat -OutputPath $OutputPath
  if ($PassThru) { $result }
  exit 0
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
  param([string]$Path)

  # Safe defaults if config is missing/invalid.
  $defaults = [pscustomobject]@{
    Mode                         = 'Audit'
    RemediationScope             = 'ServerGlobal'
    ShareName                     = @()
    ApplyClientRequireEncryption  = $false
    EnableRejectUnencryptedAccess = $false
    Force                         = $false
  }

  if ([string]::IsNullOrWhiteSpace($Path)) { return $defaults }

  if (-not (Test-Path -LiteralPath $Path)) {
    Write-Verbose -Message ('Config JSON not found at {0}. Using defaults.' -f $Path)
    return $defaults
  }

  try {
    $raw = Get-Content -LiteralPath $Path -Raw -Encoding UTF8
    if ([string]::IsNullOrWhiteSpace($raw)) {
      Write-Verbose -Message ('Config JSON is empty at {0}. Using defaults.' -f $Path)
      return $defaults
    }

    $cfg = $raw | ConvertFrom-Json
    if ($null -eq $cfg) { return $defaults }

    $mode = [string](Get-Prop -Object $cfg -Name 'Mode')
    if ($mode -and @('Audit','Remediate') -contains $mode) {
      $defaults.Mode = $mode
    } elseif ($mode -and @('ServerGlobal','ShareOnly') -contains $mode) {
      # Legacy mapping for v1 mode values.
      $defaults.Mode = 'Remediate'
      $defaults.RemediationScope = $mode
    } elseif ($mode -eq 'AuditOnly') {
      $defaults.Mode = 'Audit'
    }

    $scope = [string](Get-Prop -Object $cfg -Name 'RemediationScope')
    if ($scope -and @('ServerGlobal','ShareOnly') -contains $scope) {
      $defaults.RemediationScope = $scope
    }

    $sn = Get-Prop -Object $cfg -Name 'ShareName'
    if ($null -ne $sn) { $defaults.ShareName = @($sn) }

    $b1 = ConvertTo-BoolOrNull (Get-Prop -Object $cfg -Name 'ApplyClientRequireEncryption')
    if ($null -ne $b1) { $defaults.ApplyClientRequireEncryption = $b1 }

    $b2 = ConvertTo-BoolOrNull (Get-Prop -Object $cfg -Name 'EnableRejectUnencryptedAccess')
    if ($null -ne $b2) { $defaults.EnableRejectUnencryptedAccess = $b2 }

    $b3 = ConvertTo-BoolOrNull (Get-Prop -Object $cfg -Name 'Force')
    if ($null -ne $b3) { $defaults.Force = $b3 }

    return $defaults
  } catch {
    Write-Warning -Message ('Failed to load/parse config JSON at {0}. Using defaults. Error: {1}' -f $Path, $_.Exception.Message)
    return $defaults
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
  param([hashtable]$Params)
  $Params['Confirm'] = $false
  if ($Force) { $Params['Force'] = $true }
  Set-SmbServerConfiguration @Params
}

function Invoke-SetSmbShare {
  param([hashtable]$Params)
  $Params['Confirm'] = $false
  if ($Force) { $Params['Force'] = $true }
  Set-SmbShare @Params
}
# Encryption per share uses Set-SmbShare -EncryptData. [web:6]

function Invoke-SetSmbClientConfiguration {
  param([hashtable]$Params)
  $Params['Confirm'] = $false
  if ($Force) { $Params['Force'] = $true }
  Set-SmbClientConfiguration @Params
}

function Set-IfDifferent {
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

function Test-IsConsoleHost {
  # Avoid color/control sequences in non-interactive hosts.
  return ($Host.Name -match 'ConsoleHost')
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

  Write-ColorLine -Text ('{0,-32}: ' -f $Label) -Color ([ConsoleColor]::DarkGray) -NoNewline
  Write-ColorLine -Text ('{0} -> {1}' -f $b, $a) -Color $color
}

# -------------------------
# Apply JSON defaults (only when parameters not explicitly provided)
# -------------------------
$sanitized = Sanitize-Path -Path $JsonPath -MustExist
$cfg = Load-JsonConfigOrDefault -Path $sanitized

if (-not $PSBoundParameters.ContainsKey('Mode')) { $Mode = $cfg.Mode }
if (-not $PSBoundParameters.ContainsKey('RemediationScope')) { $RemediationScope = $cfg.RemediationScope }
if (-not $PSBoundParameters.ContainsKey('ShareName')) { $ShareName = @($cfg.ShareName) }

if (-not $PSBoundParameters.ContainsKey('ApplyClientRequireEncryption') -and $cfg.ApplyClientRequireEncryption) {
  $ApplyClientRequireEncryption = $true
}
if (-not $PSBoundParameters.ContainsKey('EnableRejectUnencryptedAccess') -and $cfg.EnableRejectUnencryptedAccess) {
  $EnableRejectUnencryptedAccess = $true
}
if (-not $PSBoundParameters.ContainsKey('Force') -and $cfg.Force) {
  $Force = $true
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

$hasRejectUnencryptedAccess = ($serverCfgProbe.PSObject.Properties.Name -contains 'RejectUnencryptedAccess')
$hasClientRequireEncryption = ($clientCfgProbe.PSObject.Properties.Name -contains 'RequireEncryption')

# -------------------------
# Main
# -------------------------
$script:Findings = New-FindingsList

if ($EnableRejectUnencryptedAccess -and -not $hasRejectUnencryptedAccess) {
  $msg = 'RejectUnencryptedAccess is not available on this OS/build. Cannot enable it.'
  Write-Warning $msg
  Add-Finding -FindingList $script:Findings -Code 'SMB-UnsupportedFeature' -Severity 'Critical' -Message $msg
  $v2Result = New-V2ResultObject -ScriptName '22-SMB-Encryption-Enforcer.ps1' -Mode $Mode -Result 'FAIL' -Findings @($script:Findings) -Summary @{ Error = $msg } -Metadata @{}
  Write-ResultObject -ResultObject $v2Result -OutputFormat $OutputFormat -OutputPath $OutputPath
  if ($PassThru) { $v2Result }
  exit 1
}
if ($ApplyClientRequireEncryption -and -not $hasClientRequireEncryption) {
  $msg = 'Client RequireEncryption is not available on this OS/build. Cannot enable it.'
  Write-Warning $msg
  Add-Finding -FindingList $script:Findings -Code 'SMB-UnsupportedFeature' -Severity 'Critical' -Message $msg
  $v2Result = New-V2ResultObject -ScriptName '22-SMB-Encryption-Enforcer.ps1' -Mode $Mode -Result 'FAIL' -Findings @($script:Findings) -Summary @{ Error = $msg } -Metadata @{}
  Write-ResultObject -ResultObject $v2Result -OutputFormat $OutputFormat -OutputPath $OutputPath
  if ($PassThru) { $v2Result }
  exit 1
}

$start = Get-Date

$serverCfgBefore = Get-SmbServerConfiguration
$clientCfgBefore = Get-SmbClientConfiguration
$sharesBefore    = @(Resolve-Shares -Names $ShareName)

$changes = [ordered]@{
  ServerEncryptDataChanged             = $false
  ServerRejectUnencryptedAccessChanged = $false
  ClientRequireEncryptionChanged       = $false
  SharesChanged                        = New-Object System.Collections.Generic.List[string]
  ShareCountTargeted                   = @($ShareName).Count
  Status                               = 'OK'
}

try {

  switch ($Mode) {

    'Audit' {
      if (-not $serverCfgBefore.EncryptData) {
        Add-Finding -Code 'SMB-Encryption-Disabled' -Severity 'Medium' -Message 'Server-wide SMB encryption is disabled.'
      }
      if ($hasRejectUnencryptedAccess -and -not $serverCfgBefore.RejectUnencryptedAccess) {
        Add-Finding -Code 'SMB-RejectUnencrypted-Disabled' -Severity 'Low' -Message 'SMB server RejectUnencryptedAccess is disabled.'
      }
      foreach ($s in $sharesBefore) {
        if (-not $s.EncryptData) {
          Add-Finding -Code 'SMB-Share-NotEncrypted' -Severity 'Low' -Message "Share '$($s.Name)' encryption is disabled." -Extra @{ Share = $s.Name }
        }
      }
    }

    'Remediate' {
      switch ($RemediationScope) {
        'ServerGlobal' {
          $changes.ServerEncryptDataChanged =
            Set-IfDifferent -Current ([bool](Get-Prop $serverCfgBefore 'EncryptData')) -Desired $true `
              -Target $env:COMPUTERNAME `
              -Action 'Set-SmbServerConfiguration EncryptData=True' `
              -Setter { Invoke-SetSmbServerConfiguration @{ EncryptData = $true } }

          if ($EnableRejectUnencryptedAccess) {
            $changes.ServerRejectUnencryptedAccessChanged =
              Set-IfDifferent -Current ([bool](Get-Prop $serverCfgBefore 'RejectUnencryptedAccess')) -Desired $true `
                -Target $env:COMPUTERNAME `
                -Action 'Set-SmbServerConfiguration RejectUnencryptedAccess=True' `
                -Setter { Invoke-SetSmbServerConfiguration @{ RejectUnencryptedAccess = $true } }
            # Microsoft documents RejectUnencryptedAccess behavior/parameter. [web:24]
          }

          foreach ($s in $sharesBefore) {
            $did = Set-IfDifferent -Current ([bool](Get-Prop $s 'EncryptData')) -Desired $true `
              -Target $s.Name `
              -Action ('Set-SmbShare EncryptData=True ({0})' -f $s.Name) `
              -Setter { Invoke-SetSmbShare @{ Name = $s.Name; EncryptData = $true } }

            if ($did) { $null = $changes.SharesChanged.Add($s.Name) }
          }
        }

        'ShareOnly' {

          if (-not $ShareName -or $ShareName.Count -eq 0) {
            throw 'Mode Remediate with RemediationScope=ShareOnly requires at least one -ShareName.'
          }

          foreach ($s in $sharesBefore) {
            $did = Set-IfDifferent -Current ([bool](Get-Prop $s 'EncryptData')) -Desired $true `
              -Target $s.Name `
              -Action ('Set-SmbShare EncryptData=True ({0})' -f $s.Name) `
              -Setter { Invoke-SetSmbShare @{ Name = $s.Name; EncryptData = $true } }

            if ($did) { $null = $changes.SharesChanged.Add($s.Name) }
          }

          if ($EnableRejectUnencryptedAccess) {
            $serverNow = Get-SmbServerConfiguration
            $changes.ServerRejectUnencryptedAccessChanged =
              Set-IfDifferent -Current ([bool](Get-Prop $serverNow 'RejectUnencryptedAccess')) -Desired $true `
                -Target $env:COMPUTERNAME `
                -Action 'Set-SmbServerConfiguration RejectUnencryptedAccess=True' `
                -Setter { Invoke-SetSmbServerConfiguration @{ RejectUnencryptedAccess = $true } }
          }
        }
      }
    }
  }

  if ($ApplyClientRequireEncryption) {
    $clientNow = Get-SmbClientConfiguration
    $changes.ClientRequireEncryptionChanged =
      Set-IfDifferent -Current ([bool](Get-Prop $clientNow 'RequireEncryption')) -Desired $true `
        -Target $env:COMPUTERNAME `
        -Action 'Set-SmbClientConfiguration RequireEncryption=True' `
        -Setter { Invoke-SetSmbClientConfiguration @{ RequireEncryption = $true } }
  }

} catch {
  $changes.Status = 'FAILED'
  Add-Finding -FindingList $script:Findings -Code 'SMB-RemediationFailed' -Severity 'Critical' -Message ("SMB remediation failed: {0}" -f $_.Exception.Message)
} finally {

  $serverCfgAfter = Get-SmbServerConfiguration
  $clientCfgAfter = Get-SmbClientConfiguration
  $sharesAfter    = @(Resolve-Shares -Names $ShareName)

  $result = [pscustomobject]@{
    ComputerName                          = $env:COMPUTERNAME
    Mode                                  = $Mode
    RemediationScope                      = $RemediationScope
    ShareName                             = if ($ShareName) { @($ShareName) } else { @() }

    ApplyClientRequireEncryption          = [bool]$ApplyClientRequireEncryption
    EnableRejectUnencryptedAccess         = [bool]$EnableRejectUnencryptedAccess
    Force                                 = [bool]$Force
    WhatIf                                = [bool]$WhatIfPreference
    JsonPath                              = $JsonPath

    Started                               = $start
    Finished                              = Get-Date

    ServerEncryptData_Before              = Get-Prop $serverCfgBefore 'EncryptData'
    ServerEncryptData_After               = Get-Prop $serverCfgAfter  'EncryptData'

    ServerRejectUnencryptedAccess_Before  = if ($hasRejectUnencryptedAccess) { Get-Prop $serverCfgBefore 'RejectUnencryptedAccess' } else { $null }
    ServerRejectUnencryptedAccess_After   = if ($hasRejectUnencryptedAccess) { Get-Prop $serverCfgAfter  'RejectUnencryptedAccess' } else { $null }

    ShareEncryptData_Before               = if (@($sharesBefore).Count -gt 0) { @($sharesBefore | Select-Object Name, EncryptData) } else { @() }
    ShareEncryptData_After                = if (@($sharesAfter).Count  -gt 0) { @($sharesAfter  | Select-Object Name, EncryptData) } else { @() }

    ClientRequireEncryption_Before        = if ($hasClientRequireEncryption) { Get-Prop $clientCfgBefore 'RequireEncryption' } else { $null }
    ClientRequireEncryption_After         = if ($hasClientRequireEncryption) { Get-Prop $clientCfgAfter  'RequireEncryption' } else { $null }

    Changes                               = [pscustomobject]@{
      Status                               = $changes.Status
      ServerEncryptDataChanged             = [bool]$changes.ServerEncryptDataChanged
      ServerRejectUnencryptedAccessChanged = [bool]$changes.ServerRejectUnencryptedAccessChanged
      ClientRequireEncryptionChanged       = [bool]$changes.ClientRequireEncryptionChanged
      SharesChanged                        = @($changes.SharesChanged)
      ShareCountTargeted                   = [int]$changes.ShareCountTargeted
    }
  }

  # Console-only output (no pipeline pollution)
  $summaryObj = [pscustomobject]@{ ComputerName = $result.ComputerName; StartTime = $result.Started; EndTime = $result.Finished }
  $findingsAL = [System.Collections.ArrayList]@($script:Findings)
  Write-ConsoleSummary -Summary $summaryObj -Findings $findingsAL `
    -CustomFields ([ordered]@{
      Mode             = $result.Mode
      WhatIf           = (Format-Bool $result.WhatIf)
      Force            = (Format-Bool $result.Force)
      Status           = $result.Changes.Status
      'Shares targeted' = $result.Changes.ShareCountTargeted
    })
  # Server / Client section
  Write-UiLine ''
  Write-ColorLine -Text 'Server / Client' -Color ([ConsoleColor]::Cyan)
  Write-ColorLine -Text ('-' * 46) -Color ([ConsoleColor]::DarkGray)
  Write-PrettySettingChange -Label 'Server EncryptData' `
    -Before $result.ServerEncryptData_Before -After $result.ServerEncryptData_After -Supported:$true
  Write-PrettySettingChange -Label 'Server RejectUnencryptedAccess' `
    -Before $result.ServerRejectUnencryptedAccess_Before -After $result.ServerRejectUnencryptedAccess_After -Supported:$hasRejectUnencryptedAccess
  Write-PrettySettingChange -Label 'Client RequireEncryption' `
    -Before $result.ClientRequireEncryption_Before -After $result.ClientRequireEncryption_After -Supported:$hasClientRequireEncryption
  # Shares changed
  if (@($result.Changes.SharesChanged).Count -gt 0) {
    Write-KeyValue -Key 'Shares changed' -Value (@($result.Changes.SharesChanged) -join ', ') -ValueColor ([ConsoleColor]::Yellow)
  } else {
    Write-KeyValue -Key 'Shares changed' -Value 'none' -ValueColor ([ConsoleColor]::Gray)
  }

}

# V2 output contract
$resultToken = if ($Strict -and $script:Findings.Count -gt 0) { 'FAIL' } elseif ($script:Findings.Count -gt 0) { 'WARN' } else { 'OK' }
$v2Result = New-V2ResultObject -ScriptName '22-SMB-Encryption-Enforcer.ps1' -Mode $Mode -Result $resultToken -Findings @($script:Findings) -Summary $result -Metadata @{}
Write-ResultObject -ResultObject $v2Result -OutputFormat $OutputFormat -OutputPath $OutputPath
if ($PassThru) { $v2Result }
exit 0
