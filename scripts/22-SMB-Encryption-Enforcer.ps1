#requires -version 5.1
<#
.SYNOPSIS
Enforces SMB encryption on a Windows host (server-wide or per share) and optionally enforces encrypted outbound SMB connections on the client.

.DESCRIPTION
This script is a safe-by-default SMB encryption enforcer and auditor designed for interactive use and automation.

It supports three operating modes:
- AuditOnly: Reads current SMB server/client/share settings and produces a single structured result object. No changes are made.
- ServerGlobal: Enables server-wide SMB encryption and (optionally) sets encryption on the specified shares for transparency/consistency.
- ShareOnly: Enables SMB encryption only on the specified shares (useful for staged rollouts).

Optional enforcement/hardening:
- ApplyClientRequireEncryption forces outbound SMB connections from this client to require encryption. This can break access to SMB targets
  that do not support SMB encryption.
- EnableRejectUnencryptedAccess hardens the SMB server so that clients that do not support encryption are denied access to encrypted shares.

Configuration can be supplied through an optional JSON file. Parameters explicitly passed to the script always override JSON values.

Output behavior (important):
- Pipeline output: The script emits exactly one structured object at the end (ideal for Export-Csv / ConvertTo-Json / Where-Object).
- Console output: A human-readable summary is printed separately (no pipeline pollution).

.PARAMETER Mode
Selects the operating mode:
- AuditOnly    : No changes. Report-only.
- ServerGlobal : Enforce server-wide SMB encryption. Optionally also enables encryption on the specified shares.
- ShareOnly    : Enforce SMB encryption only on the specified shares.

Default: AuditOnly

.PARAMETER ShareName
One or more SMB share names to target.

Behavior depends on Mode:
- AuditOnly: If provided, those shares are included in the report.
- ServerGlobal: If provided, those shares are additionally set to EncryptData=True (optional but recommended for clarity).
- ShareOnly: Required. Those shares are set to EncryptData=True.

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
- Mode (string): AuditOnly | ServerGlobal | ShareOnly
- ShareName (string or array of strings)
- ApplyClientRequireEncryption (boolean or string: true/false/yes/no/1/0)
- EnableRejectUnencryptedAccess (boolean or string)
- Force (boolean or string)

If the JSON file is missing, empty, or invalid, the script continues with safe defaults.

.INPUTS
None. This script does not accept pipeline input.

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
- Console formatting is produced via Write-Host / Write-Information and is intentionally separated from pipeline output.

.EXAMPLE
# Report current SMB encryption settings (no changes)
.\22-SMB-Encryption-Enforcer.ps1

.EXAMPLE
# Audit only, but include specific shares in the report
.\22-SMB-Encryption-Enforcer.ps1 -Mode AuditOnly -ShareName 'Public','Finance'

.EXAMPLE
# Enforce server-wide SMB encryption (preview changes)
.\22-SMB-Encryption-Enforcer.ps1 -Mode ServerGlobal -WhatIf

.EXAMPLE
# Enforce server-wide SMB encryption and harden server to reject unencrypted-capability clients
.\22-SMB-Encryption-Enforcer.ps1 -Mode ServerGlobal -EnableRejectUnencryptedAccess -Force

.EXAMPLE
# Enforce encryption only for selected shares (staged rollout)
.\22-SMB-Encryption-Enforcer.ps1 -Mode ShareOnly -ShareName 'Finance','HR' -Force

.EXAMPLE
# Enforce share encryption and require encryption for outbound SMB from this machine (high impact; test first)
.\22-SMB-Encryption-Enforcer.ps1 -Mode ShareOnly -ShareName 'Finance' -ApplyClientRequireEncryption -WhatIf

.EXAMPLE
# Use a JSON config as defaults (script parameters override JSON when specified)
.\22-SMB-Encryption-Enforcer.ps1 -JsonPath 'PATH/TO/JSON/config.json' -Mode AuditOnly
#>


[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
  [ValidateSet('ServerGlobal','ShareOnly','AuditOnly')]
  [string]$Mode = 'AuditOnly',

  [string[]]$ShareName,

  [switch]$ApplyClientRequireEncryption,

  [switch]$EnableRejectUnencryptedAccess,

  [switch]$Force,

  [string]$JsonPath = 'PATH/TO/JSON/config.json'
)

$script:LibPath = Join-Path $PSScriptRoot 'lib'
Import-Module (Join-Path $script:LibPath 'Common.psm1') -Force


Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# -------------------------
# Helpers
# -------------------------

function Ensure-Cmdlet {
  param([Parameter(Mandatory)][string]$Name)
  if (-not (Get-Command -Name $Name -ErrorAction SilentlyContinue)) {
    throw ('Required cmdlet missing: {0}. Verify the SmbShare module / OS features.' -f $Name)
  }
}

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
    Mode                         = 'AuditOnly'
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
    $raw = Get-Content -LiteralPath $Path -Raw
    if ([string]::IsNullOrWhiteSpace($raw)) {
      Write-Verbose -Message ('Config JSON is empty at {0}. Using defaults.' -f $Path)
      return $defaults
    }

    $cfg = $raw | ConvertFrom-Json
    if ($null -eq $cfg) { return $defaults }

    $mode = Get-Prop -Object $cfg -Name 'Mode'
    if ($mode -and @('ServerGlobal','ShareOnly','AuditOnly') -contains $mode) {
      $defaults.Mode = $mode
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

function Write-PrettyLine {
  param(
    [Parameter(Mandatory)][string]$Text,
    [ConsoleColor]$Color = [ConsoleColor]::Gray,
    [switch]$NoNewline
  )
  if (Test-IsConsoleHost) {
    Write-Host $Text -ForegroundColor $Color -NoNewline:$NoNewline
  } else {
    # For non-console hosts, fallback without color.
    Write-Host $Text -NoNewline:$NoNewline
  }
}

function Format-Bool {
  param($Value)
  if ($null -eq $Value) { return 'n/a' }
  if ([bool]$Value) { return 'True' }
  return 'False'
}

function Write-PrettyKeyValue {
  param(
    [Parameter(Mandatory)][string]$Key,
    [Parameter(Mandatory)][string]$Value,
    [ConsoleColor]$KeyColor = [ConsoleColor]::DarkGray,
    [ConsoleColor]$ValueColor = [ConsoleColor]::Gray
  )

  Write-PrettyLine -Text ('{0,-32}: ' -f $Key) -Color $KeyColor -NoNewline
  Write-PrettyLine -Text $Value -Color $ValueColor
}

function Write-PrettySettingChange {
  param(
    [Parameter(Mandatory)][string]$Label,
    $Before,
    $After,
    [switch]$Supported
  )

  if (-not $Supported) {
    Write-PrettyKeyValue -Key $Label -Value 'n/a (not supported on this OS/build)' -ValueColor ([ConsoleColor]::DarkYellow)
    return
  }

  $b = Format-Bool $Before
  $a = Format-Bool $After

  $changed = ($b -ne $a)
  $color = if ($changed) { [ConsoleColor]::Yellow } else { [ConsoleColor]::Gray }

  Write-PrettyLine -Text ('{0,-32}: ' -f $Label) -Color ([ConsoleColor]::DarkGray) -NoNewline
  Write-PrettyLine -Text ('{0} -> {1}' -f $b, $a) -Color $color
}

function Write-ConsoleSummary {
  param(
    [Parameter(Mandatory)][pscustomobject]$Result,
    [Parameter(Mandatory)][bool]$HasRejectUnencryptedAccess,
    [Parameter(Mandatory)][bool]$HasClientRequireEncryption
  )

  $statusColor = if ($Result.Changes.Status -eq 'OK') { [ConsoleColor]::Green } else { [ConsoleColor]::Red }

  Write-Host ''
  Write-PrettyLine -Text ('=' * 46) -Color ([ConsoleColor]::DarkGray)
  Write-PrettyLine -Text 'SMB Encryption Enforcer (Summary)' -Color ([ConsoleColor]::Cyan)
  Write-PrettyLine -Text ('=' * 46) -Color ([ConsoleColor]::DarkGray)

  Write-PrettyKeyValue -Key 'Computer' -Value $Result.ComputerName -ValueColor ([ConsoleColor]::White)
  Write-PrettyKeyValue -Key 'Mode' -Value $Result.Mode -ValueColor ([ConsoleColor]::White)
  Write-PrettyKeyValue -Key 'WhatIf' -Value (Format-Bool $Result.WhatIf) -ValueColor ([ConsoleColor]::White)
  Write-PrettyKeyValue -Key 'Force' -Value (Format-Bool $Result.Force) -ValueColor ([ConsoleColor]::White)
  Write-PrettyKeyValue -Key 'JsonPath' -Value $Result.JsonPath -ValueColor ([ConsoleColor]::DarkGray)

  Write-Host ''
  Write-PrettyLine -Text 'Server / Client' -Color ([ConsoleColor]::Cyan)
  Write-PrettyLine -Text ('-' * 46) -Color ([ConsoleColor]::DarkGray)

  Write-PrettySettingChange -Label 'Server EncryptData' `
    -Before $Result.ServerEncryptData_Before -After $Result.ServerEncryptData_After -Supported:$true

  Write-PrettySettingChange -Label 'Server RejectUnencryptedAccess' `
    -Before $Result.ServerRejectUnencryptedAccess_Before -After $Result.ServerRejectUnencryptedAccess_After -Supported:$HasRejectUnencryptedAccess

  Write-PrettySettingChange -Label 'Client RequireEncryption' `
    -Before $Result.ClientRequireEncryption_Before -After $Result.ClientRequireEncryption_After -Supported:$HasClientRequireEncryption

  Write-Host ''
  Write-PrettyLine -Text 'Shares' -Color ([ConsoleColor]::Cyan)
  Write-PrettyLine -Text ('-' * 46) -Color ([ConsoleColor]::DarkGray)

  Write-PrettyKeyValue -Key 'Shares targeted' -Value ([string]$Result.Changes.ShareCountTargeted) -ValueColor ([ConsoleColor]::White)

  if (@($Result.Changes.SharesChanged).Count -gt 0) {
    Write-PrettyKeyValue -Key 'Shares changed' -Value (@($Result.Changes.SharesChanged) -join ', ') -ValueColor ([ConsoleColor]::Yellow)
  } else {
    Write-PrettyKeyValue -Key 'Shares changed' -Value 'none' -ValueColor ([ConsoleColor]::Gray)
  }

  Write-Host ''
  Write-PrettyLine -Text 'Result' -Color ([ConsoleColor]::Cyan)
  Write-PrettyLine -Text ('-' * 46) -Color ([ConsoleColor]::DarkGray)

  Write-PrettyLine -Text ('Status: {0}' -f $Result.Changes.Status) -Color $statusColor
  Write-PrettyKeyValue -Key 'Started' -Value ($Result.Started.ToString('yyyy-MM-dd HH:mm:ss')) -ValueColor ([ConsoleColor]::DarkGray)
  Write-PrettyKeyValue -Key 'Finished' -Value ($Result.Finished.ToString('yyyy-MM-dd HH:mm:ss')) -ValueColor ([ConsoleColor]::DarkGray)

  $duration = New-TimeSpan -Start $Result.Started -End $Result.Finished
  Write-PrettyKeyValue -Key 'Duration' -Value $duration.ToString() -ValueColor ([ConsoleColor]::DarkGray)

  Write-PrettyLine -Text ('=' * 46) -Color ([ConsoleColor]::DarkGray)
}

# -------------------------
# Apply JSON defaults (only when parameters not explicitly provided)
# -------------------------
$cfg = Load-JsonConfigOrDefault -Path $JsonPath

if (-not $PSBoundParameters.ContainsKey('Mode')) { $Mode = $cfg.Mode }
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
if (-not (Test-IsAdmin)) {
  throw 'Administrator privileges required (run PowerShell elevated).'
}

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

if ($EnableRejectUnencryptedAccess -and -not $hasRejectUnencryptedAccess) {
  throw 'RejectUnencryptedAccess is not available on this OS/build. Cannot enable it.'
}
if ($ApplyClientRequireEncryption -and -not $hasClientRequireEncryption) {
  throw 'Client RequireEncryption is not available on this OS/build. Cannot enable it.'
}

# -------------------------
# Main
# -------------------------
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

    'AuditOnly' {
      # Intentionally no changes.
    }

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
        throw 'Mode=ShareOnly requires at least one -ShareName.'
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
  throw
} finally {

  $serverCfgAfter = Get-SmbServerConfiguration
  $clientCfgAfter = Get-SmbClientConfiguration
  $sharesAfter    = @(Resolve-Shares -Names $ShareName)

  $result = [pscustomobject]@{
    ComputerName                          = $env:COMPUTERNAME
    Mode                                  = $Mode
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
  Write-ConsoleSummary -Result $result -HasRejectUnencryptedAccess $hasRejectUnencryptedAccess -HasClientRequireEncryption $hasClientRequireEncryption

  # Pipeline output: structured object only
#  $result
}
