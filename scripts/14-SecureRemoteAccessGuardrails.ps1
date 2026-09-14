#requires -version 5.1
<#
.SYNOPSIS
  Audits and optionally enforces secure “remote access guardrails” on a Windows endpoint by aligning RDP, Remote Assistance, Windows Firewall, and local group membership to a defined policy.
.DESCRIPTION
  This script implements an audit-first approach for remote access hardening.
  It evaluates the local system against a policy (“catalog”) and produces:
  - Console output with colored status and readable lists.
  - A structured result object on the pipeline (for automation and reporting).
  - A JSON proof file containing the same structured results.
  - An Application event log entry summarizing compliance and actions.
  Policy input is taken from a JSON catalog. If no catalog is provided or loading fails, the script uses built-in safe defaults.
  Guardrail areas:
  - RDP configuration (registry-based): enable/disable, NLA, security layer, encryption level, RDP port, Restricted Admin, password saving policy.
  - Windows Defender Firewall: disables local built-in “Remote Desktop” inbound rules and enforces scoped local inbound rules for RDP (TCP; optional UDP behavior).
  - Local group “Remote Desktop Users”: enforces an allowlist (optionally exact membership), always keeping BUILTIN\Administrators.
  - Remote Assistance (policy registry): enable/disable solicited/unsolicited assistance and ticket lifetime.
  Running with the default `-Mode Audit` performs an audit only (no changes). With `-Mode Remediate`, the script attempts to apply changes to reach the desired state.
.PARAMETER CatalogPath
  Optional path to a policy catalog JSON file.
  If provided and valid, the script uses this catalog as the desired-state definition.
  If omitted or invalid/unreadable, the script falls back to:
  1) A CatalogPath value in the optional config JSON (ConfigPath), if present and valid.
  2) Built-in default policy values.
.PARAMETER ConfigPath
  Optional path to a config JSON file that may reference a catalog path (for example: .RDP.CatalogPath).
  This parameter is used only when CatalogPath is not provided or cannot be loaded.
.PARAMETER ProofPath
  Path to the JSON proof file written at the end of execution.
  The proof file contains a structured object that mirrors the pipeline output (timestamp, host identity, drift, changes, notes, etc.).
  The parent directory is created if it does not exist.
.PARAMETER Strict
  Controls event severity rules.
  If set:
  - Any detected drift results in an “attention” event (EventId 4850).
  If not set:
  - Only execution errors or failed remediation attempts cause EventId 4850.
  - Pure audit drift may still be reported, but can remain informational.
.PARAMETER Mode
  Execution mode. 'Audit' reports only; 'Remediate' applies changes.
.PARAMETER OutputFormat
  Output format: Console, Json, Csv, or None.
.PARAMETER OutputPath
  File path for Json/Csv output.
.PARAMETER PassThru
  Emit structured v2 result object to pipeline.
.PARAMETER Quiet
  Suppress console output.
.PARAMETER NoColor
  Disable colored output.
.OUTPUTS
  One PSCustomObject (exactly one object is written to the pipeline), containing:
  - TimestampUtc (string): UTC timestamp in ISO 8601 format.
  - ComputerName (string): Local computer name.
  - User (string): User account running the script.
  - Elevated (bool): Whether the script detected an elevated session.
  - Remediate (bool): Whether remediation mode was requested.
  - Strict (bool): Whether strict mode was requested.
  - CatalogPath (string): A configured-path label when a catalog path was provided; otherwise null.
  - ConfigPath (string): A configured-path label when a config path was provided; otherwise null.
  - ProofPath (string): Proof file path.
  - Changed (string[]): Human-readable list of successful changes applied.
  - Drift (string[]): Human-readable list of detected drift and/or remediation failures.
  - Notes (string[]): Additional operational notes (e.g., non-elevated run, proof write issues).
  - EventId (int): Event ID written to the Application log (4840 informational / 4850 attention).
  - HasError (bool): True if a fatal error occurred or proof writing failed.
  - HasDrift (bool): True if drift was detected.
  The output object is designed for:
  - Export-Csv
  - ConvertTo-Json
  - Where-Object filtering
  without being polluted by console formatting output.
.EXAMPLE
  .\14-SecureRemoteAccessGuardrails.ps1
  Runs an audit only using the configured catalog or built-in defaults.
  Writes a console summary, event log entry, proof JSON, and emits one result object.
.EXAMPLE
  .\14-SecureRemoteAccessGuardrails.ps1 -CatalogPath $CatalogPath
  Runs an audit using an explicit policy catalog file.
.EXAMPLE
  .\14-SecureRemoteAccessGuardrails.ps1 -Mode Remediate -WhatIf
  Shows which changes would be applied to enforce the desired state, without making changes.
.EXAMPLE
  .\14-SecureRemoteAccessGuardrails.ps1 -Mode Remediate -Confirm
  Prompts before applying enforcement changes.
.EXAMPLE
  $r = .\14-SecureRemoteAccessGuardrails.ps1 -Mode Remediate
  $r | Where-Object HasError -eq $true
  Runs remediation and filters results in an automation-friendly way using the pipeline output.
.EXAMPLE
  .\14-SecureRemoteAccessGuardrails.ps1 -Strict | ConvertTo-Json -Depth 6
  Runs in strict mode (drift is treated as attention) and prints the result object as JSON.
.NOTES
  Safety and operational guidance:
  - Remediation can disable or restrict remote access; run with -WhatIf first and ensure console access is available.
  - Remediation may require elevation; audit can still run without elevation but changes may fail.
  - The script intentionally keeps console output separate from pipeline output for reliable automation.
  - The script writes a proof JSON file for compliance evidence and troubleshooting.
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
  [string]$CatalogPath,
  [switch]$Strict,
  [string]$ConfigPath,
  [string]$ProofPath
,
  [ValidateSet('Audit','Remediate')][string]$Mode = 'Audit',
  [ValidateSet('Console','Json','Csv','None')][string]$OutputFormat = 'Console',
  [string]$OutputPath,
  [switch]$PassThru,
  [switch]$Quiet,
  [switch]$NoColor
)
. (Join-Path $PSScriptRoot '_lib/Bootstrap.ps1')
. (Join-Path $PSScriptRoot 'internal/14-SecureRemoteAccessGuardrails.dependencies.ps1')
Set-StrictMode -Version Latest
$script:__V2Context = Initialize-V2Context -ScriptName '14-SecureRemoteAccessGuardrails.ps1' -BoundParameters $PSBoundParameters `
  -Values @{ Mode = $Mode; ConfigPath = $ConfigPath; OutputFormat = $OutputFormat; OutputPath = $OutputPath; PassThru = $PassThru; Strict = $Strict; Quiet = $Quiet; NoColor = $NoColor; DeriveRemediate = $true }
$Remediate = [bool]$script:__V2Context.Remediate
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
  $result = Get-V2ResultObject -ScriptName '14-SecureRemoteAccessGuardrails.ps1' -Mode $Mode -Result $unsupportedResult -Findings @() -Summary $summary -Metadata @{ UnsupportedHost = $true }
  Write-ResultObject -ResultObject $result -OutputFormat $OutputFormat -OutputPath $OutputPath
  if ($PassThru) { $result }
  exit (Get-V2ExitCode -Result $unsupportedResult)
}

# ----------------------------
# Constants / defaults
# ----------------------------
$eventSettings = [pscustomobject]@{ Source='SecureRemoteAccessGuardrails'; Log='Application' }
function Get-DefaultCatalogJson {
  return @"
{
  "RDP": {
    "Enable": false,
    "Port": 3389,
    "Profiles": [ "Domain" ],
    "RemoteAddresses": [ "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16" ],
    "AllowUDP": false,
    "NLA": true,
    "SecurityLayer": "TLS",
    "MinEncryptionLevel": "High",
    "RestrictedAdmin": true,
    "DisablePasswordSaving": true,
    "EnforceGroupMembership": true,
    "AllowedGroups": [ "DOMAIN\\RDP-Admins" ],
    "ExactMembership": true
  },
  "RemoteAssistance": {
    "AllowSolicited": false,
    "AllowUnsolicited": false,
    "Helpers": [],
    "TicketMaxLifetimeMinutes": 60
  }
}
"@
}
# ----------------------------
# UI helpers (console only)
# ----------------------------
# ----------------------------
# Generic helpers (no console formatting here)
# ----------------------------
function Test-IsElevated {
  try {
    return ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).
      IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
  } catch { return $false }
}
# Ensure-DirectoryForFile imported from lib/Common.psm1
function Normalize-Array {
  param([object]$Value)
  if ($null -eq $Value) { return @() }
  if ($Value -is [Array]) { return @($Value | ForEach-Object { "$_".Trim() } | Where-Object { $_ }) }
  return @("$Value".Trim()) | Where-Object { $_ }
}
function ConvertFrom-JsonSafe {
  param([string]$JsonText)
  try { return ($JsonText | ConvertFrom-Json -ErrorAction Stop) }
  catch { return $null }
}
function Get-DefaultCatalog {
  $c = ConvertFrom-JsonSafe -JsonText (Get-DefaultCatalogJson)
  if ($c) { return $c }
  throw "Built-in default catalog JSON is invalid."
}
function Merge-CatalogWithDefaults {
  param(
    [psobject]$Catalog,
    [psobject]$Defaults
  )
  if (-not $Catalog) { return $Defaults }
  Add-MissingCatalogSection -Catalog $Catalog -Defaults $Defaults -Section RDP -Properties @(
    'Enable','Port','Profiles','RemoteAddresses','AllowUDP','NLA','SecurityLayer','MinEncryptionLevel',
    'RestrictedAdmin','DisablePasswordSaving','EnforceGroupMembership','AllowedGroups','ExactMembership'
  )
  Add-MissingCatalogSection -Catalog $Catalog -Defaults $Defaults -Section RemoteAssistance -Properties @(
    'AllowSolicited','AllowUnsolicited','Helpers','TicketMaxLifetimeMinutes'
  )
  return $Catalog
}
function Add-MissingCatalogSection {
  param([psobject]$Catalog,[psobject]$Defaults,[string]$Section,[string[]]$Properties)
  if (-not $Catalog.$Section) { $Catalog | Add-Member -NotePropertyName $Section -NotePropertyValue ([pscustomobject]@{}) -Force }
  foreach ($propertyName in $Properties) {
    if ($null -eq $Catalog.$Section.$propertyName) {
      $Catalog.$Section | Add-Member -NotePropertyName $propertyName -NotePropertyValue $Defaults.$Section.$propertyName -Force
    }
  }
}
function Load-Catalog {
  param([string]$ExplicitCatalogPath,[string]$ConfigPath)
  $defaults = Get-DefaultCatalog
  $cat = Read-JsonFileSafe -Path $ExplicitCatalogPath
  if ($cat) { return (Merge-CatalogWithDefaults -Catalog $cat -Defaults $defaults) }
  $cfg = Read-JsonFileSafe -Path $ConfigPath
  if ($cfg -and $cfg.RDP -and $cfg.RDP.CatalogPath) {
    $cat2 = Read-JsonFileSafe -Path ([string]$cfg.RDP.CatalogPath)
    if ($cat2) { return (Merge-CatalogWithDefaults -Catalog $cat2 -Defaults $defaults) }
  }
  return $defaults
}
function Compare-FwMultiValue {
  param([object]$Actual,[string[]]$Expected)
  $a = (Normalize-Array -Value $Actual) | Sort-Object -Unique
  $e = (Normalize-Array -Value $Expected) | Sort-Object -Unique
  return (@($a) -join ',') -eq (@($e) -join ',')
}
function Test-CmdletAvailable {
  param([string]$Name)
  try { return [bool](Get-Command -Name $Name -ErrorAction SilentlyContinue) }
  catch { return $false }
}
# ----------------------------
# Firewall (local PersistentStore only)
# ----------------------------
function Get-LocalFirewallRuleByDisplayName {
  param([string]$DisplayName)
  try { return Get-NetFirewallRule -PolicyStore PersistentStore -DisplayName $DisplayName -ErrorAction SilentlyContinue }
  catch { return $null }
}
function Remove-LocalFirewallRuleByDisplayName {
  [CmdletBinding(SupportsShouldProcess = $true)]
  param([string]$DisplayName)
  try {
    $r = Get-LocalFirewallRuleByDisplayName -DisplayName $DisplayName
    if ($r -and $PSCmdlet.ShouldProcess($DisplayName, 'Remove local firewall rule')) {
      $r | Remove-NetFirewallRule -ErrorAction Stop | Out-Null
    }
    return $true
  } catch { return $false }
}
function Disable-LocalBuiltinRdpInbound {
  try {
    $rules = Get-NetFirewallRule -PolicyStore PersistentStore -DisplayGroup 'Remote Desktop' -Direction Inbound -ErrorAction Stop
    foreach ($r in @($rules)) {
      try { $r | Disable-NetFirewallRule -ErrorAction Stop | Out-Null } catch {
        Write-Verbose ("Built-in RDP firewall rule disable failed for '{0}': {1}" -f $r.Name,$_.Exception.Message)
      }
    }
  } catch {
    Write-Verbose ("Built-in RDP firewall rule enumeration failed: {0}" -f $_.Exception.Message)
  }
}
function Get-RdpFirewallSettings {
  param([Parameter(Mandatory)][psobject]$Rdp)
  $profiles = Get-RdpArraySetting $Rdp.Profiles @('Domain')
  $scope = Get-RdpArraySetting $Rdp.RemoteAddresses @('LocalSubnet')
  $port = Get-RdpPortSetting $Rdp.Port
  $messages = @()
  if ($port -lt 1 -or $port -gt 65535) { $port = 3389; $messages += 'Invalid RDP.Port in catalog; using 3389.' }
  $allowUdp = Get-RdpBooleanSetting $Rdp.AllowUDP
  return [pscustomobject]@{ Profiles = $profiles; Scope = $scope; Port = $port; AllowUdp = $allowUdp; Messages = $messages }
}
function Get-RdpArraySetting {
  param($Value,[string[]]$Default)
  $values = @(Normalize-Array -Value $Value)
  if ($values.Count -eq 0) { return $Default }
  return $values
}
function Get-RdpPortSetting {
  param($Value)
  try { if ($Value) { return [int]$Value } } catch { return 3389 }
  return 3389
}
function Get-RdpBooleanSetting {
  param($Value)
  try { if ($null -ne $Value) { return [bool]$Value } } catch { return $false }
  return $false
}
function New-RdpFirewallRule {
  [CmdletBinding(SupportsShouldProcess = $true)]
  param(
    [Parameter(Mandatory)][string]$DisplayName,
    [Parameter(Mandatory)][string]$Action,
    [Parameter(Mandatory)][string]$Protocol,
    [Parameter(Mandatory)][int]$Port,
    [Parameter(Mandatory)][string[]]$Profiles,
    [Parameter(Mandatory)][string[]]$RemoteAddress,
    [Parameter(Mandatory)][string]$Group
  )
  if (-not $PSCmdlet.ShouldProcess('Firewall', "Create $DisplayName")) { return $false }
  New-NetFirewallRule -PolicyStore PersistentStore -DisplayName $DisplayName -Group $Group `
    -Direction Inbound -Action $Action -Enabled True -Protocol $Protocol -LocalPort $Port `
    -Profile $Profiles -RemoteAddress $RemoteAddress -Service 'TermService' | Out-Null
  return $true
}
function Get-RdpTcpFirewallDrift {
  param([Parameter(Mandatory)]$Rule,[Parameter(Mandatory)]$Settings,[Parameter(Mandatory)][string]$DisplayName)
  $drifts = @()
  $portFilter = $Rule | Get-NetFirewallPortFilter -ErrorAction Stop
  $addressFilter = $Rule | Get-NetFirewallAddressFilter -ErrorAction Stop
  if ($Rule.Enabled -ne 'True') { $drifts += "${DisplayName}: not enabled" }
  if ($Rule.Action -ne 'Allow') { $drifts += "${DisplayName}: action not Allow" }
  if (-not (Compare-FwMultiValue -Actual $Rule.Profile -Expected $Settings.Profiles)) { $drifts += "${DisplayName}: profile drift" }
  if ("$($portFilter.LocalPort)" -ne "$($Settings.Port)") { $drifts += "${DisplayName}: LocalPort $($portFilter.LocalPort) != $($Settings.Port)" }
  if (-not (Compare-FwMultiValue -Actual $addressFilter.RemoteAddress -Expected $Settings.Scope)) { $drifts += "${DisplayName}: RemoteAddress drift" }
  return [pscustomobject]@{ Messages = $drifts; PortFilter = $portFilter; AddressFilter = $addressFilter }
}
function Set-RdpTcpFirewallRule {
  [CmdletBinding(SupportsShouldProcess = $true)]
  param([Parameter(Mandatory)]$Rule,[Parameter(Mandatory)]$Settings,[Parameter(Mandatory)][string]$DisplayName)
  if (-not $PSCmdlet.ShouldProcess('Firewall', "Repair $DisplayName")) { return $false }
  $Rule | Set-NetFirewallRule -Enabled True -Action Allow -Profile $Settings.Profiles -ErrorAction Stop | Out-Null
  $Rule | Set-NetFirewallPortFilter -Protocol TCP -LocalPort $Settings.Port -ErrorAction Stop | Out-Null
  $Rule | Set-NetFirewallAddressFilter -RemoteAddress $Settings.Scope -ErrorAction Stop | Out-Null
  return $true
}
function Ensure-RdpUdpFirewallMode {
  [CmdletBinding(SupportsShouldProcess = $true)]
  param([Parameter(Mandatory)]$Settings,[Parameter(Mandatory)][string]$AllowName,[Parameter(Mandatory)][string]$BlockName,[Parameter(Mandatory)][string]$Group,[switch]$Remediate)
  $actions = [System.Collections.Generic.List[string]]::new()
  $drifts = [System.Collections.Generic.List[string]]::new()
  $createName = if ($Settings.AllowUdp) { $AllowName } else { $BlockName }
  $createAction = if ($Settings.AllowUdp) { 'Allow' } else { 'Block' }
  $createRemoteAddress = if ($Settings.AllowUdp) { $Settings.Scope } else { @('Any') }
  Add-RdpUdpDesiredRule $Settings $createName $createAction $createRemoteAddress $Group ([bool]$Remediate) $actions $drifts
  $oppositeName = if ($Settings.AllowUdp) { $BlockName } else { $AllowName }
  $oppositeMode = if ($Settings.AllowUdp) { 'UDP allowed' } else { 'UDP blocked' }
  Remove-RdpUdpOppositeRule $Settings $oppositeName $oppositeMode ([bool]$Remediate) $actions $drifts
  return [pscustomobject]@{ Actions = @($actions); Drifts = @($drifts) }
}
function Add-RdpUdpDesiredRule {
  param($Settings,[string]$Name,[string]$Action,[string[]]$RemoteAddress,[string]$Group,[bool]$Remediate,$Actions,$Drifts)
  if (Get-LocalFirewallRuleByDisplayName -DisplayName $Name) { return }
  if (-not $Remediate) { $Drifts.Add("Missing local rule: $Name"); return }
  try {
    if (New-RdpFirewallRule -DisplayName $Name -Action $Action -Protocol UDP -Port $Settings.Port -Profiles $Settings.Profiles -RemoteAddress $RemoteAddress -Group $Group) { $Actions.Add("Created $Name") }
    else { $Drifts.Add("Missing local rule: $Name") }
  } catch { $Drifts.Add("Failed to create $Name - $($_.Exception.Message)") }
}
function Remove-RdpUdpOppositeRule {
  param($Settings,[string]$Name,[string]$Mode,[bool]$Remediate,$Actions,$Drifts)
  if (-not (Get-LocalFirewallRuleByDisplayName -DisplayName $Name)) { return }
  if (-not $Remediate) {
    $label = $(if ($Settings.AllowUdp) { 'UDP allowed but block rule exists' } else { 'UDP blocked but allow rule exists' })
    $Drifts.Add("${label}: $Name")
    return
  }
  if (Remove-LocalFirewallRuleByDisplayName -DisplayName $Name) { $Actions.Add("Removed $Name ($Mode)") }
  else { $Drifts.Add("Failed to remove $Name ($Mode)") }
}
function Get-RdpFirewallRuleNames {
  return [pscustomobject]@{ Tcp='Guardrails RDP TCP-In Scoped'; UdpAllow='Guardrails RDP UDP-In Scoped'; UdpBlock='Guardrails RDP UDP-In Blocked'; Group='Guardrails RDP Scoped' }
}
function Update-DisabledRdpFirewallRules {
  param($Names,[bool]$Remediate,$Actions,$Drifts)
  foreach ($name in @($Names.Tcp,$Names.UdpAllow,$Names.UdpBlock)) {
    if ($Remediate) {
      if (Remove-LocalFirewallRuleByDisplayName -DisplayName $name) { $Actions.Add("Removed local rule: $name") }
      else { $Drifts.Add("Failed to remove local rule: $name") }
    } elseif (Get-LocalFirewallRuleByDisplayName -DisplayName $name) { $Drifts.Add("RDP disabled but local rule exists: $name") }
  }
}
function Update-RdpTcpFirewallRule {
  param($Settings,$Names,[bool]$Remediate,$Actions,$Drifts)
  $rule = Get-LocalFirewallRuleByDisplayName -DisplayName $Names.Tcp
  if (-not $rule) { Add-RdpTcpFirewallRule $Settings $Names $Remediate $Actions $Drifts; return }
  Repair-RdpTcpFirewallRule $rule $Settings $Names $Remediate $Actions $Drifts
}
function Add-RdpTcpFirewallRule {
  param($Settings,$Names,[bool]$Remediate,$Actions,$Drifts)
  if (-not $Remediate) { $Drifts.Add("Missing local rule: $($Names.Tcp)"); return }
  try {
    if (New-RdpFirewallRule -DisplayName $Names.Tcp -Action Allow -Protocol TCP -Port $Settings.Port -Profiles $Settings.Profiles -RemoteAddress $Settings.Scope -Group $Names.Group) { $Actions.Add("Created $($Names.Tcp)") }
    else { $Drifts.Add("Missing local rule: $($Names.Tcp)") }
  } catch { $Drifts.Add("Failed to create $($Names.Tcp) - $($_.Exception.Message)") }
}
function Repair-RdpTcpFirewallRule {
  param($Rule,$Settings,$Names,[bool]$Remediate,$Actions,$Drifts)
  try {
    $inspection = Get-RdpTcpFirewallDrift -Rule $Rule -Settings $Settings -DisplayName $Names.Tcp
    foreach ($message in $inspection.Messages) { $Drifts.Add($message) }
    if ($inspection.Messages.Count -gt 0 -and $Remediate) {
      try { if (Set-RdpTcpFirewallRule -Rule $Rule -Settings $Settings -DisplayName $Names.Tcp) { $Actions.Add("Repaired $($Names.Tcp)") } }
      catch { $Drifts.Add("Failed to repair $($Names.Tcp) - $($_.Exception.Message)") }
    }
  } catch { $Drifts.Add("Failed to inspect $($Names.Tcp) - $($_.Exception.Message)") }
}
function Update-RdpDisabledFirewallMode {
  param($Names,[bool]$Remediate,$Actions,$Drifts)
  if ($Remediate) { Disable-LocalBuiltinRdpInbound }
  Update-DisabledRdpFirewallRules $Names $Remediate $Actions $Drifts
}
function Ensure-RdpFirewallRules {
  [CmdletBinding(SupportsShouldProcess = $true)]
  param([psobject]$Rdp,[switch]$Remediate)
  $actions = [System.Collections.Generic.List[string]]::new()
  $drifts = [System.Collections.Generic.List[string]]::new()
  if (-not (Test-CmdletAvailable -Name 'Get-NetFirewallRule')) {
    return @("NetSecurity cmdlets not available (Get-NetFirewallRule missing).")
  }
  $settings = Get-RdpFirewallSettings -Rdp $Rdp
  foreach ($message in $settings.Messages) { $drifts.Add($message) }
  $names = Get-RdpFirewallRuleNames
  # Only disable built-in RDP inbound rules when remediating and catalog specifies RDP disabled (§1/§16)
  if (-not [bool]$Rdp.Enable) {
    Update-RdpDisabledFirewallMode $names ([bool]$Remediate) $actions $drifts
    return @(@($actions) + @($drifts))
  }
  Update-RdpTcpFirewallRule $settings $names ([bool]$Remediate) $actions $drifts
  $udp = Ensure-RdpUdpFirewallMode -Settings $settings -AllowName $names.UdpAllow -BlockName $names.UdpBlock -Group $names.Group -Remediate:$Remediate
  foreach ($message in $udp.Actions) { $actions.Add($message) }
  foreach ($message in $udp.Drifts) { $drifts.Add($message) }
  return @(@($actions) + @($drifts))
}
# ----------------------------
# Local group enforcement
# ----------------------------
function Ensure-RdpGroupMembership {
  [CmdletBinding(SupportsShouldProcess = $true)]
  param([psobject]$Rdp,[switch]$Remediate)
  $actions = [System.Collections.Generic.List[string]]::new()
  $drifts = [System.Collections.Generic.List[string]]::new()
  if (-not [bool]$Rdp.EnforceGroupMembership) { return @() }
  if (-not (Test-CmdletAvailable -Name 'Get-LocalGroupMember')) { return @("LocalAccounts cmdlets not available (Get-LocalGroupMember missing).") }
  $targetGroup = "Remote Desktop Users"
  $allowed     = Normalize-Array -Value $Rdp.AllowedGroups
  $exact       = [bool]$Rdp.ExactMembership
  try {
    $cur = Get-LocalGroupMember -Group $targetGroup -ErrorAction Stop
    $curNames = @($cur | ForEach-Object { $_.Name })
  } catch {
    return @("Cannot read group '$targetGroup' - $($_.Exception.Message)")
  }
  Add-MissingRdpGroupMembers $targetGroup $allowed $curNames ([bool]$Remediate) $PSCmdlet $actions $drifts
  if ($exact) {
    $keep = @($allowed + "BUILTIN\Administrators") | Sort-Object -Unique
    Remove-UnexpectedRdpGroupMembers $targetGroup $keep $curNames ([bool]$Remediate) $PSCmdlet $actions $drifts
  }
  return @(@($actions) + @($drifts))
}
function Add-MissingRdpGroupMembers {
  param([string]$Group,[string[]]$Allowed,[string[]]$Current,[bool]$Remediate,$CommandContext,$Actions,$Drifts)
  foreach ($member in $Allowed) {
    if ($Current -contains $member) { continue }
    if (-not $Remediate -or -not $CommandContext.ShouldProcess($Group, "Add $member")) { $Drifts.Add("Missing member $member"); continue }
    try { Add-LocalGroupMember -Group $Group -Member $member -ErrorAction Stop; $Actions.Add("Added member $member") }
    catch { $Drifts.Add("Failed to add member $member - $($_.Exception.Message)") }
  }
}
function Remove-UnexpectedRdpGroupMembers {
  param([string]$Group,[string[]]$Keep,[string[]]$Current,[bool]$Remediate,$CommandContext,$Actions,$Drifts)
  foreach ($member in $Current) {
    if ($Keep -contains $member) { continue }
    if (-not $Remediate -or -not $CommandContext.ShouldProcess($Group, "Remove $member")) { $Drifts.Add("Unexpected member $member"); continue }
    try { Remove-LocalGroupMember -Group $Group -Member $member -Confirm:$false -ErrorAction Stop; $Actions.Add("Removed member $member") }
    catch { $Drifts.Add("Failed to remove member $member - $($_.Exception.Message)") }
  }
}
# ----------------------------
# Remote Assistance enforcement
# ----------------------------
function Ensure-RemoteAssistance {
  [CmdletBinding(SupportsShouldProcess = $true)]
  param([psobject]$Ra,[switch]$Remediate)
  $actions = [System.Collections.Generic.List[string]]::new()
  $drifts = [System.Collections.Generic.List[string]]::new()
  $polKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
  $wantSol = 0; if ([bool]$Ra.AllowSolicited) { $wantSol = 1 }
  $wantUn  = 0; if ([bool]$Ra.AllowUnsolicited) { $wantUn = 1 }
  Set-RemoteAssistancePolicyValue $polKey fAllowToGetHelp $wantSol ([bool]$Remediate) $PSCmdlet $actions $drifts
  Set-RemoteAssistancePolicyValue $polKey fAllowUnsolicited $wantUn ([bool]$Remediate) $PSCmdlet $actions $drifts
  if ($null -ne $Ra.TicketMaxLifetimeMinutes) {
    $wantTicket = [int]$Ra.TicketMaxLifetimeMinutes
    if ($wantTicket -lt 1) { $wantTicket = 60 }
    Set-RemoteAssistancePolicyValue $polKey MaxTicketExpiry $wantTicket ([bool]$Remediate) $PSCmdlet $actions $drifts
  }
  return @(@($actions) + @($drifts))
}
function Set-RemoteAssistancePolicyValue {
  param([string]$Path,[string]$Name,[int]$Desired,[bool]$Remediate,$CommandContext,$Actions,$Drifts)
  $current = Get-RegDword -Path $Path -Name $Name
  if ($current -eq $Desired) { return }
  if (-not $Remediate -or -not $CommandContext.ShouldProcess($Path, "Set $Name=$Desired")) {
    $Drifts.Add("RemoteAssistance $Name $current != $Desired")
    return
  }
  if (Set-RegDword -Path $Path -Name $Name -Value $Desired) { $Actions.Add("Set RemoteAssistance $Name=$Desired") }
  else { $Drifts.Add("Failed to set RemoteAssistance $Name=$Desired") }
}
# ----------------------------
# Main
# ----------------------------
. (Join-Path $PSScriptRoot 'internal/14-SecureRemoteAccessGuardrails.runtime.ps1')
$ProofPath = Get-RemoteAccessProofPath $ProofPath
$runState = New-RemoteAccessRunState -IsElevated (Test-IsElevated)
$runOptions = [pscustomobject]@{ CatalogPath=$CatalogPath; ConfigPath=$ConfigPath; ProofPath=$ProofPath; Remediate=$Remediate; Strict=[bool]$Strict; EventSource=$eventSettings.Source; EventLog=$eventSettings.Log }
Invoke-RemoteAccessCapability -RunState $runState -CommandContext $PSCmdlet -Options $runOptions
Add-RemoteAccessCanonicalFindings -Drifts @($runState.Drifts)
# V2 output contract
$resultToken = if ($script:Findings.Count -gt 0) { 'WARN' } else { 'OK' }
$v2Result = Get-V2ResultObject -ScriptName '14-SecureRemoteAccessGuardrails.ps1' -Mode $Mode -Result $resultToken -Findings (ConvertTo-ObjectArray -InputObject $script:Findings) -Summary ([pscustomobject]@{ ComputerName = $env:COMPUTERNAME; Timestamp = Get-Date }) -Metadata @{}
Write-ResultObject -ResultObject $v2Result -OutputFormat $OutputFormat -OutputPath $OutputPath
if ($PassThru) { $v2Result }
exit (Get-V2ExitCode -Result $resultToken)
