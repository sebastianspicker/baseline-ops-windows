#Requires -RunAsAdministrator
#requires -version 5.1
<#
.SYNOPSIS
  Audits and optionally remediates a Windows Firewall baseline (profiles, logging, and selected local firewall rules) using a JSON catalog or built-in defaults.
.DESCRIPTION
  This script evaluates a baseline in three areas:
  1) Firewall profiles (Domain/Private/Public): enabled state, default inbound/outbound actions, notifications, and logging settings.
  2) Risky inbound local rules: finds inbound rules in a chosen local policy store and flags/disables rules whose DisplayName matches configured wildcard patterns.
  3) Baseline ensure-rules: verifies required rules exist in the chosen local policy store and match key properties (direction/action/enabled/profile/port filters). Missing or drifting rules can be created/updated.
  The script supports two modes:
  - Audit (default): detects drift and reports findings.
  - Remediate (-Mode Remediate): applies changes to match the baseline, using ShouldProcess (supports -WhatIf / -Confirm).
  Output design:
  - Pipeline output: emits structured result objects only (CSV/JSON-friendly).
  - Console output: prints a summary and optional colorized findings.
  Catalog loading order:
  - If -CatalogPath is provided and valid, it is used.
  - Otherwise, if -ConfigPath is provided and contains Firewall.CatalogPath, that catalog is used.
  - Otherwise, built-in defaults are used.
.PARAMETER CatalogPath
  Path to a baseline catalog JSON file.
  If provided, this takes precedence over -ConfigPath.
.PARAMETER Strict
  If set, drift is treated as non-compliant.
  If not set, drift is reported but the compliance result is less strict (see Notes on event IDs).
.PARAMETER ConfigPath
  Path to a configuration JSON file that may contain:
    { "Firewall": { "CatalogPath": "[configured path]" } }
  Used only when -CatalogPath is not provided or cannot be loaded.
.PARAMETER LocalPolicyStore
  The local firewall policy store to read/modify.
  Typical use is the default local persistent store; other stores can be targeted as needed.
.PARAMETER EventSource
  Event source name used when writing the health event to the Windows Event Log.
.PARAMETER EventLogName
  Event log name (for example "Application") where the health event is written.
.PARAMETER ConsoleSummary
  If set (default), prints a readable summary and colorized findings to the console host.
  If not set, no console summary is printed (pipeline output still occurs).
.PARAMETER ShowOkInConsole
  If set, the console summary also includes a list of OK items.
  By default, the console focuses on Changed/Drift/Error/Note.
.INPUTS
  None. You can't pipe input objects to this script.
.PARAMETER Mode
  Execution mode. 'Audit' reports only; 'Remediate' applies changes.
  In Remediate mode, the script attempts to apply the baseline:
  update profiles, disable targeted inbound rules, and create/update ensure-rules.
  Use -WhatIf to preview changes without applying them.
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
  PSCustomObject with the following properties:
    - Time:       ISO-like timestamp (local time) when the item was produced.
    - Category:   Profile | InboundRuleDisable | EnsureRule | Catalog | Runtime
    - Target:     Logical target (e.g., profile name, pattern, or rule identifier).
    - Status:     OK | Drift | Changed | Error | Note
    - Message:    Short human-readable message describing the outcome.
    - Detail:     Optional additional detail (e.g., which properties drifted).
    - Name:       Optional firewall rule Name (internal identifier).
    - DisplayName:Optional firewall rule DisplayName (user-facing title).
.NOTES
  Safety and change control:
  - Remediation is guarded by ShouldProcess; use -WhatIf for a dry run and -Confirm for interactive approval.
  Scope:
  - This script targets a selected local policy store only. It is not intended to modify centrally managed policies.
  Health event semantics:
  - Writes an event indicating overall status:
    - 4800 indicates no errors and (when not strict) drift does not force a warning state.
    - 4810 indicates drift and/or errors (and in strict mode, any drift is considered non-compliant).
  Exit codes:
  - 0 = OK, 2 = WARN, 1 = FAIL.
.EXAMPLE
  # Audit using built-in defaults (no changes)
  .\18-Firewall-Baseline.ps1
.EXAMPLE
  # Audit using an explicit catalog JSON
  .\scripts\18-Firewall-Baseline.ps1 -CatalogPath .\examples\configs\firewall-baseline.json
.EXAMPLE
  # Remediate using a catalog, preview only (no changes applied)
  .\scripts\18-Firewall-Baseline.ps1 -CatalogPath .\examples\configs\firewall-baseline.json -Mode Remediate -WhatIf
.EXAMPLE
  # Remediate using config-driven catalog path, suppress console summary, export results to CSV
  .\18-Firewall-Baseline.ps1 -ConfigPath $ConfigPath -Mode Remediate -ConsoleSummary:$false |
    Export-Csv -NoTypeInformation -Path $OutputPath
.EXAMPLE
  # Audit, then filter only drift/error items for automation
  .\18-Firewall-Baseline.ps1 |
    Where-Object { $_.Status -in @('Drift','Error') } |
    ConvertTo-Json -Depth 5
#>
[CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Medium')]
param(
  [string]$CatalogPath,
  [switch]$Strict,
  [string]$ConfigPath,
  [ValidateSet('PersistentStore','LocalHost','StaticServiceStore','ConfigurableServiceStore')]
  [string]$LocalPolicyStore = 'PersistentStore',
  [string]$EventSource = 'Win-Firewall-Baseline',
  [string]$EventLogName = 'Application',
  # Formatted console output. Pipeline output remains structured.
  [bool]$ConsoleSummary = $true,
  # Show verbose "OK" items in the console summary.
  [switch]$ShowOkInConsole
,
  [ValidateSet('Audit','Remediate')][string]$Mode = 'Audit',
  [ValidateSet('Console','Json','Csv','None')][string]$OutputFormat = 'Console',
  [string]$OutputPath,
  [switch]$PassThru,
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
function Initialize-Capability18Runtime {
  param($EntryBoundParameters)
  $RunState = @{
    LocalPolicyStore = $LocalPolicyStore
  }
Import-Module (Join-Path $script:LibPath 'Common.psm1') -Force -DisableNameChecking
Import-Module (Join-Path $script:LibPath 'Output.psm1') -Force
Import-Module (Join-Path $script:LibPath 'EventLog.psm1') -Force
Import-Module (Join-Path $script:LibPath 'Results.psm1') -Force
Import-Module (Join-Path $script:LibPath 'Console.psm1') -Force
Import-Module (Join-Path $script:LibPath Serialization.psm1) -Force
Set-StrictMode -Version Latest
$script:__V2Context = Initialize-V2Context -ScriptName '18-Firewall-Baseline.ps1' -BoundParameters $EntryBoundParameters `
  -Values @{ Mode = $Mode; ConfigPath = $ConfigPath; OutputFormat = $OutputFormat; OutputPath = $OutputPath; PassThru = $PassThru; Strict = $Strict; Quiet = $Quiet; NoColor = $NoColor; DeriveRemediate = $true }
$RunState.Remediate = [bool]$script:__V2Context.Remediate
if ($script:__V2Context.Quiet) { $InformationPreference = 'SilentlyContinue'; $VerbosePreference = 'SilentlyContinue' }
$script:NoColor = [bool]$script:__V2Context.NoColor
$ErrorActionPreference = 'Stop'

$RunState.isWindowsHost = ($env:OS -eq 'Windows_NT')
  $script:RunState = $RunState
}

. Initialize-Capability18Runtime -EntryBoundParameters $PSBoundParameters
if (-not $RunState.isWindowsHost) {
  $summary = [pscustomobject]@{
    ComputerName = $env:COMPUTERNAME
    Timestamp    = Get-Date
    Mode         = $Mode
    Supported    = $false
    Notes        = @('Skipped: this script is only supported on Windows hosts.')
  }
  $unsupportedResult = if ($Strict) { 'FAIL' } else { 'WARN' }
  $result = Get-V2ResultObject -ScriptName '18-Firewall-Baseline.ps1' -Mode $Mode -Result $unsupportedResult -Findings @() -Summary $summary -Metadata @{ UnsupportedHost = $true }
  Write-ResultObject -ResultObject $result -OutputFormat $OutputFormat -OutputPath $OutputPath
  if ($PassThru) { $result }
  exit (Get-V2ExitCode -Result $unsupportedResult)
}

# -------------------------
# Event log helpers
# -------------------------
# -------------------------
# Console UI helpers (no pipeline output)
# -------------------------
function Get-StatusColor {
  [CmdletBinding()]
  param([Parameter(Mandatory)][ValidateSet('OK','Drift','Changed','Error','Note')][string]$Status)
  switch ($Status) {
    'OK'      { [ConsoleColor]::Green; break }
    'Changed' { [ConsoleColor]::Cyan; break }
    'Note'    { [ConsoleColor]::DarkGray; break }
    'Drift'   { [ConsoleColor]::Yellow; break }
    'Error'   { [ConsoleColor]::Red; break }
  }
}
function Write-UiItem {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]$Item
  )
  $color = Get-StatusColor -Status $Item.Status
  $left  = ("[{0}] {1}/{2}" -f $Item.Status, $Item.Category, $Item.Target)
  $msg   = $Item.Message
  if (-not [string]::IsNullOrWhiteSpace($Item.DisplayName)) { $msg += " | " + $Item.DisplayName }
  if (-not [string]::IsNullOrWhiteSpace($Item.Detail))      { $msg += " | " + $Item.Detail }
  Write-UiLine ("- " + $left + ": " + $msg) -ForegroundColor $color
}
# -------------------------
# Generic helpers
# -------------------------
function Initialize-FirewallBaselineCatalog {
  param([hashtable]$RunState)
. (Join-Path $PSScriptRoot 'internal/18-Firewall-Baseline.helpers.ps1')
# -------------------------
# Default catalog (built-in)
# -------------------------
$RunState.DefaultCatalog = ConvertFrom-Json @"
{
  "Profiles": {
    "Domain":  { "Enabled": true, "DefaultInbound": "Block", "DefaultOutbound": "Allow", "NotifyOnListen": false, "LogDropped": true, "LogAllowed": false, "LogMaxSizeKB": 16384, "LogFile": "%systemroot%\\system32\\LogFiles\\Firewall\\pfirewall_domain.log" },
    "Private": { "Enabled": true, "DefaultInbound": "Block", "DefaultOutbound": "Allow", "NotifyOnListen": false, "LogDropped": true, "LogAllowed": false, "LogMaxSizeKB": 16384, "LogFile": "%systemroot%\\system32\\LogFiles\\Firewall\\pfirewall_private.log" },
    "Public":  { "Enabled": true, "DefaultInbound": "Block", "DefaultOutbound": "Allow", "NotifyOnListen": false, "LogDropped": true, "LogAllowed": false, "LogMaxSizeKB": 16384, "LogFile": "%systemroot%\\system32\\LogFiles\\Firewall\\pfirewall_public.log" }
  },
  "DisableInboundByNameLike": [
    "Remote Desktop*",
    "Remote Assistance*",
    "File and Printer Sharing*",
    "Windows Remote Management*",
    "PowerShell Remoting*"
  ],
  "EnsureRules": [
    {
      "Name": "Baseline-Outbound-Block-SMB-445-PrivPub",
      "DisplayName": "Baseline Outbound Block SMB (Private+Public)",
      "Group": "Baseline",
      "Direction": "Outbound",
      "Action": "Block",
      "Protocol": "TCP",
      "RemotePort": "445",
      "Profile": [ "Private", "Public" ],
      "Enabled": true,
      "Description": "Blocks outbound SMB to reduce lateral movement on non-domain profiles"
    },
    {
      "Name": "Baseline-Outbound-Block-LegacySMB-137-139-PrivPub",
      "DisplayName": "Baseline Outbound Block Legacy SMB (137-139) (Private+Public)",
      "Group": "Baseline",
      "Direction": "Outbound",
      "Action": "Block",
      "Protocol": "TCP",
      "RemotePort": "137-139",
      "Profile": [ "Private", "Public" ],
      "Enabled": true
    }
  ]
}
"@
}
. Initialize-FirewallBaselineCatalog -RunState $RunState
# -------------------------
# Profile enforcement
# -------------------------
function Ensure-ProfileStage01 {
  param([hashtable]$RunState)
$RunState.spTarget = "FirewallProfile/$Name"
}

function Ensure-ProfileStage02 {
  param([hashtable]$RunState)
if ($PSCmdlet.ShouldProcess($RunState.spTarget, "Set-NetFirewallProfile")) {
        try {
          $setParams = @{
            Name                  = $Name
            Enabled               = $RunState.wantEnabled
            DefaultInboundAction  = $RunState.wantIn
            DefaultOutboundAction = $RunState.wantOut
            NotifyOnListen        = $RunState.wantNotify
          }
          if ((Test-AllConditions -Conditions @({ $null -ne $haveLogBlocked }, { $null -ne $RunState.wantLogBlocked }))) { $setParams['LogBlocked'] = [bool]$RunState.wantLogBlocked }
          if ((Test-AllConditions -Conditions @({ $null -ne $haveLogAllowed }, { $null -ne $RunState.wantLogAllowed }))) { $setParams['LogAllowed'] = [bool]$RunState.wantLogAllowed }
          if ((Test-AllConditions -Conditions @({ $null -ne $haveLogKB }, { $null -ne $RunState.wantLogKB })))           { $setParams['LogMaxSizeKilobytes'] = [int]$RunState.wantLogKB }
          if ((Test-AllConditions -Conditions @({ $null -ne $haveLogFile }, { -not [string]::IsNullOrWhiteSpace($RunState.wantLogFile) }))) { $setParams['LogFileName'] = $RunState.wantLogFile }
          Set-NetFirewallProfile @setParams | Out-Null
          $out += (Get-ResultItem -Category Profile -Target $Name -Status Changed -Message "Profile remediated")
        } catch {
          $out += (Get-ResultItem -Category Profile -Target $Name -Status Error -Message "Profile remediation failed" -Detail $_.Exception.Message)
        }
      } else {
        $out += (Get-ResultItem -Category Profile -Target $Name -Status Note -Message "Remediation skipped by ShouldProcess")
      }
}

function Ensure-Profile {
  [CmdletBinding(SupportsShouldProcess = $true)]
  param(
    [Parameter(Mandatory)][ValidateSet('Domain','Private','Public')][string]$Name,
    [Parameter(Mandatory)]$Def,
    [switch]$Remediate
  , [hashtable]$RunState)
  $out = @()
  try {
    $p = Get-NetFirewallProfile -Name $Name
    $profileDrift = Get-FirewallProfileDrift -ProfileObject $p -Definition $Def
    $drift = @($profileDrift.Items)
    $RunState.wantEnabled = $profileDrift.Desired.Enabled
    $RunState.wantIn = $profileDrift.Desired.Inbound
    $RunState.wantOut = $profileDrift.Desired.Outbound
    $RunState.wantNotify = $profileDrift.Desired.Notify
    $RunState.wantLogBlocked = $profileDrift.Desired.LogBlocked
    $RunState.wantLogAllowed = $profileDrift.Desired.LogAllowed
    $RunState.wantLogKB = $profileDrift.Desired.LogSize
    $RunState.wantLogFile = $profileDrift.Desired.LogFile
    if ($drift.Count -eq 0) {
      $out += (Get-ResultItem -Category Profile -Target $Name -Status OK -Message "Profile matches baseline")
      return $out
    }
    $out += (Get-ResultItem -Category Profile -Target $Name -Status Drift -Message "Profile drift detected" -Detail ($drift -join '; '))
    if ($Remediate) {
      . Ensure-ProfileStage01 -RunState $RunState
. Ensure-ProfileStage02 -RunState $RunState
    }
  } catch {
    $out += (Get-ResultItem -Category Profile -Target $Name -Status Error -Message "Profile query failed" -Detail $_.Exception.Message)
  }
  $out
}
# -------------------------
# Inbound rule disabling by pattern
# -------------------------
function Disable-InboundByNameLike {
  [CmdletBinding(SupportsShouldProcess = $true)]
  param(
    [Parameter(Mandatory)][string[]]$Patterns,
    [Parameter(Mandatory)][string]$LocalPolicyStore
  , [hashtable]$RunState)
  $out = @()
  $allInbound = @()
  try {
    $allInbound = @(Get-NetFirewallRule -PolicyStore $LocalPolicyStore -Direction Inbound -ErrorAction Stop)
  } catch {
    $out += (Get-ResultItem -Category InboundRuleDisable -Target "InboundRules" -Status Error -Message "Inbound rule enumeration failed" -Detail $_.Exception.Message)
    return $out
  }
  foreach ($pat in $Patterns) {
    if ([string]::IsNullOrWhiteSpace($pat)) { continue }
    $matchingRules = @($allInbound | Where-Object { $_.DisplayName -like $pat })
    foreach ($r in $matchingRules) {
      $out += @(Disable-InboundFirewallRule -Rule $r -Pattern $pat -PolicyStore $LocalPolicyStore -DecisionContext $PSCmdlet -Apply:$RunState.Remediate)
    }
  }
  if ($out.Count -eq 0) {
    $out += (Get-ResultItem -Category InboundRuleDisable -Target "InboundRules" -Status OK -Message "No matching enabled inbound rules found")
  }
  $out
}
# -------------------------
# Ensure baseline rules
# -------------------------
function Get-FirewallRuleSpecValues {
  param([Parameter(Mandatory)]$Spec)
  $values = [ordered]@{
    Name        = [string](Get-ObjProp -Object $Spec -Name 'Name' -Default '')
    DisplayName = [string](Get-ObjProp -Object $Spec -Name 'DisplayName' -Default '')
    Group       = [string](Get-ObjProp -Object $Spec -Name 'Group' -Default '')
    Direction   = [string](Get-ObjProp -Object $Spec -Name 'Direction' -Default '')
    Action      = [string](Get-ObjProp -Object $Spec -Name 'Action' -Default '')
    Protocol    = [string](Get-ObjProp -Object $Spec -Name 'Protocol' -Default '')
    LocalPort   = Get-ObjProp -Object $Spec -Name 'LocalPort' -Default $null
    RemotePort  = Get-ObjProp -Object $Spec -Name 'RemotePort' -Default $null
    Program     = Get-ObjProp -Object $Spec -Name 'Program' -Default $null
    Service     = Get-ObjProp -Object $Spec -Name 'Service' -Default $null
    Profile     = @((Get-ObjProp -Object $Spec -Name 'Profile' -Default @()) | Where-Object { $_ })
    Enabled     = Normalize-EnabledValue (Get-ObjProp -Object $Spec -Name 'Enabled' -Default $true)
    Description = [string](Get-ObjProp -Object $Spec -Name 'Description' -Default '')
  }
  return [pscustomobject]$values
}
function Find-BaselineFirewallRule {
  param([Parameter(Mandatory)]$RuleSpec,[Parameter(Mandatory)][string]$LocalPolicyStore)
  $existing = @()
  if ($RuleSpec.Name) {
    $existing = @(Get-NetFirewallRule -PolicyStore $LocalPolicyStore -Name $RuleSpec.Name -ErrorAction SilentlyContinue)
  }
  if ($existing.Count -eq 0 -and $RuleSpec.DisplayName) {
    $existing = @(Get-NetFirewallRule -PolicyStore $LocalPolicyStore -DisplayName $RuleSpec.DisplayName -ErrorAction SilentlyContinue)
    if ($RuleSpec.Group) { $existing = @($existing | Where-Object { $_.Group -eq $RuleSpec.Group }) }
  }
  return $existing
}
function Get-BaselineFirewallRuleDrift {
  param([Parameter(Mandatory)]$Rule,[Parameter(Mandatory)]$RuleSpec,[Parameter(Mandatory)][string]$LocalPolicyStore, [hashtable]$RunState)
  $need = @(Get-FirewallRulePropertyDrift -Rule $Rule -RuleSpec $RuleSpec)
  $haveProf = @(Normalize-ProfileValue $Rule.Profile)
  $wantProf = @(Normalize-ProfileValue $RuleSpec.Profile)
  if ($wantProf.Count -gt 0 -and ((@($haveProf) -join ',') -ne (@($wantProf) -join ','))) {
    $need += 'Profile'
  }
  $RunState.portFilter = $null
  try {
    $RunState.portFilter = Get-NetFirewallRule -PolicyStore $LocalPolicyStore -Name $Rule.Name |
      Get-NetFirewallPortFilter
  } catch {
    Write-Verbose ("Firewall port filter read failed for '{0}': {1}" -f $Rule.Name,$_.Exception.Message)
  }
  if ($RunState.portFilter) {
    $need += @(Get-FirewallPortPropertyDrift -PortFilter $RunState.portFilter -RuleSpec $RuleSpec)
  }
  return [pscustomobject]@{ Need = $need; PortFilter = $RunState.portFilter }
}
function Get-FirewallRulePropertyDrift {
  param($Rule, $RuleSpec)
  $need = @()
  if ($Rule.Enabled -ne $RuleSpec.Enabled) { $need += 'Enabled' }
  foreach ($property in @('Direction','Action','Group')) {
    if ($RuleSpec.$property -and $Rule.$property -ne $RuleSpec.$property) { $need += $property }
  }
  return $need
}
function Get-FirewallPortPropertyDrift {
  param($PortFilter, $RuleSpec)
  $need = @()
  foreach ($property in @('Protocol','LocalPort','RemotePort')) {
    if ($RuleSpec.$property -and $PortFilter.$property -ne $RuleSpec.$property) { $need += $property }
  }
  return $need
}
function New-BaselineFirewallRuleSection01 {
  param([hashtable]$RunState)
$params = @{ PolicyStore = $RunState.LocalPolicyStore; Direction = $RunState.RuleSpec.Direction; Action = $RunState.RuleSpec.Action; Protocol = $RunState.RuleSpec.Protocol; Enabled = $RunState.RuleSpec.Enabled }
  if ($RunState.RuleSpec.Name) { $params['Name'] = $RunState.RuleSpec.Name }
  if ($RunState.RuleSpec.DisplayName) { $params['DisplayName'] = $RunState.RuleSpec.DisplayName }
  if ($RunState.RuleSpec.Group) { $params['Group'] = $RunState.RuleSpec.Group }
  if ($RunState.RuleSpec.LocalPort) { $params['LocalPort'] = $RunState.RuleSpec.LocalPort }
  if ($RunState.RuleSpec.RemotePort) { $params['RemotePort'] = $RunState.RuleSpec.RemotePort }
}

function New-BaselineFirewallRuleSection02 {
  param([hashtable]$RunState)
if ($RunState.RuleSpec.Program) { $params['Program'] = $RunState.RuleSpec.Program }
  if ($RunState.RuleSpec.Service) { $params['Service'] = $RunState.RuleSpec.Service }
  if ($RunState.RuleSpec.Profile.Count -gt 0) { $params['Profile'] = $RunState.RuleSpec.Profile }
  if ($RunState.RuleSpec.Description) { $params['Description'] = $RunState.RuleSpec.Description }
  New-NetFirewallRule @params | Out-Null
}

function New-BaselineFirewallRule {
  param([Parameter(Mandatory)]$RuleSpec,[Parameter(Mandatory)][string]$LocalPolicyStore, [hashtable]$RunState)
  $RunState.LocalPolicyStore = $LocalPolicyStore
  $RunState.RuleSpec = $RuleSpec
  # Rules can only be added to a store at creation time.
    . New-BaselineFirewallRuleSection01 -RunState $RunState
    . New-BaselineFirewallRuleSection02 -RunState $RunState
}
function Set-BaselineFirewallRuleSection01 {
  param([hashtable]$RunState)
$setParams = @{ PolicyStore = $RunState.LocalPolicyStore; Name = $RunState.Rule.Name; Enabled = $RunState.RuleSpec.Enabled }
  if ($RunState.RuleSpec.Direction) { $setParams['Direction'] = $RunState.RuleSpec.Direction }
  if ($RunState.RuleSpec.Action) { $setParams['Action'] = $RunState.RuleSpec.Action }
  if ($RunState.RuleSpec.Group) { $setParams['Group'] = $RunState.RuleSpec.Group }
  if ($RunState.RuleSpec.Profile.Count -gt 0) { $setParams['Profile'] = $RunState.RuleSpec.Profile }
  Set-NetFirewallRule @setParams | Out-Null
}

function Set-BaselineFirewallRuleSection02 {
  param([hashtable]$RunState)
if ($RunState.PortFilter -and ((Test-AnyCondition -Conditions @({ $RunState.RuleSpec.Protocol }, { $RunState.RuleSpec.LocalPort })) -or $RunState.RuleSpec.RemotePort)) {
    $portParams = @{}
    if ($RunState.RuleSpec.Protocol) { $portParams['Protocol'] = $RunState.RuleSpec.Protocol }
    if ($RunState.RuleSpec.LocalPort) { $portParams['LocalPort'] = $RunState.RuleSpec.LocalPort }
    if ($RunState.RuleSpec.RemotePort) { $portParams['RemotePort'] = $RunState.RuleSpec.RemotePort }
    Set-NetFirewallPortFilter -InputObject $RunState.PortFilter @portParams | Out-Null
  }
}

function Set-BaselineFirewallRuleSection03 {
  param([hashtable]$RunState)
if ($RunState.RuleSpec.Description) { Set-NetFirewallRule -PolicyStore $RunState.LocalPolicyStore -Name $RunState.Rule.Name -Description $RunState.RuleSpec.Description -ErrorAction Stop | Out-Null }
}

function Set-BaselineFirewallRule {
  param([Parameter(Mandatory)]$Rule,[Parameter(Mandatory)]$RuleSpec,[object]$PortFilter,[Parameter(Mandatory)][string]$LocalPolicyStore, [hashtable]$RunState)
  $RunState.LocalPolicyStore = $LocalPolicyStore
  $RunState.PortFilter = $PortFilter
  $RunState.Rule = $Rule
  $RunState.RuleSpec = $RuleSpec
    . Set-BaselineFirewallRuleSection01 -RunState $RunState
    . Set-BaselineFirewallRuleSection02 -RunState $RunState
    . Set-BaselineFirewallRuleSection03 -RunState $RunState
}
function Ensure-FwRule {
  [CmdletBinding(SupportsShouldProcess = $true)]
  param(
    [Parameter(Mandatory)]$Spec,
    [Parameter(Mandatory)][string]$LocalPolicyStore
  , [hashtable]$RunState)
  $out = @()
  $RunState.ruleSpec = Get-FirewallRuleSpecValues -Spec $Spec
  $name = $RunState.ruleSpec.Name
  $disp = $RunState.ruleSpec.DisplayName
  $targetId = if ($name) { $name } else { $disp }
  if ([string]::IsNullOrWhiteSpace($targetId)) {
    $out += (Get-ResultItem -Category EnsureRule -Target "EnsureRules" -Status Error -Message "Invalid rule spec: missing Name/DisplayName")
    return $out
  }
  try {
    $existing = @(Find-BaselineFirewallRule -RuleSpec $RunState.ruleSpec -LocalPolicyStore $LocalPolicyStore)
  } catch {
    $out += (Get-ResultItem -Category EnsureRule -Target $targetId -Status Error -Message "Rule query failed" -Detail $_.Exception.Message -Name $name -DisplayName $disp)
    return $out
  }
  if ($existing.Count -eq 0) {
    return @(Add-MissingFirewallRuleResult -RuleSpec $RunState.ruleSpec -TargetId $targetId -PolicyStore $LocalPolicyStore -DecisionContext $PSCmdlet -Apply:$RunState.Remediate -RunState $RunState)
  }
  foreach ($r in $existing) {
    $out += @(Add-ExistingFirewallRuleResult -Rule $r -RuleSpec $RunState.ruleSpec -TargetId $targetId -PolicyStore $LocalPolicyStore -DecisionContext $PSCmdlet -Apply:$RunState.Remediate -RunState $RunState)
  }
  $out
}
# -------------------------
# Main
# -------------------------
function Invoke-Capability18MainPhase01 {
  param([hashtable]$RunState)
  if (-not (Ensure-EventSource -Source $EventSource -LogName $EventLogName)) {
    Write-Warning "EventSource could not be registered. EventLog tracing will be unavailable."
  }
  $RunState.start = Get-Date
  $isAdmin = Test-IsAdmin
  $script:Findings = Get-FindingsList
  $results = New-Object System.Collections.Generic.List[object]
  if (-not $isAdmin) {
    $results.Add((Get-ResultItem -Category Runtime -Target "Elevation" -Status Note -Message "Not elevated: remediation may fail"))
  }
  $cat = Get-EffectiveCatalog -CatalogPath $CatalogPath -ConfigPath $ConfigPath -DefaultCatalog $RunState.DefaultCatalog
  if ($null -eq $cat) {
    $cat = $RunState.DefaultCatalog
    $results.Add((Get-ResultItem -Category Catalog -Target "Catalog" -Status Note -Message "Catalog not loaded; using built-in defaults"))
  }
  $cat = Ensure-CatalogDefaults -Catalog $cat -DefaultCatalog $RunState.DefaultCatalog
}
function Invoke-Capability18MainPhase02 {
  param([hashtable]$RunState)
  foreach ($n in @('Domain','Private','Public')) {
    $def = Get-ObjProp -Object $cat.Profiles -Name $n -Default $RunState.DefaultCatalog.Profiles.$n
    $resArr = Ensure-Profile -Name $n -Def $def -Remediate:$RunState.Remediate -RunState $RunState
    foreach ($r in $resArr) {
        $results.Add($r)
        if ($r.Status -eq 'Drift') {
            Add-Finding -FindingList $script:Findings -Code 'FW-Profile-Drift' -Severity 'Medium' -Message "Firewall profile drift: $($r.Target)" -Extra @{ Profile = $r.Target; Detail = $r.Detail }
        }
    }
  }
  # Disable inbound patterns
  $patterns = @((Get-ObjProp -Object $cat -Name 'DisableInboundByNameLike' -Default @()) | Where-Object { $_ -is [string] -and $_ })
  $RunState.inboundResults = Disable-InboundByNameLike -Patterns $patterns -Remediate:$RunState.Remediate -LocalPolicyStore $RunState.LocalPolicyStore -RunState $RunState
}
function Invoke-Capability18MainPhase03 {
  param([hashtable]$RunState)
  foreach ($r in $RunState.inboundResults) {
      $results.Add($r)
      if ($r.Status -eq 'Drift') {
          Add-Finding -FindingList $script:Findings -Code 'FW-InboundRule-Enabled' -Severity 'Medium' -Message "Risky inbound rule enabled: $($r.DisplayName)" -Extra @{ Name = $r.Name; DisplayName = $r.DisplayName; Pattern = $r.Target }
      }
  }
  # Ensure rules
  $ensureRules = @((Get-ObjProp -Object $cat -Name 'EnsureRules' -Default @()) | Where-Object { $_ })
  foreach ($rule in $ensureRules) {
    $ensureResults = Ensure-FwRule -Spec $rule -Remediate:$RunState.Remediate -LocalPolicyStore $RunState.LocalPolicyStore -RunState $RunState
    foreach ($r in $ensureResults) {
        $results.Add($r)
        if ($r.Status -eq 'Drift') {
            Add-Finding -FindingList $script:Findings -Code 'FW-EnsureRule-Drift' -Severity 'Medium' -Message "Required firewall rule drift/missing: $($r.Target)" -Extra @{ RuleId = $r.Target; Detail = $r.Detail; Name = $r.Name; DisplayName = $r.DisplayName }
        }
    }
  }
  $RunState.duration = (New-TimeSpan -Start $RunState.start -End (Get-Date))
  $RunState.hasError = @($results | Where-Object { $_.Status -eq 'Error' }).Count -gt 0
  $RunState.hasDrift = @($results | Where-Object { $_.Status -eq 'Drift' }).Count -gt 0
}
function Invoke-Capability18MainPhase04 {
  param([hashtable]$RunState)
  $ok = (-not $RunState.hasError) -and (-not ($Strict -and $RunState.hasDrift))
  $eventId = if ($ok) { 4800 } else { 4810 }
  $level   = if ($ok) { 'Information' } else { 'Warning' }
  # Compact event message; no formatting.
  $eventSummary = "Mode={0}; Elevated={1}; PolicyStore={2}; Changed={3}; Drift={4}; Errors={5}; Duration={6}" -f `
    ($(if ($RunState.Remediate) { 'Remediate' } else { 'Audit' })), $isAdmin, $RunState.LocalPolicyStore, `
    (@($results | Where-Object { $_.Status -eq 'Changed' }).Count), `
    (@($results | Where-Object { $_.Status -eq 'Drift' }).Count), `
    (@($results | Where-Object { $_.Status -eq 'Error' }).Count), `
    ([string]$RunState.duration)
  Write-HealthEvent -Id $eventId -Message $eventSummary -Level $level -Source $EventSource -LogName $EventLogName
}
function Invoke-Capability18MainPhase05 {
  param([hashtable]$RunState)
  if ($ConsoleSummary) {
    $summaryObj = [pscustomobject]@{ ComputerName = $env:COMPUTERNAME; Mode = $Mode; Duration = $RunState.duration }
    $findingsAL = ConvertTo-ArrayList -InputObject $script:Findings
    Write-ConsoleSummary -Summary $summaryObj -Findings $findingsAL `
      -CustomFields ([ordered]@{
        Mode        = $(if ($RunState.Remediate) { 'Remediate' } else { 'Audit' })
        Strict      = $Strict
        Elevated    = $isAdmin
        PolicyStore = $RunState.LocalPolicyStore
        Changed     = @($results | Where-Object { $_.Status -eq 'Changed' }).Count
        Drift       = @($results | Where-Object { $_.Status -eq 'Drift' }).Count
        Errors      = @($results | Where-Object { $_.Status -eq 'Error' }).Count
        Duration    = [string]$RunState.duration
      })
    # Show important items (non-OK, top 25)
    $items = @($results)
    $top = $items | Where-Object { $_.Status -in @('Error','Drift','Changed','Note') }
    if (@($top).Count -gt 0) {
      Write-UiHeader -Text "Findings (top 25)"
      $top | Select-Object -First 25 | ForEach-Object { Write-UiItem -Item $_ }
    }
    # Show OK items if requested
    if ($ShowOkInConsole) {
      $okItems = $items | Where-Object { $_.Status -eq 'OK' }
      if (@($okItems).Count -gt 0) {
        Write-UiHeader -Text "OK items (top 25)"
        ($okItems | Select-Object -First 25) | ForEach-Object { Write-UiItem -Item $_ }
      }
    }
  }
}
function Invoke-Capability18Main {
  param($EntryBoundParameters, $EntryCmdlet, $EntryInvocation, [hashtable]$RunState)
  $script:__EntryBoundParameters = $EntryBoundParameters
  $script:__EntryCmdlet = $EntryCmdlet
  $script:__EntryInvocation = $EntryInvocation
  . Invoke-Capability18MainPhase01 -RunState $RunState
  . Invoke-Capability18MainPhase02 -RunState $RunState
  . Invoke-Capability18MainPhase03 -RunState $RunState
  . Invoke-Capability18MainPhase04 -RunState $RunState
  . Invoke-Capability18MainPhase05 -RunState $RunState
}
. Invoke-Capability18Main -EntryBoundParameters $PSBoundParameters -EntryCmdlet $PSCmdlet -EntryInvocation $MyInvocation -RunState $RunState
# V2 output contract
function Get-Capability18ResultToken {
  $resultToken = if ($Strict -and $script:Findings.Count -gt 0) { 'FAIL' } elseif ($script:Findings.Count -gt 0) { 'WARN' } else { 'OK' }
  return $resultToken
}
$resultToken = Get-Capability18ResultToken
$v2Result = Get-V2ResultObject -ScriptName '18-Firewall-Baseline.ps1' -Mode $Mode -Result $resultToken -Findings (ConvertTo-ObjectArray -InputObject $script:Findings) -Summary ([pscustomobject]@{ ComputerName = $env:COMPUTERNAME; Mode = $Mode; Duration = $RunState.duration }) -Metadata @{ Results = $results }
Write-ResultObject -ResultObject $v2Result -OutputFormat $OutputFormat -OutputPath $OutputPath
if ($PassThru) { $v2Result }
exit (Get-V2ExitCode -Result $resultToken)
