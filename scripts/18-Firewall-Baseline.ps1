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
Import-Module (Join-Path $script:LibPath 'Common.psm1') -Force -DisableNameChecking
Import-Module (Join-Path $script:LibPath 'Output.psm1') -Force
Import-Module (Join-Path $script:LibPath 'EventLog.psm1') -Force
Import-Module (Join-Path $script:LibPath 'Results.psm1') -Force
Import-Module (Join-Path $script:LibPath 'Console.psm1') -Force
Import-Module (Join-Path $script:LibPath Serialization.psm1) -Force
Set-StrictMode -Version Latest
# v2-init (migrated to Initialize-V2Context)
$script:__V2Context = Initialize-V2Context -ScriptName '18-Firewall-Baseline.ps1' -BoundParameters $PSBoundParameters `
  -Mode $Mode -ConfigPath $ConfigPath -OutputFormat $OutputFormat -OutputPath $OutputPath `
  -PassThru:$PassThru -Strict:$Strict -Quiet:$Quiet -NoColor:$NoColor -DeriveRemediate
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
. (Join-Path $PSScriptRoot 'internal/18-Firewall-Baseline.helpers.ps1')
# -------------------------
# Default catalog (built-in)
# -------------------------
$DefaultCatalog = ConvertFrom-Json @"
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
# -------------------------
# Profile enforcement
# -------------------------
function Ensure-Profile {
  [CmdletBinding(SupportsShouldProcess = $true)]
  param(
    [Parameter(Mandatory)][ValidateSet('Domain','Private','Public')][string]$Name,
    [Parameter(Mandatory)]$Def,
    [switch]$Remediate
  )
  $out = @()
  try {
    $p = Get-NetFirewallProfile -Name $Name
    $wantEnabled  = [bool](Get-ObjProp -Object $Def -Name 'Enabled' -Default $true)
    $wantIn       = [string](Get-ObjProp -Object $Def -Name 'DefaultInbound' -Default 'Block')
    $wantOut      = [string](Get-ObjProp -Object $Def -Name 'DefaultOutbound' -Default 'Allow')
    $wantNotify   = [bool](Get-ObjProp -Object $Def -Name 'NotifyOnListen' -Default $false)
    # Catalog uses LogDropped; Set-NetFirewallProfile uses LogBlocked.
    $wantLogBlocked = Get-ObjProp -Object $Def -Name 'LogDropped' -Default $null
    $wantLogAllowed = Get-ObjProp -Object $Def -Name 'LogAllowed' -Default $null
    $wantLogKB      = Get-ObjProp -Object $Def -Name 'LogMaxSizeKB' -Default $null
    $wantLogFile    = Expand-EnvPath ([string](Get-ObjProp -Object $Def -Name 'LogFile' -Default ''))
    $haveEnabled = Get-ProfileProp -ProfileObject $p -PropName 'Enabled' -Default $null
    $haveIn      = Get-ProfileProp -ProfileObject $p -PropName 'DefaultInboundAction' -Default $null
    $haveOut     = Get-ProfileProp -ProfileObject $p -PropName 'DefaultOutboundAction' -Default $null
    $haveNotify  = Get-ProfileProp -ProfileObject $p -PropName 'NotifyOnListen' -Default $null
    $haveLogBlocked = Get-ProfileProp -ProfileObject $p -PropName 'LogBlocked' -Default $null
    $haveLogAllowed = Get-ProfileProp -ProfileObject $p -PropName 'LogAllowed' -Default $null
    $haveLogKB      = Get-ProfileProp -ProfileObject $p -PropName 'LogMaxSizeKilobytes' -Default $null
    $haveLogFile    = Expand-EnvPath ([string](Get-ProfileProp -ProfileObject $p -PropName 'LogFileName' -Default ''))
    $drift = @()
    if ($null -ne $haveEnabled -and $haveEnabled -ne $wantEnabled) { $drift += "Enabled=$haveEnabled != $wantEnabled" }
    if ($null -ne $haveIn -and $haveIn -ne $wantIn)               { $drift += "DefaultInbound=$haveIn != $wantIn" }
    if ($null -ne $haveOut -and $haveOut -ne $wantOut)            { $drift += "DefaultOutbound=$haveOut != $wantOut" }
    if ($null -ne $haveNotify -and $haveNotify -ne $wantNotify)   { $drift += "NotifyOnListen=$haveNotify != $wantNotify" }
    if ($null -ne $wantLogBlocked -and $null -ne $haveLogBlocked -and $haveLogBlocked -ne [bool]$wantLogBlocked) {
      $drift += "LogBlocked=$haveLogBlocked != $wantLogBlocked"
    }
    if ($null -ne $wantLogAllowed -and $null -ne $haveLogAllowed -and $haveLogAllowed -ne [bool]$wantLogAllowed) {
      $drift += "LogAllowed=$haveLogAllowed != $wantLogAllowed"
    }
    if ($null -ne $wantLogKB -and $null -ne $haveLogKB -and $haveLogKB -ne [int]$wantLogKB) {
      $drift += "LogMaxSizeKB=$haveLogKB != $wantLogKB"
    }
    if (-not [string]::IsNullOrWhiteSpace($wantLogFile) -and -not [string]::IsNullOrWhiteSpace($haveLogFile) -and $haveLogFile -ne $wantLogFile) {
      $drift += "LogFileName=$haveLogFile != $wantLogFile"
    }
    if ($drift.Count -eq 0) {
      $out += (Get-ResultItem -Category Profile -Target $Name -Status OK -Message "Profile matches baseline")
      return $out
    }
    $out += (Get-ResultItem -Category Profile -Target $Name -Status Drift -Message "Profile drift detected" -Detail ($drift -join '; '))
    if ($Remediate) {
      $spTarget = "FirewallProfile/$Name"
      if ($PSCmdlet.ShouldProcess($spTarget, "Set-NetFirewallProfile")) {
        try {
          $setParams = @{
            Name                  = $Name
            Enabled               = $wantEnabled
            DefaultInboundAction  = $wantIn
            DefaultOutboundAction = $wantOut
            NotifyOnListen        = $wantNotify
          }
          if ($null -ne $haveLogBlocked -and $null -ne $wantLogBlocked) { $setParams['LogBlocked'] = [bool]$wantLogBlocked }
          if ($null -ne $haveLogAllowed -and $null -ne $wantLogAllowed) { $setParams['LogAllowed'] = [bool]$wantLogAllowed }
          if ($null -ne $haveLogKB -and $null -ne $wantLogKB)           { $setParams['LogMaxSizeKilobytes'] = [int]$wantLogKB }
          if ($null -ne $haveLogFile -and -not [string]::IsNullOrWhiteSpace($wantLogFile)) { $setParams['LogFileName'] = $wantLogFile }
          Set-NetFirewallProfile @setParams | Out-Null
          $out += (Get-ResultItem -Category Profile -Target $Name -Status Changed -Message "Profile remediated")
        } catch {
          $out += (Get-ResultItem -Category Profile -Target $Name -Status Error -Message "Profile remediation failed" -Detail $_.Exception.Message)
        }
      } else {
        $out += (Get-ResultItem -Category Profile -Target $Name -Status Note -Message "Remediation skipped by ShouldProcess")
      }
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
  )
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
      if ($r.Enabled -eq 'True') {
        $out += (Get-ResultItem -Category InboundRuleDisable -Target $pat -Status Drift -Message "Inbound rule enabled" -Name $r.Name -DisplayName $r.DisplayName)
        if ($Remediate) {
          $spTarget = "FirewallRule/$($r.Name)"
          if ($PSCmdlet.ShouldProcess($spTarget, "Disable inbound rule")) {
            try {
              Set-NetFirewallRule -PolicyStore $LocalPolicyStore -Name $r.Name -Enabled False | Out-Null
              $out += (Get-ResultItem -Category InboundRuleDisable -Target $pat -Status Changed -Message "Inbound rule disabled" -Name $r.Name -DisplayName $r.DisplayName)
            } catch {
              $out += (Get-ResultItem -Category InboundRuleDisable -Target $pat -Status Error -Message "Disable failed" -Detail $_.Exception.Message -Name $r.Name -DisplayName $r.DisplayName)
            }
          } else {
            $out += (Get-ResultItem -Category InboundRuleDisable -Target $pat -Status Note -Message "Remediation skipped by ShouldProcess" -Name $r.Name -DisplayName $r.DisplayName)
          }
        }
      }
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
  param([Parameter(Mandatory)]$Rule,[Parameter(Mandatory)]$RuleSpec,[Parameter(Mandatory)][string]$LocalPolicyStore)
  $need = @()
  if ($RuleSpec.Direction -and $Rule.Direction -ne $RuleSpec.Direction) { $need += 'Direction' }
  if ($RuleSpec.Action -and $Rule.Action -ne $RuleSpec.Action) { $need += 'Action' }
  if ($Rule.Enabled -ne $RuleSpec.Enabled) { $need += 'Enabled' }
  if ($RuleSpec.Group -and $Rule.Group -ne $RuleSpec.Group) { $need += 'Group' }
  $haveProf = @(Normalize-ProfileValue $Rule.Profile)
  $wantProf = @(Normalize-ProfileValue $RuleSpec.Profile)
  if ($wantProf.Count -gt 0 -and ((@($haveProf) -join ',') -ne (@($wantProf) -join ','))) { $need += 'Profile' }
  $portFilter = $null
  try { $portFilter = Get-NetFirewallRule -PolicyStore $LocalPolicyStore -Name $Rule.Name | Get-NetFirewallPortFilter } catch {
    Write-Verbose ("Firewall port filter read failed for '{0}': {1}" -f $Rule.Name,$_.Exception.Message)
  }
  if ($portFilter) {
    if ($RuleSpec.Protocol -and $portFilter.Protocol -ne $RuleSpec.Protocol) { $need += 'Protocol' }
    if ($RuleSpec.LocalPort -and $portFilter.LocalPort -ne $RuleSpec.LocalPort) { $need += 'LocalPort' }
    if ($RuleSpec.RemotePort -and $portFilter.RemotePort -ne $RuleSpec.RemotePort) { $need += 'RemotePort' }
  }
  return [pscustomobject]@{ Need = $need; PortFilter = $portFilter }
}
function New-BaselineFirewallRule {
  param([Parameter(Mandatory)]$RuleSpec,[Parameter(Mandatory)][string]$LocalPolicyStore)
  # Rules can only be added to a store at creation time.
  $params = @{ PolicyStore = $LocalPolicyStore; Direction = $RuleSpec.Direction; Action = $RuleSpec.Action; Protocol = $RuleSpec.Protocol; Enabled = $RuleSpec.Enabled }
  if ($RuleSpec.Name) { $params['Name'] = $RuleSpec.Name }
  if ($RuleSpec.DisplayName) { $params['DisplayName'] = $RuleSpec.DisplayName }
  if ($RuleSpec.Group) { $params['Group'] = $RuleSpec.Group }
  if ($RuleSpec.LocalPort) { $params['LocalPort'] = $RuleSpec.LocalPort }
  if ($RuleSpec.RemotePort) { $params['RemotePort'] = $RuleSpec.RemotePort }
  if ($RuleSpec.Program) { $params['Program'] = $RuleSpec.Program }
  if ($RuleSpec.Service) { $params['Service'] = $RuleSpec.Service }
  if ($RuleSpec.Profile.Count -gt 0) { $params['Profile'] = $RuleSpec.Profile }
  if ($RuleSpec.Description) { $params['Description'] = $RuleSpec.Description }
  New-NetFirewallRule @params | Out-Null
}
function Set-BaselineFirewallRule {
  param([Parameter(Mandatory)]$Rule,[Parameter(Mandatory)]$RuleSpec,[object]$PortFilter,[Parameter(Mandatory)][string]$LocalPolicyStore)
  $setParams = @{ PolicyStore = $LocalPolicyStore; Name = $Rule.Name; Enabled = $RuleSpec.Enabled }
  if ($RuleSpec.Direction) { $setParams['Direction'] = $RuleSpec.Direction }
  if ($RuleSpec.Action) { $setParams['Action'] = $RuleSpec.Action }
  if ($RuleSpec.Group) { $setParams['Group'] = $RuleSpec.Group }
  if ($RuleSpec.Profile.Count -gt 0) { $setParams['Profile'] = $RuleSpec.Profile }
  Set-NetFirewallRule @setParams | Out-Null
  if ($PortFilter -and ($RuleSpec.Protocol -or $RuleSpec.LocalPort -or $RuleSpec.RemotePort)) {
    $portParams = @{}
    if ($RuleSpec.Protocol) { $portParams['Protocol'] = $RuleSpec.Protocol }
    if ($RuleSpec.LocalPort) { $portParams['LocalPort'] = $RuleSpec.LocalPort }
    if ($RuleSpec.RemotePort) { $portParams['RemotePort'] = $RuleSpec.RemotePort }
    Set-NetFirewallPortFilter -InputObject $PortFilter @portParams | Out-Null
  }
  if ($RuleSpec.Description) { Set-NetFirewallRule -PolicyStore $LocalPolicyStore -Name $Rule.Name -Description $RuleSpec.Description -ErrorAction Stop | Out-Null }
}
function Ensure-FwRule {
  [CmdletBinding(SupportsShouldProcess = $true)]
  param(
    [Parameter(Mandatory)]$Spec,
    [Parameter(Mandatory)][string]$LocalPolicyStore
  )
  $out = @()
  $ruleSpec = Get-FirewallRuleSpecValues -Spec $Spec
  $name = $ruleSpec.Name
  $disp = $ruleSpec.DisplayName
  $targetId = if ($name) { $name } else { $disp }
  if ([string]::IsNullOrWhiteSpace($targetId)) {
    $out += (Get-ResultItem -Category EnsureRule -Target "EnsureRules" -Status Error -Message "Invalid rule spec: missing Name/DisplayName")
    return $out
  }
  try {
    $existing = @(Find-BaselineFirewallRule -RuleSpec $ruleSpec -LocalPolicyStore $LocalPolicyStore)
  } catch {
    $out += (Get-ResultItem -Category EnsureRule -Target $targetId -Status Error -Message "Rule query failed" -Detail $_.Exception.Message -Name $name -DisplayName $disp)
    return $out
  }
  if ($existing.Count -eq 0) {
    $out += (Get-ResultItem -Category EnsureRule -Target $targetId -Status Drift -Message "Missing rule" -Name $name -DisplayName $disp)
    if ($Remediate) {
      $spTarget = "FirewallRule/(create)/$targetId"
      if ($PSCmdlet.ShouldProcess($spTarget, "New-NetFirewallRule")) {
        try {
          New-BaselineFirewallRule -RuleSpec $ruleSpec -LocalPolicyStore $LocalPolicyStore
          $out += (Get-ResultItem -Category EnsureRule -Target $targetId -Status Changed -Message "Rule created" -Name $name -DisplayName $disp)
        } catch {
          $out += (Get-ResultItem -Category EnsureRule -Target $targetId -Status Error -Message "Rule create failed" -Detail $_.Exception.Message -Name $name -DisplayName $disp)
        }
      } else {
        $out += (Get-ResultItem -Category EnsureRule -Target $targetId -Status Note -Message "Remediation skipped by ShouldProcess" -Name $name -DisplayName $disp)
      }
    }
    return $out
  }
  foreach ($r in $existing) {
    $drift = Get-BaselineFirewallRuleDrift -Rule $r -RuleSpec $ruleSpec -LocalPolicyStore $LocalPolicyStore
    $need = @($drift.Need)
    if ($need.Count -eq 0) {
      $out += (Get-ResultItem -Category EnsureRule -Target $targetId -Status OK -Message "Rule matches baseline" -Name $r.Name -DisplayName $r.DisplayName)
      continue
    }
    $out += (Get-ResultItem -Category EnsureRule -Target $targetId -Status Drift -Message "Rule drift detected" -Detail ($need -join ', ') -Name $r.Name -DisplayName $r.DisplayName)
    if ($Remediate) {
      $spTarget = "FirewallRule/$($r.Name)"
      if ($PSCmdlet.ShouldProcess($spTarget, "Set-NetFirewallRule / Set-NetFirewallPortFilter")) {
        try {
          Set-BaselineFirewallRule -Rule $r -RuleSpec $ruleSpec -PortFilter $drift.PortFilter -LocalPolicyStore $LocalPolicyStore
          $out += (Get-ResultItem -Category EnsureRule -Target $targetId -Status Changed -Message "Rule remediated" -Name $r.Name -DisplayName $r.DisplayName)
        } catch {
          $out += (Get-ResultItem -Category EnsureRule -Target $targetId -Status Error -Message "Rule remediation failed" -Detail $_.Exception.Message -Name $r.Name -DisplayName $r.DisplayName)
        }
      } else {
        $out += (Get-ResultItem -Category EnsureRule -Target $targetId -Status Note -Message "Remediation skipped by ShouldProcess" -Name $r.Name -DisplayName $r.DisplayName)
      }
    }
  }
  $out
}
# -------------------------
# Main
# -------------------------
if (-not (Ensure-EventSource -Source $EventSource -LogName $EventLogName)) {
  Write-Warning "EventSource could not be registered. EventLog tracing will be unavailable."
}
$start = Get-Date
$isAdmin = Test-IsAdmin
$script:Findings = Get-FindingsList
$results = New-Object System.Collections.Generic.List[object]
if (-not $isAdmin) {
  $results.Add((Get-ResultItem -Category Runtime -Target "Elevation" -Status Note -Message "Not elevated: remediation may fail"))
}
$cat = Get-EffectiveCatalog -CatalogPath $CatalogPath -ConfigPath $ConfigPath -DefaultCatalog $DefaultCatalog
if ($null -eq $cat) {
  $cat = $DefaultCatalog
  $results.Add((Get-ResultItem -Category Catalog -Target "Catalog" -Status Note -Message "Catalog not loaded; using built-in defaults"))
}
$cat = Ensure-CatalogDefaults -Catalog $cat -DefaultCatalog $DefaultCatalog
# Profiles
foreach ($n in @('Domain','Private','Public')) {
  $def = Get-ObjProp -Object $cat.Profiles -Name $n -Default $DefaultCatalog.Profiles.$n
  $resArr = Ensure-Profile -Name $n -Def $def -Remediate:$Remediate
  foreach ($r in $resArr) {
      $results.Add($r)
      if ($r.Status -eq 'Drift') {
          Add-Finding -FindingList $script:Findings -Code 'FW-Profile-Drift' -Severity 'Medium' -Message "Firewall profile drift: $($r.Target)" -Extra @{ Profile = $r.Target; Detail = $r.Detail }
      }
  }
}
# Disable inbound patterns
$patterns = @((Get-ObjProp -Object $cat -Name 'DisableInboundByNameLike' -Default @()) | Where-Object { $_ -is [string] -and $_ })
$inboundResults = Disable-InboundByNameLike -Patterns $patterns -Remediate:$Remediate -LocalPolicyStore $LocalPolicyStore
foreach ($r in $inboundResults) {
    $results.Add($r)
    if ($r.Status -eq 'Drift') {
        Add-Finding -FindingList $script:Findings -Code 'FW-InboundRule-Enabled' -Severity 'Medium' -Message "Risky inbound rule enabled: $($r.DisplayName)" -Extra @{ Name = $r.Name; DisplayName = $r.DisplayName; Pattern = $r.Target }
    }
}
# Ensure rules
$ensureRules = @((Get-ObjProp -Object $cat -Name 'EnsureRules' -Default @()) | Where-Object { $_ })
foreach ($rule in $ensureRules) {
  $ensureResults = Ensure-FwRule -Spec $rule -Remediate:$Remediate -LocalPolicyStore $LocalPolicyStore
  foreach ($r in $ensureResults) {
      $results.Add($r)
      if ($r.Status -eq 'Drift') {
          Add-Finding -FindingList $script:Findings -Code 'FW-EnsureRule-Drift' -Severity 'Medium' -Message "Required firewall rule drift/missing: $($r.Target)" -Extra @{ RuleId = $r.Target; Detail = $r.Detail; Name = $r.Name; DisplayName = $r.DisplayName }
      }
  }
}
$duration = (New-TimeSpan -Start $start -End (Get-Date))
$hasError = @($results | Where-Object { $_.Status -eq 'Error' }).Count -gt 0
$hasDrift = @($results | Where-Object { $_.Status -eq 'Drift' }).Count -gt 0
# Strict means: any drift flips to WARN (4810)
$ok = (-not $hasError) -and (-not ($Strict -and $hasDrift))
$eventId = if ($ok) { 4800 } else { 4810 }
$level   = if ($ok) { 'Information' } else { 'Warning' }
# Compact event message; no formatting.
$eventSummary = "Mode={0}; Elevated={1}; PolicyStore={2}; Changed={3}; Drift={4}; Errors={5}; Duration={6}" -f `
  ($(if ($Remediate) { 'Remediate' } else { 'Audit' })), $isAdmin, $LocalPolicyStore, `
  (@($results | Where-Object { $_.Status -eq 'Changed' }).Count), `
  (@($results | Where-Object { $_.Status -eq 'Drift' }).Count), `
  (@($results | Where-Object { $_.Status -eq 'Error' }).Count), `
  ([string]$duration)
Write-HealthEvent -Id $eventId -Message $eventSummary -Level $level -Source $EventSource -LogName $EventLogName
if ($ConsoleSummary) {
  $summaryObj = [pscustomobject]@{ ComputerName = $env:COMPUTERNAME; Mode = $Mode; Duration = $duration }
  $findingsAL = ConvertTo-ArrayList -InputObject $script:Findings
  Write-ConsoleSummary -Summary $summaryObj -Findings $findingsAL `
    -CustomFields ([ordered]@{
      Mode        = $(if ($Remediate) { 'Remediate' } else { 'Audit' })
      Strict      = $Strict
      Elevated    = $isAdmin
      PolicyStore = $LocalPolicyStore
      Changed     = @($results | Where-Object { $_.Status -eq 'Changed' }).Count
      Drift       = @($results | Where-Object { $_.Status -eq 'Drift' }).Count
      Errors      = @($results | Where-Object { $_.Status -eq 'Error' }).Count
      Duration    = [string]$duration
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
# V2 output contract
$resultToken = if ($Strict -and $script:Findings.Count -gt 0) { 'FAIL' } elseif ($script:Findings.Count -gt 0) { 'WARN' } else { 'OK' }
$v2Result = Get-V2ResultObject -ScriptName '18-Firewall-Baseline.ps1' -Mode $Mode -Result $resultToken -Findings (ConvertTo-ObjectArray -InputObject $script:Findings) -Summary ([pscustomobject]@{ ComputerName = $env:COMPUTERNAME; Mode = $Mode; Duration = $duration }) -Metadata @{ Results = $results }
Write-ResultObject -ResultObject $v2Result -OutputFormat $OutputFormat -OutputPath $OutputPath
if ($PassThru) { $v2Result }
exit (Get-V2ExitCode -Result $resultToken)
