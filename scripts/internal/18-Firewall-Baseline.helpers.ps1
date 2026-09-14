<#
.SYNOPSIS
Data and catalog helpers for the firewall baseline script.

.DESCRIPTION
Normalizes catalog values, reads bounded JSON configuration, fills omitted
catalog sections, and creates result records without invoking firewall cmdlets.
#>

function Expand-EnvPath {
  [CmdletBinding()]
  param([AllowNull()][string]$Path)
  if ([string]::IsNullOrWhiteSpace($Path)) { return $Path }
  [Environment]::ExpandEnvironmentVariables($Path)
}

function Normalize-ProfileValue {
  [CmdletBinding()]
  param([AllowNull()]$ProfileValue)
  if ($null -eq $ProfileValue) { return @() }
  $parts = @($ProfileValue.ToString().Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_ })
  @($parts | Sort-Object -Unique)
}

function Normalize-EnabledValue {
  [CmdletBinding()]
  param($Value)
  # NetSecurity expects "True" or "False" for -Enabled on rules.
  if ($Value -is [bool]) { return ($(if ($Value) { 'True' } else { 'False' })) }
  $s = [string]$Value
  if ($s -match '^(True|False)$') { return $s }
  if ($s -match '^(1|Enabled)$')  { return 'True' }
  if ($s -match '^(0|Disabled)$') { return 'False' }
  'True'
}

function Get-ObjProp {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]$Object,
    [Parameter(Mandatory)][string]$Name,
    $Default = $null
  )
  if ($null -eq $Object) { return $Default }
  if ($Object -is [System.Collections.IDictionary]) {
    if ($Object.Contains($Name)) { return $Object[$Name] }
    return $Default
  }
  $property = $Object.PSObject.Properties[$Name]
  if ($property) { return $property.Value }
  $Default
}

function Try-ReadJsonFile {
  [CmdletBinding()]
  param([Parameter(Mandatory)][string]$Path)
  if (-not (Test-Path -LiteralPath $Path)) { return $null }
  try {
    $raw = Get-BoundedUtf8FileContent -Path $Path -MaximumBytes 1048576
    if ([string]::IsNullOrWhiteSpace($raw)) { return $null }
    $raw | ConvertFrom-Json
  } catch {
    $null
  }
}

function Get-ResultItem {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][ValidateSet('Profile','InboundRuleDisable','EnsureRule','Catalog','Runtime')][string]$Category,
    [Parameter(Mandatory)][string]$Target,
    [Parameter(Mandatory)][ValidateSet('OK','Drift','Changed','Error','Note')][string]$Status,
    [string]$Message,
    [string]$Detail,
    [string]$Name,
    [string]$DisplayName
  )
  [pscustomobject]@{
    Time        = (Get-Date).ToString('s')
    Category    = $Category
    Target      = $Target
    Status      = $Status
    Message     = $Message
    Detail      = $Detail
    Name        = $Name
    DisplayName = $DisplayName
  }
}

function Read-SanitizedFirewallCatalog {
  param([AllowNull()][string]$Path)
  if (-not $Path) { return $null }
  $sanitized = Sanitize-Path -Path $Path -MustExist
  if (-not $sanitized) { return $null }
  return Try-ReadJsonFile -Path $sanitized
}

function Get-ConfiguredFirewallCatalog {
  param([AllowNull()][string]$ConfigPath)
  $config = Read-SanitizedFirewallCatalog -Path $ConfigPath
  if (-not $config) { return $null }
  $firewall = Get-ObjProp -Object $config -Name 'Firewall' -Default $null
  if (-not $firewall) { return $null }
  $configuredPath = [string](Get-ObjProp -Object $firewall -Name 'CatalogPath' -Default '')
  if ([string]::IsNullOrWhiteSpace($configuredPath)) { return $null }
  return Read-SanitizedFirewallCatalog -Path $configuredPath
}

function Get-EffectiveCatalog {
  [CmdletBinding()]
  param(
    [AllowNull()][string]$CatalogPath,
    [AllowNull()][string]$ConfigPath,
    [Parameter(Mandatory)]$DefaultCatalog
  )
  $catalog = Read-SanitizedFirewallCatalog -Path $CatalogPath
  if ($catalog) { return $catalog }
  $catalog = Get-ConfiguredFirewallCatalog -ConfigPath $ConfigPath
  if ($catalog) { return $catalog }
  return $DefaultCatalog
}

function Ensure-CatalogDefaults {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]$Catalog,
    [Parameter(Mandatory)]$DefaultCatalog
  )
  $profiles = Get-ObjProp -Object $Catalog -Name 'Profiles' -Default $null
  if (-not $profiles) {
    $Catalog | Add-Member -NotePropertyName Profiles -NotePropertyValue $DefaultCatalog.Profiles -Force
    $profiles = $Catalog.Profiles
  }
  foreach ($name in @('Domain','Private','Public')) {
    if (-not (Get-ObjProp -Object $profiles -Name $name -Default $null)) {
      $profiles | Add-Member -NotePropertyName $name -NotePropertyValue (Get-ObjProp -Object $DefaultCatalog.Profiles -Name $name) -Force
    }
  }
  if ($null -eq (Get-ObjProp -Object $Catalog -Name 'DisableInboundByNameLike' -Default $null)) {
    $Catalog | Add-Member -NotePropertyName DisableInboundByNameLike -NotePropertyValue @() -Force
  }
  if ($null -eq (Get-ObjProp -Object $Catalog -Name 'EnsureRules' -Default $null)) {
    $Catalog | Add-Member -NotePropertyName EnsureRules -NotePropertyValue @() -Force
  }
  $Catalog
}

function Get-ProfileProp {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]$ProfileObject,
    [Parameter(Mandatory)][string]$PropName,
    $Default = $null
  )
  $property = $ProfileObject.PSObject.Properties[$PropName]
  if ($property) { return $property.Value }
  $Default
}


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


function Get-FirewallProfileDrift {
  param($ProfileObject, $Definition)
  $p = $ProfileObject; $Def = $Definition
  $drift = @()
  $desired = @{
    Enabled = [bool](Get-ObjProp -Object $Def -Name 'Enabled' -Default $true)
    Inbound = [string](Get-ObjProp -Object $Def -Name 'DefaultInbound' -Default 'Block')
    Outbound = [string](Get-ObjProp -Object $Def -Name 'DefaultOutbound' -Default 'Allow')
    Notify = [bool](Get-ObjProp -Object $Def -Name 'NotifyOnListen' -Default $false)
    LogBlocked = Get-ObjProp -Object $Def -Name 'LogDropped' -Default $null
    LogAllowed = Get-ObjProp -Object $Def -Name 'LogAllowed' -Default $null
    LogSize = Get-ObjProp -Object $Def -Name 'LogMaxSizeKB' -Default $null
    LogFile = Expand-EnvPath ([string](Get-ObjProp -Object $Def -Name 'LogFile' -Default ''))
  }
  $actual = @{
    Enabled = Get-ProfileProp -ProfileObject $p -PropName 'Enabled' -Default $null
    Inbound = Get-ProfileProp -ProfileObject $p -PropName 'DefaultInboundAction' -Default $null
    Outbound = Get-ProfileProp -ProfileObject $p -PropName 'DefaultOutboundAction' -Default $null
    Notify = Get-ProfileProp -ProfileObject $p -PropName 'NotifyOnListen' -Default $null
    LogBlocked = Get-ProfileProp -ProfileObject $p -PropName 'LogBlocked' -Default $null
    LogAllowed = Get-ProfileProp -ProfileObject $p -PropName 'LogAllowed' -Default $null
    LogSize = Get-ProfileProp -ProfileObject $p -PropName 'LogMaxSizeKilobytes' -Default $null
    LogFile = Expand-EnvPath ([string](Get-ProfileProp -ProfileObject $p -PropName 'LogFileName' -Default ''))
  }
  $drift += @(Get-FirewallValueDrift -Actual $actual -Desired $desired -Keys @('Enabled','Inbound','Outbound','Notify'))
  $drift += @(Get-FirewallValueDrift -Actual $actual -Desired $desired -Keys @('LogBlocked','LogAllowed','LogSize','LogFile') -DesiredMustExist)
  [pscustomobject]@{ Items = $drift; Desired = $desired; Actual = $actual }
}

function Get-FirewallValueDrift {
  param($Actual, $Desired, [string[]]$Keys, [switch]$DesiredMustExist)
  foreach ($key in $Keys) {
    if ($DesiredMustExist -and $null -eq $Desired[$key]) { continue }
    if ($null -eq $Actual[$key]) { continue }
    if ($Actual[$key] -ne $Desired[$key]) {
      "$key=$($Actual[$key]) != $($Desired[$key])"
    }
  }
}

function Disable-InboundFirewallRule {
  param($Rule, [string]$Pattern, [string]$PolicyStore, $DecisionContext, [bool]$Apply)
  $out = @()
  if ($Rule.Enabled -ne 'True') { return $out }
  $out += Get-ResultItem -Category InboundRuleDisable -Target $Pattern -Status Drift -Message 'Inbound rule enabled' -Name $Rule.Name -DisplayName $Rule.DisplayName
  if (-not $Apply) { return $out }
  $target = "FirewallRule/$($Rule.Name)"
  if (-not $DecisionContext.ShouldProcess($target, 'Disable inbound rule')) {
    $out += Get-ResultItem -Category InboundRuleDisable -Target $Pattern -Status Note -Message 'Remediation skipped by ShouldProcess' -Name $Rule.Name -DisplayName $Rule.DisplayName
    return $out
  }
  try {
    Set-NetFirewallRule -PolicyStore $PolicyStore -Name $Rule.Name -Enabled False | Out-Null
    $out += Get-ResultItem -Category InboundRuleDisable -Target $Pattern -Status Changed -Message 'Inbound rule disabled' -Name $Rule.Name -DisplayName $Rule.DisplayName
  } catch {
    $out += Get-ResultItem -Category InboundRuleDisable -Target $Pattern -Status Error -Message 'Disable failed' -Detail $_.Exception.Message -Name $Rule.Name -DisplayName $Rule.DisplayName
  }
  return $out
}

function Add-MissingFirewallRuleResult {
  param($RuleSpec, [string]$TargetId, [string]$PolicyStore, $DecisionContext, [bool]$Apply, [hashtable]$RunState)
  $out = @(Get-ResultItem -Category EnsureRule -Target $TargetId -Status Drift -Message 'Missing rule' -Name $RuleSpec.Name -DisplayName $RuleSpec.DisplayName)
  if (-not $Apply) { return $out }
  $target = "FirewallRule/(create)/$TargetId"
  if (-not $DecisionContext.ShouldProcess($target, 'New-NetFirewallRule')) {
    $out += Get-ResultItem -Category EnsureRule -Target $TargetId -Status Note -Message 'Remediation skipped by ShouldProcess' -Name $RuleSpec.Name -DisplayName $RuleSpec.DisplayName
    return $out
  }
  try {
    New-BaselineFirewallRule -RuleSpec $RuleSpec -LocalPolicyStore $PolicyStore -RunState $RunState
    $out += Get-ResultItem -Category EnsureRule -Target $TargetId -Status Changed -Message 'Rule created' -Name $RuleSpec.Name -DisplayName $RuleSpec.DisplayName
  } catch {
    $out += Get-ResultItem -Category EnsureRule -Target $TargetId -Status Error -Message 'Rule create failed' -Detail $_.Exception.Message -Name $RuleSpec.Name -DisplayName $RuleSpec.DisplayName
  }
  return $out
}

function Add-ExistingFirewallRuleResult {
  param($Rule, $RuleSpec, [string]$TargetId, [string]$PolicyStore, $DecisionContext, [bool]$Apply, [hashtable]$RunState)
  $drift = Get-BaselineFirewallRuleDrift -Rule $Rule -RuleSpec $RuleSpec -LocalPolicyStore $PolicyStore -RunState $RunState
  $need = @($drift.Need)
  if ($need.Count -eq 0) { return @(Get-ResultItem -Category EnsureRule -Target $TargetId -Status OK -Message 'Rule matches baseline' -Name $Rule.Name -DisplayName $Rule.DisplayName) }
  $out = @(Get-ResultItem -Category EnsureRule -Target $TargetId -Status Drift -Message 'Rule drift detected' -Detail ($need -join ', ') -Name $Rule.Name -DisplayName $Rule.DisplayName)
  if (-not $Apply) { return $out }
  $target = "FirewallRule/$($Rule.Name)"
  if (-not $DecisionContext.ShouldProcess($target, 'Set-NetFirewallRule / Set-NetFirewallPortFilter')) {
    $out += Get-ResultItem -Category EnsureRule -Target $TargetId -Status Note -Message 'Remediation skipped by ShouldProcess' -Name $Rule.Name -DisplayName $Rule.DisplayName
    return $out
  }
  try {
    Set-BaselineFirewallRule -Rule $Rule -RuleSpec $RuleSpec -PortFilter $drift.PortFilter -LocalPolicyStore $PolicyStore -RunState $RunState
    $out += Get-ResultItem -Category EnsureRule -Target $TargetId -Status Changed -Message 'Rule remediated' -Name $Rule.Name -DisplayName $Rule.DisplayName
  } catch {
    $out += Get-ResultItem -Category EnsureRule -Target $TargetId -Status Error -Message 'Rule remediation failed' -Detail $_.Exception.Message -Name $Rule.Name -DisplayName $Rule.DisplayName
  }
  return $out
}
