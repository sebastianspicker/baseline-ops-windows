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

function Get-EffectiveCatalog {
  [CmdletBinding()]
  param(
    [AllowNull()][string]$CatalogPath,
    [AllowNull()][string]$ConfigPath,
    [Parameter(Mandatory)]$DefaultCatalog
  )
  if ($CatalogPath) {
    $sanitized = Sanitize-Path -Path $CatalogPath -MustExist
    if ($sanitized) {
      $catalog = Try-ReadJsonFile -Path $sanitized
      if ($catalog) { return $catalog }
    }
  }
  if ($ConfigPath) {
    $sanitizedConfig = Sanitize-Path -Path $ConfigPath -MustExist
    if ($sanitizedConfig) {
      $config = Try-ReadJsonFile -Path $sanitizedConfig
      if ($config) {
        $firewall = Get-ObjProp -Object $config -Name 'Firewall' -Default $null
        $configuredPath = if ($firewall) {
          [string](Get-ObjProp -Object $firewall -Name 'CatalogPath' -Default '')
        } else {
          ''
        }
        if (-not [string]::IsNullOrWhiteSpace($configuredPath)) {
          $sanitizedCatalog = Sanitize-Path -Path $configuredPath -MustExist
          if ($sanitizedCatalog) {
            $catalog = Try-ReadJsonFile -Path $sanitizedCatalog
            if ($catalog) { return $catalog }
          }
        }
      }
    }
  }
  $DefaultCatalog
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
