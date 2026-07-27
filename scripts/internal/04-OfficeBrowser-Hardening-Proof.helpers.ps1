<#
.SYNOPSIS
Internal browser and Office policy helpers for the hardening proof script.

.DESCRIPTION
Normalizes catalog input and applies narrowly scoped Edge, Firefox, and Office
policy operations. Keeping these helpers separate makes policy decisions
independently testable while the entry script retains orchestration ownership.
#>
Import-Module (Join-Path $PSScriptRoot '../../lib/Validation.psm1')

function Get-TextOrNull {
  [CmdletBinding()]
  param($Value)
  if ($null -eq $Value) { return $null }
  $s = [string]$Value
  if ([string]::IsNullOrWhiteSpace($s)) { return $null }
  return $s
}

function Get-BoolDefault {
  [CmdletBinding()]
  param(
    $Value,
    [bool]$Default
  )
  if ($null -eq $Value) { return $Default }
  try { return [bool]$Value } catch { return $Default }
}

function Get-IntDefault {
  [CmdletBinding()]
  param(
    $Value,
    [int]$Default
  )
  if ($null -eq $Value) { return $Default }
  try { return [int]$Value } catch { return $Default }
}

function Get-ArrayStrings {
  [CmdletBinding()]
  param($Value)
  if ($null -eq $Value) { return @() }
  if ($Value -is [System.Collections.IEnumerable] -and -not ($Value -is [string])) {
    $out = @()
    foreach($x in $Value) {
      $s = Get-TextOrNull $x
      if ($s) { $out += $s }
    }
    return $out
  }
  $s2 = Get-TextOrNull $Value
  if (-not $s2) { return @() }
  return @($s2)
}

# Save-Json: using canonical Save-Json from lib/Serialization.psm1


function Convert-RegValue {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][ValidateSet('DWord','String')][string]$Type,
    [Parameter(Mandatory)]$Value
  )
  switch ($Type) {
    'DWord'  { return [int]$Value }
    'String' { return [string]$Value }
  }
}

function Get-ProofItem {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Product,
    [Parameter(Mandatory)][string]$Area,
    [Parameter(Mandatory)][string]$Policy,
    [Parameter(Mandatory)][string]$Target,
    [Parameter(Mandatory)][string]$Name,
    [Parameter(Mandatory)][ValidateSet('DWord','String','File')][string]$Type,
    [AllowNull()][Parameter(Mandatory)]$Expected,
    $Actual,
    [bool]$Compliant,
    [bool]$Changed,
    [string]$Message
  )
  [pscustomobject]@{
    Time      = (Get-Date).ToString("s")
    Product   = $Product
    Area      = $Area
    Policy    = $Policy
    Target    = $Target
    Name      = $Name
    Type      = $Type
    Expected  = $Expected
    Actual    = $Actual
    Compliant = [bool]$Compliant
    Changed   = [bool]$Changed
    Message   = $Message
  }
}

function Get-EdgeBaseKey {
  [CmdletBinding()]
  param([object]$EdgeCfg)
  $mode = Get-TextOrNull $EdgeCfg.PolicyHive
  if ($mode -and ($mode -ieq 'Recommended')) {
    return 'HKLM:\SOFTWARE\Policies\Microsoft\Edge\Recommended'
  }
  return 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
}

function Get-EdgePolicyDefinitions {
  [CmdletBinding()]
  param([Parameter(Mandatory)][object]$EdgeCfg)

  $trackingPrevention = @{ 'Basic' = 1; 'Balanced' = 2; 'Strict' = 3 }
  $trackingName = Get-TextOrNull $EdgeCfg.TrackingPrevention
  if (-not $trackingName) { $trackingName = 'Balanced' }
  $trackingValue = 2
  foreach ($name in $trackingPrevention.Keys) {
    if ($name -ieq $trackingName) { $trackingValue = $trackingPrevention[$name] }
  }

  $sslMinimum = Get-TextOrNull $EdgeCfg.SSLVersionMin
  if (-not $sslMinimum) { $sslMinimum = 'tls1.2' }

  @(
    [pscustomobject]@{ Area = 'Core'; Policy = 'SmartScreenEnabled'; Name = 'SmartScreenEnabled'; Type = 'DWord'; Value = [int](Get-BoolDefault $EdgeCfg.SmartScreen $true) }
    [pscustomobject]@{ Area = 'Core'; Policy = 'SmartScreenPuaEnabled'; Name = 'SmartScreenPuaEnabled'; Type = 'DWord'; Value = [int](Get-BoolDefault $EdgeCfg.PUA $true) }
    [pscustomobject]@{ Area = 'Core'; Policy = 'PasswordManagerEnabled'; Name = 'PasswordManagerEnabled'; Type = 'DWord'; Value = [int](Get-BoolDefault $EdgeCfg.PasswordManager $false) }
    [pscustomobject]@{ Area = 'Core'; Policy = 'AutofillAddressEnabled'; Name = 'AutofillAddressEnabled'; Type = 'DWord'; Value = [int](Get-BoolDefault $EdgeCfg.AutofillAddress $false) }
    [pscustomobject]@{ Area = 'Core'; Policy = 'AutofillCreditCardEnabled'; Name = 'AutofillCreditCardEnabled'; Type = 'DWord'; Value = [int](Get-BoolDefault $EdgeCfg.AutofillCreditCard $false) }
    [pscustomobject]@{ Area = 'Core'; Policy = 'SyncDisabled'; Name = 'SyncDisabled'; Type = 'DWord'; Value = [int](Get-BoolDefault $EdgeCfg.SyncDisabled $true) }
    [pscustomobject]@{ Area = 'Security'; Policy = 'SSLVersionMin'; Name = 'SSLVersionMin'; Type = 'String'; Value = $sslMinimum }
    [pscustomobject]@{ Area = 'Privacy'; Policy = 'TrackingPrevention'; Name = 'TrackingPrevention'; Type = 'DWord'; Value = $trackingValue }
  )
}

function Get-EdgeStartupUrlMap {
  [CmdletBinding()]
  param($StartupURLs)

  $urls = Get-ArrayStrings $StartupURLs
  $map = @{}
  $index = 1
  foreach ($url in $urls) {
    $map[[string]$index] = [string]$url
    $index++
  }
  return $map
}

function Get-EdgeStartupUrlValues {
  [CmdletBinding()]
  param([Parameter(Mandatory)][string]$Path)

  $values = @{}
  try {
    $properties = Get-ItemProperty -Path $Path -ErrorAction SilentlyContinue
    if ($properties) {
      foreach ($property in $properties.PSObject.Properties) {
        if ($property.Name -match '^\d+$') { $values[$property.Name] = [string]$property.Value }
      }
    }
  } catch {
    Write-Verbose ("Edge startup URL registry read failed for '{0}': {1}" -f $Path, $_.Exception.Message)
  }
  return $values
}

function Get-EdgeStartupUrlAuditProofItems {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][hashtable]$DesiredUrls,
    [Parameter(Mandatory)][hashtable]$CurrentUrls
  )

  $items = New-Object System.Collections.Generic.List[object]
  $keys = @($CurrentUrls.Keys + $DesiredUrls.Keys | Select-Object -Unique | Sort-Object { [int]$_ })
  foreach ($name in $keys) {
    $expected = $DesiredUrls[$name]
    $actual = $CurrentUrls[$name]
    $compliant = ($expected -eq $actual)
    $message = if ($compliant) { $null } else { 'Drift detected' }
    $items.Add((Get-ProofItem -Product 'Edge' -Area 'Startup' -Policy 'RestoreOnStartupURLs' -Target $Path -Name $name -Type String -Expected $expected -Actual $actual -Compliant $compliant -Changed $false -Message $message)) | Out-Null
  }
  return $items
}

# Removes only numbered startup URL values before rebuilding the desired list,
# avoiding deletion of unrelated Edge policy values in the same key.
function Clear-EdgeStartupUrlValues {
  [CmdletBinding()]
  param([Parameter(Mandatory)][string]$Path)

  try {
    $properties = Get-ItemProperty -Path $Path -ErrorAction SilentlyContinue
    if ($properties) {
      foreach ($property in $properties.PSObject.Properties) {
        if ($property.Name -match '^\d+$') {
          try {
            Remove-ItemProperty -Path $Path -Name $property.Name -ErrorAction Stop
          } catch {
            Write-Warning "Could not remove URL property $($property.Name): $($_.Exception.Message)"
          }
        }
      }
    }
  } catch {
    Write-Warning "Could not clear Edge startup URLs for remediation: $($_.Exception.Message)"
  }
}

# Applies one startup URL and returns proof for the attempted write so audit and
# remediation paths share the same evidence shape.
function Set-EdgeStartupUrlProof {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][string]$Name,
    [Parameter(Mandatory)][string]$Expected,
    [switch]$Skipped
  )

  $changed = $false
  $message = $null
  if ($Skipped) {
    $message = 'Set skipped by confirmation/WhatIf'
  } else {
    try {
      Ensure-RegistryKey -Path $Path
      New-ItemProperty -Path $Path -Name $Name -PropertyType String -Value $Expected -Force -ErrorAction Stop | Out-Null
      $changed = $true
    } catch {
      $message = "Write failed: $($_.Exception.Message)"
    }
  }

  $actual = Get-RegValue -Path $Path -Name $Name
  $compliant = ($actual -eq $Expected)
  if (-not $message) {
    if ($compliant -and $changed) { $message = 'Set applied' }
    elseif (-not $compliant) { $message = 'Set attempted but differs' }
  }
  return (Get-ProofItem -Product 'Edge' -Area 'Startup' -Policy 'RestoreOnStartupURLs' -Target $Path -Name $Name -Type String -Expected $Expected -Actual $actual -Compliant $compliant -Changed $changed -Message $message)
}

function Has-Prop {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]$Obj,
    [Parameter(Mandatory)][string]$Name
  )
  if ($null -eq $Obj) { return $false }
  try { return ($Obj.PSObject.Properties.Match($Name).Count -gt 0) } catch { return $false }
}

function Bool-Prop {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]$Obj,
    [Parameter(Mandatory)][string]$Name,
    [bool]$Default = $false
  )
  if (-not (Has-Prop $Obj $Name)) { return $Default }
  try { return [bool]$Obj.$Name } catch { return $Default }
}

function Ensure-ProofItemLike {
  [CmdletBinding()]
  param([Parameter(Mandatory)]$Obj)

  if ($null -eq $Obj) {
    return (Get-ProofItem -Product 'System' -Area 'Pipeline' -Policy 'NullItem' -Target 'N/A' -Name 'Null' -Type String -Expected 'ProofItem' -Actual $null -Compliant $false -Changed $false -Message 'Unexpected null item')
  }
  if ((Has-Prop $Obj 'Product') -and (Has-Prop $Obj 'Compliant') -and (Has-Prop $Obj 'Changed')) {
    return $Obj
  }
  return (Get-ProofItem -Product 'System' -Area 'Pipeline' -Policy 'NonProofObject' -Target 'N/A' -Name ($Obj.GetType().FullName) -Type String -Expected 'ProofItem' -Actual ($Obj | Out-String) -Compliant $false -Changed $false -Message 'Non-proof object leaked into pipeline')
}

function Get-ResultSummary {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Section,
    [Parameter(Mandatory)][object[]]$Items
  )

  $all = @($Items | ForEach-Object { Ensure-ProofItemLike $_ })
  $non = @($all | Where-Object { (Bool-Prop $_ 'Compliant' $true) -eq $false })
  $chg = @($all | Where-Object { (Bool-Prop $_ 'Changed' $false) -eq $true })

  [pscustomobject]@{
    Section      = $Section
    Ok           = ($non.Count -eq 0)
    Total        = $all.Count
    NonCompliant = $non.Count
    Changed      = $chg.Count
  }
}

# Resolves explicit, config-referenced, or embedded policy data in that order;
# invalid optional input falls back visibly instead of producing partial policy.
function Load-Catalog {
  [CmdletBinding()]
  param(
    [string]$CatalogPath,
    [string]$ConfigPath,
    [string]$DefaultCatalogJson
  )

  $notes      = New-Object System.Collections.Generic.List[string]
  $cat        = $null
  $loadedFrom = $null

  $default = $null
  try {
    $default = $DefaultCatalogJson | ConvertFrom-Json -ErrorAction Stop
  } catch {
    throw "Embedded default catalog JSON is invalid: $($_.Exception.Message)"
  }

  $p = Get-TextOrNull $CatalogPath
  if ($p) {
    if (Test-Path -LiteralPath $p) {
      try {
        $cat = Get-BoundedUtf8FileContent -Path $p -MaximumBytes 1048576 | ConvertFrom-Json -ErrorAction Stop
        $loadedFrom = 'CatalogPath'
      } catch {
        $notes.Add('CatalogPath JSON parse failed; using embedded defaults.') | Out-Null
      }
    } else {
      $notes.Add('CatalogPath not found; using embedded defaults.') | Out-Null
    }
  }

  if (-not $cat) {
    $cp = Get-TextOrNull $ConfigPath
    if ($cp) {
      if (Test-Path -LiteralPath $cp) {
        try {
          $cfg = Get-BoundedUtf8FileContent -Path $cp -MaximumBytes 1048576 | ConvertFrom-Json -ErrorAction Stop
          $cfgCat = $null

          if ($cfg -and $cfg.PSObject.Properties['OfficeBrowser']) {
            $ob = $cfg.OfficeBrowser
            if ($ob -and $ob.PSObject.Properties['CatalogPath']) {
              $cfgCat = Get-TextOrNull $ob.CatalogPath
            }
          }

          if ($cfgCat) {
            if (Test-Path -LiteralPath $cfgCat) {
              try {
                $cat = Get-BoundedUtf8FileContent -Path $cfgCat -MaximumBytes 1048576 | ConvertFrom-Json -ErrorAction Stop
                $loadedFrom = 'ConfigPath->OfficeBrowser.CatalogPath'
              } catch {
                $notes.Add('Config-referenced catalog JSON parse failed; using embedded defaults.') | Out-Null
              }
            } else {
              $notes.Add('Config-referenced catalog not found; using embedded defaults.') | Out-Null
            }
          } else {
            $notes.Add('ConfigPath present but OfficeBrowser.CatalogPath not set; using embedded defaults.') | Out-Null
          }
        } catch {
          $notes.Add('ConfigPath JSON parse failed; using embedded defaults.') | Out-Null
        }
      } else {
        $notes.Add('ConfigPath not found; using embedded defaults.') | Out-Null
      }
    }
  }

  if (-not $cat) {
    $cat        = $default
    $loadedFrom = 'EmbeddedDefaults'
  }

  if (-not $cat.Office)  { $cat | Add-Member -MemberType NoteProperty -Name Office  -Value $default.Office  -Force; $notes.Add('Office section missing; defaults applied.')  | Out-Null }
  if (-not $cat.Edge)    { $cat | Add-Member -MemberType NoteProperty -Name Edge    -Value $default.Edge    -Force; $notes.Add('Edge section missing; defaults applied.')    | Out-Null }
  if (-not $cat.Firefox) { $cat | Add-Member -MemberType NoteProperty -Name Firefox -Value $default.Firefox -Force; $notes.Add('Firefox section missing; defaults applied.') | Out-Null }
  if (-not $cat.Proof)   { $cat | Add-Member -MemberType NoteProperty -Name Proof   -Value $default.Proof   -Force; $notes.Add('Proof section missing; defaults applied.')   | Out-Null }

  [pscustomobject]@{
    Catalog     = $cat
    Defaults    = $default
    LoadedFrom  = $loadedFrom
    Notes       = @($notes)
  }
}

# -----------------------------
# Hardeners
# -----------------------------

# Evaluates and optionally remediates the supported Office policy set while
# emitting one proof item per decision for later aggregation.
function Ensure-Office {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][object]$OfficeCfg,
    [switch]$Remediate
  )

  $items = New-Object System.Collections.Generic.List[object]
  $ver   = Get-IntDefault $OfficeCfg.VersionMajor 16
  $base  = "HKCU:\SOFTWARE\Policies\Microsoft\Office\$ver.0"

  $apps = @('word','excel','powerpoint')
  foreach($app in $apps) {
    $appSecurity = Join-Path $base "$app\security"

    $macrosMode      = Get-TextOrNull $OfficeCfg.MacrosMode
    $wantVbaWarnings = 3
    if ($macrosMode -and ($macrosMode -ieq 'DisableAll')) { $wantVbaWarnings = 4 }

    $r = Set-RegValueProof -Product 'Office' -Area $app -Policy 'VBAWarnings' -Path $appSecurity -Name 'VBAWarnings' -Type DWord -Value $wantVbaWarnings -Remediate:$Remediate
    $items.Add($r) | Out-Null

    if (Get-BoolDefault $OfficeCfg.BlockMacrosFromInternet $true) {
      $r = Set-RegValueProof -Product 'Office' -Area $app -Policy 'BlockMacrosFromInternet' -Path $appSecurity -Name 'blockcontentexecutionfrominternet' -Type DWord -Value 1 -Remediate:$Remediate
      $items.Add($r) | Out-Null
    }

    if ($null -ne $OfficeCfg.AccessVBOM) {
      $want = if ([bool]$OfficeCfg.AccessVBOM) { 1 } else { 0 }
      $r = Set-RegValueProof -Product 'Office' -Area $app -Policy 'AccessVBOM' -Path $appSecurity -Name 'AccessVBOM' -Type DWord -Value $want -Remediate:$Remediate
      $items.Add($r) | Out-Null
    }

    $pv = $OfficeCfg.ProtectedView
    if ($pv) {
      $pvKey = Join-Path $appSecurity 'protectedview'

      if ($null -ne $pv.Internet) {
        $want = if ([bool]$pv.Internet) { 0 } else { 1 }
        $r = Set-RegValueProof -Product 'Office' -Area $app -Policy 'ProtectedViewInternet' -Path $pvKey -Name 'DisableInternetFilesInPV' -Type DWord -Value $want -Remediate:$Remediate
        $items.Add($r) | Out-Null
      }

      if ($null -ne $pv.UnsafeLocations) {
        $want = if ([bool]$pv.UnsafeLocations) { 0 } else { 1 }
        $r = Set-RegValueProof -Product 'Office' -Area $app -Policy 'ProtectedViewUnsafeLocations' -Path $pvKey -Name 'DisableUnsafeLocationsInPV' -Type DWord -Value $want -Remediate:$Remediate
        $items.Add($r) | Out-Null
      }

      if ($null -ne $pv.Outlook) {
        $want = if ([bool]$pv.Outlook) { 0 } else { 1 }
        $r = Set-RegValueProof -Product 'Office' -Area $app -Policy 'ProtectedViewOutlookAttachments' -Path $pvKey -Name 'DisableAttachmentsInPV' -Type DWord -Value $want -Remediate:$Remediate
        $items.Add($r) | Out-Null
      }
    }

    if (Get-BoolDefault $OfficeCfg.DisableTrustedLocations $true) {
      $tlKey = Join-Path $appSecurity 'trusted locations'
      $r = Set-RegValueProof -Product 'Office' -Area $app -Policy 'DisableTrustedLocations' -Path $tlKey -Name 'AllLocationsDisabled' -Type DWord -Value 1 -Remediate:$Remediate
      $items.Add($r) | Out-Null
    }
  }

  return $items
}
function Get-FirefoxDistDir {
  [CmdletBinding()]
  param([Parameter(Mandatory)][object]$FirefoxCfg)

  $explicit = Get-TextOrNull $FirefoxCfg.DistributionDir
  if ($explicit) { return $explicit }

  $paths = @(@(
      [Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles),
      [Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFilesX86)
    ) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | ForEach-Object { Join-Path $_ 'Mozilla Firefox\distribution' })
  foreach($p in $paths) {
    if (Test-Path -LiteralPath (Split-Path -Parent $p)) { return $p }
  }
  if ($paths.Count -gt 0) { return $paths[0] }
  throw 'A trusted Program Files directory could not be resolved.'
}

# Builds the complete policies.json object in memory first so remediation writes
# a coherent Firefox policy document rather than incrementally mutating JSON.
function Build-FirefoxPolicies {
  [CmdletBinding()]
  param([Parameter(Mandatory)][object]$FirefoxCfg)

  $tlsMin = Get-IntDefault $FirefoxCfg.TLSMin 3
  $tp     = Get-TextOrNull $FirefoxCfg.TrackingProtection
  if (-not $tp) { $tp = 'strict' }

  $pol = [ordered]@{
    policies = [ordered]@{
      DisableAppUpdate         = [bool](Get-BoolDefault $FirefoxCfg.DisableAppUpdate $true)
      DisableTelemetry         = [bool](Get-BoolDefault $FirefoxCfg.DisableTelemetry $true)
      DisableFirefoxStudies    = $true
      DisableShield            = $true
      BlockAboutConfig         = $true
      DNSOverHTTPS             = @{ Enabled = $false }
      SearchSuggestEnabled     = $false
      EnableTrackingProtection = $true
      TrackingProtection       = @{ Value = $tp }
      PasswordManagerEnabled   = [bool](Get-BoolDefault $FirefoxCfg.PasswordManagerEnabled $false)
      OfferToSaveLogins        = $false
      OfferToSaveLoginsDefault = $false
      TLSVersionMin            = $tlsMin
      Extensions               = @{}
    }
  }

  $allow = @()
  if ($FirefoxCfg.BlockAllAddonsExcept) { $allow = @($FirefoxCfg.BlockAllAddonsExcept) }

  $install = @()
  if ($FirefoxCfg.InstallAddons) { $install = @($FirefoxCfg.InstallAddons) }

  if ($allow.Count -gt 0) {
    $pol.policies.Extensions = @{
      Install           = @($install)
      ExtensionSettings = @{ "*" = @{ installation_mode = "blocked" } }
    }
    foreach($id in $allow) {
      $id2 = Get-TextOrNull $id
      if ($id2) { $pol.policies.Extensions.ExtensionSettings[$id2] = @{ installation_mode = "allowed" } }
    }
  } elseif ($install.Count -gt 0) {
    $pol.policies.Extensions = @{ Install = @($install) }
  }

  return $pol
}

# Compares the desired Firefox policy document with the installed file and
# writes only through the trusted distribution directory when remediation runs.
function Ensure-Firefox {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][object]$FirefoxCfg,
    [switch]$Remediate
  )

  $items = New-Object System.Collections.Generic.List[object]

  $enabled = Get-BoolDefault $FirefoxCfg.Enable $true
  if (-not $enabled) {
    $r = Get-ProofItem -Product 'Firefox' -Area 'EnterprisePolicies' -Policy 'Enable' -Target 'N/A' -Name 'Enable' -Type String -Expected 'true' -Actual 'false' -Compliant $true -Changed $false -Message 'Skipped (Enable=false)'
    $items.Add($r) | Out-Null
    return $items
  }

  $dist    = Get-FirefoxDistDir -FirefoxCfg $FirefoxCfg
  $polPath = Join-Path $dist 'policies.json'

  $obj     = Build-FirefoxPolicies -FirefoxCfg $FirefoxCfg
  $newJson = $obj | ConvertTo-Json -Depth 20

  $existingRaw = $null
  if (Test-Path -LiteralPath $polPath) {
    try { $existingRaw = Get-BoundedUtf8FileContent -Path $polPath -MaximumBytes 1048576 } catch { $existingRaw = $null }
  }

  $same = $false
  if ($existingRaw) {
    try {
      $existingObj = $existingRaw | ConvertFrom-Json -ErrorAction Stop
      $same = ( ($existingObj | ConvertTo-Json -Depth 20) -eq ($obj | ConvertTo-Json -Depth 20) )
    } catch {
      $same = ($existingRaw -eq $newJson)
    }
  }

  if (-not $same) {
    if ($Remediate) {
      $changed = $false
      $msg     = $null
      try {
        [void](Ensure-Directory -Path $dist)
        $utf8NoBOM = New-Object System.Text.UTF8Encoding($false)
        [System.IO.File]::WriteAllText($polPath, $newJson, $utf8NoBOM)
        $changed = $true
        $msg     = 'Wrote policies.json'
      } catch {
        $msg = "Write failed: $($_.Exception.Message)"
      }

      $r = Get-ProofItem -Product 'Firefox' -Area 'EnterprisePolicies' -Policy 'policies.json' -Target $polPath -Name 'policies.json' -Type File -Expected 'AsBuilt' -Actual $(if($changed){'Written'}else{$null}) -Compliant $changed -Changed $changed -Message $msg
      $items.Add($r) | Out-Null
    } else {
      $r = Get-ProofItem -Product 'Firefox' -Area 'EnterprisePolicies' -Policy 'policies.json' -Target $polPath -Name 'policies.json' -Type File -Expected 'AsBuilt' -Actual 'Different' -Compliant $false -Changed $false -Message 'Drift detected'
      $items.Add($r) | Out-Null
    }
  } else {
    $r = Get-ProofItem -Product 'Firefox' -Area 'EnterprisePolicies' -Policy 'policies.json' -Target $polPath -Name 'policies.json' -Type File -Expected 'AsBuilt' -Actual 'Same' -Compliant $true -Changed $false -Message $null
    $items.Add($r) | Out-Null
  }

  $r = Get-ProofItem -Product 'Firefox' -Area 'EnterprisePolicies' -Policy 'DistributionDir' -Target $dist -Name 'DistributionDir' -Type String -Expected 'Auto/Configured' -Actual $dist -Compliant $true -Changed $false -Message $null
  $items.Add($r) | Out-Null

  return $items
}

# -----------------------------
# Formatted console summary
# -----------------------------

function Write-ConsoleSummary {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][object[]]$AllItems,
    [Parameter(Mandatory)][object]$CatalogInfo,
    [Parameter(Mandatory)][string]$ProofPath,
    [Parameter(Mandatory)][bool]$IsAdmin,
    [Parameter(Mandatory)][bool]$Remediate,
    [Parameter(Mandatory)][bool]$Strict,
    [Parameter(Mandatory)][string[]]$Notes
  )

  $safe = @($AllItems | ForEach-Object { Ensure-ProofItemLike $_ })

  $officeItems  = @($safe | Where-Object { $_.Product -eq 'Office' })
  $edgeItems    = @($safe | Where-Object { $_.Product -eq 'Edge' })
  $firefoxItems = @($safe | Where-Object { $_.Product -eq 'Firefox' })

  $sum = @(
    Get-ResultSummary -Section 'Office'  -Items $officeItems
    Get-ResultSummary -Section 'Edge'    -Items $edgeItems
    Get-ResultSummary -Section 'Firefox' -Items $firefoxItems
  )

  Write-UiLine ""
  Write-UiLine "==================================================" -Style 'Header'
  Write-UiLine " Office / Browser Hardening Summary" -Style 'Accent'
  Write-UiLine "==================================================" -Style 'Header'
  Write-UiLine ("Catalog source : {0}" -f $CatalogInfo.LoadedFrom) -ForegroundColor Gray
  Write-UiLine ("Mode           : Remediate={0}  Strict={1}  IsAdmin={2}" -f $Remediate, $Strict, $IsAdmin) -ForegroundColor Gray
  Write-UiLine ""

  foreach($row in $sum) {
    $statusText  = if ($row.Ok) { "OK" } else { "DRIFT" }
    $statusColor = if ($row.Ok) { 'Green' } else { 'Red' }

    Write-UiLine ("[{0}]" -f $row.Section) -ForegroundColor White -NoNewline
    Write-UiLine (" {0,-5} " -f $statusText) -ForegroundColor $statusColor -NoNewline
    Write-UiLine ("Total={0}  NonCompliant={1}  Changed={2}" -f $row.Total, $row.NonCompliant, $row.Changed) -ForegroundColor Gray
  }

  $driftSample = @($safe | Where-Object { (Bool-Prop $_ 'Compliant' $true) -eq $false } | Select-Object -First 10)
  if ($driftSample.Count -gt 0) {
    Write-UiLine ""
    Write-UiLine "Drift sample (first 10 items)" -ForegroundColor Yellow
    Write-UiLine "---------------------------------------------" -Style 'Warning'
    foreach($d in $driftSample) {
      Write-UiLine ("- [{0}/{1}] {2} :: {3}\{4} (Expected={5} Actual={6})" -f $d.Product, $d.Area, $d.Policy, $d.Target, $d.Name, $d.Expected, $d.Actual) -ForegroundColor Yellow
    }
  }

  if ($Notes -and $Notes.Count -gt 0) {
    Write-UiLine ""
    Write-UiLine "Notes" -ForegroundColor White
    Write-UiLine "-----" -ForegroundColor White
    foreach($n in $Notes) { Write-UiLine ("- " + $n) -ForegroundColor DarkGray }
  }

  Write-UiLine ""
  Write-UiLine ("Proof JSON written to: {0}" -f $ProofPath) -ForegroundColor Cyan
  Write-UiLine ""

  $total        = $safe.Count
  $nonCompliant = @($safe | Where-Object { (Bool-Prop $_ 'Compliant' $true) -eq $false }).Count
  $changed      = @($safe | Where-Object { (Bool-Prop $_ 'Changed' $false) -eq $true }).Count

  $overallOk  = ($nonCompliant -eq 0)
  $finalColor = if ($overallOk -and -not $Strict) { 'Green' } else { 'Red' }
  $finalText  = if ($overallOk -and -not $Strict) { 'HARDENING OK' } else { 'DRIFT DETECTED' }

  Write-UiLine "==================================================" -Style 'Header'
  Write-UiLine (" Final result : {0}" -f $finalText) -ForegroundColor $finalColor
  Write-UiLine (" Items        : Total={0}  NonCompliant={1}  Changed={2}" -f $total, $nonCompliant, $changed) -ForegroundColor Gray
  Write-UiLine "==================================================" -Style 'Header'

  Write-Information ("Summary: FinalResult={0}; Total={1}; NonCompliant={2}; Changed={3}" -f $finalText, $total, $nonCompliant, $changed)
}
