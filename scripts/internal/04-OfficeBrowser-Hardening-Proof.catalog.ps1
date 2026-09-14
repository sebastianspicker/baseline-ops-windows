#requires -version 5.1
<#
.SYNOPSIS
  Provides private Office and browser hardening phases.
.DESCRIPTION
  Preserves capability-local policy, confirmation, error, and proof semantics for the public entry point.
#>

function Get-DefaultOfficeBrowserCatalog {
  return @"
{
  "Office": {
    "VersionMajor": 16,
    "MacrosMode": "SignedOnly",
    "BlockMacrosFromInternet": true,
    "DisableTrustedLocations": true,
    "ProtectedView": { "Internet": true, "UnsafeLocations": true, "Outlook": true },
    "AccessVBOM": false
  },
  "Edge": {
    "PolicyHive": "Mandatory",
    "SmartScreen": true,
    "PUA": true,
    "TrackingPrevention": "Balanced",
    "PasswordManager": false,
    "AutofillAddress": false,
    "AutofillCreditCard": false,
    "SSLVersionMin": "tls1.2",
    "SyncDisabled": true,
    "HomePageURL": null,
    "RestoreOnStartup": 4,
    "StartupURLs": []
  },
  "Firefox": {
    "Enable": true,
    "DistributionDir": null,
    "DisableAppUpdate": true,
    "DisableTelemetry": true,
    "PasswordManagerEnabled": false,
    "TrackingProtection": "strict",
    "TLSMin": 3,
    "BlockAllAddonsExcept": [],
    "InstallAddons": []
  },
  "Proof": {
    "OutFile": null
  }
}
"@
}

function Load-Catalog {
  [CmdletBinding()]
  param(
    [string]$CatalogPath,
    [string]$ConfigPath,
    [string]$DefaultCatalogJson
  )

  $State = @{ CatalogPath = $CatalogPath
    ConfigPath = $ConfigPath
  }
  $State.Notes = New-Object System.Collections.Generic.List[string]
  $State.Catalog = $null
  $State.LoadedFrom = $null

  $default = $null
  try {
    $default = $DefaultCatalogJson | ConvertFrom-Json -ErrorAction Stop
  }
  catch {
    throw "Embedded default catalog JSON is invalid: $($_.Exception.Message)"
  }

  Read-OfficeBrowserExplicitCatalog -State $State
  Read-OfficeBrowserConfiguredCatalog -State $State
  if (-not $State.Catalog) {
    $State.Catalog = $default
    $State.LoadedFrom = 'EmbeddedDefaults'
  }

  Complete-OfficeBrowserCatalogSections -State $State -Default $default

  [pscustomobject]@{
    Catalog = $State.Catalog
    Defaults = $default
    LoadedFrom = $State.LoadedFrom
    Notes = @($State.Notes)
  }
}

# -----------------------------
# Hardeners
# -----------------------------

# Evaluates and optionally remediates the supported Office policy set while
# emitting one proof item per decision for later aggregation.

function Read-OfficeBrowserExplicitCatalog {
  param($State)
  $p = Get-TextOrNull $State.CatalogPath
  if ($p) {
    if (Test-Path -LiteralPath $p) {
      try {
        $State.Catalog = Get-BoundedUtf8FileContent -Path $p -MaximumBytes 1048576 | ConvertFrom-Json -ErrorAction Stop
        $State.LoadedFrom = 'CatalogPath'
      }
      catch {
        $State.Notes.Add('CatalogPath JSON parse failed; using embedded defaults.') | Out-Null
      }
    }
    else {
      $State.Notes.Add('CatalogPath not found; using embedded defaults.') | Out-Null
    }
  }

}

function Read-OfficeBrowserConfiguredCatalog {
  param($State)
  if ($State.Catalog) {
    return
  }
  $cp = Get-TextOrNull $State.ConfigPath
  if (-not $cp) {
    return
  }
  if (-not (Test-Path -LiteralPath $cp)) {
    $State.Notes.Add('ConfigPath not found; using embedded defaults.') | Out-Null
    return
  }
  try {
    $cfg = Get-BoundedUtf8FileContent -Path $cp -MaximumBytes 1048576 | ConvertFrom-Json -ErrorAction Stop
    $cfgCat = Get-OfficeBrowserReferencedCatalogPath -Config $cfg
    if ($cfgCat) {
      Read-OfficeBrowserReferencedCatalog -State $State -Path $cfgCat
    }
    else {
      $State.Notes.Add('ConfigPath present but OfficeBrowser.CatalogPath not set; using embedded defaults.') | Out-Null
    }
  }
  catch {
    $State.Notes.Add('ConfigPath JSON parse failed; using embedded defaults.') | Out-Null
  }
}

function Get-OfficeBrowserReferencedCatalogPath {
  param($Config)
  $cfg = $Config
  $cfgCat = $null

  if ($cfg -and $cfg.PSObject.Properties['OfficeBrowser']) {
    $ob = $cfg.OfficeBrowser
    if ($ob -and $ob.PSObject.Properties['CatalogPath']) {
      $cfgCat = Get-TextOrNull $ob.CatalogPath
    }
  }

  return $cfgCat
}

function Read-OfficeBrowserReferencedCatalog {
  param($State, [string]$Path)
  if (Test-Path -LiteralPath $Path) {
    try {
      $State.Catalog = Get-BoundedUtf8FileContent -Path $Path -MaximumBytes 1048576 | ConvertFrom-Json -ErrorAction Stop
      $State.LoadedFrom = 'ConfigPath->OfficeBrowser.CatalogPath'
    }
    catch {
      $State.Notes.Add('Config-referenced catalog JSON parse failed; using embedded defaults.') | Out-Null
    }
  }
  else {
    $State.Notes.Add('Config-referenced catalog not found; using embedded defaults.') | Out-Null
  }
}

function Complete-OfficeBrowserCatalogSections {
  param($State, $Default)
  if (-not $State.Catalog.Office) {
    $State.Catalog | Add-Member -MemberType NoteProperty -Name Office  -Value $default.Office  -Force
    $State.Notes.Add('Office section missing; defaults applied.')  | Out-Null
  }
  if (-not $State.Catalog.Edge) {
    $State.Catalog | Add-Member -MemberType NoteProperty -Name Edge    -Value $default.Edge    -Force
    $State.Notes.Add('Edge section missing; defaults applied.')    | Out-Null
  }
  if (-not $State.Catalog.Firefox) {
    $State.Catalog | Add-Member -MemberType NoteProperty -Name Firefox -Value $default.Firefox -Force
    $State.Notes.Add('Firefox section missing; defaults applied.') | Out-Null
  }
  if (-not $State.Catalog.Proof) {
    $State.Catalog | Add-Member -MemberType NoteProperty -Name Proof   -Value $default.Proof   -Force
    $State.Notes.Add('Proof section missing; defaults applied.')   | Out-Null
  }

}
