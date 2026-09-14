#requires -version 5.1
<#
.SYNOPSIS
  Provides private Office and browser hardening phases.
.DESCRIPTION
  Preserves capability-local policy, confirmation, error, and proof semantics for the public entry point.
#>

function Get-FirefoxDistDir {
  [CmdletBinding()]
  param([Parameter(Mandatory)][object]$FirefoxCfg)

  $explicit = Get-TextOrNull $FirefoxCfg.DistributionDir
  if ($explicit) {
    return $explicit
  }

  $paths = @(@(
      [Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles),
      [Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFilesX86)
    ) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | ForEach-Object { Join-Path $_ 'Mozilla Firefox\distribution' })
  foreach ($p in $paths) {
    if (Test-Path -LiteralPath (Split-Path -Parent $p)) {
      return $p
    }
  }
  if ($paths.Count -gt 0) {
    return $paths[0]
  }
  throw 'A trusted Program Files directory could not be resolved.'
}

# Builds the complete policies.json object in memory first so remediation writes
# a coherent Firefox policy document rather than incrementally mutating JSON.

function Build-FirefoxPolicies {
  [CmdletBinding()]
  param([Parameter(Mandatory)][object]$FirefoxCfg)

  $tlsMin = Get-IntDefault $FirefoxCfg.TLSMin 3
  $tp = Get-TextOrNull $FirefoxCfg.TrackingProtection
  if (-not $tp) {
    $tp = 'strict'
  }

  $pol = [ordered]@{
    policies = [ordered]@{
      DisableAppUpdate = [bool](Get-BoolDefault $FirefoxCfg.DisableAppUpdate $true)
      DisableTelemetry = [bool](Get-BoolDefault $FirefoxCfg.DisableTelemetry $true)
      DisableFirefoxStudies = $true
      DisableShield = $true
      BlockAboutConfig = $true
      DNSOverHTTPS = @{ Enabled = $false }
      SearchSuggestEnabled = $false
      EnableTrackingProtection = $true
      TrackingProtection = @{ Value = $tp }
      PasswordManagerEnabled = [bool](Get-BoolDefault $FirefoxCfg.PasswordManagerEnabled $false)
      OfferToSaveLogins = $false
      OfferToSaveLoginsDefault = $false
      TLSVersionMin = $tlsMin
      Extensions = @{}
    }
  }

  Set-FirefoxAddonPolicy -Policy $pol -FirefoxCfg $FirefoxCfg

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
    $r = Get-ProofItem -Product 'Firefox' -Area 'EnterprisePolicies' -Policy 'Enable' -Target 'N/A' -Name 'Enable' -Type String -Expected 'true' -Observation @{ Actual = 'false'
      Compliant = $true
      Changed = $false
      Message = 'Skipped (Enable=false)'
    }
    $items.Add($r) | Out-Null
    return $items
  }

  $dist = Get-FirefoxDistDir -FirefoxCfg $FirefoxCfg
  $polPath = Join-Path $dist 'policies.json'

  $obj = Build-FirefoxPolicies -FirefoxCfg $FirefoxCfg
  $newJson = $obj | ConvertTo-Json -Depth 20

  $same = Test-FirefoxPolicyEquivalent -Path $polPath -Desired $obj -Json $newJson

  if (-not $same) {
    if ($Remediate) {
      $r = Write-FirefoxPolicyProof -Directory $dist -Path $polPath -Json $newJson
      $items.Add($r) | Out-Null
    }
    else {
      $r = Get-ProofItem -Product 'Firefox' -Area 'EnterprisePolicies' -Policy 'policies.json' -Target $polPath -Name 'policies.json' -Type File -Expected 'AsBuilt' -Observation @{ Actual = 'Different'
        Compliant = $false
        Changed = $false
        Message = 'Drift detected'
      }
      $items.Add($r) | Out-Null
    }
  }
  else {
    $r = Get-ProofItem -Product 'Firefox' -Area 'EnterprisePolicies' -Policy 'policies.json' -Target $polPath -Name 'policies.json' -Type File -Expected 'AsBuilt' -Observation @{ Actual = 'Same'
      Compliant = $true
      Changed = $false
      Message = $null
    }
    $items.Add($r) | Out-Null
  }

  Add-FirefoxDistributionProof -Items $items -Directory $dist

  return $items
}

# -----------------------------
# Formatted console summary
# -----------------------------

function Set-FirefoxAddonPolicy {
  param($Policy, $FirefoxCfg)
  $allow = @()
  if ($FirefoxCfg.BlockAllAddonsExcept) {
    $allow = @($FirefoxCfg.BlockAllAddonsExcept)
  }

  $install = @()
  if ($FirefoxCfg.InstallAddons) {
    $install = @($FirefoxCfg.InstallAddons)
  }

  if ($allow.Count -gt 0) {
    $Policy.policies.Extensions = @{
      Install = @($install)
      ExtensionSettings = @{ "*" = @{ installation_mode = "blocked" } }
    }
    foreach ($id in $allow) {
      $id2 = Get-TextOrNull $id
      if ($id2) {
        $Policy.policies.Extensions.ExtensionSettings[$id2] = @{ installation_mode = "allowed" }
      }
    }
  }
  elseif ($install.Count -gt 0) {
    $Policy.policies.Extensions = @{ Install = @($install) }
  }

}
function Test-FirefoxPolicyEquivalent {
  param([string]$Path, $Desired, [string]$Json)
  $existingRaw = $null
  if (Test-Path -LiteralPath $Path) {
    try {
      $existingRaw = Get-BoundedUtf8FileContent -Path $Path -MaximumBytes 1048576
    }
    catch {
      $existingRaw = $null
    }
  }

  $same = $false
  if ($existingRaw) {
    try {
      $existingObj = $existingRaw | ConvertFrom-Json -ErrorAction Stop
      $same = ( ($existingObj | ConvertTo-Json -Depth 20) -eq ($Desired | ConvertTo-Json -Depth 20) )
    }
    catch {
      $same = ($existingRaw -eq $Json)
    }
  }

  return $same
}

function Write-FirefoxPolicyProof {
  param([string]$Directory, [string]$Path, [string]$Json)
  $changed = $false
  $msg = $null
  try {
    [void](Ensure-Directory -Path $Directory)
    $utf8NoBOM = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($Path, $Json, $utf8NoBOM)
    $changed = $true
    $msg = 'Wrote policies.json'
  }
  catch {
    $msg = "Write failed: $($_.Exception.Message)"
  }

  $r = Get-ProofItem -Product 'Firefox' -Area 'EnterprisePolicies' -Policy 'policies.json' -Target $Path -Name 'policies.json' -Type File -Expected 'AsBuilt' -Observation @{ Actual = $(if ($changed) {
        'Written'
      }
      else {
        $null
      })
    Compliant = $changed
    Changed = $changed
    Message = $msg
  }

  return $r
}

function Add-FirefoxDistributionProof {
  param($Items, [string]$Directory)
  $r = Get-ProofItem -Product 'Firefox' -Area 'EnterprisePolicies' -Policy 'DistributionDir' -Target $Directory -Name 'DistributionDir' -Type String -Expected 'Auto/Configured' -Observation @{ Actual = $Directory
    Compliant = $true
    Changed = $false
    Message = $null
  }
  $items.Add($r) | Out-Null

}
