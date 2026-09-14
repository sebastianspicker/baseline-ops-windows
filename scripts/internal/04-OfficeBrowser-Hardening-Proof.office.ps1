#requires -version 5.1
<#
.SYNOPSIS
  Provides private Office and browser hardening phases.
.DESCRIPTION
  Preserves capability-local policy, confirmation, error, and proof semantics for the public entry point.
#>

function Ensure-Office {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][object]$OfficeCfg,
    [switch]$Remediate
  )

  $items = New-Object System.Collections.Generic.List[object]
  $ver = Get-IntDefault $OfficeCfg.VersionMajor 16
  $base = "HKCU:\SOFTWARE\Policies\Microsoft\Office\$ver.0"

  $apps = @('word', 'excel', 'powerpoint')
  foreach ($app in $apps) {
    $appSecurity = Join-Path $base "$app\security"

    Add-OfficeMacroProof -Items $items -OfficeCfg $OfficeCfg -App $app -SecurityPath $appSecurity -Remediate:$Remediate

    Add-OfficeProtectedViewProof -Items $items -ProtectedView $OfficeCfg.ProtectedView -App $app -SecurityPath $appSecurity -Remediate:$Remediate

    if (Get-BoolDefault $OfficeCfg.DisableTrustedLocations $true) {
      $tlKey = Join-Path $appSecurity 'trusted locations'
      $r = Set-RegValueProof -Product 'Office' -Area $app -Policy 'DisableTrustedLocations' -Path $tlKey -Name 'AllLocationsDisabled' -Type DWord -Value 1 -Remediate:$Remediate
      $items.Add($r) | Out-Null
    }
  }

  return $items
}

function Add-OfficeProtectedViewProof {
  param($Items, $ProtectedView, [string]$App, [string]$SecurityPath, [switch]$Remediate)
  $appSecurity = $SecurityPath
  $pv = $ProtectedView
  if ($pv) {
    $pvKey = Join-Path $appSecurity 'protectedview'

    if ($null -ne $pv.Internet) {
      $want = [int](-not [bool]$pv.Internet)
      $r = Set-RegValueProof -Product 'Office' -Area $app -Policy 'ProtectedViewInternet' -Path $pvKey -Name 'DisableInternetFilesInPV' -Type DWord -Value $want -Remediate:$Remediate
      $items.Add($r) | Out-Null
    }

    if ($null -ne $pv.UnsafeLocations) {
      $want = [int](-not [bool]$pv.UnsafeLocations)
      $r = Set-RegValueProof -Product 'Office' -Area $app -Policy 'ProtectedViewUnsafeLocations' -Path $pvKey -Name 'DisableUnsafeLocationsInPV' -Type DWord -Value $want -Remediate:$Remediate
      $items.Add($r) | Out-Null
    }

    if ($null -ne $pv.Outlook) {
      $want = [int](-not [bool]$pv.Outlook)
      $r = Set-RegValueProof -Product 'Office' -Area $app -Policy 'ProtectedViewOutlookAttachments' -Path $pvKey -Name 'DisableAttachmentsInPV' -Type DWord -Value $want -Remediate:$Remediate
      $items.Add($r) | Out-Null
    }
  }

}

function Add-OfficeMacroProof {
  param($Items, $OfficeCfg, [string]$App, [string]$SecurityPath, [switch]$Remediate)
  $appSecurity = $SecurityPath
  $macrosMode = Get-TextOrNull $OfficeCfg.MacrosMode
  $wantVbaWarnings = 3
  if ($macrosMode -and ($macrosMode -ieq 'DisableAll')) {
    $wantVbaWarnings = 4
  }

  $r = Set-RegValueProof -Product 'Office' -Area $app -Policy 'VBAWarnings' -Path $appSecurity -Name 'VBAWarnings' -Type DWord -Value $wantVbaWarnings -Remediate:$Remediate
  $items.Add($r) | Out-Null

  if (Get-BoolDefault $OfficeCfg.BlockMacrosFromInternet $true) {
    $r = Set-RegValueProof -Product 'Office' -Area $app -Policy 'BlockMacrosFromInternet' -Path $appSecurity -Name 'blockcontentexecutionfrominternet' -Type DWord -Value 1 -Remediate:$Remediate
    $items.Add($r) | Out-Null
  }

  if ($null -ne $OfficeCfg.AccessVBOM) {
    $want = if ([bool]$OfficeCfg.AccessVBOM) {
      1
    }
    else {
      0
    }
    $r = Set-RegValueProof -Product 'Office' -Area $app -Policy 'AccessVBOM' -Path $appSecurity -Name 'AccessVBOM' -Type DWord -Value $want -Remediate:$Remediate
    $items.Add($r) | Out-Null
  }

}
