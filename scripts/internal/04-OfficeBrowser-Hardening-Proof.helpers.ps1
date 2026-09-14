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
  if ($null -eq $Value) {
    return $null
  }
  $s = [string]$Value
  if ([string]::IsNullOrWhiteSpace($s)) {
    return $null
  }
  return $s
}

function Get-BoolDefault {
  [CmdletBinding()]
  param(
    $Value,
    [bool]$Default
  )
  if ($null -eq $Value) {
    return $Default
  }
  try {
    return [bool]$Value
  }
  catch {
    return $Default
  }
}

function Get-IntDefault {
  [CmdletBinding()]
  param(
    $Value,
    [int]$Default
  )
  if ($null -eq $Value) {
    return $Default
  }
  try {
    return [int]$Value
  }
  catch {
    return $Default
  }
}

function Get-ArrayStrings {
  [CmdletBinding()]
  param($Value)
  if ($null -eq $Value) {
    return @()
  }
  if ($Value -is [System.Collections.IEnumerable] -and -not ($Value -is [string])) {
    $out = @()
    foreach ($x in $Value) {
      $s = Get-TextOrNull $x
      if ($s) {
        $out += $s
      }
    }
    return $out
  }
  $s2 = Get-TextOrNull $Value
  if (-not $s2) {
    return @()
  }
  return @($s2)
}

# Save-Json: using canonical Save-Json from lib/Serialization.psm1


function Convert-RegValue {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][ValidateSet('DWord', 'String')][string]$Type,
    [Parameter(Mandatory)]$Value
  )
  switch ($Type) {
    'DWord' {
      return [int]$Value
    }
    'String' {
      return [string]$Value
    }
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
    [Parameter(Mandatory)][ValidateSet('DWord', 'String', 'File')][string]$Type,
    [AllowNull()][Parameter(Mandatory)]$Expected,
    [hashtable]$Observation = @{}
  )
  [pscustomobject]@{
    Time = (Get-Date).ToString("s")
    Product = $Product
    Area = $Area
    Policy = $Policy
    Target = $Target
    Name = $Name
    Type = $Type
    Expected = $Expected
    Actual = $Observation.Actual
    Compliant = [bool]$Observation.Compliant
    Changed = [bool]$Observation.Changed
    Message = [string]$Observation.Message
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
        if ($property.Name -match '^\d+$') {
          $values[$property.Name] = [string]$property.Value
        }
      }
    }
  }
  catch {
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
    $message = if ($compliant) {
      $null
    }
    else {
      'Drift detected'
    }
    $items.Add((Get-ProofItem -Product 'Edge' -Area 'Startup' -Policy 'RestoreOnStartupURLs' -Target $Path -Name $name -Type String -Expected $expected -Observation @{ Actual = $actual
          Compliant = $compliant
          Changed = $false
          Message = $message
        })) | Out-Null
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
          }
          catch {
            Write-Warning "Could not remove URL property $($property.Name): $($_.Exception.Message)"
          }
        }
      }
    }
  }
  catch {
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
  }
  else {
    try {
      Ensure-RegistryKey -Path $Path
      New-ItemProperty -Path $Path -Name $Name -PropertyType String -Value $Expected -Force -ErrorAction Stop | Out-Null
      $changed = $true
    }
    catch {
      $message = "Write failed: $($_.Exception.Message)"
    }
  }

  $actual = Get-RegValue -Path $Path -Name $Name
  $compliant = ($actual -eq $Expected)
  if (-not $message) {
    if ($compliant -and $changed) {
      $message = 'Set applied'
    }
    elseif (-not $compliant) {
      $message = 'Set attempted but differs'
    }
  }
  return (Get-ProofItem -Product 'Edge' -Area 'Startup' -Policy 'RestoreOnStartupURLs' -Target $Path -Name $Name -Type String -Expected $Expected -Observation @{ Actual = $actual
      Compliant = $compliant
      Changed = $changed
      Message = $message
    })
}

function Has-Prop {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]$Obj,
    [Parameter(Mandatory)][string]$Name
  )
  if ($null -eq $Obj) {
    return $false
  }
  try {
    return ($Obj.PSObject.Properties.Match($Name).Count -gt 0)
  }
  catch {
    return $false
  }
}

function Bool-Prop {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]$Obj,
    [Parameter(Mandatory)][string]$Name,
    [bool]$Default = $false
  )
  if (-not (Has-Prop $Obj $Name)) {
    return $Default
  }
  try {
    return [bool]$Obj.$Name
  }
  catch {
    return $Default
  }
}

function Ensure-ProofItemLike {
  [CmdletBinding()]
  param([Parameter(Mandatory)]$Obj)

  if ($null -eq $Obj) {
    return (Get-ProofItem -Product 'System' -Area 'Pipeline' -Policy 'NullItem' -Target 'N/A' -Name 'Null' -Type String -Expected 'ProofItem' -Observation @{ Actual = $null
        Compliant = $false
        Changed = $false
        Message = 'Unexpected null item'
      })
  }
  if ((Has-Prop $Obj 'Product') -and (Has-Prop $Obj 'Compliant') -and (Has-Prop $Obj 'Changed')) {
    return $Obj
  }
  return (Get-ProofItem -Product 'System' -Area 'Pipeline' -Policy 'NonProofObject' -Target 'N/A' -Name ($Obj.GetType().FullName) -Type String -Expected 'ProofItem' -Observation @{ Actual = ($Obj | Out-String)
      Compliant = $false
      Changed = $false
      Message = 'Non-proof object leaked into pipeline'
    })
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
    Section = $Section
    Ok = ($non.Count -eq 0)
    Total = $all.Count
    NonCompliant = $non.Count
    Changed = $chg.Count
  }
}

# Resolves explicit, config-referenced, or embedded policy data in that order;
# invalid optional input falls back visibly instead of producing partial policy.
function Set-RegValueProof {
  [CmdletBinding(SupportsShouldProcess = $true)]
  param(
    [Parameter(Mandatory)][string]$Product,
    [Parameter(Mandatory)][string]$Area,
    [Parameter(Mandatory)][string]$Policy,
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][string]$Name,
    [Parameter(Mandatory)][ValidateSet('DWord', 'String')][string]$Type,
    [Parameter(Mandatory)]$Value,
    [switch]$Remediate
  )

  # Only ensure key exists when remediating (§2/§17)
  $expected = Convert-RegValue -Type $Type -Value $Value
  $cur = Get-RegValue -Path $Path -Name $Name

  $compliant = ($cur -eq $expected)
  $changed = $false
  $msg = $null

  if (-not $compliant) {
    if ($Remediate) {
      if (-not $PSCmdlet.ShouldProcess("$Path\$Name", "Set $Type value")) {
        return (Get-ProofItem -Product $Product -Area $Area -Policy $Policy -Target $Path -Name $Name -Type $Type -Expected $expected -Observation @{ Actual = $cur
            Compliant = $false
            Changed = $false
            Message = 'Set skipped by confirmation/WhatIf'
          })
      }

      $observation = Invoke-OfficeBrowserRegistryWrite -Path $Path -Name $Name -Type $Type -Expected $expected
      $cur = $observation.Actual
      $compliant = $observation.Compliant
      $changed = $observation.Changed
      $msg = $observation.Message
    }
    else {
      $compliant = $false
      $msg = 'Drift detected'
    }
  }

  Get-ProofItem -Product $Product -Area $Area -Policy $Policy -Target $Path -Name $Name -Type $Type -Expected $expected -Observation @{ Actual = $cur
    Compliant = $compliant
    Changed = $changed
    Message = $msg
  }
}


function Ensure-Edge {
  [CmdletBinding(SupportsShouldProcess = $true)]
  param(
    [Parameter(Mandatory)][object]$EdgeCfg,
    [switch]$Remediate
  )

  $items = New-Object System.Collections.Generic.List[object]
  $base = Get-EdgeBaseKey -EdgeCfg $EdgeCfg

  foreach ($policy in Get-EdgePolicyDefinitions -EdgeCfg $EdgeCfg) {
    $items.Add((Set-RegValueProof -Product 'Edge' -Area $policy.Area -Policy $policy.Policy -Path $base -Name $policy.Name -Type $policy.Type -Value $policy.Value -Remediate:$Remediate)) | Out-Null
  }

  $hp = Get-TextOrNull $EdgeCfg.HomePageURL
  if ($hp) {
    $r = Set-RegValueProof -Product 'Edge' -Area 'UX' -Policy 'HomepageLocation' -Path $base -Name 'HomepageLocation' -Type String -Value $hp -Remediate:$Remediate
    $items.Add($r) | Out-Null

    $r = Set-RegValueProof -Product 'Edge' -Area 'UX' -Policy 'HomepageIsNewTabPage' -Path $base -Name 'HomepageIsNewTabPage' -Type DWord -Value 0 -Remediate:$Remediate
    $items.Add($r) | Out-Null
  }

  if ($null -ne $EdgeCfg.RestoreOnStartup) {
    $r = Set-RegValueProof -Product 'Edge' -Area 'Startup' -Policy 'RestoreOnStartup' -Path $base -Name 'RestoreOnStartup' -Type DWord -Value ([int]$EdgeCfg.RestoreOnStartup) -Remediate:$Remediate
    $items.Add($r) | Out-Null
  }

  Add-EdgeStartupProof -Items $items -Base $base -EdgeCfg $EdgeCfg -Remediate:$Remediate -DecisionContext $PSCmdlet

  return $items
}



function Add-EdgeStartupProof {
  param($Items, [string]$Base, $EdgeCfg, [switch]$Remediate, $DecisionContext)
  $urlsKey = Join-Path $base 'RestoreOnStartupURLs'
  $desiredUrls = Get-EdgeStartupUrlMap -StartupURLs $EdgeCfg.StartupURLs

  if ($Remediate) {
    if ($DecisionContext.ShouldProcess($urlsKey, 'Reset Edge startup URLs')) {
      Ensure-RegistryKey -Path $urlsKey
      Clear-EdgeStartupUrlValues -Path $urlsKey
    }

    foreach ($name in @($desiredUrls.Keys | Sort-Object { [int]$_ })) {
      $expected = $desiredUrls[$name]
      if ($DecisionContext.ShouldProcess("$urlsKey\$name", 'Set Edge startup URL')) {
        $items.Add((Set-EdgeStartupUrlProof -Path $urlsKey -Name $name -Expected $expected)) | Out-Null
      }
      else {
        $items.Add((Set-EdgeStartupUrlProof -Path $urlsKey -Name $name -Expected $expected -Skipped)) | Out-Null
      }
    }
  }
  else {
    $currentUrls = Get-EdgeStartupUrlValues -Path $urlsKey
    foreach ($item in Get-EdgeStartupUrlAuditProofItems -Path $urlsKey -DesiredUrls $desiredUrls -CurrentUrls $currentUrls) {
      $items.Add($item) | Out-Null
    }
  }

}

. (Join-Path $PSScriptRoot '04-OfficeBrowser-Hardening-Proof.catalog.ps1')

. (Join-Path $PSScriptRoot '04-OfficeBrowser-Hardening-Proof.office.ps1')

. (Join-Path $PSScriptRoot '04-OfficeBrowser-Hardening-Proof.firefox.ps1')

. (Join-Path $PSScriptRoot '04-OfficeBrowser-Hardening-Proof.presentation.ps1')

. (Join-Path $PSScriptRoot '04-OfficeBrowser-Hardening-Proof.runtime.ps1')

function Invoke-OfficeBrowserRegistryWrite {
  param([string]$Path, [string]$Name, [string]$Type, $Expected)
  $changed = $false
  $msg = $null
  try {
    Ensure-RegistryKey -Path $Path
    New-ItemProperty -Path $Path -Name $Name -PropertyType $Type -Value $expected -Force -ErrorAction Stop | Out-Null
    $changed = $true
  }
  catch {
    $msg = "Write failed: $($_.Exception.Message)"
  }

  $cur = Get-RegValue -Path $Path -Name $Name
  $compliant = ($cur -eq $expected)

  if (-not $msg) {
    $msg = $(if ($compliant) {
        'Set applied'
      }
      else {
        'Set attempted but differs'
      })
  }
  return @{ Actual = $cur
    Compliant = $compliant
    Changed = $changed
    Message = $msg
  }
}

. (Join-Path $PSScriptRoot '04-OfficeBrowser-Hardening-Proof.edge.ps1')
