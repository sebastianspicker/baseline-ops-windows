#requires -version 5.1
<#
.SYNOPSIS
  Supports local Administrators policy and member observation.
.DESCRIPTION
  Preserves bounded allow-list loading, identity resolution, provider fallbacks, and result fields.
#>

function Try-ReadJsonFile {
  [CmdletBinding()]
  param([Parameter(Mandatory)] [string]$Path)

  try {
    if ($Path -and (Test-Path -LiteralPath $Path)) {
      return (Get-BoundedUtf8FileContent -Path $Path -MaximumBytes 1048576 | ConvertFrom-Json)
    }
  }
  catch {
    Write-Verbose ("JSON read failed for '{0}': {1}" -f $Path, $_.Exception.Message)
  }

  return $null
}

function Get-Config {
  [CmdletBinding()]
  param([string]$Path)

  $cfg = $null
  if ($Path) {
    $cfg = Try-ReadJsonFile -Path $Path
  }
  if ($cfg) {
    return $cfg
  }
  return $null
}

function Get-GuardrailAllowedEntries {
  param($Json)
  if ($Json -and $Json.LocalAdmins -and $Json.LocalAdmins.Allowed) {
    return $Json.LocalAdmins.Allowed
  }
  elseif ($Json -and $Json.Allowed) {
    return $Json.Allowed
  }
}

function Read-AllowListFromJson {
  [CmdletBinding()]
  param([object]$Json)

  $all = New-Object System.Collections.Generic.List[string]

  try {
    foreach ($entry in @(Get-GuardrailAllowedEntries -Json $Json)) {
      if ($null -ne $entry) {
        [void]$all.Add($entry.ToString())
      }
    }
  }
  catch {
    Write-Verbose ("Allow-list JSON parsing failed: {0}" -f $_.Exception.Message)
  }

  return $all.ToArray()
}

function Read-AllowList {
  [CmdletBinding()]
  param(
    [string]$AllowListPath,
    [string[]]$Extra
  )

  $all = New-Object System.Collections.Generic.List[string]

  if ($AllowListPath) {
    $j = Try-ReadJsonFile -Path $AllowListPath
    if ($j) {
      foreach ($x in (Read-AllowListFromJson -Json $j)) {
        [void]$all.Add($x)
      }
    }
  }

  if ($Extra) {
    foreach ($x in $Extra) {
      if ($null -ne $x) {
        [void]$all.Add($x.ToString())
      }
    }
  }

  # Return strings only
  return @(
    $all.ToArray() |
      ForEach-Object { $_.Trim() } |
      Where-Object { $_ -ne '' } |
      Sort-Object -Unique
  )
}

function Resolve-ToSid {
  [CmdletBinding()]
  param([Parameter(Mandatory)] [string]$IdOrName)

  # SID string input?
  try {
    if ($IdOrName -match '^S-\d-\d+-.+$') {
      return (New-Object System.Security.Principal.SecurityIdentifier($IdOrName)).Value
    }
  }
  catch {
    Write-Verbose ("SID literal resolution failed for '{0}': {1}" -f $IdOrName, $_.Exception.Message)
    return $null
  }

  # NTAccount -> SID
  try {
    $nt = New-Object System.Security.Principal.NTAccount($IdOrName)
    $sid = $nt.Translate([System.Security.Principal.SecurityIdentifier])
    return $sid.Value
  }
  catch {
    # Local shorthand ".\Name"
    try {
      if ($IdOrName -match '^[.\\]+') {
        $name = $IdOrName -replace '^[.\\]+', ''
        $lu = Get-LocalUser -Name $name -ErrorAction Stop
        return $lu.SID.Value
      }
    }
    catch {
      Write-Verbose ("Local user shorthand resolution failed for '{0}': {1}" -f $IdOrName, $_.Exception.Message)
    }
  }

  return $null
}

function Get-BuiltinAdministratorSid {
  [CmdletBinding()]
  param()

  # RID 500 -> SID ends with -500
  try {
    $adm = Get-LocalUser | Where-Object { $_.SID.Value -match '-500$' } | Select-Object -First 1
    if ($adm) {
      return $adm.SID.Value
    }
  }
  catch {
    Write-Verbose ("Builtin Administrator SID lookup failed: {0}" -f $_.Exception.Message)
  }

  return $null
}

function Get-AdministratorsGroupName {
  [CmdletBinding()]
  param()

  $sidObj = New-Object System.Security.Principal.SecurityIdentifier($script:AdministratorsGroupSid)
  $nt = $sidObj.Translate([System.Security.Principal.NTAccount]).Value
  return ($nt -split '\\', 2)[1]
}

function Get-GuardrailMemberSid {
  param($RawMember)
  $sidString = $null
  try {
    if ($RawMember.SID -and $RawMember.SID.Value) {
      $sidString = [string]$RawMember.SID.Value
    }
  }
  catch {
    Write-Verbose ("Member SID.Value read failed: {0}" -f $_.Exception.Message)
  }
  if (-not $sidString) {
    try {
      if ($RawMember.SID) {
        $sidString = [string]$RawMember.SID
      }
    }
    catch {
      Write-Verbose ("Member SID fallback read failed: {0}" -f $_.Exception.Message)
    }
  }

  return $sidString
}

function Get-GuardrailMemberName {
  param($RawMember)
  $name = $null
  try {
    $name = [string]$RawMember.Name
  }
  catch {
    Write-Verbose ("Member Name read failed: {0}" -f $_.Exception.Message)
  }
  if ([string]::IsNullOrWhiteSpace($name)) {
    try {
      $name = [string]$RawMember.ToString()
    }
    catch {
      Write-Verbose ("Member ToString fallback failed: {0}" -f $_.Exception.Message)
    }
  }
  return $name
}

function ConvertTo-AdminMemberRecord {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)] $RawMember,
    [Parameter(Mandatory)] [string]$GroupName,
    [Parameter(Mandatory)] [ValidateSet('LocalAccounts', 'ADSI')] [string]$Provider
  )

  $sidString = Get-GuardrailMemberSid -RawMember $RawMember
  $name = Get-GuardrailMemberName -RawMember $RawMember

  $principalSource = $null
  try {
    $principalSource = [string]$RawMember.PrincipalSource
  }
  catch {
    Write-Verbose ("Member PrincipalSource read failed: {0}" -f $_.Exception.Message)
  }

  $objectClass = $null
  try {
    $objectClass = [string]$RawMember.ObjectClass
  }
  catch {
    Write-Verbose ("Member ObjectClass read failed: {0}" -f $_.Exception.Message)
  }

  [pscustomobject]@{
    PSTypeName = 'LocalAdmins.Guardrail.Member'
    GroupName = $GroupName
    Provider = $Provider
    Name = $name
    SID = $sidString
    PrincipalSource = $principalSource
    ObjectClass = $objectClass
  }
}

function Get-AdministratorsGroupMembers {
  [CmdletBinding()]
  param( [Parameter(Mandatory)] [string]$GroupName)

  # Prefer LocalAccounts for best fidelity.
  try {
    $raw = Get-LocalGroupMember -Group $GroupName -ErrorAction Stop
    foreach ($m in $raw) {
      ConvertTo-AdminMemberRecord -RawMember $m -GroupName $GroupName -Provider 'LocalAccounts'
    }
    return
  }
  catch {
    # ADSI fallback enumeration
    $grp = [ADSI]"WinNT://$env:COMPUTERNAME/$GroupName,group"
    $grp.Invoke("Members") | ForEach-Object {
      $path = $_.GetType().InvokeMember("ADsPath", 'GetProperty', $null, $_, $null)
      $name = $path -replace '^WinNT://', '' -replace '/', '\'

      $sid = $null
      try {
        $nt = New-Object System.Security.Principal.NTAccount($name)
        $sid = ($nt.Translate([System.Security.Principal.SecurityIdentifier])).Value
      }
      catch {
        Write-Verbose ("ADSI member SID translation failed for '{0}': {1}" -f $name, $_.Exception.Message)
      }

      $src =
      if ($name -match '^AzureAD\\') {
        'Microsoft Entra group'
      }
      elseif ($name -match '^MicrosoftAccount\\') {
        'Microsoft Account'
      }
      elseif ($name -match "^[^\\]+\\") {
        'Active Directory'
      }
      else {
        'Local'
      }

      ConvertTo-AdminMemberRecord -RawMember ([pscustomobject]@{
          Name = $name
          ObjectClass = 'UserOrGroup'
          PrincipalSource = $src
          SID = $sid
        }) -GroupName $GroupName -Provider 'ADSI'
    }
  }
}

function Is-DomainLikePrincipal {
  [CmdletBinding()]
  param([Parameter(Mandatory)] $MemberRecord)

  # PrincipalSource may be blank on older OS; treat blank as domain-like (fail-safe).
  $src = [string]$MemberRecord.PrincipalSource
  if ([string]::IsNullOrWhiteSpace($src)) {
    return $true
  }

  return ($src -in @(
      'Active Directory',
      'Microsoft Entra group',
      'Microsoft Account',
      'ActiveDirectory',
      'MicrosoftAccount'
    ))
}

function Get-GuardrailResult {
  [CmdletBinding()]
  param($RunState, [Parameter(Mandatory)] [string]$GroupName)

  [pscustomobject]@{
    PSTypeName = 'LocalAdmins.Guardrail.Result'
    Timestamp = (Get-Date).ToString('o')
    ComputerName = $env:COMPUTERNAME
    GroupName = $GroupName

    Remediate = [bool]$RunState.Remediate
    AllowDomainRemediation = [bool]$RunState.AllowDomainRemediation

    ConfigLoaded = $false
    AllowListPathUsed = $null

    AllowInput = @()
    AllowResolved = @()  # objects: Input, SID
    AllowSIDs = @()
    UnresolvedAllowInput = @()

    BuiltinAdminSid500 = $null
    AlwaysKeepSIDs = @()

    FailSafeNoRemove = $false
    DriftDetected = $false
    PostCompliant = $null

    MembersBefore = @()
    MembersAfter = @()

    ToAddSIDs = @()
    ToRemove = @()  # member records

    AddedSIDs = @()
    RemovedIds = @()

    Errors = @()

    EventId = $null
    EventLevel = $null
    EventMessage = $null
  }
}

. (Join-Path $PSScriptRoot '03-LocalAdmins-Guardrail.runtime.ps1')
