#requires -version 5.1
<#
.SYNOPSIS
  Provides private LAPS hygiene phases.
.DESCRIPTION
  Preserves policy precedence, rotation decisions, diagnostics, and result reporting for the public capability.
#>

function Get-ActiveLapsPolicy {
  # Policy roots and selection order are documented by Microsoft.
  $roots = @(
    @{ Type = 'WindowsLAPS'
      Mechanism = 'CSP'
      Path = 'HKLM:\Software\Microsoft\Policies\LAPS'
    },
    @{ Type = 'WindowsLAPS'
      Mechanism = 'GPO'
      Path = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\LAPS'
    },
    @{ Type = 'WindowsLAPS'
      Mechanism = 'Local'
      Path = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\LAPS\Config'
    }
  )
  foreach ($r in $roots) {
    try {
      if (Test-Path -LiteralPath $r.Path) {
        $p = Get-ItemProperty -LiteralPath $r.Path -ErrorAction Stop
        if ((Get-RegistryPropertiesCount $p) -gt 0) {
          return [pscustomobject]@{
            Type = $r.Type
            Mechanism = $r.Mechanism
            RootPath = $r.Path
            Policy = $p
          }
        }
      }
    }
    catch {
      Write-Verbose ("LAPS registry policy read failed for '{0}': {1}" -f $r.Path, $_.Exception.Message)
    }
  }
  return Get-LegacyLapsPolicy
}
function Get-BuiltInAdminNameRid500 {
  try {
    $acc = Get-LocalUser -ErrorAction Stop | Where-Object { $_.SID.Value -match '-500$' } | Select-Object -First 1
    if ($acc) {
      return $acc.Name
    }
  }
  catch {
    try {
      $acc2 = Get-CimInstance Win32_UserAccount -Filter "LocalAccount=True AND SID LIKE '%-500'" -ErrorAction Stop | Select-Object -First 1
      if ($acc2) {
        return $acc2.Name
      }
    }
    catch {
      Write-Verbose ("CIM fallback for RID-500 admin name failed: {0}" -f $_.Exception.Message)
    }
  }
  return 'Administrator'
}
function Get-ManagedAdminAccountName {
  param(
    [Parameter(Mandatory)][string]$PolicyType,
    $PolicyObject
  )
  if ($PolicyType -eq 'WindowsLAPS') {
    $windowsName = Get-WindowsManagedAdminName -PolicyObject $PolicyObject
    if ($windowsName) {
      return $windowsName
    }
  }
  if ($PolicyType -eq 'LegacyLAPS') {
    $legacyName = Get-LegacyManagedAdminName -PolicyObject $PolicyObject
    if ($legacyName) {
      return $legacyName
    }
  }
  return (Get-BuiltInAdminNameRid500)
}
function Get-LocalAdminInfo {
  param([Parameter(Mandatory)][string]$Name)
  try {
    $u = Get-LocalUser -Name $Name -ErrorAction Stop
    return [pscustomobject]@{
      Exists = $true
      Enabled = [bool]$u.Enabled
      PasswordLastSet = $u.PasswordLastSet
      Source = 'Get-LocalUser'
    }
  }
  catch {
    try {
      $escapedName = $Name -replace "'", "''"
      $u2 = Get-CimInstance Win32_UserAccount -Filter "LocalAccount=True AND Name='$escapedName'" -ErrorAction Stop | Select-Object -First 1
      if ($u2) {
        return [pscustomobject]@{
          Exists = $true
          Enabled = -not [bool]$u2.Disabled
          PasswordLastSet = $null
          Source = 'CIM'
        }
      }
    }
    catch {
      Write-Verbose ("CIM fallback for local user '{0}' failed: {1}" -f $Name, $_.Exception.Message)
    }
    return [pscustomobject]@{
      Exists = $false
      Enabled = $false
      PasswordLastSet = $null
      Source = 'n/a'
    }
  }
}
function Get-AADJoin {
  # Always return [bool]
  try {
    $out = (dsregcmd /status) 2>$null
    return [bool]($out -match 'AzureAdJoined\s*:\s*YES')
  }
  catch {
    Write-Verbose ("Azure AD join detection failed: {0}" -f $_.Exception.Message)
    return $false
  }
}
function Get-ADJoin {
  # Always return [bool]
  try {
    return [bool](Get-CimInstance Win32_ComputerSystem -ErrorAction Stop).PartOfDomain
  }
  catch {
    Write-Verbose ("AD domain join detection failed: {0}" -f $_.Exception.Message)
    return $false
  }
}
function Try-RotateWindowsLAPS {
  # Cmdlets are documented by Microsoft.
  [CmdletBinding()]
  param([switch]$DoIt)
  if (-not $DoIt) {
    return $false, "DryRun"
  }
  $err1 = ''
  $err2 = ''
  try {
    $cmd = Get-Command Reset-LapsPassword -ErrorAction SilentlyContinue
    if ($cmd) {
      Reset-LapsPassword -ErrorAction Stop | Out-Null
      return $true, 'Reset-LapsPassword'
    }
  }
  catch {
    $err1 = $_.Exception.Message
  }
  try {
    $cmd2 = Get-Command Invoke-LapsPolicyProcessing -ErrorAction SilentlyContinue
    if ($cmd2) {
      Invoke-LapsPolicyProcessing -ErrorAction Stop | Out-Null
      return $true, 'Invoke-LapsPolicyProcessing'
    }
  }
  catch {
    $err2 = $_.Exception.Message
  }
  return Get-LapsRotationFailure -ResetError $err1 -PolicyError $err2
}
function Try-CollectLapsDiagnostics {
  [CmdletBinding()]
  param(
    [switch]$DoIt,
    [string]$OutputFolder
  )
  if (-not $DoIt) {
    return $false, "DryRun"
  }
  try {
    $cmd = Get-Command Get-LapsDiagnostics -ErrorAction SilentlyContinue
    if (-not $cmd) {
      return $false, "Get-LapsDiagnostics not available"
    }
    $null = New-Item -ItemType Directory -Path $OutputFolder -Force -ErrorAction Stop
    $out = Get-LapsDiagnostics -OutputFolder $OutputFolder -ErrorAction Stop
    return $true, (($out | Out-String).Trim())
  }
  catch {
    return $false, $_.Exception.Message
  }
}
function Get-PolicyPasswordAgeDays {
  param(
    [Parameter(Mandatory)][string]$PolicyType,
    $PolicyObject,
    [Parameter(Mandatory)][int]$DefaultAgeDays
  )
  if ($PolicyType -eq 'WindowsLAPS') {
    if ($PolicyObject -and $PolicyObject.PSObject.Properties['PasswordAgeDays']) {
      try {
        return [int]$PolicyObject.PasswordAgeDays
      }
      catch {
        Write-Verbose ("Windows LAPS PasswordAgeDays cast failed: {0}" -f $_.Exception.Message)
      }
    }
    return $DefaultAgeDays
  }
  if ($PolicyType -eq 'LegacyLAPS') {
    return Get-LegacyLapsPasswordAge -PolicyObject $PolicyObject -DefaultAgeDays $DefaultAgeDays
  }
  return $DefaultAgeDays
}
function Get-PolicyComplexity {
  param($PolicyObject)
  try {
    if ($PolicyObject -and $PolicyObject.PSObject.Properties['PasswordComplexity']) {
      return [int]$PolicyObject.PasswordComplexity
    }
  }
  catch {
    Write-Verbose ("LAPS PasswordComplexity cast failed: {0}" -f $_.Exception.Message)
  }
  return $null
}
function Get-WindowsLapsBackupDirectory {
  param($PolicyObject)
  try {
    if ($PolicyObject -and $PolicyObject.PSObject.Properties['BackupDirectory']) {
      return [int]$PolicyObject.BackupDirectory
    }
  }
  catch {
    Write-Verbose ("Windows LAPS BackupDirectory cast failed: {0}" -f $_.Exception.Message)
  }
  return $null
}
function Convert-BackupDirectoryToText {
  param([int]$BackupDirectory)
  if ($BackupDirectory -eq 1) {
    return 'AAD'
  }
  if ($BackupDirectory -eq 2) {
    return 'AD DS'
  }
  if ($BackupDirectory -eq 0) {
    return 'Disabled'
  }
  return '(unknown/not set)'
}
function Get-LegacyLapsPolicy {
  $legacyRoot = 'HKLM:\Software\Policies\Microsoft Services\AdmPwd'
  try {
    if (Test-Path -LiteralPath $legacyRoot) {
      $lp = Get-ItemProperty -LiteralPath $legacyRoot -ErrorAction Stop
      if ((Get-RegistryPropertiesCount $lp) -gt 0) {
        return [pscustomobject]@{
          Type = 'LegacyLAPS'
          Mechanism = 'GPO'
          RootPath = $legacyRoot
          Policy = $lp
        }
      }
    }
  }
  catch {
    Write-Verbose ("Legacy LAPS registry policy read failed for '{0}': {1}" -f $legacyRoot, $_.Exception.Message)
  }
  return $null
}
function Get-LegacyManagedAdminName {
  param($PolicyObject)
  try {
    if ($PolicyObject -and $PolicyObject.PSObject.Properties['AdminAccountName']) {
      $n = [string]$PolicyObject.AdminAccountName
      if ($n -and $n.Trim().Length -gt 0) {
        return $n.Trim()
      }
    }
  }
  catch {
    Write-Verbose ("Legacy LAPS AdminAccountName read failed: {0}" -f $_.Exception.Message)
  }
}
function Get-LegacyLapsPasswordAge {
  param($PolicyObject, [int]$DefaultAgeDays)
  if ($PolicyObject -and $PolicyObject.PSObject.Properties['PasswordAge']) {
    try {
      $hours = [int]$PolicyObject.PasswordAge
      return [math]::Ceiling($hours / 24)
    }
    catch {
      Write-Verbose ("Legacy LAPS PasswordAge cast failed: {0}" -f $_.Exception.Message)
    }
  }
  return $DefaultAgeDays
}
function Get-LapsRotationFailure {
  param([string]$ResetError, [string]$PolicyError)
  $err1 = $ResetError
  $err2 = $PolicyError
  $msg = "No rotation cmdlet available"
  if ($err1) {
    $msg += " | Reset-LapsPassword: $err1"
  }
  if ($err2) {
    $msg += " | Invoke-LapsPolicyProcessing: $err2"
  }
  return $false, $msg
}

function Get-WindowsManagedAdminName {
  param($PolicyObject)
  try {
    if ($PolicyObject -and $PolicyObject.PSObject.Properties['AdministratorAccountName']) {
      $n = [string]$PolicyObject.AdministratorAccountName
      if ($n -and $n.Trim().Length -gt 0) {
        return $n.Trim()
      }
    }
  }
  catch {
    Write-Verbose ("Windows LAPS AdministratorAccountName read failed: {0}" -f $_.Exception.Message)
  }
}
