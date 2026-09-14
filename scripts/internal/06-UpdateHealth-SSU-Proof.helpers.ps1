#requires -version 5.1
<#
.SYNOPSIS
Provides private Update Health and servicing stack probes.
.DESCRIPTION
Encapsulates catalog loading, service and task operations, and bounded native evidence collection.
#>
function Write-FallbackLogLine {
  param([string]$Line)
  try {
    [void](Ensure-Directory (Split-Path -Parent $script:FallbackLog))
    ("{0} {1}" -f (Get-Date).ToString('s'), $Line) | Out-File -FilePath $script:FallbackLog -Encoding UTF8 -Append
  } catch {
    Write-Verbose ("Fallback log write failed: {0}" -f $_.Exception.Message)
  }
}
# Test-IsAdmin imported from lib/Common.psm1
# Save-Json: using canonical Save-Json from lib/Serialization.psm1
function Get-SafeString {
  param($Value,[string]$Default)
  if ($null -eq $Value) { return $Default }
  $s = [string]$Value
  if ([string]::IsNullOrWhiteSpace($s)) { return $Default }
  return $s
}
function Normalize-VersionString {
  param([string]$s)
  if ([string]::IsNullOrWhiteSpace($s)) { return $null }
  $t = $s -replace '[A-Za-z_-]',' '
  $t = ($t -replace '[^\d\.]',' ').Trim()
  $m = [regex]::Matches($t,'\d+(\.\d+){1,3}') |
    Sort-Object { $_.Value.Length } -Descending |
    Select-Object -First 1
  if ($m) { try { return [version]$m.Value } catch { return $null } }
  try { return [version]$s } catch { return $null }
}
function Compare-Version {
  param([string]$a,[string]$b)
  $va = Normalize-VersionString $a
  $vb = Normalize-VersionString $b
  if (-not $va -or -not $vb) { return $null }
  if     ($va -lt $vb) { return -1 }
  elseif ($va -gt $vb) { return  1 }
  else                 { return  0 }
}
function Get-LegacyFinding {
  param([string]$Area,[ValidateSet('Info','Warning','Error')][string]$Severity,[string]$Message)
  [pscustomobject]@{
    Time     = (Get-Date).ToString('s')
    Area     = $Area
    Severity = $Severity
    Message  = $Message
  }
}
function Add-FindingToCanonical {
  # Map the compatibility payload to the shared finding contract.
  param([pscustomobject]$LegacyFinding)
  $c10Sev = switch ($LegacyFinding.Severity) { 'Error' { 'High' }; 'Warning' { 'Medium' }; default { 'Info' } }
  Add-Finding -FindingList $script:Findings -Code $LegacyFinding.Area -Severity $c10Sev -Message $LegacyFinding.Message -Extra @{ Time = $LegacyFinding.Time }
}
function Get-LegacyAction {
  param([string]$Target,[string]$Operation,[ValidateSet('Success','Failed')][string]$Result,[string]$Message)
  [pscustomobject]@{
    Time      = (Get-Date).ToString('s')
    Target    = $Target
    Operation = $Operation
    Result    = $Result
    Message   = $Message
  }
}
function Add-ArrayList {
  param([System.Collections.ArrayList]$List,$Item)
  [void]$List.Add($Item)
}
function Add-ArrayListMany {
  param([System.Collections.ArrayList]$List,$Items)
  if ($null -eq $Items) { return }
  foreach($i in @($Items)) { [void]$List.Add($i) }
}
# -------------------------------- Service/Tasks helpers -----------------------------
function Invoke-ServiceStartTypeChange {
  [CmdletBinding(SupportsShouldProcess = $true)]
  param([string]$Name, [string]$StartType)

  if (-not $PSCmdlet.ShouldProcess($Name, "Set startup type to $StartType")) {
    return Get-LegacyAction -Target $Name -Operation SetStartupType -Result Skipped -Message 'ShouldProcess declined'
  }
  if ($StartType -eq 'AutomaticDelayedStart') {
    $native = Invoke-NativeCommand -Command sc.exe -Arguments @('config',$Name,'start=','delayed-auto') -ThrowOnError -CaptureOutput -TimeoutSeconds 30 -MaxOutputBytes 65536
    if ($native.TimedOut -or $native.OutputTruncated -or $native.StderrTruncated) { throw 'sc.exe output was incomplete or timed out.' }
    return Get-LegacyAction -Target $Name -Operation SetStartupType -Result Success -Message 'AutomaticDelayedStart (sc.exe delayed-auto)'
  }
  Set-Service -Name $Name -StartupType $StartType -ErrorAction Stop
  return Get-LegacyAction -Target $Name -Operation SetStartupType -Result Success -Message $StartType
}

function Set-ServiceStartType {
  [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
  param([string]$Name, [ValidateSet('Disabled','Manual','Automatic','AutomaticDelayedStart')][string]$StartType)
  $actions = New-Object System.Collections.ArrayList
  try { Add-ArrayList $actions (Invoke-ServiceStartTypeChange -Name $Name -StartType $StartType) }
  catch { Add-ArrayList $actions (Get-LegacyAction -Target $Name -Operation SetStartupType -Result Failed -Message $_.Exception.Message) }
  return $actions
}

function Add-ServiceStartupDrift {
  param($Result, $Service, [string]$Name, [string]$ExpectedStart, [bool]$Remediate)
  $actual = $Service.StartType.ToString()
  if ($actual -eq $ExpectedStart) { return }
  $Result.Ok = $false
  Add-ArrayList $Result.Drift (Get-LegacyFinding -Area ("Service:{0}" -f $Name) -Severity Warning -Message ("StartType={0} expected={1}" -f $actual,$ExpectedStart))
  if ($Remediate) { Add-ArrayListMany $Result.Actions (Set-ServiceStartType -Name $Name -StartType $ExpectedStart) }
}

function Add-ServiceStatusDrift {
  [CmdletBinding(SupportsShouldProcess = $true)]
  param($Result, $Service, [string]$Name, [string]$ExpectedState, [bool]$Remediate)
  $actual = $Service.Status.ToString()
  if ($actual -eq $ExpectedState) { return }
  $Result.Ok = $false
  Add-ArrayList $Result.Drift (Get-LegacyFinding -Area ("Service:{0}" -f $Name) -Severity Warning -Message ("State={0} expected={1}" -f $actual,$ExpectedState))
  if (-not $Remediate) { return }
  try {
    if (-not $PSCmdlet.ShouldProcess($Name, "Set service state to $ExpectedState")) {
      Add-ArrayList $Result.Actions (Get-LegacyAction -Target $Name -Operation SetState -Result Skipped -Message 'ShouldProcess declined')
      return
    }
    if ($ExpectedState -eq 'Running') { Start-Service -Name $Name -ErrorAction Stop }
    else { Stop-Service -Name $Name -Force -ErrorAction Stop }
    Add-ArrayList $Result.Actions (Get-LegacyAction -Target $Name -Operation SetState -Result Success -Message $ExpectedState)
  }
  catch { Add-ArrayList $Result.Actions (Get-LegacyAction -Target $Name -Operation SetState -Result Failed -Message $_.Exception.Message) }
}

function Ensure-ServiceState {
  [CmdletBinding(SupportsShouldProcess = $true)]
  param(
    [string]$Name,
    [ValidateSet('Disabled','Manual','Automatic','AutomaticDelayedStart')][string]$Start,
    [ValidateSet('Running','Stopped')][string]$State,
    [switch]$Remediate
  )
  $result = [pscustomobject]@{ Ok = $true; Drift = [System.Collections.ArrayList]::new(); Actions = [System.Collections.ArrayList]::new() }
  try {
    $service = Get-Service -Name $Name -ErrorAction Stop
    Add-ServiceStartupDrift -Result $result -Service $service -Name $Name -ExpectedStart $Start -Remediate $Remediate
    Add-ServiceStatusDrift -Result $result -Service $service -Name $Name -ExpectedState $State -Remediate $Remediate
  }
  catch {
    $result.Ok = $false
    Add-ArrayList $result.Drift (Get-LegacyFinding -Area ("Service:{0}" -f $Name) -Severity Error -Message ("Not found or inaccessible: {0}" -f $_.Exception.Message))
  }
  return $result
}

function Get-TaskInfoUnder {
  param([string]$Folder)
  $list = New-Object System.Collections.ArrayList
  try {
    $tasks = Get-ScheduledTask -TaskPath $Folder -ErrorAction Stop
    foreach($t in $tasks){
      $state = "Unknown"
      try { $state = (Get-ScheduledTaskInfo -TaskName $t.TaskName -TaskPath $t.TaskPath -ErrorAction Stop).State.ToString() } catch {
        Write-Verbose ("Scheduled task state read failed for '{0}{1}': {2}" -f $t.TaskPath,$t.TaskName,$_.Exception.Message)
      }
      Add-ArrayList $list ([pscustomobject]@{
        Path    = ($t.TaskPath + $t.TaskName)
        Enabled = [bool]$t.Enabled
        State   = $state
      })
    }
  } catch {
    Write-Verbose ("Scheduled task enumeration failed for folder '{0}': {1}" -f $Folder,$_.Exception.Message)
  }
  return $list
}
function Ensure-TasksEnabled {
  param([string]$Folder,[switch]$Remediate)
  $drift   = New-Object System.Collections.ArrayList
  $actions = New-Object System.Collections.ArrayList
  $ok = $true
  try {
    $tasks = Get-ScheduledTask -TaskPath $Folder -ErrorAction Stop
    foreach($t in $tasks){
      if (-not $t.Enabled) {
        $ok = $false
        Add-ArrayList $drift (Get-LegacyFinding -Area ("Task:{0}{1}" -f $t.TaskPath,$t.TaskName) -Severity 'Warning' -Message 'Disabled')
        if ($Remediate) {
          try {
            Enable-ScheduledTask -TaskName $t.TaskName -TaskPath $t.TaskPath -ErrorAction Stop
            Add-ArrayList $actions (Get-LegacyAction -Target ("{0}{1}" -f $t.TaskPath,$t.TaskName) -Operation 'EnableTask' -Result 'Success' -Message 'Enabled')
          } catch {
            Add-ArrayList $actions (Get-LegacyAction -Target ("{0}{1}" -f $t.TaskPath,$t.TaskName) -Operation 'EnableTask' -Result 'Failed' -Message $_.Exception.Message)
          }
        }
      }
    }
  } catch {
    $ok = $false
    Add-ArrayList $drift (Get-LegacyFinding -Area ("TaskFolder:{0}" -f $Folder) -Severity 'Error' -Message $_.Exception.Message)
  }
  [pscustomobject]@{ Ok=$ok; Drift=$drift; Actions=$actions }
}
# ------------------------------------ Catalog defaults -----------------------------
function Get-DefaultUpdateHealthProofPath {
  return Join-Path ([System.IO.Path]::GetTempPath()) 'UpdateHealth-SSU-Proof.json'
}

function Get-DefaultUpdateHealthCatalog {
  return @"
{
  "UpdateHealthTools": {
    "Require": true,
    "MinVersion": "5.0.0.0",
    "ServiceStartAllowed": ["Automatic","AutomaticDelayedStart"],
    "ServiceDesiredState": "Running",
    "EnsureTasksEnabled": true,
    "TaskFolder": "\\Microsoft\\UpdateHealthService\\"
  },
  "ServicingStack": {
    "MinVersion": "10.0.22621.3800"
  },
  "Proof": {
    "OutFile": null
  }
}
"@ | ConvertFrom-Json
}

function Read-UpdateHealthJson {
  param([string]$Path)
  if (-not (Test-Path -LiteralPath $Path)) { return [pscustomobject]@{ Found = $false; Value = $null; Error = $null } }
  try {
    $value = Get-BoundedUtf8FileContent -Path $Path -MaximumBytes 1048576 | ConvertFrom-Json -ErrorAction Stop
    return [pscustomobject]@{ Found = $true; Value = $value; Error = $null }
  }
  catch { return [pscustomobject]@{ Found = $true; Value = $null; Error = $_.Exception.Message } }
}

function Get-ExplicitUpdateHealthCatalog {
  param([string]$CatalogPath)
  $read = Read-UpdateHealthJson -Path $CatalogPath
  if (-not $read.Found) { return [pscustomobject]@{ Catalog = $null; Source = $null; Error = 'CatalogPath not found.' } }
  if ($read.Error) { return [pscustomobject]@{ Catalog = $null; Source = $null; Error = ('CatalogPath JSON parse failed: {0}' -f $read.Error) } }
  return [pscustomobject]@{ Catalog = $read.Value; Source = 'CatalogPath'; Error = $null }
}

function Get-UpdateHealthCatalogReference {
  param([string]$ConfigPath)
  $configRead = Read-UpdateHealthJson -Path $ConfigPath
  if (-not $configRead.Found) { return [pscustomobject]@{ Path = $null; Error = 'ConfigPath not found.' } }
  if ($configRead.Error) { return [pscustomobject]@{ Path = $null; Error = ('Config JSON parse failed: {0}' -f $configRead.Error) } }
  $path = $(if ($configRead.Value -and $configRead.Value.UpdateHealth -and $configRead.Value.UpdateHealth.CatalogPath) { [string]$configRead.Value.UpdateHealth.CatalogPath } else { $null })
  if (-not $path) { return [pscustomobject]@{ Path = $null; Error = 'Config JSON has no UpdateHealth.CatalogPath.' } }
  return [pscustomobject]@{ Path = $path; Error = $null }
}

function Get-ConfiguredUpdateHealthCatalog {
  param([string]$ConfigPath)
  $reference = Get-UpdateHealthCatalogReference -ConfigPath $ConfigPath
  if ($reference.Error) { return [pscustomobject]@{ Catalog = $null; Source = $null; Error = $reference.Error } }
  $catalogRead = Read-UpdateHealthJson -Path $reference.Path
  if (-not $catalogRead.Found) { return [pscustomobject]@{ Catalog = $null; Source = $null; Error = 'Config points to catalog path, but it was not found.' } }
  if ($catalogRead.Error) { return [pscustomobject]@{ Catalog = $null; Source = $null; Error = ('Config JSON parse failed: {0}' -f $catalogRead.Error) } }
  return [pscustomobject]@{ Catalog = $catalogRead.Value; Source = 'ConfigPath->CatalogPath'; Error = $null }
}

function Load-Catalog {
  param([string]$CatalogPath,[string]$ConfigPath,[object]$FallbackCatalog)
  $meta = [pscustomobject]@{ CatalogLoaded = $false; CatalogSource = 'Default'; Errors = @() }
  if ($CatalogPath) {
    $explicit = Get-ExplicitUpdateHealthCatalog -CatalogPath $CatalogPath
    if ($explicit.Catalog) { $meta.CatalogLoaded = $true; $meta.CatalogSource = $explicit.Source; return [pscustomobject]@{ Catalog = $explicit.Catalog; Meta = $meta } }
    $meta.Errors += $explicit.Error
  }
  if ($ConfigPath) {
    $configured = Get-ConfiguredUpdateHealthCatalog -ConfigPath $ConfigPath
    if ($configured.Catalog) { $meta.CatalogLoaded = $true; $meta.CatalogSource = $configured.Source; return [pscustomobject]@{ Catalog = $configured.Catalog; Meta = $meta } }
    $meta.Errors += $configured.Error
  }
  return [pscustomobject]@{ Catalog = $FallbackCatalog; Meta = $meta }
}

# ------------------------------------ Probes ---------------------------------------
function Find-UhtRegistryPackage {
  foreach ($key in @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall')) {
    try {
      foreach ($item in Get-ChildItem -LiteralPath $key -ErrorAction Stop) {
        $properties = Get-ItemProperty -LiteralPath $item.PSPath -ErrorAction SilentlyContinue
        if ($properties.DisplayName -match 'Microsoft Update Health Tools') { return $properties }
      }
    }
    catch { Write-Verbose ("Update Health Tools registry probe failed for '{0}': {1}" -f $key,$_.Exception.Message) }
  }
  return $null
}

function Set-UhtFileMetadata {
  param($Result)
  $baseDirs = @(
    [Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles),
    [Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFilesX86)
  ) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | ForEach-Object { Join-Path $_ 'Microsoft Update Health Tools' }
  foreach ($directory in $baseDirs) {
    if ($Result.FileVersion) { break }
    try {
      if (-not (Test-Path -LiteralPath $directory)) { continue }
      $executable = Get-ChildItem -LiteralPath $directory -Filter *.exe -Recurse -File -ErrorAction SilentlyContinue | Sort-Object { $_.VersionInfo.FileVersionRaw } -Descending | Select-Object -First 1
      if ($executable) { $Result.FileVersion = $executable.VersionInfo.FileVersion }
      if (-not $Result.InstallLocation) { $Result.InstallLocation = $directory }
    }
    catch { Write-Verbose ("Update Health Tools install directory probe failed for '{0}': {1}" -f $directory,$_.Exception.Message) }
  }
}

function Get-UhtServiceInfo {
  try {
    $service = Get-Service -Name uhssvc -ErrorAction Stop
    return [ordered]@{ Name = $service.Name; StartType = $service.StartType.ToString(); Status = $service.Status.ToString() }
  }
  catch { return [ordered]@{ Name = 'uhssvc'; StartType = 'N/A'; Status = 'N/A' } }
}

function Get-UHT-Info {
  $result = [ordered]@{ Installed = $false; DisplayName = $null; DisplayVersion = $null; InstallDate = $null; InstallLocation = $null; Service = $null; Tasks = @(); FileVersion = $null }
  $package = Find-UhtRegistryPackage
  if ($package) {
    $result.Installed = $true; $result.DisplayName = $package.DisplayName; $result.DisplayVersion = $package.DisplayVersion
    $result.InstallDate = $package.InstallDate; $result.InstallLocation = $package.InstallLocation
  }
  Set-UhtFileMetadata -Result $result
  $result.Service = Get-UhtServiceInfo
  $result.Tasks = Get-TaskInfoUnder '\Microsoft\UpdateHealthService\'
  return $result
}

function Get-SsuRegistryInfo {
  try {
    $properties = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\Servicing' -ErrorAction Stop
    if ($properties.ServicingStackVersion) {
      return [ordered]@{ Version = [string]$properties.ServicingStackVersion; Source = 'Registry:ServicingStackVersion'; PackageIdentity = $null; InstalledOn = $null }
    }
  }
  catch { Write-Verbose ('SSU registry version probe failed: {0}' -f $_.Exception.Message) }
  return $null
}

function Assert-CompleteSsuDismResult {
  param($Result)
  if ($null -eq $Result -or -not $Result.Success -or $Result.TimedOut -or $Result.OutputTruncated -or $Result.StderrTruncated) {
    throw 'DISM SSU detection did not complete with complete output.'
  }
}

function Get-SsuPackageIdentity {
  param([string]$Line)
  $identity = (($Line -replace '^\s*\|\s*','') -replace '\s*\|\s*.*$','').Trim()
  if ([string]::IsNullOrWhiteSpace($identity)) { return ($Line -replace '.*:\s*','').Trim() }
  return $identity
}

function Get-SsuDismInfo {
  $result = [ordered]@{ Version = $null; Source = $null; PackageIdentity = $null; InstalledOn = $null }
  try {
    $dism = Invoke-NativeCommand -Command dism.exe -Arguments @('/online','/get-packages','/format:table') -CaptureOutput -TimeoutSeconds 180 -MaxOutputBytes 1048576
    Assert-CompleteSsuDismResult -Result $dism
    $line = $dism.Output -split "`r?`n" | Where-Object { $_ -match 'Package_for_ServicingStack' } | Select-Object -First 1
    if (-not $line) { return $result }
    $result.PackageIdentity = Get-SsuPackageIdentity -Line $line
    $version = Normalize-VersionString $result.PackageIdentity
    if ($version) { $result.Version = $version.ToString() }
    $result.Source = 'DISM:Get-Packages'
  }
  catch { Write-Verbose ('DISM SSU detection failed: {0}' -f $_.Exception.Message) }
  return $result
}

function Get-SSU-Info {
  $registry = Get-SsuRegistryInfo
  if ($registry) { return $registry }
  return Get-SsuDismInfo
}

function Get-WU-CoreServices {
  $names = @('UsoSvc','WaaSMedicSvc','wuauserv','DoSvc','BITS','cryptsvc')
  $list = New-Object System.Collections.ArrayList
  foreach($n in $names){
    try {
      $s = Get-Service -Name $n -ErrorAction Stop
      Add-ArrayList $list ([pscustomobject]@{ Name=$n; StartType=$s.StartType.ToString(); Status=$s.Status.ToString() })
    } catch {
      Add-ArrayList $list ([pscustomobject]@{ Name=$n; StartType='N/A'; Status='N/A' })
    }
  }
  return $list
}
