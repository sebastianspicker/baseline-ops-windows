#requires -version 5.1
<#
.SYNOPSIS
  Sweeps the local Windows host for IOC indicators, optional Defender scans, and optional evidence collection.
.DESCRIPTION
  Loads an IOC catalog from -CatalogPath, ConfigPath -> IOC.CatalogPath, or built-in defaults. Checks files, file globs, registry values, services, scheduled tasks, processes, remote IPs, and DNS cache domains. Remediate mode applies catalog-requested non-destructive containment actions.
.PARAMETER CatalogPath
  Path to an IOC catalog JSON file.
.PARAMETER ConfigPath
  Configuration JSON that can provide IOC.CatalogPath.
.PARAMETER ScanType
  Defender scan type: Full, Quick, or None.
.PARAMETER CustomScanPaths
  Defender custom scan paths used when ScanType is None.
.PARAMETER CollectEvidence
  Copy matched files and export matched registry keys into the evidence directory.
.PARAMETER Strict
  Treat a no-finding run as noteworthy for compliance/audit signaling.
.PARAMETER PassThru
  Emit the final proof object to the success pipeline.
.PARAMETER Mode
  Audit reports only; Remediate applies catalog-requested containment.
.PARAMETER OutputFormat
  Output format: Console, Json, Csv, or None.
.PARAMETER OutputPath
  File path for Json/Csv output.
.PARAMETER Quiet
  Suppress console output.
.PARAMETER NoColor
  Disable colored output.
.OUTPUTS
  By default, none. With -PassThru, emits the structured proof object.
.NOTES
  Exit 0 means no findings/errors; exit 1 means findings, source errors, or Strict triggered a non-OK outcome. Evidence collection failures are recorded in Proof.Errors.
.EXAMPLE
  .\11-IOC-Sweep-Defender.ps1
.EXAMPLE
  .\11-IOC-Sweep-Defender.ps1 -CatalogPath "PATH/TO/JSON/ioc-catalog.json" -CollectEvidence
.EXAMPLE
  .\11-IOC-Sweep-Defender.ps1 -ScanType Quick
.EXAMPLE
  .\11-IOC-Sweep-Defender.ps1 -ScanType None -CustomScanPaths "C:\Temp","C:\Users\Public" -CollectEvidence
.EXAMPLE
  .\11-IOC-Sweep-Defender.ps1 -Mode Remediate -Strict
.EXAMPLE
  $proof = .\11-IOC-Sweep-Defender.ps1 -PassThru
  $proof.Findings.Files | Where-Object { $_.Signed -eq $false } | ConvertTo-Json -Depth 5
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
  [string]$CatalogPath,
  [switch]$CollectEvidence,
  [ValidateSet('Quick','Full','None')] [string]$ScanType = 'Full',
  [string[]]$CustomScanPaths,
  [switch]$Strict,
  [string]$ConfigPath,
  [switch]$PassThru,
  [ValidateSet('Audit','Remediate')][string]$Mode = 'Audit',
  [ValidateSet('Console','Json','Csv','None')][string]$OutputFormat = 'Console',
  [string]$OutputPath,
  [switch]$Quiet,
  [switch]$NoColor
)
. (Join-Path $PSScriptRoot '_lib/Bootstrap.ps1')
Import-Module (Join-Path $script:LibPath 'Common.psm1') -Force -DisableNameChecking
Import-Module (Join-Path $script:LibPath 'Output.psm1') -Force
Import-Module (Join-Path $script:LibPath 'EventLog.psm1') -Force
Import-Module (Join-Path $script:LibPath 'Results.psm1') -Force
Import-Module (Join-Path $script:LibPath 'Evidence.psm1') -Force
Import-Module (Join-Path $script:LibPath 'External.psm1') -Force -DisableNameChecking
Import-Module (Join-Path $script:LibPath 'JsonCatalog.psm1') -Force
Import-Module (Join-Path $script:LibPath Serialization.psm1) -Force
# v2-init (migrated to Initialize-V2Context)
Initialize-V2Context -ScriptName '11-IOC-Sweep-Defender.ps1' -BoundParameters $PSBoundParameters -DeriveRemediate
$ErrorActionPreference = 'Stop'

$isWindowsHost = ($env:OS -eq 'Windows_NT')
if (-not $isWindowsHost) {
  $summary = [pscustomobject]@{
    ComputerName = $env:COMPUTERNAME
    Timestamp    = Get-Date
    Mode         = $Mode
    Supported    = $false
    Notes        = @('Skipped: this script is only supported on Windows hosts.')
  }
  $result = Get-V2ResultObject -ScriptName '11-IOC-Sweep-Defender.ps1' -Mode $Mode -Result 'OK' -Findings @() -Summary $summary -Metadata @{ UnsupportedHost = $true }
  Write-ResultObject -ResultObject $result -OutputFormat $OutputFormat -OutputPath $OutputPath
  if ($PassThru) { $result }
  exit 0
}

Set-StrictMode -Version Latest
# -----------------------------
# Globals / Defaults (anonymized)
# -----------------------------
$DefaultProofOutFile = Join-Path ([System.IO.Path]::GetTempPath()) 'IOC-Sweep-Defender-proof.json'
$DefaultEvidenceDir  = Join-Path ([System.IO.Path]::GetTempPath()) 'IOC-Sweep-Defender-evidence'
# -----------------------------
# Console helpers (host-only)
# -----------------------------
# -----------------------------
# Core helpers
# -----------------------------
# Save-Json: using canonical Save-Json from lib/Serialization.psm1
# Expand-Env imported from lib/Evidence.psm1
# Read-Json replaced by Read-JsonFileSafe from lib/JsonCatalog.psm1
function Get-ObjPropValue {
  param(
    [Parameter(Mandatory=$true)] $Obj,
    [Parameter(Mandatory=$true)] [string] $Name
  )
  try {
    if ($null -eq $Obj) { return $null }
    $p = $Obj.PSObject.Properties[$Name]
    if ($p) { return $p.Value }
  } catch {
    Write-Verbose ("IOC object property access failed for '{0}': {1}" -f $Name,$_.Exception.Message)
  }
  return $null
}
function Get-OrDefault([object]$Value, [object]$Default){
  if ($null -ne $Value -and "$Value" -ne "") { return $Value }
  return $Default
}
function Get-DefaultCatalog {
  $cat = New-Object psobject
  Add-Member -InputObject $cat -MemberType NoteProperty -Name Proof       -Value ([pscustomobject]@{ OutFile = $DefaultProofOutFile })
  Add-Member -InputObject $cat -MemberType NoteProperty -Name EvidenceDir -Value $DefaultEvidenceDir
  Add-Member -InputObject $cat -MemberType NoteProperty -Name Files          -Value @()
  Add-Member -InputObject $cat -MemberType NoteProperty -Name FileGlobs      -Value @()
  Add-Member -InputObject $cat -MemberType NoteProperty -Name Registry       -Value @()
  Add-Member -InputObject $cat -MemberType NoteProperty -Name Services       -Value @()
  Add-Member -InputObject $cat -MemberType NoteProperty -Name ScheduledTasks -Value @()
  Add-Member -InputObject $cat -MemberType NoteProperty -Name Processes      -Value @()
  Add-Member -InputObject $cat -MemberType NoteProperty -Name IPs            -Value @()
  Add-Member -InputObject $cat -MemberType NoteProperty -Name Domains        -Value @()
  return $cat
}
function Load-Catalog {
  param([string]$CatalogPath,[string]$ConfigPath)
  $res = [ordered]@{ Catalog = $null; Source = 'Default'; Errors = @() }
  $sanitizedCatalog = if ([string]::IsNullOrWhiteSpace($CatalogPath)) { $null } else { Sanitize-Path -Path $CatalogPath -MustExist }
  if ($sanitizedCatalog) {
    $c = Read-JsonFileSafe -Path $sanitizedCatalog
    if ($c) { $res.Catalog = $c; $res.Source = 'CatalogPath'; return $res }
    $res.Errors += ("CatalogPath not loaded: {0}" -f $sanitizedCatalog)
  }
  $cfg = $null
  $sanitizedConfig = if ([string]::IsNullOrWhiteSpace($ConfigPath)) { $null } else { Sanitize-Path -Path $ConfigPath -MustExist }
  if ($sanitizedConfig) {
    $cfg = Read-JsonFileSafe -Path $sanitizedConfig
    if (-not $cfg) { $res.Errors += ("ConfigPath not loaded: {0}" -f $sanitizedConfig) }
  }
  $p = $null
  try { if ($cfg -and $cfg.IOC -and $cfg.IOC.CatalogPath) { $p = [string]$cfg.IOC.CatalogPath } } catch { $p = $null }
  if ($p) {
    $sanitizedP = Sanitize-Path -Path $p -MustExist
    if ($sanitizedP) {
      $c2 = Read-JsonFileSafe -Path $sanitizedP
      if ($c2) { $res.Catalog = $c2; $res.Source = 'Config->IOC.CatalogPath'; return $res }
      $res.Errors += ("Config IOC.CatalogPath not loaded: {0}" -f $sanitizedP)
    }
  }
  $res.Catalog = (Get-DefaultCatalog)
  $res.Source  = 'Default'
  return $res
}
function Get-ProcessImageSha256([int]$ProcessId){
  try {
    $p = Get-Process -Id $ProcessId -ErrorAction Stop
    if ($p.Path) { return Get-FileSha256 -Path $p.Path }
  } catch {
    Write-Verbose ("Process image hash lookup failed for PID {0}: {1}" -f $ProcessId,$_.Exception.Message)
  }
  return $null
}
function Get-FilePublisher([string]$File){
  if (-not $File -or -not (Test-Path -LiteralPath $File)) { return $null, $false }
  try {
    $sig = Get-AuthenticodeSignature -FilePath $File -ErrorAction Stop
    return $sig.SignerCertificate.Subject, ($sig.Status -eq 'Valid')
  } catch {
    return $null, $false
  }
}
function Convert-RegProviderToRegExePath([string]$KeyPath){
  if (-not $KeyPath) { return $null }
  $p = $KeyPath
  if ($p -like 'Registry::*') { $p = $p -replace '^Registry::','' }
  $p = $p.Replace('HKLM:\','HKEY_LOCAL_MACHINE\')
  $p = $p.Replace('HKCU:\','HKEY_CURRENT_USER\')
  $p = $p.Replace('HKCR:\','HKEY_CLASSES_ROOT\')
  $p = $p.Replace('HKU:\','HKEY_USERS\')
  $p = $p.Replace('HKCC:\','HKEY_CURRENT_CONFIG\')
  return $p
}
function Export-Reg([string]$RegPath,[string]$OutFile){
  try {
    [void](Ensure-Directory (Split-Path -Parent $OutFile))
    $res = Invoke-RegExe -Arguments @('export', $RegPath, $OutFile, '/y')
    if ($res -eq $true) { return $true, $OutFile }
    return $false, 'reg-export-failed'
  } catch {
    return $false, $_.Exception.Message
  }
}
function Find-MpCmdRun {
  $cands = @(
    "$env:ProgramFiles\Windows Defender\MpCmdRun.exe",
    "$env:ProgramFiles\Microsoft Defender\MpCmdRun.exe"
  )
  foreach ($c in $cands) {
    if (Test-Path -LiteralPath $c) { return $c }
  }
  return $null
}
# -----------------------------
# Proof object (data only)
# -----------------------------
$Proof = [ordered]@{
  Time      = (Get-Date).ToString('s')
  Hostname  = $env:COMPUTERNAME
  User      = $env:USERNAME
  IsAdmin   = (Test-IsAdmin)
  Params    = @{
    CatalogPath      = (Get-OrDefault $CatalogPath "")
    ConfigPath       = (Get-OrDefault $ConfigPath "")
    Remediate        = [bool]$Remediate
    CollectEvidence  = [bool]$CollectEvidence
    ScanType         = $ScanType
    CustomScanPaths  = @($CustomScanPaths)
    Strict           = [bool]$Strict
    PassThru         = [bool]$PassThru
  }
  Catalog   = @{ Source = ""; Errors = @() }
  Scan      = @{ Requested = $ScanType; Result = 'not-run'; MpCmdRun = $null }
  Findings  = @{
    Files     = @()
    Registry  = @()
    Services  = @()
    Tasks     = @()
    Processes = @()
    Network   = @()
  }
  Actions   = @()
  Errors    = @()
  SourceStatus = @{}
  Summary   = @{}
}
$script:Findings = Get-FindingsList

function Add-IocSourceStatus {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Name,
    [Parameter(Mandatory)][bool]$Attempted,
    [Parameter(Mandatory)][bool]$Succeeded,
    [string]$ErrorMessage
  )

  $Proof.SourceStatus[$Name] = [ordered]@{
    Attempted = $Attempted
    Succeeded = $Succeeded
    Error = $ErrorMessage
  }

  if ($Attempted -and -not $Succeeded -and -not [string]::IsNullOrWhiteSpace($ErrorMessage)) {
    $msg = "{0} source failed: {1}" -f $Name, $ErrorMessage
    $Proof.Errors += $msg
    [void](Add-Finding -Code 'IOC-SourceFailed' -Severity 'High' -Message $msg -Extra @{ Source = $Name })
  }
}

if (-not (Ensure-EventSource)) {
  Write-Warning "EventSource could not be registered. EventLog tracing will be unavailable."
}
$ok       = $true
$foundAny = $false
$outFile  = $DefaultProofOutFile
$evDir    = $DefaultEvidenceDir
$cat      = $null
try {
  $catLoad = Load-Catalog -CatalogPath $CatalogPath -ConfigPath $ConfigPath
  $cat = $catLoad.Catalog
  $Proof.Catalog.Source = $catLoad.Source
  $Proof.Catalog.Errors = @($catLoad.Errors)
  $proofObj = Get-ObjPropValue $cat 'Proof'
  if ($proofObj) { $outFile = Get-ObjPropValue $proofObj 'OutFile' }
  $outFile = [string](Get-OrDefault $outFile $DefaultProofOutFile)
  $evDir = Get-OrDefault (Get-ObjPropValue $cat 'EvidenceDir') $DefaultEvidenceDir
  $evDir = [string]$evDir
  if ($CollectEvidence) { [void](Ensure-Directory $evDir) }
  [void](Ensure-Directory (Split-Path -Parent $outFile))
  # Defender scan
  try {
    $mp = Find-MpCmdRun
    $scanInfo = @{ Requested = $ScanType; Result = "skipped"; MpCmdRun = $mp }
    $Proof['Scan'] = $scanInfo
    if ($mp) {
      if ($ScanType -eq 'None') {
        if ($CustomScanPaths -and $CustomScanPaths.Count -gt 0) {
          $expanded = @()
          foreach ($c in $CustomScanPaths) {
            $e = Expand-Env $c
            if ($e -and (Test-Path -LiteralPath $e)) { $expanded += $e }
          }
          if ($expanded.Count -gt 0) {
            $results = @()
            foreach ($item in $expanded) {
              $scanArgs = @("-Scan","-ScanType","3","-File",$item)
              $p = Start-Process -FilePath $mp -ArgumentList $scanArgs -PassThru -Wait -WindowStyle Hidden
              $results += ("custom:{0} exit:{1}" -f $item, $p.ExitCode)
              if ($p.ExitCode -eq 2) {
                $foundAny = $true
                [void](Add-Finding -FindingList $script:Findings -Code 'IOC-DefenderDetection' -Severity 'High' `
                    -Message "Defender scan reported threat(s) detected (MpCmdRun exit 2)." `
                    -Extra @{ MpCmdRun = $mp; ScanType = 'Custom'; CustomScanPath = $item })
              } elseif ($p.ExitCode -ne 0) {
                $ok = $false
                [void](Add-Finding -FindingList $script:Findings -Code 'IOC-DefenderError' -Severity 'Medium' `
                    -Message ("Defender scan exited with unexpected code {0}." -f $p.ExitCode) `
                    -Extra @{ ExitCode = $p.ExitCode; MpCmdRun = $mp; ScanType = 'Custom'; CustomScanPath = $item })
              }
            }
            $scanInfo.Result = ($results -join "; ")
          } else {
            $scanInfo.Result = "skipped(no valid CustomScanPaths)"
          }
        }
      } else {
        $type = 2
        if ($ScanType -eq 'Quick') { $type = 1 }
        $scanArgs = @("-Scan","-ScanType", "$type")
        $p = Start-Process -FilePath $mp -ArgumentList $scanArgs -PassThru -Wait -WindowStyle Hidden
        $scanInfo.Result = "exit:$($p.ExitCode)"
        if ($p.ExitCode -eq 2) {
          $foundAny = $true
          [void](Add-Finding -FindingList $script:Findings -Code 'IOC-DefenderDetection' -Severity 'High' `
              -Message "Defender scan reported threat(s) detected (MpCmdRun exit 2)." `
              -Extra @{ MpCmdRun = $mp; ScanType = $ScanType })
        } elseif ($p.ExitCode -ne 0) {
          $ok = $false
          [void](Add-Finding -FindingList $script:Findings -Code 'IOC-DefenderError' -Severity 'Medium' `
              -Message ("Defender scan exited with unexpected code {0}." -f $p.ExitCode) `
              -Extra @{ ExitCode = $p.ExitCode; MpCmdRun = $mp; ScanType = $ScanType })
        }
      }
    }
    $Proof['Scan'] = $scanInfo
  } catch {
    if (-not $Proof['Scan'] -or -not $Proof['Scan'].ContainsKey('Requested')) {
      $Proof['Scan'] = @{ Requested = $ScanType; Result = 'failed'; MpCmdRun = $null }
    }
    $Proof.Errors += "Defender scan failed: $($_.Exception.Message)"
    $ok = $false
  }
  # File IOCs
  foreach ($f in @($cat.Files)) {
    $pathVal = Get-ObjPropValue $f 'Path'
    $p = Expand-Env ([string]$pathVal)
    if (-not $p) { continue }
    if (-not (Test-Path -LiteralPath $p)) { continue }
    $sha = Get-FileSha256 -Path $p
    $pub,$valid = Get-FilePublisher $p
    $fSha    = [string](Get-ObjPropValue $f 'Sha256')
    $fSigner = [string](Get-ObjPropValue $f 'Signer')
    $matchSha = ($fSha -and $sha -and ($sha -ieq $fSha))
    $matchSig = ($fSigner -and $pub -and ($pub -like ("*{0}*" -f $fSigner)))
    $hit = $false
    if ($fSha) { $hit = $matchSha }
    elseif ($fSigner) { $hit = $matchSig }
    else { $hit = $false }
    if ($hit) {
      $foundAny = $true
      $evPath = $null
      if ($CollectEvidence) {
        $okc,$ev = Copy-ToEvidence -SourcePath $p -EvidenceBaseDir $evDir
        if ($okc) { $evPath = $ev } else { $Proof.Errors += "Evidence copy failed ($p): $ev"; $ok = $false }
      }
      $finding = [ordered]@{
        Kind      = 'File'
        Path      = $p
        Sha256    = $sha
        Publisher = $pub
        Signed    = $valid
        Evidence  = $evPath
        Action    = (Get-ObjPropValue $f 'Action')
        Match     = [ordered]@{ Sha256 = $matchSha; Signer = $matchSig }
      }
      $Proof.Findings.Files += $finding
      [void](Add-Finding -Code 'IOC-FileMatch' -Severity 'High' -Message "IOC file match: $p" -Extra $finding)
    }
  }
  foreach ($g in @($cat.FileGlobs)) {
    $globVal = Get-ObjPropValue $g 'Glob'
    $glob    = Expand-Env ([string]$globVal)
    if (-not $glob) { continue }
    $dir = Split-Path $glob -Parent
    $pat = Split-Path $glob -Leaf
    if (-not (Test-Path -LiteralPath $dir)) { continue }
    $hits = Get-ChildItem -LiteralPath $dir -Filter $pat -File -ErrorAction SilentlyContinue
    foreach ($h in $hits) {
      $sha = Get-FileSha256 -Path $h.FullName
      $pub,$valid = Get-FilePublisher $h.FullName
      $gSha    = [string](Get-ObjPropValue $g 'Sha256')
      $gSigner = [string](Get-ObjPropValue $g 'Signer')
      if ($gSha -and $sha -and ($sha -ine $gSha)) { continue }
      if ($gSigner -and $pub -and ($pub -notlike ("*{0}*" -f $gSigner))) { continue }
      if (-not $gSha -and -not $gSigner) { continue }
      $foundAny = $true
      $evPath = $null
      if ($CollectEvidence) {
        $okc,$ev = Copy-ToEvidence -SourcePath $h.FullName -EvidenceBaseDir $evDir
        if ($okc) { $evPath = $ev } else { $Proof.Errors += "Evidence copy failed ($($h.FullName)): $ev"; $ok = $false }
      }
      $Proof.Findings.Files += [ordered]@{
        Kind      = 'Glob'
        Path      = $h.FullName
        Sha256    = $sha
        Publisher = $pub
        Signed    = $valid
        Evidence  = $evPath
        Action    = (Get-ObjPropValue $g 'Action')
      }
    }
  }
  # Registry IOCs
  foreach ($r in @($cat.Registry)) {
    $path = [string](Get-ObjPropValue $r 'Path')
    if (-not $path) { continue }
    $okReg = $false
    $data  = $null
    $key   = $null
    $value = $null
    try {
      $key   = Split-Path $path -Parent
      $value = Split-Path $path -Leaf
      $prop  = Get-ItemProperty -Path $key -ErrorAction Stop
      if ($prop.PSObject.Properties.Name -contains $value) {
        $data  = $prop.$value
        $okReg = $true
      }
    } catch { $okReg = $false }
    if ($okReg) {
      $regexOk = $true
      $dr = [string](Get-ObjPropValue $r 'DataRegex')
      if ($dr) { $regexOk = ($data -match $dr) }
      if ($regexOk) {
        $foundAny = $true
        $regExp = $null
        if ($CollectEvidence) {
          $regExePath = Convert-RegProviderToRegExePath $key
          $safeKey    = ($key -replace '[:\\]','_')
          $out        = Join-Path $evDir ("reg-{0}.reg" -f $safeKey)
          $okx,$exportOut = Export-Reg -RegPath $regExePath -OutFile $out
          if ($okx) { $regExp = $exportOut } else { $Proof.Errors += "Reg export failed ($key): $exportOut"; $ok = $false }
        }
        $finding = [ordered]@{
          Path     = $path
          Data     = $data
          Evidence = $regExp
          Action   = (Get-ObjPropValue $r 'Action')
        }
        $Proof.Findings.Registry += $finding
        [void](Add-Finding -Code 'IOC-RegistryMatch' -Severity 'High' -Message "IOC registry match: $path" -Extra $finding)
        if ($Remediate -and ((Get-ObjPropValue $r 'Action') -eq 'neutralize')) {
          try {
            if ($PSCmdlet.ShouldProcess($path, 'Neutralize registry value')) {
              Remove-ItemProperty -Path $key -Name $value -Force -ErrorAction Stop
              $Proof.Actions += "Registry neutralized: $path"
            } else {
              $Proof.Actions += "Registry neutralize skipped by ShouldProcess: $path"
            }
          } catch {
            $Proof.Errors += "Registry neutralize failed ($path): $($_.Exception.Message)"
            $ok = $false
          }
        }
      }
    }
  }
  # Services
  $servicesRequested = (@($cat.Services).Count -gt 0)
  $servicesSourceFailed = $false
  foreach ($s in @($cat.Services)) {
    $name = [string](Get-ObjPropValue $s 'Name')
    if (-not $name) { continue }
    try {
      $escapedSvcName = $name -replace "'", "''"
      $svc = Get-CimInstance -ClassName Win32_Service -Filter ("Name='{0}'" -f $escapedSvcName) -ErrorAction Stop
      $img = $svc.PathName
      $match = $true
      $imgRx = [string](Get-ObjPropValue $s 'ImagePathRegex')
      if ($imgRx) { if ($img -notmatch $imgRx) { $match = $false } }
      if ($match) {
        $foundAny = $true
        $action = [string](Get-ObjPropValue $s 'Action')
        $finding = [ordered]@{
          Name        = $svc.Name
          DisplayName = $svc.DisplayName
          State       = $svc.State
          StartMode   = $svc.StartMode
          ImagePath   = $img
          Action      = $action
        }
        $Proof.Findings.Services += $finding
        [void](Add-Finding -Code 'IOC-ServiceMatch' -Severity 'High' -Message "IOC service match: $($svc.Name)" -Extra $finding)
        if ($Remediate -and ($action -in @('disable','stop'))) {
          try {
            if ($PSCmdlet.ShouldProcess($svc.Name, "Contain service ($action)")) {
              if ($svc.State -ne 'Stopped') { Stop-Service -Name $svc.Name -Force -ErrorAction Stop }
              if ($action -eq 'disable')    { Set-Service -Name $svc.Name -StartupType Disabled -ErrorAction Stop }
              $Proof.Actions += "Service remediated: $($svc.Name) ($action)"
            } else {
              $Proof.Actions += "Service remediation skipped by ShouldProcess: $($svc.Name) ($action)"
            }
          } catch {
            $Proof.Errors += "Service remediation failed ($($svc.Name)): $($_.Exception.Message)"
            $ok = $false
          }
        }
      }
    } catch {
      $servicesSourceFailed = $true
      Add-IocSourceStatus -Name 'Services' -Attempted $true -Succeeded $false -ErrorMessage $_.Exception.Message
      Write-Warning "IOC service sweep error: $($_.Exception.Message)"
    }
  }
  if ($servicesRequested -and -not $servicesSourceFailed) {
    Add-IocSourceStatus -Name 'Services' -Attempted $true -Succeeded $true
  }
  # Scheduled tasks
  $allTasks = @()
  $tasksRequested = (@($cat.ScheduledTasks).Count -gt 0)
  if ($tasksRequested) {
    try {
      $allTasks = Get-ScheduledTask -ErrorAction Stop
      Add-IocSourceStatus -Name 'ScheduledTasks' -Attempted $true -Succeeded $true
    } catch {
      Add-IocSourceStatus -Name 'ScheduledTasks' -Attempted $true -Succeeded $false -ErrorMessage $_.Exception.Message
      Write-Warning "IOC scheduled task sweep error: $($_.Exception.Message)"
      $allTasks = @()
    }
  }
  foreach ($t in @($cat.ScheduledTasks)) {
    $rx = [string](Get-ObjPropValue $t 'Regex')
    if (-not $rx) { continue }
    foreach ($task in $allTasks) {
      $full = $task.TaskPath + $task.TaskName
      if ($full -match $rx) {
        $foundAny = $true
        $state = "Unknown"
        try {
          $ti = Get-ScheduledTaskInfo -TaskName $task.TaskName -TaskPath $task.TaskPath -ErrorAction Stop
          if ($ti -and $ti.State) { $state = $ti.State.ToString() }
        } catch { $state = "Unknown" }
        $action = [string](Get-ObjPropValue $t 'Action')
        $finding = [ordered]@{
          Path    = $full
          Enabled = [bool]$task.Enabled
          State   = $state
          Action  = $action
        }
        $Proof.Findings.Tasks += $finding
        [void](Add-Finding -Code 'IOC-TaskMatch' -Severity 'High' -Message "IOC task match: $full" -Extra $finding)
        if ($Remediate -and ($action -eq 'disable')) {
          try {
            if ($PSCmdlet.ShouldProcess($full, 'Disable scheduled task')) {
              Disable-ScheduledTask -TaskName $task.TaskName -TaskPath $task.TaskPath -ErrorAction Stop | Out-Null
              $Proof.Actions += "Task disabled: $full"
            } else {
              $Proof.Actions += "Task disable skipped by ShouldProcess: $full"
            }
          } catch {
            $Proof.Errors += "Task disable failed ($full): $($_.Exception.Message)"
            $ok = $false
          }
        }
      }
    }
  }
  # Processes
  $processesRequested = (@($cat.Processes).Count -gt 0)
  $procs = @()
  if ($processesRequested) {
    try {
      $procs = Get-Process -ErrorAction Stop
      Add-IocSourceStatus -Name 'Processes' -Attempted $true -Succeeded $true
    } catch {
      Add-IocSourceStatus -Name 'Processes' -Attempted $true -Succeeded $false -ErrorMessage $_.Exception.Message
      Write-Warning "IOC process sweep error: $($_.Exception.Message)"
      $procs = @()
    }
  }
  foreach ($pRule in @($cat.Processes)) {
    $imgRx = [string](Get-ObjPropValue $pRule 'ImageRegex')
    if (-not $imgRx) { continue }
    foreach ($pr in $procs) {
      $img = $null
      try { $img = $pr.Path } catch { $img = $null }
      if (-not $img) { continue }
      if ($img -match $imgRx) {
        $sha = Get-ProcessImageSha256 -ProcessId $pr.Id
        $pub,$valid = Get-FilePublisher $img
        $signer = [string](Get-ObjPropValue $pRule 'Signer')
        if ($signer -and $pub -and ($pub -notlike ("*{0}*" -f $signer))) { continue }
        $foundAny = $true
        $finding = [ordered]@{
          Name      = $pr.Name
          Id        = $pr.Id
          Path      = $img
          Sha256    = $sha
          Publisher = $pub
          Signed    = $valid
          Action    = (Get-ObjPropValue $pRule 'Action')
        }
        $Proof.Findings.Processes += $finding
        [void](Add-Finding -Code 'IOC-ProcessMatch' -Severity 'High' -Message "IOC process match: $($pr.Name) ($($pr.Id))" -Extra $finding)
      }
    }
  }
  # Network (IPs + DNS cache)
  $nFind = @()
  $ips = @($cat.IPs)
  if ($ips.Count -gt 0) {
    $conns = @()
    try {
      $conns = Get-NetTCPConnection -State Established,SynSent,SynReceived -ErrorAction Stop
      Add-IocSourceStatus -Name 'NetworkConnections' -Attempted $true -Succeeded $true
    } catch {
      Add-IocSourceStatus -Name 'NetworkConnections' -Attempted $true -Succeeded $false -ErrorMessage $_.Exception.Message
      Write-Warning "IOC network connection sweep error: $($_.Exception.Message)"
      $conns = @()
    }
    foreach ($c in $conns) {
      if ($ips -contains $c.RemoteAddress) {
        $foundAny = $true
        $pName = $null
        try { $pName = (Get-Process -Id $c.OwningProcess -ErrorAction Stop).Name } catch { $pName = $null }
        $finding = [ordered]@{
          Kind          = 'IP'
          Remote        = $c.RemoteAddress
          Local         = $c.LocalAddress
          LPort         = $c.LocalPort
          RPort         = $c.RemotePort
          State         = $c.State
          OwningProcess = $c.OwningProcess
          ProcessName   = $pName
        }
        $nFind += $finding
        [void](Add-Finding -Code 'IOC-NetworkIPMatch' -Severity 'High' -Message "IOC network match: IP $($c.RemoteAddress)" -Extra $finding)
      }
    }
  }
  $domains = @($cat.Domains)
  if ($domains.Count -gt 0) {
    try {
      $dns = Get-DnsClientCache -ErrorAction Stop
      Add-IocSourceStatus -Name 'DnsCache' -Attempted $true -Succeeded $true
      foreach ($d in $domains) {
        foreach ($h in $dns) {
          $entry = Get-ObjPropValue $h 'Entry'
          if (-not $entry) { $entry = Get-ObjPropValue $h 'Name' }
          if (-not $entry) { $entry = Get-ObjPropValue $h 'RecordName' }
          if ($entry -and ([string]$entry -ieq [string]$d)) {
            $foundAny = $true
            $typ = Get-ObjPropValue $h 'Type'
            if (-not $typ) { $typ = Get-ObjPropValue $h 'RecordType' }
            $dat = Get-ObjPropValue $h 'Data'
            $finding = [ordered]@{
              Kind  = 'Domain'
              Entry = $entry
              Type  = $typ
              Data  = $dat
            }
            $nFind += $finding
            [void](Add-Finding -Code 'IOC-NetworkDomainMatch' -Severity 'High' -Message "IOC network match: Domain $entry" -Extra $finding)
          }
        }
      }
    } catch {
      Add-IocSourceStatus -Name 'DnsCache' -Attempted $true -Succeeded $false -ErrorMessage $_.Exception.Message
      Write-Warning "IOC network DNS cache check error: $($_.Exception.Message)"
    }
  }
  if ($nFind.Count -gt 0) { $Proof.Findings.Network = $nFind }
  Save-Json -InputObject $Proof -Path $outFile -Depth 50
  if ($foundAny -or (@($Proof.Errors).Count -gt 0) -or $Strict) {
    $msg = "IOC sweep: findings/errors detected. Proof: $outFile"
    if (@($Proof.Errors).Count -gt 0) { $msg += " | Errors: " + ($Proof.Errors -join ' | ') }
    Write-HealthEvent -Id 10010 -Msg $msg -Level 'Warning'
  } else {
    Write-HealthEvent -Id 10000 -Msg ("IOC sweep: OK (no findings). Proof: $outFile") -Level 'Information'
  }
} catch {
  $ok = $false
  $err = "IOC sweep failed: $($_.Exception.Message)"
  $Proof.Errors += $err
  try { Save-Json -InputObject $Proof -Path $outFile -Depth 50 } catch {
    Write-Verbose ("Partial IOC proof save failed: {0}" -f $_.Exception.Message)
  }
  Write-HealthEvent -Id 10010 -Msg $err -Level 'Error'
}
# -----------------------------
# Summary (data + pretty host output)
# -----------------------------
$filesCount = @($Proof.Findings.Files).Count
$regCount   = @($Proof.Findings.Registry).Count
$svcCount   = @($Proof.Findings.Services).Count
$taskCount  = @($Proof.Findings.Tasks).Count
$procCount  = @($Proof.Findings.Processes).Count
$netCount   = @($Proof.Findings.Network).Count
$actCount   = @($Proof.Actions).Count
$errCount   = @($Proof.Errors).Count
$totalFindings = $filesCount + $regCount + $svcCount + $taskCount + $procCount + $netCount
$exitCode = 0
if (-not ($ok -and -not $foundAny -and ($errCount -eq 0))) { $exitCode = 1 }
$Proof.Summary = @{
  CatalogSource  = $Proof.Catalog.Source
  FindingsTotal  = $totalFindings
  Files          = $filesCount
  Registry       = $regCount
  Services       = $svcCount
  Tasks          = $taskCount
  Processes      = $procCount
  Network        = $netCount
  Actions        = $actCount
  Errors         = $errCount
  ExitCode       = $exitCode
  ProofFile      = $outFile
  EvidenceDir    = $evDir
}
# Pretty output
Write-UiHeader "IOC Sweep (Defender) - Result"
Write-KeyValue "Time"     $Proof.Time     -ValueStyle Gray
Write-KeyValue "Host"     $Proof.Hostname -ValueStyle Gray
Write-KeyValue "User"     $Proof.User     -ValueStyle Gray
$adminColor = [ConsoleColor]::Yellow
if ($Proof.IsAdmin) { $adminColor = [ConsoleColor]::Green }
Write-KeyValue "Admin" ([string]$Proof.IsAdmin) -ValueStyle $adminColor
$catColor = [ConsoleColor]::Green
if ($Proof.Catalog.Source -eq 'Default') { $catColor = [ConsoleColor]::Yellow }
Write-KeyValue "Catalog" $Proof.Catalog.Source -ValueStyle $catColor
if (@($Proof.Catalog.Errors).Count -gt 0) {
  Write-UiStatus -Label "Catalog warnings" -State "WARN" -Detail ("{0} issue(s)" -f @($Proof.Catalog.Errors).Count)
  foreach ($ce in $Proof.Catalog.Errors) { Write-UiBullet $ce DarkGray }
} else {
  Write-UiStatus -Label "Catalog load" -State "OK" -Detail "No issues"
}
$scanReq = Get-OrDefault $Proof.Scan.Requested "n/a"
$scanRes = Get-OrDefault $Proof.Scan.Result "n/a"
Write-KeyValue "Scan" ("{0} -> {1}" -f $scanReq, $scanRes) -ValueStyle Cyan
Write-KeyValue "Proof" $outFile -ValueStyle Gray
Write-KeyValue "Evidence" $evDir -ValueStyle Gray
Write-UiLine ""
if ($exitCode -eq 0) {
  Write-UiStatus -Label "Overall status" -State "OK" -Detail "No findings and no errors"
} elseif ($errCount -gt 0) {
  Write-UiStatus -Label "Overall status" -State "FAIL" -Detail "Errors occurred (check proof file)"
} else {
  Write-UiStatus -Label "Overall status" -State "WARN" -Detail "Findings detected (check proof file)"
}
Write-UiLine ""
Write-UiLine "Findings breakdown:" DarkGray
$fc = [ConsoleColor]::Green; if ($filesCount -gt 0) { $fc = [ConsoleColor]::Yellow }
$rc = [ConsoleColor]::Green; if ($regCount -gt 0)   { $rc = [ConsoleColor]::Yellow }
$sc = [ConsoleColor]::Green; if ($svcCount -gt 0)   { $sc = [ConsoleColor]::Yellow }
$tc = [ConsoleColor]::Green; if ($taskCount -gt 0)  { $tc = [ConsoleColor]::Yellow }
$pc = [ConsoleColor]::Green; if ($procCount -gt 0)  { $pc = [ConsoleColor]::Yellow }
$nc = [ConsoleColor]::Green; if ($netCount -gt 0)   { $nc = [ConsoleColor]::Yellow }
Write-UiBullet ("Files:     {0}" -f $filesCount) $fc
Write-UiBullet ("Registry:  {0}" -f $regCount)   $rc
Write-UiBullet ("Services:  {0}" -f $svcCount)   $sc
Write-UiBullet ("Tasks:     {0}" -f $taskCount)  $tc
Write-UiBullet ("Processes: {0}" -f $procCount)  $pc
Write-UiBullet ("Network:   {0}" -f $netCount)   $nc
Write-UiLine ""
$actColor = [ConsoleColor]::Green; if ($actCount -gt 0) { $actColor = [ConsoleColor]::Yellow }
$errColor = [ConsoleColor]::Green; if ($errCount -gt 0) { $errColor = [ConsoleColor]::Red }
$exitColor = [ConsoleColor]::Green; if ($exitCode -ne 0) { $exitColor = [ConsoleColor]::Yellow }
Write-KeyValue "Actions"  ([string]$actCount) -ValueStyle $actColor
Write-KeyValue "Errors"   ([string]$errCount) -ValueStyle $errColor
Write-KeyValue "ExitCode" ([string]$exitCode) -ValueStyle $exitColor
if ($errCount -gt 0) {
  Write-UiLine ""
  Write-UiStatus -Label "Error details" -State "FAIL"
  foreach ($e in $Proof.Errors) { Write-UiBullet $e Red }
}
# V2 output contract
$resultToken = if ($exitCode -ne 0) { 'FAIL' } elseif ($script:Findings.Count -gt 0) { 'WARN' } else { 'OK' }
$v2Result = Get-V2ResultObject -ScriptName '11-IOC-Sweep-Defender.ps1' -Mode $Mode -Result $resultToken -Findings $script:Findings.ToArray() -Summary $Proof -Metadata @{}
Write-ResultObject -ResultObject $v2Result -OutputFormat $OutputFormat -OutputPath $OutputPath
if ($PassThru) { $v2Result }
exit $exitCode
