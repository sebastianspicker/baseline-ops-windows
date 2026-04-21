#requires -version 5.1
<#
.SYNOPSIS
  Performs an IOC (Indicator of Compromise) sweep on the local Windows host, optionally runs a Microsoft Defender on-demand scan, optionally collects evidence, and writes an audit-ready JSON proof file.
.DESCRIPTION
  This script loads an IOC catalog from JSON (or uses a built-in default catalog if no JSON is available), then evaluates multiple IOC types on the local system.
  Covered IOC checks:
  - Files: exact file paths validated by SHA256 hash and/or certificate publisher (Authenticode).
  - FileGlobs: wildcard patterns resolved to files, then validated by SHA256 hash and/or publisher.
  - Registry: registry value presence with optional data regex match.
  - Services: service existence with optional image path regex match.
  - ScheduledTasks: tasks matched by regex against full task path + name.
  - Processes: running processes matched by image path regex and optional publisher constraint.
  - Network: remote IP matches against established TCP connections; domain matches against the DNS client cache.
  Optional actions:
  - Defender scan: Quick/Full scan, or Custom scan for specific paths when ScanType is set to None and CustomScanPaths are provided.
  - Evidence collection: copies matched files and exports registry keys to an evidence directory.
  - Remediation: non-destructive containment actions based on catalog rule actions (for example: disable a task, stop/disable a service, remove a registry value when Action=neutralize).
  Output behavior:
  - The script prints a human-friendly, colorized summary to the console.
  - The script writes a JSON proof file that contains parameters, scan results, findings, actions taken, errors, and a summary.
  - By default, the script does not write objects to the success pipeline (to keep pipelines clean); use -PassThru to output the final Proof object.
.PARAMETER CatalogPath
  Path to an IOC catalog JSON file.
  If specified and loadable, this catalog is used.
.PARAMETER ConfigPath
  Path to a configuration JSON file that can provide a catalog location (expected property: IOC.CatalogPath).
  If CatalogPath is not provided or cannot be loaded, the script attempts to read ConfigPath and then load the catalog from IOC.CatalogPath.
.PARAMETER ScanType
  Controls Microsoft Defender scan execution.
  Valid values:
  - Full  : Runs a Defender full scan.
  - Quick : Runs a Defender quick scan.
  - None  : Skips standard scan types; can still perform custom scans if CustomScanPaths are provided.
.PARAMETER CustomScanPaths
  One or more file/folder paths to scan with Microsoft Defender custom scan mode.
  Used only when ScanType is set to None.
  Environment variables in paths are expanded before validation.
.PARAMETER CollectEvidence
  Enables evidence collection for matched IOCs.
  Evidence collection includes:
  - Copying matched files into the evidence directory.
  - Exporting registry keys (containing matched values) into .reg files.
.PARAMETER Remediate
  Enables remediation/containment actions for matched IOCs when the corresponding catalog rule requests an action.
  Actions are intentionally non-destructive and limited to:
  - Services: stop and/or disable (based on rule action).
  - Scheduled tasks: disable (based on rule action).
  - Registry values: remove only when Action is exactly 'neutralize'.
.PARAMETER Strict
  Controls the overall "signal" behavior.
  When enabled, the script will treat the run as noteworthy even if there are no findings (for example, for compliance/audit runs), and will emit the warning event path instead of the OK event path.
.PARAMETER PassThru
  Outputs the final Proof object to the success pipeline.
  Use this when you want to programmatically consume results, for example:
  - ConvertTo-Json
  - Export-Csv
  - Where-Object filtering
.PARAMETER Mode
  Execution mode. 'Audit' reports only; 'Remediate' applies changes.
.PARAMETER OutputFormat
  Output format: Console, Json, Csv, or None.
.PARAMETER OutputPath
  File path for Json/Csv output.
.PARAMETER Quiet
  Suppress console output.
.PARAMETER NoColor
  Disable colored output.
.OUTPUTS
  By default: none (no objects are written to the success pipeline).
  With -PassThru: a single structured object (the Proof object) containing:
  - Runtime context (time, hostname, user, admin state)
  - Input parameters
  - Catalog source metadata
  - Defender scan result (if executed)
  - Findings by category
  - Actions performed
  - Errors encountered
  - Summary including ExitCode
.NOTES
  Catalog loading fallback order:
  1) CatalogPath (if provided and readable)
  2) ConfigPath -> IOC.CatalogPath (if provided and readable)
  3) Built-in default catalog (empty rule sets)
  Exit codes:
  - 0: No findings and no errors.
  - 1: Findings and/or errors occurred (or Strict triggered a non-OK outcome).
  Evidence handling:
  - Evidence collection is best-effort; failures to copy/export are recorded in the proof Errors array.
  - Evidence paths are stored in findings when available.
  Console output:
  - The console summary is intended for operators and is produced via host-only output functions.
  - Structured results are persisted to JSON and optionally emitted via -PassThru.
.EXAMPLE
  .\11-IOC-Sweep-Defender.ps1
  Runs the sweep with the default scan type (Full) and uses JSON configuration/catalog if available; otherwise uses the built-in default catalog.
  Writes the proof JSON file and prints the console summary.
.EXAMPLE
  .\11-IOC-Sweep-Defender.ps1 -CatalogPath "PATH/TO/JSON/ioc-catalog.json" -CollectEvidence
  Loads a specific IOC catalog and collects evidence for any matches.
.EXAMPLE
  .\11-IOC-Sweep-Defender.ps1 -ScanType Quick
  Runs the IOC sweep and performs a Defender quick scan.
.EXAMPLE
  .\11-IOC-Sweep-Defender.ps1 -ScanType None -CustomScanPaths "C:\Temp","C:\Users\Public" -CollectEvidence
  Runs the IOC sweep and performs Defender custom scans of the specified paths, then collects evidence for any IOC matches.
.EXAMPLE
  .\11-IOC-Sweep-Defender.ps1 -Remediate -Strict
  Runs the sweep and applies non-destructive remediation actions as defined by the catalog rules.
  Strict mode forces a "noteworthy" run classification even if no findings are detected.
.EXAMPLE
  $proof = .\11-IOC-Sweep-Defender.ps1 -PassThru
  $proof.Findings.Files | Where-Object { $_.Signed -eq $false } | ConvertTo-Json -Depth 5
  Runs the sweep and returns the proof object for further filtering and conversion.
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
Import-Module (Join-Path $script:LibPath 'Common.psm1') -Force
Import-Module (Join-Path $script:LibPath 'Output.psm1') -Force
Import-Module (Join-Path $script:LibPath 'EventLog.psm1') -Force
Import-Module (Join-Path $script:LibPath 'Results.psm1') -Force
Import-Module (Join-Path $script:LibPath 'Evidence.psm1') -Force
Import-Module (Join-Path $script:LibPath 'External.psm1') -Force
Import-Module (Join-Path $script:LibPath 'JsonCatalog.psm1') -Force
Import-Module (Join-Path $script:LibPath Serialization.psm1) -Force
# v2-init
$null = $Mode, $ConfigPath, $OutputFormat, $OutputPath, $PassThru, $Strict, $Quiet, $NoColor
$script:__V2Context = @{
  Mode = $Mode
  ConfigPath = $ConfigPath
  OutputFormat = $OutputFormat
  OutputPath = $OutputPath
  PassThru = [bool]$PassThru
  Strict = [bool]$Strict
  Quiet = [bool]$Quiet
  NoColor = [bool]$NoColor
}
$Remediate = ($Mode -eq 'Remediate')
if ($Quiet) {
  $InformationPreference = 'SilentlyContinue'
  $VerbosePreference = 'SilentlyContinue'
}
if ($NoColor) {
  $script:NoColor = $true
}
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
  $result = New-V2ResultObject -ScriptName '11-IOC-Sweep-Defender.ps1' -Mode $Mode -Result 'OK' -Findings @() -Summary $summary -Metadata @{ UnsupportedHost = $true }
  Write-ResultObject -ResultObject $result -OutputFormat $OutputFormat -OutputPath $OutputPath
  if ($PassThru) { $result }
  exit 0
}

Set-StrictMode -Version Latest
# -----------------------------
# Globals / Defaults (anonymized)
# -----------------------------
$DefaultProofOutFile = $null
$DefaultEvidenceDir  = $null
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
  } catch { <# best-effort: property access on dynamic object #> }
  return $null
}
function Get-OrDefault([object]$Value, [object]$Default){
  if ($null -ne $Value -and "$Value" -ne "") { return $Value }
  return $Default
}
function New-DefaultCatalog {
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
  $sanitizedCatalog = Sanitize-Path -Path $CatalogPath -MustExist
  if ($sanitizedCatalog) {
    $c = Read-JsonFileSafe -Path $sanitizedCatalog
    if ($c) { $res.Catalog = $c; $res.Source = 'CatalogPath'; return $res }
    $res.Errors += ("CatalogPath not loaded: {0}" -f $sanitizedCatalog)
  }
  $cfg = $null
  $sanitizedConfig = Sanitize-Path -Path $ConfigPath -MustExist
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
  $res.Catalog = (New-DefaultCatalog)
  $res.Source  = 'Default'
  return $res
}
function Get-ProcessImageSha256([int]$ProcessId){
  try {
    $p = Get-Process -Id $ProcessId -ErrorAction Stop
    if ($p.Path) { return Get-FileSha256 -Path $p.Path }
  } catch { <# best-effort: process may have exited or path may be inaccessible #> }
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
    Ensure-Directory (Split-Path -Parent $OutFile)
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
  Scan      = @{}
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
  Summary   = @{}
}
$script:Findings = New-FindingsList
Ensure-EventSource
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
  if ($CollectEvidence) { Ensure-Directory $evDir }
  Ensure-Directory (Split-Path -Parent $outFile)
  # Defender scan
  try {
    $mp = Find-MpCmdRun
    $scanInfo = @{ Requested = $ScanType; Result = "skipped"; MpCmdRun = $mp }
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
      }
    }
    $Proof.Scan = $scanInfo
  } catch {
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
      Add-Finding -Code 'IOC-FileMatch' -Severity 'High' -Message "IOC file match: $p" -Extra $finding
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
        Add-Finding -Code 'IOC-RegistryMatch' -Severity 'High' -Message "IOC registry match: $path" -Extra $finding
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
        Add-Finding -Code 'IOC-ServiceMatch' -Severity 'High' -Message "IOC service match: $($svc.Name)" -Extra $finding
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
    } catch { Write-Warning "IOC service sweep error: $($_.Exception.Message)" }
  }
  # Scheduled tasks
  $allTasks = @()
  try { $allTasks = Get-ScheduledTask -ErrorAction Stop } catch { $allTasks = @() }
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
        Add-Finding -Code 'IOC-TaskMatch' -Severity 'High' -Message "IOC task match: $full" -Extra $finding
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
  $procs = Get-Process -ErrorAction SilentlyContinue
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
        Add-Finding -Code 'IOC-ProcessMatch' -Severity 'High' -Message "IOC process match: $($pr.Name) ($($pr.Id))" -Extra $finding
      }
    }
  }
  # Network (IPs + DNS cache)
  $nFind = @()
  try {
    $ips = @($cat.IPs)
    if ($ips.Count -gt 0) {
      $conns = Get-NetTCPConnection -State Established,SynSent,SynReceived -ErrorAction SilentlyContinue
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
          Add-Finding -Code 'IOC-NetworkIPMatch' -Severity 'High' -Message "IOC network match: IP $($c.RemoteAddress)" -Extra $finding
        }
      }
    }
    $domains = @($cat.Domains)
    if ($domains.Count -gt 0) {
      try {
        $dns = Get-DnsClientCache -ErrorAction Stop
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
              Add-Finding -Code 'IOC-NetworkDomainMatch' -Severity 'High' -Message "IOC network match: Domain $entry" -Extra $finding
            }
          }
        }
      } catch { Write-Warning "IOC network DNS cache check error: $($_.Exception.Message)" }
    }
  } catch { Write-Warning "IOC network sweep error: $($_.Exception.Message)" }
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
  try { Save-Json -InputObject $Proof -Path $outFile -Depth 50 } catch { <# best-effort: attempt to save partial proof on fatal error #> }
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
Write-KeyValue "Time"     $Proof.Time     Gray
Write-KeyValue "Host"     $Proof.Hostname Gray
Write-KeyValue "User"     $Proof.User     Gray
$adminColor = [ConsoleColor]::Yellow
if ($Proof.IsAdmin) { $adminColor = [ConsoleColor]::Green }
Write-KeyValue "Admin" ([string]$Proof.IsAdmin) $adminColor
$catColor = [ConsoleColor]::Green
if ($Proof.Catalog.Source -eq 'Default') { $catColor = [ConsoleColor]::Yellow }
Write-KeyValue "Catalog" $Proof.Catalog.Source $catColor
if (@($Proof.Catalog.Errors).Count -gt 0) {
  Write-UiStatus -Label "Catalog warnings" -State "WARN" -Detail ("{0} issue(s)" -f @($Proof.Catalog.Errors).Count)
  foreach ($ce in $Proof.Catalog.Errors) { Write-UiBullet $ce DarkGray }
} else {
  Write-UiStatus -Label "Catalog load" -State "OK" -Detail "No issues"
}
$scanReq = Get-OrDefault $Proof.Scan.Requested "n/a"
$scanRes = Get-OrDefault $Proof.Scan.Result "n/a"
Write-KeyValue "Scan" ("{0} -> {1}" -f $scanReq, $scanRes) Cyan
Write-KeyValue "Proof" $outFile Gray
Write-KeyValue "Evidence" $evDir Gray
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
Write-KeyValue "Actions"  ([string]$actCount) $actColor
Write-KeyValue "Errors"   ([string]$errCount) $errColor
Write-KeyValue "ExitCode" ([string]$exitCode) $exitColor
if ($errCount -gt 0) {
  Write-UiLine ""
  Write-UiStatus -Label "Error details" -State "FAIL"
  foreach ($e in $Proof.Errors) { Write-UiBullet $e Red }
}
# V2 output contract
$resultToken = if ($exitCode -ne 0) { 'FAIL' } elseif ($script:Findings.Count -gt 0) { 'WARN' } else { 'OK' }
$v2Result = New-V2ResultObject -ScriptName '11-IOC-Sweep-Defender.ps1' -Mode $Mode -Result $resultToken -Findings @($script:Findings) -Summary $Proof -Metadata @{}
Write-ResultObject -ResultObject $v2Result -OutputFormat $OutputFormat -OutputPath $OutputPath
if ($PassThru) { $v2Result }
exit $exitCode

