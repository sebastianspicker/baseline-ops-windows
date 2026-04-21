#requires -version 5.1
<#
.SYNOPSIS
  Collects endpoint artifacts and packages them into a structured incident-response bundle.

.DESCRIPTION
  This script gathers common forensic/IR artifacts from a Windows endpoint and writes them to a timestamped working
  directory, a JSON summary, and a ZIP bundle.

  Collection is normally gated by a trigger (registry value and/or file flag). Use -Force to run immediately.

  The script is designed for two consumers at once:
  - Humans: a “pretty” console summary at the end (with colored highlights and optional Top-N suspicious items).
  - Automation: structured outputs (CSV and JSON) that remain pipeline-friendly and easy to parse.

  Artifacts collected (high level):
  - Processes: PID, name, command line, executable path; optional SHA256 hashing; optional Authenticode info.
  - Network: TCP connections, listeners, UDP endpoints (best-effort), routing, IP configuration, DNS cache (best-effort).
  - Scheduled Tasks: flattened CSV; optional XML export for suspicious tasks.
  - WMI persistence: event filters, bindings, and multiple consumer types.
  - Autoruns: Run/RunOnce keys for HKLM and HKCU.
  - Samples (optional): copies selected executables into an evidence folder (size-limited and policy-controlled).

.PARAMETER CatalogPath
  Optional path to a JSON “catalog” that defines output base path, trigger locations, and collection policies.

  If provided and readable, it overrides the built-in defaults. If missing/unreadable, the script continues with
  safe defaults.

.PARAMETER ConfigPath
  Optional path to a JSON config file that can point to a catalog (for example, via a property like Grabber.CatalogPath).

  If CatalogPath is not specified or cannot be loaded, the script attempts to load a catalog via ConfigPath.
  If that also fails, built-in defaults are used.

.PARAMETER Force
  Runs the script immediately, even if no registry/file trigger is present.

  Use this for manual/interactive runs or when a trigger mechanism is not deployed.

.PARAMETER CollectSamples
  Forces sample collection (copying files into the evidence folder) subject to the configured size limits
  and filtering rules.

  This is additive: it enables samples even if the trigger did not request samples.

.PARAMETER HashAllProcesses
  Hashes all process executable paths (when readable), not only “userland” paths.

  Note: hashing all processes increases runtime and I/O.

.PARAMETER Strict
  Makes the run more “fail loud” from an operational perspective by treating findings/errors as warnings for status/logging.
  Data collection still follows best-effort behavior where applicable.

.INPUTS
  None. This script does not accept pipeline input.


.PARAMETER Mode
  Execution mode. 'Audit' reports only; 'Remediate' applies changes.

.PARAMETER OutputFormat
  Output format: Console, Json, Csv, or None.

.PARAMETER OutputPath
  File path for Json/Csv output.

.PARAMETER PassThru
  Emit structured v2 result object to pipeline.

.PARAMETER Quiet
  Suppress console output.

.PARAMETER NoColor
  Disable colored output.

.OUTPUTS
  This script writes files to disk and prints a human-readable summary to the host.

  Primary on-disk outputs (within the working directory):
  - Summary.json
    A structured summary object containing run metadata, counts, findings, errors/notes (if any), and optional Top-N items.
  - CSV files per collector (for example processes.csv, tasks.csv, network CSVs, autoruns CSVs, WMI CSVs).
  - Optional XML exports for suspicious scheduled tasks.
  - Optional evidence copies under a samples/ folder (policy-controlled).

  Final bundle:
  - A ZIP archive containing the full working directory content.

  Pipeline output:
  - None by default (intentionally). All “pretty” formatting is done via host output to keep pipelines clean.

.EXAMPLE
  # Run using deployed triggers (registry/file flag)
  .\IR-Grabber.ps1

.EXAMPLE
  # Force a run (ignores triggers)
  .\IR-Grabber.ps1 -Force

.EXAMPLE
  # Force a run and enable sample collection
  .\IR-Grabber.ps1 -Force -CollectSamples

.EXAMPLE
  # Load a specific catalog JSON
  .\IR-Grabber.ps1 -CatalogPath "PATH/TO/JSON/catalog.json" -Force

.EXAMPLE
  # Hash all process images (more I/O)
  .\IR-Grabber.ps1 -Force -HashAllProcesses

.EXAMPLE
  # Automated usage: run and then consume the generated summary
  .\IR-Grabber.ps1 -Force
  Get-Content -Raw "PATH/TO/OUTPUT/ir/H2/<timestamp>/Summary.json" | ConvertFrom-Json

.NOTES
  Operational guidance:
  - Run from an elevated console if you expect restricted artifacts (some registry areas, task exports, event source creation)
    to be accessible.
  - Sample collection is intentionally constrained by size limits and filtering rules to reduce risk and volume.
  - Network and DNS cache collection are best-effort; availability varies by OS features and permissions.

  Using Get-Help:
  - Get full help:    Get-Help .\IR-Grabber.ps1 -Full
  - View examples:   Get-Help .\IR-Grabber.ps1 -Examples
#>


[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
  [string]$CatalogPath,
  [switch]$Force,
  [switch]$CollectSamples,
  [switch]$HashAllProcesses,
  [switch]$Strict,
  [string]$ConfigPath

,
  [ValidateSet('Audit','Remediate')][string]$Mode = 'Audit',
  [ValidateSet('Console','Json','Csv','None')][string]$OutputFormat = 'Console',
  [string]$OutputPath,
  [switch]$PassThru,
  [switch]$Quiet,
  [switch]$NoColor
)

. (Join-Path $PSScriptRoot '_lib/Bootstrap.ps1')
Import-Module (Join-Path $script:LibPath 'Common.psm1') -Force
Import-Module (Join-Path $script:LibPath 'Output.psm1') -Force
Import-Module (Join-Path $script:LibPath 'EventLog.psm1') -Force
Import-Module (Join-Path $script:LibPath 'Results.psm1') -Force
Import-Module (Join-Path $script:LibPath 'Evidence.psm1') -Force
Import-Module (Join-Path $script:LibPath 'Validation.psm1') -Force
Import-Module (Join-Path $script:LibPath 'JsonCatalog.psm1') -Force
Import-Module (Join-Path $script:LibPath Serialization.psm1) -Force


Set-StrictMode -Version Latest
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
if ($PSBoundParameters.ContainsKey('Mode')) {
  if (Get-Variable -Name Remediate -ErrorAction SilentlyContinue) {
    Set-Variable -Name Remediate -Scope Script -Value ($Mode -eq 'Remediate')
  }
}
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
  $result = New-V2ResultObject -ScriptName '12-Suspicious-Artifact-Grabber.ps1' -Mode $Mode -Result 'OK' -Findings @() -Summary $summary -Metadata @{ UnsupportedHost = $true }
  Write-ResultObject -ResultObject $result -OutputFormat $OutputFormat -OutputPath $OutputPath
  if ($PassThru) { $result }
  exit 0
}

# Make Write-Information visible for humans; it is controlled by InformationPreference.
if (-not $Quiet) { $InformationPreference = 'Continue' }

# -------------------------
# Globals
# -------------------------
$ScriptVersion = '2025.12.22-ps51'

# -------------------------
# Console helpers (no pipeline output)
# -------------------------




# -------------------------
# Logging helpers
# -------------------------


# -------------------------
# Generic helpers
# -------------------------

# Expand-Env imported from lib/Evidence.psm1

# Save-Json: using canonical Save-Json from lib/Serialization.psm1

# Read-Json replaced by Read-JsonFileSafe from lib/JsonCatalog.psm1

. (Join-Path $PSScriptRoot 'private/12-Suspicious-Artifact-Grabber.helpers.ps1')

function Reset-Trigger {
  [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
  param($cat)
  try {
    $rk = [string]$cat.Trigger.Registry
    if ($rk -and (Test-Path -LiteralPath $rk)) {
      if (-not $PSCmdlet.ShouldProcess($rk, 'Reset artifact grabber trigger registry flag')) {
        return
      }
      New-ItemProperty -Path $rk -Name 'Request' -PropertyType DWord -Value 0 -Force | Out-Null
    }
  } catch { <# best-effort: trigger registry reset may fail without admin rights #> }
}


# -------------------------
# MAIN
# -------------------------
$script:Findings = New-FindingsList
Ensure-EventSource

$errors   = New-Object System.Collections.Generic.List[string]
$findings = $false
$ok       = $true
$summary  = $null
$catalogNote = $null

try {
  Write-Information ("IR Grabber starting (v{0})" -f $ScriptVersion)

  $cat = Load-Catalog -CatalogPath $CatalogPath -ConfigPath $ConfigPath -CatalogLoadNote ([ref]$catalogNote)
  if (-not $cat) { $cat = New-BaseClone $DefaultCatalog }

  $tr = Read-Trigger -cat $cat -Force:$Force -CollectSamples:$CollectSamples
  if (-not $tr.Want) {
    $msg = "IR Grabber: no trigger set (registry/fileflag), aborted. Hint: run with -Force."
    Write-HealthEvent 10021 $msg 'Warning'

    $summary = [ordered]@{
      Host    = $env:COMPUTERNAME
      Time    = (Get-Date).ToString('s')
      Reason  = $tr.Reason
      Trigger = @{
        Registry = [string]$cat.Trigger.Registry
        FileFlag = [string]$cat.Trigger.FileFlag
        Force    = [bool]$Force
      }
      Output  = @{ WorkDir = $null; Zip = $null }
      Counts  = @{}
      Errors  = @()
      Notes   = @()
      Samples = @()
    }

    return
  }

  $ts = New-RunId

  $base = $null
  try { $base = [string]$cat.OutputBase } catch { $base = $null }
  if (-not $base) { $base = [string]$DefaultCatalog.OutputBase }
  Assert-NoPathTraversal -Path $base -ParameterName 'Catalog.OutputBase'

  $work = Join-Path $base $ts
  $zip  = Join-Path $base ("Grabber-{0}-{1}.zip" -f $env:COMPUTERNAME,$ts)

  Ensure-Directory $work

  $summary = [ordered]@{
    Host    = $env:COMPUTERNAME
    Time    = (Get-Date).ToString('s')
    Reason  = $tr.Reason
    Trigger = @{
      Registry = [string]$cat.Trigger.Registry
      FileFlag = [string]$cat.Trigger.FileFlag
      Force    = [bool]$Force
    }
    Output  = @{ WorkDir = $work; Zip = $zip }
    Counts  = @{}
    Errors  = @()
    Notes   = @()
    Samples = @()
  }

  # Processes
  $pDir = Join-Path $work 'process'
  $pRes = Collect-Processes -outDir $pDir -cat $cat -hashAll:$HashAllProcesses
  $summary.Counts.Processes = Safe-ToInt $pRes.Counts.Count 0
  if ($pRes.Errors.Count -gt 0) { $pRes.Errors | ForEach-Object { [void]$errors.Add($_) } }

  # Network
  $nDir = Join-Path $work 'network'
  $nRes = Collect-Network -outDir $nDir
  $summary.Counts.Network = $nRes.Counts
  if ($nRes.Errors.Count -gt 0) { $nRes.Errors | ForEach-Object { [void]$errors.Add($_) } }
  if ($nRes.Notes.Count -gt 0) { $summary.Notes += @($nRes.Notes) }

  # Tasks
  $tDir = Join-Path $work 'tasks'
  $tRes = Collect-Tasks -outDir $tDir -cat $cat
  $summary.Counts.Tasks = $tRes.Counts
  if ($tRes.Errors.Count -gt 0) { $tRes.Errors | ForEach-Object { [void]$errors.Add($_) } }
  if (Safe-ToInt $tRes.Counts.Suspicious 0 -gt 0) { $findings = $true }

  # WMI persistence
  $wDir = Join-Path $work 'wmi'
  $wRes = Collect-WmiPersistence -outDir $wDir
  $summary.Counts.WMI = $wRes.Counts
  if ($wRes.Errors.Count -gt 0) { $wRes.Errors | ForEach-Object { [void]$errors.Add($_) } }

  $wmiTotal = (Safe-ToInt $wRes.Counts.Filters 0) + (Safe-ToInt $wRes.Counts.Bindings 0) + (Safe-ToInt $wRes.Counts.Cmd 0) + (Safe-ToInt $wRes.Counts.ActiveScript 0) + (Safe-ToInt $wRes.Counts.NTEventLog 0) + (Safe-ToInt $wRes.Counts.LogFile 0)
  if ($wmiTotal -gt 0) { $findings = $true }

  # Autoruns
  $aDir = Join-Path $work 'autoruns'
  $aRes = Export-Autoruns -outDir $aDir
  $summary.Counts.Autoruns = $aRes.Counts
  if ($aRes.Errors.Count -gt 0) { $aRes.Errors | ForEach-Object { [void]$errors.Add($_) } }

  # Samples (optional)
  if ($tr.Samples -or (Safe-ToBool $cat.Samples.Enable $false)) {
    $sDir = Join-Path $work 'samples'
    Ensure-Directory $sDir

    $maxFileMB  = Safe-ToInt $tr.MaxFileMB (Safe-ToInt $cat.Samples.MaxFileSizeMB 20)
    $maxTotalMB = Safe-ToInt $tr.MaxTotalMB (Safe-ToInt $cat.Samples.MaxTotalMB 100)
    $totalBytes = [ref]([int64]0)

    $procCsv = Join-Path $pDir 'processes.csv'
    if (Test-Path -LiteralPath $procCsv) {
      $procList = Import-Csv -Path $procCsv
      foreach ($row in $procList) {
        $path = [string]$row.Path
        if (-not $path) { continue }
        if (-not (Test-Path -LiteralPath $path)) { continue }

        $pick = $false
        foreach ($rx in @($cat.Samples.PathIncludeRegex)) { if ($path -match $rx) { $pick = $true; break } }
        if (-not $pick) { continue }

        if (Safe-ToBool $cat.Samples.OnlyUnsignedOrUnknown $true) {
          if ($row.Signed -eq 'True') { continue }
        }

        $okc, $dstOrWhy = Copy-ToEvidence -SourcePath $path -EvidenceBaseDir $sDir -MaxFileSizeMB $maxFileMB -MaxTotalMB $maxTotalMB -RunningTotalBytes $totalBytes
        $sha = $null
        if ($okc) { 
            $sha = Get-FileSha256 -Path $dstOrWhy
            Add-Finding -Code 'Grabber-SampleCollected' -Severity 'Low' -Message "Suspicious sample collected: $path" -Extra @{ Path = $path; Sha256 = $sha; Evidence = $dstOrWhy }
        }

        $summary.Samples += [pscustomobject]@{
          Source = $path
          Copied = [bool]$okc
          Info   = $dstOrWhy
          Sha256 = $sha
        }
      }
    } else {
      [void]$errors.Add("samples: processes.csv missing")
    }

    $copiedCount = @($summary.Samples | Where-Object { $_.Copied }).Count
    $summary.Counts.Samples = @{
      Copied     = $copiedCount
      MaxFileMB  = $maxFileMB
      MaxTotalMB = $maxTotalMB
    }
    if ($copiedCount -gt 0) { $findings = $true }
  }

  if ($errors.Count -gt 0) { $summary.Errors = @($errors) }
  Save-Json -InputObject $summary -Path (Join-Path $work 'Summary.json') -Depth 30

  try {
    if (Test-Path -LiteralPath $zip) { Remove-Item -LiteralPath $zip -Force -ErrorAction SilentlyContinue }
    Compress-Archive -Path (Join-Path $work '*') -DestinationPath $zip -Force
  } catch {
    [void]$errors.Add("zip: " + $_.Exception.Message)
    $ok = $false
  }

  $msg = "IR Grabber: bundle created -> " + $zip
  if ($errors.Count -gt 0) { $msg = $msg + " | Errors: " + (@($errors) -join " | ") }

  $warn = ($errors.Count -gt 0) -or [bool]$Strict -or $findings -or (-not $ok)
  $eventId = 10020
  $level = 'Information'
  if ($warn) { $eventId = 10021; $level = 'Warning' }

  Write-HealthEvent $eventId $msg $level
  Reset-Trigger -cat $cat

} catch {
  $errMsg = "IR Grabber fatal: " + $_.Exception.Message
  [void]$errors.Add($errMsg)
  Write-HealthEvent 10021 $errMsg 'Error'
} finally {
  if ($null -ne $summary) {
    if ($errors.Count -gt 0) { $summary.Errors = @($errors) }
    try { Print-ConsoleSummary -Summary $summary -Errors $errors -Findings $findings -CatalogLoadNote $catalogNote } catch { <# best-effort: console summary display in finally block #> }
  } else {
    Write-UiStatus -Label 'IR Grabber' -State 'FAIL' -Text "No summary object created."
  }
} # end script try

# V2 output contract
$resultToken = if ($errors.Count -gt 0) { 'FAIL' } elseif ($script:Findings.Count -gt 0) { 'WARN' } else { 'OK' }
$v2Result = New-V2ResultObject -ScriptName '12-Suspicious-Artifact-Grabber.ps1' -Mode $Mode -Result $resultToken -Findings @($script:Findings) -Summary $summary -Metadata @{}
Write-ResultObject -ResultObject $v2Result -OutputFormat $OutputFormat -OutputPath $OutputPath
if ($PassThru) { $v2Result }
exit 0
