#requires -version 5.1
<#
.SYNOPSIS
Parses the newest SupportBundle ZIP in a folder, extracts key metadata, and returns a single structured result object for automation.
.DESCRIPTION
This script is designed for two audiences at the same time:
- Automation: With -PassThru, it emits exactly one structured PowerShell object to the pipeline, so it can be filtered and exported cleanly (e.g. ConvertTo-Json, Export-Csv, Where-Object).
- Humans: It prints a readable console summary (with optional colors) without polluting the pipeline.
High-level workflow:
1) Locate the newest ZIP named 'SupportBundle-*.zip' under -SupportDir (by LastWriteTime).
2) Safely extract the ZIP to a fresh directory below -ExtractRoot.
3) Load 'Summary.json' only from that validated extraction.  Sidecar summaries
   are deliberately not trusted because they can outlive or differ from a ZIP.
4) Load an optional config JSON from -ConfigPath to determine which proof files are expected.
   If the config is missing or invalid, built-in defaults are used.
5) Determine proof presence for each expected proof file name:
   - Match by legacy text markers found in Summary.Outputs (if present)
   - Match by file existence (directly in SearchDir and recursively below it)
6) Collect event log files (*.evtx) from 'WorkDir\eventlogs' (if that folder exists).
7) Load 'KBStatus.json' from WorkDir (root or recursively) and expose installed/missing KB lists if present.
8) Generate Findings based on failed producer records, missing proofs, and missing KBs (when available).
9) Print a console summary (optional colors), then return the result object to the pipeline.
.PARAMETER SupportDir
Folder that contains SupportBundle ZIP files.
The script searches this directory for 'SupportBundle-*.zip' and selects the newest file by LastWriteTime.
Default: %ProgramData%\BaselineOpsForWindows\SupportBundles
.PARAMETER ConfigPath
Path to an optional configuration JSON that can define expected proof outputs.
If the file cannot be loaded or is invalid JSON, the script falls back to built-in defaults.
Default: <script directory>\support-bundle.json
Expected config shape (optional):
- ProofOutFiles.SysmonState
- ProofOutFiles.SysmonDriftState
- ProofOutFiles.SoftwareInventory
- ProofOutFiles.FirewallAudit
- ProofOutFiles.HardwareAudit
Only the leaf file names are used (Split-Path -Leaf).
.PARAMETER ExtractRoot
Protected root where ZIP files are extracted. For elevated parsing this path is
fixed to %ProgramData%\BaselineOpsForWindows\SupportBundles\_extracted;
an explicitly supplied value must resolve to that same path. Each run uses a
fresh, uniquely named WorkDir below the protected root.
.PARAMETER ForceExtract
Compatibility switch. Extraction already uses a fresh WorkDir on every run, so
stale files are never reused.
.PARAMETER ConsoleMode
Controls how the human-readable summary is printed:
- Host: Uses Write-UiLine (supports colors when -NoColor is not set).
- Information: Uses Write-Information only (no colors, easier to redirect/collect).
Default: Host
.PARAMETER NoColor
Disables colored output in Host mode.
Has no effect when -ConsoleMode Information is used.
.INPUTS
None. You cannot pipe objects into this script.
.PARAMETER Mode
  Execution mode. 'Audit' reports only; 'Remediate' applies changes.
.PARAMETER OutputFormat
  Output format: Console, Json, Csv, or None.
.PARAMETER OutputPath
  File path for Json/Csv output.
.PARAMETER PassThru
  Emit structured v2 result object to pipeline.
.PARAMETER Strict
  Treat warnings as failures.
.PARAMETER Quiet
  Suppress console output.
.OUTPUTS
System.Management.Automation.PSCustomObject
With -PassThru, the script returns exactly one V2 result object whose Summary
contains these parser properties:
- Hostname (String)
  Hostname reported by the summary (if present).
- Time (String)
  Timestamp from the summary (if present).
- Reason (String)
  Reason field from the summary (if present).
- User (String)
  User field from the summary (if present).
- Admin (Boolean)
  Indicates whether the bundle was collected with administrative privileges (best-effort, defaults to $false).
- Errors (String[])
  Error messages reported by legacy summaries plus failed Records entries (may be empty).
- Notes (String[])
  Combined notes from the summary plus script/runtime notes (e.g., config fallback notices).
- Outputs (String[])
  Raw output lines from the summary (may be empty).
- BundleZipName (String)
  File name of the selected ZIP.
- BundleZipPath (String)
  Full path to the selected ZIP.
- SummaryPath (String)
  Full path to the summary JSON that was successfully loaded.
- WorkDir (String)
  Extraction directory for the ZIP (may be $null if extraction failed).
- Proofs (PSCustomObject[])
  One element per expected proof file name:
  - FileName (String)
  - Present (Boolean)
  - PresentByOutput (Boolean)
  - PresentByFile (Boolean)
  - PresentByDirect (Boolean)
  - PresentByRecurse (Boolean)
  - FoundPath (String)
- EventLogDirExists (Boolean)
  True if 'WorkDir\eventlogs' exists.
- EventLogs (String[])
  Full paths of discovered *.evtx files (may be empty).
- KbStatus (PSCustomObject)
  - KbStatusPath (String)  Path that was searched/used
  - Present (Boolean)      True if KBStatus.json was found and parsed
  - Installed (Object[])   Raw array from KBStatus.json (if present)
  - MissingZeroDay (Object[])
  - MissingCritical (Object[])
  - Summary (Object)
- BundleArchiveValidated (Boolean)
  True after the selected ZIP has been safely extracted with a valid Summary.json.
- ZipMarkerPresent (Boolean)
  Compatibility alias for BundleArchiveValidated. New producer summaries do not emit Outputs ZIP markers.
- Findings (String[])
  Human-readable findings derived from producer failures, proof presence, WorkDir availability, and KBStatus.
.EXAMPLE
PS> .\10-SupportBundle-Parser.ps1 -PassThru
Runs with defaults, prints a console summary, and returns the result object.
.EXAMPLE
PS> $r = .\10-SupportBundle-Parser.ps1 -SupportDir $SupportDir -PassThru
PS> $r.Proofs | Where-Object { -not $_.Present } | Select-Object FileName,FoundPath
Parses the newest bundle and lists missing proofs in a structured way.
.EXAMPLE
PS> .\10-SupportBundle-Parser.ps1 -ConsoleMode Information -PassThru | ConvertTo-Json -Depth 6 | Set-Content -Encoding UTF8 '.\bundle-result.json'
Sends the object to the pipeline for JSON export while keeping console output on the Information stream.
.EXAMPLE
PS> .\10-SupportBundle-Parser.ps1 -ForceExtract -NoColor
Forces re-extraction and prints a plain (non-colored) console summary.
.NOTES
- The script is strict-mode friendly and treats summary/config fields as optional; missing properties are handled with defaults.
- Console output is intentionally separated from pipeline output to keep automation reliable.
- Extraction uses a fresh protected directory for every run and never reuses stale contents.
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
  [Parameter()][ValidateNotNullOrEmpty()][string]$SupportDir,
  [Parameter()][ValidateNotNullOrEmpty()][string]$ConfigPath,
  [Parameter()][ValidateNotNullOrEmpty()][string]$ExtractRoot,
  [Parameter()][switch]$ForceExtract,
  [Parameter()][ValidateSet('Host','Information')][string]$ConsoleMode = 'Host',
  [Parameter()][switch]$NoColor,
  [ValidateSet('Audit','Remediate')][string]$Mode = 'Audit',
  [ValidateSet('Console','Json','Csv','None')][string]$OutputFormat = 'Console',
  [string]$OutputPath,
  [switch]$PassThru,
  [switch]$Strict,
  [switch]$Quiet
)
. (Join-Path $PSScriptRoot '_lib/Bootstrap.ps1')
. (Join-Path $PSScriptRoot 'internal/10-SupportBundle-Parser.helpers.ps1')
. (Join-Path $PSScriptRoot 'internal/10-SupportBundle-Parser.runtime.ps1')
Initialize-SupportBundleParserModules -LibPath $script:LibPath
Set-StrictMode -Version Latest
$script:__V2Context = Initialize-V2Context -ScriptName '10-SupportBundle-Parser.ps1' -BoundParameters $PSBoundParameters `
  -Values @{ Mode = $Mode; ConfigPath = $ConfigPath; OutputFormat = $OutputFormat; OutputPath = $OutputPath; PassThru = $PassThru; Strict = $Strict; Quiet = $Quiet; NoColor = $NoColor; DeriveRemediate = $false }
Initialize-SupportBundleParserEntry -V2Context $script:__V2Context

$isWindowsHost = ($env:OS -eq 'Windows_NT')
if (-not $isWindowsHost) {
  $summary = New-SupportBundleUnsupportedSummary -Mode $Mode
  $unsupportedResult = if ($Strict) { 'FAIL' } else { 'WARN' }
  $result = Get-V2ResultObject -ScriptName '10-SupportBundle-Parser.ps1' -Mode $Mode -Result $unsupportedResult -Findings @() -Summary $summary -Metadata @{ UnsupportedHost = $true }
  Write-ResultObject -ResultObject $result -OutputFormat $OutputFormat -OutputPath $OutputPath
  if ($PassThru) { $result }
  exit (Get-V2ExitCode -Result $unsupportedResult)
}

$script:Findings = Get-FindingsList
$pathState = Get-SupportBundleParserPaths -SupportDir $SupportDir -ConfigPath $ConfigPath -ExtractRoot $ExtractRoot -ScriptRoot $PSScriptRoot
$SupportDir, $ConfigPath, $ExtractRoot = $pathState.SupportDir, $pathState.ConfigPath, $pathState.ExtractRoot
if (-not $pathState.ExtractRootAllowed) {
  $v2Result = New-SupportBundleRootFailureResult -SupportDir $SupportDir -ConfigPath $ConfigPath -ExtractRoot $ExtractRoot -Mode $Mode
  Write-ResultObject -ResultObject $v2Result -OutputFormat $OutputFormat -OutputPath $OutputPath
  if ($PassThru) { $v2Result }
  exit (Get-V2ExitCode -Result 'FAIL')
}
$script:ConsoleMode = $ConsoleMode
$state = New-SupportBundleParserState
Invoke-SupportBundleParserRun -State $state -SupportDir $SupportDir -ConfigPath $ConfigPath -ExtractRoot $ExtractRoot -ForceExtract ([bool]$ForceExtract)
$result = $state.Result

# V2 output contract
$resultToken = Get-SupportBundleParserResultToken -Strict ([bool]$Strict)
$v2Result = Get-V2ResultObject -ScriptName '10-SupportBundle-Parser.ps1' -Mode $Mode -Result $resultToken -Findings (ConvertTo-ObjectArray -InputObject $script:Findings) -Summary $result -Metadata @{}
Write-ResultObject -ResultObject $v2Result -OutputFormat $OutputFormat -OutputPath $OutputPath
if ($PassThru) { $v2Result }
exit (Get-V2ExitCode -Result $resultToken)
