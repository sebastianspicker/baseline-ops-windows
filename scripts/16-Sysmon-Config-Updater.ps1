#requires -version 5.1
<#
.SYNOPSIS
  Applies a desired Sysmon configuration in an idempotent, auditable way and reports drift/compliance.
.DESCRIPTION
  This script selects a target Sysmon XML configuration, validates it, compares it to the last known applied state and the current runtime configuration, and optionally remediates drift by installing/updating Sysmon.
  It supports three configuration source modes:
  - Direct file mode: use -ConfigPath to point to a specific XML file.
  - Directory mode: use -SourceDir to pick a suitable XML from a folder (optionally filtered with -ConfigNameHint).
  - Manifest mode: use -ManifestPath to load JSON settings (optional allowlist + min engine) and optionally pick a config file named by the manifest.
  Validation and decision logic:
  - Validates that the XML is well-formed and has a Sysmon root element.
  - Optionally enforces a SHA256 allowlist if provided by the manifest.
  - Optionally enforces a minimum Sysmon engine version if provided by the manifest or -MinEngine.
  - Detects drift using:
    - The desired config file SHA256 vs. the previously recorded desired SHA256 in the state file.
    - A hash of the current runtime config dump (Sysmon "-c" without a file) vs. the previously recorded runtime dump hash.
  Remediation behavior:
  - If -Mode Remediate is set and Sysmon is not installed, the script installs Sysmon using the selected XML.
  - If -Mode Remediate is set and drift is detected, the script updates Sysmon to use the selected XML.
  - If -Mode Audit is used, the script runs in audit mode and returns a non-OK status when drift/non-compliance is detected.
  Optional logging channel management:
  - If -EnsureChannel is set, the script checks whether the Sysmon Operational channel is enabled and whether its maximum size meets the requested value.
  - If -EnsureChannel is set together with -Mode Remediate, the script attempts to enable/resize the channel to become compliant.
  State and output:
  - Writes a state JSON that records what was applied/observed (host, time, sysmon engine details, desired config SHA256, source, runtime dump hash).
  - Emits a structured summary object to the pipeline (suitable for Export-Csv / ConvertTo-Json / Where-Object).
  - Writes a human-readable console summary at the end (can be disabled).
.PARAMETER ConfigPath
  Path to a Sysmon configuration XML file to apply/audit.
.PARAMETER SourceDir
  Directory containing one or more Sysmon configuration XML files.
  The script selects one file (optionally filtered by -ConfigNameHint, otherwise picks the "best" candidate based on naming/version hint and timestamps).
.PARAMETER ManifestPath
  Path to a manifest JSON file that can define:
  - Config.File: Preferred XML file name to select (typically relative to -SourceDir).
  - AllowedHashes: Array of allowed SHA256 hashes for the selected XML file.
  - MinEngine: Minimum Sysmon engine version required.
.PARAMETER SysmonExePath
  Optional explicit path to sysmon.exe/sysmon64.exe.
  If not provided, the script attempts to discover the Sysmon executable from the installed service configuration or known default locations.
.PARAMETER Mode
  Execution mode:
  - Audit: report drift/non-compliance without changing the system.
  - Remediate: perform changes to reach the desired state (install/update Sysmon config; optionally enable/resize channel when -EnsureChannel is used).
.PARAMETER EnsureChannel
  If set, validates the Sysmon Operational channel status (enabled + minimum size).
  Use together with -Mode Remediate to enforce the desired channel settings.
.PARAMETER ChannelSizeMiB
  Desired minimum maximum size of the Sysmon Operational channel in MiB.
  Only used when -EnsureChannel is set.
.PARAMETER StatePath
  Path to the state JSON file used to track last applied/observed configuration.
  If the state file is missing or invalid JSON, the script uses safe defaults and continues.
.PARAMETER ConfigPathFallback
  Optional fallback XML file path to use if selection via -ConfigPath/-SourceDir/-ManifestPath does not yield a config.
.PARAMETER MinEngine
  Optional minimum Sysmon engine version requirement (for example: "15.0").
  If not provided, the script may use MinEngine from the manifest.
.PARAMETER ConfigNameHint
  Optional regex hint used to filter XML files in -SourceDir (for example: "prod|server" or "v15").
.PARAMETER NoConsoleSummary
  If set, disables the human-readable console summary.
  The structured pipeline output is still produced.
.PARAMETER SanitizeConsoleOutput
  If set, the console summary masks local/UNC paths (helpful when pasting console output into tickets or GitHub issues).
  This does not change the structured pipeline output.
.PARAMETER NoColor
  If set, disables colored console output.
.INPUTS
  None. This script does not accept pipeline input.
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
  System.Management.Automation.PSCustomObject.
  The script outputs exactly one structured summary object with fields such as:
  - Ok, DriftDetected, Remediate, EnsureChannel, IsAdmin
  - ConfigFile, DesiredSha256, PrevDesiredSha256
  - SysmonService, SysmonExe, EngineVersion, MinEngineRequired
  - CurrentDumpSha256, InstalledNow, StateWritten
  - Actions (string[]), Warnings (string[])
.EXAMPLE
  # Audit a specific config file (no changes)
  .\16-Sysmon-Config-Updater.ps1 -ConfigPath $ConfigPath
.EXAMPLE
  # Remediate: apply the config if drift is detected (or install if missing)
  .\16-Sysmon-Config-Updater.ps1 -ConfigPath $ConfigPath -Mode Remediate
.EXAMPLE
  # Select config from a directory using a name hint, audit-only
  .\16-Sysmon-Config-Updater.ps1 -SourceDir $SourceDir -ConfigNameHint "prod"
.EXAMPLE
  # Use a manifest and a directory (manifest may specify Config.File, AllowedHashes, MinEngine)
  .\16-Sysmon-Config-Updater.ps1 -ManifestPath $ManifestPath -SourceDir $SourceDir -Mode Remediate
.EXAMPLE
  # Enforce Sysmon Operational channel settings during remediation
  .\16-Sysmon-Config-Updater.ps1 -ConfigPath $ConfigPath -EnsureChannel -ChannelSizeMiB 256 -Mode Remediate
.EXAMPLE
  # Export the structured result (pipeline-safe)
  .\16-Sysmon-Config-Updater.ps1 -ConfigPath $ConfigPath | Export-Csv -NoTypeInformation -Path $OutputPath
.NOTES
  Behavior on missing/invalid JSON:
  - An explicitly supplied manifest must exist and conform to the expected shape. Missing, invalid, or unsafe manifests block Sysmon installation and config application.
  - State: if missing/invalid, the script continues with empty defaults (drift detection may rely on runtime dump hash and current desired hash).
  Idempotency and drift:
  - In audit mode (-Mode Audit), the script reports non-OK when it detects drift or required settings are not compliant.
  - In remediate mode, the script only applies changes when drift/non-compliance is detected.
  Security considerations:
  - When using AllowedHashes, ensure the allowlist is maintained securely.
  - Running with -Mode Remediate requires administrative privileges to install/update Sysmon and to change event log channel settings.
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
  [string]$ConfigPath,
  [string]$SourceDir,
  [string]$ManifestPath,
  [string]$SysmonExePath,
  [switch]$EnsureChannel,
  [ValidateRange(1, 4096)]
  [int]$ChannelSizeMiB = 256,
  # Optional caller input; runtime resolves a protected default state path.
  [string]$StatePath,
  [string]$ConfigPathFallback,
  [string]$MinEngine,
  [string]$ConfigNameHint,
  # Console output control (does NOT affect pipeline output)
  [switch]$NoConsoleSummary,
  # Sanitizes only console output (pipeline output remains raw/structured)
  [switch]$SanitizeConsoleOutput,
  # Console rendering preferences
  [switch]$NoColor
,
  [ValidateSet('Audit','Remediate')][string]$Mode = 'Audit',
  [ValidateSet('Console','Json','Csv','None')][string]$OutputFormat = 'Console',
  [string]$OutputPath,
  [switch]$PassThru,
  [switch]$Strict,
  [switch]$Quiet
)
. (Join-Path $PSScriptRoot '_lib/Bootstrap.ps1')
. (Join-Path $PSScriptRoot 'internal/16-Sysmon-Config-Updater.dependencies.ps1')
Set-StrictMode -Version Latest
$script:__V2Context = Initialize-SysmonUpdaterEntry $PSBoundParameters $Mode $OutputFormat $OutputPath ([bool]$PassThru) ([bool]$Strict) ([bool]$Quiet) ([bool]$NoColor)

$isWindowsHost = ($env:OS -eq 'Windows_NT')
if (-not $isWindowsHost) {
  $summary = New-SysmonUnsupportedSummary $Mode
  $resultToken = if ($Strict) { 'FAIL' } else { 'WARN' }
  $result = Get-V2ResultObject -ScriptName '16-Sysmon-Config-Updater.ps1' -Mode $Mode -Result $resultToken -Findings @() -Summary $summary -Metadata @{ UnsupportedHost = $true }
  Write-ResultObject -ResultObject $result -OutputFormat $OutputFormat -OutputPath $OutputPath
  if ($PassThru) { $result }
  exit (Get-V2ExitCode -Result $resultToken)
}

$script:Findings = Get-FindingsList
$options = New-SysmonUpdaterOptions $PSBoundParameters $StatePath $script:__V2Context
$runState = New-SysmonUpdaterState $options
Invoke-SysmonUpdater -State $runState -Options $options -CommandContext $PSCmdlet
Add-SysmonCanonicalFindings -Warnings @($runState.Warnings)
$summary = $runState.Summary
# V2 output contract
$summary.PolicyBlocked = [bool]$runState.PolicyBlocked
$resultToken = Get-SysmonUpdaterResultToken -State $runState -Strict ([bool]$Strict)
$v2Result = Get-V2ResultObject -ScriptName '16-Sysmon-Config-Updater.ps1' -Mode $Mode -Result $resultToken -Findings (ConvertTo-ObjectArray -InputObject $script:Findings.ToArray()) -Summary ([pscustomobject]$summary) -Metadata @{}
Write-ResultObject -ResultObject $v2Result -OutputFormat $OutputFormat -OutputPath $OutputPath
if ($PassThru) { $v2Result }
exit (Get-V2ExitCode -Result $resultToken)
