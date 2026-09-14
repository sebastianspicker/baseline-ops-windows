#requires -version 5.1
<#
.SYNOPSIS
Local Administrators Guardrail - detect and optionally remediate unexpected members in the local Administrators group.

.DESCRIPTION
This script enforces a guardrail for the local Administrators group by comparing the current direct group members to a configured allow-list.

The allow-list can be provided through:
- A JSON allow-list file (recommended for centralized management).
- A JSON config file that points to the allow-list file.
- Ad-hoc entries via -ExtraAllow.

The script normalizes allow-list entries to SIDs, detects drift (unexpected or missing members), and can optionally remediate:
- Add missing allowed principals.
- Remove disallowed principals (with multiple safety mechanisms).

Safety / guardrails:
- The built-in local Administrator account (RID 500) is never removed.
- Domain-like principals (for example AD / Entra / Microsoft Account) are NOT removed unless -AllowDomainRemediation is specified.
- If the allow-list is missing OR partially unresolved, removal actions are suppressed (fail-safe) to reduce lockout risk.
- Supports -WhatIf and -Confirm via SupportsShouldProcess.

Operational behavior:
- Always writes a concise event log entry with the overall status (best effort).
- Always prints a human-readable console summary (unless -Quiet).
- Emits a single structured result object to the pipeline (unless -NoPipelineOutput).

.PARAMETER AllowDomainRemediation
When specified, the script is allowed to remove domain-like principals (for example AD / Entra / Microsoft Account) from the Administrators group if they are not in the allow-list.

If not specified, domain-like principals are protected from removal to avoid accidental removal of delegated admin access or device management accounts.

.PARAMETER ConfigPath
Optional path to a JSON config file.

If the config is present and contains a LocalAdmins.AllowListPath entry, that value is used as the default allow-list path unless -AllowListPath is explicitly provided.

If the config file cannot be loaded, the script continues with safe defaults.

.PARAMETER AllowListPath
Optional path to a JSON allow-list file.

Supported JSON shapes (either is accepted):
- { "LocalAdmins": { "Allowed": [ "DOMAIN\User", "S-1-...", ".\LocalUser" ] } }
- { "Allowed": [ "DOMAIN\User", "S-1-...", ".\LocalUser" ] }

If the allow-list file cannot be loaded, the script continues with safe defaults and suppresses removals (fail-safe).

.PARAMETER ExtraAllow
One or more additional allow-list entries to append at runtime (strings).
Each entry can be:
- A SID (for example "S-1-5-21-...").
- A name resolvable to a SID (for example "DOMAIN\User", "AzureAD\User", ".\LocalUser").

Use this to temporarily allow accounts without modifying the central JSON.

.PARAMETER Quiet
Suppresses the formatted console summary.
The script still writes the event log entry (best effort) and can still emit the structured pipeline result unless -NoPipelineOutput is used.

.PARAMETER NoPipelineOutput
Suppresses the structured pipeline output object.
Use this for interactive runs or scheduled executions where only console/event log output is desired.


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

.PARAMETER NoColor
  Disable colored output.

.OUTPUTS
LocalAdmins.Guardrail.Result (PSCustomObject)

The script emits exactly one object (unless -NoPipelineOutput), containing:
- Execution metadata (Timestamp, ComputerName, GroupName)
- Inputs and resolved allow-list (AllowInput, AllowResolved, AllowSIDs, UnresolvedAllowInput)
- Safety flags (BuiltinAdminSid500, AlwaysKeepSIDs, FailSafeNoRemove)
- Member snapshots and actions (MembersBefore, MembersAfter, ToAddSIDs, ToRemove, AddedSIDs, RemovedIds)
- Outcome and status (DriftDetected, PostCompliant, Errors, EventId, EventLevel)

All nested properties are structured to support filtering and exporting.

.EXAMPLE
# Report-only run using config/allow-list defaults (no changes)
.\scripts\03-LocalAdmins-Guardrail.ps1

.EXAMPLE
# Report-only run with explicit allow-list path
.\scripts\03-LocalAdmins-Guardrail.ps1 -AllowListPath .\examples\configs\local-admins-allowlist.json

.EXAMPLE
# Report-only run with an ad-hoc allowed entry
.\scripts\03-LocalAdmins-Guardrail.ps1 -ExtraAllow "CONTOSO\Helpdesk-LocalAdmins"

.EXAMPLE
# Remediate using allow-list (adds missing allowed members; removes disallowed local members when safe)
.\scripts\03-LocalAdmins-Guardrail.ps1 -Mode Remediate

.EXAMPLE
# Remediate and allow removal of domain-like members (use with extreme caution)
.\scripts\03-LocalAdmins-Guardrail.ps1 -Mode Remediate -AllowDomainRemediation -Confirm

.EXAMPLE
# Dry-run to see what would change without applying changes
.\scripts\03-LocalAdmins-Guardrail.ps1 -Mode Remediate -WhatIf

.EXAMPLE
# Automation: export the structured result to JSON
.\scripts\03-LocalAdmins-Guardrail.ps1 | ConvertTo-Json -Depth 6

.EXAMPLE
# Automation: export a flattened view to CSV (example of selecting fields)
.\scripts\03-LocalAdmins-Guardrail.ps1 |
  Select-Object Timestamp,ComputerName,GroupName,DriftDetected,PostCompliant,FailSafeNoRemove,EventId,EventLevel |
  Export-Csv -NoTypeInformation -Path .\local-admins-guardrail.csv

.NOTES
- The script checks only direct members of the Administrators group (no recursive group expansion).
- Removal actions are intentionally conservative to reduce the risk of lockouts.
- Event log writing is best effort; if unavailable, the script continues and relies on console/pipeline output.
#>


[CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='High')]
param(
  [switch]$AllowDomainRemediation,
  [string]$ConfigPath,
  [string]$AllowListPath,
  [string[]]$ExtraAllow,
  [switch]$Quiet,
  [switch]$NoPipelineOutput

,
  [ValidateSet('Audit','Remediate')][string]$Mode = 'Audit',
  [ValidateSet('Console','Json','Csv','None')][string]$OutputFormat = 'Console',
  [string]$OutputPath,
  [switch]$PassThru,
  [switch]$Strict,
  [switch]$NoColor
)

function Get-GuardrailUnsupportedSummary {
  param([string]$Mode)
  $summary = [pscustomobject]@{
    ComputerName = $env:COMPUTERNAME
    Timestamp    = Get-Date
    Mode         = $Mode
    Supported    = $false
    Notes        = @('Skipped: this script is only supported on Windows hosts.')
  }
  return $summary
}

function Get-GuardrailTerminalToken {
  param($Result, [switch]$Strict)
  $resultToken = if ($Result.DriftDetected) { 'WARN' } else { 'OK' }
  if ($Strict -and $resultToken -eq 'WARN') { $resultToken = 'FAIL' }
  return $resultToken
}

. (Join-Path $PSScriptRoot '_lib/Bootstrap.ps1')
Import-Module (Join-Path $script:LibPath 'Output.psm1') -Force
Import-Module (Join-Path $script:LibPath 'EventLog.psm1') -Force
Import-Module (Join-Path $script:LibPath 'Console.psm1') -Force
Import-Module (Join-Path $script:LibPath Serialization.psm1) -Force
Import-Module (Join-Path $script:LibPath 'Validation.psm1')


$script:Quiet = [bool]$Quiet

Set-StrictMode -Version Latest
$script:__V2Context = Initialize-V2Context -ScriptName '03-LocalAdmins-Guardrail.ps1' -BoundParameters $PSBoundParameters `
  -Values @{ Mode = $Mode; ConfigPath = $ConfigPath; OutputFormat = $OutputFormat; OutputPath = $OutputPath; PassThru = $PassThru; Strict = $Strict; Quiet = $Quiet; NoColor = $NoColor; DeriveRemediate = $true }
$Remediate = [bool]$script:__V2Context.Remediate
if ($script:__V2Context.Quiet) { $InformationPreference = 'SilentlyContinue'; $VerbosePreference = 'SilentlyContinue' }
$script:NoColor = [bool]$script:__V2Context.NoColor
$null = $NoPipelineOutput
$ErrorActionPreference = 'Stop'

if ($env:OS -ne 'Windows_NT') {
  $summary = Get-GuardrailUnsupportedSummary -Mode $Mode
  $unsupportedResult = if ($Strict) { 'FAIL' } else { 'WARN' }
  $result = Get-V2ResultObject -ScriptName '03-LocalAdmins-Guardrail.ps1' -Mode $Mode -Result $unsupportedResult -Findings @() -Summary $summary -Metadata @{ UnsupportedHost = $true }
  Write-ResultObject -ResultObject $result -OutputFormat $OutputFormat -OutputPath $OutputPath
  if ($PassThru) { $result }
  exit (Get-V2ExitCode -Result $unsupportedResult)
}

# ---------------- Constants / Defaults ----------------

function Initialize-GuardrailDefaults {
$script:EventSource            = 'LocalAdmins-Guardrail'
$script:EventLogName           = 'Application'
$script:AdministratorsGroupSid = 'S-1-5-32-544'   # Builtin\Administrators (language-neutral)

# Safe default when JSON is missing/unreadable:
# An empty allow-list means: no removals (fail-safe), adds only possible via ExtraAllow + Remediate mode.
$script:DefaultAllowList = @()

}
Initialize-GuardrailDefaults

# ---------------- Helper Functions ----------------


. (Join-Path $PSScriptRoot 'internal/03-LocalAdmins-Guardrail.helpers.ps1')
$runState = New-GuardrailRunState -Inputs @{ Remediate = $Remediate; AllowDomainRemediation = $AllowDomainRemediation; ConfigPath = $ConfigPath; AllowListPath = $AllowListPath; ExtraAllow = $ExtraAllow; Quiet = $Quiet }
. Invoke-LocalAdminsGuardrail -RunState $runState -DecisionContext $PSCmdlet

# V2 output contract
$resultToken = Get-GuardrailTerminalToken -Result $runState.result -Strict:$Strict
$v2Result = Get-V2ResultObject -ScriptName '03-LocalAdmins-Guardrail.ps1' -Mode $Mode -Result $resultToken -Findings @() -Summary $runState.result -Metadata @{}
Write-ResultObject -ResultObject $v2Result -OutputFormat $OutputFormat -OutputPath $OutputPath
if ($PassThru) { $v2Result }
exit (Get-V2ExitCode -Result $resultToken)
