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
- Always prints a human-friendly console summary (unless -Quiet).
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
Suppresses the pretty console summary output.
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
.\LocalAdmins-Guardrail.ps1

.EXAMPLE
# Report-only run with explicit allow-list path
.\LocalAdmins-Guardrail.ps1 -AllowListPath "PATH/TO/JSON/local-admins-allowlist.json"

.EXAMPLE
# Report-only run with an ad-hoc allowed entry
.\LocalAdmins-Guardrail.ps1 -ExtraAllow "CONTOSO\Helpdesk-LocalAdmins"

.EXAMPLE
# Remediate using allow-list (adds missing allowed members; removes disallowed local members when safe)
.\LocalAdmins-Guardrail.ps1 -Mode Remediate

.EXAMPLE
# Remediate and allow removal of domain-like members (use with extreme caution)
.\LocalAdmins-Guardrail.ps1 -Mode Remediate -AllowDomainRemediation -Confirm

.EXAMPLE
# Dry-run to see what would change without applying changes
.\LocalAdmins-Guardrail.ps1 -Mode Remediate -WhatIf

.EXAMPLE
# Automation: export the structured result to JSON
.\LocalAdmins-Guardrail.ps1 | ConvertTo-Json -Depth 6

.EXAMPLE
# Automation: export a flattened view to CSV (example of selecting fields)
.\LocalAdmins-Guardrail.ps1 |
  Select-Object Timestamp,ComputerName,GroupName,DriftDetected,PostCompliant,FailSafeNoRemove,EventId,EventLevel |
  Export-Csv -NoTypeInformation -Path "PATH/TO/REPORT/local-admins-guardrail.csv"

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

. (Join-Path $PSScriptRoot '_lib/Bootstrap.ps1')
Import-Module (Join-Path $script:LibPath 'Output.psm1') -Force
Import-Module (Join-Path $script:LibPath 'EventLog.psm1') -Force
Import-Module (Join-Path $script:LibPath 'Console.psm1') -Force
Import-Module (Join-Path $script:LibPath Serialization.psm1) -Force


$script:Quiet = [bool]$Quiet

Set-StrictMode -Version Latest
# v2-init
$null = $Mode, $ConfigPath, $OutputFormat, $OutputPath, $PassThru, $Strict, $Quiet, $NoColor, $NoPipelineOutput
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
  $result = New-V2ResultObject -ScriptName '03-LocalAdmins-Guardrail.ps1' -Mode $Mode -Result 'OK' -Findings @() -Summary $summary -Metadata @{ UnsupportedHost = $true }
  Write-ResultObject -ResultObject $result -OutputFormat $OutputFormat -OutputPath $OutputPath
  if ($PassThru) { $result }
  exit 0
}

# ---------------- Constants / Defaults ----------------

$script:EventSource            = 'LocalAdmins-Guardrail'
$script:EventLogName           = 'Application'
$script:AdministratorsGroupSid = 'S-1-5-32-544'   # Builtin\Administrators (language-neutral)

# Safe default when JSON is missing/unreadable:
# An empty allow-list means: no removals (fail-safe), adds only possible via ExtraAllow + -Remediate.
$script:DefaultAllowList = @()

# ---------------- Helper Functions ----------------


function Try-ReadJsonFile {
  [CmdletBinding()]
  param([Parameter(Mandatory)] [string]$Path)

  try {
    if ($Path -and (Test-Path -LiteralPath $Path)) {
      return (Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json)
    }
  } catch { <# best-effort: JSON file may be missing or invalid #> }

  return $null
}

function Get-Config {
  [CmdletBinding()]
  param([string]$Path)

  $cfg = $null
  if ($Path) { $cfg = Try-ReadJsonFile -Path $Path }
  if ($cfg) { return $cfg }

  # Optional relative fallback (anonymized)
  try {
    $here = Split-Path -Parent $MyInvocation.MyCommand.Path
    if ($here) {
      $alt = Join-Path (Split-Path -Parent $here) "config\global.config.json"
      $cfg2 = Try-ReadJsonFile -Path $alt
      if ($cfg2) { return $cfg2 }
    }
  } catch { <# best-effort: fallback config path may not exist #> }

  return $null
}

function Read-AllowListFromJson {
  [CmdletBinding()]
  param([object]$Json)

  $all = New-Object System.Collections.Generic.List[string]

  try {
    if ($Json -and $Json.LocalAdmins -and $Json.LocalAdmins.Allowed) {
      foreach ($x in @($Json.LocalAdmins.Allowed)) { if ($null -ne $x) { [void]$all.Add($x.ToString()) } }
    } elseif ($Json -and $Json.Allowed) {
      foreach ($x in @($Json.Allowed)) { if ($null -ne $x) { [void]$all.Add($x.ToString()) } }
    }
  } catch { <# best-effort: JSON shape may not match expected allow-list format #> }

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
      foreach ($x in (Read-AllowListFromJson -Json $j)) { [void]$all.Add($x) }
    }
  }

  if ($Extra) {
    foreach ($x in $Extra) {
      if ($null -ne $x) { [void]$all.Add($x.ToString()) }
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
  } catch { return $null }

  # NTAccount -> SID
  try {
    $nt  = New-Object System.Security.Principal.NTAccount($IdOrName)
    $sid = $nt.Translate([System.Security.Principal.SecurityIdentifier])
    return $sid.Value
  } catch {
    # Local shorthand ".\Name"
    try {
      if ($IdOrName -match '^[.\\]+') {
        $name = $IdOrName -replace '^[.\\]+',''
        $lu = Get-LocalUser -Name $name -ErrorAction Stop
        return $lu.SID.Value
      }
    } catch { <# best-effort: local user shorthand resolution may fail #> }
  }

  return $null
}

function Get-BuiltinAdministratorSid {
  [CmdletBinding()]
  param()

  # RID 500 -> SID ends with -500
  try {
    $adm = Get-LocalUser | Where-Object { $_.SID.Value -match '-500$' } | Select-Object -First 1
    if ($adm) { return $adm.SID.Value }
  } catch { <# best-effort: LocalAccounts module may not be available #> }

  return $null
}

function Get-AdministratorsGroupName {
  [CmdletBinding()]
  param()

  $sidObj = New-Object System.Security.Principal.SecurityIdentifier($script:AdministratorsGroupSid)
  $nt = $sidObj.Translate([System.Security.Principal.NTAccount]).Value
  return ($nt -split '\\',2)[1]
}

function ConvertTo-AdminMemberRecord {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)] $RawMember,
    [Parameter(Mandatory)] [string]$GroupName,
    [Parameter(Mandatory)] [ValidateSet('LocalAccounts','ADSI')] [string]$Provider
  )

  $sidString = $null
  try { if ($RawMember.SID -and $RawMember.SID.Value) { $sidString = [string]$RawMember.SID.Value } } catch { <# best-effort: SID property may vary by provider #> }
  if (-not $sidString) { try { if ($RawMember.SID) { $sidString = [string]$RawMember.SID } } catch { <# best-effort: SID fallback #> } }

  $name = $null
  try { $name = [string]$RawMember.Name } catch { <# best-effort: Name property may not exist #> }
  if ([string]::IsNullOrWhiteSpace($name)) { try { $name = [string]$RawMember.ToString() } catch { <# best-effort: ToString fallback #> } }

  $principalSource = $null
  try { $principalSource = [string]$RawMember.PrincipalSource } catch { <# best-effort: PrincipalSource may not exist on all OS versions #> }

  $objectClass = $null
  try { $objectClass = [string]$RawMember.ObjectClass } catch { <# best-effort: ObjectClass may not exist #> }

  [pscustomobject]@{
    PSTypeName      = 'LocalAdmins.Guardrail.Member'
    GroupName       = $GroupName
    Provider        = $Provider
    Name            = $name
    SID             = $sidString
    PrincipalSource = $principalSource
    ObjectClass     = $objectClass
  }
}

function Get-AdministratorsGroupMembers {
  [CmdletBinding()]
  param([Parameter(Mandatory)] [string]$GroupName)

  # Prefer LocalAccounts for best fidelity.
  try {
    $raw = Get-LocalGroupMember -Group $GroupName -ErrorAction Stop
    foreach ($m in $raw) {
      ConvertTo-AdminMemberRecord -RawMember $m -GroupName $GroupName -Provider 'LocalAccounts'
    }
    return
  } catch {
    # ADSI fallback enumeration
    $grp = [ADSI]"WinNT://$env:COMPUTERNAME/$GroupName,group"
    $grp.Invoke("Members") | ForEach-Object {
      $path = $_.GetType().InvokeMember("ADsPath",'GetProperty',$null,$_,$null)
      $name = $path -replace '^WinNT://','' -replace '/','\'

      $sid = $null
      try {
        $nt = New-Object System.Security.Principal.NTAccount($name)
        $sid = ($nt.Translate([System.Security.Principal.SecurityIdentifier])).Value
      } catch { <# best-effort: ADSI member SID translation may fail for orphaned/external accounts #> }

      $src =
        if ($name -match '^AzureAD\\') { 'Microsoft Entra group' }
        elseif ($name -match '^MicrosoftAccount\\') { 'Microsoft Account' }
        elseif ($name -match "^[^\\]+\\") { 'Active Directory' }
        else { 'Local' }

      ConvertTo-AdminMemberRecord -RawMember ([pscustomobject]@{
        Name            = $name
        ObjectClass     = 'UserOrGroup'
        PrincipalSource = $src
        SID             = $sid
      }) -GroupName $GroupName -Provider 'ADSI'
    }
  }
}

function Is-DomainLikePrincipal {
  [CmdletBinding()]
  param([Parameter(Mandatory)] $MemberRecord)

  # PrincipalSource may be blank on older OS; treat blank as domain-like (fail-safe).
  $src = [string]$MemberRecord.PrincipalSource
  if ([string]::IsNullOrWhiteSpace($src)) { return $true }

  return ($src -in @(
    'Active Directory',
    'Microsoft Entra group',
    'Microsoft Account',
    'ActiveDirectory',
    'MicrosoftAccount'
  ))
}

function New-GuardrailResult {
  [CmdletBinding()]
  param([Parameter(Mandatory)] [string]$GroupName)

  [pscustomobject]@{
    PSTypeName              = 'LocalAdmins.Guardrail.Result'
    Timestamp               = (Get-Date).ToString('o')
    ComputerName            = $env:COMPUTERNAME
    GroupName               = $GroupName

    Remediate               = [bool]$Remediate
    AllowDomainRemediation  = [bool]$AllowDomainRemediation

    ConfigLoaded            = $false
    AllowListPathUsed       = $null

    AllowInput              = @()
    AllowResolved           = @()  # objects: Input, SID
    AllowSIDs               = @()
    UnresolvedAllowInput    = @()

    BuiltinAdminSid500      = $null
    AlwaysKeepSIDs          = @()

    FailSafeNoRemove        = $false
    DriftDetected           = $false
    PostCompliant           = $null

    MembersBefore           = @()
    MembersAfter            = @()

    ToAddSIDs               = @()
    ToRemove                = @()  # member records

    AddedSIDs               = @()
    RemovedIds              = @()

    Errors                  = @()

    EventId                 = $null
    EventLevel              = $null
    EventMessage            = $null
  }
}


# ---------------- Main ----------------

Ensure-EventSource -Source $script:EventSource -LogName $script:EventLogName

$result = $null

try {
  $adminGroupName = Get-AdministratorsGroupName
  $result = New-GuardrailResult -GroupName $adminGroupName

  # Load config (optional)
  $cfg = Get-Config -Path $ConfigPath
  if ($cfg) {
    $result.ConfigLoaded = $true
    if (-not $AllowListPath -and $cfg.LocalAdmins -and $cfg.LocalAdmins.AllowListPath) {
      $AllowListPath = [string]$cfg.LocalAdmins.AllowListPath
    }
  }
  $result.AllowListPathUsed = $AllowListPath

  # Read allow-list (optional) + defaults
  $allowInput = Read-AllowList -AllowListPath $AllowListPath -Extra $ExtraAllow
  if (-not $allowInput -or $allowInput.Count -eq 0) { $allowInput = @($script:DefaultAllowList) }
  $result.AllowInput = @($allowInput)

  # Resolve allow-list entries -> SIDs
  $allowResolved = @()
  $unresolvedAllow = @()

  foreach ($a in $allowInput) {
    $sid = Resolve-ToSid -IdOrName $a
    if ($sid) { $allowResolved += [pscustomobject]@{ Input = $a; SID = $sid } }
    else      { $unresolvedAllow += $a }
  }

  $allowSIDs = @($allowResolved | Select-Object -ExpandProperty SID | Sort-Object -Unique)

  $result.AllowResolved        = @($allowResolved)
  $result.AllowSIDs            = @($allowSIDs)
  $result.UnresolvedAllowInput = @($unresolvedAllow)

  # Always keep built-in Administrator (RID 500)
  $sid500 = Get-BuiltinAdministratorSid
  $result.BuiltinAdminSid500 = $sid500
  if ($sid500) { $result.AlwaysKeepSIDs = @($sid500) }

  # Fail-safe removals:
  # - unresolved allow entries OR no effective allow-list
  $noEffectiveAllowList = (@($allowSIDs).Count -eq 0)
  $result.FailSafeNoRemove = ((@($unresolvedAllow).Count -gt 0) -or $noEffectiveAllowList)

  # Enumerate members (structured records)
  $membersBefore = @(Get-AdministratorsGroupMembers -GroupName $adminGroupName)
  $result.MembersBefore = $membersBefore

  $currSIDs = @($membersBefore | Where-Object { $_.SID } | Select-Object -ExpandProperty SID | Sort-Object -Unique)

  # Diff: Add
  $toAddSIDs = @()
  if (@($allowSIDs).Count -gt 0) {
    $toAddSIDs = @($allowSIDs | Where-Object { $currSIDs -notcontains $_ })
  }
  $result.ToAddSIDs = $toAddSIDs

  # Diff: Remove
  $toRemove = @()
  foreach ($m in $membersBefore) {
    if (-not $m.SID) { continue }
    if ($allowSIDs -contains $m.SID) { continue }
    if ($result.AlwaysKeepSIDs -contains $m.SID) { continue }

    $isDomainLike = Is-DomainLikePrincipal -MemberRecord $m
    if (-not $AllowDomainRemediation -and $isDomainLike) { continue }

    if (-not $result.FailSafeNoRemove) { $toRemove += $m }
  }
  $result.ToRemove = $toRemove

  $result.DriftDetected = (
    (@($unresolvedAllow).Count -gt 0) -or
    (@($toAddSIDs).Count -gt 0) -or
    (@($toRemove).Count -gt 0)
  )

  # Remediation
  if ($Remediate) {

    foreach ($sid in $toAddSIDs) {
      try {
        if ($PSCmdlet.ShouldProcess($adminGroupName, "Add SID $sid")) {
          # Add by SID using -SID.
          $sidObj = New-Object System.Security.Principal.SecurityIdentifier($sid)
          Add-LocalGroupMember -Group $adminGroupName -SID $sidObj -ErrorAction Stop
          $result.AddedSIDs += $sid
        }
      } catch {
        $result.Errors += "Add $sid failed: $($_.Exception.Message)"
      }
    }

    foreach ($m in $toRemove) {
      try {
        # Remove by name or SID string via -Member.
        $memberId = $null
        if ($m.SID) { $memberId = $m.SID } elseif ($m.Name) { $memberId = $m.Name }
        if (-not $memberId) { throw "Cannot determine member identity for removal." }

        if ($PSCmdlet.ShouldProcess($adminGroupName, "Remove $memberId")) {
          Remove-LocalGroupMember -Group $adminGroupName -Member $memberId -ErrorAction Stop
          $result.RemovedIds += $memberId
        }
      } catch {
        $disp = if ($m.Name) { $m.Name } elseif ($m.SID) { $m.SID } else { "(unknown)" }
        $result.Errors += "Remove $disp failed: $($_.Exception.Message)"
      }
    }

    # Post-check (same rules)
    $membersAfter = @(Get-AdministratorsGroupMembers -GroupName $adminGroupName)
    $result.MembersAfter = $membersAfter

    $currAfterSIDs = @($membersAfter | Where-Object { $_.SID } | Select-Object -ExpandProperty SID | Sort-Object -Unique)

    $toAddAfter = @()
    if (@($allowSIDs).Count -gt 0) {
      $toAddAfter = @($allowSIDs | Where-Object { $currAfterSIDs -notcontains $_ })
    }

    $toRemoveAfter = @()
    foreach ($m in $membersAfter) {
      if (-not $m.SID) { continue }
      if ($allowSIDs -contains $m.SID) { continue }
      if ($result.AlwaysKeepSIDs -contains $m.SID) { continue }

      $isDomainLike = Is-DomainLikePrincipal -MemberRecord $m
      if (-not $AllowDomainRemediation -and $isDomainLike) { continue }

      if (-not $result.FailSafeNoRemove) { $toRemoveAfter += $m }
    }

    $result.PostCompliant = (
      (@($unresolvedAllow).Count -eq 0) -and
      (@($toAddAfter).Count -eq 0) -and
      (@($toRemoveAfter).Count -eq 0) -and
      (@($result.Errors).Count -eq 0)
    )
  }

  # Status + event
  $ok = $true
  if (@($result.Errors).Count -gt 0) { $ok = $false }
  elseif ((-not $Remediate) -and $result.DriftDetected) { $ok = $false }
  elseif ($Remediate -and ($result.PostCompliant -ne $true)) { $ok = $false }

  if ($ok) {
    $result.EventId    = 3500
    $result.EventLevel = 'Information'
  } else {
    $result.EventId    = 3510
    $result.EventLevel = 'Warning'
  }

  $result.EventMessage = @(
    "Local Admins Guardrail"
    ("Group={0}; Remediate={1}; AllowDomainRemediation={2}" -f $result.GroupName, $result.Remediate, $result.AllowDomainRemediation)
    ("ConfigLoaded={0}; AllowListPath={1}" -f $result.ConfigLoaded, ($(if ($result.AllowListPathUsed) { $result.AllowListPathUsed } else { "(none)" })))
    ("AllowResolvedSidCount={0}; UnresolvedAllowCount={1}; FailSafeNoRemove={2}" -f @($result.AllowSIDs).Count, @($result.UnresolvedAllowInput).Count, $result.FailSafeNoRemove)
    ("MembersBefore={0}; ToAdd={1}; ToRemove={2}; Errors={3}" -f @($result.MembersBefore).Count, @($result.ToAddSIDs).Count, @($result.ToRemove).Count, @($result.Errors).Count)
    ($(if ($result.Remediate) { "PostCompliant=$($result.PostCompliant)" } else { "DriftDetected=$($result.DriftDetected)" }))
  ) -join "`r`n"

  Write-HealthEvent -Id $result.EventId -Message $result.EventMessage -Level $result.EventLevel

} catch {
  $errMsg = $_.Exception.Message

  if (-not $result) {
    $groupNameFallback = '(unknown)'
    try { $groupNameFallback = Get-AdministratorsGroupName } catch { <# best-effort: group name resolution in error handler #> }
    $result = New-GuardrailResult -GroupName $groupNameFallback
  }

  $result.Errors += ("Fatal error: " + $errMsg)
  $result.EventId = 3510
  $result.EventLevel = 'Error'
  $result.EventMessage = "Local Admins Guardrail error: $errMsg"

  Write-HealthEvent -Id 3510 -Message $result.EventMessage -Level 'Error'

} finally {
  if ($result -and -not $Quiet) {
    $summaryObj = [pscustomobject]@{ ComputerName = $result.ComputerName; Timestamp = Get-Date }
    Write-ConsoleSummary -Summary $summaryObj -Findings ([System.Collections.ArrayList]::new()) `
      -CustomFields ([ordered]@{
        Group            = $result.GroupName
        Status           = ("{0} (EventId {1})" -f $result.EventLevel, $result.EventId)
        Remediate        = [string]$result.Remediate
        DriftDetected    = [string]$result.DriftDetected
        ToAdd            = @($result.ToAddSIDs).Count
        ToRemove         = @($result.ToRemove).Count
        FailSafeNoRemove = [string]$result.FailSafeNoRemove
        ConfigLoaded     = [string]$result.ConfigLoaded
      })
    if (@($result.Errors).Count -gt 0) {
      Write-ColorLine "Errors:" 'Red'
      foreach ($e in $result.Errors) { Write-ColorLine ("- {0}" -f $e) 'Red' }
      Write-UiLine ""
    }
  }
}

# V2 output contract
$resultToken = if ($result.DriftDetected) { 'WARN' } else { 'OK' }
$v2Result = New-V2ResultObject -ScriptName '03-LocalAdmins-Guardrail.ps1' -Mode $Mode -Result $resultToken -Findings @() -Summary $result -Metadata @{}
Write-ResultObject -ResultObject $v2Result -OutputFormat $OutputFormat -OutputPath $OutputPath
if ($PassThru) { $v2Result }
exit 0
