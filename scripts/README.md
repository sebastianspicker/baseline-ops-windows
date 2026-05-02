# Security Hardening Scripts

This directory contains PowerShell scripts for Windows MDM security hardening and v2 orchestration, organized by category.

## Maintainer map

Use the `00-*` scripts as the orchestration layer and the numbered scripts as
the endpoint-operation layer. Profiles should describe intent and sequencing;
they should not bypass runner-owned safety controls such as script roots,
hash/signature checks, `-WhatIf`, or `-Confirm`.

When reading a numbered script, start with the help block and parameter block,
then jump to the final summary/result construction. Helper functions in the
middle should either wrap a Windows API/command, normalize configuration, or
build findings for the v2 result contract.

## Categories

### Audit Scripts
Scripts that check configuration and report drift without making changes.

| Script | Purpose | Key Parameters |
|--------|---------|----------------|
| `01-ASR-Defender-Allowlist.ps1` | ASR rules and Defender exclusions audit | `-ExceptionsPath`, `-ConfigPath` |
| `02-LAPS-Hygiene.ps1` | LAPS password rotation hygiene | `-MinDaysBeforeRotate`, `-Mode Remediate` |
| `03-LocalAdmins-Guardrail.ps1` | Local administrator group membership audit | `-AllowlistPath`, `-Mode Remediate` |
| `04-OfficeBrowser-Hardening-Proof.ps1` | Office/Browser registry hardening proof | `-CatalogPath`, `-ConfigPath`, `-Mode Remediate` |
| `05-WUFB-Proofing.ps1` | Windows Update for Business proofing | `-CatalogPath`, `-Mode Remediate` |
| `06-UpdateHealth-SSU-Proof.ps1` | Update health and SSU verification | `-CatalogPath`, `-ConfigPath` |
| `07-ScheduledTasks-Hygiene.ps1` | Scheduled task health and security hygiene | `-CatalogPath`, `-ConfigPath`, `-Mode Remediate` |
| `09-SupportBundle.ps1` | Collect diagnostic support bundle | `-BundleName`, `-IncludeKbFeed` |
| `10-SupportBundle-Parser.ps1` | Parse support bundle archives | `-SupportDir`, `-ConfigPath` |
| `13-LSASS-CG-HVCI-VBS.ps1` | LSASS, Credential Guard, HVCI, VBS audit | `-ConfigPath`, `-Mode Remediate` |
| `14-SecureRemoteAccessGuardrails.ps1` | Secure remote access guardrails audit | `-ConfigPath`, `-Mode Remediate` |
| `15-HardwareTPM-Audit.ps1` | Hardware and TPM compliance | `-CatalogPath`, `-ConfigPath` |
| `16-Sysmon-Config-Updater.ps1` | Sysmon configuration audit and update | `-ConfigPath`, `-Mode Remediate` |
| `18-Firewall-Baseline.ps1` | Firewall baseline audit | `-ConfigPath`, `-Mode Remediate` |
| `19-Software-Audit.ps1` | Installed software inventory | `-CatalogPath`, `-StatePath` |
| `22-SMB-Encryption-Enforcer.ps1` | SMB encryption settings audit | `-ConfigPath`, `-Mode Remediate` |
| `23-BitLocker-Operations-Audit.ps1` | BitLocker configuration audit | `-ConfigPath` |
| `24-Cert-AutoEnrollment-Health.ps1` | Certificate autoenrollment health, expiring cert report | `-WarnDays`, `-ConfigPath`, `-ExportPath` |
| `26-Get-WinEvent-FastTriage.ps1` | Fast event log triage | `-ConfigPath`, `-MaxEvents` |
| `27-Defender-Health-Audit.ps1` | Defender health status | `-SettingsJsonPath` |
| `28-Join-Identity-Audit.ps1` | Domain join and identity audit | `-ConfigPath`, `-ExportPath` |
| `29-Network-Config-Audit.ps1` | Network configuration audit | `-JsonPath`, `-ExportPath` |
| `30-Service-Process-Audit.ps1` | Running services and processes | `-ConfigJsonPath` |
| `33-AdvancedAuditPolicy-Audit.ps1` | Advanced audit policy settings | `-DesiredPolicyJson`, `-Mode Remediate` |
| `35-Storage-Reliability-Audit.ps1` | Storage and disk health | `-ConfigJsonPath`, `-ExportPath` |
| `36-Backup-Readiness-Audit.ps1` | Backup configuration readiness | `-ConfigJsonPath` |
| `37-Remote-Surface-Audit.ps1` | Remote access surface audit | `-ConfigPath`, `-ExportPath` |
| `42-Client-SecurityBaseline-Report-IntuneRef.ps1` | Security baseline comparison | `-ReferenceJsonPath` |
| `43-AppControlForBusiness-Audit.ps1` | App Control for Business audit | `-ConfigPath` |
| `44-Defender-Ransomware-NetworkProtection-AuditRemediate.ps1` | Ransomware protection audit | `-ConfigJsonPath`, `-Mode Remediate` |
| `45-WEF-Client-Forwarding-Readiness-Audit.ps1` | WEF client readiness | `-ConfigPath`, `-IncludeWecutilCheck` |
| `46-SecureBoot-UEFI-Audit.ps1` | Secure Boot and UEFI firmware verification | `-ConfigPath` |
| `47-WDAG-Readiness-Audit.ps1` | Application Guard prerequisites audit | `-ConfigPath` |
| `48-ExploitProtection-Audit.ps1` | Exploit Protection and ASR mitigations | `-ConfigPath` |
| `49-DriverSigning-Integrity-Audit.ps1` | Driver signing and kernel code integrity | `-ConfigPath` |
| `50-AMSI-Audit.ps1` | AMSI provider registration and bypass detection | `-ConfigPath` |
| `51-AppLocker-Audit.ps1` | AppLocker policy enforcement and rule coverage | `-ConfigPath` |
| `52-DoH-Audit.ps1` | DNS-over-HTTPS client configuration audit | `-ConfigPath` |

### Remediation Scripts
Scripts that can apply fixes when run with `-Mode Remediate`.

| Script | Purpose | What It Remediates |
|--------|---------|-------------------|
| `01-ASR-Defender-Allowlist.ps1` | ASR/Defender allowlist sync | Adds/removes exclusions to match JSON |
| `02-LAPS-Hygiene.ps1` | LAPS password rotation | Rotates expired LAPS passwords |
| `03-LocalAdmins-Guardrail.ps1` | Local admins enforcement | Removes unauthorized admins |
| `04-OfficeBrowser-Hardening-Proof.ps1` | Office/Browser hardening | Applies registry hardening settings |
| `05-WUFB-Proofing.ps1` | WUfB configuration | Applies update policy settings |
| `07-ScheduledTasks-Hygiene.ps1` | Scheduled task hygiene | Re-enables critical tasks; quarantines risky tasks |
| `13-LSASS-CG-HVCI-VBS.ps1` | LSASS/Credential Guard | Enables VBS, HVCI, Credential Guard |
| `14-SecureRemoteAccessGuardrails.ps1` | Remote access hardening | Configures RDP, VPN, firewall rules |
| `16-Sysmon-Config-Updater.ps1` | Sysmon configuration | Updates Sysmon config, ensures channel |
| `18-Firewall-Baseline.ps1` | Firewall rules | Creates/updates firewall rules |
| `21-EmergencyKillSwitch.ps1` | Emergency containment | Blocks network, disables accounts |
| `22-SMB-Encryption-Enforcer.ps1` | SMB encryption | Enforces SMB encryption settings |
| `31-PowerShell-Logging-Baseline.ps1` | PowerShell logging | Enables script block logging |
| `33-AdvancedAuditPolicy-Audit.ps1` | Audit policy | Sets audit subcategory settings |
| `39-CredentialGuard-VBS-AuditRemediate.ps1` | Credential Guard | Enables CG, VBS, HVCI |
| `40-AddedLSAProtection-RunAsPPL-AuditRemediate.ps1` | LSA Protection | Enables LSA Protection (RunAsPPL) |
| `44-Defender-Ransomware-NetworkProtection-AuditRemediate.ps1` | Network protection | Enables ransomware protection |

### Collection Scripts
Scripts that gather data for analysis without configuration changes.

| Script | Purpose | Output |
|--------|---------|--------|
| `09-SupportBundle.ps1` | Diagnostic bundle collection | ZIP archive with logs, configs |
| `10-SupportBundle-Parser.ps1` | Bundle parsing and analysis | Structured JSON analysis |
| `11-IOC-Sweep-Defender.ps1` | IOC scanning and collection | Evidence archive, findings |
| `12-Suspicious-Artifact-Grabber.ps1` | Artifact collection | Structured artifact archive |
| `20-MissingPatch-Notification.ps1` | Patch status notification | Notification, state JSON |

### Utility Scripts
Helper scripts for setup and operations.

| Script | Purpose |
|--------|---------|
| `00-Copy-Local.ps1` | Copy repository to local machine |
| `00-Run-Local.ps1` | Run scripts from local copy |
| `00-Validate-Profile.ps1` | Validate v2 orchestration profile JSON |
| `00-Run-Profile.ps1` | Execute profile steps with dependency + fail strategy |
| `00-Run-Batch.ps1` | Execute category-based batches via profile layer |
| `00-Report-Aggregate.ps1` | Aggregate v2 JSON results into a summary report |
| `25-WinGet-Config-Baseline-Runner.ps1` | WinGet configuration deployment |
| `08-WinGet-SelfHeal.ps1` | WinGet self-healing for apps |

### Monitoring Scripts
Scripts for ongoing monitoring and drift detection.

| Script | Purpose | Frequency |
|---------|---------|-----------|
| `17-Sysmon-Rule-Drift-Sensor.ps1` | Sysmon config drift detection | Continuous |
| `34-TimeSync-Health.ps1` | Time synchronization health | Periodic |
| `38-SecurityOptions-Drift.ps1` | Security options drift | Periodic |
| `41-NTLM-Audit-Client.ps1` | NTLM / LAN Manager authentication level audit | Periodic |
| `32-Firewall-Logging-Audit.ps1` | Firewall logging status | Periodic |

### Private Helpers

Internal helper files dot-sourced by their parent scripts. Not for direct invocation.

| File | Used By | Content |
|------|---------|---------|
| `private/04-OfficeBrowser-Hardening-Proof.helpers.ps1` | `04-OfficeBrowser-Hardening-Proof.ps1` | Office/Edge/Firefox proof helpers, catalog loading, result summary |
| `private/09-SupportBundle.helpers.ps1` | `09-SupportBundle.ps1` | Bundle record creation, file/log export, config loading |
| `private/12-Suspicious-Artifact-Grabber.helpers.ps1` | `12-Suspicious-Artifact-Grabber.ps1` | Artifact collection, process/network/task collectors, result objects |

## Common Parameters and Conventions

Most scripts support these common parameters:

| Parameter | Description |
|-----------|-------------|
| `-Mode` | v2 normalized mode for orchestration (`Audit`/`Remediate`) |
| `-ConfigPath` / `-CatalogPath` | Path to JSON configuration or catalog file |
| `-OutputFormat` | `Console`, `Json`, `Csv`, or `None` |
| `-OutputPath` | Target path for `Json`/`Csv` output modes |
| `-ExportPath` | Base path for CSV/JSON export (scripts append suffixes) |
| `-Strict` | Fail on warnings, not just errors (where supported) |
| `-PassThru` | Emit a single structured object to the pipeline (Summary, Findings, etc.) |
| `-Quiet` / `-NoColor` | Reduce console noise / disable color where supported |
| `-WhatIf` | Preview changes without applying (where supported) |
| `-Confirm` | Require confirmation before changes (where supported) |

Mutation-capable scripts should implement `SupportsShouldProcess` and honor `-WhatIf` / `-Confirm` for any state-changing path.

**Pipeline output:** Scripts that document pipeline output emit exactly one structured object (e.g. `Summary`, `Findings`, `Config`) for automation (Export-Csv, ConvertTo-Json, Where-Object). Use `-PassThru` where the script gates pipeline output on that switch.

**Lib usage:** Scripts should use `lib/Console.psm1` for severity colors and summary output, `lib/JsonCatalog.psm1` for safe JSON reading, `lib/Serialization.psm1` for JSON/CSV writing, and `lib/Evidence.psm1` for hashing and evidence copy where applicable; see `lib/README.md`.

**Optional behaviour:** Some scripts support `-Strict` (treat warnings as errors) or reduced output; see each script’s comment-based help. Version and change history are in the repository root `CHANGELOG.md`.

## Usage Patterns

### Basic Audit
```powershell
.\01-ASR-Defender-Allowlist.ps1
```

### Audit with Custom Config
```powershell
.\01-ASR-Defender-Allowlist.ps1 -ConfigPath "C:\Config\asr-config.json"
```

### Remediation with Preview
```powershell
.\03-LocalAdmins-Guardrail.ps1 -Mode Remediate -WhatIf
```

### Remediation with Confirmation
```powershell
.\03-LocalAdmins-Guardrail.ps1 -Mode Remediate -Confirm
```

### Get Structured Output
```powershell
$result = .\05-WUFB-Proofing.ps1 -PassThru
$result | ConvertTo-Json -Depth 6
```

### Export Results
```powershell
.\19-Software-Audit.ps1 -PassThru | Export-Csv -NoTypeInformation -Path "software-audit.csv"
```

## Prerequisites

### Required Privileges
- Most scripts require **Administrator** privileges
- Some scripts require **Domain Admin** or equivalent for AD operations

### Required Modules
- `Common.psm1` - Core utilities
- `Output.psm1` - Console output helpers
- `Registry.psm1` - Registry operations
- `Config.psm1` - Configuration loading
- `EventLog.psm1` - Event log operations
- `Results.psm1` - Findings management
- `Console.psm1` - Console formatting
- `External.psm1` - External command wrappers

### Required Features
- Windows 10/11 or Windows Server 2016+
- PowerShell 5.1 or PowerShell 7+
- Various Windows features depending on script (BitLocker, Defender, etc.)

## Error Handling

Scripts follow consistent error handling patterns:

1. **Prerequisite checks** - Fail fast if requirements not met
2. **Structured findings** - Issues recorded as findings with severity
3. **Exit codes** - 0 for success, non-zero for errors
4. **Event logging** - Results logged to Application event log

## Output Format

Scripts that support `-PassThru` return a structured object:

```powershell
[pscustomobject]@{
  Timestamp    = [datetime]
  ComputerName = [string]
  Result       = [string]  # 'OK', 'WARN', 'FAIL'
  Findings     = [array]
  # ... script-specific properties
}
```

## Configuration Files

Most scripts support JSON configuration files. See `../examples/configs/` for examples.

### Configuration Structure
```json
{
  "ScriptName": {
    "Setting1": "value1",
    "Setting2": "value2"
  },
  "Findings": {
    "CODE001": {
      "Severity": "Medium",
      "Enabled": true
    }
  }
}
```

## Support

For issues and feature requests, see the main repository README or create an issue in the issue tracker.
