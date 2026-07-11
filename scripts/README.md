# Security Hardening Scripts

This directory contains PowerShell scripts for Windows MDM security auditing, triage, and controlled remediation.

Use `00-*` scripts as the orchestration layer. Use numbered scripts as endpoint-operation units.

## Maintainer Map

- Profiles describe intent and sequencing.
- Profiles must not bypass runner-owned script-root, hash/signature, `-WhatIf`, or `-Confirm` controls.
- When reviewing a numbered script, start with the help block and parameter block, then inspect the final result object.
- Helper functions should wrap Windows APIs/commands, normalize configuration, or build findings for the v2 result contract.

## Orchestration Scripts

| Script | Purpose |
| --- | --- |
| `00-Copy-Local.ps1` | Copy the repository to a local execution path. |
| `00-Run-Local.ps1` | Run one script through the local runner path. |
| `00-Validate-Profile.ps1` | Validate a v2 orchestration profile. |
| `00-Run-Profile.ps1` | Run profile steps in dependency/order sequence. |
| `00-Run-Batch.ps1` | Run scripts by category. |
| `00-Report-Aggregate.ps1` | Aggregate JSON outputs from multiple runs. |

## Script Catalog

| Script | Area | Mode |
| --- | --- | --- |
| `01-ASR-Defender-Allowlist.ps1` | Defender ASR and exclusions | Audit, Remediate |
| `02-LAPS-Hygiene.ps1` | LAPS hygiene | Audit, Remediate |
| `03-LocalAdmins-Guardrail.ps1` | Local administrator membership | Audit, Remediate |
| `04-OfficeBrowser-Hardening-Proof.ps1` | Office/browser hardening proof | Audit, Remediate |
| `05-WUFB-Proofing.ps1` | Windows Update for Business | Audit, Remediate |
| `06-UpdateHealth-SSU-Proof.ps1` | Update health and SSU proof | Audit, Remediate |
| `07-ScheduledTasks-Hygiene.ps1` | Scheduled task hygiene | Audit, Remediate |
| `08-WinGet-SelfHeal.ps1` | WinGet self-heal checks | Audit, Remediate |
| `09-SupportBundle.ps1` | Support bundle collection | Audit |
| `10-SupportBundle-Parser.ps1` | Support bundle parsing | Audit |
| `11-IOC-Sweep-Defender.ps1` | Defender IOC sweep | Audit, Remediate |
| `12-Suspicious-Artifact-Grabber.ps1` | Suspicious artifact collection | Audit |
| `13-LSASS-CG-HVCI-VBS.ps1` | LSASS, Credential Guard, HVCI, VBS | Audit, Remediate |
| `14-SecureRemoteAccessGuardrails.ps1` | Secure remote access guardrails | Audit, Remediate |
| `15-HardwareTPM-Audit.ps1` | Hardware and TPM posture | Audit |
| `16-Sysmon-Config-Updater.ps1` | Sysmon configuration | Audit, Remediate |
| `17-Sysmon-Rule-Drift-Sensor.ps1` | Sysmon rule drift | Audit |
| `18-Firewall-Baseline.ps1` | Firewall baseline | Audit, Remediate |
| `19-Software-Audit.ps1` | Software inventory | Audit |
| `20-MissingPatch-Notification.ps1` | Patch notification state | Audit |
| `21-EmergencyKillSwitch.ps1` | Emergency containment | Audit, Remediate |
| `22-SMB-Encryption-Enforcer.ps1` | SMB encryption | Audit, Remediate |
| `23-BitLocker-Operations-Audit.ps1` | BitLocker operations | Audit |
| `24-Cert-AutoEnrollment-Health.ps1` | Certificate autoenrollment | Audit |
| `25-WinGet-Config-Baseline-Runner.ps1` | WinGet configuration baseline | Audit, Remediate |
| `26-Get-WinEvent-FastTriage.ps1` | Event log triage | Audit |
| `27-Defender-Health-Audit.ps1` | Defender health | Audit |
| `28-Join-Identity-Audit.ps1` | Domain/join identity | Audit |
| `29-Network-Config-Audit.ps1` | Network configuration | Audit |
| `30-Service-Process-Audit.ps1` | Services and processes | Audit |
| `31-PowerShell-Logging-Baseline.ps1` | PowerShell logging baseline | Audit, Remediate |
| `32-Firewall-Logging-Audit.ps1` | Firewall logging | Audit, Remediate |
| `33-AdvancedAuditPolicy-Audit.ps1` | Advanced audit policy | Audit, Remediate |
| `34-TimeSync-Health.ps1` | Time sync health | Audit |
| `35-Storage-Reliability-Audit.ps1` | Storage reliability | Audit |
| `36-Backup-Readiness-Audit.ps1` | Backup readiness | Audit |
| `37-Remote-Surface-Audit.ps1` | Remote access surface | Audit |
| `38-SecurityOptions-Drift.ps1` | Security options drift | Audit, Remediate |
| `39-CredentialGuard-VBS-AuditRemediate.ps1` | Credential Guard and VBS | Audit, Remediate |
| `40-AddedLSAProtection-RunAsPPL-AuditRemediate.ps1` | LSA protection | Audit, Remediate |
| `41-NTLM-Audit-Client.ps1` | NTLM client posture | Audit |
| `42-Client-SecurityBaseline-Report-IntuneRef.ps1` | Intune baseline comparison | Audit |
| `43-AppControlForBusiness-Audit.ps1` | App Control for Business | Audit |
| `44-Defender-Ransomware-NetworkProtection-AuditRemediate.ps1` | Defender ransomware and network protection | Audit, Remediate |
| `45-WEF-Client-Forwarding-Readiness-Audit.ps1` | WEF forwarding readiness | Audit |
| `46-SecureBoot-UEFI-Audit.ps1` | Secure Boot and UEFI | Audit |
| `47-WDAG-Readiness-Audit.ps1` | Windows Defender Application Guard readiness | Audit |
| `48-ExploitProtection-Audit.ps1` | Exploit Protection | Audit |
| `49-DriverSigning-Integrity-Audit.ps1` | Driver signing integrity | Audit |
| `50-AMSI-Audit.ps1` | AMSI posture | Audit |
| `51-AppLocker-Audit.ps1` | AppLocker policy | Audit |
| `52-DoH-Audit.ps1` | DNS-over-HTTPS client configuration | Audit |

## Common Parameters

Most scripts support a subset of these parameters:

| Parameter | Description |
| --- | --- |
| `-Mode` | v2 normalized mode: `Audit` or `Remediate`. |
| `-ConfigPath` / `-CatalogPath` | JSON configuration or catalog path. |
| `-OutputFormat` | `Console`, `Json`, `Csv`, or `None`. |
| `-OutputPath` | Target path for JSON or CSV output. |
| `-ExportPath` | Base path for script-specific exports. |
| `-Strict` | Fail on warnings where supported. |
| `-PassThru` | Emit one structured object for the pipeline. |
| `-Quiet` / `-NoColor` | Reduce console noise or disable color. |
| `-WhatIf` | Preview changes without applying them. |
| `-Confirm` | Require confirmation before changes. |

Mutation-capable scripts implement `SupportsShouldProcess` and honor `-WhatIf` / `-Confirm` on state-changing paths.

## Examples

```powershell
# Audit with defaults
.\01-ASR-Defender-Allowlist.ps1

# Audit with config
.\01-ASR-Defender-Allowlist.ps1 -ConfigPath "C:\Config\asr-config.json"

# Preview remediation
.\03-LocalAdmins-Guardrail.ps1 -Mode Remediate -WhatIf

# Get structured output
$result = .\05-WUFB-Proofing.ps1 -PassThru
$result | ConvertTo-Json -Depth 6
```

## Prerequisites

- Windows 10/11 or Windows Server 2016+
- PowerShell 5.1 or PowerShell 7+
- Administrator privileges for most scripts
- Domain privileges for some identity operations
- Script-specific Windows features such as Defender, BitLocker, Sysmon, or WinGet

The optional Windows Forms launcher has a narrower current prerequisite:
Windows PowerShell 5.1 with .NET Framework 4.8. PowerShell 7 support is intended,
but the launcher remains alpha until both runtimes complete the Windows UI gate.

## Configuration

Most scripts support JSON configuration files. See `../examples/configs/` for examples.

## Output Contract

Scripts that support `-PassThru` return one structured object. v2 orchestration-compatible scripts use the shared result helpers in `lib/Serialization.psm1`.

See [lib/README.md](../lib/README.md) for the shared result shape and finding-code conventions.
