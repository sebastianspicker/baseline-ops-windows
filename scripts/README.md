# Script reference

The `scripts/` directory contains operator entry points. Files under `scripts/internal/` and `scripts/_lib/` are implementation details and should not be invoked directly.

## Orchestration scripts

| Script | Function |
| --- | --- |
| `00-Copy-Local.ps1` | Copies a selected repository revision or local source into a destination root. |
| `00-Report-Aggregate.ps1` | Reads v2 JSON results from a directory and writes a combined report. |
| `00-Run-Batch.ps1` | Builds a temporary profile for a curated category and delegates to the profile runner. |
| `00-Run-Local.ps1` | Resolves and runs one numbered script with optional signature or hash verification. |
| `00-Run-Profile.ps1` | Validates and executes profile steps in dependency order. |
| `00-Validate-Profile.ps1` | Validates profile structure, script references, dependencies, and integrity fields. |

The default deployment root for the runners is `C:\install\mdm\ps1`. When that path is absent and `-RootPath` was not supplied, source-tree execution falls back to the repository root. Pass `-RootPath` explicitly in automation.

`00-Run-Batch.ps1` accepts these categories:

| Category | Script numbers |
| --- | --- |
| `Audit` | 01-07, 09-11, 13-15, 18-20, 22-24, 26-52 |
| `Remediation` | 01-08, 13, 14, 16, 18, 21, 22, 25, 31-33, 38-40, 44 |
| `Collection` | 09-12, 20 |
| `Utility` | 08, 25 |
| `Monitoring` | 17, 32, 34, 38 |
| `All` | Every numbered script |

These are curated batch memberships. A script can expose additional direct-invocation behavior that is not represented by a batch category.

## Endpoint script catalog

| Script | Primary function |
| --- | --- |
| `01-ASR-Defender-Allowlist.ps1` | Synchronize Defender exclusions, ASR-only exclusions, and Controlled Folder Access allow lists. |
| `02-LAPS-Hygiene.ps1` | Check Windows LAPS health and optionally trigger password rotation. |
| `03-LocalAdmins-Guardrail.ps1` | Compare and optionally reconcile local Administrators membership. |
| `04-OfficeBrowser-Hardening-Proof.ps1` | Audit and optionally set Office, Edge, and Firefox registry policy values. |
| `05-WUFB-Proofing.ps1` | Audit and optionally set Windows Update policy from a catalog. |
| `06-UpdateHealth-SSU-Proof.ps1` | Check update health, SSU state, services, and tasks; apply selected fixes. |
| `07-ScheduledTasks-Hygiene.ps1` | Audit scheduled tasks and optionally enable or quarantine selected tasks. |
| `08-WinGet-SelfHeal.ps1` | Check WinGet prerequisites and optionally install dependencies or add a source. |
| `09-SupportBundle.ps1` | Collect diagnostics and selected event logs into a ZIP archive. |
| `10-SupportBundle-Parser.ps1` | Extract and summarize the newest support bundle in a directory. |
| `11-IOC-Sweep-Defender.ps1` | Check catalog-defined indicators and optionally perform requested containment actions. |
| `12-Suspicious-Artifact-Grabber.ps1` | Collect process and file artifacts into an incident-response bundle. |
| `13-LSASS-CG-HVCI-VBS.ps1` | Audit and optionally set LSASS, Credential Guard, HVCI, and VBS policy. |
| `14-SecureRemoteAccessGuardrails.ps1` | Audit and optionally configure RDP, Remote Assistance, firewall, and group membership. |
| `15-HardwareTPM-Audit.ps1` | Report TPM, Secure Boot, BitLocker, and BIOS posture. |
| `16-Sysmon-Config-Updater.ps1` | Validate, install, or update a Sysmon configuration. |
| `17-Sysmon-Rule-Drift-Sensor.ps1` | Detect Sysmon event-rule drift and optionally trigger a trusted updater. |
| `18-Firewall-Baseline.ps1` | Audit and optionally apply firewall profile, logging, and local-rule configuration. |
| `19-Software-Audit.ps1` | Compare installed software with a catalog. |
| `20-MissingPatch-Notification.ps1` | Compare installed KBs with a curated JSON feed. |
| `21-EmergencyKillSwitch.ps1` | Audit or apply host network isolation with optional break-glass and rollback settings. |
| `22-SMB-Encryption-Enforcer.ps1` | Audit or require SMB encryption globally, per share, or for client connections. |
| `23-BitLocker-Operations-Audit.ps1` | Report BitLocker state for a volume. |
| `24-Cert-AutoEnrollment-Health.ps1` | Trigger autoenrollment and report related events and certificate expiry. |
| `25-WinGet-Config-Baseline-Runner.ps1` | Run WinGet Configuration validate, test, and optional apply operations. |
| `26-Get-WinEvent-FastTriage.ps1` | Query Windows event logs with bounded filters and optional export. |
| `27-Defender-Health-Audit.ps1` | Report Defender service, protection, signature, and scan state. |
| `28-Join-Identity-Audit.ps1` | Report host, domain or workgroup, role, and operating system identity. |
| `29-Network-Config-Audit.ps1` | Report per-interface IP, gateway, and DNS configuration. |
| `30-Service-Process-Audit.ps1` | Report processes, services, resource use, and executable paths. |
| `31-PowerShell-Logging-Baseline.ps1` | Audit and optionally set PowerShell logging policy. |
| `32-Firewall-Logging-Audit.ps1` | Audit and optionally set firewall log configuration. |
| `33-AdvancedAuditPolicy-Audit.ps1` | Audit and optionally apply Advanced Audit Policy subcategories. |
| `34-TimeSync-Health.ps1` | Report Windows Time service, source, sync, and configuration state. |
| `35-Storage-Reliability-Audit.ps1` | Report physical disks and available reliability counters. |
| `36-Backup-Readiness-Audit.ps1` | Report built-in backup and restore readiness indicators. |
| `37-Remote-Surface-Audit.ps1` | Report WinRM, SSH, RDP, and SMB exposure. |
| `38-SecurityOptions-Drift.ps1` | Compare selected security-related registry settings with desired state. |
| `39-CredentialGuard-VBS-AuditRemediate.ps1` | Audit and optionally set Credential Guard and VBS policy. |
| `40-AddedLSAProtection-RunAsPPL-AuditRemediate.ps1` | Audit and optionally set LSA protection policy. |
| `41-NTLM-Audit-Client.ps1` | Report LAN Manager authentication-level policy. |
| `42-Client-SecurityBaseline-Report-IntuneRef.ps1` | Compare local state with a reference client security baseline. |
| `43-AppControlForBusiness-Audit.ps1` | Report WDAC and App Control for Business indicators. |
| `44-Defender-Ransomware-NetworkProtection-AuditRemediate.ps1` | Audit and optionally set Controlled Folder Access and Network Protection. |
| `45-WEF-Client-Forwarding-Readiness-Audit.ps1` | Report Windows Event Forwarding client readiness. |
| `46-SecureBoot-UEFI-Audit.ps1` | Report Secure Boot and UEFI state. |
| `47-WDAG-Readiness-Audit.ps1` | Report Windows Defender Application Guard readiness. |
| `48-ExploitProtection-Audit.ps1` | Report Windows exploit-protection settings. |
| `49-DriverSigning-Integrity-Audit.ps1` | Report driver-signing and kernel code-integrity state. |
| `50-AMSI-Audit.ps1` | Report AMSI provider registration and common bypass indicators. |
| `51-AppLocker-Audit.ps1` | Report AppLocker enforcement and rule coverage. |
| `52-DoH-Audit.ps1` | Report Windows DNS-over-HTTPS client configuration. |

## Common parameters

Every script has comment-based help. Run `Get-Help .\scripts\<name>.ps1 -Full` before use because parameters and side effects are script-specific.

Most numbered scripts expose some of these shared parameters:

| Parameter | Meaning |
| --- | --- |
| `-Mode` | `Audit` or `Remediate`, subject to the script's accepted values and implementation. |
| `-ConfigPath` | Script-specific wrapper configuration. |
| `-OutputFormat` | `Console`, `Json`, `Csv`, or `None`. |
| `-OutputPath` | Path for shared JSON or CSV result output. |
| `-PassThru` | Emit the structured result object. |
| `-Strict` | Apply stricter warning or drift handling where implemented. |
| `-Quiet` | Reduce informational console output. |
| `-NoColor` | Disable colored console rendering. |
| `-WhatIf` | Skip state-changing operations guarded by `ShouldProcess`. |
| `-Confirm` | Request or suppress confirmation for guarded operations. |

Script-specific exports use parameters such as `-ExportPath`, `-ProofPath`, `-AuditPath`, or `-StatePath`. These outputs can be written in Audit mode.

## Examples

Run a direct audit with a shipped catalog:

```powershell
.\scripts\18-Firewall-Baseline.ps1 `
  -CatalogPath .\examples\configs\firewall-baseline.json -Mode Audit
```

Preview direct remediation:

```powershell
.\scripts\18-Firewall-Baseline.ps1 `
  -CatalogPath .\examples\configs\firewall-baseline.json `
  -Mode Remediate -WhatIf
```

Run one script with an expected SHA-256 hash:

```powershell
$hash = (Get-FileHash .\scripts\27-Defender-Health-Audit.ps1 -Algorithm SHA256).Hash
.\scripts\00-Run-Local.ps1 `
  -ScriptName 27-Defender-Health-Audit.ps1 -RootPath . `
  -ExpectedHash "SHA256:$hash" -Mode Audit
```

Validate a profile before execution:

```powershell
.\scripts\00-Validate-Profile.ps1 `
  -ProfilePath .\examples\profiles\baseline-audit.json -RootPath .
```

## Result contract

Orchestration-compatible scripts use the v2 result helpers in `lib/Serialization.psm1`. See the [shared module reference](../lib/README.md) for the object and finding structure.
