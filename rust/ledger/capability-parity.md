# Human-readable capability parity summary

This table shows the Rust implementation status of the 52 numbered PowerShell capabilities. It excludes the `00-*` orchestration helpers and is generated from [`capability-parity.json`](capability-parity.json), which records the status and evidence for each capability.

A capability marked `code_complete` can run Audit and Plan. Production Apply also requires reviewed Windows evidence, an `implemented` status, and permission compiled into the application.

## Totals

- `legacy_capabilities_expected`: 52
- `registry_descriptors`: 52
- `native_code_complete`: 48
- `native_implemented`: 0
- `in_development`: 4
- `legacy_only`: 0

## Capabilities

| Legacy | Stable v3 ID | Script | Maturity | Apply | Oracle |
| --- | --- | --- | --- | --- | --- |
| 01 | `v3.defender.asr-allowlist` | `01-ASR-Defender-Allowlist.ps1` | `code_complete` | `evidence_required` | `v3.defender.asr-allowlist.neutral` |
| 02 | `v3.laps.hygiene` | `02-LAPS-Hygiene.ps1` | `code_complete` | `evidence_required` | `v3.laps.hygiene.neutral` |
| 03 | `v3.local-admins.guardrail` | `03-LocalAdmins-Guardrail.ps1` | `code_complete` | `evidence_required` | `v3.local-admins.guardrail.neutral` |
| 04 | `v3.office-browser.hardening` | `04-OfficeBrowser-Hardening-Proof.ps1` | `code_complete` | `evidence_required` | `v3.office-browser.hardening.neutral` |
| 05 | `v3.windows-update.policy` | `05-WUFB-Proofing.ps1` | `code_complete` | `evidence_required` | `v3.windows-update.policy.neutral` |
| 06 | `v3.update-health.ssu` | `06-UpdateHealth-SSU-Proof.ps1` | `code_complete` | `evidence_required` | `v3.update-health.ssu.neutral` |
| 07 | `v3.scheduled-tasks.hygiene` | `07-ScheduledTasks-Hygiene.ps1` | `code_complete` | `evidence_required` | `v3.scheduled-tasks.hygiene.neutral` |
| 08 | `v3.winget.self-heal` | `08-WinGet-SelfHeal.ps1` | `code_complete` | `evidence_required` | `v3.winget.self-heal.neutral` |
| 09 | `v3.support-bundle.collect` | `09-SupportBundle.ps1` | `in_development` | `evidence_required` | `v3.support-bundle.collect.neutral` |
| 10 | `v3.support-bundle.parse` | `10-SupportBundle-Parser.ps1` | `code_complete` | `evidence_required` | `v3.support-bundle.parse.neutral` |
| 11 | `v3.defender.ioc-sweep` | `11-IOC-Sweep-Defender.ps1` | `in_development` | `evidence_required` | `v3.defender.ioc-sweep.neutral` |
| 12 | `v3.ir.artifact-grabber` | `12-Suspicious-Artifact-Grabber.ps1` | `in_development` | `evidence_required` | `v3.ir.artifact-grabber.neutral` |
| 13 | `v3.lsass.vbs-hardening` | `13-LSASS-CG-HVCI-VBS.ps1` | `code_complete` | `evidence_required` | `v3.lsass.vbs-hardening.neutral` |
| 14 | `v3.remote-access.guardrails` | `14-SecureRemoteAccessGuardrails.ps1` | `code_complete` | `evidence_required` | `v3.remote-access.guardrails.neutral` |
| 15 | `v3.hardware.tpm-posture` | `15-HardwareTPM-Audit.ps1` | `code_complete` | `evidence_required` | `v3.hardware.tpm-posture.neutral` |
| 16 | `v3.sysmon.config` | `16-Sysmon-Config-Updater.ps1` | `code_complete` | `evidence_required` | `v3.sysmon.config.neutral` |
| 17 | `v3.sysmon.rule-drift` | `17-Sysmon-Rule-Drift-Sensor.ps1` | `code_complete` | `evidence_required` | `v3.sysmon.rule-drift.neutral` |
| 18 | `v3.firewall.baseline` | `18-Firewall-Baseline.ps1` | `code_complete` | `evidence_required` | `v3.firewall.baseline.neutral` |
| 19 | `v3.software.inventory` | `19-Software-Audit.ps1` | `code_complete` | `evidence_required` | `v3.software.inventory.neutral` |
| 20 | `v3.patch.missing` | `20-MissingPatch-Notification.ps1` | `code_complete` | `evidence_required` | `v3.patch.missing.neutral` |
| 21 | `v3.network.emergency-isolation` | `21-EmergencyKillSwitch.ps1` | `in_development` | `evidence_required` | `v3.network.emergency-isolation.neutral` |
| 22 | `v3.smb.encryption` | `22-SMB-Encryption-Enforcer.ps1` | `code_complete` | `evidence_required` | `v3.smb.encryption.neutral` |
| 23 | `v3.bitlocker.operations` | `23-BitLocker-Operations-Audit.ps1` | `code_complete` | `evidence_required` | `v3.bitlocker.operations.neutral` |
| 24 | `v3.cert.autoenrollment-health` | `24-Cert-AutoEnrollment-Health.ps1` | `code_complete` | `evidence_required` | `v3.cert.autoenrollment-health.neutral` |
| 25 | `v3.winget.configuration` | `25-WinGet-Config-Baseline-Runner.ps1` | `code_complete` | `evidence_required` | `v3.winget.configuration.neutral` |
| 26 | `v3.eventlog.fast-triage` | `26-Get-WinEvent-FastTriage.ps1` | `code_complete` | `evidence_required` | `v3.eventlog.fast-triage.neutral` |
| 27 | `v3.defender.health` | `27-Defender-Health-Audit.ps1` | `code_complete` | `evidence_required` | `v3.defender.health.neutral` |
| 28 | `v3.identity.join` | `28-Join-Identity-Audit.ps1` | `code_complete` | `evidence_required` | `v3.identity.join.neutral` |
| 29 | `v3.network.configuration` | `29-Network-Config-Audit.ps1` | `code_complete` | `evidence_required` | `v3.network.configuration.neutral` |
| 30 | `v3.service-process.inventory` | `30-Service-Process-Audit.ps1` | `code_complete` | `evidence_required` | `v3.service-process.inventory.neutral` |
| 31 | `v3.powershell.logging` | `31-PowerShell-Logging-Baseline.ps1` | `code_complete` | `evidence_required` | `v3.powershell.logging.neutral` |
| 32 | `v3.firewall.logging` | `32-Firewall-Logging-Audit.ps1` | `code_complete` | `evidence_required` | `v3.firewall.logging.neutral` |
| 33 | `v3.advanced-audit-policy` | `33-AdvancedAuditPolicy-Audit.ps1` | `code_complete` | `evidence_required` | `v3.advanced-audit-policy.neutral` |
| 34 | `v3.time-sync.health` | `34-TimeSync-Health.ps1` | `code_complete` | `evidence_required` | `v3.time-sync.health.neutral` |
| 35 | `v3.storage.reliability` | `35-Storage-Reliability-Audit.ps1` | `code_complete` | `evidence_required` | `v3.storage.reliability.neutral` |
| 36 | `v3.backup.readiness` | `36-Backup-Readiness-Audit.ps1` | `code_complete` | `evidence_required` | `v3.backup.readiness.neutral` |
| 37 | `v3.remote-surface.audit` | `37-Remote-Surface-Audit.ps1` | `code_complete` | `evidence_required` | `v3.remote-surface.audit.neutral` |
| 38 | `v3.security-options.drift` | `38-SecurityOptions-Drift.ps1` | `code_complete` | `evidence_required` | `v3.security-options.drift.neutral` |
| 39 | `v3.credential-guard.vbs` | `39-CredentialGuard-VBS-AuditRemediate.ps1` | `code_complete` | `evidence_required` | `v3.credential-guard.vbs.neutral` |
| 40 | `v3.lsa.protection` | `40-AddedLSAProtection-RunAsPPL-AuditRemediate.ps1` | `code_complete` | `evidence_required` | `v3.lsa.protection.neutral` |
| 41 | `v3.ntlm.client` | `41-NTLM-Audit-Client.ps1` | `code_complete` | `evidence_required` | `v3.ntlm.client.neutral` |
| 42 | `v3.client-security-baseline` | `42-Client-SecurityBaseline-Report-IntuneRef.ps1` | `code_complete` | `evidence_required` | `v3.client-security-baseline.neutral` |
| 43 | `v3.app-control.audit` | `43-AppControlForBusiness-Audit.ps1` | `code_complete` | `evidence_required` | `v3.app-control.audit.neutral` |
| 44 | `v3.defender.ransomware-network-protection` | `44-Defender-Ransomware-NetworkProtection-AuditRemediate.ps1` | `code_complete` | `evidence_required` | `v3.defender.ransomware-network-protection.neutral` |
| 45 | `v3.wef.client-readiness` | `45-WEF-Client-Forwarding-Readiness-Audit.ps1` | `code_complete` | `evidence_required` | `v3.wef.client-readiness.neutral` |
| 46 | `v3.secure-boot.uefi` | `46-SecureBoot-UEFI-Audit.ps1` | `code_complete` | `evidence_required` | `v3.secure-boot.uefi.neutral` |
| 47 | `v3.wdag.readiness` | `47-WDAG-Readiness-Audit.ps1` | `code_complete` | `evidence_required` | `v3.wdag.readiness.neutral` |
| 48 | `v3.exploit-protection.audit` | `48-ExploitProtection-Audit.ps1` | `code_complete` | `evidence_required` | `v3.exploit-protection.audit.neutral` |
| 49 | `v3.driver-signing.integrity` | `49-DriverSigning-Integrity-Audit.ps1` | `code_complete` | `evidence_required` | `v3.driver-signing.integrity.neutral` |
| 50 | `v3.amsi.audit` | `50-AMSI-Audit.ps1` | `code_complete` | `evidence_required` | `v3.amsi.audit.neutral` |
| 51 | `v3.applocker.audit` | `51-AppLocker-Audit.ps1` | `code_complete` | `evidence_required` | `v3.applocker.audit.neutral` |
| 52 | `v3.doh.audit` | `52-DoH-Audit.ps1` | `code_complete` | `evidence_required` | `v3.doh.audit.neutral` |

Each entry identifies a tracked structural test fixture and the complete set of current PowerShell v2 source files it covers, including extracted helpers. These fixtures check structure, not equivalent behavior. The separate behavioral tests record only the operations actually compared.

Rust intentionally rejects legacy mechanisms that let input data choose paths, URLs, executables, arguments, or credentials, or authorize registry, network, or output operations. These restrictions are deliberate safety differences from PowerShell behavior.

Windows VM, LocalSystem, signing, protected-install, hardware, accessibility, TPM, Secure Boot, and BitLocker checks are still outstanding. See [`../release/evidence-gates.json`](../release/evidence-gates.json) for the remaining requirements. This table does not establish release readiness.
