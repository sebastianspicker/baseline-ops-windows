# Examples

## Config examples

`examples/configs/` contains JSON config samples for individual scripts:

- `asr-defender-allowlist.json`
- `local-admins-allowlist.json`
- `firewall-baseline.json`
- `wufb-proofing.json`

Use with script-level `-ConfigPath` parameters.

## Profile examples (v2 orchestration)

`examples/profiles/` contains orchestration profiles for `00-Run-Profile.ps1`:

| Profile | Description | Scripts | Mode |
|---------|-------------|---------|------|
| `baseline-audit.json` | Core security baseline checks (ASR, PS logging, AppControl) | 3 | Audit |
| `rapid-triage.json` | Quick triage with bundle parser, event triage, Defender health | 3 | Audit |
| `hardening-remediate.json` | Apply hardening fixes (PS logging, firewall logging, ransomware protection) | 3 | Remediate |
| `full-audit.json` | All audit-capable scripts across every category (identity, OS, network, Defender, monitoring, storage, software, collection) | 39 | Audit |
| `endpoint-health-check.json` | Quick 10-script health check covering Defender, TPM, BitLocker, updates, time, storage, network, identity, and baseline | 10 | Audit |
| `incident-response.json` | Incident triage workflow: event triage, IOC sweep, artifact grab, process audit, scheduled tasks, remote surface, then support bundle (with dependencies) | 7 | Audit |
| `compliance-full.json` | Full compliance posture check: baseline, audit policy, AppControl, Credential Guard, LSA, VBS/HVCI, PS logging, SMB, ransomware, ASR, BitLocker, NTLM | 12 | Audit |

Run example:

```powershell
pwsh -NoProfile -File .\scripts\00-Run-Profile.ps1 -ProfilePath .\examples\profiles\baseline-audit.json -Mode Audit -OutputFormat None -Confirm:$false
```

Validate profile before execution:

```powershell
pwsh -NoProfile -File .\scripts\00-Validate-Profile.ps1 -ProfilePath .\examples\profiles\baseline-audit.json
```

Note: when a profile is smoke-tested from a non-Windows development host, Windows-only steps should surface a structured unsupported-host result instead of aborting orchestration startup.
