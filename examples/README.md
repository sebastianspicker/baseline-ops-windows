# Configuration and profile examples

The files in this directory are executable examples. They are not organization-specific policy and should be reviewed before use.

## Configuration examples

Files under `examples/configs/` are direct inputs to individual scripts:

| File | Script | Direct parameter | Shipped state |
| --- | --- | --- | --- |
| `asr-defender-allowlist.json` | `01-ASR-Defender-Allowlist.ps1` | `-ExceptionsPath` | All exclusion and allow-list arrays are empty. |
| `local-admins-allowlist.json` | `03-LocalAdmins-Guardrail.ps1` | `-AllowListPath` | The allowed-members array is empty. |
| `firewall-baseline.json` | `18-Firewall-Baseline.ps1` | `-CatalogPath` | Domain, Private, and Public profiles are defined; custom rule lists are empty. |
| `wufb-proofing.json` | `05-WUFB-Proofing.ps1` | `-CatalogPath` | WUfB is selected; target release and active hours are disabled. |

Start with Audit mode:

```powershell
.\scripts\01-ASR-Defender-Allowlist.ps1 `
  -ExceptionsPath .\examples\configs\asr-defender-allowlist.json -Mode Audit

.\scripts\03-LocalAdmins-Guardrail.ps1 `
  -AllowListPath .\examples\configs\local-admins-allowlist.json -Mode Audit

.\scripts\18-Firewall-Baseline.ps1 `
  -CatalogPath .\examples\configs\firewall-baseline.json -Mode Audit

.\scripts\05-WUFB-Proofing.ps1 `
  -CatalogPath .\examples\configs\wufb-proofing.json -Mode Audit
```

`-ConfigPath` is a wrapper document, not an alias for these direct inputs. The wrapper keys for these examples are:

| Direct input | `-ConfigPath` wrapper key |
| --- | --- |
| Defender and ASR allow list | `DefenderAllowlistPath` |
| Local administrator allow list | `LocalAdmins.AllowListPath` |
| Firewall catalog | `Firewall.CatalogPath` |
| WUfB catalog | `WUfB.CatalogPath` |

## Profile examples

Files under `examples/profiles/` are inputs to `scripts/00-Run-Profile.ps1`:

| File | Declared mode | Steps | Scope |
| --- | --- | ---: | --- |
| `baseline-audit.json` | Audit | 3 | Defender exclusions and ASR, PowerShell logging, App Control |
| `rapid-triage.json` | Audit | 3 | Support bundle parsing, event triage, Defender health |
| `hardening-remediate.json` | Remediate | 3 | PowerShell logging, firewall logging, ransomware and network protection |
| `full-audit.json` | Audit | 42 | Broad endpoint audit and collection set |
| `endpoint-health-check.json` | Audit | 10 | Defender, hardware, updates, storage, network, identity, and baseline health |
| `incident-response.json` | Audit | 7 | Event, IOC, artifact, process, task, remote-surface, and support-bundle collection |
| `compliance-full.json` | Audit | 12 | Security baseline, policy, platform protection, logging, SMB, Defender, BitLocker, and NTLM |

The runner treats profile JSON as untrusted input:

- `Steps[].Args` must be an empty array.
- `Defaults.Mode` cannot enable remediation. Pass `-Mode Remediate` to the runner.
- `Defaults.Strict` can enable strict handling.
- `Integrity.RequireSigned` can require signatures.
- `Defaults.OutputFormat` and `Defaults.OutputPath` do not control runner output.
- A command-line `-Strict` or `-RequireSigned` can strengthen profile settings.

Validate one profile:

```powershell
pwsh -NoProfile -File .\scripts\00-Validate-Profile.ps1 `
  -ProfilePath .\examples\profiles\baseline-audit.json -RootPath .
```

Validate every shipped profile:

```powershell
Get-ChildItem -LiteralPath .\examples\profiles -Filter '*.json' | ForEach-Object {
  & pwsh -NoProfile -File .\scripts\00-Validate-Profile.ps1 `
    -ProfilePath $_.FullName -RootPath . -OutputFormat None
  if ($LASTEXITCODE -ne 0) {
    throw "Profile validation failed: $($_.Name)"
  }
}
```

Run the baseline profile:

```powershell
pwsh -NoProfile -File .\scripts\00-Run-Profile.ps1 `
  -ProfilePath .\examples\profiles\baseline-audit.json `
  -RootPath . -Mode Audit -OutputFormat None -Confirm:$false
```

## Preview behavior

At the profile layer, `-WhatIf` skips every selected child script. At the batch layer, it stops before creating the temporary profile workspace:

```powershell
pwsh -NoProfile -File .\scripts\00-Run-Profile.ps1 `
  -ProfilePath .\examples\profiles\hardening-remediate.json `
  -RootPath . -Mode Remediate -Strict -OutputFormat None `
  -WhatIf -Confirm:$false

pwsh -NoProfile -File .\scripts\00-Run-Batch.ps1 `
  -Category Remediation -RootPath . -Mode Remediate `
  -OutputFormat None -WhatIf -Confirm:$false
```

Both commands return warning exit code `2`. The preview verifies control flow only. It does not query the endpoint or prove that remediation would succeed. `-Confirm:$false` without `-WhatIf` is not a preview.
