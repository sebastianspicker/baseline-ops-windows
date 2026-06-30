# Shared Modules (`lib/`)

Shared PowerShell modules remove script-level duplication and standardize behavior.

## Module Index

- `Common.psm1` - caller-scope lookup, admin checks, safe path helpers, `Has-Property`, and `New-SafeFileName`
- `Output.psm1` - capture-friendly console output helpers
- `Console.psm1` - severity colors, summaries, finding statistics, and decorative rule output
- `Registry.psm1` - registry read/write wrappers
- `Config.psm1` - config loading and merge helpers
- `External.psm1` - validated native command wrappers
- `EventLog.psm1` - event source and health event helpers
- `Results.psm1` - finding object/list helpers
- `JsonCatalog.psm1` - safe JSON reading helper (`Read-JsonFileSafe`)
- `Evidence.psm1` - evidence copy/hash helpers
- `Validation.psm1` - path traversal, script-name, URL, and reference validation
- `Execution.psm1` - argument-token parsing and timed child script execution
- `Serialization.psm1` - v2 result objects plus JSON/CSV writers with path-traversal protection

## Module Boundaries

- Use `Output.psm1` for generic human-readable sections, key/value lines, warnings, and status lines.
- Use `Console.psm1` only when a script needs severity or finding-specific console summaries.
- Use `Serialization.psm1` for machine-readable v2 output; scripts should not hand-roll final JSON/CSV writers.
- Use `Execution.psm1` when invoking child PowerShell scripts through the v2 runner path.
- Use `Validation.psm1` for path, script-name, URL, or reference checks.

Import only the modules the target script needs.

```powershell
. (Join-Path $PSScriptRoot '_lib/Bootstrap.ps1')
Import-Module (Join-Path $script:LibPath 'Output.psm1') -Force
Import-Module (Join-Path $script:LibPath 'Common.psm1') -Force
Import-Module (Join-Path $script:LibPath 'Serialization.psm1') -Force
```

## v2 Result Contract

Use `New-V2ResultObject` from `Serialization.psm1` for orchestration-compatible output:

- `SchemaVersion` - always `"2.0"`
- `ScriptName` - script filename, for example `"27-Defender-Health-Audit.ps1"`
- `Mode` - `"Audit"` or `"Remediate"`
- `ComputerName` - target hostname
- `TimestampUtc` - execution time in UTC
- `Result` - `"OK"`, `"WARN"`, or `"FAIL"`
- `Findings` - array of finding objects
- `Summary` - script-specific summary object
- `Metadata` - additional key/value metadata

Use `ConvertTo-V2Json` for consistent JSON serialization.

## Finding Object Shape

```json
{
  "Code": "DEF-AMServiceDisabled",
  "Severity": "High",
  "Message": "Defender AM Service is not enabled."
}
```

Extra script-specific properties may be attached through the shared finding helper `-Extra` parameter.

## Finding Code Convention

Finding codes follow `PREFIX-Description`.

| Prefix | Domain |
| --- | --- |
| `AC-` | App Control for Business |
| `AMSI-` | AMSI provider or bypass detection |
| `APPLOCK-` | AppLocker policy enforcement |
| `ASR-` | ASR rules and Defender exclusions |
| `AUD-` | Advanced audit policy |
| `BKP-` | Backup readiness |
| `BLKR-` | BitLocker operations |
| `CERT-` | Certificate autoenrollment |
| `CFG-` | Configuration loading |
| `CG-` | Credential Guard |
| `DATA-` | Data collection |
| `DEF-` | Defender health |
| `DOH-` | DNS-over-HTTPS client config |
| `DS-` | Driver signing and kernel integrity |
| `EP-` | Exploit Protection mitigations |
| `FW-` | Firewall baseline |
| `Grabber-` | Artifact collection |
| `HVCI-` | HVCI and memory integrity |
| `HW-` | Hardware and TPM |
| `IOC-` | IOC sweep |
| `JOIN-` | Identity and domain join |
| `LAPS-` | LAPS hygiene |
| `LSA-` | LSA protection |
| `WEF-` | WEF client forwarding |
| `WDAG-` | Windows Defender Application Guard |

## Severity Levels

| Severity | Meaning |
| --- | --- |
| `Critical` | Immediate action required |
| `High` | Non-compliant, remediation needed |
| `Medium` | Drift or warning, review recommended |
| `Low` | Informational finding, low risk |
| `Info` | No action needed |
| `OK` / `Pass` | Check passed |
