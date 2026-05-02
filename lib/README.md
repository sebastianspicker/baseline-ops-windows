# Shared modules (`lib/`)

Shared PowerShell modules used to remove script-level duplication and standardize behavior.

## Module index

- `Common.psm1`
  - caller-scope lookup, admin checks, safe directory/path helpers, property existence check (`Has-Property`), file name sanitization (`New-SafeFileName`)
- `Output.psm1`
  - unified console output helpers
- `Console.psm1`
  - severity colors, summary rendering with pluggable `CustomFields`, finding statistics, decorative rule output (`Write-DecorativeRule`)
- `Registry.psm1`
  - registry read/write wrappers
- `Config.psm1`
  - config loading/merge helpers
- `External.psm1`
  - validated native command wrappers
- `EventLog.psm1`
  - event source and health event helpers
- `Results.psm1`
  - finding object/list helpers
- `JsonCatalog.psm1`
  - safe JSON reading helper (`Read-JsonFileSafe`); JSON writing moved to `Serialization.psm1`
- `Evidence.psm1`
  - evidence copy/hash helpers
- `Validation.psm1` (v2)
  - path traversal checks, script-name validation, URL/ref validation
- `Execution.psm1` (v2)
  - retry helpers, process execution, timed script execution
- `Serialization.psm1` (v2)
  - JSON/CSV writers (with path-traversal protection) and standardized v2 result objects

## Module boundaries

Use `Output.psm1` for generic human-readable UI primitives such as sections,
key/value lines, warnings, and status lines. Use `Console.psm1` only when a
script needs severity/finding-specific console summary helpers. Use
`Serialization.psm1` for machine-readable v2 output and file export; scripts
should not hand-roll their final JSON/CSV writers.

Use `Execution.psm1` when invoking child PowerShell scripts or native processes,
especially when argument token parsing or timeout behavior matters. Use
`Validation.psm1` for path, script-name, URL, or reference validation before
crossing a trust boundary such as profile input, remediation script selection,
or output-file writing.

## Recommended import pattern

```powershell
. (Join-Path $PSScriptRoot '_lib/Bootstrap.ps1')
Import-Module (Join-Path $script:LibPath 'Output.psm1') -Force
Import-Module (Join-Path $script:LibPath 'Common.psm1') -Force
Import-Module (Join-Path $script:LibPath 'Console.psm1') -Force
Import-Module (Join-Path $script:LibPath 'Validation.psm1') -Force
Import-Module (Join-Path $script:LibPath 'Execution.psm1') -Force
Import-Module (Join-Path $script:LibPath 'Serialization.psm1') -Force
Import-Module (Join-Path $script:LibPath 'Results.psm1') -Force
```

Import only what the target script needs.

## v2 result contract helper

Use `New-V2ResultObject` from `Serialization.psm1` for orchestration-compatible output:

- `SchemaVersion` - always `"2.0"`
- `ScriptName` - e.g. `"27-Defender-Health-Audit.ps1"`
- `Mode` - `"Audit"` or `"Remediate"`
- `ComputerName` - hostname of the target machine
- `TimestampUtc` - execution time in UTC
- `Result` - overall result: `"OK"`, `"WARN"`, or `"FAIL"`
- `Findings` - array of finding objects (see below)
- `Summary` - script-specific summary object
- `Metadata` - additional key-value metadata

Use `ConvertTo-V2Json` for consistent JSON serialization of result objects.

### Finding object shape

Each finding in the `Findings` array has this structure:

```json
{
  "Code": "DEF-AMServiceDisabled",
  "Severity": "High",
  "Message": "Defender AM Service is not enabled."
}
```

Extra properties (script-specific context) may be attached via the `-Extra` parameter.

### Finding code convention

Finding codes follow the pattern `PREFIX-Description`:

| Prefix | Domain | Script(s) |
|--------|--------|-----------|
| `AC-` | App Control for Business | 43-AppControlForBusiness |
| `AMSI-` | AMSI provider / bypass detection | 50-AMSI-Audit |
| `APPLOCK-` | AppLocker policy enforcement | 51-AppLocker-Audit |
| `ASR-` | ASR rules / Defender exclusions | 01-ASR-Defender-Allowlist |
| `AUD-` | Advanced audit policy | 33-AdvancedAuditPolicy |
| `BKP-` | Backup readiness | 36-Backup-Readiness |
| `BLKR-` | BitLocker operations | 23-BitLocker-Operations |
| `CERT-` | Certificate autoenrollment | 24-Cert-AutoEnrollment |
| `CFG-` | Configuration loading | (shared) |
| `CG-` | Credential Guard | 13-LSASS-CG-HVCI-VBS, 39-CredentialGuard |
| `DATA-` | Data collection | (shared) |
| `DEF-` | Defender health | 27-Defender-Health |
| `DOH-` | DNS-over-HTTPS client config | 52-DoH-Audit |
| `DS-` | Driver signing / kernel integrity | 49-DriverSigning |
| `EP-` | Exploit Protection mitigations | 48-ExploitProtection |
| `FW-` | Firewall baseline | 18-Firewall-Baseline |
| `Grabber-` | Artifact collection | 12-Suspicious-Artifact |
| `HVCI-` | HVCI / memory integrity | 13-LSASS-CG-HVCI-VBS |
| `HW-` | Hardware / TPM | 15-HardwareTPM |
| `IOC-` | IOC sweep | 11-IOC-Sweep |
| `JOIN-` | Identity / domain join | 28-Join-Identity |
| `LAPS-` | LAPS hygiene | 02-LAPS-Hygiene |
| `LSA-` | LSA Protection (RunAsPPL) | 13-LSASS-CG-HVCI-VBS, 40-AddedLSAProtection |
| `NET-` | Network configuration | 29-Network-Config |
| `NTLM-` | NTLM authentication audit | 41-NTLM-Audit-Client |
| `PATCH-` | Patch / update status | 20-MissingPatch-Notification |
| `PROFILE-` | Profile validation | 00-Validate-Profile |
| `PSLOG-` | PowerShell logging baseline | 31-PowerShell-Logging |
| `REMOTE-` | Remote access surface | 37-Remote-Surface |
| `SB-` | Secure Boot / UEFI | 46-SecureBoot-UEFI |
| `SECOPT-` | Security options drift | 38-SecurityOptions |
| `SMB-` | SMB encryption | 22-SMB-Encryption |
| `STO-` | Storage reliability | 35-Storage-Reliability |
| `TASK-` | Scheduled task hygiene | 07-ScheduledTasks |
| `TIME-` | Time synchronization health | 34-TimeSync |
| `VBS-` | Virtualization-Based Security | 13-LSASS-CG-HVCI-VBS |
| `WDAG-` | Windows Defender App Guard | 47-WDAG-Readiness |
| `WEF-` | WEF client forwarding | 45-WEF-Client |

### Severity levels

| Severity | Meaning | Console color |
|----------|---------|---------------|
| `Critical` | Immediate action required | Red |
| `High` | Non-compliant, remediation needed | Red |
| `Medium` | Drift or warning, review recommended | Yellow |
| `Low` | Informational finding, low risk | Cyan |
| `Info` | No action needed | Gray |
| `OK` / `Pass` | Check passed | Green |
