<a id="verification-and-closure"></a>

# Verification

Portable checks cover formatting, Clippy with warnings denied, unit and integration tests, doc tests,
strict schema snapshots, and dependency policy. They verify portable domain behavior. They do not
verify Windows APIs, packaging, elevation, or endpoint changes.

## Comparison with PowerShell v2

`oracles/v2-capability-manifests.json` maps all 52 fixture IDs to the current PowerShell v2 source,
including helper code extracted from the public scripts. A PowerShell source change invalidates the
corresponding manifest entry until someone deliberately regenerates and reviews the fixture.
PowerShell is a development reference, not a Rust runtime dependency.

`oracles/v2-neutral-fixtures.json` inventories the structure of those capabilities. It does not
compare their behavior. Behavioral comparison currently comes from
`v2-rust-behavioral-cases.json`, which is read by the Rust verifier and the mocked v2 adapter. That
corpus contains four DoH policy cases, seven finite Windows Update policy cases, five Security
Options cases, and five PowerShell Logging cases. The other 48 capabilities have structural
coverage only. Windows observation and mutation are outside these portable comparisons.

## Required Windows environments

Release testing requires disposable Windows 11 Pro and Enterprise x64 environments for 24H2,
25H2, and 26H1. The test matrix includes standard-user audit and plan, UAC apply, LocalSystem,
missing Windows features, access denial, stale and tampered plans, reparse points, untrusted
binaries, timeouts, oversized output, and localized native-tool output.

The complete inventory is stored in `release/evidence-gates.json`. Publication is blocked if a
required entry is absent, renamed, empty, or still open. UAC apply runs with an administrator token.
LocalSystem is tested separately and cannot be treated as equivalent to UAC elevation.

Every capability that can change state must demonstrate an accurate plan, a successful apply,
post-apply audit, an idempotent second apply, injected failures, correct reboot signaling, and
rollback when the capability declares its action reversible. Tests for firewall, SMB, RDP,
Defender, audit policy, logging, Sysmon, registry, and emergency isolation use snapshot VMs.
Emergency isolation also requires isolated VMs that remain accessible through the console.

TPM, Secure Boot, and BitLocker tests require suitable hardware or equivalent release
infrastructure. If that environment is unavailable, the requirement remains open; the test is not
silently skipped.

The native GUI must be tested with keyboard-only navigation, high-DPI settings, and screen-reader
metadata. Its cancellation, progress, artifact-opening, and UAC transitions also require Windows
tests. A package process-spy test must show that none of the three executables starts PowerShell or
ships a PowerShell runtime.

## Release requirements

The v3 release requires all 52 parity-ledger entries to be complete and the signed package to pass
verification from a protected installation. Before parsing or trusting `manifest.json`, the package
verifier authenticates a detached PKCS#7 signature over its exact bytes. Authenticode signatures on
the executables do not authenticate the rest of the package inventory.

At runtime, verification requires the configured exact signer subject and the SHA-256 digest of its
canonical DER SubjectPublicKeyInfo. The code-signing chain must be valid at the current system time,
using cached revocation data. A newly provisioned offline computer can therefore reject a package
when it has no revocation information.

Validation after the signing certificate expires still needs release testing, even when the detached
signature includes an external RFC 3161 timestamp. Until signed Windows fixtures and tamper tests
satisfy the package requirements, the presence of a registry entry or successful compilation must
not be described as capability parity.
