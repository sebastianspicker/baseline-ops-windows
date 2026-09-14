# Rust v3 implementation

Rust v3 is a self-contained rewrite under
[`rust/`](https://github.com/sebastianspicker/baseline-ops/blob/main/rust/README.md).
It is not yet released. The existing PowerShell product remains the supported
release line and the reference for expected behavior.

Rust releases have their own `rust-v*` tags and CI/release workflows. A
capability appearing in the registry does not mean that its native Windows
behavior matches PowerShell. The machine-readable
[capability ledger](https://github.com/sebastianspicker/baseline-ops/blob/main/rust/ledger/capability-parity.json)
is the authority for implementation status. Its
[Markdown companion](https://github.com/sebastianspicker/baseline-ops/blob/main/rust/ledger/capability-parity.md)
shows the evidence state for every PowerShell endpoint capability.

The v3 package targets Windows 11 Pro and Enterprise x64, version 24H2 or
later. It cannot be published until all 52 capabilities and every retained
external evidence gate are complete. Publication also requires an exact
`rust-v<Cargo version>` tag and Authenticode subject and public-key pin
verification for all three executables. A detached PKCS#7 signature over the
exact manifest bytes authenticates the package inventory.

The [verification contract](https://github.com/sebastianspicker/baseline-ops/blob/main/rust/docs/verification.md)
covers the schemas, SBOM, protected-install checks, and the remaining
current-time and offline trust evidence. The release workflow currently refuses
publication because the capability and Windows evidence gates are still open.
