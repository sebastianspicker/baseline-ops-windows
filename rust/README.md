# BaselineOps v3 Rust workspace

This directory contains the self-contained BaselineOps v3 implementation. It is an unreleased
Rust workspace for Windows endpoints. The supported PowerShell product remains the reference for
expected behavior, but none of these crates depends on it at runtime. The Rust executables never
invoke PowerShell, `cmd.exe`, or another command shell.

## Support contract

The initial target is Windows 11 Pro and Enterprise x64, version 24H2 or later. Windows Home,
Education, Server, ARM64, and older releases are outside the v3 alpha contract.

Tests for the domain model, schemas, scheduler, parsers, and packaging can run on other operating
systems. Those tests are useful during development, but only execution on the supported Windows
targets can establish Windows behavior.

## Workspace

- `baselineops-domain`: profile v3, result v3, and plan v4 JSON contracts; validation; digests;
  and exit-code mapping.
- `baselineops-windows`: paths, trust checks, ACLs, Authenticode, Windows APIs, and the no-shell
  process boundary.
- `baselineops-capabilities`: the compile-time capability registry and endpoint implementations.
- `baselineops-engine`: audit, planning, application, journaling, cancellation, reporting, and
  evidence handling.
- `baselineops`: the standard-user command-line client.
- `baselineops-gui`: the native Win32 standard-user launcher.
- `baselineops-worker`: the short-lived, UAC-elevated apply worker.
- `xtask`: schema, parity, verification, package, manifest, and SBOM tasks.

The machine-readable [parity ledger](ledger/capability-parity.json) records the implementation
status of every capability. The [Markdown parity summary](ledger/capability-parity.md) presents the
same information for readers. A capability appearing in the registry only proves that the
executables can discover it. The capability is complete only when its ledger entry includes the
required comparisons with the PowerShell behavior and the required Windows test results.

## Developer commands

Run these commands from `rust/`:

```text
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
RUSTDOCFLAGS='-D warnings' cargo doc --workspace --all-features --no-deps
cargo run -p xtask -- generate
cargo run -p xtask -- verify
cargo check --workspace --all-targets --all-features --target x86_64-pc-windows-msvc
cargo deny check
```

The workspace uses Rust 1.96.0 from `rust-toolchain.toml`. CI rejects rustdoc warnings and runs
`cargo deny check` with cargo-deny 0.20.2.

Unsigned local builds are permitted. Publishing a release requires valid Authenticode signatures
from the configured publisher on all three x64 executables, a tag that exactly matches the Cargo
version, all 52 completed ledger entries, and every required external test result. The `rust-v*`
workflow stops before publication if any requirement is missing.

## External resources

The `audit`, `plan`, and `apply` commands accept repeated `--resource logical-id=path` bindings. The
standard-user process validates each regular file or directory manifest within its size limits and
computes its digest. A saved plan contains only the logical ID, resource kind, digest, and size.
Applying that plan requires the caller to bind every resource again with exactly matching metadata.

The worker currently rejects any resource-dependent Apply operation. Authenticated transfer of the
already validated resource handles has not been implemented. The `--support-dir DIR` option remains
as a compatibility alias for `--resource support_bundle=DIR` on `audit`, `plan`, and `apply`.

## Security boundary

The three operating modes deliberately grant different authority:

1. `audit` observes endpoint state. It writes only the report or evidence files the caller requests.
2. `plan` observes endpoint state and creates an expiring proposal bound to the current host.
3. `apply` uses a short-lived elevated worker. The standard-user broker reads the profile within its
   byte limit and sends those exact bytes over authenticated IPC, so the worker does not reopen an
   attacker-controlled path. The worker repeats the observations, derives the actions independently,
   retains the proposal it produced, and returns its canonical digest. A second operator message
   must approve that exact digest before execution can proceed.

Plans use schema `4.0`, and the broker uses IPC protocol `2`. Older saved plans must be regenerated
and their new digests approved. Profile and result schemas remain at `3.0`. Each observation is
bound to one profile step and its parameters. The CLI, the GUI's native review screen, and the
worker derive proposals with the same pure capability planners. Read-only steps produce explicit
observation proposals.

The code includes native Authenticode checks, protected owner and DACL checks, UAC launch support,
host binding, authenticated installed-package binding, Job Object containment, evidence quotas,
journal verification, and authenticated named-pipe communication. The local pipe is restricted by
ACL, created as the first instance, and authenticates both peer processes. The peers exchange
bounded, nonce-linked frames. Protected journal composition, exact UAC process-tree containment,
capability mutators, signed signer-key fixtures, and the remaining Windows runtime tests are still
incomplete. The worker therefore refuses every mutation.

All 52 capabilities remain in the registry. Of those, 48 retain their existing native observation
code. Capability 21 also has partial firewall preflight acquisition. Capabilities 09, 11, 12, and
21 remain `in_development`; 09, 11, and 12 cannot yet acquire their required state. No capability is
marked `implemented`, no sealed mutation handler is ready for production, and Apply cannot perform
production changes. The [implementation status](docs/implementation-status.md) describes the exact
state and the remaining work.

For more detail, see the [architecture](docs/architecture.md) and
[verification requirements](docs/verification.md).
