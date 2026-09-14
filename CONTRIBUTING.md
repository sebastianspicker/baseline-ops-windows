# Contributing

BaselineOps can change Windows settings with elevated privileges. Keep changes
focused, explain their effect on an endpoint, and test the behavior they change.

## Development requirements

- PowerShell 7.6.3
- PSScriptAnalyzer 1.25.0
- Pester 5.8.0
- Python 3 with venv support for pinned Lizard 1.21.2
- Node.js 18 or newer with npm for pinned jscpd 5.1.2
- Bash for `scripts/ci-local.sh`
- Windows PowerShell 5.1 for compatibility checks
- Rust 1.96.0 from `rust/rust-toolchain.toml` for changes under `rust/`
- A disposable Windows test device for changes that depend on endpoint features or remediation

## Change workflow

1. Create a branch from the intended base branch.
2. Make one focused change.
3. Add or update tests for behavior changes.
4. Update public documentation when parameters, configuration, output, security boundaries, or operation changes.
5. Run the focused tests and applicable full gates.
6. Review `git diff --check` and the complete diff.
7. Open a pull request with scope, risk, compatibility impact, and validation results.

Call out changes to profile parsing, dependency handling, remediation, integrity checks, privileged path validation, native process execution, evidence collection, or result serialization.

## Source requirements

- Follow the dependency map in `docs/architecture.md`: capability policy stays
  in its numbered script, shared behavior belongs in `lib/`, private
  platform implementation belongs in `lib/platform/`, and capability-specific
  helpers belong in `scripts/internal/`.
- Do not expose files under `scripts/internal/` or `scripts/_lib/` as operator entry points.
- Treat profiles, configuration files, paths, URLs, native output, and arguments as untrusted input.
- Keep mode, toolkit root, output, confirmation, signature, and hash choices
  under the runner's control; profile data must not override them.
- Implement state changes through `SupportsShouldProcess` and verify `-WhatIf` and `-Confirm` behavior.
- Do not weaken ACL, ownership, reparse-point, signature, hash, or input-validation checks to accommodate a local environment.
- Use the v2 result helpers for orchestration-compatible output.
- Avoid committing generated reports, support bundles, launcher logs, Pester XML, or other endpoint evidence.

Every maintained `.ps1` and `.psm1` file must begin with comment-based help containing `.SYNOPSIS` and `.DESCRIPTION`. Shell, JavaScript, Docker, PowerShell data, and YAML sources need a leading purpose comment where the format permits comments.

Adding a numbered capability changes the public product catalog. Scaffold the
next number with:

```powershell
pwsh -NoProfile -File .\tools\new-script.ps1 -Name 53-Example-Audit
```

Add `-SupportsRemediate` only when the script will implement guarded state changes:

```powershell
pwsh -NoProfile -File .\tools\new-script.ps1 `
  -Name 53-Example-Audit -SupportsRemediate
```

Update the script catalog, example profiles, documentation, and Rust capability
ledger in the same change.

## Local checks

Run the complete PowerShell 7 gate from Bash or Git Bash:

```bash
bash ./scripts/ci-local.sh
```

The wrapper requires PowerShell Core 7.6.3. Set `PWSH_BIN` to an absolute executable path when necessary:

```bash
PWSH_BIN='/absolute/path/to/pwsh' bash ./scripts/ci-local.sh
```

Run individual PowerShell 7 checks:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\tools\secret-scan.ps1 -RootPath .
pwsh -NoProfile -ExecutionPolicy Bypass -File .\tools\Test-Documentation.ps1 -RootPath .
pwsh -NoProfile -ExecutionPolicy Bypass -Command `
  "Import-Module PSScriptAnalyzer -RequiredVersion 1.25.0 -Force; & .\tools\verify.ps1 -RootPath ."
pwsh -NoProfile -Command `
  "Import-Module Pester -RequiredVersion 5.8.0 -Force; Invoke-Pester -Path .\tests -CI -Output Detailed"
pwsh -NoProfile -File .\tools\quality\Test-CodeQuality.ps1 -ReleaseLine PowerShell
```

The code-quality command installs pinned analyzers in the ignored
`.cache/quality/` directory. Rust and PowerShell have separate scan settings
and reviewed records of existing duplication.

The combined gate checks metrics and duplication first, then runs static
analysis once across maintained PowerShell files and Rust's PowerShell
comparison scripts. Standalone quality commands also run their analyzers.
`-SkipAnalyzer` reports a partial check; the combined gate reports the later
analyzer result separately. CI reuses cached dependencies and Rust builds
only for matching platforms, toolchains, and locked inputs, and checks the
exact analyzer versions on every run.

Any new, moved, expanded, or removed duplicate block fails the check, even if
the overall duplication percentage falls.

Run the Rust-only quality gate from the repository root:

```powershell
pwsh -NoProfile -File .\tools\quality\Test-CodeQuality.ps1 -ReleaseLine Rust
```

Check both implementations, or generate an updated duplication baseline for
review, with:

```powershell
pwsh -NoProfile -File .\tools\quality\Test-CodeQuality.ps1 -ReleaseLine All
pwsh -NoProfile -File .\tools\quality\Test-CodeQuality.ps1 -ReleaseLine All -UpdateDuplicationBaseline
```

The update switch marks each new duplicate-block fingerprint `REVIEW REQUIRED`.
Review the source and remove duplication where practical. If sharing the code
would weaken compatibility, clarity, or a security boundary, record that specific
reason. Tool errors, scans with no files, malformed baselines, and fingerprints
without a rationale fail the check. Updating the baseline alone is not a fix.

Run Windows PowerShell 5.1 compatibility checks on Windows:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command `
  "Import-Module PSScriptAnalyzer -RequiredVersion 1.25.0 -Force; & .\tools\verify.ps1 -RootPath ."
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command `
  "Import-Module Pester -RequiredVersion 5.8.0 -Force; Invoke-Pester -Path .\tests -CI -Output Detailed"
```

Pester skips tests whose requirements are unavailable, such as LocalSystem, a
protected workspace, another operating system, or a Windows feature. Report
these skips and test the relevant environment separately. Keep the assertions
intact.

For changes under `rust/`, run the workspace gates from that directory:

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
RUSTDOCFLAGS='-D warnings' cargo doc --workspace --all-features --no-deps
cargo run -p xtask -- generate
cargo run -p xtask -- verify
cargo deny check
```

Rust v3 is unreleased and tested separately from PowerShell. Compilation and
portable tests do not establish that it matches the PowerShell capabilities or
is ready to ship. Keep its capability ledger and Windows test evidence current
when making those claims.

The operator release ZIP excludes the test suite. Package checks are documented in the [release guide](docs/alpha-release.md#check-the-extracted-operator-package).

For browser demo changes, follow the [demo checks and screenshot instructions](docs/demo.md#maintain-the-tour).

## Pull request content

A pull request should state:

- What changed and why
- Which scripts, modules, profiles, or workflows are affected
- Whether the change reads, writes, deletes, exports, launches, or stops anything
- Required privilege and Windows feature assumptions
- Compatibility impact for PowerShell 7.6.3 and Windows PowerShell 5.1
- Tests and manual validation performed
- Remaining limitations or untested platform behavior

For remediation changes, include a focused `-WhatIf` test and describe the rollback or recovery path.

## Documentation policy

Public Markdown belongs in one of these maintained locations:

- `README.md`
- `CONTRIBUTING.md`
- `SECURITY.md`
- `CHANGELOG.md`
- `docs/`
- `scripts/README.md`
- `lib/README.md`
- `examples/README.md`
- `rust/README.md`
- `rust/docs/`
- `rust/ledger/capability-parity.md`

Link new guides from [docs/README.md](docs/README.md), and check local links
with `tools/Test-Documentation.ps1`. Keep machine-specific notes, private
operational data, endpoint identifiers in screenshots, and unverified test
counts out of public docs.

`tools/verify.ps1` allows only named, reviewed files under the root `docs/`
directory. Add a new document to that list and the documentation index in the
same change. Rust packages copy their own docs through `xtask`; keep those
docs consistent with the schemas, capability ledger, and release requirements.
Keep private notes and local generated output in ignored directories. Do not
force-add them.

Do not report vulnerabilities in a public pull request or issue. Follow [SECURITY.md](SECURITY.md).
