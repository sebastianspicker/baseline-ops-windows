# Security policy

## Supported versions

Security fixes target the current `main` branch. Reports against the latest published prerelease are also accepted. Backports to older tags are not guaranteed.

Test the audits and remediation you intend to use on disposable Windows devices
before deployment. Some operations require administrator or LocalSystem access.

## In scope

- Incorrect audit results that could lead to unsafe operational decisions
- Remediation behavior that makes unintended system changes
- Path traversal, command injection, argument injection, or unsafe native process execution
- Privilege escalation, admin-to-SYSTEM escalation, or bypass of the protected execution boundary
- Signature, hash, ownership, ACL, reparse-point, or profile-integrity bypasses
- Credential, secret, private key, PII, or endpoint-evidence exposure
- CI or release-pipeline weaknesses that could alter published source or artifacts

## Out of scope

- Vulnerabilities in Windows, Sysmon, WinGet, Defender, or another third-party component
- General hardening-policy disagreements without a security defect in the implementation
- Actions already fully available to the same administrator or SYSTEM token, unless the issue bypasses a defined trust boundary, exposes credentials, establishes persistence, or causes unintended execution

## Execution trust boundary

Before running as administrator, follow the [protected installation procedure](docs/alpha-release.md#install-a-protected-windows-copy).
Do not run elevated code from a user-owned checkout, a Downloads extraction,
a path with a writable parent directory, or a reparse point. The runners and
launcher check the toolkit directory and its relevant parents before loading
modules or running endpoint scripts.

For privileged runs, write reports and evidence only to protected directories
that untrusted users cannot rename, replace, or redirect. The application checks
paths and reparse points before writing, but does not keep a directory handle
open to ensure the write reaches the same directory it checked.

`RequireSigned` validates an Authenticode certificate chain; it does not check
that the signer is the BaselineOps publisher. A hash supplied by a profile is
only as trustworthy as that profile. Verify the release provenance first, then
use trusted signer identities or hashes set by your deployment policy.

The profile runner keeps a private execution lease until it finishes writing
the result. This lease retains handles to the named runner control files and
the `lib`, `scripts/_lib`, and `scripts/internal` trees in both the runner and
target directories. On Windows, the read-sharing handles are intended to
prevent those open files from being written, deleted, or replaced.

A child runner can reuse a lease only while its registered identity is live,
for the exact canonical runner and target directories, and when invoked directly
by the owning profile runner. Profile fields and result metadata cannot grant
access to it. A direct local run acquires its own lease. Target-file, signature,
hash, ACL, and reparse-point checks still run independently.

Portable tests cover lease identity and lifetime. Windows tests must separately
verify that the file handles deny changes and that ACL checks work before a
release is approved.

The launcher assigns its worker to a Windows Job Object before signaling that
it may import repository code and run the requested operation. PowerShell and
the CLR have already started at that point; the Job Object does not contain
that earlier startup work.

On Windows, `tools/verify.ps1` and `tools/secret-scan.ps1` accept a bare `git`
command only when it resolves to a standard Program Files location. Otherwise,
they inspect files recursively, as they would in an extracted package. In a
checkout, that fallback may include ignored local files. Do not substitute a
per-user Git shim to bypass this restriction.

`tools/Test-Documentation.ps1` uses the Git executable found on `PATH` for repository file discovery. It does not execute endpoint scripts.

## Sensitive artifacts

Treat these files as sensitive endpoint data:

- JSON and CSV results
- Support bundles and collected evidence
- Script-specific exports and proof files
- Saved launcher output and temporary launcher logs
- Pester XML, which can include host name, user name, and working directory

Keep them outside the repository, restrict access, redact before sharing, and delete them according to the applicable retention policy. Launcher crash residue can remain under `%TEMP%\baselineops-windows-launcher`.

## Reporting a vulnerability

Do not open a public issue containing exploit details, secrets, logs, screenshots, or environment identifiers.

Open a [private GitHub security advisory][security-advisory].

If the advisory form is unavailable, open a public issue without technical details
and request private contact.

Include:

- A concise description and security impact
- Reproduction steps or a minimal proof of concept
- Affected script, module, workflow, or release artifact
- PowerShell version and edition
- Windows version and relevant installed features
- Whether the process ran as standard user, administrator, or LocalSystem
- Redacted path, owner, ACL, and reparse-point context for trust-boundary reports
- Suggested mitigation, if known

[security-advisory]: https://github.com/sebastianspicker/baseline-ops/security/advisories/new
