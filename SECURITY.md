# Security policy

## Supported versions

Security fixes target the current `main` branch. Reports against the latest published prerelease are also accepted. Backports to older tags are not guaranteed.

This repository contains privileged endpoint code. Validate selected audit and remediation behavior on disposable Windows devices before deployment.

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

Do not run elevated repository code from a user-owned checkout, Downloads extraction, writable ancestor, or reparse-point path. Elevated runners and the launcher check the toolkit root and relevant ancestors before importing repository modules or executing endpoint scripts. Use the protected installation procedure in the [release guide](docs/alpha-release.md#install-a-protected-windows-copy).

On Windows, `tools/verify.ps1` and `tools/secret-scan.ps1` accept a bare Git executable only from standard Program Files locations. If trusted Git is unavailable, they fall back to recursive package discovery. That fallback is intended for extracted packages and can include ignored local files in a checkout. Do not substitute a per-user Git shim to bypass this policy.

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

Use one of these private channels:

- Open a [GitHub security advisory][security-advisory].
- Contact the maintainer through the email listed on the GitHub profile.

If neither channel is available, open a public issue without technical details and request private contact.

Include:

- A concise description and security impact
- Reproduction steps or a minimal proof of concept
- Affected script, module, workflow, or release artifact
- PowerShell version and edition
- Windows version and relevant installed features
- Whether the process ran as standard user, administrator, or LocalSystem
- Redacted path, owner, ACL, and reparse-point context for trust-boundary reports
- Suggested mitigation, if known

[security-advisory]: https://github.com/sebastianspicker/win-mdm-security-hardening-kit/security/advisories/new
