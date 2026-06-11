# Security Policy

## Supported Versions

Only the current `main` branch is actively maintained unless the maintainer
explicitly confirms support for another branch or tag. Scripts are intended for
controlled, lab-tested environments; ask for maintainer confirmation before
using them outside that scope. For production use, validate remediation scripts
against your own environment or open a maintainer discussion before proceeding.

## Scope

**In scope:**

- Logic errors in audit/remediation scripts that produce incorrect results or
  unsafe system changes
- Secrets, credentials, or PII inadvertently committed to the repository
- Path traversal, command injection, or privilege-escalation risks in script
  logic or shared lib modules
- CI pipeline issues that could introduce malicious code

**Out of scope:**

- Issues in third-party tools (Sysmon, WinGet, Defender) that scripts merely
  invoke
- Findings that require attacker-controlled input with local admin or SYSTEM
  access to exploit
- General Windows hardening advice or opinionated baseline disagreements

## Reporting a Vulnerability

Please report security issues **privately** — do not open a public issue:

- Open a [GitHub security advisory][security-advisory], or
- Contact the maintainer via the email listed on their GitHub profile.

If both private channels are unavailable, open a public issue that contains no
exploit details, secrets, logs, screenshots, or environment-specific identifiers,
and ask for a private maintainer contact.

Please include:

- A clear description of the issue
- Steps to reproduce
- Impact assessment
- Any potential mitigations

We will acknowledge receipt within 7 days and work on a fix as appropriate.

[security-advisory]: https://github.com/sebastianspicker/win-mdm-security-hardening-kit/security/advisories/new
