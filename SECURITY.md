# Security Policy

## Supported Versions

Only the current `main` branch is actively maintained. Scripts are provided for use in controlled, lab-tested environments. Always validate remediation scripts against your own environment before production use.

## Scope

**In scope:**
- Logic errors in audit/remediation scripts that produce incorrect results or unsafe system changes
- Secrets, credentials, or PII inadvertently committed to the repository
- Path traversal, command injection, or privilege-escalation risks in script logic or shared lib modules
- CI pipeline issues that could introduce malicious code

**Out of scope:**
- Issues in third-party tools (Sysmon, WinGet, Defender) that scripts merely invoke
- Findings that require attacker-controlled input with local admin or SYSTEM access to exploit
- General Windows hardening advice or opinionated baseline disagreements

## Reporting a Vulnerability

Please report security issues **privately** — do not open a public issue:

- Open a [GitHub security advisory](https://github.com/sebastianspicker/win-mdm-security-hardening-kit/security/advisories/new), or
- Contact the maintainer via the email listed on their GitHub profile.

Please include:
- A clear description of the issue
- Steps to reproduce
- Impact assessment
- Any potential mitigations

We will acknowledge receipt within 7 days and work on a fix as appropriate.
