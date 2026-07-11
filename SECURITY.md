# Security Policy

## Supported Versions

Only the current `main` branch is actively maintained unless the maintainer explicitly confirms support for another branch or tag.

Scripts are intended for controlled, lab-tested environments. For production use, validate remediation scripts in your own environment and open a maintainer discussion before proceeding.

## Scope

In scope:

- Logic errors in audit or remediation scripts that produce incorrect results or unsafe system changes
- Secrets, credentials, or PII inadvertently committed to the repository
- Path traversal, command injection, or privilege-escalation risks in script logic or shared modules
- CI pipeline issues that could introduce malicious code

Out of scope:

- Issues in third-party tools such as Sysmon, WinGet, or Defender
- Findings that require attacker-controlled local admin or SYSTEM access
- General Windows hardening advice or baseline preference disagreements

## Reporting A Vulnerability

Please report security issues privately. Do not open a public issue with exploit details.

Use one of these channels:

- Open a [GitHub security advisory][security-advisory].
- Contact the maintainer via the email listed on the GitHub profile.

If both private channels are unavailable, open a public issue that contains no exploit details, secrets, logs, screenshots, or environment-specific identifiers, and ask for a private maintainer contact.

Please include:

- Clear description of the issue
- Steps to reproduce
- Impact assessment
- Potential mitigations, if known

We aim to acknowledge reports as soon as maintainer availability permits and
will communicate the next review or mitigation step when triage begins.

[security-advisory]: https://github.com/sebastianspicker/win-mdm-security-hardening-kit/security/advisories/new
