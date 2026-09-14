---
name: Bug report
about: Report incorrect behavior, unsafe output, or a broken script/profile
labels: bug
---

# Bug report

Do not include secrets, private hostnames, user names, account identifiers, full
support bundles, or exploit details in public issues. Report security issues
by following the private process in the [security policy](https://github.com/sebastianspicker/baseline-ops/security/policy).

## Affected area

Name the script, profile, module, workflow, or document involved. For example:
`scripts/18-Firewall-Baseline.ps1`.

## Release, tag, or commit

Which published prerelease, Git tag, or commit did you test?

## Expected behavior

What did you expect to happen?

## Actual behavior

What actually happened?

## Steps to reproduce

List the steps and commands needed to reproduce the problem. Include relevant
configuration with private values redacted.

## Invocation mode

Which command did you run? Include `-Mode`, `-WhatIf`, `-Confirm`, profile path,
output format, and whether the shell was elevated.

## Environment

Include the Windows version, PowerShell version, and relevant tools. If you
found the problem on another operating system, name it here.

## Logs or output

Paste the smallest relevant error or output excerpt. Redact sensitive data.

## Regression check

Did this work in an earlier commit, release, or environment?
