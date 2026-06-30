# Documentation

This directory contains the public documentation index and assets for the Windows MDM Endpoint Security Hardening Kit.

## Active Docs

- [Project overview and quick start](../README.md)
- [Script catalog and usage](../scripts/README.md)
- [Shared module reference](../lib/README.md)
- [Example profiles and configs](../examples/README.md)
- [Security policy](../SECURITY.md)
- [Contribution guide](../CONTRIBUTING.md)
- [Changelog](../CHANGELOG.md)

## Public Documentation Policy

Public docs describe the current supported project surface. Keep durable user and maintainer guidance in the active docs listed above.

Do not commit internal review artifacts, including:

- audit notes
- remediation plans
- ledgers and status logs
- deprecated docs
- generated evidence
- local archive packets
- local Codacy Analysis CLI output
- vendored source snapshots
- machine-specific harness state

Those files belong in ignored local paths such as `private/`, `docs/archive/`, `archive/`, or another `.gitignore`-covered workspace.

## Ignored Local Material

The repository intentionally ignores these local documentation paths and filename patterns:

- `private/`
- `docs/archive/`
- `docs/source-audit/`
- `docs/tmp/`
- `docs/temp/`
- `docs/*audit*.md`
- `docs/*remediation*.md`
- `docs/*plan*.md`
- `docs/*ledger*.md`
- `docs/*status*.md`
- `docs/*findings*.md`
- `.codacy/`
- `.codegraph/`
- `.serena/`
- `archive/`
- `vendor/`
- `third_party/`
- `third-party/`
- `external/`

Keep one-off reviews, work logs, and remediation scratch files out of public documentation.
