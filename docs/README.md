# Documentation

This directory contains public documentation assets for the Windows MDM Endpoint
Security Hardening Kit.

## Active docs

- [Project overview and quick start](../README.md)
- [Script catalog and usage](../scripts/README.md)
- [Shared module reference](../lib/README.md)
- [Example profiles and configs](../examples/README.md)
- [Security policy](../SECURITY.md)
- [Contribution guide](../CONTRIBUTING.md)
- [Changelog](../CHANGELOG.md)

## Documentation policy

Public docs describe the current supported project surface. Internal audit
notes, remediation plans, ledgers, status logs, deprecated docs, local archives,
generated evidence, and machine-specific harness artifacts are not part of the
committed public documentation set.

Store those materials only in ignored local archive paths such as `docs/agent/`
or another `.gitignore`-covered workspace.

## Local-only materials

The following paths and filename patterns are intentionally ignored:

- `docs/agent/`
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
- `archive/`
- `vendor/`
- `third_party/`
- `third-party/`
- `external/`

Keep durable public guidance in the active docs above. Keep one-off reviews,
work logs, and remediation plans in pull request descriptions or ignored local
workspace files.
