# Dev Scripts

One-off maintenance helpers used during refactor/migration work.

- `fix-error-handling.ps1`: scans for risky `-ErrorAction SilentlyContinue` usage.
- `fix-placeholders.ps1`: replaces legacy `PATH/TO/...` parameter defaults.

These are developer helpers and not part of runtime or CI requirements.
