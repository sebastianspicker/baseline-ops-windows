#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
pwsh_bin="${PWSH_BIN:-pwsh}"
psa_version="${PSSCRIPTANALYZER_VERSION:-1.24.0}"

if ! command -v "$pwsh_bin" >/dev/null 2>&1; then
  echo "pwsh not found. Install PowerShell 7+ or set PWSH_BIN to the executable path." >&2
  exit 1
fi

skip_analyzer="${CI_SKIP_ANALYZER:-}"
skip_tests="${CI_SKIP_TESTS:-}"

if [[ -z "$skip_analyzer" ]]; then
  "$pwsh_bin" -NoProfile -Command "if (-not (Get-Module -ListAvailable -Name PSScriptAnalyzer | Where-Object { \$_.Version -eq '$psa_version' })) { Set-PSRepository -Name 'PSGallery' -InstallationPolicy Trusted; Install-Module -Name PSScriptAnalyzer -RequiredVersion '$psa_version' -Scope CurrentUser -Force }"
fi

"$pwsh_bin" -NoProfile -File "$root_dir/tools/secret-scan.ps1" -RootPath "$root_dir"

if [[ -n "$skip_analyzer" ]]; then
  "$pwsh_bin" -NoProfile -File "$root_dir/tools/verify.ps1" -RootPath "$root_dir" -SkipAnalyzer
else
  "$pwsh_bin" -NoProfile -File "$root_dir/tools/verify.ps1" -RootPath "$root_dir"
fi

if [[ -z "$skip_tests" ]]; then
  "$pwsh_bin" -NoProfile -Command "Invoke-Pester -Path '$root_dir/tests' -Output Detailed"
fi
