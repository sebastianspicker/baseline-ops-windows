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

secret_status="NOT_RUN"
static_status="NOT_RUN"
analyzer_status="NOT_RUN"
tests_status="NOT_RUN"
overall_status="PASS"
summary_printed=0

print_summary() {
  if [[ "$summary_printed" -eq 1 ]]; then
    return
  fi
  summary_printed=1
  echo
  echo "CI gate summary"
  printf '| %-12s | %-8s |\n' "Gate" "Status"
  printf '| %-12s | %-8s |\n' "------------" "--------"
  printf '| %-12s | %-8s |\n' "SecretScan" "$secret_status"
  printf '| %-12s | %-8s |\n' "Static" "$static_status"
  printf '| %-12s | %-8s |\n' "Analyzer" "$analyzer_status"
  printf '| %-12s | %-8s |\n' "Tests" "$tests_status"
  printf '| %-12s | %-8s |\n' "Overall" "$overall_status"
}

fail_with_summary() {
  local exit_code="$1"
  overall_status="FAILED"
  print_summary
  exit "$exit_code"
}

if [[ -n "$skip_analyzer" || -n "$skip_tests" ]]; then
  overall_status="PARTIAL"
fi

if [[ -z "$skip_analyzer" ]]; then
  analyzer_status="SETUP"
  if "$pwsh_bin" -NoProfile -Command "if (-not (Get-Module -ListAvailable -Name PSScriptAnalyzer | Where-Object { \$_.Version -eq '$psa_version' })) { Set-PSRepository -Name 'PSGallery' -InstallationPolicy Trusted; Install-Module -Name PSScriptAnalyzer -RequiredVersion '$psa_version' -Scope CurrentUser -Force }"; then
    analyzer_status="READY"
  else
    analyzer_status="FAILED"
    fail_with_summary 1
  fi
else
  analyzer_status="SKIPPED"
fi

secret_status="RUN"
if "$pwsh_bin" -NoProfile -File "$root_dir/tools/secret-scan.ps1" -RootPath "$root_dir"; then
  secret_status="PASS"
else
  secret_status="FAILED"
  fail_with_summary 1
fi

static_status="RUN"
if [[ -n "$skip_analyzer" ]]; then
  if "$pwsh_bin" -NoProfile -File "$root_dir/tools/verify.ps1" -RootPath "$root_dir" -SkipAnalyzer; then
    static_status="PASS"
  else
    static_status="FAILED"
    fail_with_summary "$?"
  fi
else
  if "$pwsh_bin" -NoProfile -File "$root_dir/tools/verify.ps1" -RootPath "$root_dir"; then
    static_status="PASS"
    analyzer_status="PASS"
  else
    static_status="FAILED"
    analyzer_status="FAILED"
    fail_with_summary "$?"
  fi
fi

if [[ -z "$skip_tests" ]]; then
  tests_status="RUN"
  if "$pwsh_bin" -NoProfile -Command "Invoke-Pester -Path '$root_dir/tests' -Output Detailed"; then
    tests_status="PASS"
  else
    tests_status="FAILED"
    fail_with_summary "$?"
  fi
else
  tests_status="SKIPPED"
fi

print_summary
