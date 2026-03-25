#requires -version 5.1
<#
.SYNOPSIS
Fixes -ErrorAction SilentlyContinue patterns in scripts.

.DESCRIPTION
This script identifies and helps fix problematic -ErrorAction SilentlyContinue
patterns that hide failures. It can:
1. Report all occurrences
2. Suggest fixes
3. Apply fixes automatically (with -Apply)

.PARAMETER Apply
If set, applies fixes to the files.

.PARAMETER DryRun
If set, shows what would be changed without making modifications.

.EXAMPLE
.\tools\fix-error-handling.ps1 -DryRun
.\tools\fix-error-handling.ps1 -Apply
#>

[CmdletBinding()]
param(
  [switch]$DryRun,
  [switch]$Apply
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$scriptsPath = Join-Path $PSScriptRoot '..\scripts'
$files = Get-ChildItem -Path $scriptsPath -Filter '*.ps1' -File

$totalIssues = 0
$issuesByFile = @{}

# Patterns to check
$patterns = @(
  @{
    Pattern = '-ErrorAction\s+SilentlyContinue'
    Type = 'SilentlyContinue'
    Severity = 'Warning'
    Suggestion = 'Consider using -ErrorAction Stop with try/catch'
  }
)

foreach ($file in $files) {
  $content = Get-Content -Path $file.FullName -Raw
  $fileIssues = @()
  
  foreach ($p in $patterns) {
    $matchList = [regex]::Matches($content, $p.Pattern)
    foreach ($match in $matchList) {
      $fileIssues += @{
        Type = $p.Type
        Severity = $p.Severity
        Line = $match.Value
        Position = $match.Index
        Suggestion = $p.Suggestion
      }
    }
  }
  
  if ($fileIssues.Count -gt 0) {
    $totalIssues += $fileIssues.Count
    $issuesByFile[$file.Name] = $fileIssues
  }
}

# Report
Write-Host "`n=== Error Handling Analysis ===" -ForegroundColor Cyan
Write-Host "Total issues found: $totalIssues" -ForegroundColor $(if ($totalIssues -gt 0) { 'Yellow' } else { 'Green' })

foreach ($entry in $issuesByFile.GetEnumerator()) {
  Write-Host "`n[$($entry.Value.Count) issues] $($entry.Key)" -ForegroundColor Yellow
  foreach ($issue in $entry.Value) {
    Write-Host "  - $($issue.Type): $($issue.Suggestion)" -ForegroundColor Gray
  }
}

if ($DryRun) {
  Write-Host "`nDry run complete. No changes made." -ForegroundColor Cyan
}
if ($Apply) {
  Write-Host "`nApply not implemented; use -DryRun to review. Fixes require manual edit." -ForegroundColor Yellow
}

# Note: Automatic fixing is complex because context matters.
# Some SilentlyContinue uses are legitimate (checking if command exists, etc.)
# Manual review is recommended.