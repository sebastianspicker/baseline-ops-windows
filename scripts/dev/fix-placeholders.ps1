#requires -version 5.1
<#
.SYNOPSIS
Replaces PATH/TO/* placeholder paths with $null defaults in script parameters.

.DESCRIPTION
This script scans all .ps1 files in the scripts directory and replaces:
1. Parameter defaults like [string]$ConfigPath = "PATH/TO/..." with [string]$ConfigPath
2. Internal variables using PATH/TO/* placeholders with appropriate defaults

This is a one-time migration script for Phase 3 of the repo improvement plan.

.PARAMETER DryRun
If set, shows what would be changed without making modifications.

.EXAMPLE
.\tools\fix-placeholders.ps1 -DryRun
.\tools\fix-placeholders.ps1
#>

[CmdletBinding()]
param(
  [switch]$DryRun
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$scriptsPath = Join-Path $PSScriptRoot '..\scripts'
$files = Get-ChildItem -Path $scriptsPath -Filter '*.ps1' -File

$totalReplacements = 0

# Pattern: Parameter defaults with PATH/TO/... strings (double-quoted)
$pattern1 = [regex]'(\[\s*string\s*\]\s*\$\w+)\s*=\s*"[^"]*PATH/TO/[^"]*"'

# Pattern: Parameter defaults with PATH/TO/... strings (single-quoted)
$pattern2 = [regex]"(\[\s*string\s*\]\s*\$\w+)\s*=\s*'[^']*PATH/TO/[^']*'"

foreach ($file in $files) {
  $content = Get-Content -Path $file.FullName -Raw
  $fileReplacements = 0
  
  # Replace double-quoted PATH/TO defaults
  $matches1 = $pattern1.Matches($content)
  foreach ($match in $matches1) {
    $fileReplacements++
  }
  $content = $pattern1.Replace($content, '$1')
  
  # Replace single-quoted PATH/TO defaults
  $matches2 = $pattern2.Matches($content)
  foreach ($match in $matches2) {
    $fileReplacements++
  }
  $content = $pattern2.Replace($content, '$1')
  
  if ($fileReplacements -gt 0) {
    $totalReplacements += $fileReplacements
    
    if ($DryRun) {
      Write-Host "[$fileReplacements changes] $($file.Name)" -ForegroundColor Yellow
    } else {
      Set-Content -Path $file.FullName -Value $content -NoNewline
      Write-Host "[$fileReplacements changes] $($file.Name)" -ForegroundColor Green
    }
  }
}

if ($DryRun) {
  Write-Host "`nDry run complete. Would make $totalReplacements replacements." -ForegroundColor Cyan
} else {
  Write-Host "`nComplete. Made $totalReplacements replacements." -ForegroundColor Green
}
