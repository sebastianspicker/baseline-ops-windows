#requires -Version 5.1
<#
.SYNOPSIS
Starts the BaselineOps Windows Forms operator console.

.DESCRIPTION
Loads the isolated launcher application implementation after enforcing the
Windows-only runtime contract for the shipped GUI entry point.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ($env:OS -ne 'Windows_NT') {
  Write-Error 'Launcher-GUI requires Windows.'
  exit 1
}

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
Import-Module (Join-Path $PSScriptRoot 'Launcher-GUI.App.psm1') -Force
Start-LauncherGui
