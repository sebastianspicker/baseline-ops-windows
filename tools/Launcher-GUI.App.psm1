<#
.SYNOPSIS
Composes the private Windows Forms launcher implementation.

.DESCRIPTION
Loads the runtime, catalog, and view components into one module scope so they
share the launcher state while the public GUI entry point stays minimal.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'Launcher-GUI.Runtime.ps1')
. (Join-Path $PSScriptRoot 'Launcher-GUI.Catalog.ps1')
. (Join-Path $PSScriptRoot 'Launcher-GUI.View.ps1')

Export-ModuleMember -Function Start-LauncherGui
