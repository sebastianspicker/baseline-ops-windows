<#
.SYNOPSIS
Stable facade for native command execution and Windows tool operations.

.DESCRIPTION
Loads focused platform implementations while preserving External.psm1's
public command contract for existing endpoint scripts.
#>

Set-StrictMode -Version Latest
Microsoft.PowerShell.Core\Import-Module ([System.IO.Path]::Combine($PSScriptRoot, 'Validation.psm1'))
$script:IsWindowsHost = (
  [System.Environment]::OSVersion.Platform -eq [System.PlatformID]::Win32NT
)

$platformRoot = Join-Path $PSScriptRoot 'platform'
. (Join-Path $platformRoot 'Executable.ps1')
. (Join-Path $platformRoot 'NativeProcess.ps1')
. (Join-Path $platformRoot 'NativeTools.ps1')

Export-ModuleMember -Function @(
  'Resolve-TrustedWindowsSystemFile',
  'Resolve-TrustedWingetPath',
  'Resolve-TrustedGitPath',
  'Test-CommandExists',
  'Ensure-Cmdlet',
  'Ensure-Exe',
  'Invoke-NativeCommand',
  'Invoke-Auditpol',
  'Invoke-Wevtutil',
  'Invoke-RegExe',
  'Invoke-WinrmCommand'
)
