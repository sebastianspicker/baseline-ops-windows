<#
.SYNOPSIS
WinGet self-heal install helpers.

.DESCRIPTION
Contains capability-private WinGet self-heal install behavior.
#>

function Test-VcRedistInstalled {
  [CmdletBinding()]
  param([ValidateSet('x64','x86')]$Arch='x64')
  $paths = @(
    "HKLM:\SOFTWARE\Microsoft\VisualStudio\14.0\VC\Runtimes\$Arch",
    "HKLM:\SOFTWARE\Wow6432Node\Microsoft\VisualStudio\14.0\VC\Runtimes\$Arch"
  )
  foreach ($key in $paths) {
    if (Test-Path $key) {
      try {
        $p = Get-ItemProperty -Path $key -ErrorAction Stop
        $installed = ($p.Installed -eq 1) -or ($p.PSObject.Properties['Version'] -and $p.Version)
        if ($installed) { return $true, ($p.Version) }
      } catch {
        Write-Verbose ("VC++ redistributable registry probe failed for '{0}': {1}" -f $key,$_.Exception.Message)
      }
    }
  }
  return $false, $null
}

function Open-VcRedistInstaller {
  param([string]$Path)
  $providerPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)
  if (-not (Test-Path -LiteralPath $providerPath -PathType Leaf)) {
    return @{ Ok = $false; Message = "Installer not found: $Path" }
  }
  $volumeRoot = [System.IO.Path]::GetPathRoot([System.IO.Path]::GetFullPath($providerPath))
  if (Test-PathContainsReparsePoint -Path $providerPath -Root $volumeRoot) {
    return @{ Ok = $false; Message = 'Installer path contains a reparse point.' }
  }
  $resolvedPath = (Resolve-Path -LiteralPath $providerPath -ErrorAction Stop).ProviderPath
  $item = Get-Item -LiteralPath $resolvedPath -Force -ErrorAction Stop
  if ($item.Length -le 0 -or $item.Length -gt 128MB) {
    return @{ Ok = $false; Message = 'Installer size is outside the accepted range.' }
  }
  $stream = [System.IO.File]::Open(
    $resolvedPath,
    [System.IO.FileMode]::Open,
    [System.IO.FileAccess]::Read,
    [System.IO.FileShare]::Read
  )
  return @{ Ok = $true; Path = $resolvedPath; Item = $item; Stream = $stream }
}

function Get-VcRedistIdentityError {
  param($Installer, [string]$Architecture)
  if ($env:OS -ne 'Windows_NT') { return $null }
  $signature = Get-AuthenticodeSignature -LiteralPath $Installer.Path -ErrorAction Stop
  $signerSubject = if ($null -ne $signature.SignerCertificate) { [string]$signature.SignerCertificate.Subject } else { '' }
  if ($signature.Status -ne [System.Management.Automation.SignatureStatus]::Valid -or
      $signerSubject -notmatch '(?i)(^|,\s*)O=Microsoft Corporation(,|$)') {
    return 'Installer must have a valid Microsoft Authenticode signature.'
  }
  $expectedOriginalName = "VC_redist.$Architecture.exe"
  $originalName = [string]$Installer.Item.VersionInfo.OriginalFilename
  if (-not $originalName.Equals($expectedOriginalName, [System.StringComparison]::OrdinalIgnoreCase)) {
    return "Installer identity does not match $expectedOriginalName."
  }
  return $null
}

function Get-VcRedistProcessResult {
  param($NativeResult)
  if ($null -eq $NativeResult) { return $false, 'Installer process could not be started.' }
  if ($NativeResult.TimedOut) { return $false, 'Installer timed out after 600 s.' }
  if ($NativeResult.OutputTruncated -or $NativeResult.StderrTruncated) {
    return $false, 'Installer output was truncated; result is unusable.'
  }
  if ($NativeResult.Success) { return $true, 'OK' }
  return $false, "ExitCode=$($NativeResult.ExitCode)"
}

function Install-VcRedist {
  [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
  param(
    [Parameter(Mandatory)][string]$Path,
    [string]$InstallArgs = "/install /quiet /norestart",
    [ValidateSet('x64','x86')][string]$Architecture = 'x64'
  )
  $installer = $null
  try {
    $installer = Open-VcRedistInstaller -Path $Path
    if (-not $installer.Ok) { return $false, $installer.Message }
    $identityError = Get-VcRedistIdentityError -Installer $installer -Architecture $Architecture
    if ($identityError) { return $false, $identityError }
    $arguments = ConvertTo-ConservativeNativeArguments -ArgumentString $InstallArgs
    if (-not $PSCmdlet.ShouldProcess($installer.Path, "Install VC++ $Architecture redistributable")) {
      return $false, 'Skipped by ShouldProcess'
    }
    $native = Invoke-NativeCommand -Command $installer.Path -Arguments $arguments -CaptureOutput -Quiet `
      -TimeoutSeconds 600 -MaxOutputBytes 1048576
    return Get-VcRedistProcessResult -NativeResult $native
  }
  catch { return $false, $_.Exception.Message }
  finally {
    if ($null -ne $installer -and $null -ne $installer.Stream) { $installer.Stream.Dispose() }
  }
}
