<#
.SYNOPSIS
  Invokes an approved fixed native tool through the native command boundary.
.DESCRIPTION
  Restricts callers to the Windows tools exposed by the public compatibility
  wrappers while keeping their native invocation semantics consistent.
#>
function Invoke-FixedNativeTool {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]
    [ValidateSet('auditpol.exe', 'wevtutil.exe', 'reg.exe')]
    [string]$Tool,

    [Parameter(Mandatory)]
    [string[]]$Arguments,

    [switch]$ThrowOnError,

    [switch]$CaptureOutput,
    [ValidateRange(1, 86400)][int]$TimeoutSeconds = 300,
    [ValidateRange(1024, 10485760)][int]$MaxOutputBytes = 1048576
  )

  return (Invoke-NativeCommand -Command $Tool -Arguments $Arguments `
      -ThrowOnError:$ThrowOnError -CaptureOutput:$CaptureOutput -TimeoutSeconds $TimeoutSeconds -MaxOutputBytes $MaxOutputBytes)
}

<#
.SYNOPSIS
  Wrapper for auditpol.exe with exit code validation.
#>
function Invoke-Auditpol {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]
    [string[]]$Arguments,

    [switch]$ThrowOnError,

    [switch]$CaptureOutput
  )

  return (Invoke-FixedNativeTool -Tool 'auditpol.exe' -Arguments $Arguments -ThrowOnError:$ThrowOnError -CaptureOutput:$CaptureOutput)
}

<#
.SYNOPSIS
  Wrapper for wevtutil.exe with exit code validation.
#>
function Invoke-Wevtutil {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]
    [string[]]$Arguments,

    [switch]$ThrowOnError,

    [switch]$CaptureOutput
  )

  return (Invoke-FixedNativeTool -Tool 'wevtutil.exe' -Arguments $Arguments -ThrowOnError:$ThrowOnError -CaptureOutput:$CaptureOutput)
}

<#
.SYNOPSIS
  Wrapper for reg.exe with exit code validation.
#>
function Invoke-RegExe {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]
    [string[]]$Arguments,

    [switch]$ThrowOnError,

    [switch]$CaptureOutput
  )

  return (Invoke-FixedNativeTool -Tool 'reg.exe' -Arguments $Arguments -ThrowOnError:$ThrowOnError -CaptureOutput:$CaptureOutput)
}

<#
.SYNOPSIS
  Invokes the trusted System32 WinRM script through the trusted cscript host.
#>
function Invoke-WinrmCommand {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string[]]$Arguments,
    [switch]$ThrowOnError,
    [switch]$CaptureOutput,
    [switch]$Quiet,
    [ValidateRange(1, 86400)][int]$TimeoutSeconds = 300,
    [ValidateRange(1024, 10485760)][int]$MaxOutputBytes = 1048576
  )

  $winrmScript = Resolve-TrustedWindowsSystemFile -LeafName 'winrm.vbs'
  if ([string]::IsNullOrWhiteSpace($winrmScript)) {
    $message = 'Trusted WinRM script not found.'
    if ($ThrowOnError) { throw $message }
    if (-not $Quiet) { Write-Warning $message }
    return $null
  }

  $scriptLock = $null
  try {
    $scriptLock = [IO.File]::Open($winrmScript, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    return Invoke-NativeCommand -Command 'cscript.exe' -Arguments (@('//NoLogo', $winrmScript) + $Arguments) `
      -ThrowOnError:$ThrowOnError -CaptureOutput:$CaptureOutput -Quiet:$Quiet `
      -TimeoutSeconds $TimeoutSeconds -MaxOutputBytes $MaxOutputBytes
  } finally {
    if ($null -ne $scriptLock) { $scriptLock.Dispose() }
  }
}

<#
.SYNOPSIS
  Tests that a bounded native result finished without failure or truncation.
.DESCRIPTION
  Prevents a partial Git response from becoming a file inventory.
#>
function Test-GitResultComplete {
  [CmdletBinding()]
  param($Result)

  return [bool]($Result -and $Result.Success -and -not $Result.TimedOut -and
    -not $Result.OutputTruncated -and -not $Result.StderrTruncated)
}

<#
.SYNOPSIS
  Converts one Git-reported path to a validated absolute file path.
.DESCRIPTION
  Throws for rooted, control-character, and escaping paths; returns $null when the path is not an existing file.
#>
function ConvertTo-GitWorkingTreeFilePath {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$RelativePath,
    [Parameter(Mandatory)][string]$RootPath
  )

  if ([string]::IsNullOrWhiteSpace($RelativePath) -or
      [System.IO.Path]::IsPathRooted($RelativePath) -or
      $RelativePath -match '[\x00-\x1F\x7F]') {
    throw 'git returned an unsafe repository-relative path.'
  }
  $candidate = [System.IO.Path]::GetFullPath((Join-Path $RootPath $RelativePath))
  if (-not (Validation\Test-PathUnderRoot -Path $candidate -Root $RootPath)) {
    throw 'git returned a path outside the requested root.'
  }
  if (Test-Path -LiteralPath $candidate -PathType Leaf) { return $candidate }
  return $null
}

<#
.SYNOPSIS
  Lists tracked and non-ignored files of a Git work tree as validated absolute paths.
.DESCRIPTION
  Returns $null when the path is not a work tree or Git fails, times out, or truncates its output.
#>
function Get-GitWorkingTreeFiles {
  [CmdletBinding()]
  param([Parameter(Mandatory)][string]$Path)

  if (-not (Test-CommandExists -Name 'git')) { return $null }
  $separators = [char[]]@([System.IO.Path]::DirectorySeparatorChar, [System.IO.Path]::AltDirectorySeparatorChar)
  $root = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path).TrimEnd($separators)
  $rootResult = Invoke-NativeCommand -Command 'git' -Arguments @('-C', $root, 'rev-parse', '--is-inside-work-tree') `
    -CaptureOutput -Quiet -TimeoutSeconds 30 -MaxOutputBytes 1048576
  if (-not (Test-GitResultComplete -Result $rootResult) -or $rootResult.Stdout.Trim() -ne 'true') { return $null }
  $filesResult = Invoke-NativeCommand -Command 'git' `
    -Arguments @('-C', $root, 'ls-files', '-z', '--cached', '--others', '--exclude-standard') `
    -CaptureOutput -Quiet -TimeoutSeconds 30 -MaxOutputBytes 1048576
  if (-not (Test-GitResultComplete -Result $filesResult)) { return $null }
  $files = foreach ($relative in $filesResult.Stdout.Split([char]0, [System.StringSplitOptions]::RemoveEmptyEntries)) {
    ConvertTo-GitWorkingTreeFilePath -RelativePath $relative -RootPath $root
  }
  # Case-sensitive: on a case-sensitive file system Key.json and key.json are two files to scan.
  return @($files | Where-Object { $null -ne $_ } | Sort-Object -Unique -CaseSensitive)
}
