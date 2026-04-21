Set-StrictMode -Version Latest

<#
.SYNOPSIS
Script execution and process invocation utilities.

.DESCRIPTION
Provides helpers for argument tokenization, retry logic, native process
invocation with timeout support, and timed script execution.
#>

function Convert-TokenValue {
  [CmdletBinding()]
  param(
    [AllowNull()]
    [object]$Value
  )

  if ($null -eq $Value) { return $null }
  $text = [string]$Value

  switch -Regex ($text) {
    '^\$(?i:true)$' { return $true }
    '^\$(?i:false)$' { return $false }
    default { return $text }
  }
}

<#
.SYNOPSIS
  Retries a scriptblock up to a maximum number of attempts.
.PARAMETER Action
  Scriptblock to execute.
.PARAMETER MaxAttempts
  Maximum number of attempts before re-throwing.
.PARAMETER DelaySeconds
  Delay in seconds between retry attempts.
#>
function Invoke-WithRetry {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]
    [scriptblock]$Action,
    [int]$MaxAttempts = 3,
    [int]$DelaySeconds = 1
  )

  if ($MaxAttempts -lt 1) { throw 'MaxAttempts must be >= 1.' }
  if ($DelaySeconds -lt 0) { throw 'DelaySeconds must be >= 0.' }

  $attempt = 0
  while ($attempt -lt $MaxAttempts) {
    $attempt++
    try {
      return & $Action
    } catch {
      if ($attempt -ge $MaxAttempts) { throw }
      if ($DelaySeconds -gt 0) { Start-Sleep -Seconds $DelaySeconds }
    }
  }
}

<#
.SYNOPSIS
  Parses a string array of CLI-style arguments into named and positional tokens.
.PARAMETER Arguments
  Array of argument strings to tokenize.
#>
function Convert-ArgumentTokens {
  [CmdletBinding()]
  param(
    [string[]]$Arguments = @()
  )

  $namedArgs = @{}
  $positionalArgs = New-Object System.Collections.ArrayList
  $optionPattern = '^-{1,2}[A-Za-z][A-Za-z0-9-]*$'
  $optionWithInlineValuePattern = '^-{1,2}([A-Za-z][A-Za-z0-9-]*):(.*)$'

  for ($i = 0; $i -lt $Arguments.Count; $i++) {
    $token = [string]$Arguments[$i]

    if ($token -match $optionWithInlineValuePattern) {
      $name = $Matches[1]
      $value = Convert-TokenValue -Value $Matches[2]
      if ($namedArgs.ContainsKey($name)) {
        $existing = @($namedArgs[$name])
        $namedArgs[$name] = @($existing + $value)
      } else {
        $namedArgs[$name] = $value
      }
      continue
    }

    if ($token -match $optionPattern) {
      $name = $token.TrimStart('-')
      $next = $null
      if ($i + 1 -lt $Arguments.Count) {
        $next = [string]$Arguments[$i + 1]
      }

      if ($null -eq $next -or $next -match $optionPattern -or $next -match $optionWithInlineValuePattern) {
        $namedArgs[$name] = $true
      } else {
        $value = Convert-TokenValue -Value $next
        if ($namedArgs.ContainsKey($name)) {
          $existing = @($namedArgs[$name])
          $namedArgs[$name] = @($existing + $value)
        } else {
          $namedArgs[$name] = $value
        }
        $i++
      }
    } else {
      [void]$positionalArgs.Add($token)
    }
  }

  return [pscustomobject]@{
    Named = $namedArgs
    Positional = @($positionalArgs)
  }
}

<#
.SYNOPSIS
  Launches an external process and captures stdout, stderr, and exit code.
.PARAMETER FilePath
  Path to the executable.
.PARAMETER Arguments
  Arguments passed to the process.
.PARAMETER WorkingDirectory
  Optional working directory for the process.
.PARAMETER TimeoutSeconds
  Maximum seconds to wait. Zero means wait indefinitely.
.PARAMETER ThrowOnError
  Throw an exception if the process exits with a non-zero code.
#>
function Invoke-NativeProcess {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]
    [string]$FilePath,
    [string[]]$Arguments = @(),
    [string]$WorkingDirectory,
    [int]$TimeoutSeconds = 0,
    [switch]$ThrowOnError
  )

  $psi = New-Object System.Diagnostics.ProcessStartInfo
  $psi.FileName = $FilePath
  $psi.UseShellExecute = $false
  $psi.RedirectStandardOutput = $true
  $psi.RedirectStandardError = $true
  $psi.CreateNoWindow = $true

  foreach ($arg in $Arguments) {
    [void]$psi.ArgumentList.Add([string]$arg)
  }

  if (-not [string]::IsNullOrWhiteSpace($WorkingDirectory)) {
    $psi.WorkingDirectory = $WorkingDirectory
  }

  $proc = New-Object System.Diagnostics.Process
  $proc.StartInfo = $psi

  if (-not $proc.Start()) {
    throw "Failed to start process: $FilePath"
  }

  # Begin async reads before WaitForExit to prevent pipe-buffer deadlock.
  # If reads started after WaitForExit the child could block trying to write
  # to a full pipe while we block waiting for the child to exit.
  $stdoutTask = $proc.StandardOutput.ReadToEndAsync()
  $stderrTask = $proc.StandardError.ReadToEndAsync()

  if ($TimeoutSeconds -gt 0) {
    if (-not $proc.WaitForExit($TimeoutSeconds * 1000)) {
      try { $proc.Kill() } catch { <# best-effort #> }
      throw "Process timeout after $TimeoutSeconds seconds: $FilePath"
    }
  } else {
    $proc.WaitForExit()
  }

  $stdout = $stdoutTask.Result
  $stderr = $stderrTask.Result

  $result = [pscustomobject]@{
    FilePath  = $FilePath
    Arguments = @($Arguments)
    ExitCode  = $proc.ExitCode
    StdOut    = $stdout
    StdErr    = $stderr
    Success   = ($proc.ExitCode -eq 0)
  }

  if ($ThrowOnError -and -not $result.Success) {
    throw "Process failed (exit $($result.ExitCode)): $FilePath $($Arguments -join ' ')"
  }

  return $result
}

<#
.SYNOPSIS
  Invokes a PowerShell script and measures its execution time.
.PARAMETER ScriptPath
  Path to the .ps1 script to execute.
.PARAMETER Arguments
  Arguments to pass to the script.
#>
function Invoke-ScriptWithTiming {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]
    [string]$ScriptPath,
    [string[]]$Arguments = @()
  )

  $sw = [System.Diagnostics.Stopwatch]::StartNew()
  $err = $null
  $global:LASTEXITCODE = 0
  try {
    & $ScriptPath @Arguments
    $exitCode = if ($null -ne $LASTEXITCODE -and $LASTEXITCODE -ne 0) { $LASTEXITCODE } else { 0 }
  } catch {
    $exitCode = if ($null -ne $LASTEXITCODE -and $LASTEXITCODE -ne 0) { $LASTEXITCODE } else { 1 }
    $err = $_
  } finally {
    $sw.Stop()
  }

  $result = [pscustomobject]@{
    ScriptPath         = $ScriptPath
    Arguments          = @($Arguments)
    DurationMs         = $sw.ElapsedMilliseconds
    ExitCode           = $exitCode
    Success            = ($exitCode -eq 0)
    ErrorMessage       = if ($err) { $err.Exception.Message } else { $null }
  }

  return $result
}

Export-ModuleMember -Function `
  Convert-ArgumentTokens, `
  Invoke-WithRetry, `
  Invoke-NativeProcess, `
  Invoke-ScriptWithTiming
