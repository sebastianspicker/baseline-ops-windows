Set-StrictMode -Version Latest

<#
.SYNOPSIS
Wrappers for external command-line tools with exit code validation.

.DESCRIPTION
This module provides safe wrappers for common Windows command-line utilities
that are used across multiple scripts. Each wrapper:
- Validates the command exists before execution
- Captures and validates exit codes
- Provides consistent error handling
- Supports -ErrorAction and -WarningAction

.NOTES
Provides centralized external command exit code validation for runtime scripts.
#>

<#
.SYNOPSIS
  Tests whether an external command exists in PATH.
.PARAMETER Name
  Executable name to look up.
#>
function Test-CommandExists {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]
    [string]$Name
  )

  return ($null -ne (Get-Command -Name $Name -CommandType Application -ErrorAction SilentlyContinue))
}

<#
.SYNOPSIS
  Throws if a required cmdlet or function is not available.
.PARAMETER Name
  Cmdlet or function name to check.
.PARAMETER Message
  Custom error message on failure.
#>
function Ensure-Cmdlet {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]
    [string]$Name,
    [string]$Message
  )
  if ($null -ne (Get-Command -Name $Name -ErrorAction SilentlyContinue)) { return $true }
  $msg = if ($Message) { $Message } else { "Required cmdlet or function not found: $Name" }
  throw $msg
}

<#
.SYNOPSIS
  Throws if a required executable is not found in PATH.
.PARAMETER Name
  Executable name to check.
.PARAMETER Message
  Custom error message on failure.
#>
function Ensure-Exe {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]
    [string]$Name,
    [string]$Message
  )
  $exe = Get-Command -Name $Name -CommandType Application -ErrorAction SilentlyContinue
  if ($exe) { return $true }
  $msg = if ($Message) { $Message } else { "Required executable not found: $Name" }
  throw $msg
}

<#
.SYNOPSIS
  Invokes an external command with exit code validation.
.PARAMETER Command
  Executable name or path (single token, no spaces).
.PARAMETER Arguments
  Arguments to pass to the command.
.PARAMETER ThrowOnError
  Throw on non-zero exit code instead of writing a warning.
.PARAMETER CaptureOutput
  Return a structured object with Output, ExitCode, and Success.
.PARAMETER Quiet
  Suppress warning messages on non-zero exit codes.
#>
  # NOTE: Callers are responsible for sanitizing $Arguments before passing them to this function.
  # This is by design for flexibility - the function intentionally does not validate argument content
  # because valid arguments vary widely across different external commands.
function Invoke-NativeCommand {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]
    [string]$Command,

    [Parameter(Mandatory)]
    [string[]]$Arguments,

    [switch]$ThrowOnError,

    [switch]$CaptureOutput,

    [switch]$Quiet
  )

  # Restrict -Command to a single executable name or path to avoid command injection
  $trimmed = $Command.Trim()
  if ([string]::IsNullOrWhiteSpace($trimmed) -or $trimmed -match '\s' -or $trimmed -match '[|;&<>]') {
    throw "Invoke-NativeCommand: -Command must be a single executable name or path (no pipe, semicolon, or redirection operators)."
  }

  # Validate command exists
  if (-not (Test-CommandExists -Name $Command)) {
    $msg = "Command not found: $Command"
    if ($ThrowOnError) {
      throw $msg
    }
    Write-Warning $msg
    return $null
  }

  $stderrPath = $null
  try {
    $stderrPath = [System.IO.Path]::GetTempFileName()
    $stderr = ''

    if ($CaptureOutput) {
      $output = & $Command @Arguments 2> $stderrPath
      $exitCode = $LASTEXITCODE

      if (Test-Path -LiteralPath $stderrPath) {
        $stderr = Get-Content -LiteralPath $stderrPath -Raw -ErrorAction SilentlyContinue
        if ($null -eq $stderr) { $stderr = '' }
      }

      $mergedOutput = $output
      if (-not [string]::IsNullOrWhiteSpace($stderr)) {
        $stderrLines = $stderr -split "`r?`n" | Where-Object { $_ -ne '' }
        $mergedOutput = if ($null -eq $mergedOutput) { $stderrLines } else { @($mergedOutput) + $stderrLines }
      }

      if ($exitCode -ne 0 -and -not $Quiet) {
        $msg = "$Command exited with code $exitCode"
        $stderrText = $stderr.Trim()
        if (-not [string]::IsNullOrWhiteSpace($stderrText)) {
          $msg = "$msg. Stderr: $stderrText"
        }
        if ($ThrowOnError) { throw $msg }
        Write-Warning $msg
      }

      return [pscustomobject]@{
        Output   = $mergedOutput
        Stderr   = $stderr
        ExitCode = $exitCode
        Success  = ($exitCode -eq 0)
      }
    } else {
      & $Command @Arguments 2> $stderrPath | Out-Null
      $exitCode = $LASTEXITCODE

      if (Test-Path -LiteralPath $stderrPath) {
        $stderr = Get-Content -LiteralPath $stderrPath -Raw -ErrorAction SilentlyContinue
        if ($null -eq $stderr) { $stderr = '' }
      }

      if ($exitCode -ne 0 -and -not $Quiet) {
        $msg = "$Command exited with code $exitCode"
        $stderrText = $stderr.Trim()
        if (-not [string]::IsNullOrWhiteSpace($stderrText)) {
          $msg = "$msg. Stderr: $stderrText"
        }
        if ($ThrowOnError) { throw $msg }
        Write-Warning $msg
        return $false
      }

      return $true
    }
  } catch {
    $msg = "Failed to execute $Command : $($_.Exception.Message)"
    if ($ThrowOnError) {
      throw $msg
    }
    Write-Warning $msg
    return $null
  } finally {
    if ($stderrPath -and (Test-Path -LiteralPath $stderrPath)) {
      Remove-Item -LiteralPath $stderrPath -Force -ErrorAction SilentlyContinue
    }
  }
}

function Invoke-ExternalTool {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]
    [string]$Command,

    [Parameter(Mandatory)]
    [string[]]$Arguments,

    [switch]$ThrowOnError,

    [switch]$CaptureOutput
  )

  return (Invoke-NativeCommand -Command $Command -Arguments $Arguments `
      -ThrowOnError:$ThrowOnError -CaptureOutput:$CaptureOutput)
}

<#
.SYNOPSIS
  Wrapper for schtasks.exe with exit code validation.
#>
function Invoke-Schtasks {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]
    [string[]]$Arguments,
    
    [switch]$ThrowOnError,
    
    [switch]$CaptureOutput
  )

  return (Invoke-ExternalTool -Command 'schtasks.exe' -Arguments $Arguments -ThrowOnError:$ThrowOnError -CaptureOutput:$CaptureOutput)
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

  return (Invoke-ExternalTool -Command 'auditpol.exe' -Arguments $Arguments -ThrowOnError:$ThrowOnError -CaptureOutput:$CaptureOutput)
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

  return (Invoke-ExternalTool -Command 'wevtutil.exe' -Arguments $Arguments -ThrowOnError:$ThrowOnError -CaptureOutput:$CaptureOutput)
}

<#
.SYNOPSIS
  Wrapper for wecutil.exe with exit code validation.
#>
function Invoke-Wecutil {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]
    [string[]]$Arguments,
    
    [switch]$ThrowOnError,
    
    [switch]$CaptureOutput
  )

  return (Invoke-ExternalTool -Command 'wecutil.exe' -Arguments $Arguments -ThrowOnError:$ThrowOnError -CaptureOutput:$CaptureOutput)
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

  $regExe = Join-Path $env:WINDIR 'System32\reg.exe'
  
  return (Invoke-ExternalTool -Command $regExe -Arguments $Arguments -ThrowOnError:$ThrowOnError -CaptureOutput:$CaptureOutput)
}

<#
.SYNOPSIS
  Wrapper for git with optional working directory and exit code validation.
.PARAMETER Arguments
  Arguments to pass to git.
.PARAMETER WorkingDirectory
  Directory to run git in.
.PARAMETER ThrowOnError
  Throw on non-zero exit code.
.PARAMETER CaptureOutput
  Return structured output object.
#>
function Invoke-Git {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]
    [string[]]$Arguments,

    [string]$WorkingDirectory,

    [switch]$ThrowOnError,

    [switch]$CaptureOutput
  )

  # Validate git exists
  if (-not (Test-CommandExists -Name 'git')) {
    $msg = "git command not found. Please install Git."
    if ($ThrowOnError) {
      throw $msg
    }
    Write-Warning $msg
    return $null
  }

  # Use git -C instead of Set-Location to avoid changing process working directory
  $gitArgs = if ($WorkingDirectory) {
    @('-C', $WorkingDirectory) + $Arguments
  } else {
    $Arguments
  }

  $result = Invoke-NativeCommand -Command 'git' -Arguments $gitArgs `
    -ThrowOnError:$ThrowOnError -CaptureOutput:$CaptureOutput
  return $result
}

<#
.SYNOPSIS
  Retrieves all audit policy subcategories via auditpol.exe.
#>
function Get-AuditPolSubcategories {
  [CmdletBinding()]
  param()

  $result = Invoke-Auditpol -Arguments @('/get', '/category:*') -CaptureOutput
  
  if ($result -and $result.Success) {
    return $result.Output
  }
  
  return $null
}

<#
.SYNOPSIS
  Gets event log configuration via wevtutil.exe.
.PARAMETER LogName
  Name of the event log to query.
#>
function Get-EventLogInfo {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]
    [string]$LogName
  )

  $result = Invoke-Wevtutil -Arguments @('gl', $LogName) -CaptureOutput
  
  if ($result -and $result.Success) {
    return $result.Output
  }
  
  return $null
}

<#
.SYNOPSIS
  Enables a Windows event log via wevtutil.exe.
.PARAMETER LogName
  Name of the event log to enable.
#>
function Enable-EventLog {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]
    [string]$LogName
  )

  $result = Invoke-Wevtutil -Arguments @('sl', $LogName, '/e:true')
  return ($result -eq $true)
}

<#
.SYNOPSIS
  Sets the maximum size of a Windows event log via wevtutil.exe.
.PARAMETER LogName
  Name of the event log.
.PARAMETER MaxSizeBytes
  Maximum log size in bytes.
#>
function Set-EventLogMaxSize {
  [CmdletBinding(SupportsShouldProcess = $true)]
  param(
    [Parameter(Mandatory)]
    [string]$LogName,

    [Parameter(Mandatory)]
    [int64]$MaxSizeBytes
  )

  if (-not $PSCmdlet.ShouldProcess($LogName, "Set event log max size to $MaxSizeBytes bytes")) {
    return $false
  }
  $result = Invoke-Wevtutil -Arguments @('sl', $LogName, "/ms:$MaxSizeBytes")
  return ($result -eq $true)
}

<#
.SYNOPSIS
  Exports an event log to a file via wevtutil.exe.
.PARAMETER LogName
  Name of the event log to export.
.PARAMETER OutputPath
  File path for the exported .evtx file.
.PARAMETER Query
  Optional XPath query to filter events.
#>
function Export-EventLog {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]
    [string]$LogName,

    [Parameter(Mandatory)]
    [string]$OutputPath,

    [string]$Query
  )

  # Validate XPath query contains only safe characters to prevent injection
  if ($Query -and $Query -notmatch '^[a-zA-Z0-9\s\[\]/\x27"=*@\.\-_(),]+$') {
    throw "Export-EventLog: Query contains unsafe characters. Only letters, digits, spaces, brackets, slashes, quotes, equals, stars, at-signs, dots, hyphens, underscores, parentheses, and commas are allowed."
  }

  $wevtArgs = @('epl', $LogName, $OutputPath, '/ow:true')
  if ($Query) {
    $wevtArgs += "/q:`"$Query`""
  }

  $result = Invoke-Wevtutil -Arguments $wevtArgs -ThrowOnError
  return ($result -eq $true)
}

<#
.SYNOPSIS
  Creates a scheduled task via schtasks.exe.
.PARAMETER TaskName
  Name (and optional folder path) for the task.
.PARAMETER TaskRun
  Command or script the task will execute.
.PARAMETER Schedule
  Trigger schedule type (default: ONCE).
.PARAMETER StartTime
  Start time for the trigger.
.PARAMETER RunLevel
  Run level (default: HIGHEST).
.PARAMETER Force
  Overwrite an existing task with the same name.
#>
function New-MdmScheduledTask {
  [CmdletBinding(SupportsShouldProcess = $true)]
  param(
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$TaskName,

    [Parameter(Mandatory)]
    [string]$TaskRun,

    [string]$Schedule = 'ONCE',

    [string]$StartTime,

    [string]$RunLevel = 'HIGHEST',

    [switch]$Force
  )

  # S16 fix: validate TaskName to prevent path traversal in task folders and special chars.
  # Callers are responsible for validating $TaskRun content beyond these basic guards.
  if ($TaskRun -match '^-') {
    throw "New-MdmScheduledTask: TaskRun must not start with '-' (option injection prevention)."
  }
  if ($TaskRun -match '\.\.') {
    throw "New-MdmScheduledTask: TaskRun must not contain '..' (path traversal prevention)."
  }
  if ($TaskName -notmatch '^[a-zA-Z0-9\-_\\]+$') {
    throw "New-MdmScheduledTask: TaskName contains invalid characters. Only alphanumeric, hyphens, underscores, and backslashes (for task folders) are allowed."
  }

  $taskArgs = @('/Create', '/TN', $TaskName, '/SC', $Schedule, '/TR', $TaskRun, '/RL', $RunLevel)
  if ($Force) { $taskArgs += '/F' }
  if ($StartTime) { $taskArgs += '/ST', $StartTime }

  if (-not $PSCmdlet.ShouldProcess($TaskName, 'Create scheduled task')) {
    return $false
  }
  $result = Invoke-Schtasks -Arguments $taskArgs -ThrowOnError
  return ($result -eq $true)
}

<#
.SYNOPSIS
  Removes a scheduled task via schtasks.exe.
.PARAMETER TaskName
  Name of the task to remove.
#>
function Remove-ScheduledTask {
  [CmdletBinding(SupportsShouldProcess = $true)]
  param(
    [Parameter(Mandatory)]
    [string]$TaskName
  )

  if (-not $PSCmdlet.ShouldProcess($TaskName, 'Remove scheduled task')) {
    return $false
  }
  $result = Invoke-Schtasks -Arguments @('/Delete', '/TN', $TaskName, '/F')
  return ($result -eq $true)
}

<#
.SYNOPSIS
  Exports a registry key to a .reg file via reg.exe.
.PARAMETER KeyPath
  Registry key path to export.
.PARAMETER OutputPath
  File path for the exported .reg file.
#>
function Export-RegistryKey {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]
    [string]$KeyPath,

    [Parameter(Mandatory)]
    [string]$OutputPath
  )

  if ($OutputPath -match '\.\.') {
    throw "Path traversal not allowed in OutputPath"
  }
  if ($KeyPath -match '\\(SAM|SECURITY)\\') {
    throw "Export of sensitive registry hives is blocked"
  }

  $result = Invoke-RegExe -Arguments @('export', $KeyPath, $OutputPath, '/y') -ThrowOnError
  return ($result -eq $true)
}

Export-ModuleMember -Function `
  Test-CommandExists, `
  Ensure-Cmdlet, `
  Ensure-Exe, `
  Invoke-NativeCommand, `
  Invoke-Schtasks, `
  Invoke-Auditpol, `
  Invoke-Wevtutil, `
  Invoke-Wecutil, `
  Invoke-RegExe, `
  Invoke-Git, `
  Get-AuditPolSubcategories, `
  Get-EventLogInfo, `
  Enable-EventLog, `
  Set-EventLogMaxSize, `
  Export-EventLog, `
  New-MdmScheduledTask, `
  Remove-ScheduledTask, `
  Export-RegistryKey
