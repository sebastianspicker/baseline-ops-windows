<#
.SYNOPSIS
Script execution and process invocation utilities.

.DESCRIPTION
Provides helpers for argument tokenization and timed script execution.
#>

Set-StrictMode -Version Latest

<#
.SYNOPSIS
Converts one argument token to its supported scalar value.
.DESCRIPTION
Recognizes literal PowerShell boolean tokens while leaving other argument text
unchanged for later parameter binding.
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
  Parses a string array of CLI-style arguments into named and positional tokens.
.PARAMETER Arguments
  Array of argument strings to tokenize.
#>
function Convert-ArgumentTokens {
  [CmdletBinding()]
  param(
    [string[]]$Arguments = @()
  )

  # Windows PowerShell 5.1 binds an explicitly supplied empty string array as
  # $null. Normalize it before using Count or indexing so callers can pass an
  # optional token vector without special-casing the legacy binder.
  $argumentTokens = @($Arguments | Where-Object { $null -ne $_ })
  $namedArgs = @{}
  $positionalArgs = New-Object System.Collections.ArrayList
  $optionPattern = '^-{1,2}[A-Za-z][A-Za-z0-9-]*$'
  $optionWithInlineValuePattern = '^-{1,2}([A-Za-z][A-Za-z0-9-]*):(.*)$'

  for ($i = 0; $i -lt $argumentTokens.Count; $i++) {
    $token = [string]$argumentTokens[$i]

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
      if ($i + 1 -lt $argumentTokens.Count) {
        $next = [string]$argumentTokens[$i + 1]
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
  $previousExitVariable = Get-Variable -Name LASTEXITCODE -Scope Global -ErrorAction SilentlyContinue
  $previousExitCode = if ($null -ne $previousExitVariable) { $previousExitVariable.Value } else { $null }
  try {
    & $ScriptPath @Arguments
    $scriptSucceeded = $?
    $currentExitVariable = Get-Variable -Name LASTEXITCODE -Scope Global -ErrorAction SilentlyContinue
    $currentExitCode = if ($null -ne $currentExitVariable) { $currentExitVariable.Value } else { $null }
    if ($null -ne $currentExitCode -and $currentExitCode -ne 0 -and ((-not $scriptSucceeded) -or $currentExitCode -ne $previousExitCode)) {
      $exitCode = [int]$currentExitCode
    } else {
      $exitCode = 0
    }
  } catch {
    $currentExitVariable = Get-Variable -Name LASTEXITCODE -Scope Global -ErrorAction SilentlyContinue
    $currentExitCode = if ($null -ne $currentExitVariable) { $currentExitVariable.Value } else { $null }
    if ($null -ne $currentExitCode -and $currentExitCode -ne 0 -and $currentExitCode -ne $previousExitCode) {
      $exitCode = [int]$currentExitCode
    } else {
      $exitCode = 1
    }
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
  Invoke-ScriptWithTiming
