<#
.SYNOPSIS
Script execution and process invocation utilities.

.DESCRIPTION
Provides helpers for argument tokenization.
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
  Adds a named argument value while preserving repeated-value behavior.
#>
function Add-NamedArgumentValue {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][hashtable]$NamedArguments,
    [Parameter(Mandatory)][string]$Name,
    [AllowNull()][object]$Value
  )

  if ($NamedArguments.ContainsKey($Name)) {
    $NamedArguments[$Name] = @(@($NamedArguments[$Name]) + $Value)
    return
  }
  $NamedArguments[$Name] = $Value
}

<#
.SYNOPSIS
  Handles one inline named argument token.
#>
function Add-InlineArgumentToken {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][hashtable]$NamedArguments,
    [Parameter(Mandatory)][string]$Token,
    [Parameter(Mandatory)][string]$Pattern
  )

  $match = [regex]::Match($Token, $Pattern)
  if (-not $match.Success) { return $false }
  Add-NamedArgumentValue -NamedArguments $NamedArguments -Name $match.Groups[1].Value `
    -Value (Convert-TokenValue -Value $match.Groups[2].Value)
  return $true
}

<#
.SYNOPSIS
  Handles one named argument token and its optional following value.
#>
function Add-OptionArgumentToken {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][hashtable]$NamedArguments,
    [Parameter(Mandatory)][string[]]$ArgumentTokens,
    [Parameter(Mandatory)][ref]$Index,
    [Parameter(Mandatory)][string]$OptionPattern,
    [Parameter(Mandatory)][string]$InlineValuePattern
  )

  $token = [string]$ArgumentTokens[$Index.Value]
  if ($token -notmatch $OptionPattern) { return $false }
  $name = $token.TrimStart('-')
  $next = if ($Index.Value + 1 -lt $ArgumentTokens.Count) { [string]$ArgumentTokens[$Index.Value + 1] } else { $null }
  if ($null -eq $next -or $next -match $OptionPattern -or $next -match $InlineValuePattern) {
    Add-NamedArgumentValue -NamedArguments $NamedArguments -Name $name -Value $true
    return $true
  }
  Add-NamedArgumentValue -NamedArguments $NamedArguments -Name $name -Value (Convert-TokenValue -Value $next)
  $Index.Value++
  return $true
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
    if (Add-InlineArgumentToken -NamedArguments $namedArgs -Token $token -Pattern $optionWithInlineValuePattern) { continue }
    if (Add-OptionArgumentToken -NamedArguments $namedArgs -ArgumentTokens $argumentTokens -Index ([ref]$i `
        ) -OptionPattern $optionPattern -InlineValuePattern $optionWithInlineValuePattern) { continue }
    [void]$positionalArgs.Add($token)
  }

  return [pscustomobject]@{
    Named = $namedArgs
    Positional = @($positionalArgs)
  }
}

Export-ModuleMember -Function Convert-ArgumentTokens
