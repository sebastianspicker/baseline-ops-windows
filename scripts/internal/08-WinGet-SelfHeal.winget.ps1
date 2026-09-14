<#
.SYNOPSIS
WinGet self-heal winget helpers.

.DESCRIPTION
Contains capability-private WinGet self-heal winget behavior.
#>

function Resolve-WingetPath {
  [CmdletBinding()]
  param()
  return (Resolve-TrustedWingetPath)
}

function Invoke-Winget {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$WingetPath,
    [Parameter(Mandatory)][string[]]$WingetArgs,
    [ValidateRange(1, 86400)][int]$TimeoutSec = 120
  )
  $native = Invoke-NativeCommand -Command $WingetPath -Arguments $WingetArgs -CaptureOutput -Quiet -TimeoutSeconds $TimeoutSec -MaxOutputBytes 1048576
  $metadataArgs = @($WingetArgs | ForEach-Object { Protect-WingetProcessMetadata -Value $_ })
  if ($null -eq $native) {
    return @{ ExitCode = 1; StdOut = ''; StdErr = 'winget process could not be started.'; Args = $metadataArgs; TimedOut = $false; OutputTruncated = $false; StderrTruncated = $false; Success = $false }
  }
  return ConvertFrom-WingetNativeResult -NativeResult $native -MetadataArgs $metadataArgs -TimeoutSec $TimeoutSec
}

function ConvertFrom-WingetNativeResult {
  param($NativeResult, [string[]]$MetadataArgs, [int]$TimeoutSec)
  $timedOut = [bool]$NativeResult.TimedOut
  $truncated = [bool]$NativeResult.OutputTruncated -or [bool]$NativeResult.StderrTruncated
  $exitCode = Get-WingetEffectiveExitCode -NativeResult $NativeResult
  $stdout = Protect-WingetProcessMetadata -Value $NativeResult.Stdout
  $stderr = Protect-WingetProcessMetadata -Value $NativeResult.Stderr
  if ($timedOut) { $stderr = (($stderr, "Timeout after $TimeoutSec s" | Where-Object { $_ }) -join "`n") }
  if ($truncated) { $stderr = (($stderr, 'Output truncated at 1048576 bytes; result is unusable.' | Where-Object { $_ }) -join "`n") }
  return @{ ExitCode = $exitCode; StdOut = $stdout; StdErr = $stderr; Args = $MetadataArgs; TimedOut = $timedOut; OutputTruncated = [bool]$NativeResult.OutputTruncated; StderrTruncated = [bool]$NativeResult.StderrTruncated; Success = ([bool]$NativeResult.Success -and -not $timedOut -and -not $truncated) }
}

function Get-WingetEffectiveExitCode {
  param($NativeResult)
  if ($NativeResult.TimedOut) { return 408 }
  if ($NativeResult.OutputTruncated -or $NativeResult.StderrTruncated) { return 413 }
  return [int]$NativeResult.ExitCode
}

function Add-ConservativeNativeArgumentCharacter {
  param([hashtable]$ParseState, [char]$Character, [int]$Index, [string]$ArgumentString)
  if ($Character -eq '"') {
    if ($Index -gt 0 -and $ArgumentString[$Index - 1] -eq '\') { throw 'Installer arguments must not use escaped quotes.' }
    $ParseState.InQuotes = -not $ParseState.InQuotes
    $ParseState.Started = $true
    return
  }
  if ([char]::IsWhiteSpace($Character) -and -not $ParseState.InQuotes) {
    if ($ParseState.Started) {
      [void]$ParseState.Arguments.Add($ParseState.Token.ToString())
      $ParseState.Token.Clear() | Out-Null
      $ParseState.Started = $false
    }
    return
  }
  [void]$ParseState.Token.Append($Character)
  $ParseState.Started = $true
}

function ConvertTo-ConservativeNativeArguments {
  [CmdletBinding()]
  param([AllowEmptyString()][string]$ArgumentString)
  if ([string]::IsNullOrWhiteSpace($ArgumentString)) { return @() }
  if ($ArgumentString -match '[\x00-\x1F\x7F]') { throw 'Installer arguments contain control characters.' }
  $parseState = @{
    Arguments = New-Object System.Collections.Generic.List[string]
    Token = New-Object System.Text.StringBuilder
    InQuotes = $false
    Started = $false
  }
  for ($index = 0; $index -lt $ArgumentString.Length; $index++) {
    Add-ConservativeNativeArgumentCharacter -ParseState $parseState -Character $ArgumentString[$index] `
      -Index $index -ArgumentString $ArgumentString
  }
  if ($parseState.InQuotes) { throw 'Installer arguments contain an unclosed quote.' }
  if ($parseState.Started) { [void]$parseState.Arguments.Add($parseState.Token.ToString()) }
  return $parseState.Arguments.ToArray()
}

function Convert-ExitCodeToHex32 {
  [CmdletBinding()]
  param([Parameter(Mandatory)][int]$ExitCode)
  $bytes = [System.BitConverter]::GetBytes([int]$ExitCode)
  $u = [System.BitConverter]::ToUInt32($bytes, 0)
  return ("0x{0:X8}" -f $u)
}

function Get-WingetErrorText {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$WingetPath,
    [Parameter(Mandatory)][int]$ExitCode
  )
  try {
    $res = Invoke-Winget -WingetPath $WingetPath -WingetArgs @('error','--input',"$ExitCode") -TimeoutSec 30
    $t = ($res.StdOut + "`n" + $res.StdErr).Trim()
    if ($t) { return $t }
  } catch {
    Write-Verbose ("winget error diagnostic lookup failed: {0}" -f $_.Exception.Message)
  }
  return $null
}

function Parse-Version {
  [CmdletBinding()]
  param([string]$s)
  if ([string]::IsNullOrWhiteSpace($s)) { return $null }
  $m = [regex]::Match($s, 'v?(\d+)\.(\d+)\.(\d+)')
  if (-not $m.Success) { $m = [regex]::Match($s, 'v?(\d+)\.(\d+)') }
  if (-not $m.Success) { return $null }
  $maj = [int]$m.Groups[1].Value
  $min = [int]$m.Groups[2].Value
  $pat = 0
  if ($m.Groups.Count -ge 4 -and $m.Groups[3].Value) { $pat = [int]$m.Groups[3].Value }
  return [pscustomobject]@{ Major=$maj; Minor=$min; Patch=$pat; Raw=$s.Trim() }
}

function Is-Version-AtLeast {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]$v,
    [Parameter(Mandatory)][int]$maj,
    [Parameter(Mandatory)][int]$min,
    [int]$pat = 0
  )
  if (-not $v) { return $false }
  if ($v.Major -gt $maj) { return $true }
  if ($v.Major -lt $maj) { return $false }
  if ($v.Minor -gt $min) { return $true }
  if ($v.Minor -lt $min) { return $false }
  return ($v.Patch -ge $pat)
}

function Test-WingetSupportsAcceptSourceAgreements {
  [CmdletBinding()]
  param([Parameter(Mandatory)][string]$WingetPath)
  try {
    $h = Invoke-Winget -WingetPath $WingetPath -WingetArgs @('source','update','--help') -TimeoutSec 30
    $t = ($h.StdOut + "`n" + $h.StdErr)
    if ($t -match '--accept-source-agreements') { return $true }
  } catch {
    Write-Verbose ("winget source update help check failed: {0}" -f $_.Exception.Message)
  }
  return $false
}

function Invoke-WingetSourceUpdate {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$WingetPath,
    [string]$SourceName,
    [bool]$SupportAcceptSourceAgreements
  )
  # Use "-n <name>" for compatibility with documented syntax.
  $wingetArgs = @('source','update')
  if ($SourceName) { $wingetArgs += @('-n', $SourceName) }
  if ($SupportAcceptSourceAgreements) { $wingetArgs += '--accept-source-agreements' }
  return Invoke-Winget -WingetPath $WingetPath -WingetArgs $wingetArgs
}

function Test-WingetSourceOutputContainsName {
  [CmdletBinding()]
  [OutputType([bool])]
  param(
    [AllowNull()][AllowEmptyString()][string]$Text,
    [Parameter(Mandatory)][string]$Name
  )

  foreach ($line in @($Text -split '\r?\n')) {
    $propertyMatch = [regex]::Match($line, '^\s*Name\s*:\s*(?<Name>.+?)\s*$', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
    if ($propertyMatch.Success -and $propertyMatch.Groups['Name'].Value.Equals($Name, [System.StringComparison]::OrdinalIgnoreCase)) {
      return $true
    }

    $tableMatch = [regex]::Match($line, '^\s*(?<Name>\S+)\s+https://\S+', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
    if ($tableMatch.Success -and $tableMatch.Groups['Name'].Value.Equals($Name, [System.StringComparison]::OrdinalIgnoreCase)) {
      return $true
    }
  }

  return $false
}

function Test-WingetSourcePresent {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$WingetPath,
    [Parameter(Mandatory)][string]$Name
  )
  $res = Invoke-Winget -WingetPath $WingetPath -WingetArgs @('source','list','-n',$Name)
  if ($res.ExitCode -eq 0) {
    if (Test-WingetSourceOutputContainsName -Text $res.StdOut -Name $Name) { return $true, "Found via 'source list -n'" }
  }
  $res2 = Invoke-Winget -WingetPath $WingetPath -WingetArgs @('source','list')
  if ($res2.ExitCode -eq 0 -and (Test-WingetSourceOutputContainsName -Text $res2.StdOut -Name $Name)) {
    return $true, "Found via 'source list'"
  }
  $err = (($res.StdErr + "`n" + $res.StdOut).Trim())
  if (-not $err) { $err = "ExitCode=$($res.ExitCode)" }
  return $false, $err
}

function Ensure-PrivateSource {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$WingetPath,
    [string]$Name,
    [string]$Url,
    [string]$Type,
    [switch]$DoIt
  )
  if ([string]::IsNullOrWhiteSpace($Name)) { return $false, "No private source name configured" }
  $present = $false; $detail = $null
  $present, $detail = Test-WingetSourcePresent -WingetPath $WingetPath -Name $Name
  if ($present) {
    return $true, 'Present'
  }
  if (-not $DoIt) { return $false, "Missing (no remediation). Detail: $detail" }
  if (-not (Test-WingetPrivateSourceDefinition -Url $Url -Type $Type)) {
    return $false, 'Private source must use a supported type and an absolute HTTPS endpoint path without credentials, query, or fragment components, or local, loopback, or link-local hosts. Configure authentication out of band.'
  }
  $add = Invoke-Winget -WingetPath $WingetPath -WingetArgs @(
    'source','add',
    '-n', $Name,
    '-t', $Type,
    '-a', $Url,
    '--accept-source-agreements'
  )
  if ($add.ExitCode -eq 0) { return $true, "Added" }
  $txt = (($add.StdErr + ' ' + $add.StdOut).Trim())
  if (-not $txt) { $txt = "ExitCode=$($add.ExitCode)" }
  return $false, "Add failed: $txt"
}
