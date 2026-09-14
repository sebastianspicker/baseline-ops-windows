#requires -version 5.1
<#
.SYNOPSIS
Runs the trusted local capability target.

.DESCRIPTION
Resolves, verifies, invokes, and validates one numbered or named target while
the public runner retains its profile execution lease.
#>

function Initialize-RunLocalEntry {
  param($Options)

  $script:__V2Context = Initialize-V2Context `
    -ScriptName '00-Run-Local.ps1' `
    -BoundParameters $Options.BoundParameters `
    -Values @{
      Mode = $Options.Mode
      ConfigPath = $Options.ConfigPath
      OutputFormat = $Options.OutputFormat
      OutputPath = $Options.OutputPath
      PassThru = $Options.PassThru
      Strict = $Options.Strict
      Quiet = $Options.Quiet
      NoColor = $Options.NoColor
      DeriveRemediate = $false
    }
  if ($script:__V2Context.Quiet) {
    $script:InformationPreference = 'SilentlyContinue'
    $script:VerbosePreference = 'SilentlyContinue'
  }
  $script:NoColor = [bool]$script:__V2Context.NoColor
  $script:ErrorActionPreference = 'Stop'
}

function Get-RunLocalBoundValue {
  param(
    $BoundParameters,
    [string]$Name,
    $Default
  )

  if ($BoundParameters.ContainsKey($Name)) {
    return $BoundParameters[$Name]
  }
  return $Default
}

function New-RunLocalOptions {
  param(
    $BoundParameters,
    [string]$ParameterSetName,
    [string]$RootPath
  )

  return [pscustomobject]@{
    BoundParameters = $BoundParameters
    ParameterSetName = $ParameterSetName
    RootPath = $RootPath
    ScriptNumber = Get-RunLocalBoundValue $BoundParameters 'ScriptNumber' 0
    ScriptName = Get-RunLocalBoundValue $BoundParameters 'ScriptName' $null
    ScriptArgs = @(Get-RunLocalBoundValue $BoundParameters 'ScriptArgs' @())
    RequireSigned = [bool](Get-RunLocalBoundValue $BoundParameters 'RequireSigned' $false)
    ExpectedHash = Get-RunLocalBoundValue $BoundParameters 'ExpectedHash' $null
    HashAlgorithm = Get-RunLocalBoundValue $BoundParameters 'HashAlgorithm' 'SHA256'
    Mode = Get-RunLocalBoundValue $BoundParameters 'Mode' 'Audit'
    ConfigPath = Get-RunLocalBoundValue $BoundParameters 'ConfigPath' $null
    OutputFormat = Get-RunLocalBoundValue $BoundParameters 'OutputFormat' 'Console'
    OutputPath = Get-RunLocalBoundValue $BoundParameters 'OutputPath' $null
    PassThru = [bool](Get-RunLocalBoundValue $BoundParameters 'PassThru' $false)
    Strict = [bool](Get-RunLocalBoundValue $BoundParameters 'Strict' $false)
    Quiet = [bool](Get-RunLocalBoundValue $BoundParameters 'Quiet' $false)
    NoColor = [bool](Get-RunLocalBoundValue $BoundParameters 'NoColor' $false)
  }
}

function New-RunLocalTerminal {
  param(
    [int]$ExitCode,
    [AllowEmptyCollection()][object[]]$Output = @()
  )

  return [pscustomobject]@{
    ExitCode = $ExitCode
    Output = $Output
    IsRunLocalTerminal = $true
  }
}

function New-RunLocalFailureTerminal {
  param(
    [string]$Code,
    [string]$Message,
    [AllowNull()][string]$TargetPath
  )

  $output = @(Write-RunLocalFailureResult -Code $Code -Message $Message -TargetPath $TargetPath)
  return New-RunLocalTerminal -ExitCode (Get-V2ExitCode -Result 'FAIL') -Output $output
}

function Test-RunLocalTerminal {
  param($Value)

  return [bool](
    $null -ne $Value -and
    $Value.PSObject.Properties.Name -contains 'IsRunLocalTerminal' -and
    $Value.IsRunLocalTerminal
  )
}

function Resolve-RunLocalScriptPath {
  param($Options)

  $scriptsRoot = Join-Path $Options.RootPath 'scripts'
  if (-not (Test-Path -LiteralPath $scriptsRoot)) {
    return New-RunLocalFailureTerminal `
      -Code 'RunLocal-ScriptsRootMissing' `
      -Message "Scripts root not found: $scriptsRoot" `
      -TargetPath $scriptsRoot
  }
  if ($Options.ParameterSetName -eq 'ByNumber') {
    return Resolve-RunLocalScriptNumber $scriptsRoot $Options.ScriptNumber
  }
  return Resolve-RunLocalScriptName $scriptsRoot $Options.ScriptName
}

function Resolve-RunLocalScriptNumber {
  param(
    [string]$ScriptsRoot,
    [int]$ScriptNumber
  )

  $prefix = '{0:D2}-' -f $ScriptNumber
  $scriptMatches = @(Get-ChildItem -Path $ScriptsRoot -Filter "$prefix*.ps1" -File)
  if ($scriptMatches.Count -eq 0) {
    return New-RunLocalFailureTerminal `
      -Code 'RunLocal-ScriptNumberNotFound' `
      -Message "No script found for number $prefix in $ScriptsRoot" `
      -TargetPath $ScriptsRoot
  }
  if ($scriptMatches.Count -gt 1) {
    $names = ($scriptMatches | Select-Object -ExpandProperty Name) -join ', '
    return New-RunLocalFailureTerminal `
      -Code 'RunLocal-ScriptNumberAmbiguous' `
      -Message "Multiple scripts match number ${prefix}: $names" `
      -TargetPath $ScriptsRoot
  }
  return Resolve-ValidatedRunLocalPath $scriptMatches[0].FullName $ScriptsRoot
}

function Resolve-RunLocalScriptName {
  param(
    [string]$ScriptsRoot,
    [string]$ScriptName
  )

  if ($ScriptName -match '[/\\]' -or $ScriptName -match '\.\.') {
    return New-RunLocalFailureTerminal `
      -Code 'RunLocal-UnsafeScriptName' `
      -Message 'ScriptName must be a script file name without path components (e.g. 18-Firewall-Baseline.ps1).' `
      -TargetPath $ScriptName
  }
  $baseName = [System.IO.Path]::GetFileName($ScriptName)
  if ([string]::IsNullOrWhiteSpace($baseName)) {
    return New-RunLocalFailureTerminal `
      -Code 'RunLocal-InvalidScriptName' `
      -Message 'ScriptName must be a script file name (e.g. 18-Firewall-Baseline.ps1).' `
      -TargetPath $ScriptName
  }
  if ([System.IO.Path]::GetExtension($baseName) -ne '.ps1') {
    return New-RunLocalFailureTerminal `
      -Code 'RunLocal-InvalidScriptExtension' `
      -Message 'ScriptName must reference a .ps1 file.' `
      -TargetPath $ScriptName
  }
  $path = Join-Path $ScriptsRoot $baseName
  if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
    return New-RunLocalFailureTerminal `
      -Code 'RunLocal-ScriptNotFound' `
      -Message "Script not found: $path" `
      -TargetPath $path
  }
  return Resolve-ValidatedRunLocalPath $path $ScriptsRoot
}

function Resolve-ValidatedRunLocalPath {
  param(
    [string]$Path,
    [string]$ScriptsRoot
  )

  if (Test-PathIsSymlink -Path $Path) {
    return New-RunLocalFailureTerminal `
      -Code 'RunLocal-ReparsePointRejected' `
      -Message "Refusing to execute reparse-point script path: $Path" `
      -TargetPath $Path
  }
  if (-not (Test-ResolvedPathUnderScriptsRoot -Path $Path -ScriptsRootPath $ScriptsRoot)) {
    return New-RunLocalFailureTerminal `
      -Code 'RunLocal-PathOutsideRoot' `
      -Message 'Resolved script path is outside scripts root or invalid.' `
      -TargetPath $Path
  }
  return (Resolve-Path -LiteralPath $Path).Path
}

function Test-RunLocalRecursion {
  param([string]$Path)

  if (-not [string]::Equals(
      (Split-Path -Leaf $Path),
      '00-Run-Local.ps1',
      [System.StringComparison]::OrdinalIgnoreCase)) {
    return $null
  }
  return New-RunLocalFailureTerminal `
    -Code 'RunLocal-ControlPlaneRecursion' `
    -Message '00-Run-Local.ps1 cannot execute itself.' `
    -TargetPath $Path
}

function Test-RunLocalTargetIntegrity {
  param(
    $Options,
    [string]$Path,
    $Stream
  )

  if ($Options.RequireSigned) {
    $signature = Get-AuthenticodeSignature -FilePath $Path
    if ($signature.Status -ne 'Valid') {
      return New-RunLocalFailureTerminal `
        -Code 'RunLocal-SignatureInvalid' `
        -Message "Script signature verification failed for $Path : $($signature.Status)" `
        -TargetPath $Path
    }
    Write-UiLine "Signature verified: $($signature.SignerCertificate.Subject)" -Style 'Success'
  }
  if (-not [string]::IsNullOrWhiteSpace($Options.ExpectedHash)) {
    return Test-RunLocalTargetHash $Options $Path $Stream
  }
  return $null
}

function Test-RunLocalTargetHash {
  param(
    $Options,
    [string]$Path,
    $Stream
  )

  $allowedAlgorithms = @('SHA256', 'SHA384', 'SHA512')
  $algorithm = $Options.HashAlgorithm
  $expected = $Options.ExpectedHash.Trim()
  if ($expected -match '^(\w+):([A-Fa-f0-9]+)$') {
    $algorithm = $Matches[1].ToUpperInvariant()
    $expected = $Matches[2]
  }
  if ($allowedAlgorithms -notcontains $algorithm) {
    return New-RunLocalFailureTerminal `
      -Code 'RunLocal-HashAlgorithmRejected' `
      -Message "Unsupported hash algorithm '$algorithm'. Allowed algorithms: $($allowedAlgorithms -join ', ')." `
      -TargetPath $Path
  }
  $Stream.Position = 0
  $actual = (Get-FileHash -InputStream $Stream -Algorithm $algorithm).Hash
  if (-not [string]::Equals($actual, $expected, [System.StringComparison]::OrdinalIgnoreCase)) {
    return New-RunLocalFailureTerminal `
      -Code 'RunLocal-HashMismatch' `
      -Message "Hash mismatch for $Path. Expected ($algorithm): $expected, Actual: $actual" `
      -TargetPath $Path
  }
  Write-UiLine "Hash verified ($algorithm)" -Style 'Success'
  return $null
}

function Invoke-RunLocalTarget {
  param(
    $Options,
    [string]$Path
  )

  if ($WhatIfPreference) {
    return New-RunLocalSkipTerminal $Options $Path
  }
  try {
    $output = @(Invoke-TargetScript `
      -Path $Path `
      -Arguments $Options.ScriptArgs `
      -CaptureV2Result:$Options.PassThru `
      -RunnerBoundParameters $Options.BoundParameters)
    $exitCode = if ($null -eq $LASTEXITCODE) { 0 } else { [int]$LASTEXITCODE }
  } catch {
    return New-RunLocalFailureTerminal `
      -Code 'RunLocal-TargetInvocationFailed' `
      -Message "Target script invocation failed: $($_.Exception.Message)" `
      -TargetPath $Path
  }
  if ($Options.PassThru) {
    return Complete-RunLocalV2Target $Options $Path $output $exitCode
  }
  return New-RunLocalTerminal -ExitCode $exitCode
}

function New-RunLocalSkipTerminal {
  param(
    $Options,
    [string]$Path
  )

  Write-UiLine ("[SKIP] {0} (WhatIf/Confirm)" -f (Split-Path -Leaf $Path)) -Style 'Muted'
  $token = if ($Options.Strict) { 'FAIL' } else { 'WARN' }
  $result = Get-V2ResultObject `
    -ScriptName '00-Run-Local.ps1' `
    -Mode $Options.Mode `
    -Result $token `
    -Findings @([pscustomobject]@{
      Code = 'RunLocal-ExecutionSkipped'
      Severity = 'Info'
      Message = 'Target execution was skipped by WhatIf or confirmation.'
    }) `
    -Summary ([pscustomobject]@{ Target = $Path; Executed = $false }) `
    -Metadata @{}
  $output = @(Write-ResultObject `
    -ResultObject $result `
    -OutputFormat $Options.OutputFormat `
    -OutputPath $Options.OutputPath)
  if ($Options.PassThru) {
    $output += $result
  }
  return New-RunLocalTerminal -ExitCode (Get-V2ExitCode -Result $result.Result) -Output $output
}

function Complete-RunLocalV2Target {
  param(
    $Options,
    [string]$Path,
    [object[]]$Output,
    [int]$ExitCode
  )

  $results = @($Output | Where-Object { Test-RunLocalV2ResultObject -InputObject $_ })
  if ($results.Count -eq 1 -and $Output.Count -eq 1) {
    return Complete-SingleRunLocalV2Result $Options $results[0] $ExitCode
  }
  $failure = Get-RunLocalOutputFailure $results $Output
  Write-Warning $failure.Message
  return New-RunLocalFailureTerminal `
    -Code $failure.Code `
    -Message $failure.Message `
    -TargetPath $Path
}

function Complete-SingleRunLocalV2Result {
  param(
    $Options,
    $Result,
    [int]$ExitCode
  )

  $expected = switch ([string]$Result.Result) {
    'OK' { 0 }
    'WARN' { 2 }
    'FAIL' { 1 }
  }
  if ($ExitCode -ne $expected) {
    Set-RunLocalExitMismatch $Result $ExitCode $expected
  }
  Set-RunLocalStrictResult $Options $Result
  return New-RunLocalTerminal `
    -ExitCode (Get-V2ExitCode -Result ([string]$Result.Result)) `
    -Output @($Result)
}

function Set-RunLocalStrictResult {
  param($Options, $Result)

  if (-not $Options.Strict -or $Result.Result -ne 'WARN') {
    return
  }
  if ($Result.PSObject.Properties.Name -notcontains 'RunnerDeclaredResult') {
    $Result | Add-Member -NotePropertyName 'RunnerDeclaredResult' -NotePropertyValue 'WARN' -Force
  }
  $Result | Add-Member -NotePropertyName 'RunnerStrictPromotion' -NotePropertyValue $true -Force
  $Result.Result = 'FAIL'
}

function Set-RunLocalExitMismatch {
  param(
    $Result,
    [int]$ExitCode,
    [int]$Expected
  )

  $declared = [string]$Result.Result
  $Result | Add-Member -NotePropertyName 'RunnerExitMismatch' -NotePropertyValue $true -Force
  $Result | Add-Member -NotePropertyName 'RunnerDeclaredResult' -NotePropertyValue $declared -Force
  $Result | Add-Member -NotePropertyName 'RunnerExpectedExitCode' -NotePropertyValue $Expected -Force
  $Result | Add-Member -NotePropertyName 'RunnerActualExitCode' -NotePropertyValue $ExitCode -Force
  Write-Warning "Target V2 result '$($Result.Result)' does not match process exit code $ExitCode. Expected $Expected."
  $processResult = switch ($ExitCode) {
    0 { 'OK' }
    2 { 'WARN' }
    default { 'FAIL' }
  }
  $rank = @{ OK = 0; WARN = 1; FAIL = 2 }
  if ($rank[$processResult] -le $rank[[string]$Result.Result]) {
    return
  }
  $finding = [pscustomobject]@{
    Code = 'RunLocal-ExitContractMismatch'
    Severity = 'High'
    Message = "Target declared '$declared' but exited with code $ExitCode (expected $Expected)."
  }
  $Result.Findings = @($Result.Findings) + @($finding)
  $Result.Result = $processResult
}

function Get-RunLocalOutputFailure {
  param($Results, $Output)

  if ($Results.Count -gt 1) {
    return [pscustomobject]@{
      Code = 'RunLocal-MultipleV2Results'
      Message = "Target script emitted $($Results.Count) V2 result objects; exactly one is required."
    }
  }
  if ($Results.Count -eq 1 -and $Output.Count -gt 1) {
    return [pscustomobject]@{
      Code = 'RunLocal-ExtraneousOutput'
      Message = "Target script emitted one V2 result plus $($Output.Count - 1) additional success-stream item(s); exactly one total object is required."
    }
  }
  if ($Output.Count -gt 0) {
    return [pscustomobject]@{
      Code = 'RunLocal-MissingV2Result'
      Message = 'Target script emitted output but no valid V2 result.'
    }
  }
  return [pscustomobject]@{
    Code = 'RunLocal-MissingV2Result'
    Message = 'Target script did not emit a V2 result.'
  }
}

function Get-RunLocalLockedPathFailure {
  param(
    [string]$Path,
    [string]$ScriptsRoot
  )

  if (Test-PathOrAncestorIsReparsePoint -Path $Path -ScriptsRootPath $ScriptsRoot) {
    return New-RunLocalFailureTerminal `
      -Code 'RunLocal-ReparsePointRejected' `
      -Message "Refusing to execute a script beneath a reparse-point path: $Path" `
      -TargetPath $Path
  }
  return $null
}

function Invoke-RunLocalLockedTarget {
  param(
    $Options,
    [string]$Path,
    $Bootstrap
  )

  $scriptsRoot = Join-Path $Options.RootPath 'scripts'
  $maxScriptBytes = 10MB
  $stream = $null
  try {
    $terminal = Get-RunLocalLockedPathFailure $Path $scriptsRoot
    if (Test-RunLocalTerminal $terminal) {
      return $terminal
    }
    $stream = New-Object System.IO.FileStream(
      $Path,
      [System.IO.FileMode]::Open,
      [System.IO.FileAccess]::Read,
      [System.IO.FileShare]::Read)
    if ($stream.Length -gt $maxScriptBytes) {
      return New-RunLocalFailureTerminal `
        -Code 'RunLocal-ScriptTooLarge' `
        -Message "Refusing to execute script larger than $maxScriptBytes bytes: $Path" `
        -TargetPath $Path
    }
    $terminal = Get-RunLocalLockedPathFailure $Path $scriptsRoot
    if (Test-RunLocalTerminal $terminal) {
      return $terminal
    }
    if ($Bootstrap.IsElevated) {
      Assert-RunLocalTrustedWindowsAcl -Path $Path
    }
    $terminal = Test-RunLocalTargetIntegrity $Options $Path $stream
    if (Test-RunLocalTerminal $terminal) {
      return $terminal
    }
    return Invoke-RunLocalTarget $Options $Path
  } finally {
    if ($null -ne $stream) {
      $stream.Dispose()
    }
  }
}

function Invoke-RunLocalCapability {
  param($Options, $Bootstrap)

  Initialize-RunLocalEntry $Options
  $path = Resolve-RunLocalScriptPath $Options
  if (Test-RunLocalTerminal $path) {
    return $path
  }
  $terminal = Test-RunLocalRecursion $path
  if (Test-RunLocalTerminal $terminal) {
    return $terminal
  }
  return Invoke-RunLocalLockedTarget $Options $path $Bootstrap
}
