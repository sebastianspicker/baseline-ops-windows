#requires -version 5.1
<#
.SYNOPSIS
Execute a v2 orchestration profile.

.DESCRIPTION
Runs profile steps with dependency checks and optional integrity verification
through 00-Run-Local.ps1.
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
  [Parameter(Mandatory)]
  [string]$ProfilePath,

  [ValidateSet('Audit','Remediate')]
  [string]$Mode,

  [string]$RootPath = 'C:\install\mdm\ps1',

  [ValidateSet('Console','Json','Csv','None')]
  [string]$OutputFormat = 'Console',

  [string]$OutputPath,

  [switch]$PassThru,

  [switch]$Strict,

  [switch]$RequireSigned

,
  [string]$ConfigPath,
  [switch]$Quiet,
  [switch]$NoColor
)

. (Join-Path $PSScriptRoot '_lib/Bootstrap.ps1')
Import-Module (Join-Path $script:LibPath 'Output.psm1') -Force
Import-Module (Join-Path $script:LibPath 'Common.psm1') -Force
Import-Module (Join-Path $script:LibPath 'Validation.psm1') -Force
Import-Module (Join-Path $script:LibPath 'Serialization.psm1') -Force

Set-StrictMode -Version Latest
# v2-init
$null = $Mode, $ConfigPath, $OutputFormat, $OutputPath, $PassThru, $Strict, $Quiet, $NoColor
$script:__V2Context = @{
  Mode = $Mode
  ConfigPath = $ConfigPath
  OutputFormat = $OutputFormat
  OutputPath = $OutputPath
  PassThru = [bool]$PassThru
  Strict = [bool]$Strict
  Quiet = [bool]$Quiet
  NoColor = [bool]$NoColor
}
if ($Quiet) {
  $InformationPreference = 'SilentlyContinue'
  $VerbosePreference = 'SilentlyContinue'
}
if ($NoColor) {
  $script:NoColor = $true
}
$ErrorActionPreference = 'Stop'

# Has-Property moved to lib/Common.psm1

function ConvertTo-HashtableSafe {
  [CmdletBinding()]
  param([object]$InputObject)

  if ($null -eq $InputObject) { return @{} }
  if ($InputObject -is [hashtable]) { return $InputObject }

  $hash = @{}
  foreach ($p in $InputObject.PSObject.Properties) {
    $hash[$p.Name] = $p.Value
  }
  return $hash
}

function Test-StepArgHasToken {
  [CmdletBinding()]
  param(
    [string[]]$ArgsList,
    [Parameter(Mandatory)][string]$Name
  )

  if (-not $ArgsList) { return $false }
  $pattern = '^-{0}($|:)' -f [regex]::Escape($Name)
  foreach ($arg in $ArgsList) {
    if ([string]$arg -imatch $pattern) { return $true }
  }
  return $false
}

$validatorPath = Join-Path $PSScriptRoot '00-Validate-Profile.ps1'
$runLocalPath = Join-Path $PSScriptRoot '00-Run-Local.ps1'

if (-not (Test-Path -LiteralPath $validatorPath -PathType Leaf)) {
  throw "Missing validator script: $validatorPath"
}
if (-not (Test-Path -LiteralPath $runLocalPath -PathType Leaf)) {
  throw "Missing Run-Local script: $runLocalPath"
}

if ($RootPath -eq 'C:\install\mdm\ps1') {
  $repoRootCandidate = Split-Path -Parent $PSScriptRoot
  if (Test-Path -LiteralPath (Join-Path $repoRootCandidate 'scripts') -PathType Container) {
    $RootPath = $repoRootCandidate
  }
}

$validation = & $validatorPath -ProfilePath $ProfilePath -OutputFormat None -PassThru
if ($LASTEXITCODE -ne 0) {
  if ($LASTEXITCODE -eq 2) {
    Write-Warning "Profile validation produced warnings: $ProfilePath"
    if ($Strict) {
      throw "Profile validation produced warnings (strict mode): $ProfilePath"
    }
  } else {
    throw "Profile validation failed: $ProfilePath"
  }
}

$profileDoc = Get-Content -LiteralPath $ProfilePath -Raw -Encoding UTF8 | ConvertFrom-Json -ErrorAction Stop
$defaults = if (Has-Property -Object $profileDoc -Name 'Defaults') { $profileDoc.Defaults } else { [pscustomobject]@{} }
$integrity = if (Has-Property -Object $profileDoc -Name 'Integrity') { $profileDoc.Integrity } else { [pscustomobject]@{} }
$expectedHashes = if (Has-Property -Object $integrity -Name 'ExpectedHashes') { ConvertTo-HashtableSafe -InputObject $integrity.ExpectedHashes } else { @{} }

$globalMode = if ($PSBoundParameters.ContainsKey('Mode')) { $Mode } elseif (Has-Property -Object $defaults -Name 'Mode') { [string]$defaults.Mode } else { 'Audit' }
$profileStrict = [bool]($Strict -or ((Has-Property -Object $defaults -Name 'Strict') -and $defaults.Strict))
$profileRequireSigned = [bool]($RequireSigned -or ((Has-Property -Object $integrity -Name 'RequireSigned') -and $integrity.RequireSigned))

$results = New-Object System.Collections.ArrayList
$stepStatus = @{}
$pending = New-Object System.Collections.ArrayList
foreach ($step in @($profileDoc.Steps)) { [void]$pending.Add($step) }

Write-Section -Title ("Run Profile: {0}" -f $profileDoc.ProfileName)
Write-KeyValue -Key 'ProfilePath' -Value (Resolve-Path -LiteralPath $ProfilePath).Path
Write-KeyValue -Key 'Mode' -Value $globalMode
Write-KeyValue -Key 'Strict' -Value $profileStrict
Write-KeyValue -Key 'RequireSigned' -Value $profileRequireSigned

while ($pending.Count -gt 0) {
  $progress = $false

  for ($i = 0; $i -lt $pending.Count; $i++) {
    $step = $pending[$i]
    $scriptName = [string]$step.Script
    $dependsOn = if (Has-Property -Object $step -Name 'DependsOn' -and $null -ne $step.DependsOn) { @($step.DependsOn) } else { @() }

    $depsReady = $true
    $depFailed = $false
    foreach ($dep in $dependsOn) {
      if (-not $stepStatus.ContainsKey([string]$dep)) {
        $depsReady = $false
        break
      }
      if ($stepStatus[[string]$dep] -notin @('Success', 'Partial')) {
        $depFailed = $true
      }
    }

    if (-not $depsReady) { continue }

    [void]$pending.RemoveAt($i)
    $progress = $true

    if ($depFailed) {
      $stepStatus[$scriptName] = 'Skipped'
      [void]$results.Add([pscustomobject]@{
          ScriptName = $scriptName
          Status     = 'Skipped'
          ExitCode   = 2
          DurationMs = 0
          Message    = 'Skipped due to failed dependency.'
        })
      Write-UiLine -Text ("[SKIP] {0} (dependency failure)" -f $scriptName) -Style Muted
      break
    }

    $stepArgs = @()
    if (Has-Property -Object $step -Name 'Args' -and $null -ne $step.Args) {
      $stepArgs += @($step.Args)
    }

    # Validate that profile step args don't attempt to override security-sensitive parameters
    $blockedOverrides = @('-RootPath', '-ConfigPath', '-ExpectedHash')
    foreach ($argVal in @($stepArgs)) {
      foreach ($blocked in $blockedOverrides) {
        if ([string]$argVal -ieq $blocked -or [string]$argVal -imatch "^$([regex]::Escape($blocked)):") {
          Write-Warning "Profile step '$scriptName' contains blocked argument override '$argVal'. Removing it."
          $stepArgs = @($stepArgs | Where-Object { [string]$_ -ine $argVal })
        }
      }
    }

    # Legacy profile compatibility: normalize removed v1 token "-Remediate" to v2 mode.
    if (@($stepArgs | Where-Object { [string]$_ -ieq '-Remediate' }).Count -gt 0) {
      $stepArgs = @($stepArgs | Where-Object { [string]$_ -ine '-Remediate' })
      if (-not (Test-StepArgHasToken -ArgsList $stepArgs -Name 'Mode')) {
        $stepArgs += @('-Mode','Remediate')
      }
    }

    if (-not (Test-StepArgHasToken -ArgsList $stepArgs -Name 'Mode')) {
      $stepArgs += @('-Mode', $globalMode)
    }
    if ($profileStrict -and -not (Test-StepArgHasToken -ArgsList $stepArgs -Name 'Strict')) {
      $stepArgs += '-Strict'
    }
    if ($PassThru -and -not (Test-StepArgHasToken -ArgsList $stepArgs -Name 'PassThru')) {
      $stepArgs += '-PassThru'
    }

    $runParams = @{
      ScriptName = $scriptName
      ScriptArgs = $stepArgs
      RootPath   = $RootPath
    }

    if ($profileRequireSigned) {
      $runParams.RequireSigned = $true
    }

    if ($expectedHashes.ContainsKey($scriptName)) {
      $runParams.ExpectedHash = [string]$expectedHashes[$scriptName]
    }
    if ($WhatIfPreference) {
      $runParams.WhatIf = $true
    }
    if ($PSBoundParameters.ContainsKey('Confirm')) {
      $runParams.Confirm = [bool]$PSBoundParameters['Confirm']
    }

    $continueOnError = if (Has-Property -Object $step -Name 'ContinueOnError') { [bool]$step.ContinueOnError } else { $false }

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    try {
      if ($PSCmdlet.ShouldProcess($scriptName, 'Execute profile step')) {
        Write-UiLine -Text ("[RUN ] {0}" -f $scriptName) -Style Header
        & $runLocalPath @runParams
        $exitCode = if ($null -eq $LASTEXITCODE) { 0 } else { [int]$LASTEXITCODE }
        $status = if ($exitCode -eq 0) { 'Success' } elseif ($exitCode -eq 2) { 'Partial' } else { 'Failed' }
        $message = "Exit code: $exitCode"
      } else {
        $exitCode = 0
        $status = 'Skipped'
        $message = 'Skipped by ShouldProcess (-WhatIf/-Confirm).'
        Write-UiLine -Text ("[SKIP] {0} (WhatIf/Confirm)" -f $scriptName) -Style Muted
      }
    } catch {
      $exitCode = 1
      $status = 'Failed'
      $message = $_.Exception.Message
      Write-UiLine -Text ("[FAIL] {0} - {1}" -f $scriptName, $message) -Style Error
    } finally {
      $sw.Stop()
    }

    $stepStatus[$scriptName] = $status
    [void]$results.Add([pscustomobject]@{
        ScriptName = $scriptName
        Status     = $status
        ExitCode   = $exitCode
        DurationMs = $sw.ElapsedMilliseconds
        Message    = $message
      })

    if ($status -eq 'Success') {
      Write-UiLine -Text ("[ OK ] {0} ({1} ms)" -f $scriptName, $sw.ElapsedMilliseconds) -Style Success
    } elseif ($status -eq 'Partial') {
      Write-UiLine -Text ("[WARN] {0} ({1} ms)" -f $scriptName, $sw.ElapsedMilliseconds) -Style Warning
    }

    if ($status -eq 'Failed' -and -not $continueOnError) {
      Write-UiLine -Text ("Stopping profile run due to failure in {0} (ContinueOnError=false)." -f $scriptName) -Style Error
      $pending.Clear()
      break
    }

    continue
  }

  if (-not $progress -and $pending.Count -gt 0) {
    foreach ($remaining in @($pending)) {
      [void]$results.Add([pscustomobject]@{
          ScriptName = [string]$remaining.Script
          Status     = 'Skipped'
          ExitCode   = 2
          DurationMs = 0
          Message    = 'Dependency cycle or unresolved dependency.'
        })
    }
    break
  }
}

$resultsArr = @($results)
$failed = @($resultsArr | Where-Object { $_.Status -eq 'Failed' }).Count
$partial = @($resultsArr | Where-Object { $_.Status -eq 'Partial' }).Count
$skipped = @($resultsArr | Where-Object { $_.Status -eq 'Skipped' }).Count

$resultToken = if ($failed -gt 0) { 'FAIL' } elseif ($partial -gt 0 -or $skipped -gt 0) { 'WARN' } else { 'OK' }

$summary = [pscustomobject]@{
  ProfileName   = [string]$profileDoc.ProfileName
  Version       = [string]$profileDoc.Version
  Mode          = $globalMode
  StepsTotal    = $resultsArr.Count
  StepsFailed   = $failed
  StepsPartial  = $partial
  StepsSkipped  = $skipped
}

$runResult = New-V2ResultObject `
  -ScriptName '00-Run-Profile.ps1' `
  -Mode $globalMode `
  -Result $resultToken `
  -Findings @() `
  -Summary $summary `
  -Metadata @{ Steps = $resultsArr; Validation = $validation }

if ($OutputFormat -eq 'Console') {
  Write-Section -Title 'Profile Summary'
  Write-KeyValue -Key 'Profile' -Value $summary.ProfileName
  Write-KeyValue -Key 'Mode' -Value $summary.Mode
  Write-KeyValue -Key 'Total' -Value $summary.StepsTotal
  Write-KeyValue -Key 'Failed' -Value $summary.StepsFailed
  Write-KeyValue -Key 'Partial' -Value $summary.StepsPartial
  Write-KeyValue -Key 'Skipped' -Value $summary.StepsSkipped
}

Write-ResultObject -ResultObject $runResult -OutputFormat $OutputFormat -OutputPath $OutputPath

if ($PassThru) {
  $runResult
}

if ($failed -gt 0) { exit 1 }
if ($partial -gt 0 -or $skipped -gt 0) { exit 2 }
exit 0
