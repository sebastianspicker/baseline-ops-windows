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
Import-Module (Join-Path $script:LibPath 'Common.psm1') -Force -DisableNameChecking
Import-Module (Join-Path $script:LibPath 'Config.psm1') -Force
Import-Module (Join-Path $script:LibPath 'Validation.psm1') -Force
Import-Module (Join-Path $script:LibPath 'Serialization.psm1') -Force

Set-StrictMode -Version Latest
# v2-init (migrated to Initialize-V2Context)
Initialize-V2Context -ScriptName '00-Run-Profile.ps1' -BoundParameters $PSBoundParameters
$ErrorActionPreference = 'Stop'

# Has-Property moved to lib/Common.psm1

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

# Profile JSON is untrusted run input. The runner owns deployment roots,
# integrity controls, and confirmation policy; a profile step may add
# script-specific arguments but must not weaken those run-level decisions.
function Get-ProfileStepAllowedArgs {
  [CmdletBinding()]
  param(
    [string[]]$ArgsList,
    [Parameter(Mandatory)][string[]]$BlockedNames,
    [Parameter(Mandatory)][string]$ScriptName
  )

  if (-not $ArgsList) { return @() }

  $cleanArgs = New-Object System.Collections.ArrayList
  for ($i = 0; $i -lt $ArgsList.Count; $i++) {
    $argVal = [string]$ArgsList[$i]
    $blockedMatch = $null

    foreach ($blocked in $BlockedNames) {
      $pattern = '^-{0}($|:)' -f [regex]::Escape($blocked)
      if ($argVal -imatch $pattern) {
        $blockedMatch = $blocked
        break
      }
    }

    if ($null -ne $blockedMatch) {
      Write-Warning "Profile step '$ScriptName' contains blocked argument override '$argVal'. Removing it."
      if ($argVal -notmatch ':' -and ($i + 1) -lt $ArgsList.Count -and [string]$ArgsList[$i + 1] -notmatch '^-') {
        $i++
      }
      continue
    }

    [void]$cleanArgs.Add($ArgsList[$i])
  }

  return @($cleanArgs)
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
  # Keep the production default for deployed Windows hosts while allowing repo
  # checkout smoke tests to run on non-Windows developer machines.
  $repoRootCandidate = Split-Path -Parent $PSScriptRoot
  if (Test-Path -LiteralPath (Join-Path $repoRootCandidate 'scripts') -PathType Container) {
    $RootPath = $repoRootCandidate
  }
}

$validation = & $validatorPath -ProfilePath $ProfilePath -RootPath $RootPath -OutputFormat None -PassThru
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
$expectedHashes = if (Has-Property -Object $integrity -Name 'ExpectedHashes') { ConvertTo-Hashtable -Object $integrity.ExpectedHashes } else { @{} }

# Profile JSON is untrusted run input. The operator's CLI invocation owns
# runner-level side effects such as remediation mode and output destinations.
if (-not $PSBoundParameters.ContainsKey('Mode') -and (Has-Property -Object $defaults -Name 'Mode') -and [string]$defaults.Mode -eq 'Remediate') {
  Write-Warning "Ignoring profile Defaults.Mode='Remediate'. Pass -Mode Remediate on the runner CLI to remediate."
}
if (-not $PSBoundParameters.ContainsKey('OutputFormat') -and (Has-Property -Object $defaults -Name 'OutputFormat') -and -not [string]::IsNullOrWhiteSpace([string]$defaults.OutputFormat)) {
  Write-Warning "Ignoring profile Defaults.OutputFormat. Pass -OutputFormat on the runner CLI to change output format."
}
if (-not $PSBoundParameters.ContainsKey('OutputPath') -and (Has-Property -Object $defaults -Name 'OutputPath') -and -not [string]::IsNullOrWhiteSpace([string]$defaults.OutputPath)) {
  Write-Warning "Ignoring profile Defaults.OutputPath. Pass -OutputPath on the runner CLI to write result output."
}
$globalMode = if ($PSBoundParameters.ContainsKey('Mode')) { $Mode } else { 'Audit' }
$effectiveOutputFormat = $OutputFormat
$effectiveOutputPath = $OutputPath
$profileStrict = [bool]($Strict -or ((Has-Property -Object $defaults -Name 'Strict') -and $defaults.Strict))
$profileRequireSigned = [bool]($RequireSigned -or ((Has-Property -Object $integrity -Name 'RequireSigned') -and $integrity.RequireSigned))

$script:__V2Context.OutputFormat = $effectiveOutputFormat
$script:__V2Context.OutputPath = $effectiveOutputPath

$results = New-Object System.Collections.ArrayList
$stepStatus = @{}
$pending = New-Object System.Collections.ArrayList
foreach ($step in @($profileDoc.Steps)) { [void]$pending.Add($step) }
$profileFindings = New-Object System.Collections.ArrayList
$dependencyCycleDetected = $false
$dependencyCycleScripts = @()

Write-Section -Title ("Run Profile: {0}" -f $profileDoc.ProfileName)
Write-KeyValue -Key 'ProfilePath' -Value (Resolve-Path -LiteralPath $ProfilePath).Path
Write-KeyValue -Key 'Mode' -Value $globalMode
Write-KeyValue -Key 'Strict' -Value $profileStrict
Write-KeyValue -Key 'RequireSigned' -Value $profileRequireSigned

# The scheduler is intentionally simple: repeatedly run steps whose
# dependencies have finished, mark dependents skipped when an upstream failed,
# and treat a no-progress pass as an unresolved dependency cycle.
while ($pending.Count -gt 0) {
  $progress = $false

  for ($i = 0; $i -lt $pending.Count; $i++) {
    $step = $pending[$i]
    $scriptName = [string]$step.Script
    $dependsOn = if ((Has-Property -Object $step -Name 'DependsOn') -and $null -ne $step.DependsOn) { @($step.DependsOn) } else { @() }

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
    if ((Has-Property -Object $step -Name 'Args') -and $null -ne $step.Args) {
      $stepArgs += @($step.Args)
    }

    # Profile steps must not override runner-owned mode, path, integrity, output, or confirmation controls.
    $stepArgs = @(Get-ProfileStepAllowedArgs -ArgsList $stepArgs -BlockedNames @('Mode', 'Remediate', 'RootPath', 'ConfigPath', 'ExpectedHash', 'OutputFormat', 'OutputPath', 'PassThru', 'Confirm', 'WhatIf') -ScriptName $scriptName)

    if (-not (Test-StepArgHasToken -ArgsList $stepArgs -Name 'Mode')) {
      $stepArgs += @('-Mode', $globalMode)
    }
    if ($profileStrict -and -not (Test-StepArgHasToken -ArgsList $stepArgs -Name 'Strict')) {
      $stepArgs += '-Strict'
    }
    $runParams = @{
      ScriptName   = $scriptName
      ScriptArgs   = $stepArgs
      RootPath     = $RootPath
      OutputFormat = 'None'
      PassThru     = $true
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
    $processExitCode = $null
    $childResult = $null
    try {
      if ($WhatIfPreference) {
        $exitCode = 0
        $status = 'Skipped'
        $message = 'Skipped (-WhatIf).'
        Write-UiLine -Text ("[SKIP] {0} (-WhatIf)" -f $scriptName) -Style Muted
      } else {
        Write-UiLine -Text ("[RUN ] {0}" -f $scriptName) -Style Header
        $childOutput = @(& $runLocalPath @runParams)
        $processExitCode = if ($null -eq $LASTEXITCODE) { 0 } else { [int]$LASTEXITCODE }
        $childResults = @(
          $childOutput | Where-Object {
            $null -ne $_ -and
            $_.PSObject.Properties.Name -contains 'Result' -and
            @('OK','WARN','FAIL') -contains [string]$_.Result
          }
        )

        if ($childResults.Count -gt 0) {
          $childResult = $childResults[-1]
          switch ([string]$childResult.Result) {
            'OK' {
              $exitCode = 0
              $status = 'Success'
            }
            'WARN' {
              $exitCode = 2
              $status = 'Partial'
            }
            'FAIL' {
              $exitCode = 1
              $status = 'Failed'
            }
          }
          $message = "Child V2 result: $($childResult.Result); process exit code: $processExitCode"
          $expectedProcessExitCode = switch ([string]$childResult.Result) {
            'OK' { 0 }
            'WARN' { 2 }
            'FAIL' { 1 }
          }
          $actualChildExitCode = $processExitCode
          if (Has-Property -Object $childResult -Name 'RunnerActualExitCode') {
            $actualChildExitCode = [int]$childResult.RunnerActualExitCode
          }
          if ($null -ne $actualChildExitCode -and $actualChildExitCode -ne $expectedProcessExitCode) {
            [void]$profileFindings.Add([pscustomobject]@{
                Code       = 'Profile-ChildResultExitMismatch'
                Severity   = if ([string]$childResult.Result -eq 'OK') { 'High' } else { 'Medium' }
                Message    = "Child V2 result '$($childResult.Result)' does not match process exit code $actualChildExitCode for $scriptName."
                ScriptName = $scriptName
                ChildResult = [string]$childResult.Result
                ExpectedExitCode = $expectedProcessExitCode
                ActualExitCode = $actualChildExitCode
              })
            $message = "$message; V2 result/exit-code mismatch"
            if ([string]$childResult.Result -eq 'OK') {
              $exitCode = 1
              $status = 'Failed'
            }
          }
          if ((Has-Property -Object $childResult -Name 'Findings') -and $null -ne $childResult.Findings) {
            foreach ($finding in @($childResult.Findings)) {
              if ($null -ne $finding) {
                [void]$profileFindings.Add($finding)
              }
            }
          }
        } else {
          $exitCode = 1
          $status = 'Failed'
          $message = "Child did not emit a valid V2 result. Process exit code: $processExitCode"
        }
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
        RunnerExitCode = if ($null -ne $processExitCode) { $processExitCode } else { $exitCode }
        ChildResult = if ($null -ne $childResult) { [string]$childResult.Result } else { $null }
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
    $dependencyCycleDetected = $true
    $dependencyCycleScripts = @($pending | ForEach-Object { [string]$_.Script })
    [void]$profileFindings.Add([pscustomobject]@{
        Code     = 'Profile-DependencyCycle'
        Severity = 'High'
        Message  = "Dependency cycle or unresolved dependency. Scripts not run: $($dependencyCycleScripts -join ', ')"
        Scripts  = $dependencyCycleScripts
      })
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
$failedForResult = $failed
if ($dependencyCycleDetected) { $failedForResult++ }

$resultToken = if ($failedForResult -gt 0) { 'FAIL' } elseif ($partial -gt 0 -or $skipped -gt 0) { 'WARN' } else { 'OK' }

$summary = [pscustomobject]@{
  ProfileName   = [string]$profileDoc.ProfileName
  Version       = [string]$profileDoc.Version
  Mode          = $globalMode
  StepsTotal    = $resultsArr.Count
  StepsFailed   = $failedForResult
  StepsPartial  = $partial
  StepsSkipped  = $skipped
  DependencyCycle = $dependencyCycleDetected
  DependencyCycleScripts = $dependencyCycleScripts
}

$runResult = Get-V2ResultObject `
  -ScriptName '00-Run-Profile.ps1' `
  -Mode $globalMode `
  -Result $resultToken `
  -Findings @($profileFindings) `
  -Summary $summary `
  -Metadata @{ Steps = $resultsArr; Validation = $validation }

if ($effectiveOutputFormat -eq 'Console') {
  Write-Section -Title 'Profile Summary'
  Write-KeyValue -Key 'Profile' -Value $summary.ProfileName
  Write-KeyValue -Key 'Mode' -Value $summary.Mode
  Write-KeyValue -Key 'Total' -Value $summary.StepsTotal
  Write-KeyValue -Key 'Failed' -Value $summary.StepsFailed
  Write-KeyValue -Key 'Partial' -Value $summary.StepsPartial
  Write-KeyValue -Key 'Skipped' -Value $summary.StepsSkipped
}

Write-ResultObject -ResultObject $runResult -OutputFormat $effectiveOutputFormat -OutputPath $effectiveOutputPath

if ($PassThru) {
  $runResult
}

if ($WhatIfPreference -and $failedForResult -eq 0) { exit 0 }
if ($failedForResult -gt 0) { exit 1 }
if ($partial -gt 0 -or $skipped -gt 0) { exit 2 }
exit 0
