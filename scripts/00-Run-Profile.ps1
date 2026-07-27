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

$rootPathWasExplicit = $PSBoundParameters.ContainsKey('RootPath')
$defaultDeploymentPresent = $false
if ([System.Environment]::OSVersion.Platform -eq [System.PlatformID]::Win32NT) {
  $defaultDeploymentPresent = Test-Path -LiteralPath (Join-Path $RootPath 'scripts') -PathType Container
}
if (-not $rootPathWasExplicit -and $RootPath -eq 'C:\install\mdm\ps1' -and -not $defaultDeploymentPresent) {
  # Keep an explicitly selected root authoritative. Checkout fallback is only
  # for source invocations that omitted RootPath and have no installed kit.
  $repoRootCandidate = Split-Path -Parent $PSScriptRoot
  if (Test-Path -LiteralPath (Join-Path $repoRootCandidate 'scripts') -PathType Container) {
    $RootPath = $repoRootCandidate
  }
}

function Assert-RunProfileTrustedWindowsAcl {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Path,
    [switch]$CheckAncestors
  )

  $trustedSids = @{
    'S-1-5-18' = $true
    'S-1-5-32-544' = $true
    'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464' = $true
  }
  $writeMask =
    [System.Security.AccessControl.FileSystemRights]::Write -bor
    [System.Security.AccessControl.FileSystemRights]::Modify -bor
    [System.Security.AccessControl.FileSystemRights]::FullControl -bor
    [System.Security.AccessControl.FileSystemRights]::Delete -bor
    [System.Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor
    [System.Security.AccessControl.FileSystemRights]::ChangePermissions -bor
    [System.Security.AccessControl.FileSystemRights]::TakeOwnership
  $ancestorReplacementMask =
    [System.Security.AccessControl.FileSystemRights]::Delete -bor
    [System.Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor
    [System.Security.AccessControl.FileSystemRights]::ChangePermissions -bor
    [System.Security.AccessControl.FileSystemRights]::TakeOwnership

  $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
  $current = $item.FullName
  $isProtectedItem = $true
  while (-not [string]::IsNullOrWhiteSpace($current)) {
    $currentItem = Get-Item -LiteralPath $current -Force -ErrorAction Stop
    if (($currentItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
      throw "Privileged execution path contains a reparse point: $current"
    }
    $acl = Get-Acl -LiteralPath $currentItem.FullName -ErrorAction Stop
    $ownerSid = $acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value
    if (-not $trustedSids.ContainsKey($ownerSid)) {
      throw "Privileged execution path has an untrusted owner SID: $current"
    }
    $effectiveMask = if ($isProtectedItem) { $writeMask } else { $ancestorReplacementMask }
    foreach ($rule in @($acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]))) {
      if ($rule.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) { continue }
      if (($rule.PropagationFlags -band [System.Security.AccessControl.PropagationFlags]::InheritOnly) -ne 0) { continue }
      $sid = [string]$rule.IdentityReference.Value
      if (-not $trustedSids.ContainsKey($sid) -and
          ([int64]$rule.FileSystemRights -band [int64]$effectiveMask) -ne 0) {
        throw "Privileged execution path grants write/replace rights to an untrusted SID: $current"
      }
    }
    if (-not $CheckAncestors) { break }
    $parent = Split-Path -Parent $currentItem.FullName
    if ([string]::IsNullOrWhiteSpace($parent) -or
        [string]::Equals($parent, $currentItem.FullName, [System.StringComparison]::OrdinalIgnoreCase)) { break }
    $current = $parent
    $isProtectedItem = $false
  }
}

$validatorPath = Join-Path $PSScriptRoot '00-Validate-Profile.ps1'
$runLocalPath = Join-Path $PSScriptRoot '00-Run-Local.ps1'
$isWindowsPlatform = [System.Environment]::OSVersion.Platform -eq [System.PlatformID]::Win32NT
$isElevatedWindows = $false
if ($isWindowsPlatform) {
  $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
  $principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
  $isElevatedWindows = $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

if ($isElevatedWindows) {
  # This list is deliberately constructed without importing repository code.
  # Every path capable of influencing profile orchestration is trusted first.
  $runnerRoot = Split-Path -Parent $PSScriptRoot
  $runnerLib = Join-Path $runnerRoot 'lib'
  $trustedBootstrapPaths = @(
    $runnerRoot,
    $PSScriptRoot,
    $PSCommandPath,
    $runnerLib,
    (Join-Path $PSScriptRoot '_lib/Bootstrap.ps1'),
    (Join-Path $runnerLib 'Output.psm1'),
    (Join-Path $runnerLib 'Common.psm1'),
    (Join-Path $runnerLib 'Config.psm1'),
    (Join-Path $runnerLib 'Validation.psm1'),
    (Join-Path $runnerLib 'Serialization.psm1'),
    $validatorPath,
    $runLocalPath,
    $RootPath,
    (Join-Path $RootPath 'scripts'),
    (Join-Path $RootPath 'lib')
  ) | Select-Object -Unique
  foreach ($trustedPath in $trustedBootstrapPaths) {
    Assert-RunProfileTrustedWindowsAcl -Path $trustedPath -CheckAncestors:($trustedPath -in @($runnerRoot, $RootPath))
  }
}

. (Join-Path $PSScriptRoot '_lib/Bootstrap.ps1')
Import-Module (Join-Path $script:LibPath 'Output.psm1') -Force
Import-Module (Join-Path $script:LibPath 'Common.psm1') -Force -DisableNameChecking
Import-Module (Join-Path $script:LibPath 'Config.psm1') -Force
Import-Module (Join-Path $script:LibPath 'Validation.psm1') -Force
Import-Module (Join-Path $script:LibPath 'Serialization.psm1') -Force

Set-StrictMode -Version Latest
# v2-init (migrated to Initialize-V2Context)
$bootstrapMode = if ($PSBoundParameters.ContainsKey('Mode')) { $Mode } else { 'Audit' }
$script:__V2Context = Initialize-V2Context -ScriptName '00-Run-Profile.ps1' -BoundParameters $PSBoundParameters `
  -Mode $bootstrapMode -ConfigPath $ConfigPath -OutputFormat $OutputFormat -OutputPath $OutputPath `
  -PassThru:$PassThru -Strict:$Strict -Quiet:$Quiet -NoColor:$NoColor
if ($script:__V2Context.Quiet) { $InformationPreference = 'SilentlyContinue'; $VerbosePreference = 'SilentlyContinue' }
$script:NoColor = [bool]$script:__V2Context.NoColor
$ErrorActionPreference = 'Stop'

# Has-Property moved to lib/Common.psm1

$globalMode = $bootstrapMode

function Write-ProfileFailureResult {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Code,
    [Parameter(Mandatory)][string]$Message,
    [AllowNull()][object]$ValidationResult
  )

  $failureFindings = @(
    [pscustomobject]@{
      Code     = $Code
      Severity = 'High'
      Message  = $Message
    }
  )
  if ($null -ne $ValidationResult -and (Has-Property -Object $ValidationResult -Name 'Findings')) {
    $failureFindings += @($ValidationResult.Findings)
  }

  $failureResult = Get-V2ResultObject `
    -ScriptName '00-Run-Profile.ps1' `
    -Mode $globalMode `
    -Result 'FAIL' `
    -Findings $failureFindings `
    -Summary ([pscustomobject]@{
        ProfilePath  = $ProfilePath
        StepsTotal   = 0
        StepsFailed  = 1
        StepsPartial = 0
        StepsSkipped = 0
        Error        = $Message
      }) `
    -Metadata @{ Validation = $ValidationResult }

  Write-ResultObject -ResultObject $failureResult -OutputFormat $OutputFormat -OutputPath $OutputPath
  if ($PassThru) { $failureResult }
}

if (-not (Test-Path -LiteralPath $validatorPath -PathType Leaf)) {
  Write-ProfileFailureResult -Code 'Profile-MissingValidator' -Message "Missing validator script: $validatorPath"
  exit (Get-V2ExitCode -Result 'FAIL')
}
if (-not (Test-Path -LiteralPath $runLocalPath -PathType Leaf)) {
  Write-ProfileFailureResult -Code 'Profile-MissingRunner' -Message "Missing Run-Local script: $runLocalPath"
  exit (Get-V2ExitCode -Result 'FAIL')
}

$validation = & $validatorPath -ProfilePath $ProfilePath -RootPath $RootPath -OutputFormat None -PassThru
$validationExitCode = $LASTEXITCODE
if ($validationExitCode -ne 0) {
  if ($validationExitCode -eq 2) {
    Write-Warning "Profile validation produced warnings: $ProfilePath"
    if ($Strict) {
      Write-ProfileFailureResult -Code 'Profile-StrictValidationWarning' -Message "Profile validation produced warnings (strict mode): $ProfilePath" -ValidationResult $validation
      exit (Get-V2ExitCode -Result 'FAIL')
    }
  } else {
    Write-ProfileFailureResult -Code 'Profile-ValidationFailed' -Message "Profile validation failed: $ProfilePath" -ValidationResult $validation
    exit (Get-V2ExitCode -Result 'FAIL')
  }
}

$validatedProfileHash = if (
  $null -ne $validation -and
  (Has-Property -Object $validation -Name 'Metadata') -and
  $null -ne $validation.Metadata -and
  (Has-Property -Object $validation.Metadata -Name 'ProfileContentSha256')
) { [string]$validation.Metadata.ProfileContentSha256 } else { '' }
if ($validatedProfileHash -notmatch '^[A-Fa-f0-9]{64}$') {
  Write-ProfileFailureResult -Code 'Profile-MissingValidationHash' -Message 'Profile validator did not return a valid content hash.' -ValidationResult $validation
  exit (Get-V2ExitCode -Result 'FAIL')
}

try {
  $profileRaw = Get-BoundedUtf8FileContent -Path $ProfilePath -MaximumBytes 1048576
} catch {
  Write-ProfileFailureResult -Code 'Profile-ReadFailed' -Message "Profile read failed: $($_.Exception.Message)" -ValidationResult $validation
  exit (Get-V2ExitCode -Result 'FAIL')
}
$profileContentHash = Get-TextSha256 -Text $profileRaw
if (-not $profileContentHash.Equals($validatedProfileHash, [System.StringComparison]::OrdinalIgnoreCase)) {
  Write-ProfileFailureResult -Code 'Profile-ChangedAfterValidation' -Message 'Profile content changed after validation.' -ValidationResult $validation
  exit (Get-V2ExitCode -Result 'FAIL')
}
$profileDoc = $profileRaw | ConvertFrom-Json -ErrorAction Stop
$nonEmptyArgsStep = $profileDoc.Steps | Where-Object {
    (Has-Property -Object $_ -Name 'Args') -and $null -ne $_.Args -and @($_.Args).Count -gt 0
  } | Select-Object -First 1
if ($null -ne $nonEmptyArgsStep) {
  Write-ProfileFailureResult -Code 'Profile-StepArgsNotAllowed' -Message "Profile step '$([string]$nonEmptyArgsStep.Script)' contains Args. Profile JSON cannot supply step arguments; use a trusted direct runner invocation for advanced arguments." -ValidationResult $validation
  exit (Get-V2ExitCode -Result 'FAIL')
}
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
$effectiveOutputFormat = $OutputFormat
$effectiveOutputPath = $OutputPath
$profileStrict = [bool]($Strict -or ((Has-Property -Object $defaults -Name 'Strict') -and $defaults.Strict))
$profileRequireSigned = [bool]($RequireSigned -or ((Has-Property -Object $integrity -Name 'RequireSigned') -and $integrity.RequireSigned))
$declaredStepCount = @($profileDoc.Steps).Count

$script:__V2Context.OutputFormat = $effectiveOutputFormat
$script:__V2Context.OutputPath = $effectiveOutputPath

$results = New-Object System.Collections.ArrayList
$stepStatus = @{}
$pending = New-Object System.Collections.ArrayList
foreach ($step in @($profileDoc.Steps)) { [void]$pending.Add($step) }
$profileFindings = New-Object System.Collections.ArrayList
$validationWarned = [bool]($validationExitCode -eq 2 -or [string]$validation.Result -eq 'WARN')
foreach ($finding in @($validation.Findings)) { [void]$profileFindings.Add($finding) }
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

    # Step arguments are intentionally unavailable to untrusted profile JSON.
    # Only this trusted runner invocation supplies the child parameters.
    $stepArgs = @('-Mode', $globalMode)
    if ($profileStrict) {
      $stepArgs += '-Strict'
    }
    $runParams = @{
      ScriptName   = $scriptName
      ScriptArgs   = $stepArgs
      RootPath     = $RootPath
      OutputFormat = 'None'
      PassThru     = $true
    }

    if ($profileStrict) {
      $runParams.Strict = $true
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
          $declaredChildResult = if (Has-Property -Object $childResult -Name 'RunnerDeclaredResult') {
            [string]$childResult.RunnerDeclaredResult
          } else {
            [string]$childResult.Result
          }
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
          $expectedProcessExitCode = switch ($declaredChildResult) {
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
                Severity   = if ($declaredChildResult -eq 'OK') { 'High' } else { 'Medium' }
                Message    = "Child V2 result '$declaredChildResult' does not match process exit code $actualChildExitCode for $scriptName."
                ScriptName = $scriptName
                ChildResult = $declaredChildResult
                ExpectedExitCode = $expectedProcessExitCode
                ActualExitCode = $actualChildExitCode
              })
            $message = "$message; V2 result/exit-code mismatch"
            if ($declaredChildResult -eq 'OK') {
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
        ChildResult = if ($null -ne $childResult) {
          if (Has-Property -Object $childResult -Name 'RunnerDeclaredResult') { [string]$childResult.RunnerDeclaredResult } else { [string]$childResult.Result }
        } else { $null }
        ChildEffectiveResult = if ($null -ne $childResult) { [string]$childResult.Result } else { $null }
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
      foreach ($remaining in @($pending)) {
        $remainingScriptName = [string]$remaining.Script
        $stepStatus[$remainingScriptName] = 'Skipped'
        [void]$results.Add([pscustomobject]@{
            ScriptName = $remainingScriptName
            Status     = 'Skipped'
            ExitCode   = 2
            DurationMs = 0
            Message    = "Not run because the profile stopped after failure in $scriptName."
          })
        Write-UiLine -Text ("[SKIP] {0} (profile stopped after failure)" -f $remainingScriptName) -Style Muted
      }
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

$resultToken = if ($failedForResult -gt 0) { 'FAIL' } elseif ($validationWarned -or $partial -gt 0 -or $skipped -gt 0) { 'WARN' } else { 'OK' }
$whatIfOnlyWarning = [bool](
  $WhatIfPreference -and
  -not $validationWarned -and
  $failedForResult -eq 0 -and
  $partial -eq 0 -and
  $skipped -eq $declaredStepCount
)
$strictPromoted = [bool]($profileStrict -and $resultToken -eq 'WARN' -and -not $whatIfOnlyWarning)
if ($strictPromoted) { $resultToken = 'FAIL' }

$summary = [pscustomobject]@{
  ProfileName   = [string]$profileDoc.ProfileName
  Version       = [string]$profileDoc.Version
  Mode          = $globalMode
  StepsTotal    = $declaredStepCount
  StepsFailed   = $failedForResult
  StepsPartial  = $partial
  StepsSkipped  = $skipped
  Strict        = $profileStrict
  StrictPromoted = $strictPromoted
  ValidationWarnings = @($validation.Findings | Where-Object Severity -in @('Medium','Low')).Count
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

exit (Get-V2ExitCode -Result $resultToken)
