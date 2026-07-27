#requires -version 5.1
<#
.SYNOPSIS
Validate a v2 execution profile JSON.

.DESCRIPTION
Performs structural validation for profile files used by 00-Run-Profile.ps1.

.PARAMETER ProfilePath
Path to the profile JSON file.

.PARAMETER OutputFormat
Console, Json, Csv, or None.

.PARAMETER OutputPath
Output file path for Json/Csv formats.

.PARAMETER PassThru
Emit standardized result object to pipeline.
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
  [Parameter(Mandatory)]
  [string]$ProfilePath,

  [ValidateSet('Console','Json','Csv','None')]
  [string]$OutputFormat = 'Console',

  [string]$RootPath,

  [string]$OutputPath,

  [switch]$PassThru

,
  [ValidateSet('Audit','Remediate')][string]$Mode = 'Audit',
  [string]$ConfigPath,
  [switch]$Strict,
  [switch]$Quiet,
  [switch]$NoColor
)

. (Join-Path $PSScriptRoot '_lib/Bootstrap.ps1')
Import-Module (Join-Path $script:LibPath 'Output.psm1') -Force
Import-Module (Join-Path $script:LibPath 'Common.psm1') -Force -DisableNameChecking
Import-Module (Join-Path $script:LibPath 'Validation.psm1') -Force
Import-Module (Join-Path $script:LibPath 'Serialization.psm1') -Force

Set-StrictMode -Version Latest
# v2-init (migrated to Initialize-V2Context)
$script:__V2Context = Initialize-V2Context -ScriptName '00-Validate-Profile.ps1' -BoundParameters $PSBoundParameters `
  -Mode $Mode -ConfigPath $ConfigPath -OutputFormat $OutputFormat -OutputPath $OutputPath `
  -PassThru:$PassThru -Strict:$Strict -Quiet:$Quiet -NoColor:$NoColor
if ($script:__V2Context.Quiet) { $InformationPreference = 'SilentlyContinue'; $VerbosePreference = 'SilentlyContinue' }
$script:NoColor = [bool]$script:__V2Context.NoColor
$ErrorActionPreference = 'Stop'

$issues = New-Object System.Collections.ArrayList

function Add-Issue {
  param(
    [Parameter(Mandatory)][string]$Severity,
    [Parameter(Mandatory)][string]$Code,
    [Parameter(Mandatory)][string]$Message
  )

  [void]$issues.Add([pscustomobject]@{
      Severity = $Severity
      Code     = $Code
      Message  = $Message
    })
}

function Get-ValidationExceptionCode {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Message
  )

  if ($Message -match 'path traversal') { return 'PROFILE-PATH-TRAVERSAL' }
  if ($Message -like 'Profile file not found:*') { return 'PROFILE-NOT-FOUND' }
  if ($Message -eq 'Profile file is empty.') { return 'PROFILE-EMPTY' }
  if ($Message -like 'File exceeds the * byte size limit.') { return 'PROFILE-TOO-LARGE' }
  if ($Message -like 'Profile JSON is invalid:*') { return 'PROFILE-INVALID-JSON' }
  'PROFILE-VALIDATION-ERROR'
}

function Write-ValidationFailureResult {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Code,
    [Parameter(Mandatory)][string]$Message
  )

  $issue = [pscustomobject]@{
    Severity = 'High'
    Code     = $Code
    Message  = $Message
  }
  $summary = [pscustomobject]@{
    ProfilePath = $ProfilePath
    Issues      = 1
    HighIssues  = 1
    Warnings    = 0
  }
  $resultObj = Get-V2ResultObject `
    -ScriptName '00-Validate-Profile.ps1' `
    -Mode $Mode `
    -Result 'FAIL' `
    -Findings @($issue) `
    -Summary $summary `
    -Metadata @{ Component = 'ProfileValidation' }

  Write-ResultObject -ResultObject $resultObj -OutputFormat $OutputFormat -OutputPath $OutputPath
  if ($PassThru) { $resultObj }
}

# Has-Property moved to lib/Common.psm1

function Test-JsonObject {
  [CmdletBinding()]
  param([AllowNull()]$Value)

  return (
    $null -ne $Value -and
    $Value -isnot [string] -and
    $Value -isnot [System.ValueType] -and
    $Value -isnot [System.Array]
  )
}

function Test-JsonArray {
  [CmdletBinding()]
  param([AllowNull()]$Value)

  return ($null -ne $Value -and $Value -is [System.Array])
}

try {
  Assert-NoPathTraversal -Path $ProfilePath -ParameterName 'ProfilePath'

  if (-not (Test-Path -LiteralPath $ProfilePath -PathType Leaf)) {
    throw "Profile file not found: $ProfilePath"
  }

  $raw = Get-BoundedUtf8FileContent -Path $ProfilePath -MaximumBytes 1048576
  if ([string]::IsNullOrWhiteSpace($raw)) {
    throw 'Profile file is empty.'
  }
  $profileContentSha256 = Get-TextSha256 -Text $raw

  try {
    $profileDoc = $raw | ConvertFrom-Json -ErrorAction Stop
  } catch {
    throw "Profile JSON is invalid: $($_.Exception.Message)"
  }

  if (-not (Test-JsonObject -Value $profileDoc)) {
    Add-Issue -Severity 'High' -Code 'PROFILE-ROOT-TYPE' -Message 'Profile JSON root must be an object.'
  }

  foreach ($required in @('ProfileName','Version','Defaults','Steps','Integrity')) {
    if (-not (Has-Property -Object $profileDoc -Name $required)) {
      Add-Issue -Severity 'High' -Code 'PROFILE-MISSING-FIELD' -Message "Missing required field '$required'."
    }
  }

  if (Has-Property -Object $profileDoc -Name 'Defaults') {
    $defaults = $profileDoc.Defaults
    if (-not (Test-JsonObject -Value $defaults)) {
      Add-Issue -Severity 'High' -Code 'PROFILE-DEFAULTS-TYPE' -Message 'Defaults must be an object.'
    } elseif (-not (Has-Property -Object $defaults -Name 'Mode')) {
      Add-Issue -Severity 'High' -Code 'PROFILE-DEFAULTS-MODE' -Message "Defaults.Mode is required."
    } elseif (@('Audit','Remediate') -notcontains [string]$defaults.Mode) {
      Add-Issue -Severity 'High' -Code 'PROFILE-DEFAULTS-MODE-VALUE' -Message "Defaults.Mode must be Audit or Remediate."
    }

    if ((Has-Property -Object $defaults -Name 'OutputFormat') -and @('Console','Json','Csv','None') -notcontains [string]$defaults.OutputFormat) {
      Add-Issue -Severity 'High' -Code 'PROFILE-DEFAULTS-OUTPUTFORMAT' -Message "Defaults.OutputFormat must be Console, Json, Csv, or None."
    }
    if ((Has-Property -Object $defaults -Name 'Strict') -and $defaults.Strict -isnot [bool]) {
      Add-Issue -Severity 'High' -Code 'PROFILE-DEFAULTS-STRICT-TYPE' -Message 'Defaults.Strict must be a JSON boolean.'
    }
  }

  if (Has-Property -Object $profileDoc -Name 'Steps') {
    if (-not (Test-JsonArray -Value $profileDoc.Steps)) {
      Add-Issue -Severity 'High' -Code 'PROFILE-STEPS-TYPE' -Message 'Steps must be a JSON array.'
    }
    $scriptsBasePath = if ([string]::IsNullOrWhiteSpace($RootPath)) {
      $PSScriptRoot
    } elseif (Test-Path -LiteralPath (Join-Path $RootPath 'scripts') -PathType Container) {
      Join-Path $RootPath 'scripts'
    } else {
      $RootPath
    }

    $index = 0
    $knownStepNames = @()
    $seenScriptNames = @{}
    foreach ($step in @($profileDoc.Steps)) {
      $index++
      if (-not (Test-JsonObject -Value $step)) {
        Add-Issue -Severity 'High' -Code 'PROFILE-STEP-TYPE' -Message "Step #$index must be an object."
        continue
      }
      if (-not (Has-Property -Object $step -Name 'Script')) {
        Add-Issue -Severity 'High' -Code 'PROFILE-STEP-SCRIPT' -Message "Step #$index is missing Script."
        continue
      }

      $scriptName = [string]$step.Script
      if (-not (Test-SafeScriptName -Name $scriptName)) {
        Add-Issue -Severity 'High' -Code 'PROFILE-STEP-SCRIPT-NAME' -Message "Step #$index uses unsafe script name '$scriptName'."
      } elseif ($scriptName -match '^00-') {
        Add-Issue -Severity 'High' -Code 'PROFILE-STEP-CONTROL-PLANE' -Message "Step #$index references control-plane script '$scriptName'. Profiles may execute numbered workload scripts only."
      } else {
        $scriptPath = Join-Path $scriptsBasePath $scriptName
        if (-not (Test-Path -LiteralPath $scriptPath -PathType Leaf)) {
          Add-Issue -Severity 'High' -Code 'PROFILE-STEP-SCRIPT-NOT-FOUND' -Message "Step #$index references script '$scriptName' that does not exist under scripts/."
        }
      }

      if ($seenScriptNames.ContainsKey($scriptName)) {
        Add-Issue -Severity 'High' -Code 'PROFILE-STEP-DUPLICATE' -Message "Duplicate step script '$scriptName' is not allowed."
      } else {
        $seenScriptNames[$scriptName] = $true
      }

      $knownStepNames += $scriptName

      if ((Has-Property -Object $step -Name 'Args') -and $null -ne $step.Args) {
        if (-not (Test-JsonArray -Value $step.Args)) {
          Add-Issue -Severity 'High' -Code 'PROFILE-STEP-ARGS-ARRAY' -Message "Step #$index Args must be a JSON array."
        } else {
          if (@($step.Args).Count -gt 0) {
            Add-Issue -Severity 'High' -Code 'PROFILE-STEP-ARGS-NOT-ALLOWED' -Message "Step #$index Args must be empty. Profile JSON cannot supply step arguments; use a trusted direct runner invocation for advanced arguments."
          }
          $argIndex = 0
          foreach ($arg in @($step.Args)) {
            $argIndex++
            if ($null -eq $arg -or $arg -isnot [string]) {
              Add-Issue -Severity 'High' -Code 'PROFILE-STEP-ARGS-TYPE' -Message "Step #$index contains non-string Args value at position $argIndex."
              continue
            }

            if ([string]::IsNullOrWhiteSpace($arg)) {
              Add-Issue -Severity 'High' -Code 'PROFILE-STEP-ARGS-EMPTY' -Message "Step #$index contains an empty Args token at position $argIndex."
            }

            if ([string]$arg -ieq '-Remediate') {
              Add-Issue -Severity 'Medium' -Code 'PROFILE-STEP-ARGS-LEGACY-REMEDIATE' -Message "Step #$index uses removed legacy token '-Remediate'. Use '-Mode Remediate' instead."
            }
          }
        }
      }

      if ((Has-Property -Object $step -Name 'DependsOn') -and $null -ne $step.DependsOn) {
        if (-not (Test-JsonArray -Value $step.DependsOn)) {
          Add-Issue -Severity 'High' -Code 'PROFILE-STEP-DEPENDS-TYPE' -Message "Step #$index DependsOn must be a JSON array."
        } else {
          foreach ($dep in @($step.DependsOn)) {
            if ($dep -isnot [string] -or [string]::IsNullOrWhiteSpace([string]$dep)) {
              Add-Issue -Severity 'High' -Code 'PROFILE-STEP-DEPENDS-VALUE' -Message "Step #$index contains a non-string or empty DependsOn value."
            }
          }
        }
      }
      if ((Has-Property -Object $step -Name 'ContinueOnError') -and $step.ContinueOnError -isnot [bool]) {
        Add-Issue -Severity 'High' -Code 'PROFILE-STEP-CONTINUE-TYPE' -Message "Step #$index ContinueOnError must be a JSON boolean."
      }
    }

    # second pass for dependency references
    $index = 0
    foreach ($step in @($profileDoc.Steps)) {
      $index++
      if ((Has-Property -Object $step -Name 'DependsOn') -and $null -ne $step.DependsOn) {
        foreach ($dep in @($step.DependsOn)) {
          if (-not [string]::IsNullOrWhiteSpace([string]$dep) -and $knownStepNames -notcontains [string]$dep) {
            Add-Issue -Severity 'High' -Code 'PROFILE-STEP-DEPENDS-NOT-FOUND' -Message "Step #$index depends on unknown script '$dep'."
          }
        }
      }
    }
  }

  if (Has-Property -Object $profileDoc -Name 'Integrity') {
    $integrity = $profileDoc.Integrity
    if (-not (Test-JsonObject -Value $integrity)) {
      Add-Issue -Severity 'High' -Code 'PROFILE-INTEGRITY-TYPE' -Message 'Integrity must be an object.'
    }
    if ((Has-Property -Object $integrity -Name 'RequireSigned') -and $integrity.RequireSigned -isnot [bool]) {
      Add-Issue -Severity 'High' -Code 'PROFILE-INTEGRITY-SIGNED-TYPE' -Message 'Integrity.RequireSigned must be a JSON boolean.'
    }
    if ((Has-Property -Object $integrity -Name 'ExpectedHashes') -and $null -ne $integrity.ExpectedHashes -and -not (Test-JsonObject -Value $integrity.ExpectedHashes)) {
      Add-Issue -Severity 'High' -Code 'PROFILE-HASHES-TYPE' -Message 'Integrity.ExpectedHashes must be an object.'
    } elseif ((Has-Property -Object $integrity -Name 'ExpectedHashes') -and $null -ne $integrity.ExpectedHashes) {
      foreach ($kv in $integrity.ExpectedHashes.PSObject.Properties) {
        if (-not (Test-SafeScriptName -Name $kv.Name)) {
          Add-Issue -Severity 'High' -Code 'PROFILE-HASH-KEY' -Message "Integrity.ExpectedHashes contains unsafe key '$($kv.Name)'."
        }
        if ([string]::IsNullOrWhiteSpace([string]$kv.Value)) {
          Add-Issue -Severity 'Medium' -Code 'PROFILE-HASH-VALUE' -Message "Integrity.ExpectedHashes for '$($kv.Name)' is empty."
        }
      }
    }
  }

  $highCount = @($issues | Where-Object { $_.Severity -in @('High','Critical') }).Count
  $warnCount = @($issues | Where-Object { $_.Severity -in @('Medium','Low') }).Count

  $resultToken = if ($highCount -gt 0) { 'FAIL' } elseif ($warnCount -gt 0) { 'WARN' } else { 'OK' }
  if ($Strict -and $resultToken -eq 'WARN') { $resultToken = 'FAIL' }
  $summary = [pscustomobject]@{
    ProfilePath = (Resolve-Path -LiteralPath $ProfilePath).Path
    Issues      = $issues.Count
    HighIssues  = $highCount
    Warnings    = $warnCount
  }

  $resultObj = Get-V2ResultObject `
    -ScriptName '00-Validate-Profile.ps1' `
    -Mode $Mode `
    -Result $resultToken `
    -Findings (ConvertTo-ObjectArray -InputObject $issues) `
    -Summary $summary `
    -Metadata @{ Component = 'ProfileValidation'; ProfileContentSha256 = $profileContentSha256 }

  if ($OutputFormat -eq 'Console') {
    Write-Section -Title 'Profile Validation'
    Write-KeyValue -Key 'Profile' -Value $summary.ProfilePath
    Write-KeyValue -Key 'Issues' -Value $summary.Issues
    Write-KeyValue -Key 'High' -Value $summary.HighIssues
    Write-KeyValue -Key 'Warnings' -Value $summary.Warnings
    if ($issues.Count -gt 0) {
      Write-UiLine -Text 'Findings:' -ForegroundColor Yellow
      foreach ($i in $issues) {
        Write-UiLine -Text ("[{0}] {1} - {2}" -f $i.Severity.ToUpperInvariant(), $i.Code, $i.Message) -ForegroundColor Gray
      }
    }
  }

  Write-ResultObject -ResultObject $resultObj -OutputFormat $OutputFormat -OutputPath $OutputPath

  if ($PassThru) {
    $resultObj
  }

  exit (Get-V2ExitCode -Result $resultToken)
} catch {
  $message = $_.Exception.Message
  Write-UiLine -Text ("Validation failed: {0}" -f $message) -Style Error
  Write-ValidationFailureResult -Code (Get-ValidationExceptionCode -Message $message) -Message $message
  exit (Get-V2ExitCode -Result 'FAIL')
}
