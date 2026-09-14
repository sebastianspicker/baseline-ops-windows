#requires -version 5.1
<#
.SYNOPSIS
Private runtime helpers for 00-Validate-Profile.ps1.

.DESCRIPTION
Contains profile document validation after the public entrypoint has loaded its
bootstrap and shared validation services.
#>

function Add-Issue {
  [CmdletBinding()]
  param([Parameter(Mandatory)][string]$Severity, [Parameter(Mandatory)][string]$Code, [Parameter(Mandatory)][string]$Message)
  [void]$script:issues.Add([pscustomobject]@{ Severity = $Severity; Code = $Code; Message = $Message })
}

function Get-ValidationExceptionCode {
  [CmdletBinding()]
  param([Parameter(Mandatory)][string]$Message)
  if ($Message -match 'path traversal') { return 'PROFILE-PATH-TRAVERSAL' }
  if ($Message -like 'Profile file not found:*') { return 'PROFILE-NOT-FOUND' }
  if ($Message -eq 'Profile file is empty.') { return 'PROFILE-EMPTY' }
  if ($Message -like 'File exceeds the * byte size limit.') { return 'PROFILE-TOO-LARGE' }
  if ($Message -like 'Profile JSON is invalid:*') { return 'PROFILE-INVALID-JSON' }
  return 'PROFILE-VALIDATION-ERROR'
}

function Write-ValidationFailureResult {
  [CmdletBinding()]
  param([Parameter(Mandatory)][string]$Code, [Parameter(Mandatory)][string]$Message)
  $issue = [pscustomobject]@{ Severity = 'High'; Code = $Code; Message = $Message }
  $summary = [pscustomobject]@{ ProfilePath = $ProfilePath; Issues = 1; HighIssues = 1; Warnings = 0 }
  $resultObject = Get-V2ResultObject -ScriptName '00-Validate-Profile.ps1' -Mode $Mode -Result 'FAIL' -Findings @($issue) -Summary $summary -Metadata @{ Component = 'ProfileValidation' }
  Write-ResultObject -ResultObject $resultObject -OutputFormat $OutputFormat -OutputPath $OutputPath
  if ($PassThru) { $resultObject }
}

function Test-JsonObject {
  [CmdletBinding()]
  [OutputType([bool])]
  param([AllowNull()]$Value)
  return ($null -ne $Value -and $Value -isnot [string] -and $Value -isnot [System.ValueType] -and $Value -isnot [System.Array])
}

function Test-JsonArray {
  [CmdletBinding()]
  [OutputType([bool])]
  param([AllowNull()]$Value)
  return ($null -ne $Value -and $Value -is [System.Array])
}

function Get-ProfileValidationDocument {
  [CmdletBinding()]
  [OutputType([object])]
  param([Parameter(Mandatory)][string]$Path)

  Assert-NoPathTraversal -Path $Path -ParameterName 'ProfilePath'
  if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { throw "Profile file not found: $Path" }
  $raw = Get-BoundedUtf8FileContent -Path $Path -MaximumBytes 1048576
  if ([string]::IsNullOrWhiteSpace($raw)) { throw 'Profile file is empty.' }
  try { $document = $raw | ConvertFrom-Json -ErrorAction Stop }
  catch { throw "Profile JSON is invalid: $($_.Exception.Message)" }
  return [pscustomobject]@{ Document = $document; ContentSha256 = Get-TextSha256 -Text $raw }
}

function Test-ProfileValidationRequiredFields {
  [CmdletBinding()]
  param([AllowNull()]$Document)

  if (-not (Test-JsonObject -Value $Document)) { Add-Issue -Severity 'High' -Code 'PROFILE-ROOT-TYPE' -Message 'Profile JSON root must be an object.' }
  foreach ($required in @('ProfileName','Version','Defaults','Steps','Integrity')) {
    if (-not (Has-Property -Object $Document -Name $required)) { Add-Issue -Severity 'High' -Code 'PROFILE-MISSING-FIELD' -Message "Missing required field '$required'." }
  }
}

function Test-ProfileValidationDefaultMode {
  [CmdletBinding()]
  param($Defaults)
  if (-not (Has-Property -Object $Defaults -Name 'Mode')) { Add-Issue -Severity 'High' -Code 'PROFILE-DEFAULTS-MODE' -Message 'Defaults.Mode is required.'; return }
  if (@('Audit','Remediate') -notcontains [string]$Defaults.Mode) { Add-Issue -Severity 'High' -Code 'PROFILE-DEFAULTS-MODE-VALUE' -Message 'Defaults.Mode must be Audit or Remediate.' }
}

function Test-ProfileValidationDefaultOptions {
  [CmdletBinding()]
  param($Defaults)
  if ((Has-Property -Object $Defaults -Name 'OutputFormat') -and @('Console','Json','Csv','None') -notcontains [string]$Defaults.OutputFormat) { Add-Issue -Severity 'High' -Code 'PROFILE-DEFAULTS-OUTPUTFORMAT' -Message 'Defaults.OutputFormat must be Console, Json, Csv, or None.' }
  if ((Has-Property -Object $Defaults -Name 'Strict') -and $Defaults.Strict -isnot [bool]) { Add-Issue -Severity 'High' -Code 'PROFILE-DEFAULTS-STRICT-TYPE' -Message 'Defaults.Strict must be a JSON boolean.' }
}

function Test-ProfileValidationDefaults {
  [CmdletBinding()]
  param([AllowNull()]$Document)

  if (-not (Has-Property -Object $Document -Name 'Defaults')) { return }
  $defaults = $Document.Defaults
  if (-not (Test-JsonObject -Value $defaults)) { Add-Issue -Severity 'High' -Code 'PROFILE-DEFAULTS-TYPE' -Message 'Defaults must be an object.'; return }
  Test-ProfileValidationDefaultMode -Defaults $defaults
  Test-ProfileValidationDefaultOptions -Defaults $defaults
}

function Get-ProfileValidationScriptsBasePath {
  [CmdletBinding()]
  [OutputType([string])]
  param([string]$CandidateRoot)

  if ([string]::IsNullOrWhiteSpace($CandidateRoot)) { return $script:validateProfileScriptsRoot }
  if (Test-Path -LiteralPath (Join-Path $CandidateRoot 'scripts') -PathType Container) { return Join-Path $CandidateRoot 'scripts' }
  return $CandidateRoot
}

function Test-ProfileValidationArgument {
  [CmdletBinding()]
  param($Argument, [Parameter(Mandatory)][int]$StepIndex, [Parameter(Mandatory)][int]$ArgumentIndex)
  if ($null -eq $Argument -or $Argument -isnot [string]) { Add-Issue -Severity 'High' -Code 'PROFILE-STEP-ARGS-TYPE' -Message "Step #$StepIndex contains non-string Args value at position $ArgumentIndex."; return }
  if ([string]::IsNullOrWhiteSpace($Argument)) { Add-Issue -Severity 'High' -Code 'PROFILE-STEP-ARGS-EMPTY' -Message "Step #$StepIndex contains an empty Args token at position $ArgumentIndex." }
  if ([string]$Argument -ieq '-Remediate') { Add-Issue -Severity 'Medium' -Code 'PROFILE-STEP-ARGS-LEGACY-REMEDIATE' -Message "Step #$StepIndex uses removed legacy token '-Remediate'. Use '-Mode Remediate' instead." }
}

function Test-ProfileValidationStepArguments {
  [CmdletBinding()]
  param($Step, [Parameter(Mandatory)][int]$Index)

  if (-not ((Has-Property -Object $Step -Name 'Args') -and $null -ne $Step.Args)) { return }
  if (-not (Test-JsonArray -Value $Step.Args)) { Add-Issue -Severity 'High' -Code 'PROFILE-STEP-ARGS-ARRAY' -Message "Step #$Index Args must be a JSON array."; return }
  if (@($Step.Args).Count -gt 0) { Add-Issue -Severity 'High' -Code 'PROFILE-STEP-ARGS-NOT-ALLOWED' -Message "Step #$Index Args must be empty. Profile JSON cannot supply step arguments; use a trusted direct runner invocation for advanced arguments." }
  $argumentIndex = 0
  foreach ($argument in @($Step.Args)) {
    $argumentIndex++
    Test-ProfileValidationArgument -Argument $argument -StepIndex $Index -ArgumentIndex $argumentIndex
  }
}

function Test-ProfileValidationStepDependencies {
  [CmdletBinding()]
  param($Step, [Parameter(Mandatory)][int]$Index)

  if ((Has-Property -Object $Step -Name 'DependsOn') -and $null -ne $Step.DependsOn) {
    if (-not (Test-JsonArray -Value $Step.DependsOn)) { Add-Issue -Severity 'High' -Code 'PROFILE-STEP-DEPENDS-TYPE' -Message "Step #$Index DependsOn must be a JSON array." }
    else { foreach ($dependency in @($Step.DependsOn)) { if ($dependency -isnot [string] -or [string]::IsNullOrWhiteSpace([string]$dependency)) { Add-Issue -Severity 'High' -Code 'PROFILE-STEP-DEPENDS-VALUE' -Message "Step #$Index contains a non-string or empty DependsOn value." } } }
  }
}

function Test-ProfileValidationStepScript {
  [CmdletBinding()]
  [OutputType([string])]
  param($Step, [Parameter(Mandatory)][int]$Index, [Parameter(Mandatory)][string]$ScriptsBasePath)
  $scriptName = [string]$Step.Script
  if (-not (Test-SafeScriptName -Name $scriptName)) { Add-Issue -Severity 'High' -Code 'PROFILE-STEP-SCRIPT-NAME' -Message "Step #$Index uses unsafe script name '$scriptName'."; return $scriptName }
  if ($scriptName -match '^00-') { Add-Issue -Severity 'High' -Code 'PROFILE-STEP-CONTROL-PLANE' -Message "Step #$Index references control-plane script '$scriptName'. Profiles may execute numbered workload scripts only."; return $scriptName }
  if (-not (Test-Path -LiteralPath (Join-Path $ScriptsBasePath $scriptName) -PathType Leaf)) { Add-Issue -Severity 'High' -Code 'PROFILE-STEP-SCRIPT-NOT-FOUND' -Message "Step #$Index references script '$scriptName' that does not exist under scripts/." }
  return $scriptName
}

function Test-ProfileValidationStep {
  [CmdletBinding()]
  [OutputType([string])]
  param($Step, [Parameter(Mandatory)][int]$Index, [Parameter(Mandatory)][string]$ScriptsBasePath)

  if (-not (Test-JsonObject -Value $Step)) { Add-Issue -Severity 'High' -Code 'PROFILE-STEP-TYPE' -Message "Step #$Index must be an object."; return $null }
  if (-not (Has-Property -Object $Step -Name 'Script')) { Add-Issue -Severity 'High' -Code 'PROFILE-STEP-SCRIPT' -Message "Step #$Index is missing Script."; return $null }
  $scriptName = Test-ProfileValidationStepScript -Step $Step -Index $Index -ScriptsBasePath $ScriptsBasePath
  Test-ProfileValidationStepArguments -Step $Step -Index $Index
  Test-ProfileValidationStepDependencies -Step $Step -Index $Index
  if ((Has-Property -Object $Step -Name 'ContinueOnError') -and $Step.ContinueOnError -isnot [bool]) { Add-Issue -Severity 'High' -Code 'PROFILE-STEP-CONTINUE-TYPE' -Message "Step #$Index ContinueOnError must be a JSON boolean." }
  return $scriptName
}

function Test-ProfileValidationDependencyReferences {
  [CmdletBinding()]
  param([Parameter(Mandatory)][object[]]$Steps, [Parameter(Mandatory)][string[]]$KnownNames)
  $index = 0
  foreach ($step in $Steps) {
    $index++
    if ((Has-Property -Object $step -Name 'DependsOn') -and $null -ne $step.DependsOn) { foreach ($dependency in @($step.DependsOn)) { if (-not [string]::IsNullOrWhiteSpace([string]$dependency) -and $KnownNames -notcontains [string]$dependency) { Add-Issue -Severity 'High' -Code 'PROFILE-STEP-DEPENDS-NOT-FOUND' -Message "Step #$index depends on unknown script '$dependency'." } } }
  }
}

function Test-ProfileValidationSteps {
  [CmdletBinding()]
  param([AllowNull()]$Document, [Parameter(Mandatory)][string]$ScriptsBasePath)

  if (-not (Has-Property -Object $Document -Name 'Steps')) { return }
  if (-not (Test-JsonArray -Value $Document.Steps)) { Add-Issue -Severity 'High' -Code 'PROFILE-STEPS-TYPE' -Message 'Steps must be a JSON array.'; return }
  $knownNames = @(); $seenNames = @{}; $index = 0
  foreach ($step in @($Document.Steps)) {
    $index++; $scriptName = Test-ProfileValidationStep -Step $step -Index $index -ScriptsBasePath $ScriptsBasePath
    if ($null -eq $scriptName) { continue }
    if ($seenNames.ContainsKey($scriptName)) { Add-Issue -Severity 'High' -Code 'PROFILE-STEP-DUPLICATE' -Message "Duplicate step script '$scriptName' is not allowed." } else { $seenNames[$scriptName] = $true }
    $knownNames += $scriptName
  }
  Test-ProfileValidationDependencyReferences -Steps @($Document.Steps) -KnownNames $knownNames
}

function Test-ProfileValidationExpectedHashes {
  [CmdletBinding()]
  param($Integrity)
  if (-not ((Has-Property -Object $Integrity -Name 'ExpectedHashes') -and $null -ne $Integrity.ExpectedHashes)) { return }
  if (-not (Test-JsonObject -Value $Integrity.ExpectedHashes)) { Add-Issue -Severity 'High' -Code 'PROFILE-HASHES-TYPE' -Message 'Integrity.ExpectedHashes must be an object.'; return }
  foreach ($property in $Integrity.ExpectedHashes.PSObject.Properties) {
    if (-not (Test-SafeScriptName -Name $property.Name)) { Add-Issue -Severity 'High' -Code 'PROFILE-HASH-KEY' -Message "Integrity.ExpectedHashes contains unsafe key '$($property.Name)'." }
    if ([string]::IsNullOrWhiteSpace([string]$property.Value)) { Add-Issue -Severity 'Medium' -Code 'PROFILE-HASH-VALUE' -Message "Integrity.ExpectedHashes for '$($property.Name)' is empty." }
  }
}

function Test-ProfileValidationIntegrity {
  [CmdletBinding()]
  param([AllowNull()]$Document)

  if (-not (Has-Property -Object $Document -Name 'Integrity')) { return }
  $integrity = $Document.Integrity
  if (-not (Test-JsonObject -Value $integrity)) { Add-Issue -Severity 'High' -Code 'PROFILE-INTEGRITY-TYPE' -Message 'Integrity must be an object.'; return }
  if ((Has-Property -Object $integrity -Name 'RequireSigned') -and $integrity.RequireSigned -isnot [bool]) { Add-Issue -Severity 'High' -Code 'PROFILE-INTEGRITY-SIGNED-TYPE' -Message 'Integrity.RequireSigned must be a JSON boolean.' }
  Test-ProfileValidationExpectedHashes -Integrity $integrity
}

function Invoke-ValidateProfile {
  [CmdletBinding()]
  param()

  try {
    $documentRecord = Get-ProfileValidationDocument -Path $ProfilePath
    $profileDocument = $documentRecord.Document
    Test-ProfileValidationRequiredFields -Document $profileDocument
    Test-ProfileValidationDefaults -Document $profileDocument
    Test-ProfileValidationSteps -Document $profileDocument -ScriptsBasePath (Get-ProfileValidationScriptsBasePath -CandidateRoot $RootPath)
    Test-ProfileValidationIntegrity -Document $profileDocument
    Write-ProfileValidationSuccess -ContentSha256 $documentRecord.ContentSha256
  } catch {
    $message = $_.Exception.Message
    Write-UiLine -Text ("Validation failed: {0}" -f $message) -Style Error
    Write-ValidationFailureResult -Code (Get-ValidationExceptionCode -Message $message) -Message $message
    exit (Get-V2ExitCode -Result 'FAIL')
  }
}

function Write-ProfileValidationConsoleSummary {
  [CmdletBinding()]
  param([Parameter(Mandatory)]$Summary)
  Write-Section -Title 'Profile Validation'
  Write-KeyValue -Key 'Profile' -Value $Summary.ProfilePath
  Write-KeyValue -Key 'Issues' -Value $Summary.Issues
  Write-KeyValue -Key 'High' -Value $Summary.HighIssues
  Write-KeyValue -Key 'Warnings' -Value $Summary.Warnings
  if ($script:issues.Count -gt 0) { Write-UiLine -Text 'Findings:' -ForegroundColor Yellow; foreach ($issue in $script:issues) { Write-UiLine -Text ("[{0}] {1} - {2}" -f $issue.Severity.ToUpperInvariant(), $issue.Code, $issue.Message) -ForegroundColor Gray } }
}

function Write-ProfileValidationSuccess {
  [CmdletBinding()]
  param([Parameter(Mandatory)][string]$ContentSha256)

  $highCount = @($script:issues | Where-Object { $_.Severity -in @('High','Critical') }).Count
  $warnCount = @($script:issues | Where-Object { $_.Severity -in @('Medium','Low') }).Count
  $resultToken = if ($highCount -gt 0) { 'FAIL' } elseif ($warnCount -gt 0) { 'WARN' } else { 'OK' }
  if ($Strict -and $resultToken -eq 'WARN') { $resultToken = 'FAIL' }
  $summary = [pscustomobject]@{ ProfilePath = (Resolve-Path -LiteralPath $ProfilePath).Path; Issues = $script:issues.Count; HighIssues = $highCount; Warnings = $warnCount }
  $resultObject = Get-V2ResultObject -ScriptName '00-Validate-Profile.ps1' -Mode $Mode -Result $resultToken -Findings (ConvertTo-ObjectArray -InputObject $script:issues) -Summary $summary -Metadata @{ Component = 'ProfileValidation'; ProfileContentSha256 = $ContentSha256 }
  if ($OutputFormat -eq 'Console') { Write-ProfileValidationConsoleSummary -Summary $summary }
  Write-ResultObject -ResultObject $resultObject -OutputFormat $OutputFormat -OutputPath $OutputPath
  if ($PassThru) { $resultObject }
  exit (Get-V2ExitCode -Result $resultToken)
}
