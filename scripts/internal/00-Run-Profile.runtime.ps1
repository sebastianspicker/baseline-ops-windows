#requires -version 5.1
<#
.SYNOPSIS
Validates and prepares one profile run.
.DESCRIPTION
Creates explicit runner state, validates immutable profile input, and coordinates scheduling and result construction.
#>
function Get-RunProfileBoundValue {
  param($BoundParameters, [string]$Name, $Default)

  if ($BoundParameters.ContainsKey($Name)) {
    return $BoundParameters[$Name]
  }
  return $Default
}

function New-RunProfileOptions {
  param(
    $BoundParameters,
    [string]$ParameterSetName,
    [string]$RootPath,
    [bool]$PreviewOnly
  )

  return [pscustomobject]@{
    BoundParameters = $BoundParameters
    ParameterSetName = $ParameterSetName
    ProfilePath = Get-RunProfileBoundValue $BoundParameters 'ProfilePath' $null
    Mode = Get-RunProfileBoundValue $BoundParameters 'Mode' 'Audit'
    RootPath = $RootPath
    OutputFormat = Get-RunProfileBoundValue $BoundParameters 'OutputFormat' 'Console'
    OutputPath = Get-RunProfileBoundValue $BoundParameters 'OutputPath' $null
    PassThru = [bool](Get-RunProfileBoundValue $BoundParameters 'PassThru' $false)
    Strict = [bool](Get-RunProfileBoundValue $BoundParameters 'Strict' $false)
    RequireSigned = [bool](Get-RunProfileBoundValue $BoundParameters 'RequireSigned' $false)
    ConfigPath = Get-RunProfileBoundValue $BoundParameters 'ConfigPath' $null
    Quiet = [bool](Get-RunProfileBoundValue $BoundParameters 'Quiet' $false)
    NoColor = [bool](Get-RunProfileBoundValue $BoundParameters 'NoColor' $false)
    WhatIf = $PreviewOnly
    ConfirmBound = $BoundParameters.ContainsKey('Confirm')
    Confirm = [bool](Get-RunProfileBoundValue $BoundParameters 'Confirm' $false)
  }
}

function New-RunProfileState {
  param($Options)

  return [pscustomobject]@{
    Validation = $null
    ValidationExitCode = $null
    ValidationWarned = $false
    ValidatedProfileHash = $null
    ProfileDocument = $null
    ProfileStrict = $Options.Strict
    ProfileRequireSigned = $Options.RequireSigned
    ExpectedHashes = @{}
    DeclaredStepCount = 0
    Results = [System.Collections.Generic.List[object]]::new()
    StepStatus = @{}
    Pending = [System.Collections.Generic.List[object]]::new()
    Findings = [System.Collections.Generic.List[object]]::new()
    DependencyCycleDetected = $false
    DependencyCycleScripts = @()
  }
}

function New-RunProfileTerminal {
  param(
    [Parameter(Mandatory)]$ResultObject,
    [Parameter(Mandatory)][string]$OutputFormat,
    [AllowNull()][string]$OutputPath
  )

  return [pscustomobject]@{
    ResultObject = $ResultObject
    OutputFormat = $OutputFormat
    OutputPath = $OutputPath
    ExitCode = Get-V2ExitCode -Result ([string]$ResultObject.Result)
    IsRunProfileTerminal = $true
  }
}

function New-RunProfileFailureTerminal {
  param(
    $Options,
    [string]$Code,
    [string]$Message,
    [AllowNull()]$ValidationResult
  )

  $result = New-RunProfileFailureResult `
    -Options $Options `
    -Code $Code `
    -Message $Message `
    -ValidationResult $ValidationResult
  return New-RunProfileTerminal `
    -ResultObject $result `
    -OutputFormat $Options.OutputFormat `
    -OutputPath $Options.OutputPath
}

function Test-RunProfileTerminal {
  param($Value)

  return [bool](
    $null -ne $Value -and
    $Value.PSObject.Properties.Name -contains 'IsRunProfileTerminal' -and
    $Value.IsRunProfileTerminal
  )
}

function Initialize-RunProfileContext {
  param($Options)

  Set-StrictMode -Version Latest
  $script:__V2Context = Initialize-V2Context `
    -ScriptName '00-Run-Profile.ps1' `
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

function Test-RunProfileControlFiles {
  param($Options, $Bootstrap)

  if (-not (Test-Path -LiteralPath $Bootstrap.ValidatorPath -PathType Leaf)) {
    return New-RunProfileFailureTerminal `
      -Options $Options `
      -Code 'Profile-MissingValidator' `
      -Message "Missing validator script: $($Bootstrap.ValidatorPath)"
  }
  if (-not (Test-Path -LiteralPath $Bootstrap.RunLocalPath -PathType Leaf)) {
    return New-RunProfileFailureTerminal `
      -Options $Options `
      -Code 'Profile-MissingRunner' `
      -Message "Missing Run-Local script: $($Bootstrap.RunLocalPath)"
  }
  return $null
}

function Invoke-RunProfileValidation {
  param($Options, $State, $Bootstrap)

  $State.Validation = Invoke-RunProfileValidator $Bootstrap $Options
  $State.ValidationExitCode = $LASTEXITCODE
  if ($State.ValidationExitCode -eq 0) {
    return Test-RunProfileValidationHash $Options $State
  }
  if ($State.ValidationExitCode -eq 2) {
    Write-Warning "Profile validation produced warnings: $($Options.ProfilePath)"
    if (-not $Options.Strict) {
      return Test-RunProfileValidationHash $Options $State
    }
    return New-RunProfileFailureTerminal `
      -Options $Options `
      -Code 'Profile-StrictValidationWarning' `
      -Message "Profile validation produced warnings (strict mode): $($Options.ProfilePath)" `
      -ValidationResult $State.Validation
  }
  return New-RunProfileFailureTerminal `
    -Options $Options `
    -Code 'Profile-ValidationFailed' `
    -Message "Profile validation failed: $($Options.ProfilePath)" `
    -ValidationResult $State.Validation
}

function Test-RunProfileValidationHash {
  param($Options, $State)

  $hash = ''
  if ($null -ne $State.Validation -and
      (Has-Property -Object $State.Validation -Name 'Metadata') -and
      $null -ne $State.Validation.Metadata -and
      (Has-Property -Object $State.Validation.Metadata -Name 'ProfileContentSha256')) {
    $hash = [string]$State.Validation.Metadata.ProfileContentSha256
  }
  if ($hash -notmatch '^[A-Fa-f0-9]{64}$') {
    return New-RunProfileFailureTerminal `
      -Options $Options `
      -Code 'Profile-MissingValidationHash' `
      -Message 'Profile validator did not return a valid content hash.' `
      -ValidationResult $State.Validation
  }
  $State.ValidatedProfileHash = $hash
  return $null
}

function Read-RunProfileDocument {
  param($Options, $State)

  try {
    $profileRaw = Get-BoundedUtf8FileContent -Path $Options.ProfilePath -MaximumBytes 1048576
  } catch {
    return New-RunProfileFailureTerminal `
      -Options $Options `
      -Code 'Profile-ReadFailed' `
      -Message "Profile read failed: $($_.Exception.Message)" `
      -ValidationResult $State.Validation
  }
  $actualHash = Get-TextSha256 -Text $profileRaw
  if (-not $actualHash.Equals($State.ValidatedProfileHash, [System.StringComparison]::OrdinalIgnoreCase)) {
    return New-RunProfileFailureTerminal `
      -Options $Options `
      -Code 'Profile-ChangedAfterValidation' `
      -Message 'Profile content changed after validation.' `
      -ValidationResult $State.Validation
  }
  $State.ProfileDocument = $profileRaw | ConvertFrom-Json -ErrorAction Stop
  return Test-RunProfileStepArguments $Options $State
}

function Test-RunProfileStepArguments {
  param($Options, $State)

  $stepWithArguments = $State.ProfileDocument.Steps | Where-Object {
    (Has-Property -Object $_ -Name 'Args') -and
    $null -ne $_.Args -and
    @($_.Args).Count -gt 0
  } | Select-Object -First 1
  if ($null -eq $stepWithArguments) {
    return $null
  }
  return New-RunProfileFailureTerminal `
    -Options $Options `
    -Code 'Profile-StepArgsNotAllowed' `
    -Message "Profile step '$([string]$stepWithArguments.Script)' contains Args. Profile JSON cannot supply step arguments; use a trusted direct runner invocation for advanced arguments." `
    -ValidationResult $State.Validation
}

function Initialize-RunProfilePolicy {
  param($Options, $State)

  $document = $State.ProfileDocument
  $defaults = if (Has-Property -Object $document -Name 'Defaults') {
    $document.Defaults
  } else {
    [pscustomobject]@{}
  }
  $integrity = if (Has-Property -Object $document -Name 'Integrity') {
    $document.Integrity
  } else {
    [pscustomobject]@{}
  }
  Write-RunProfileIgnoredDefaults $Options $defaults
  Set-RunProfileIntegrityPolicy $Options $State $defaults $integrity
  Initialize-RunProfileCollections $State $document
}

function Set-RunProfileIntegrityPolicy {
  param($Options, $State, $Defaults, $Integrity)

  if (Has-Property -Object $Integrity -Name 'ExpectedHashes') {
    $State.ExpectedHashes = ConvertTo-Hashtable -Object $Integrity.ExpectedHashes
  }
  $State.ProfileStrict = [bool](
    $Options.Strict -or
    ((Has-Property -Object $Defaults -Name 'Strict') -and $Defaults.Strict)
  )
  $State.ProfileRequireSigned = [bool](
    $Options.RequireSigned -or
    ((Has-Property -Object $Integrity -Name 'RequireSigned') -and $Integrity.RequireSigned)
  )
}

function Initialize-RunProfileCollections {
  param($State, $Document)

  $State.DeclaredStepCount = @($Document.Steps).Count
  $State.ValidationWarned = [bool](
    $State.ValidationExitCode -eq 2 -or
    [string]$State.Validation.Result -eq 'WARN'
  )
  foreach ($step in @($Document.Steps)) {
    [void]$State.Pending.Add($step)
  }
  foreach ($finding in @($State.Validation.Findings)) {
    [void]$State.Findings.Add($finding)
  }
}

function Write-RunProfileIgnoredDefaults {
  param($Options, $Defaults)

  Write-RunProfileIgnoredMode $Options $Defaults
  Write-RunProfileIgnoredOutputFormat $Options $Defaults
  Write-RunProfileIgnoredOutputPath $Options $Defaults
}

function Write-RunProfileIgnoredMode {
  param($Options, $Defaults)

  if (-not $Options.BoundParameters.ContainsKey('Mode') -and
      (Has-Property -Object $Defaults -Name 'Mode') -and
      [string]$Defaults.Mode -eq 'Remediate') {
    Write-Warning "Ignoring profile Defaults.Mode='Remediate'. Pass -Mode Remediate on the runner CLI to remediate."
  }
}

function Write-RunProfileIgnoredOutputFormat {
  param($Options, $Defaults)

  if (-not $Options.BoundParameters.ContainsKey('OutputFormat') -and
      (Has-Property -Object $Defaults -Name 'OutputFormat') -and
      -not [string]::IsNullOrWhiteSpace([string]$Defaults.OutputFormat)) {
    Write-Warning 'Ignoring profile Defaults.OutputFormat. Pass -OutputFormat on the runner CLI to change output format.'
  }
}

function Write-RunProfileIgnoredOutputPath {
  param($Options, $Defaults)

  if (-not $Options.BoundParameters.ContainsKey('OutputPath') -and
      (Has-Property -Object $Defaults -Name 'OutputPath') -and
      -not [string]::IsNullOrWhiteSpace([string]$Defaults.OutputPath)) {
    Write-Warning 'Ignoring profile Defaults.OutputPath. Pass -OutputPath on the runner CLI to write result output.'
  }
}

function Write-RunProfileHeader {
  param($Options, $State)

  Write-Section -Title ("Run Profile: {0}" -f $State.ProfileDocument.ProfileName)
  Write-KeyValue -Key 'ProfilePath' -Value (Resolve-Path -LiteralPath $Options.ProfilePath).Path
  Write-KeyValue -Key 'Mode' -Value $Options.Mode
  Write-KeyValue -Key 'Strict' -Value $State.ProfileStrict
  Write-KeyValue -Key 'RequireSigned' -Value $State.ProfileRequireSigned
}

function Invoke-RunProfile {
  param($Options, $Bootstrap)

  Initialize-RunProfileContext $Options
  $state = New-RunProfileState $Options
  $terminal = Test-RunProfileControlFiles $Options $Bootstrap
  if (Test-RunProfileTerminal $terminal) {
    return $terminal
  }
  $terminal = Invoke-RunProfileValidation $Options $state $Bootstrap
  if (Test-RunProfileTerminal $terminal) {
    return $terminal
  }
  $terminal = Read-RunProfileDocument $Options $state
  if (Test-RunProfileTerminal $terminal) {
    return $terminal
  }
  Initialize-RunProfilePolicy $Options $state
  Write-RunProfileHeader $Options $state
  Invoke-RunProfileSchedule $Options $state $Bootstrap
  return New-RunProfileResultTerminal $Options $state
}
