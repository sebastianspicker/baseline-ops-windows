#requires -version 5.1
<#
.SYNOPSIS
Runs supported v2 policy comparisons for the shared Rust v3 behavioral cases.

.DESCRIPTION
Provides Pester helpers for bounded executable comparisons of selected actual
PowerShell v2 policy functions. Structural source-closure bindings are verified
by the Rust workspace (`cargo run -p xtask -- verify`), not by this adapter.
#>

Set-StrictMode -Version Latest

function Get-RustV3OracleProperty {
  [OutputType([object])]
  param([Parameter(Mandatory)] [object]$Value, [Parameter(Mandatory)] [string]$Name)

  if ($Value -is [System.Collections.IDictionary]) {
    if ($Value.Contains($Name)) { return $Value[$Name] }
    return $null
  }
  $property = $Value.PSObject.Properties[$Name]
  if ($null -eq $property) { return $null }
  return $property.Value
}

function Test-RustV3OraclePropertyExists {
  [OutputType([bool])]
  param([Parameter(Mandatory)] [object]$Value, [Parameter(Mandatory)] [string]$Name)

  if ($Value -is [System.Collections.IDictionary]) { return $Value.Contains($Name) }
  return $null -ne $Value.PSObject.Properties[$Name]
}

function Get-RustV3OracleDocuments {
  [OutputType([pscustomobject])]
  param([string]$RepositoryRoot = (Join-Path $PSScriptRoot '../..'))

  $root = (Resolve-Path -LiteralPath $RepositoryRoot).Path
  [pscustomobject]@{
    RepositoryRoot = $root
    Behavioral = Get-Content -LiteralPath (Join-Path $root 'rust/oracles/v2-rust-behavioral-cases.json') -Raw -Encoding UTF8 | ConvertFrom-Json
  }
}

function Invoke-RustV3OracleV2DohPolicy {
  [OutputType([pscustomobject])]
  param([Parameter(Mandatory)] $Observation, [string]$RepositoryRoot = (Join-Path $PSScriptRoot '../..'))

  $script:RustV3OracleObservation = $Observation
  $scriptPath = Join-Path $RepositoryRoot 'scripts/52-DoH-Audit.ps1'
  $tokens = $null
  $parseErrors = $null
  $ast = [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$tokens, [ref]$parseErrors)
  if ($parseErrors.Count -gt 0) { throw "DoH v2 policy source does not parse." }
  $names = @('Invoke-Capability52MainPhase01', 'Invoke-Capability52MainPhase02', 'Invoke-Capability52MainPhase03', 'Invoke-Capability52MainPhase04', 'Invoke-Capability52MainPhase05')
  $definitions = foreach ($name in $names) {
    $functionAst = @($ast.FindAll({ param($Node) $Node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $Node.Name -eq $name }, $true))
    if ($functionAst.Count -ne 1) { throw "DoH v2 policy function is missing or duplicated: $name" }
    $functionAst[0].Extent.Text
  }
  . ([scriptblock]::Create(($definitions -join "`n")))

  function Get-FindingsList { return ,(New-Object System.Collections.ArrayList) }
  function Add-Finding {
    param($FindingList, $Code, $Severity, $Message)
    [void]$FindingList.Add([pscustomobject]@{ Code = $Code; Severity = $Severity; Message = $Message })
  }
  function Get-RegValue {
    param($Path, $Name, $ErrorAction)
    $null = $Path
    $null = $ErrorAction
    switch ($Name) {
      'EnableAutoDoh' { return $script:RustV3OracleObservation.enable_auto_doh }
      'DohNameServers' {
        $values = @($script:RustV3OracleObservation.name_servers)
        if ($values.Count -eq 0) { return $null }
        return ($values -join ' ')
      }
      'ServerAddresses' {
        $values = @($script:RustV3OracleObservation.bootstrap_addresses)
        if ($values.Count -eq 0) { return $null }
        return ($values -join ' ')
      }
      'BlockUntrustedDoh' { return $script:RustV3OracleObservation.block_untrusted_doh }
    }
  }

  $runState = @{}
  Invoke-Capability52MainPhase01 -RunState $runState
  Invoke-Capability52MainPhase02 -RunState $runState
  Invoke-Capability52MainPhase03 -RunState $runState
  Invoke-Capability52MainPhase04 -RunState $runState
  Invoke-Capability52MainPhase05 -RunState $runState
  [pscustomobject]@{ Mode = $runState.dohModeLabel; FindingCodes = @($script:Findings | ForEach-Object Code) }
}

function Import-RustV3OracleWufbFunctions {
  param([string]$RepositoryRoot)
  $sources = @(
    @{ Path = 'scripts/internal/05-WUFB-Proofing.helpers.ps1'; Names = @('Set-WufbDword', 'Set-REGSZ', 'Remove-REGValue', 'Add-Result') },
    @{ Path = 'scripts/internal/05-WUFB-Proofing.runtime.ps1'; Names = @('Set-WufbUpdateSource', 'Get-WufbConfiguredDay', 'Get-WufbDeferralDays', 'Set-WufbDeferrals', 'Set-WufbTargetRelease', 'Set-WufbOptionalPolicies') }
  )
  foreach ($source in $sources) {
    $tokens = $null; $parseErrors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $RepositoryRoot $source.Path), [ref]$tokens, [ref]$parseErrors)
    if ($parseErrors.Count -gt 0) { throw "WUfB v2 policy source does not parse: $($source.Path)" }
    foreach ($name in $source.Names) {
      $functionAst = @($ast.FindAll({ param($Node) $Node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $Node.Name -eq $name }, $true))
      if ($functionAst.Count -ne 1) { throw "WUfB v2 policy function is missing or duplicated: $name" }
      $functionAst[0].Extent.Text
    }
  }
}

function Get-RustV3OracleWufbFieldName {
  param([string]$Name)
  $fields = @{ UseWUServer = 'use_wsus'; WUServer = 'wsus_server'; WUStatusServer = 'wsus_status_server'
    DeferFeatureUpdates = 'defer_feature_updates'; DeferFeatureUpdatesPeriodInDays = 'defer_feature_days'
    DeferQualityUpdates = 'defer_quality_updates'; DeferQualityUpdatesPeriodInDays = 'defer_quality_days'
    TargetReleaseVersion = 'target_release_version'; ProductVersion = 'product_version'
    TargetReleaseVersionInfo = 'target_release_version_info'; DODownloadMode = 'delivery_optimization_mode' }
  return $fields[$Name]
}

function ConvertFrom-RustV3OracleSnapshot {
  param($Snapshot)
  if ($null -eq $Snapshot -or $Snapshot.status -eq 'missing') { return $null }
  return $Snapshot.value
}

function Get-RustV3OracleWufbCatalog {
  param($Case)
  $modes = @{ http_only = 0; lan = 1; group = 2; internet = 3; simple = 99 }
  $overrides = Get-RustV3OracleProperty $Case 'v2_overrides'
  $wsusServer = $null; $wsusStatusServer = $null
  if ($null -ne $overrides) {
    $wsusServer = Get-RustV3OracleProperty $overrides 'wsus_server'
    $wsusStatusServer = Get-RustV3OracleProperty $overrides 'wsus_status_server'
  }
  $updateSource = $(if ($Case.desired.update_source -eq 'wsus') { 'WSUS' } else { 'WUfB' })
  [pscustomobject]@{
    UpdateSource = $updateSource
    WSUS = [pscustomobject]@{ WUServer = $wsusServer; WUStatusServer = $wsusStatusServer }
    AllowMU = $Case.desired.allow_microsoft_update
    Deferrals = [pscustomobject]@{ FeatureDays = $Case.desired.deferrals.feature_days; QualityDays = $Case.desired.deferrals.quality_days }
    TargetRelease = [pscustomobject]@{ Enable = $Case.desired.target_release.enabled; ProductVersion = $Case.desired.target_release.product_version; TargetReleaseVersionInfo = $Case.desired.target_release.release }
    DeliveryOptimization = [pscustomobject]@{ DownloadMode = $modes[[string]$Case.desired.delivery_optimization.download_mode] }
    ActiveHours = $null
  }
}

function ConvertTo-RustV3OracleWufbMutation {
  param($Operation)
  $field = Get-RustV3OracleWufbFieldName -Name $Operation.Name
  $kind = $(if ($field -in @('wsus_server', 'wsus_status_server', 'product_version', 'target_release_version_info')) { 'string' } else { 'dword' })
  $current = $(if ($null -eq $Operation.Current) { [ordered]@{ status = 'missing' } } else { [ordered]@{ status = $kind; value = $Operation.Current } })
  $desired = $(if ($null -eq $Operation.Desired) { [ordered]@{ status = 'missing' } } else { [ordered]@{ status = $kind; value = $Operation.Desired } })
  [pscustomobject][ordered]@{ field = $field; current = $current; desired = $desired }
}

function Invoke-RustV3OracleV2WufbPolicy {
  [OutputType([pscustomobject])]
  param([Parameter(Mandatory)] $Case, [string]$RepositoryRoot = (Join-Path $PSScriptRoot '../..'))
  $definitions = @(Import-RustV3OracleWufbFunctions -RepositoryRoot $RepositoryRoot)
  . ([scriptblock]::Create(($definitions -join "`n")))
  $script:RustV3OracleWufbObservation = $Case.observation
  function Get-REG {
    param($Path, $Name)
    $null = $Path
    $field = Get-RustV3OracleWufbFieldName -Name $Name
    return ConvertFrom-RustV3OracleSnapshot -Snapshot (Get-RustV3OracleProperty $script:RustV3OracleWufbObservation $field)
  }
  $state = [pscustomobject]@{ Ok = $true; Operations = [Collections.Generic.List[object]]::new(); Changes = [Collections.Generic.List[string]]::new(); Drifts = [Collections.Generic.List[string]]::new(); Notes = [Collections.Generic.List[string]]::new(); Proof = [ordered]@{ Settings = [ordered]@{} } }
  $catalog = Get-RustV3OracleWufbCatalog -Case $Case
  $remediate = $Case.execution_mode -eq 'remediation_denied'
  $WhatIfPreference = $remediate
  Set-WufbUpdateSource $state $catalog $remediate 'WU' 'AU'
  Set-WufbDeferrals $state $catalog $remediate 'WU'
  Set-WufbTargetRelease $state $catalog $remediate 'WU'
  Set-WufbOptionalPolicies $state $catalog $remediate 'DO'
  $WhatIfPreference = $false
  $mutations = @($state.Operations | Where-Object Drift | ForEach-Object { ConvertTo-RustV3OracleWufbMutation $_ } | Sort-Object field)
  [pscustomobject]@{ Mutations = $mutations; Actions = @($state.Operations | ForEach-Object Action | Sort-Object -Unique); DriftActions = @($state.Operations | Where-Object Drift | ForEach-Object Action | Sort-Object -Unique); Notes = @($state.Notes) }
}

function Add-RustV3OracleWufbCaseErrors {
  param($Case, $RepositoryRoot, $Errors)
  $actual = Invoke-RustV3OracleV2WufbPolicy -Case $Case -RepositoryRoot $RepositoryRoot
  Add-RustV3OracleWufbMutationError $Case $actual $Errors
  Add-RustV3OracleWufbActionError $Case $actual $Errors
  Add-RustV3OracleWufbNoteError $Case $actual $Errors
}

function Add-RustV3OracleWufbMutationError {
  param($Case, $Actual, $Errors)
  $actualJson = ConvertTo-Json @($Actual.Mutations) -Depth 8 -Compress
  $expectedJson = ConvertTo-Json @($Case.expected.normalized_mutations) -Depth 8 -Compress
  if ($actualJson -ne $expectedJson) { [void]$Errors.Add(('PowerShell v2 WUfB policy diverges for {0}.' -f $Case.id)) }
}

function Add-RustV3OracleWufbActionError {
  param($Case, $Actual, $Errors)
  if (@($Actual.DriftActions | Where-Object { $_ -ne $Case.expected.v2_action }).Count -gt 0) {
    [void]$Errors.Add(('PowerShell v2 WUfB action diverges for {0}.' -f $Case.id))
  }
  if ($Actual.Mutations.Count -eq 0 -and ($Actual.Actions.Count -ne 1 -or $Actual.Actions[0] -ne $Case.expected.v2_action)) {
    [void]$Errors.Add(('PowerShell v2 WUfB compliant action diverges for {0}.' -f $Case.id))
  }
}

function Add-RustV3OracleWufbNoteError {
  param($Case, $Actual, $Errors)
  $expectedNote = Get-RustV3OracleProperty $Case.expected 'v2_note'
  if ($expectedNote -and $expectedNote -notin $Actual.Notes) {
    [void]$Errors.Add(('PowerShell v2 WUfB note diverges for {0}.' -f $Case.id))
  }
}

function Import-RustV3OracleSecurityOptionsFunctions {
  param([string]$RepositoryRoot)
  $scriptPath = Join-Path $RepositoryRoot 'scripts/38-SecurityOptions-Drift.ps1'
  $tokens = $null; $parseErrors = $null
  $ast = [System.Management.Automation.Language.Parser]::ParseFile($scriptPath, [ref]$tokens, [ref]$parseErrors)
  if ($parseErrors.Count -gt 0) { throw 'Security Options v2 policy source does not parse.' }
  $names = @('Normalize-RegistryType', 'Normalize-ValueForType', 'Compare-OrderedArray', 'Compare-Value',
    'Resolve-SecurityOptionsDesiredValue', 'Get-NormalizedSecurityOptionCurrentValue',
    'Invoke-SecurityOptionsDesiredValue', 'Set-SecurityOptionDrift')
  foreach ($name in $names) {
    $functions = @($ast.FindAll({ param($Node) $Node -is [Management.Automation.Language.FunctionDefinitionAst] -and $Node.Name -eq $name }, $true))
    if ($functions.Count -ne 1) { throw "Security Options v2 policy function is missing or duplicated: $name" }
    $functions[0].Extent.Text
  }
}

function Get-RustV3OracleSecurityOptionsField {
  param([string]$Path, [string]$Name)
  $fields = @{
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA' = 'enable_lua'
    'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\LmCompatibilityLevel' = 'lm_compatibility_level'
    'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\NoLMHash' = 'no_lm_hash'
    'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\RestrictAnonymous' = 'restrict_anonymous'
    'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\RestrictAnonymousSAM' = 'restrict_anonymous_sam'
    'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\LimitBlankPasswordUse' = 'limit_blank_password_use'
  }
  return $fields[('{0}\{1}' -f $Path, $Name)]
}

function ConvertTo-RustV3OracleSecurityOptionsMutation {
  param($Row)
  $current = if ($null -eq $Row.Current) { [ordered]@{ status = 'missing' } } else { [ordered]@{ status = 'present'; value = $Row.Current } }
  [pscustomobject][ordered]@{
    field = Get-RustV3OracleSecurityOptionsField -Path $Row.Path -Name $Row.Name
    current = $current
    desired = $Row.Desired
  }
}

function Invoke-RustV3OracleV2SecurityOptionsPolicy {
  [OutputType([pscustomobject])]
  param([Parameter(Mandatory)] $Case, [string]$RepositoryRoot = (Join-Path $PSScriptRoot '../..'))
  $definitions = @(Import-RustV3OracleSecurityOptionsFunctions -RepositoryRoot $RepositoryRoot)
  . ([scriptblock]::Create(($definitions -join "`n")))
  $script:RustV3OracleSecurityOptionsObservation = $Case.observation
  $script:Findings = [Collections.ArrayList]::new()
  $script:Drift = [Collections.Generic.List[object]]::new()
  $script:__EntryCmdlet = $null
  $Mode = 'Audit'
  $null = $Mode
  function Add-Finding {
    param($FindingList, $Code, $Severity, $Message, $Extra, [switch]$TimestampLocal)
    $null = $Extra
    $null = $TimestampLocal
    [void]$FindingList.Add([pscustomobject]@{ Code = $Code; Severity = $Severity; Message = $Message })
  }
  function Get-Reg {
    param($Path, $Name)
    $field = Get-RustV3OracleSecurityOptionsField -Path $Path -Name $Name
    if (-not $field) { throw "Unexpected Security Options registry field: $Path\$Name" }
    $snapshot = Get-RustV3OracleProperty $script:RustV3OracleSecurityOptionsObservation $field
    if ($null -eq $snapshot -or $snapshot.status -ne 'present') { return $null }
    return $snapshot.value
  }
  $errorType = $null
  try {
    foreach ($pathProperty in $Case.v2_desired.PSObject.Properties) {
      foreach ($valueProperty in $pathProperty.Value.PSObject.Properties) {
        Invoke-SecurityOptionsDesiredValue -Path $pathProperty.Name -ValueProperty $valueProperty
      }
    }
  }
  catch { $errorType = $_.Exception.GetType().FullName }
  $mutations = @($script:Drift | Where-Object Drift | ForEach-Object { ConvertTo-RustV3OracleSecurityOptionsMutation $_ } | Sort-Object field)
  $outcome = if ($errorType) { 'error' } else { 'completed' }
  [pscustomobject]@{ Outcome = $outcome; ErrorType = $errorType; Mutations = $mutations; FindingCodes = @($script:Findings | ForEach-Object Code) }
}

function Add-RustV3OracleSecurityOptionsCaseErrors {
  param($Case, $RepositoryRoot, $Errors)
  $actual = Invoke-RustV3OracleV2SecurityOptionsPolicy -Case $Case -RepositoryRoot $RepositoryRoot
  $actualMutations = ConvertTo-Json @($actual.Mutations) -Depth 8 -Compress
  $expectedMutationValue = if (Test-RustV3OraclePropertyExists $Case.expected 'v2_normalized_mutations') {
    @($Case.expected.v2_normalized_mutations)
  }
  else { @($Case.expected.normalized_mutations) }
  $expectedMutations = ConvertTo-Json @($expectedMutationValue) -Depth 8 -Compress
  $actualFindings = ConvertTo-Json @($actual.FindingCodes) -Compress
  $expectedFindings = ConvertTo-Json @($Case.expected.v2_finding_codes) -Compress
  $expectedError = Get-RustV3OracleProperty $Case.expected 'v2_error_type'
  if ($actual.Outcome -ne $Case.expected.v2_outcome -or $actual.ErrorType -ne $expectedError -or
      $actualMutations -ne $expectedMutations -or $actualFindings -ne $expectedFindings) {
    [void]$Errors.Add(('PowerShell v2 Security Options policy diverges for {0}.' -f $Case.id))
  }
}

function Add-RustV3OracleDohCaseErrors {
  param($Case, $RepositoryRoot, $Errors)
  if ($Case.observation.server_query_failed) {
    [void]$Errors.Add(('Unsupported v2 behavioral case: {0}.' -f $Case.id))
    return
  }
  $actual = Invoke-RustV3OracleV2DohPolicy -Observation $Case.observation -RepositoryRoot $RepositoryRoot
  if ($actual.Mode -ne $Case.expected.mode -or (Compare-Object @($actual.FindingCodes) @($Case.expected.finding_codes) -SyncWindow 0)) {
    [void]$Errors.Add(('PowerShell v2 DoH policy diverges for {0}.' -f $Case.id))
  }
}

. (Join-Path $PSScriptRoot 'RustV3Oracle.PowerShellLogging.Adapter.ps1')

function Test-RustV3OracleV2BehavioralCases {
  [OutputType([pscustomobject])]
  param([string]$RepositoryRoot = (Join-Path $PSScriptRoot '../..'))

  $documents = Get-RustV3OracleDocuments -RepositoryRoot $RepositoryRoot
  $errors = New-Object 'System.Collections.Generic.List[string]'
  foreach ($case in @($documents.Behavioral.cases)) {
    if ($case.capability_id -eq 'v3.windows-update.policy') {
      Add-RustV3OracleWufbCaseErrors $case $documents.RepositoryRoot $errors
    }
    elseif ($case.capability_id -eq 'v3.security-options.drift') {
      Add-RustV3OracleSecurityOptionsCaseErrors $case $documents.RepositoryRoot $errors
    }
    elseif ($case.capability_id -eq 'v3.doh.audit') {
      Add-RustV3OracleDohCaseErrors $case $documents.RepositoryRoot $errors
    }
    elseif ($case.capability_id -eq 'v3.powershell.logging') {
      Add-RustV3OraclePowerShellLoggingCaseError $case $documents.RepositoryRoot $errors
    }
    else {
      $errors.Add(('Unsupported v2 behavioral case: {0}.' -f $case.id))
    }
  }
  [pscustomobject]@{ IsValid = ($errors.Count -eq 0); Errors = @($errors); CaseCount = @($documents.Behavioral.cases).Count }
}

function ConvertTo-RustV3OracleNormalizedObservation {
  [OutputType([pscustomobject])]
  param([Parameter(Mandatory)] [object]$V2Result, [Parameter(Mandatory)] [string]$CapabilityId)

  [pscustomobject][ordered]@{
    capability_id = $CapabilityId
    normalized_observation = [pscustomobject][ordered]@{
      source = 'mocked-v2-result'
      script_name = [string](Get-RustV3OracleProperty $V2Result 'ScriptName')
      result = [string](Get-RustV3OracleProperty $V2Result 'Result')
      summary = Get-RustV3OracleProperty $V2Result 'Summary'
      metadata = Get-RustV3OracleProperty $V2Result 'Metadata'
      complete = $true
    }
  }
}
