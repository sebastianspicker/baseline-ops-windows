<#
.SYNOPSIS
Coordinates WinGet self-heal checks and result production.

.DESCRIPTION
Maintains explicit capability state across configuration, WinGet, redistributable,
private-source, source-update, event, and presentation phases.
#>

function New-WinGetSelfHealState {
  param([hashtable]$Inputs)
  return @{
    Inputs = $Inputs
    Records = New-Object System.Collections.Generic.List[object]
    ConfigLoaded = $false
    VcX64Path = $Inputs.InstallerX64Path
    VcX86Path = $Inputs.InstallerX86Path
    VcArgs = '/install /quiet /norestart'
    PrivateName = $Inputs.PrivateSourceName
    PrivateUrl = $Inputs.PrivateSourceUrl
    PrivateType = 'Microsoft.Rest'
    WingetPath = $null
    WingetVersionRaw = $null
    SupportsSourceAgreement = $false
    OverallOk = $false
    ResultToken = 'FAIL'
  }
}

function New-WinGetSelfHealInputs {
  param($BoundParameters, $DecisionContext, [bool]$Remediate)
  return @{
    ConfigPath = $ConfigPath
    InstallerX64Path = $InstallerX64Path
    InstallerX86Path = $InstallerX86Path
    PrivateSourceName = $PrivateSourceName
    PrivateSourceUrl = $PrivateSourceUrl
    RequirePrivateSource = $RequirePrivateSource
    DiagnoseWingetErrors = [bool]$DiagnoseWingetErrors
    FailOnSourceUpdateError = [bool]$FailOnSourceUpdateError
    Remediate = $Remediate
    Strict = [bool]$Strict
    BoundParameters = $BoundParameters
    DecisionContext = $DecisionContext
  }
}

function Initialize-WinGetSelfHealEventSource {
  try {
    if (-not (Ensure-EventSource -Source 'WinGet-SelfHeal' -LogName Application)) {
      Write-Warning 'EventSource could not be registered. EventLog tracing will be unavailable.'
    }
  }
  catch {
    Write-Warning 'EventSource could not be registered. EventLog tracing will be unavailable.'
  }
}

function Initialize-WinGetSelfHealConfiguration {
  param([hashtable]$RunState)
  $config = Get-Config -Path $RunState.Inputs.ConfigPath
  if ($config) {
    $RunState.ConfigLoaded = $true
    $RunState.PrivateName = Get-WinGetConfiguredPrivateSourceName -RunState $RunState -Config $config
  }
  $status = if ($RunState.ConfigLoaded) { 'OK' } else { 'Warning' }
  $message = if ($RunState.ConfigLoaded) { 'Loaded (path redacted).' } else { 'Not loaded. Using defaults/parameters.' }
  Add-Record -List $RunState.Records -Record (Get-CheckRecord -Name Config -Status $status -Message $message -Data @{
    ConfigPath = if ($RunState.Inputs.ConfigPath) { '[configured path]' } else { '[not configured]' }
    RequirePrivateSource = $RunState.Inputs.RequirePrivateSource
  })
}

function Get-WinGetConfiguredPrivateSourceName {
  param([hashtable]$RunState, $Config)
  if ($RunState.Inputs.Remediate -or $RunState.PrivateName) { return $RunState.PrivateName }
  $configuredName = Get-NestedPropValue -Object $Config -Path @('Winget', 'PrivateSourceName')
  if ($configuredName) { return [string]$configuredName }
  return $RunState.PrivateName
}

function Add-WinGetVersionRecord {
  param([hashtable]$RunState, $VersionResult, $Version)
  if ($VersionResult.ExitCode -ne 0 -or -not $Version) {
    Add-Record -List $RunState.Records -Record (Get-CheckRecord -Name WinGet -Status Error -Message 'Version check failed.' -Data @{
      ExitCode = $VersionResult.ExitCode
      StdErr = $VersionResult.StdErr.Trim()
      StdOut = $VersionResult.StdOut.Trim()
    })
    return
  }
  if (-not (Is-Version-AtLeast -v $Version -maj 1 -min 6 -pat 0)) {
    Add-Record -List $RunState.Records -Record (Get-CheckRecord -Name WinGet -Status Error -Message 'Version too old.' -Data @{
      Have = $Version.Raw
      Need = '1.6.0'
    })
    return
  }
  Add-Record -List $RunState.Records -Record (Get-CheckRecord -Name WinGet -Status OK -Message 'OK.' -Data @{
    Version = $Version.Raw
    Path = $RunState.WingetPath
  })
  [void](Add-Finding -FindingList $script:Findings -Code 'Winget-Found' -Severity Low `
    -Message "WinGet version $($Version.Raw) located at $($RunState.WingetPath)")
}

function Test-WinGetSelfHealExecutable {
  param([hashtable]$RunState)
  $RunState.WingetPath = Resolve-WingetPath
  if (-not $RunState.WingetPath) {
    Add-Record -List $RunState.Records -Record (Get-CheckRecord -Name WinGet -Status Error -Message 'winget.exe not found.')
    return
  }
  $env:WINGET_SUPPRESS_PROMPT = '1'
  $versionResult = Invoke-Winget -WingetPath $RunState.WingetPath -WingetArgs @('--version')
  $version = Parse-Version $versionResult.StdOut
  $RunState.WingetVersionRaw = $versionResult.StdOut.Trim()
  Add-WinGetVersionRecord -RunState $RunState -VersionResult $versionResult -Version $version
  $RunState.SupportsSourceAgreement = Test-WingetSupportsAcceptSourceAgreements -WingetPath $RunState.WingetPath
  Add-Record -List $RunState.Records -Record (Get-CheckRecord -Name WinGetSourceUpdateCapabilities -Status OK `
    -Message 'Capability probe done.' -Data @{ AcceptSourceAgreementsForSourceUpdate = $RunState.SupportsSourceAgreement })
}

function Add-VcRedistRemediationRecord {
  param([hashtable]$RunState, [string]$Architecture, [string]$InstallerPath)
  $installed, $detail = Install-VcRedist -Path $InstallerPath -InstallArgs $RunState.VcArgs -Architecture $Architecture
  $status = 'Error'
  $message = 'Install failed.'
  if ($detail -eq 'Skipped by ShouldProcess') { $status = 'Skipped'; $message = $detail }
  elseif ($installed) { $status = 'OK'; $message = 'Installed.' }
  Add-Record -List $RunState.Records -Record (Get-CheckRecord -Name "VcRedist$($Architecture.ToUpper())Remediation" `
    -Status $status -Message $message -Data @{ Detail = $detail; InstallerPath = $InstallerPath })
}

function Test-WinGetVcRedistX64 {
  param([hashtable]$RunState)
  $installed, $version = Test-VcRedistInstalled -Arch x64
  if ($installed) {
    Add-Record -List $RunState.Records -Record (Get-CheckRecord -Name VcRedistX64 -Status OK -Message 'OK.' -Data @{ Version = $version })
    return
  }
  Add-Record -List $RunState.Records -Record (Get-CheckRecord -Name VcRedistX64 -Status Error -Message 'Missing.')
  if (-not $RunState.Inputs.Remediate) { return }
  if (-not $RunState.VcX64Path) {
    Add-Record -List $RunState.Records -Record (Get-CheckRecord -Name VcRedistX64Remediation -Status Error `
      -Message 'Remediation requested but installer path not configured.')
    return
  }
  Add-VcRedistRemediationRecord -RunState $RunState -Architecture x64 -InstallerPath $RunState.VcX64Path
}

function Test-WinGetVcRedistX86 {
  param([hashtable]$RunState)
  $installed, $version = Test-VcRedistInstalled -Arch x86
  if ($installed) {
    Add-Record -List $RunState.Records -Record (Get-CheckRecord -Name VcRedistX86 -Status OK -Message 'OK.' -Data @{ Version = $version })
    return
  }
  Add-Record -List $RunState.Records -Record (Get-CheckRecord -Name VcRedistX86 -Status Warning -Message 'Not installed (optional).')
  if ($RunState.Inputs.Remediate -and $RunState.VcX86Path) {
    Add-VcRedistRemediationRecord -RunState $RunState -Architecture x86 -InstallerPath $RunState.VcX86Path
  }
}

function Test-WinGetPrivateSource {
  param([hashtable]$RunState)
  if (-not $RunState.Inputs.RequirePrivateSource) {
    Add-Record -List $RunState.Records -Record (Get-CheckRecord -Name PrivateSource -Status Skipped -Message 'Not required.')
    return
  }
  if (-not $RunState.WingetPath) {
    Add-Record -List $RunState.Records -Record (Get-CheckRecord -Name PrivateSource -Status Error -Message 'Skipped (winget missing).')
    return
  }
  $authorized = $RunState.Inputs.Remediate -and
    $RunState.Inputs.BoundParameters.ContainsKey('PrivateSourceName') -and
    $RunState.Inputs.BoundParameters.ContainsKey('PrivateSourceUrl') -and
    $RunState.Inputs.DecisionContext.ShouldProcess("WinGet source '$($RunState.PrivateName)'", 'Add the source if it is missing')
  $present, $message = Ensure-PrivateSource -WingetPath $RunState.WingetPath -Name $RunState.PrivateName `
    -Url $RunState.PrivateUrl -Type $RunState.PrivateType -DoIt:$authorized
  $status = if ($present) { 'OK' } else { 'Error' }
  Add-Record -List $RunState.Records -Record (Get-CheckRecord -Name PrivateSource -Status $status -Message $message `
    -Data (Get-PrivateSourceResultMetadata -Name $RunState.PrivateName -Type $RunState.PrivateType))
}

function Add-WinGetSourceUpdateFailure {
  param([hashtable]$RunState, $UpdateResult)
  $diagnostic = $null
  if ($RunState.Inputs.DiagnoseWingetErrors) {
    $diagnostic = Get-WingetErrorText -WingetPath $RunState.WingetPath -ExitCode $UpdateResult.ExitCode
  }
  $status = if ($RunState.Inputs.FailOnSourceUpdateError) { 'Error' } else { 'Warning' }
  Add-Record -List $RunState.Records -Record (Get-CheckRecord -Name SourceUpdate -Status $status -Message 'Failed.' -Data @{
    ExitCode = $UpdateResult.ExitCode
    ExitCodeHex = Convert-ExitCodeToHex32 -ExitCode $UpdateResult.ExitCode
    StdErr = $UpdateResult.StdErr.Trim()
    StdOut = $UpdateResult.StdOut.Trim()
    WingetError = $diagnostic
    Args = ($UpdateResult.Args -join ' ')
  })
}

function Update-WinGetSources {
  param([hashtable]$RunState)
  if (-not $RunState.WingetPath) {
    Add-Record -List $RunState.Records -Record (Get-CheckRecord -Name SourceUpdate -Status Skipped -Message 'Skipped (winget missing).')
    return
  }
  if (-not $RunState.Inputs.Remediate) {
    Add-Record -List $RunState.Records -Record (Get-CheckRecord -Name SourceUpdate -Status Skipped -Message 'Skipped (audit mode).')
    return
  }
  if (-not $RunState.Inputs.DecisionContext.ShouldProcess('WinGet sources', 'Refresh source metadata')) {
    Add-Record -List $RunState.Records -Record (Get-CheckRecord -Name SourceUpdate -Status Skipped -Message 'Skipped by ShouldProcess.')
    return
  }
  $update = Invoke-WingetSourceUpdate -WingetPath $RunState.WingetPath `
    -SupportAcceptSourceAgreements:$RunState.SupportsSourceAgreement
  if ($update.ExitCode -eq 0) {
    Add-Record -List $RunState.Records -Record (Get-CheckRecord -Name SourceUpdate -Status OK -Message 'OK.')
  }
  else {
    Add-WinGetSourceUpdateFailure -RunState $RunState -UpdateResult $update
  }
}

function Write-WinGetSelfHealEvent {
  param([hashtable]$RunState)
  $eventLines = foreach ($record in $RunState.Records) {
    '[{0}] {1}: {2}' -f $record.Status, $record.Name, (Get-TextOrEmpty $record.Message)
  }
  $eventId = if ($RunState.OverallOk) { 4100 } else { 4110 }
  $eventLevel = if ($RunState.OverallOk) { 'Information' } else { 'Warning' }
  Write-HealthEvent -Id $eventId -Msg ($eventLines -join "`r`n") -Level $eventLevel `
    -Source 'WinGet-SelfHeal' -LogName Application
}

function Write-WinGetSelfHealRecords {
  param([hashtable]$RunState)
  if ($script:NoConsole) { return }
  Write-UiLine ''
  Write-UiLine 'Checks:' -ForegroundColor Cyan
  foreach ($record in $RunState.Records) {
    $color = Get-StatusColor -Status $record.Status
    Write-UiLine ("- {0,-32} {1,-8} {2}" -f $record.Name, $record.Status, (Get-TextOrEmpty $record.Message)) `
      -ForegroundColor $color
  }
}

function Write-WinGetSelfHealSummary {
  param([hashtable]$RunState)
  $display = Get-WinGetSelfHealDisplayValues -RunState $RunState
  Write-ConsoleHeader -Title 'WinGet Self-Heal Summary'
  Write-KeyValue -Key Status -Value $display.StatusText -ValueColor $display.StatusColor
  Write-KeyValue -Key Remediate -Value $display.RemediateText -ValueColor $display.RemediateColor
  Write-KeyValue -Key RequirePrivateSource -Value ([string]$RunState.Inputs.RequirePrivateSource) `
    -ValueColor $display.PrivateSourceColor
  Write-KeyValue -Key ConfigPath -Value $display.ConfigPath -ValueColor Gray
  if ($RunState.WingetVersionRaw) {
    Write-KeyValue -Key WinGetVersion -Value $RunState.WingetVersionRaw -ValueColor White
  }
  Write-WinGetSelfHealRecords -RunState $RunState
}

function Get-WinGetSelfHealDisplayValues {
  param([hashtable]$RunState)
  return @{
    StatusText = if ($RunState.OverallOk) { 'OK' } else { 'NOT OK' }
    StatusColor = if ($RunState.OverallOk) { 'Green' } else { 'Red' }
    RemediateText = if ($RunState.Inputs.Remediate) { 'Yes' } else { 'No' }
    RemediateColor = if ($RunState.Inputs.Remediate) { 'Yellow' } else { 'Gray' }
    PrivateSourceColor = if ($RunState.Inputs.RequirePrivateSource) { 'Yellow' } else { 'Gray' }
    ConfigPath = if ($RunState.Inputs.ConfigPath) { '[configured path]' } else { '[not configured]' }
  }
}

function Complete-WinGetSelfHeal {
  param([hashtable]$RunState)
  if ($RunState.Records.Count -eq 0) {
    Add-Record -List $RunState.Records -Record (Get-CheckRecord -Name Runtime -Status Error `
      -Message 'No records were produced (early termination).')
  }
  $RunState.OverallOk = Get-OverallOk -Records $RunState.Records.ToArray()
  Write-WinGetSelfHealEvent -RunState $RunState
  Write-WinGetSelfHealSummary -RunState $RunState
  $hasWarnings = @($RunState.Records.ToArray() | Where-Object Status -eq Warning).Count -gt 0
  $RunState.ResultToken = if (-not $RunState.OverallOk) { 'FAIL' } elseif ($hasWarnings -or $script:Findings.Count -gt 0) { 'WARN' } else { 'OK' }
  if ($RunState.Inputs.Strict -and $RunState.ResultToken -eq 'WARN') { $RunState.ResultToken = 'FAIL' }
}

function Invoke-WinGetSelfHeal {
  param([hashtable]$RunState)
  try {
    Initialize-WinGetSelfHealEventSource
    Initialize-WinGetSelfHealConfiguration -RunState $RunState
    Test-WinGetSelfHealExecutable -RunState $RunState
    Test-WinGetVcRedistX64 -RunState $RunState
    Test-WinGetVcRedistX86 -RunState $RunState
    Test-WinGetPrivateSource -RunState $RunState
    Update-WinGetSources -RunState $RunState
  }
  catch {
    Add-Record -List $RunState.Records -Record (Get-CheckRecord -Name UnhandledException -Status Error `
      -Message $_.Exception.Message -Data @{ Position = Get-TextOrEmpty $_.InvocationInfo.PositionMessage })
  }
  finally {
    Complete-WinGetSelfHeal -RunState $RunState
  }
}
