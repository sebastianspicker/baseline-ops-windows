#requires -version 5.1
<#
.SYNOPSIS
Runs the secure remote access guardrail capability.
.DESCRIPTION
Evaluates registry, firewall, group, and Remote Assistance policy through an
explicit run state while preserving the public script's output and exit flow.
#>

function New-RemoteAccessRunState {
  param([bool]$IsElevated)
  $script:Findings = Get-FindingsList
  return [pscustomobject]@{
    Start = Get-Date
    IsElevated = $IsElevated
    Changes = [System.Collections.Generic.List[string]]::new()
    Drifts = [System.Collections.Generic.List[string]]::new()
    Notes = [System.Collections.Generic.List[string]]::new()
    HadError = $false
    ResultObject = $null
    EventIsBad = $false
    Duration = $null
  }
}

function Get-RemoteAccessProofPath {
  param([string]$ProofPath)
  if (-not [string]::IsNullOrWhiteSpace($ProofPath)) { return $ProofPath }
  return Join-Path ([System.IO.Path]::GetTempPath()) 'SecureRemoteAccessGuardrails-proof.json'
}

function Set-RemoteAccessRegistryValue {
  param(
    $RunState,
    $CommandContext,
    $Setting,
    [bool]$Remediate,
    [switch]$TreatMissingAsZero
  )
  $current = Get-RegDword -Path $Setting.Path -Name $Setting.Name
  if ($TreatMissingAsZero -and $null -eq $current) { $current = 0 }
  if ($current -eq $Setting.Desired) { return }
  if (-not $Remediate -or -not $CommandContext.ShouldProcess($Setting.Path, "Set $($Setting.Name)=$($Setting.Desired)")) {
    [void]$RunState.Drifts.Add("$($Setting.DriftLabel) $current != $($Setting.Desired)")
    return
  }
  if (Set-RegDword -Path $Setting.Path -Name $Setting.Name -Value $Setting.Desired) {
    [void]$RunState.Changes.Add($Setting.ChangeMessage)
    return
  }
  [void]$RunState.Drifts.Add("Failed to set $($Setting.Name)=$($Setting.Desired)")
  $RunState.HadError = $true
}

function New-RemoteAccessRegistrySetting {
  param([string]$Path,[string]$Name,[int]$Desired,[string]$ChangeMessage,[string]$DriftLabel)
  return [pscustomobject]@{ Path=$Path; Name=$Name; Desired=$Desired; ChangeMessage=$ChangeMessage; DriftLabel=$DriftLabel }
}

function Get-RemoteAccessMappedSetting {
  param($Value, [hashtable]$Map, [int]$Default)
  try {
    $key = [string]$Value
    if ($key -and $Map.ContainsKey($key)) { return [int]$Map[$key] }
  } catch { return $Default }
  return $Default
}

function Set-RemoteAccessRdpRegistryPolicy {
  param($RunState, $Catalog, $CommandContext, [bool]$Remediate)
  $tsKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server'
  $rdpTcpKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'
  $lsaKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
  $policyKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services'
  $wantDeny = $(if ([bool]$Catalog.RDP.Enable) { 0 } else { 1 })
  $wantNla = $(if ([bool]$Catalog.RDP.NLA) { 1 } else { 0 })
  $wantSecurity = Get-RemoteAccessMappedSetting $Catalog.RDP.SecurityLayer @{ RDP=0; Negotiate=1; TLS=2 } 2
  $wantEncryption = Get-RemoteAccessMappedSetting $Catalog.RDP.MinEncryptionLevel @{ ClientCompatible=2; High=3; FIPS=4 } 3
  $wantRestrictedAdmin = $(if ([bool]$Catalog.RDP.RestrictedAdmin) { 0 } else { 1 })
  $wantPort = 3389
  try { if ($Catalog.RDP.Port) { $wantPort = [int]$Catalog.RDP.Port } } catch { $wantPort = 3389 }
  $settings = @(
    New-RemoteAccessRegistrySetting $tsKey fDenyTSConnections $wantDeny "Set fDenyTSConnections=$wantDeny" fDenyTSConnections
    New-RemoteAccessRegistrySetting $rdpTcpKey UserAuthentication $wantNla "Set UserAuthentication(NLA)=$wantNla" UserAuthentication/NLA
    New-RemoteAccessRegistrySetting $rdpTcpKey SecurityLayer $wantSecurity "Set SecurityLayer=$wantSecurity" SecurityLayer
    New-RemoteAccessRegistrySetting $rdpTcpKey MinEncryptionLevel $wantEncryption "Set MinEncryptionLevel=$wantEncryption" MinEncryptionLevel
  )
  foreach ($setting in $settings) { Set-RemoteAccessRegistryValue $RunState $CommandContext $setting $Remediate }
  $restricted = New-RemoteAccessRegistrySetting $lsaKey DisableRestrictedAdmin $wantRestrictedAdmin "Set DisableRestrictedAdmin=$wantRestrictedAdmin" DisableRestrictedAdmin
  Set-RemoteAccessRegistryValue $RunState $CommandContext $restricted $Remediate -TreatMissingAsZero
  Set-RemoteAccessPortPolicy $RunState $CommandContext $rdpTcpKey $wantPort $Remediate
  Set-RemoteAccessPasswordSavingPolicy $RunState $CommandContext $policyKey $Catalog.RDP.DisablePasswordSaving $Remediate
}

function Set-RemoteAccessPortPolicy {
  param($RunState,$CommandContext,[string]$Path,[int]$Desired,[bool]$Remediate)
  if ($null -eq (Get-RegDword -Path $Path -Name PortNumber)) { return }
  $setting = New-RemoteAccessRegistrySetting $Path PortNumber $Desired "Set PortNumber=$Desired" PortNumber
  Set-RemoteAccessRegistryValue $RunState $CommandContext $setting $Remediate
}

function Set-RemoteAccessPasswordSavingPolicy {
  param($RunState,$CommandContext,[string]$Path,$Value,[bool]$Remediate)
  if ($null -eq $Value) { return }
  $wantPasswordSaving = $(if ([bool]$Value) { 1 } else { 0 })
  $currentPasswordSaving = Get-RegDword -Path $Path -Name DisablePasswordSaving
  if ($currentPasswordSaving -eq $wantPasswordSaving) { return }
  [void]$RunState.Notes.Add('DisablePasswordSaving is under Policies hive and may be overridden by policy.')
  $setting = New-RemoteAccessRegistrySetting $Path DisablePasswordSaving $wantPasswordSaving "Set DisablePasswordSaving=$wantPasswordSaving" DisablePasswordSaving
  Set-RemoteAccessRegistryValue $RunState $CommandContext $setting $Remediate
}

function Add-RemoteAccessClassifiedMessages {
  param($RunState, [object[]]$Messages, [string]$DriftPattern)
  foreach ($message in @($Messages)) {
    if ($message -match $DriftPattern) { [void]$RunState.Drifts.Add([string]$message) }
    else { [void]$RunState.Changes.Add([string]$message) }
  }
}

function Invoke-RemoteAccessPolicyEvaluation {
  param($RunState, $Catalog, $CommandContext, [bool]$Remediate)
  Set-RemoteAccessRdpRegistryPolicy $RunState $Catalog $CommandContext $Remediate
  $firewall = Ensure-RdpFirewallRules -Rdp $Catalog.RDP -Remediate:$Remediate
  Add-RemoteAccessClassifiedMessages $RunState @($firewall) '^(Failed|Missing|.*drift|.*not |NetSecurity)'
  $membership = Ensure-RdpGroupMembership -Rdp $Catalog.RDP -Remediate:$Remediate
  Add-RemoteAccessClassifiedMessages $RunState @($membership) '^(Failed|Missing|Unexpected|Cannot|LocalAccounts)'
  $assistance = Ensure-RemoteAssistance -Ra $Catalog.RemoteAssistance -Remediate:$Remediate
  Add-RemoteAccessClassifiedMessages $RunState @($assistance) '^(Failed|RemoteAssistance)'
}

function New-RemoteAccessResultObject {
  param($RunState, [string]$CatalogPath, [string]$ConfigPath, [string]$ProofPath, [bool]$Remediate, [bool]$Strict)
  return [pscustomobject]@{
    TimestampUtc = (Get-Date).ToUniversalTime().ToString('o')
    ComputerName = $env:COMPUTERNAME
    User = $env:USERNAME
    Elevated = $RunState.IsElevated
    Remediate = $Remediate
    Strict = $Strict
    CatalogPath = $(if ($CatalogPath) { '[configured path]' } else { $null })
    ConfigPath = $(if ($ConfigPath) { '[configured path]' } else { $null })
    ProofPath = $ProofPath
    Changed = @($RunState.Changes)
    Drift = @($RunState.Drifts)
    Notes = @($RunState.Notes)
    EventId = $null
    HasError = $RunState.HadError
    HasDrift = ($RunState.Drifts.Count -gt 0)
  }
}

function Save-RemoteAccessProof {
  param($RunState, [string]$ProofPath)
  Ensure-DirectoryForFile -FilePath $ProofPath | Out-Null
  try { $RunState.ResultObject | ConvertTo-Json -Depth 6 | Set-Content -Path $ProofPath -Encoding UTF8 -ErrorAction Stop }
  catch {
    [void]$RunState.Notes.Add("Failed to write proof JSON - $($_.Exception.Message)")
    $RunState.HadError = $true
    $RunState.ResultObject.HasError = $true
    $RunState.ResultObject.Notes = @($RunState.Notes)
  }
}

function Publish-RemoteAccessEvent {
  param($RunState, [string]$ProofPath, [bool]$Strict, [string]$EventSource)
  $RunState.Duration = New-TimeSpan -Start $RunState.Start -End (Get-Date)
  $RunState.EventIsBad = $RunState.HadError -or ($Strict -and $RunState.ResultObject.HasDrift)
  $message = Get-RemoteAccessEventMessage $RunState $ProofPath
  $RunState.ResultObject.EventId = $(if ($RunState.EventIsBad) { 4850 } else { 4840 })
  $level = $(if ($RunState.EventIsBad) { 'Warning' } else { 'Information' })
  Write-HealthEvent -Id $RunState.ResultObject.EventId -Message $message -Level $level -Source $EventSource
}

function Get-RemoteAccessEventMessage {
  param($RunState,[string]$ProofPath)
  $lines = [System.Collections.Generic.List[string]]::new()
  foreach ($group in @(
      @{ Label='Changed'; Items=$RunState.Changes },
      @{ Label='Drift'; Items=$RunState.Drifts },
      @{ Label='Notes'; Items=$RunState.Notes }
    )) {
    if ($group.Items.Count -gt 0) { [void]$lines.Add("$($group.Label): " + (@($group.Items) -join ' | ')) }
  }
  if ($lines.Count -eq 0) { [void]$lines.Add('Compliant. No drift.') }
  [void]$lines.Add(('Duration: {0:00}:{1:00}:{2:00}' -f $RunState.Duration.Hours,$RunState.Duration.Minutes,$RunState.Duration.Seconds))
  [void]$lines.Add("Proof: $ProofPath")
  return @($lines) -join "`r`n"
}

function Get-RemoteAccessPresentation {
  param($RunState,[bool]$Remediate,[bool]$Strict)
  $statusColor = 'Green'; $statusText = 'COMPLIANT'
  if ($RunState.EventIsBad) { $statusColor = 'Yellow'; $statusText = 'ATTENTION' }
  if ($RunState.HadError) { $statusColor = 'Red'; $statusText = 'ERROR' }
  return [pscustomobject]@{
    StatusColor=$statusColor; StatusText=$statusText
    ElevatedColor=(Select-RemoteAccessColor $RunState.IsElevated Green Yellow)
    RemediateColor=(Select-RemoteAccessColor $Remediate Yellow Gray)
    StrictColor=(Select-RemoteAccessColor $Strict Yellow Gray)
    EventColor=(Select-RemoteAccessColor $RunState.EventIsBad Yellow Green)
    ChangesColor=(Select-RemoteAccessColor ($RunState.Changes.Count -gt 0) Yellow Gray)
    DriftsColor=(Select-RemoteAccessColor ($RunState.Drifts.Count -gt 0) Yellow Green)
    NotesColor=(Select-RemoteAccessColor ($RunState.Notes.Count -gt 0) Cyan Gray)
  }
}

function Select-RemoteAccessColor {
  param([bool]$Condition,[string]$WhenTrue,[string]$WhenFalse)
  if ($Condition) { return $WhenTrue }
  return $WhenFalse
}

function Write-RemoteAccessSummary {
  param($RunState, [string]$ProofPath, [bool]$Remediate, [bool]$Strict)
  $presentation = Get-RemoteAccessPresentation $RunState $Remediate $Strict
  Write-UiLine ''
  Write-UiSeparator -Title 'Secure Remote Access Guardrails'
  Write-KeyValue -Key Computer -Value $env:COMPUTERNAME -Color Gray
  Write-KeyValue -Key Elevated -Value $RunState.IsElevated.ToString() -Color $presentation.ElevatedColor
  Write-KeyValue -Key Remediate -Value $Remediate -Color $presentation.RemediateColor
  Write-KeyValue -Key Strict -Value $Strict -Color $presentation.StrictColor
  Write-KeyValue -Key EventId -Value $RunState.ResultObject.EventId -Color $presentation.EventColor
  Write-KeyValue -Key Proof -Value $ProofPath -Color Cyan
  Write-KeyValue -Key Duration -Value ('{0:00}:{1:00}:{2:00}' -f $RunState.Duration.Hours,$RunState.Duration.Minutes,$RunState.Duration.Seconds) -Color Gray
  Write-UiSeparator
  Write-UiLine -Text "Status: $($presentation.StatusText)" -Color $presentation.StatusColor
  Write-KeyValue -Key Changes -Value $RunState.Changes.Count -Color $presentation.ChangesColor
  Write-KeyValue -Key Drifts -Value $RunState.Drifts.Count -Color $presentation.DriftsColor
  Write-KeyValue -Key Notes -Value $RunState.Notes.Count -Color $presentation.NotesColor
  Write-UiLine ''
  Write-UiList -Header Changes -Items @($RunState.Changes) -Color Yellow
  Write-UiList -Header Drift -Items @($RunState.Drifts) -Color Yellow
  Write-UiList -Header Notes -Items @($RunState.Notes) -Color Cyan
  Write-Information -MessageData ("Guardrails done. EventId={0}, Proof={1}" -f $RunState.ResultObject.EventId,$ProofPath) -InformationAction Continue
}

function Invoke-RemoteAccessRun {
  param($RunState, $CommandContext, [string]$CatalogPath, [string]$ConfigPath, [string]$ProofPath, [bool]$Remediate, [bool]$Strict, [string]$EventSource)
  if (-not $RunState.IsElevated) {
    [void]$RunState.Notes.Add('Not elevated - audit works, remediation may fail.')
    if ($Remediate) { [void]$RunState.Notes.Add('Remediate requested but session not elevated.') }
  }
  $catalog = Load-Catalog -ExplicitCatalogPath $CatalogPath -ConfigPath $ConfigPath
  Invoke-RemoteAccessPolicyEvaluation $RunState $catalog $CommandContext $Remediate
  $RunState.ResultObject = New-RemoteAccessResultObject $RunState $CatalogPath $ConfigPath $ProofPath $Remediate $Strict
  Save-RemoteAccessProof $RunState $ProofPath
  Publish-RemoteAccessEvent $RunState $ProofPath $Strict $EventSource
  Write-RemoteAccessSummary $RunState $ProofPath $Remediate $Strict
  $RunState.ResultObject
}

function Invoke-RemoteAccessFailure {
  param($RunState, [string]$Message, [string]$CatalogPath, [string]$ConfigPath, [string]$ProofPath, [bool]$Remediate, [bool]$Strict, [string]$EventSource)
  Write-HealthEvent -Id 4850 -Message ('Guardrail error - ' + $Message) -Level Error -Source $EventSource
  Ensure-DirectoryForFile -FilePath $ProofPath | Out-Null
  try { [pscustomobject]@{ TimestampUtc=(Get-Date).ToUniversalTime().ToString('o'); ComputerName=$env:COMPUTERNAME; Error=$Message } | ConvertTo-Json -Depth 4 | Set-Content -Path $ProofPath -Encoding UTF8 -ErrorAction Stop }
  catch { Write-Warning "Could not write proof file: $($_.Exception.Message)" }
  Write-UiLine ''; Write-UiSeparator -Title 'Secure Remote Access Guardrails'
  Write-UiLine -Text 'Status: ERROR' -Color Red; Write-UiLine -Text "Message: $Message" -Color Red
  Write-UiLine -Text "Proof:   $ProofPath" -Color Cyan; Write-UiSeparator
  return [pscustomobject]@{
    TimestampUtc=(Get-Date).ToUniversalTime().ToString('o'); ComputerName=$env:COMPUTERNAME; User=$env:USERNAME
    Elevated=$RunState.IsElevated; Remediate=$Remediate; Strict=$Strict
    CatalogPath=$(if ($CatalogPath) { '[configured path]' } else { $null }); ConfigPath=$(if ($ConfigPath) { '[configured path]' } else { $null })
    ProofPath=$ProofPath; Changed=@(); Drift=@(); Notes=@("Guardrail error - $Message"); EventId=4850; HasError=$true; HasDrift=$false
  }
}

function Add-RemoteAccessCanonicalFindings {
  param([object[]]$Drifts)
  foreach ($drift in @($Drifts)) {
    $classification = Get-RemoteAccessFindingClassification $drift
    Add-Finding -FindingList $script:Findings -Code $classification.Code -Severity $classification.Severity -Message $drift
  }
}

function Get-RemoteAccessFindingClassification {
  param([string]$Drift)
  $code = 'RDP-Drift'
  foreach ($rule in @(
      @{ Pattern='fDenyTSConnections|UserAuthentication|NLA'; Code='RDP-ConfigDrift' },
      @{ Pattern='SecurityLayer|MinEncryption'; Code='RDP-EncryptionDrift' },
      @{ Pattern='DisableRestrictedAdmin|DisablePasswordSaving'; Code='RDP-SecurityDrift' },
      @{ Pattern='PortNumber'; Code='RDP-PortDrift' },
      @{ Pattern='RemoteAssistance'; Code='RDP-RemoteAssistDrift' },
      @{ Pattern='rule|firewall|TCP|UDP'; Code='RDP-FirewallDrift' },
      @{ Pattern='member'; Code='RDP-GroupDrift' }
    )) { if ($Drift -match $rule.Pattern) { $code = $rule.Code } }
  $severity = $(if ($Drift -match 'Failed|Missing|Unexpected') { 'High' } else { 'Medium' })
  return [pscustomobject]@{ Code=$code; Severity=$severity }
}

function Invoke-RemoteAccessCapability {
  param($RunState,$CommandContext,$Options)
  if (-not (Ensure-EventSource -Source $Options.EventSource -LogName $Options.EventLog)) {
    Write-Warning 'EventSource could not be registered. EventLog tracing will be unavailable.'
  }
  try {
    Invoke-RemoteAccessRun $RunState $CommandContext $Options.CatalogPath $Options.ConfigPath $Options.ProofPath $Options.Remediate $Options.Strict $Options.EventSource
  } catch {
    Invoke-RemoteAccessFailure $RunState $_.Exception.Message $Options.CatalogPath $Options.ConfigPath $Options.ProofPath $Options.Remediate $Options.Strict $Options.EventSource
  }
}
