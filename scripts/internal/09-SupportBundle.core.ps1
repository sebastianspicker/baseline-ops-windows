<#
.SYNOPSIS
Support bundle core helpers.

.DESCRIPTION
Contains capability-private support bundle core behavior.
#>

function SB_IsWindowsPlatform {
  [CmdletBinding()]
  param()

  if ($PSVersionTable.PSEdition -eq 'Core') { return [bool]$IsWindows }
  return $true
}

function SB_GetDefaultTrustedOutputRoot {
  [CmdletBinding()]
  param()

  $commonData = if (SB_IsWindowsPlatform) {
    [Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)
  } else {
    # Test hosts may exercise the Windows-only script with a scoped ProgramData.
    $env:ProgramData
  }
  if ([string]::IsNullOrWhiteSpace($commonData)) {
    throw 'The system CommonApplicationData directory could not be resolved.'
  }

  return [System.IO.Path]::GetFullPath(
    (Join-Path (Join-Path $commonData 'BaselineOpsForWindows') 'SupportBundles')
  )
}

function SB_NewRestrictedDirectoryAcl {
  $administrators = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')
  $localSystem = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-18')
  $inheritance = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
    [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
  $propagation = [System.Security.AccessControl.PropagationFlags]::None
  $fullControl = [System.Security.AccessControl.FileSystemRights]::FullControl
  $allow = [System.Security.AccessControl.AccessControlType]::Allow
  $acl = New-Object System.Security.AccessControl.DirectorySecurity
  $acl.SetOwner($administrators)
  $acl.SetAccessRuleProtection($true, $false)
  foreach ($sid in @($administrators, $localSystem)) {
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
      $sid, $fullControl, $inheritance, $propagation, $allow
    )
    [void]$acl.AddAccessRule($rule)
  }
  return [pscustomobject]@{ Acl = $acl; Administrators = $administrators; LocalSystem = $localSystem; Allow = $allow; FullControl = $fullControl }
}

function SB_AssertRestrictedDirectoryAcl {
  param([string]$Path, $AclDefinition)
  $verified = Get-Acl -LiteralPath $Path -ErrorAction Stop
  if (-not $verified.AreAccessRulesProtected) {
    throw "Trusted output ACL inheritance remains enabled: $Path"
  }
  $allowedSids = @($AclDefinition.Administrators.Value, $AclDefinition.LocalSystem.Value)
  $rules = @($verified.GetAccessRules($true, $false, [System.Security.Principal.SecurityIdentifier]))
  if ($rules.Count -ne 2) { throw "Trusted output ACL contains unexpected explicit rules: $Path" }
  foreach ($rule in $rules) {
    if (
      $allowedSids -notcontains $rule.IdentityReference.Value -or
      $rule.AccessControlType -ne $AclDefinition.Allow -or
      ($rule.FileSystemRights -band $AclDefinition.FullControl) -ne $AclDefinition.FullControl
    ) {
      throw "Trusted output ACL grants unexpected access: $Path"
    }
  }
}

function SB_SetRestrictedDirectoryAcl {
  [CmdletBinding()]
  param([Parameter(Mandatory)][string]$Path)
  if (-not (SB_IsWindowsPlatform)) { return }
  $definition = SB_NewRestrictedDirectoryAcl
  Set-Acl -LiteralPath $Path -AclObject $definition.Acl -ErrorAction Stop
  SB_AssertRestrictedDirectoryAcl -Path $Path -AclDefinition $definition
}

function SB_WriteLog {
  param(
    [AllowNull()]
    [AllowEmptyString()]
    [string]$Message,

    [ValidateSet('INFO','WARN','ERROR','OK')]
    [string]$Level = 'INFO'
  )

  # Never throw on empty log lines.
  if ([string]::IsNullOrEmpty($Message)) { return }

  $prefix = "[{0}] " -f $Level
  switch ($Level) {
    'INFO'  { Write-UiLine -Message ($prefix + $Message) -ForegroundColor Gray -UseInformationStream:$script:UseInformationStream }
    'OK'    { Write-UiLine -Message ($prefix + $Message) -ForegroundColor Green -UseInformationStream:$script:UseInformationStream }
    'WARN'  { Write-UiLine -Message ($prefix + $Message) -ForegroundColor Yellow -UseInformationStream:$script:UseInformationStream }
    'ERROR' { Write-UiLine -Message ($prefix + $Message) -ForegroundColor Red -UseInformationStream:$script:UseInformationStream }
  }
}

function SB_WriteSection {
  param([Parameter(Mandatory)][string]$Title)

  $line = ('-' * 72)
  Write-UiLine -Message ("[INFO] {0}" -f $line) -ForegroundColor DarkGray -UseInformationStream:$script:UseInformationStream
  Write-UiLine -Message ("[INFO] {0}" -f $Title) -ForegroundColor Cyan -UseInformationStream:$script:UseInformationStream
  Write-UiLine -Message ("[INFO] {0}" -f $line) -ForegroundColor DarkGray -UseInformationStream:$script:UseInformationStream
}

function SB_WriteHealthEvent {
  param(
    [int]$Id,
    [string]$Msg,
    [ValidateSet('Information','Warning','Error')]
    [string]$Level = 'Information'
  )

  if (-not (Write-HealthEvent -LogName Application -Source $EventSource -Level $Level -Id $Id -Message $Msg)) {
    SB_WriteLog -Level $(if ($Level -eq 'Error') { 'ERROR' } elseif ($Level -eq 'Warning') { 'WARN' } else { 'INFO' }) -Message $Msg
  }
}

function SB_SaveTextFile {
  param(
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][string]$Text
  )
  [void](Ensure-Directory -Path (Split-Path -Parent $Path))
  $Text | Out-File -FilePath $Path -Encoding utf8
}

function SB_SaveJsonFile {
  param(
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)]$Object
  )
  [void](Ensure-Directory -Path (Split-Path -Parent $Path))
  ($Object | ConvertTo-Json -Depth 40) | Out-File -FilePath $Path -Encoding utf8
}

function SB_NewRecord {
  param(
    [Parameter(Mandatory)][string]$Name,
    [bool]$Ok,
    [string]$ArtifactPath,
    [string]$Note,
    [Alias('Error')]
    [string]$ErrorText
  )

  [pscustomobject]@{
    Name         = $Name
    Ok           = [bool]$Ok
    ArtifactPath = $ArtifactPath
    Note         = $Note
    Error        = $ErrorText
    Time         = (Get-Date).ToString('s')
  }
}

function SB_NewSummary {
  param(
    [Parameter(Mandatory)][string]$ComputerName,
    [Parameter(Mandatory)][bool]$IsAdminNow,
    [Parameter(Mandatory)][int]$DaysBack,
    [Parameter(Mandatory)][bool]$IncludeSec,
    [Parameter(Mandatory)][bool]$IncludeDef,
    [string]$ConfigPath,
    [string]$ProofDir,
    [string]$ReasonText
  )

  [pscustomobject]@{
    Hostname    = $ComputerName
    Time        = (Get-Date).ToString('s')
    User        = $env:USERNAME
    Admin       = $IsAdminNow
    DaysBack    = $DaysBack
    IncludeSec  = $IncludeSec
    IncludeDef  = $IncludeDef
    ConfigPath  = $ConfigPath
    ProofDir    = $ProofDir
    Reason      = $ReasonText
    ZipPath     = $null
    WorkDir     = $null
    Records     = @()
  }
}

function SB_AddRecord {
  param(
    [Parameter(Mandatory)][object]$Summary,
    [Parameter(Mandatory)][pscustomobject]$Record
  )

  if (-not $Summary) { return }
  if (@($Summary.PSObject.Properties.Name) -notcontains 'Records') { return }

  if ($Summary.Records -isnot [object[]]) {
    $Summary.Records = @($Summary.Records)
  }

  $Summary.Records += $Record
}

function SB_TryStep {
  param(
    [Parameter(Mandatory)][string]$Name,
    [Parameter(Mandatory)][scriptblock]$Code
  )

  try {
    $r = & $Code
    if ($r -is [pscustomobject]) { return $r }
    return (SB_NewRecord -Name $Name -Ok $true -ArtifactPath $null -Note $null -Error $null)
  } catch {
    return (SB_NewRecord -Name $Name -Ok $false -ArtifactPath $null -Note $null -Error $_.Exception.Message)
  }
}

function SB_GetSummaryRecords {
  param([Parameter(Mandatory)][object]$Summary)
  if (-not $Summary) {
    SB_WriteLog -Level 'ERROR' -Message 'Summary is null (unexpected).'
    return [pscustomobject]@{ Valid = $false; Records = @() }
  }
  if (@($Summary.PSObject.Properties.Name) -notcontains 'Records') {
    SB_WriteLog -Level 'ERROR' -Message ("Summary missing Records. Type={0}" -f $Summary.GetType().FullName)
    return [pscustomobject]@{ Valid = $false; Records = @() }
  }
  try { $records = @($Summary.Records) } catch { $records = @() }
  return [pscustomobject]@{ Valid = $true; Records = $records }
}

function SB_ShowSummaryIdentity {
  param([Parameter(Mandatory)][object]$Summary)
  SB_WriteSection -Title 'SupportBundle summary'
  SB_WriteLog -Message ("Host            : {0}" -f $Summary.Hostname) -Level 'INFO'
  SB_WriteLog -Message ("Time            : {0}" -f $Summary.Time) -Level 'INFO'
  SB_WriteLog -Message ("User            : {0}" -f $Summary.User) -Level 'INFO'
  SB_WriteLog -Message ("Admin           : {0}" -f $Summary.Admin) -Level $(if ($Summary.Admin) { 'OK' } else { 'WARN' })
  SB_WriteLog -Message ("DaysBack        : {0}" -f $Summary.DaysBack) -Level 'INFO'
  SB_WriteLog -Message ("IncludeSecurity : {0}" -f $Summary.IncludeSec) -Level 'INFO'
  SB_WriteLog -Message ("IncludeDefender : {0}" -f $Summary.IncludeDef) -Level 'INFO'
  if (-not [string]::IsNullOrWhiteSpace($Summary.Reason)) {
    SB_WriteLog -Message ("Reason          : {0}" -f $Summary.Reason) -Level 'INFO'
  }

  SB_WriteLog -Message ("WorkDir         : {0}" -f $(if (-not [string]::IsNullOrWhiteSpace($Summary.WorkDir)) { $Summary.WorkDir } else { '(not created)' })) -Level 'INFO'
  SB_WriteLog -Message ("Zip             : {0}" -f $(if (-not [string]::IsNullOrWhiteSpace($Summary.ZipPath)) { $Summary.ZipPath } else { '(not created)' })) -Level 'INFO'
}

function SB_ShowSummaryRecords {
  param([object[]]$Records)
  $errors = @($Records | Where-Object { -not $_.Ok })
  $ok = @($Records | Where-Object { $_.Ok })
  if (-not $script:UseInformationStream) {
    Write-UiLine -Message '' -ForegroundColor Gray
  }
  SB_WriteLog -Message ("Records         : {0}" -f $Records.Count) -Level 'INFO'
  SB_WriteLog -Message ("Successful      : {0}" -f $ok.Count) -Level 'OK'

  if ($errors.Count -gt 0) {
    SB_WriteLog -Message ("Errors          : {0}" -f $errors.Count) -Level 'ERROR'
    foreach ($e in ($errors | Select-Object -First 25)) {
      $msg = if (-not [string]::IsNullOrEmpty($e.Error)) { $e.Error } else { 'Unknown error' }
      SB_WriteLog -Level 'ERROR' -Message ("  ! {0} :: {1}" -f $e.Name, $msg)
    }
    if ($errors.Count -gt 25) {
      SB_WriteLog -Level 'WARN' -Message ("  ... ({0} more errors)" -f ($errors.Count - 25))
    }
  } else {
    SB_WriteLog -Message "Errors          : 0" -Level 'OK'
  }
}

function SB_ShowSummary {
  param([Parameter(Mandatory)][object]$Summary)
  $recordState = SB_GetSummaryRecords -Summary $Summary
  if (-not $recordState.Valid) { return }
  SB_ShowSummaryIdentity -Summary $Summary
  SB_ShowSummaryRecords -Records $recordState.Records
}
