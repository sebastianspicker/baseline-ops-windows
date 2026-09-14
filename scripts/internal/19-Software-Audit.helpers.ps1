#requires -version 5.1
<#
.SYNOPSIS
Private inventory, catalog, classification, and reporting helpers for software audit.
.DESCRIPTION
Keeps the public endpoint thin while preserving registry ordering, filtering,
deduplication, classification, event, proof, console, and v2 result contracts.
#>

function Test-HasProperty {
  [CmdletBinding()]
  param([Parameter(Mandatory)]$Object, [Parameter(Mandatory)][string]$Name)
  if (-not $Object) {
    return $false
  }
  return ($Object.PSObject.Properties.Match($Name).Count -gt 0)
}


function Get-PropString {
  [CmdletBinding()]
  param([Parameter(Mandatory)]$Object, [Parameter(Mandatory)][string]$Name)
  if (-not (Test-HasProperty -Object $Object -Name $Name)) {
    return ''
  }
  return [string]$Object.$Name
}

function Get-PropInt {
  [CmdletBinding()]
  param([Parameter(Mandatory)]$Object, [Parameter(Mandatory)][string]$Name, [int]$Default = 0)
  if (-not (Test-HasProperty -Object $Object -Name $Name)) {
    return $Default
  }
  try {
    return [int]$Object.$Name
  }
  catch {
    return $Default
  }
}

function ConvertFrom-JsonSafe {
  [CmdletBinding()]
  param([Parameter(Mandatory)][string]$Json)
  try {
    if ([string]::IsNullOrWhiteSpace($Json)) {
      return $null
    }
    return ($Json | ConvertFrom-Json -ErrorAction Stop)
  }
  catch {
    return $null
  }
}

function Get-SoftwareCatalogRuleArray {
  [CmdletBinding()]
  [OutputType([object[]])]
  param($CatalogObject, [Parameter(Mandatory)][string]$Name)
  if (-not $CatalogObject -or -not $CatalogObject.PSObject) {
    return @()
  }
  $property = $CatalogObject.PSObject.Properties[$Name]
  if (-not $property -or -not $property.Value) {
    return @()
  }
  return @($property.Value)
}

function Get-CatalogWrapper {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Source,
    [Parameter(Mandatory)][bool]$Loaded,
    $CatalogObject,
    [object[]]$Issues = @(),
    [object[]]$Attempts = @()
  )
  [pscustomobject]@{
    Meta = [pscustomobject]@{ Source = $Source
      Loaded = $Loaded
      Issues = @($Issues)
      Attempts = @($Attempts)
    }
    Whitelist = @(Get-SoftwareCatalogRuleArray -CatalogObject $CatalogObject -Name 'Whitelist')
    Blacklist = @(Get-SoftwareCatalogRuleArray -CatalogObject $CatalogObject -Name 'Blacklist')
  }
}

function Get-CatalogLoadIssue {
  [CmdletBinding()]
  param([Parameter(Mandatory)][string]$Kind, [Parameter(Mandatory)]$Meta)
  [pscustomobject]@{ Kind = $Kind
    Path = $Meta.Path
    Status = $Meta.Status
    Error = $Meta.Error
  }
}

function Get-ExplicitSoftwareCatalog {
  [CmdletBinding()]
  param([string]$CatalogPath, [bool]$CatalogPathProvided, [Parameter(Mandatory)]$Issues, [Parameter(Mandatory)]$Attempts)
  if ([string]::IsNullOrWhiteSpace($CatalogPath)) {
    return $null
  }
  $load = Read-JsonFileWithStatus -Path $CatalogPath
  $Attempts.Add([pscustomobject]@{ Kind = 'CatalogPath'
      Meta = $load.Meta
    })
  if ($load.Meta.Loaded) {
    return (Get-CatalogWrapper -Source 'CatalogPath' -Loaded $true -CatalogObject $load.Data -Issues $Issues -Attempts $Attempts)
  }
  if ($CatalogPathProvided) {
    $Issues.Add((Get-CatalogLoadIssue -Kind 'CatalogPath' -Meta $load.Meta))
  }
  return $null
}

function Get-SoftwareCatalogPathFromConfig {
  [CmdletBinding()]
  param($Config)
  if (-not $Config) {
    return $null
  }
  if (-not (Test-HasProperty $Config 'Software')) {
    return $null
  }
  if (-not $Config.Software) {
    return $null
  }
  if (-not (Test-HasProperty $Config.Software 'CatalogPath')) {
    return $null
  }
  return [string]$Config.Software.CatalogPath
}

function Get-ConfiguredSoftwareCatalog {
  [CmdletBinding()]
  param([string]$ConfigPath, [bool]$ConfigPathProvided, [Parameter(Mandatory)]$Issues, [Parameter(Mandatory)]$Attempts)
  if ([string]::IsNullOrWhiteSpace($ConfigPath)) {
    return $null
  }
  $configLoad = Read-JsonFileWithStatus -Path $ConfigPath
  $Attempts.Add([pscustomobject]@{ Kind = 'ConfigPath'
      Meta = $configLoad.Meta
    })
  if ($ConfigPathProvided -and -not $configLoad.Meta.Loaded) {
    $Issues.Add((Get-CatalogLoadIssue -Kind 'ConfigPath' -Meta $configLoad.Meta))
  }
  $path = Get-SoftwareCatalogPathFromConfig -Config $configLoad.Data
  if ([string]::IsNullOrWhiteSpace($path)) {
    return $null
  }
  $catalogLoad = Read-JsonFileWithStatus -Path $path
  $Attempts.Add([pscustomobject]@{ Kind = 'ConfigPath:Software.CatalogPath'
      Meta = $catalogLoad.Meta
    })
  if ($catalogLoad.Meta.Loaded) {
    return (Get-CatalogWrapper -Source 'ConfigPath:Software.CatalogPath' -Loaded $true -CatalogObject $catalogLoad.Data -Issues $Issues -Attempts $Attempts)
  }
  $Issues.Add((Get-CatalogLoadIssue -Kind 'ConfigPath:Software.CatalogPath' -Meta $catalogLoad.Meta))
  return $null
}

function Load-Catalog {
  [CmdletBinding()]
  param([string]$CatalogPath, [string]$ConfigPath, [bool]$CatalogPathProvided, [bool]$ConfigPathProvided)
  $issues = [System.Collections.Generic.List[object]]::new()
  $attempts = [System.Collections.Generic.List[object]]::new()
  $catalog = Get-ExplicitSoftwareCatalog -CatalogPath $CatalogPath -CatalogPathProvided $CatalogPathProvided -Issues $issues -Attempts $attempts
  if ($catalog) {
    return $catalog
  }
  $catalog = Get-ConfiguredSoftwareCatalog -ConfigPath $ConfigPath -ConfigPathProvided $ConfigPathProvided -Issues $issues -Attempts $attempts
  if ($catalog) {
    return $catalog
  }
  $fallback = ConvertFrom-JsonSafe -Json $Script:DefaultCatalogJson
  if ($fallback) {
    return (Get-CatalogWrapper -Source 'EmbeddedDefault' -Loaded $true -CatalogObject $fallback -Issues $issues -Attempts $attempts)
  }
  return (Get-CatalogWrapper -Source 'EmptyFallback' -Loaded $false -CatalogObject $null -Issues $issues -Attempts $attempts)
}

function ConvertTo-SoftwareInventoryItem {
  [CmdletBinding()]
  param([Parameter(Mandatory)]$RegistryValue, [Parameter(Mandatory)]$RegistryKey, [Parameter(Mandatory)][string]$HivePath)
  $properties = $RegistryValue.PSObject.Properties
  $displayNameProperty = $properties['DisplayName']
  if (-not $displayNameProperty) {
    return $null
  }
  $displayName = [string]$displayNameProperty.Value
  if ([string]::IsNullOrWhiteSpace($displayName)) {
    return $null
  }
  if ((Get-SoftwareRegistryInt -Properties $properties -Name 'SystemComponent') -eq 1) {
    return $null
  }
  $parentKeyName = Get-SoftwareRegistryString -Properties $properties -Name 'ParentKeyName'
  if (-not [string]::IsNullOrWhiteSpace($parentKeyName)) {
    return $null
  }
  $releaseType = Get-SoftwareRegistryString -Properties $properties -Name 'ReleaseType'
  if (-not [string]::IsNullOrWhiteSpace($releaseType) -and $releaseType -match 'Update|Hotfix|Security Update') {
    return $null
  }
  return [pscustomobject]@{
    Name = $displayName
    Version = Get-SoftwareRegistryString $properties 'DisplayVersion'
    Publisher = Get-SoftwareRegistryString $properties 'Publisher'
    UninstallString = Get-SoftwareRegistryString $properties 'UninstallString'
    InstallDate = Get-SoftwareRegistryString $properties 'InstallDate'
    Key = [string]$RegistryKey.PSChildName
    HivePath = $HivePath
    Source = 'Registry'
  }
}

function Get-SoftwareRegistryString {
  param($Properties, [string]$Name)
  $property = $Properties[$Name]
  if ($property) {
    return [string]$property.Value
  }
  return ''
}
function Get-SoftwareRegistryInt {
  param($Properties, [string]$Name)
  $property = $Properties[$Name]
  if (-not $property) {
    return 0
  }
  try {
    return [int]$property.Value
  }
  catch {
    return 0
  }
}

function Get-InstalledSoftware {
  [CmdletBinding()]
  param()
  $paths = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
  )
  $items = [System.Collections.Generic.List[object]]::new()
  foreach ($path in $paths) {
    foreach ($key in Get-ChildItem -Path $path -ErrorAction SilentlyContinue) {
      $value = Get-ItemProperty -Path $key.PSPath -ErrorAction SilentlyContinue
      if (-not $value) {
        continue
      }
      $item = ConvertTo-SoftwareInventoryItem -RegistryValue $value -RegistryKey $key -HivePath $path
      if ($null -ne $item) {
        $items.Add($item)
      }
    }
  }
  $dedup = @{}
  foreach ($item in $items) {
    $identity = '{0}||{1}||{2}' -f $item.Name, $item.Version, $item.Publisher
    if (-not $dedup.ContainsKey($identity)) {
      $dedup[$identity] = $item
    }
  }
  return @($dedup.Values | Sort-Object Name, Version)
}

function Test-SoftwareRuleMatch {
  [CmdletBinding()]
  [OutputType([bool])]
  param([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Rules, [Parameter(Mandatory)][string]$Name, [AllowEmptyString()][string]$Publisher)
  foreach ($rule in $Rules) {
    $nameRegex = [string]$rule.NameRegex
    $vendorRegex = [string]$rule.VendorRegex
    $nameMatches = [string]::IsNullOrWhiteSpace($nameRegex) -or $Name -match $nameRegex
    $publisherMatches = [string]::IsNullOrWhiteSpace($vendorRegex) -or $Publisher -match $vendorRegex
    if ($nameMatches -and $publisherMatches) {
      return $true
    }
  }
  return $false
}

function Test-SoftwareCompliance {
  [CmdletBinding()]
  param([Parameter(Mandatory)]$Inventory, [Parameter(Mandatory)]$Catalog)
  $blacklisted = [System.Collections.Generic.List[object]]::new()
  $whitelisted = [System.Collections.Generic.List[object]]::new()
  $unknown = [System.Collections.Generic.List[object]]::new()
  foreach ($software in $Inventory) {
    $name = [string]$software.Name
    $publisher = [string]$software.Publisher
    $allow = Test-SoftwareRuleMatch -Rules @($Catalog.Whitelist) -Name $name -Publisher $publisher
    $deny = Test-SoftwareRuleMatch -Rules @($Catalog.Blacklist) -Name $name -Publisher $publisher
    if ($deny) {
      $blacklisted.Add($software)
    }
    elseif ($allow) {
      $whitelisted.Add($software)
    }
    else {
      $unknown.Add($software)
    }
  }
  return [pscustomobject]@{ Blacklisted = $blacklisted.ToArray()
    Whitelisted = $whitelisted.ToArray()
    Unknown = $unknown.ToArray()
  }
}

function Get-AuditStatus {
  [CmdletBinding()]
  param([Parameter(Mandatory)][int]$BlacklistedCount, [Parameter(Mandatory)][int]$UnknownCount, [int]$ConfigIssueCount = 0, [switch]$Strict)
  [void]$Strict
  if ($BlacklistedCount -gt 0) {
    return [pscustomobject]@{ EventId = 4902
      Level = 'Error'
    }
  }
  if ($UnknownCount -gt 0 -or $ConfigIssueCount -gt 0) {
    return [pscustomobject]@{ EventId = 4901
      Level = 'Warning'
    }
  }
  return [pscustomobject]@{ EventId = 4900
    Level = 'Information'
  }
}

function Get-SummaryLines {
  [CmdletBinding()]
  param([Parameter(Mandatory)][int]$Total, [Parameter(Mandatory)][int]$Whitelisted, [Parameter(Mandatory)][int]$Unknown, [Parameter(Mandatory)][int]$Blacklisted, [Parameter(Mandatory)]$Audit)
  $lines = [System.Collections.Generic.List[string]]::new()
  $lines.Add(('Total={0}; Whitelisted={1}; Unknown={2}; Blacklisted={3}' -f $Total, $Whitelisted, $Unknown, $Blacklisted))
  if ($Blacklisted -gt 0) {
    $lines.Add('Blacklisted: ' + ((@($Audit.Blacklisted).Name | Sort-Object) -join '; '))
  }
  if ($Unknown -gt 0) {
    $lines.Add('Unknown: ' + ((@($Audit.Unknown).Name | Sort-Object) -join '; '))
  }
  return , $lines.ToArray()
}

function Get-SoftwareCatalogFindings {
  [CmdletBinding()]
  param([Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Issues)
  $findings = [System.Collections.Generic.List[object]]::new()
  foreach ($issue in $Issues) {
    $findings.Add([pscustomobject]@{
        Code = 'CFG-CatalogLoadFailed'
        Severity = 'Medium'
        Message = ('Explicit catalog/config input was not loaded ({0}: {1}). Defaults were used.' -f $issue.Kind, $issue.Status)
        Kind = $issue.Kind
        Path = $issue.Path
        Status = $issue.Status
        Error = $issue.Error
      })
  }
  return $findings.ToArray()
}

function New-SoftwareAuditResult {
  [CmdletBinding()]
  param([Parameter(Mandatory)]$Inventory, [Parameter(Mandatory)]$Audit, [Parameter(Mandatory)]$Catalog, [bool]$EventSourceReady, [switch]$Strict)
  $total = [int]@($Inventory).Count
  $blacklisted = [int]@($Audit.Blacklisted).Count
  $whitelisted = [int]@($Audit.Whitelisted).Count
  $unknown = [int]@($Audit.Unknown).Count
  $issues = @($Catalog.Meta.Issues)
  $status = Get-AuditStatus -BlacklistedCount $blacklisted -UnknownCount $unknown -ConfigIssueCount $issues.Count -Strict:$Strict
  $summary = Get-SummaryLines -Total $total -Whitelisted $whitelisted -Unknown $unknown -Blacklisted $blacklisted -Audit $Audit
  return [pscustomobject]@{
    Time = (Get-Date).ToString('s')
    Host = [string]$env:COMPUTERNAME
    Catalog = $Catalog
    EventSource = [pscustomobject]@{ Name = [string]$Script:EventSourceName
      Ready = $EventSourceReady
    }
    Status = $status
    Total = $total
    CountWhitelisted = $whitelisted
    CountUnknown = $unknown
    CountBlacklisted = $blacklisted
    Summary = @($summary)
    Findings = @(Get-SoftwareCatalogFindings -Issues $issues)
    Whitelisted = @($Audit.Whitelisted)
    Blacklisted = @($Audit.Blacklisted)
    Unknown = @($Audit.Unknown)
  }
}

function Write-SoftwareAuditState {
  [CmdletBinding()]
  param([Parameter(Mandatory)]$Result, [string]$StatePath)
  if ([string]::IsNullOrWhiteSpace($StatePath)) {
    return
  }
  try {
    $directory = Split-Path -Parent $StatePath
    if ($directory) {
      Ensure-Directory -Path $directory | Out-Null
    }
    ($Result | ConvertTo-Json -Depth 7) | Set-Content -Encoding UTF8 -LiteralPath $StatePath
  }
  catch {
    Write-Verbose ("Software audit state write failed for '{0}': {1}" -f $StatePath, $_.Exception.Message)
  }
}

function Write-SoftwareAuditConsole {
  [CmdletBinding()]
  param([Parameter(Mandatory)]$Result)
  $summaryObject = [pscustomobject]@{ ComputerName = [string]$Result.Host
    Timestamp = Get-Date
  }
  Write-ConsoleSummary -Summary $summaryObject -Findings ([System.Collections.ArrayList]::new()) -CustomFields ([ordered]@{
      Catalog = [string]$Result.Catalog.Meta.Source
      Status = '{0} ({1})' -f $Result.Status.EventId, $Result.Status.Level
      Total = $Result.Total
      Whitelisted = $Result.CountWhitelisted
      Unknown = $Result.CountUnknown
      Blacklisted = $Result.CountBlacklisted
      CatalogWarnings = @($Result.Catalog.Meta.Issues).Count
    })
  Write-UiLine ''
  Write-UiLine 'Summary:' -ForegroundColor 'Gray'
  foreach ($line in @($Result.Summary)) {
    Write-UiLine ('  ' + [string]$line) -ForegroundColor 'Gray'
  }
  $blacklistedNames = @($Result.Blacklisted.Name | Sort-Object)
  $unknownNames = @($Result.Unknown.Name | Sort-Object)
  Write-UiLine ''
  Write-ConsoleList -Header 'Blacklisted items:' -Items $blacklistedNames -HeaderColor 'Red' -ItemColor 'Red' -MaxItems 20
  Write-ConsoleList -Header 'Unknown items:' -Items $unknownNames -HeaderColor 'Yellow' -ItemColor 'Yellow' -MaxItems 20
}

function Write-SoftwareAuditFailure {
  [CmdletBinding()]
  param([Parameter(Mandatory)]$ErrorRecord)
  $message = [string]('SW Inventory Error: ' + $ErrorRecord.Exception.Message)
  Write-HealthEvent -Id 4902 -Msg $message -Level 'Error' | Out-Null
  Write-ConsoleBanner -Title 'Software Audit (FAILED)' -Color 'Red'
  Write-UiLine ('Error: {0}' -f $message) -ForegroundColor 'Red'
  if ($ErrorRecord.InvocationInfo) {
    Write-UiLine ('Line:    {0}' -f $ErrorRecord.InvocationInfo.ScriptLineNumber) -ForegroundColor 'DarkGray'
    Write-UiLine ('Cmd:     {0}' -f $ErrorRecord.InvocationInfo.Line.Trim()) -ForegroundColor 'DarkGray'
  }
  Write-UiLine ''
  return [pscustomobject]@{ Message = $message
    Status = [pscustomobject]@{ EventId = 4902
      Level = 'Error'
    }
    Findings = @([pscustomobject]@{ Code = 'SW-AuditFailed'
        Severity = 'High'
        Message = $message
      })
  }
}

function New-SoftwareAuditCompletion {
  [CmdletBinding()]
  param($Result, [Parameter(Mandatory)]$Status, [object[]]$Findings, [string]$RuntimeError)
  $token = if ($RuntimeError -or $Status.EventId -eq 4902) {
    'FAIL'
  }
  elseif ($Status.EventId -eq 4901) {
    'WARN'
  }
  else {
    'OK'
  }
  $summary = if ($Result) {
    $Result
  }
  else {
    [pscustomobject]@{ ComputerName = $env:COMPUTERNAME
      Timestamp = Get-Date
      Error = $RuntimeError
    }
  }
  return [pscustomobject]@{ ResultToken = $token
    Summary = $summary
    Findings = @($Findings)
  }
}

function Invoke-SoftwareAudit {
  [CmdletBinding()]
  param([bool]$CatalogPathProvided, [bool]$ConfigPathProvided)
  $eventSourceReady = Ensure-EventSource
  if (-not $eventSourceReady) {
    Write-Warning 'EventSource could not be registered. EventLog tracing will be unavailable.'
  }
  $result = $null
  $status = $null
  $findings = @()
  $runtimeError = $null
  try {
    $catalog = Load-Catalog -CatalogPath $CatalogPath -ConfigPath $ConfigPath -CatalogPathProvided $CatalogPathProvided -ConfigPathProvided $ConfigPathProvided
    $inventory = Get-InstalledSoftware
    $audit = Test-SoftwareCompliance -Inventory $inventory -Catalog $catalog
    $result = New-SoftwareAuditResult -Inventory $inventory -Audit $audit -Catalog $catalog -EventSourceReady $eventSourceReady -Strict:$Strict
    $status = $result.Status
    $findings = @($result.Findings)
    Write-SoftwareAuditState -Result $result -StatePath $StatePath
    Write-HealthEvent -Id $status.EventId -Msg ([string](@($result.Summary) -join "`r`n")) -Level $status.Level | Out-Null
    Write-SoftwareAuditConsole -Result $result
  }
  catch {
    $failure = Write-SoftwareAuditFailure -ErrorRecord $_
    $runtimeError = $failure.Message
    $status = $failure.Status
    $findings = @($failure.Findings)
  }
  return (New-SoftwareAuditCompletion -Result $result -Status $status -Findings $findings -RuntimeError $runtimeError)
}
