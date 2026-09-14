#requires -version 5.1
<#
.SYNOPSIS
Runs SupportBundle parser phases.
.DESCRIPTION
Resolves parser inputs, projects producer errors, evaluates proof evidence, and renders the terminal summary through explicit state.
#>
function Get-ConsoleColor {
  [CmdletBinding()]
  param([Parameter(Mandatory)][ValidateSet('Header','Key','Value','Ok','Warn','Error','Muted')][string]$Role)
  if ($script:NoColor) { return $null }
  return @{ Header='Cyan'; Key='Gray'; Value='White'; Ok='Green'; Warn='Yellow'; Error='Red'; Muted='DarkGray' }[$Role]
}

function ConvertTo-SafeDisplayPath {
  [CmdletBinding()]
  param(
    [Parameter()]
    [AllowNull()]
    [string]$Path
  )
  if ([string]::IsNullOrWhiteSpace($Path)) { return $null }
  $p = $Path
  $p = $p -replace '(?i)^[A-Z]:\\ProgramData\\[^\\]+\\', '[application data]\'
  $p = $p -replace '(?i)^[A-Z]:\\Users\\[^\\]+\\', '[user profile]\'
  $p = $p -replace '(?i)^[A-Z]:\\', '[local drive]\'
  return $p
}
function ConvertTo-SafeFindingDetail {
  [CmdletBinding()]
  param(
    [Parameter()]
    [AllowNull()]
    [AllowEmptyString()]
    [string]$Value
  )
  if ([string]::IsNullOrWhiteSpace($Value)) { return '<no detail supplied>' }
  $detail = ($Value -replace '[\x00-\x1F\x7F]', ' ').Trim()
  if ([string]::IsNullOrWhiteSpace($detail)) { return '<no detail supplied>' }
  if ($detail.Length -gt 1024) { $detail = $detail.Substring(0, 1024) + '...' }
  return $detail
}
# -------------------- StrictMode-safe property access --------------------
function Get-PropValue {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]
    [AllowNull()]
    [object]$Object,
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$Name,
    [Parameter()]
    [AllowNull()]
    $Default = $null
  )
  if ($null -eq $Object) { return $Default }
  $prop = $Object.PSObject.Properties.Item($Name)
  if ($null -eq $prop) { return $Default }
  return $prop.Value
}
function Get-PropArrayStrings {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]
    [AllowNull()]
    [object]$Object,
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$Name
  )
  $v = Get-PropValue -Object $Object -Name $Name -Default $null
  if ($null -eq $v) { return @() }
  return @($v | ForEach-Object { "$_" })
}
function Coalesce-Bool {
  [CmdletBinding()]
  param(
    [Parameter()]
    $Value,
    [Parameter()]
    [bool]$Default = $false
  )
  if ($null -eq $Value) { return $Default }
  try { return [bool]$Value } catch { return $Default }
}
# -------------------- File/JSON helpers --------------------
# Ensure-Directory imported from lib/Common.psm1
# Load-JsonFile replaced by Read-JsonFileSafe from lib/JsonCatalog.psm1
function Get-LatestSupportBundleZip {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$SupportDir
  )
  if (-not (Test-Path -LiteralPath $SupportDir -PathType Container)) { return $null }
  Get-ChildItem -LiteralPath $SupportDir -Filter 'SupportBundle-*.zip' -File -ErrorAction SilentlyContinue |
    Sort-Object LastWriteTime -Descending |
    Select-Object -First 1
}
function Resolve-WorkDirAndSummary {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]
    [System.IO.FileInfo]$Zip,
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$ExtractRoot,
    [Parameter()]
    [switch]$ForceExtract
  )
  $notes = New-Object System.Collections.Generic.List[string]
  $workDir = Ensure-ExtractedWorkDir -ZipPath $Zip.FullName -ExtractRoot $ExtractRoot -Force:$ForceExtract
  if (-not $workDir) {
    return $null
  }
  if ($workDir -and (Test-Path -LiteralPath $workDir -PathType Container)) {
    $workSummaryPath = Join-Path -Path $workDir -ChildPath 'Summary.json'
    if (Test-Path -LiteralPath $workSummaryPath -PathType Leaf) {
      $summary = Read-JsonFileSafe -Path $workSummaryPath
      if ($summary) {
        return [pscustomobject]@{
          ZipPath     = $Zip.FullName
          ZipName     = $Zip.Name
          SummaryPath = $workSummaryPath
          WorkDir     = $workDir
          Summary     = $summary
          Notes       = @($notes)
        }
      }
    }
  }
  return $null
}
function Exit-ParserFailure {
  [CmdletBinding()]
  param([Parameter(Mandatory)][string]$Message)
  Add-Finding -FindingList $script:Findings -Code 'SB-ParserFailure' -Severity 'High' -Message $Message
  $summary = [pscustomobject]@{ Error = $Message; SupportDir = $SupportDir; ConfigPath = $ConfigPath; ExtractRoot = $ExtractRoot }
  $v2Result = Get-V2ResultObject -ScriptName '10-SupportBundle-Parser.ps1' -Mode $Mode -Result 'FAIL' -Findings (ConvertTo-ObjectArray -InputObject $script:Findings) -Summary $summary -Metadata @{}
  Write-ResultObject -ResultObject $v2Result -OutputFormat $OutputFormat -OutputPath $OutputPath
  if ($PassThru) { $v2Result }
  exit 1
}
function Find-FileUnderDir {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$Dir,
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$FileName
  )
  if (-not (Test-Path -LiteralPath $Dir -PathType Container)) { return $null }
  $hit = Get-ChildItem -LiteralPath $Dir -Recurse -File -Filter $FileName -ErrorAction SilentlyContinue | Select-Object -First 1
  if ($hit) { return $hit.FullName }
  return $null
}
# -------------------- Domain logic --------------------
function Get-DefaultExpectedProofFiles {
  [CmdletBinding()]
  param()
  @(
    'SysmonState.json'
    'SysmonDriftState.json'
    'SoftwareInventory.json'
    'FirewallAudit.json'
    'HardwareAudit.json'
  )
}
function Get-ConfiguredProofPaths {
  param($ConfigObject)
  if (-not $ConfigObject) { return @() }
  $proofProperty = $ConfigObject.PSObject.Properties.Item('ProofOutFiles')
  if (-not $proofProperty -or -not $proofProperty.Value) { return @() }
  $proofs = $proofProperty.Value
  return @(
    Get-PropValue $proofs SysmonState $null; Get-PropValue $proofs SysmonDriftState $null
    Get-PropValue $proofs SoftwareInventory $null; Get-PropValue $proofs FirewallAudit $null; Get-PropValue $proofs HardwareAudit $null
  ) | Where-Object { $_ }
}

function Get-ExpectedProofFiles {
  [CmdletBinding()]
  param($ConfigObject)
  $paths = @(Get-ConfiguredProofPaths -ConfigObject $ConfigObject)
  if ($paths.Count -eq 0) { return Get-DefaultExpectedProofFiles }
  return @($paths | ForEach-Object { try { Split-Path -Path $_ -Leaf } catch { "$_" } })
}

function Get-ProofFilePresence {
  param([string]$FileName, [string[]]$Outputs, [string]$SearchDir)
  $pattern = [regex]::Escape($FileName)
  $byOutput = [bool]($Outputs | Where-Object { $_ -match $pattern } | Select-Object -First 1)
  $byDirect = $false; $byRecurse = $false; $foundPath = $null
  if ($SearchDir -and (Test-Path -LiteralPath $SearchDir -PathType Container)) {
    $candidate = Join-Path $SearchDir $FileName
    if (Test-Path -LiteralPath $candidate -PathType Leaf) { $byDirect = $true; $foundPath = $candidate }
    else { $foundPath = Find-FileUnderDir -Dir $SearchDir -FileName $FileName; $byRecurse = [bool]$foundPath }
  }
  return [pscustomobject]@{
    FileName=$FileName; Present=($byOutput -or $byDirect -or $byRecurse); PresentByOutput=$byOutput
    PresentByFile=($byDirect -or $byRecurse); PresentByDirect=$byDirect; PresentByRecurse=$byRecurse; FoundPath=$foundPath
  }
}

function Get-ProofPresence {
  [CmdletBinding()]
  param([AllowNull()][AllowEmptyCollection()][string[]]$Outputs=@(), [AllowNull()][AllowEmptyCollection()][string[]]$ExpectedProofFileNames=@(), [AllowNull()][string]$SearchDir)
  foreach ($fileName in @($ExpectedProofFileNames)) { Get-ProofFilePresence -FileName $fileName -Outputs @($Outputs) -SearchDir $SearchDir }
}

function Get-EventLogFiles {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$WorkDir
  )
  $evDir = Join-Path -Path $WorkDir -ChildPath 'eventlogs'
  if (-not (Test-Path -LiteralPath $evDir -PathType Container)) {
    return [pscustomobject]@{ EventLogDirExists = $false; EventLogs = @() }
  }
  $evtx = Get-ChildItem -LiteralPath $evDir -Filter '*.evtx' -File -ErrorAction SilentlyContinue
  return [pscustomobject]@{ EventLogDirExists = $true; EventLogs = @($evtx.FullName) }
}
function Get-KBStatusSummary {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$WorkDir
  )
  $kbStatusPath = Join-Path -Path $WorkDir -ChildPath 'KBStatus.json'
  if (-not (Test-Path -LiteralPath $kbStatusPath -PathType Leaf)) {
    $kbStatusPath = Find-FileUnderDir -Dir $WorkDir -FileName 'KBStatus.json'
  }
  if (-not $kbStatusPath) {
    return [pscustomobject]@{
      KbStatusPath    = (Join-Path -Path $WorkDir -ChildPath 'KBStatus.json')
      Present         = $false
      Installed       = @()
      MissingZeroDay  = @()
      MissingCritical = @()
      Summary         = $null
    }
  }
  $kb = Read-JsonFileSafe -Path $kbStatusPath
  if (-not $kb) {
    return [pscustomobject]@{
      KbStatusPath    = $kbStatusPath
      Present         = $false
      Installed       = @()
      MissingZeroDay  = @()
      MissingCritical = @()
      Summary         = $null
    }
  }
  return [pscustomobject]@{
    KbStatusPath    = $kbStatusPath
    Present         = $true
    Installed       = @((Get-PropValue -Object $kb -Name 'Installed' -Default @()))
    MissingZeroDay  = @((Get-PropValue -Object $kb -Name 'MissingZeroDay' -Default @()))
    MissingCritical = @((Get-PropValue -Object $kb -Name 'MissingCritical' -Default @()))
    Summary         = (Get-PropValue -Object $kb -Name 'Summary' -Default $null)
  }
}
function Add-ProofPresenceFindings {
  param([pscustomobject[]]$Proofs, [bool]$WorkDirExists, [System.Collections.Generic.List[string]]$LegacyFindings)
  if (@($Proofs | Where-Object { -not $_.Present }).Count -gt 0) {
    $message = 'At least one expected proof file is missing.'
    Add-Finding -FindingList $script:Findings -Code SB-MissingProof -Severity Medium -Message $message
    [void]$LegacyFindings.Add($message)
  }
  if (-not $WorkDirExists) {
    $message = 'WorkDir not found; event logs and KB status may be incomplete.'
    Add-Finding -FindingList $script:Findings -Code SB-NoWorkDir -Severity Low -Message $message
    [void]$LegacyFindings.Add($message)
  }
}

function Add-KbStatusFindings {
  param($KbStatus, [System.Collections.Generic.List[string]]$LegacyFindings)
  if (-not $KbStatus -or -not $KbStatus.Present) { return }
  foreach ($item in @(
      @{ Values=@($KbStatus.MissingZeroDay);Code='SB-MissingZeroDayKB';Severity='High';Message='Missing zero-day KBs reported by KBStatus.json.' },
      @{ Values=@($KbStatus.MissingCritical);Code='SB-MissingCriticalKB';Severity='Medium';Message='Missing critical KBs reported by KBStatus.json.' }
    )) {
    if ($item.Values.Count -eq 0) { continue }
    Add-Finding -FindingList $script:Findings -Code $item.Code -Severity $item.Severity -Message $item.Message
    [void]$LegacyFindings.Add($item.Message)
  }
}

function Invoke-FindingsCheck {
  [CmdletBinding()]
  param([AllowNull()][AllowEmptyCollection()][pscustomobject[]]$Proofs=@(), [Parameter(Mandatory)][bool]$WorkDirExists, [Parameter(Mandatory)]$KbStatus)
  $legacy = [System.Collections.Generic.List[string]]::new()
  Add-ProofPresenceFindings -Proofs $Proofs -WorkDirExists $WorkDirExists -LegacyFindings $legacy
  Add-KbStatusFindings -KbStatus $KbStatus -LegacyFindings $legacy
  return $legacy.ToArray()
}

function Initialize-SupportBundleParserEntry {
  param($V2Context)
  if ($V2Context.Quiet) { $InformationPreference = 'SilentlyContinue'; $VerbosePreference = 'SilentlyContinue' }
  $script:NoColor = [bool]$V2Context.NoColor
  $ErrorActionPreference = 'Stop'
}

function New-SupportBundleUnsupportedSummary {
  param([string]$Mode)
  return [pscustomobject]@{ ComputerName=$env:COMPUTERNAME;Timestamp=Get-Date;Mode=$Mode;Supported=$false;Notes=@('Skipped: this script is only supported on Windows hosts.') }
}

function Get-SupportBundleCommonDataPath {
  if ($PSVersionTable.PSEdition -eq 'Core' -and -not $IsWindows) { return $env:ProgramData }
  return [Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)
}

function Get-SupportBundleParserPaths {
  param([string]$SupportDir, [string]$ConfigPath, [string]$ExtractRoot, [string]$ScriptRoot)
  $commonData = Get-SupportBundleCommonDataPath
  if ([string]::IsNullOrWhiteSpace($commonData)) { throw 'CommonApplicationData could not be resolved.' }
  $defaultSupport = Join-Path (Join-Path $commonData 'BaselineOpsForWindows') SupportBundles
  $trustedExtract = Join-Path $defaultSupport _extracted
  $support = $(if ([string]::IsNullOrWhiteSpace($SupportDir)) { $defaultSupport } else { $SupportDir })
  $config = $(if ([string]::IsNullOrWhiteSpace($ConfigPath)) { Join-Path $ScriptRoot support-bundle.json } else { $ConfigPath })
  $extract = $(if ([string]::IsNullOrWhiteSpace($ExtractRoot)) { $trustedExtract } else { $ExtractRoot })
  try { $allowed = [IO.Path]::GetFullPath($extract).Equals([IO.Path]::GetFullPath($trustedExtract),[StringComparison]::OrdinalIgnoreCase) }
  catch { $allowed = $false }
  return [pscustomobject]@{ SupportDir=$support;ConfigPath=$config;ExtractRoot=$(if($allowed){[IO.Path]::GetFullPath($trustedExtract)}else{$extract});TrustedExtractRoot=$trustedExtract;ExtractRootAllowed=$allowed }
}

function New-SupportBundleParserState {
  return [pscustomobject]@{
    Notes=[System.Collections.Generic.List[string]]::new();Bundle=$null;Summary=$null;Outputs=@();Errors=@()
    WorkDir=$null;WorkDirExists=$false;Proofs=@();EventInfo=[pscustomobject]@{EventLogDirExists=$false;EventLogs=@()}
    KbInfo=[pscustomobject]@{KbStatusPath=$null;Present=$false;Installed=@();MissingZeroDay=@();MissingCritical=@();Summary=$null}
    LegacyFindings=@();Result=$null
  }
}

function Add-SupportBundleProducerRecordErrors {
  param($State)
  $errors=[System.Collections.Generic.List[string]]::new()
  foreach ($record in @(Get-PropValue $State.Summary Records @())) {
    if ($null -eq $record) { continue }
    $recordOk=Get-PropValue $record Ok $null
    if ($recordOk -isnot [bool] -or $recordOk) { continue }
    $name=ConvertTo-SafeFindingDetail ([string](Get-PropValue $record Name '<unnamed>'))
    $errorText=[string](Get-PropValue $record Error $null)
    if ([string]::IsNullOrWhiteSpace($errorText)) { $errorText=[string](Get-PropValue $record Note $null) }
    $detail=ConvertTo-SafeFindingDetail $errorText
    [void]$errors.Add(('{0}: {1}' -f $name,$detail))
    Add-Finding -FindingList $script:Findings -Code SB-ProducerError -Severity Medium -Message ("SupportBundle producer record '{0}' failed: {1}" -f $name,$detail) -Extra @{RecordName=$name}|Out-Null
  }
  return $errors.ToArray()
}

function Initialize-SupportBundleSummaryData {
  param($State)
  $State.Outputs=@(Get-PropArrayStrings $State.Summary Outputs)
  $legacyErrors=@(Get-PropArrayStrings $State.Summary Errors)
  $recordErrors=@(Add-SupportBundleProducerRecordErrors $State)
  $State.Errors=@($legacyErrors+$recordErrors)
  foreach ($producerError in $legacyErrors) {
    $detail=ConvertTo-SafeFindingDetail $producerError
    Add-Finding -FindingList $script:Findings -Code SB-ProducerError -Severity Medium -Message ("SupportBundle producer reported an error: {0}" -f $detail)|Out-Null
  }
}

function Initialize-SupportBundleEvidence {
  param($State,[string]$ConfigPath)
  $config=Read-JsonFileSafe -Path $ConfigPath
  if (-not $config) { [void]$State.Notes.Add(('Config not loaded; using defaults (ConfigPath={0}).' -f (ConvertTo-SafeDisplayPath $ConfigPath))) }
  $expected=@(Get-ExpectedProofFiles $config)
  $State.WorkDir=$State.Bundle.WorkDir
  $State.WorkDirExists=[bool]($State.WorkDir -and (Test-Path -LiteralPath $State.WorkDir -PathType Container))
  $searchDir=$(if ($State.WorkDirExists){$State.WorkDir}else{$null})
  $State.Proofs=@(Get-ProofPresence -Outputs $State.Outputs -ExpectedProofFileNames $expected -SearchDir $searchDir)
  if ($State.WorkDirExists) {
    $State.EventInfo=Get-EventLogFiles $State.WorkDir
    $State.KbInfo=Get-KBStatusSummary $State.WorkDir
  }
  else { [void]$State.Notes.Add('WorkDir is not available; event logs and KB status may be missing.') }
  $State.LegacyFindings=Invoke-FindingsCheck -Proofs $State.Proofs -WorkDirExists $State.WorkDirExists -KbStatus $State.KbInfo
}

function New-SupportBundleParserResult {
  param($State)
  return [pscustomobject]@{
    Hostname=Get-PropValue $State.Summary Hostname $null;Time=Get-PropValue $State.Summary Time $null;Reason=Get-PropValue $State.Summary Reason $null
    User=Get-PropValue $State.Summary User $null;Admin=Coalesce-Bool (Get-PropValue $State.Summary Admin $null) $false
    Errors=@($State.Errors);Notes=@((Get-PropArrayStrings $State.Summary Notes)+@($State.Notes.ToArray()));Outputs=@($State.Outputs)
    BundleZipName=$State.Bundle.ZipName;BundleZipPath=$State.Bundle.ZipPath;SummaryPath=$State.Bundle.SummaryPath;WorkDir=$State.WorkDir
    Proofs=@($State.Proofs);EventLogDirExists=$State.EventInfo.EventLogDirExists;EventLogs=@($State.EventInfo.EventLogs);KbStatus=$State.KbInfo
    BundleArchiveValidated=$true;ZipMarkerPresent=$true;Findings=@($State.LegacyFindings)
  }
}

function Get-SupportBundleDisplayState {
  param($Result)
  $missing=@($Result.Proofs|Where-Object{-not $_.Present})
  $kbText='not present';$kbRole='Muted'
  if ($Result.KbStatus -and $Result.KbStatus.Present) {
    $zeroDay=@($Result.KbStatus.MissingZeroDay).Count;$critical=@($Result.KbStatus.MissingCritical).Count
    $kbText=('present (ZD missing: {0}, CR missing: {1})' -f $zeroDay,$critical);$kbRole=$(if ($zeroDay -gt 0 -or $critical -gt 0){'Warn'}else{'Ok'})
  }
  return [pscustomobject]@{Missing=$missing;PresentCount=@($Result.Proofs).Count-$missing.Count;Errors=@($Result.Errors).Count;Notes=@($Result.Notes).Count;Outputs=@($Result.Outputs).Count;EventLogs=@($Result.EventLogs).Count;Findings=@($Result.Findings).Count;KbText=$kbText;KbRole=$kbRole}
}

function Write-SupportBundleParserCounts {
  param($Result,$Display)
  $roles = Get-SupportBundleCountRoles $Result $Display
  Write-ConsoleHeader -Title 'SupportBundle summary'
  Write-KeyValue -Key Hostname -Value $Result.Hostname -ValueRole Value
  Write-KeyValue -Key Time -Value $Result.Time -ValueRole Value
  if ($Result.Reason) { Write-KeyValue -Key Reason -Value $Result.Reason -ValueRole Value }
  Write-KeyValue -Key User -Value $Result.User -ValueRole Value
  Write-KeyValue -Key Admin -Value $Result.Admin.ToString() -ValueRole $roles.Admin
  Write-ConsoleLine -Text '' -Role Muted
  Write-KeyValue -Key ZIP -Value $Result.BundleZipName -ValueRole Value
  Write-KeyValue -Key ZIPpath -Value (ConvertTo-SafeDisplayPath $Result.BundleZipPath) -ValueRole Muted
  Write-KeyValue -Key WorkDir -Value (ConvertTo-SafeDisplayPath $Result.WorkDir) -ValueRole Value
  Write-KeyValue -Key Summary -Value (ConvertTo-SafeDisplayPath $Result.SummaryPath) -ValueRole Muted
  Write-ConsoleLine -Text '' -Role Muted
  Write-KeyValue -Key Errors -Value $Display.Errors -ValueRole $roles.Errors
  Write-KeyValue -Key Notes -Value $Display.Notes -ValueRole $roles.Notes
  Write-KeyValue -Key Outputs -Value $Display.Outputs -ValueRole $roles.Outputs
  Write-KeyValue -Key Proofs -Value ("{0}/{1} present" -f $Display.PresentCount,@($Result.Proofs).Count) -ValueRole $roles.Proof
  Write-KeyValue -Key EventLogs -Value ("{0} (dir: {1})" -f $Display.EventLogs,$Result.EventLogDirExists) -ValueRole $roles.Events
  Write-KeyValue -Key KBStatus -Value $Display.KbText -ValueRole $Display.KbRole
  Write-ConsoleLine -Text '' -Role Muted
}

function Write-SupportBundleParserFindings {
  param($Result,$Display)
  if ($Display.Findings -eq 0) { Write-ConsoleLine -Text 'Findings: none' -Role Ok; return }
  Write-ConsoleLine -Text 'Findings:' -Role Warn
  foreach ($finding in $Result.Findings) { Write-ConsoleLine -Text ("- $finding") -Role Warn }
  if ($Display.Missing.Count -eq 0) { return }
  Write-ConsoleLine -Text '' -Role Muted
  Write-ConsoleLine -Text 'Missing proofs:' -Role Warn
  foreach ($proof in $Display.Missing) {
    $path = $proof.FoundPath
    if ($path) { $path = ConvertTo-SafeDisplayPath $path }
    if ([string]::IsNullOrWhiteSpace($path)) { $path = '<not found>' }
    Write-ConsoleLine -Text ('- {0} ({1})' -f $proof.FileName,$path) -Role Warn
  }
}

function Write-SupportBundleParserSummary {
  param($Result)
  $display=Get-SupportBundleDisplayState $Result
  Write-SupportBundleParserCounts $Result $display
  Write-SupportBundleParserFindings $Result $display
  Write-ConsoleLine -Text '============================================================' -Role Header
}

function Invoke-SupportBundleParserRun {
  param($State,[string]$SupportDir,[string]$ConfigPath,[string]$ExtractRoot,[bool]$ForceExtract)
  $zip=Get-LatestSupportBundleZip $SupportDir
  if(-not$zip){Exit-ParserFailure ("No SupportBundle-*.zip found in: {0}" -f (ConvertTo-SafeDisplayPath $SupportDir))}
  $State.Bundle=Resolve-WorkDirAndSummary -Zip $zip -ExtractRoot $ExtractRoot -ForceExtract:$ForceExtract
  if(-not$State.Bundle -or -not$State.Bundle.Summary){Exit-ParserFailure ("ZIP could not be safely extracted with a valid Summary.json: {0}" -f $zip.Name)}
  foreach($note in @($State.Bundle.Notes)){if($note){[void]$State.Notes.Add($note)}}
  $State.Summary=$State.Bundle.Summary
  Initialize-SupportBundleSummaryData $State
  Initialize-SupportBundleEvidence $State $ConfigPath
  $State.Result=New-SupportBundleParserResult $State
  Write-SupportBundleParserSummary $State.Result
}

function Get-SupportBundleParserResultToken {
  param([bool]$Strict)
  if($script:Findings.Count -eq 0){return 'OK'}
  if($Strict){return 'FAIL'}
  return 'WARN'
}

function Initialize-SupportBundleParserModules {
  param([string]$LibPath)
  Import-Module (Join-Path $LibPath Output.psm1) -Force
  Import-Module (Join-Path $LibPath Common.psm1) -Force -DisableNameChecking
  Import-Module (Join-Path $LibPath JsonCatalog.psm1) -Force
  Import-Module (Join-Path $LibPath Results.psm1) -Force
  Import-Module (Join-Path $LibPath Serialization.psm1) -Force
  Import-Module (Join-Path $LibPath Validation.psm1) -Force
}

function New-SupportBundleRootFailureResult {
  param([string]$SupportDir,[string]$ConfigPath,[string]$ExtractRoot,[string]$Mode)
  $message='ExtractRoot must equal the fixed CommonApplicationData support-bundle extraction root.'
  Add-Finding -FindingList $script:Findings -Code SB-UntrustedExtractRoot -Severity High -Message $message
  $summary=[pscustomobject]@{Error=$message;SupportDir=$SupportDir;ConfigPath=$ConfigPath;ExtractRoot=$ExtractRoot}
  return Get-V2ResultObject -ScriptName 10-SupportBundle-Parser.ps1 -Mode $Mode -Result FAIL -Findings (ConvertTo-ObjectArray $script:Findings) -Summary $summary -Metadata @{}
}

function Get-SupportBundleCountRoles {
  param($Result,$Display)
  return [pscustomobject]@{
    Admin=$(if($Result.Admin){'Ok'}else{'Muted'});Proof=$(if($Display.Missing.Count){'Warn'}else{'Ok'});Errors=$(if($Display.Errors){'Error'}else{'Ok'})
    Notes=$(if($Display.Notes){'Warn'}else{'Muted'});Outputs=$(if($Display.Outputs){'Ok'}else{'Muted'});Events=$(if($Display.EventLogs){'Ok'}else{'Muted'})
  }
}
