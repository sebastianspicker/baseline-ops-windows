<#
.SYNOPSIS
Internal catalog, collection, and evidence helpers for the Defender IOC sweep.

.DESCRIPTION
Loads bounded IOC rules and collects evidence from supported Windows sources.
The entry script imports shared modules first, making this dot-sourced file's
state dependencies explicit and keeping source failures visible in the result.
#>
$script:DefaultProofOutFile = Join-Path ([System.IO.Path]::GetTempPath()) 'IOC-Sweep-Defender-proof.json'
$script:DefaultEvidenceDir = Join-Path ([System.IO.Path]::GetTempPath()) 'IOC-Sweep-Defender-evidence'
function Initialize-IocRuntimeContext { $script:IocRemediate = [bool]$script:__V2Context.Remediate }
function Get-ObjPropValue {
  param([Parameter(Mandatory=$true)] $Obj, [Parameter(Mandatory=$true)] [string] $Name)
  try { if ($null -eq $Obj) { return $null }; $p = $Obj.PSObject.Properties[$Name]; if ($p) { return $p.Value } }
  catch { Write-Verbose ("IOC object property access failed for '{0}': {1}" -f $Name,$_.Exception.Message) }
  return $null
}
function Get-OrDefault([object]$Value, [object]$Default) { if ($null -ne $Value -and "$Value" -ne '') { return $Value }; return $Default }
function Get-DefaultCatalog {
  $cat = New-Object psobject
  Add-Member -InputObject $cat -MemberType NoteProperty -Name Proof -Value ([pscustomobject]@{ OutFile = $script:DefaultProofOutFile })
  Add-Member -InputObject $cat -MemberType NoteProperty -Name EvidenceDir -Value $script:DefaultEvidenceDir
  foreach ($name in @('Files','FileGlobs','Registry','Services','ScheduledTasks','Processes','IPs','Domains')) { Add-Member -InputObject $cat -MemberType NoteProperty -Name $name -Value @() }
  return $cat
}
# Resolves the IOC catalog from explicit input, shared configuration, or safe
# defaults while preserving load failures in the returned status object.
function Get-IocCatalogFromPath {
  param([string]$Path,[string]$Source,[Parameter(Mandatory)]$Errors)
  if ([string]::IsNullOrWhiteSpace($Path)) { return $null }
  $sanitized = Sanitize-Path -Path $Path -MustExist
  if (-not $sanitized) { return $null }
  $catalog = Read-JsonFileSafe -Path $sanitized
  if ($catalog) { return [pscustomobject]@{ Catalog = $catalog; Source = $Source } }
  $label = if ($Source -eq 'CatalogPath') { 'CatalogPath' } else { 'Config IOC.CatalogPath' }
  $Errors.Add(("{0} not loaded: {1}" -f $label, $sanitized))
  return $null
}
function Get-IocConfiguredCatalog {
  param([string]$ConfigPath,[Parameter(Mandatory)]$Errors)
  if ([string]::IsNullOrWhiteSpace($ConfigPath)) { return $null }
  $sanitized = Sanitize-Path -Path $ConfigPath -MustExist
  if (-not $sanitized) { return $null }
  $config = Read-JsonFileSafe -Path $sanitized
  if (-not $config) { $Errors.Add(("ConfigPath not loaded: {0}" -f $sanitized)); return $null }
  $path = $null
  try { if ($config.IOC -and $config.IOC.CatalogPath) { $path = [string]$config.IOC.CatalogPath } } catch { $path = $null }
  return (Get-IocCatalogFromPath -Path $path -Source 'Config->IOC.CatalogPath' -Errors $Errors)
}
function Load-Catalog {
  param([string]$CatalogPath,[string]$ConfigPath)
  $errors = [System.Collections.Generic.List[string]]::new()
  $loaded = Get-IocCatalogFromPath -Path $CatalogPath -Source 'CatalogPath' -Errors $errors
  if (-not $loaded) { $loaded = Get-IocConfiguredCatalog -ConfigPath $ConfigPath -Errors $errors }
  if ($loaded) { return [ordered]@{ Catalog = $loaded.Catalog; Source = $loaded.Source; Errors = $errors.ToArray() } }
  return [ordered]@{ Catalog = Get-DefaultCatalog; Source = 'Default'; Errors = $errors.ToArray() }
}
function Get-ProcessImageSha256([int]$ProcessId) { try { $p = Get-Process -Id $ProcessId -ErrorAction Stop; if ($p.Path) { return Get-FileSha256 -Path $p.Path } } catch { Write-Verbose ("Process image hash lookup failed for PID {0}: {1}" -f $ProcessId,$_.Exception.Message) }; return $null }
function Get-FilePublisher([string]$File) { if (-not $File -or -not (Test-Path -LiteralPath $File)) { return $null, $false }; try { $sig = Get-AuthenticodeSignature -FilePath $File -ErrorAction Stop; return $sig.SignerCertificate.Subject, ($sig.Status -eq 'Valid') } catch { return $null, $false } }
function Convert-RegProviderToRegExePath([string]$KeyPath) { if (-not $KeyPath) { return $null }; $p = $KeyPath; if ($p -like 'Registry::*') { $p = $p -replace '^Registry::','' }; $p = $p.Replace('HKLM:\','HKEY_LOCAL_MACHINE\').Replace('HKCU:\','HKEY_CURRENT_USER\').Replace('HKCR:\','HKEY_CLASSES_ROOT\').Replace('HKU:\','HKEY_USERS\').Replace('HKCC:\','HKEY_CURRENT_CONFIG\'); return $p }
# Exports registry evidence through the shared native wrapper so command
# resolution and argument handling use the repository's hardened boundary.
function Export-Reg([string]$RegPath,[string]$OutFile) { try { [void](Ensure-Directory (Split-Path -Parent $OutFile)); $res = Invoke-RegExe -Arguments @('export', $RegPath, $OutFile, '/y'); if ($res -eq $true) { return $true, $OutFile }; return $false, 'reg-export-failed' } catch { return $false, $_.Exception.Message } }
function Find-MpCmdRun { $programFiles = [Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles); if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) { $programFiles = $env:BASELINEOPS_TEST_PROGRAM_FILES }; if ([string]::IsNullOrWhiteSpace($programFiles)) { return $null }; foreach ($relative in @('Windows Defender\MpCmdRun.exe','Microsoft Defender\MpCmdRun.exe')) { $candidate = Join-Path $programFiles $relative; if (Test-Path -LiteralPath $candidate -PathType Leaf) { return $candidate } }; return $null }
# Compiles catalog regexes with length and execution-time bounds so hostile or
# accidental patterns cannot monopolize an endpoint sweep.
function New-IocRegex { param([Parameter(Mandatory)][string]$Pattern,[Parameter(Mandatory)][string]$Label); if ($Pattern.Length -gt 1024) { throw "IOC $Label regex exceeds the 1024-character limit." }; try { return New-Object System.Text.RegularExpressions.Regex($Pattern, [System.Text.RegularExpressions.RegexOptions]::CultureInvariant, ([TimeSpan]::FromMilliseconds(250))) } catch { throw "IOC $Label regex is invalid: $($_.Exception.Message)" } }
# Precompiles each supported rule exactly once and enforces per-source limits
# before any Windows evidence collection starts.
function Initialize-IocRegexRules {
  param([Parameter(Mandatory)]$Catalog)
  $groups = @(@{ Name = 'Registry'; Property = 'DataRegex'; Compiled = '__IocDataRegex' }, @{ Name = 'Services'; Property = 'ImagePathRegex'; Compiled = '__IocImagePathRegex' }, @{ Name = 'ScheduledTasks'; Property = 'Regex'; Compiled = '__IocTaskRegex' }, @{ Name = 'Processes'; Property = 'ImageRegex'; Compiled = '__IocImageRegex' })
  foreach ($group in $groups) { $entries = @($Catalog.($group.Name)); if ($entries.Count -gt 256) { throw "IOC $($group.Name) supports at most 256 rules." }; foreach ($entry in $entries) { $pattern = [string](Get-ObjPropValue $entry $group.Property); if ($pattern) { Add-Member -InputObject $entry -MemberType NoteProperty -Name $group.Compiled -Value (New-IocRegex -Pattern $pattern -Label "$($group.Name).$($group.Property)") -Force } } }
}
function Add-IocSourceStatus {
  [CmdletBinding()] param([Parameter(Mandatory)][string]$Name,[Parameter(Mandatory)][bool]$Attempted,[Parameter(Mandatory)][bool]$Succeeded,[string]$ErrorMessage)
  $script:IocRun.Proof.SourceStatus[$Name] = [ordered]@{ Attempted = $Attempted; Succeeded = $Succeeded; Error = $ErrorMessage }
  if ($Attempted -and -not $Succeeded -and -not [string]::IsNullOrWhiteSpace($ErrorMessage)) { $msg = "{0} source failed: {1}" -f $Name, $ErrorMessage; $script:IocRun.Proof.Errors.Add($msg); [void](Add-Finding -FindingList $script:IocRun.Findings -Code 'IOC-SourceFailed' -Severity 'High' -Message $msg -Extra @{ Source = $Name }) }
}

function New-IocMembershipSet {
  [CmdletBinding()]
  param([object[]]$Values)
  $set = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
  foreach ($value in $Values) { if ($null -ne $value) { [void]$set.Add([string]$value) } }
  return ,$set
}

function Get-IocDnsEntryName {
  [CmdletBinding()]
  param([Parameter(Mandatory)]$DnsEntry)
  foreach ($name in @('Entry','Name','RecordName')) {
    $value = Get-ObjPropValue $DnsEntry $name
    if ($value) { return [string]$value }
  }
  return $null
}

function New-IocDnsEntryIndex {
  [CmdletBinding()]
  param([object[]]$DnsEntries)
  $index = [System.Collections.Generic.Dictionary[string, System.Collections.Generic.List[object]]]::new([System.StringComparer]::OrdinalIgnoreCase)
  foreach ($entry in $DnsEntries) {
    $name = Get-IocDnsEntryName -DnsEntry $entry
    if (-not $name) { continue }
    $entryList = $null
    if (-not $index.TryGetValue($name, [ref]$entryList)) { $entryList = [System.Collections.Generic.List[object]]::new(); $index[$name] = $entryList }
    $entryList.Add($entry)
  }
  return ,$index
}

function Get-IocIndexedDomainMatches {
  [CmdletBinding()]
  param([object[]]$Domains, [Parameter(Mandatory)][AllowEmptyCollection()]$DnsEntryIndex)
  $domainMatches = [System.Collections.Generic.List[object]]::new()
  foreach ($domain in $Domains) {
    $entries = $null
    if ($null -ne $domain -and $DnsEntryIndex.TryGetValue([string]$domain, [ref]$entries)) { $domainMatches.AddRange($entries) }
  }
  return $domainMatches.ToArray()
}

function New-IocRunState {
  [CmdletBinding()] param([Parameter(Mandatory)]$PublicCmdlet)
  $proof = [ordered]@{
    Time = (Get-Date).ToString('s'); Hostname = $env:COMPUTERNAME; User = $env:USERNAME; IsAdmin = (Test-IsAdmin)
    Params = @{ CatalogPath = (Get-OrDefault $CatalogPath ''); ConfigPath = (Get-OrDefault $ConfigPath ''); Remediate = [bool]$script:IocRemediate; CollectEvidence = [bool]$CollectEvidence; ScanType = $ScanType; CustomScanPaths = @($CustomScanPaths); Strict = [bool]$Strict; PassThru = [bool]$PassThru }
    Catalog = @{ Source = ''; Errors = @() }; Scan = @{ Requested = $ScanType; Result = 'not-run'; MpCmdRun = $null }
    Findings = @{ Files = [Collections.Generic.List[object]]::new(); Registry = [Collections.Generic.List[object]]::new(); Services = [Collections.Generic.List[object]]::new(); Tasks = [Collections.Generic.List[object]]::new(); Processes = [Collections.Generic.List[object]]::new(); Network = [Collections.Generic.List[object]]::new() }
    Actions = [Collections.Generic.List[string]]::new(); Errors = [Collections.Generic.List[string]]::new(); SourceStatus = @{}; Summary = @{}
  }
  return [ordered]@{ Proof = $proof; Findings = (Get-FindingsList); Ok = $true; FoundAny = $false; OutFile = $script:DefaultProofOutFile; EvidenceDir = $script:DefaultEvidenceDir; Catalog = $null; PublicCmdlet = $PublicCmdlet }
}

function Initialize-IocRunCatalog {
  $loaded = Load-Catalog -CatalogPath $CatalogPath -ConfigPath $ConfigPath
  $script:IocRun.Catalog = $loaded.Catalog; Initialize-IocRegexRules -Catalog $script:IocRun.Catalog
  $script:IocRun.Proof.Catalog.Source = $loaded.Source; $script:IocRun.Proof.Catalog.Errors = @($loaded.Errors)
  $proofObject = Get-ObjPropValue $script:IocRun.Catalog 'Proof'
  if ($proofObject) { $script:IocRun.OutFile = Get-ObjPropValue $proofObject 'OutFile' }
  $script:IocRun.OutFile = [string](Get-OrDefault $script:IocRun.OutFile $script:DefaultProofOutFile)
  $script:IocRun.EvidenceDir = [string](Get-OrDefault (Get-ObjPropValue $script:IocRun.Catalog 'EvidenceDir') $script:DefaultEvidenceDir)
  if ($CollectEvidence) { [void](Ensure-Directory $script:IocRun.EvidenceDir) }
  [void](Ensure-Directory (Split-Path -Parent $script:IocRun.OutFile))
}

function Test-IocNativeEvidenceIncomplete { param($Native); return ($null -eq $Native -or $Native.TimedOut -or $Native.OutputTruncated -or $Native.StderrTruncated) }
function Add-IocDefenderResult {
  param($Native,[string]$Mp,[string]$EffectiveScanType,[string]$CustomScanPath)
  $extra = @{ MpCmdRun = $Mp; ScanType = $EffectiveScanType }; if ($CustomScanPath) { $extra.CustomScanPath = $CustomScanPath }
  if (Test-IocNativeEvidenceIncomplete $Native) {
    $script:IocRun.Ok = $false; [void](Add-Finding -FindingList $script:IocRun.Findings -Code 'IOC-DefenderError' -Severity 'Medium' -Message 'Defender scan timed out or produced truncated output.' -Extra $extra)
    return 'incomplete native evidence'
  }
  if ($Native.ExitCode -eq 2) { $script:IocRun.FoundAny = $true; [void](Add-Finding -FindingList $script:IocRun.Findings -Code 'IOC-DefenderDetection' -Severity 'High' -Message 'Defender scan reported threat(s) detected (MpCmdRun exit 2).' -Extra $extra) }
  elseif ($Native.ExitCode -ne 0) { $script:IocRun.Ok = $false; $extra.ExitCode = $Native.ExitCode; [void](Add-Finding -FindingList $script:IocRun.Findings -Code 'IOC-DefenderError' -Severity 'Medium' -Message ("Defender scan exited with unexpected code {0}." -f $Native.ExitCode) -Extra $extra) }
  return "exit:$($Native.ExitCode)"
}

function Invoke-IocCustomDefenderScan {
  param([string]$Mp)
  if (-not $CustomScanPaths -or $CustomScanPaths.Count -eq 0) { return 'skipped' }
  $expanded = @(Get-IocValidCustomScanPaths)
  if ($expanded.Count -eq 0) { return 'skipped(no valid CustomScanPaths)' }
  $results = [Collections.Generic.List[string]]::new()
  foreach ($path in $expanded) {
    $native = Invoke-NativeCommand -Command $Mp -Arguments @('-Scan','-ScanType','3','-File',$path) -CaptureOutput -Quiet -TimeoutSeconds 3600 -MaxOutputBytes 1048576
    $status = Add-IocDefenderResult -Native $native -Mp $Mp -EffectiveScanType 'Custom' -CustomScanPath $path
    if ($status -eq 'incomplete native evidence') { $results.Add(("custom:{0} incomplete native evidence" -f $path)) } else { $results.Add(("custom:{0} {1}" -f $path, $status)) }
  }
  return ($results -join '; ')
}

function Get-IocValidCustomScanPaths {
  $expanded = [Collections.Generic.List[string]]::new()
  foreach ($candidate in $CustomScanPaths) { $path = Expand-Env $candidate; if ($path -and (Test-Path -LiteralPath $path)) { $expanded.Add($path) } }
  return $expanded.ToArray()
}

function Get-IocDefenderScanType { if ($ScanType -eq 'Quick') { return 1 }; return 2 }

function Invoke-IocDefenderScan {
  try {
    $mp = Find-MpCmdRun; $scan = @{ Requested = $ScanType; Result = 'skipped'; MpCmdRun = $mp }; $script:IocRun.Proof.Scan = $scan
    if ($mp -and $ScanType -eq 'None') { $scan.Result = Invoke-IocCustomDefenderScan -Mp $mp }
    elseif ($mp) { $type = Get-IocDefenderScanType; $native = Invoke-NativeCommand -Command $mp -Arguments @('-Scan','-ScanType',"$type") -CaptureOutput -Quiet -TimeoutSeconds 3600 -MaxOutputBytes 1048576; $scan.Result = Add-IocDefenderResult -Native $native -Mp $mp -EffectiveScanType $ScanType }
    $script:IocRun.Proof.Scan = $scan
  } catch {
    if (-not $script:IocRun.Proof.Scan -or -not $script:IocRun.Proof.Scan.ContainsKey('Requested')) { $script:IocRun.Proof.Scan = @{ Requested = $ScanType; Result = 'failed'; MpCmdRun = $null } }
    $script:IocRun.Proof.Errors.Add("Defender scan failed: $($_.Exception.Message)"); $script:IocRun.Ok = $false
  }
}

function Add-IocFileEvidence {
  param([string]$Path)
  if (-not $CollectEvidence) { return $null }
  $copied,$output = Copy-ToEvidence -SourcePath $Path -EvidenceBaseDir $script:IocRun.EvidenceDir
  if ($copied) { return $output }
  $script:IocRun.Proof.Errors.Add("Evidence copy failed ($Path): $output"); $script:IocRun.Ok = $false; return $null
}

function Test-IocFileRuleMatch {
  param($Rule,[string]$Sha,[string]$Publisher)
  $expectedSha = [string](Get-ObjPropValue $Rule 'Sha256'); $expectedSigner = [string](Get-ObjPropValue $Rule 'Signer')
  $shaMatches = ($expectedSha -and $Sha -and ($Sha -ieq $expectedSha)); $signerMatches = ($expectedSigner -and $Publisher -and ($Publisher -like ("*{0}*" -f $expectedSigner)))
  $matched = if ($expectedSha) { $shaMatches } elseif ($expectedSigner) { $signerMatches } else { $false }
  return [pscustomobject]@{ Matched = $matched; Sha256 = $shaMatches; Signer = $signerMatches }
}

function Invoke-IocFileRules {
  foreach ($rule in @($script:IocRun.Catalog.Files)) {
    $path = Expand-Env ([string](Get-ObjPropValue $rule 'Path')); if (-not $path -or -not (Test-Path -LiteralPath $path)) { continue }
    $sha = Get-FileSha256 -Path $path; $publisher,$valid = Get-FilePublisher $path
    $match = Test-IocFileRuleMatch -Rule $rule -Sha $sha -Publisher $publisher; if (-not $match.Matched) { continue }
    $script:IocRun.FoundAny = $true; $finding = [ordered]@{ Kind = 'File'; Path = $path; Sha256 = $sha; Publisher = $publisher; Signed = $valid; Evidence = (Add-IocFileEvidence -Path $path); Action = (Get-ObjPropValue $rule 'Action'); Match = [ordered]@{ Sha256 = $match.Sha256; Signer = $match.Signer } }
    $script:IocRun.Proof.Findings.Files.Add($finding); [void](Add-Finding -FindingList $script:IocRun.Findings -Code 'IOC-FileMatch' -Severity 'High' -Message "IOC file match: $path" -Extra $finding)
  }
}

function Invoke-IocGlobRules {
  foreach ($rule in @($script:IocRun.Catalog.FileGlobs)) {
    $glob = Expand-Env ([string](Get-ObjPropValue $rule 'Glob')); if (-not $glob) { continue }; $directory = Split-Path $glob -Parent; if (-not (Test-Path -LiteralPath $directory)) { continue }
    foreach ($hit in Get-ChildItem -LiteralPath $directory -Filter (Split-Path $glob -Leaf) -File -ErrorAction SilentlyContinue) {
      $sha = Get-FileSha256 -Path $hit.FullName; $publisher,$valid = Get-FilePublisher $hit.FullName
      if (-not (Test-IocGlobRuleMatch -Rule $rule -Sha $sha -Publisher $publisher)) { continue }
      $script:IocRun.FoundAny = $true; $script:IocRun.Proof.Findings.Files.Add([ordered]@{ Kind = 'Glob'; Path = $hit.FullName; Sha256 = $sha; Publisher = $publisher; Signed = $valid; Evidence = (Add-IocFileEvidence -Path $hit.FullName); Action = (Get-ObjPropValue $rule 'Action') })
    }
  }
}

function Test-IocGlobRuleMatch {
  param($Rule,[string]$Sha,[string]$Publisher)
  $expectedSha = [string](Get-ObjPropValue $Rule 'Sha256'); $expectedSigner = [string](Get-ObjPropValue $Rule 'Signer')
  if ($expectedSha -and $Sha -and ($Sha -ine $expectedSha)) { return $false }; if (Test-IocSignerMismatch -Expected $expectedSigner -Actual $Publisher) { return $false }
  return [bool]($expectedSha -or $expectedSigner)
}
function Test-IocSignerMismatch { param([string]$Expected,[string]$Actual); return ($Expected -and $Actual -and ($Actual -notlike ("*{0}*" -f $Expected))) }

function Invoke-IocRegistryRemediation {
  param($Rule,[string]$Path,[string]$Key,[string]$Value)
  if (-not $script:IocRemediate -or (Get-ObjPropValue $Rule 'Action') -ne 'neutralize') { return }
  try {
    if ($script:IocRun.PublicCmdlet.ShouldProcess($Path, 'Neutralize registry value')) { Remove-ItemProperty -Path $Key -Name $Value -Force -ErrorAction Stop; $script:IocRun.Proof.Actions.Add("Registry neutralized: $Path") }
    else { $script:IocRun.Proof.Actions.Add("Registry neutralize skipped by ShouldProcess: $Path") }
  } catch { $script:IocRun.Proof.Errors.Add("Registry neutralize failed ($Path): $($_.Exception.Message)"); $script:IocRun.Ok = $false }
}

function Add-IocRegistryEvidence {
  param([string]$Key)
  if (-not $CollectEvidence) { return $null }
  $safeKey = $Key -replace '[:\\]','_'; $outputPath = Join-Path $script:IocRun.EvidenceDir ("reg-{0}.reg" -f $safeKey)
  $exported,$output = Export-Reg -RegPath (Convert-RegProviderToRegExePath $Key) -OutFile $outputPath
  if ($exported) { return $output }
  $script:IocRun.Proof.Errors.Add("Reg export failed ($Key): $output"); $script:IocRun.Ok = $false; return $null
}

function Invoke-IocRegistryRules {
  foreach ($rule in @($script:IocRun.Catalog.Registry)) {
    $path = [string](Get-ObjPropValue $rule 'Path'); if (-not $path) { continue }; $key = Split-Path $path -Parent; $value = Split-Path $path -Leaf
    try { $property = Get-ItemProperty -Path $key -ErrorAction Stop; if ($property.PSObject.Properties.Name -notcontains $value) { continue }; $data = $property.$value } catch { continue }
    $pattern = [string](Get-ObjPropValue $rule 'DataRegex'); if ($pattern -and -not $rule.__IocDataRegex.IsMatch([string]$data)) { continue }
    $script:IocRun.FoundAny = $true; $finding = [ordered]@{ Path = $path; Data = $data; Evidence = (Add-IocRegistryEvidence -Key $key); Action = (Get-ObjPropValue $rule 'Action') }
    $script:IocRun.Proof.Findings.Registry.Add($finding); [void](Add-Finding -FindingList $script:IocRun.Findings -Code 'IOC-RegistryMatch' -Severity 'High' -Message "IOC registry match: $path" -Extra $finding)
    Invoke-IocRegistryRemediation -Rule $rule -Path $path -Key $key -Value $value
  }
}

function Invoke-IocServiceRemediation {
  param($Service,[string]$Action)
  if (-not $script:IocRemediate -or $Action -notin @('disable','stop')) { return }
  try {
    if ($script:IocRun.PublicCmdlet.ShouldProcess($Service.Name, "Contain service ($Action)")) { if ($Service.State -ne 'Stopped') { Stop-Service -Name $Service.Name -Force -ErrorAction Stop }; if ($Action -eq 'disable') { Set-Service -Name $Service.Name -StartupType Disabled -ErrorAction Stop }; $script:IocRun.Proof.Actions.Add("Service remediated: $($Service.Name) ($Action)") }
    else { $script:IocRun.Proof.Actions.Add("Service remediation skipped by ShouldProcess: $($Service.Name) ($Action)") }
  } catch { $script:IocRun.Proof.Errors.Add("Service remediation failed ($($Service.Name)): $($_.Exception.Message)"); $script:IocRun.Ok = $false }
}

function Invoke-IocServices {
  $requested = (@($script:IocRun.Catalog.Services).Count -gt 0); $failed = $false
  foreach ($rule in @($script:IocRun.Catalog.Services)) {
    $name = [string](Get-ObjPropValue $rule 'Name'); if (-not $name) { continue }
    try {
      $service = Get-CimInstance -ClassName Win32_Service -Filter ("Name='{0}'" -f ($name -replace "'", "''")) -ErrorAction Stop
      Invoke-IocServiceRule -Rule $rule -Service $service
    } catch { $failed = $true; Add-IocSourceStatus -Name 'Services' -Attempted $true -Succeeded $false -ErrorMessage $_.Exception.Message; Write-Warning "IOC service sweep error: $($_.Exception.Message)" }
  }
  if ($requested -and -not $failed) { Add-IocSourceStatus -Name 'Services' -Attempted $true -Succeeded $true }
}

function Invoke-IocServiceRule {
  param($Rule,$Service)
  $image = $Service.PathName; $pattern = [string](Get-ObjPropValue $Rule 'ImagePathRegex'); if ($pattern -and -not $Rule.__IocImagePathRegex.IsMatch([string]$image)) { return }
  $script:IocRun.FoundAny = $true; $action = [string](Get-ObjPropValue $Rule 'Action'); $finding = [ordered]@{ Name = $Service.Name; DisplayName = $Service.DisplayName; State = $Service.State; StartMode = $Service.StartMode; ImagePath = $image; Action = $action }
  $script:IocRun.Proof.Findings.Services.Add($finding); [void](Add-Finding -FindingList $script:IocRun.Findings -Code 'IOC-ServiceMatch' -Severity 'High' -Message "IOC service match: $($Service.Name)" -Extra $finding); Invoke-IocServiceRemediation -Service $Service -Action $action
}

function Get-IocScheduledTasks {
  if (@($script:IocRun.Catalog.ScheduledTasks).Count -eq 0) { return @() }
  try { $tasks = @(Get-ScheduledTask -ErrorAction Stop); Add-IocSourceStatus -Name 'ScheduledTasks' -Attempted $true -Succeeded $true; return $tasks }
  catch { Add-IocSourceStatus -Name 'ScheduledTasks' -Attempted $true -Succeeded $false -ErrorMessage $_.Exception.Message; Write-Warning "IOC scheduled task sweep error: $($_.Exception.Message)"; return @() }
}

function Invoke-IocTaskRemediation {
  param($Task,[string]$FullPath,[string]$Action)
  if (-not $script:IocRemediate -or $Action -ne 'disable') { return }
  try {
    if ($script:IocRun.PublicCmdlet.ShouldProcess($FullPath, 'Disable scheduled task')) { Disable-ScheduledTask -TaskName $Task.TaskName -TaskPath $Task.TaskPath -ErrorAction Stop | Out-Null; $script:IocRun.Proof.Actions.Add("Task disabled: $FullPath") }
    else { $script:IocRun.Proof.Actions.Add("Task disable skipped by ShouldProcess: $FullPath") }
  } catch { $script:IocRun.Proof.Errors.Add("Task disable failed ($FullPath): $($_.Exception.Message)"); $script:IocRun.Ok = $false }
}

function Invoke-IocTasks {
  $allTasks = @(Get-IocScheduledTasks)
  foreach ($rule in @($script:IocRun.Catalog.ScheduledTasks)) {
    $pattern = [string](Get-ObjPropValue $rule 'Regex'); if (-not $pattern) { continue }
    foreach ($task in $allTasks) {
      Invoke-IocTaskRule -Rule $rule -Task $task
    }
  }
}

function Invoke-IocTaskRule {
  param($Rule,$Task)
  $full = $Task.TaskPath + $Task.TaskName; if (-not $Rule.__IocTaskRegex.IsMatch([string]$full)) { return }; $script:IocRun.FoundAny = $true; $state = 'Unknown'
  try { $info = Get-ScheduledTaskInfo -TaskName $Task.TaskName -TaskPath $Task.TaskPath -ErrorAction Stop; if ($info -and $info.State) { $state = $info.State.ToString() } } catch { $state = 'Unknown' }
  $action = [string](Get-ObjPropValue $Rule 'Action'); $finding = [ordered]@{ Path = $full; Enabled = [bool]$Task.Enabled; State = $state; Action = $action }
  $script:IocRun.Proof.Findings.Tasks.Add($finding); [void](Add-Finding -FindingList $script:IocRun.Findings -Code 'IOC-TaskMatch' -Severity 'High' -Message "IOC task match: $full" -Extra $finding); Invoke-IocTaskRemediation -Task $Task -FullPath $full -Action $action
}

function Get-IocProcesses {
  if (@($script:IocRun.Catalog.Processes).Count -eq 0) { return @() }
  try { $processes = @(Get-Process -ErrorAction Stop); Add-IocSourceStatus -Name 'Processes' -Attempted $true -Succeeded $true; return $processes }
  catch { Add-IocSourceStatus -Name 'Processes' -Attempted $true -Succeeded $false -ErrorMessage $_.Exception.Message; Write-Warning "IOC process sweep error: $($_.Exception.Message)"; return @() }
}

function Invoke-IocProcesses {
  $processes = @(Get-IocProcesses)
  foreach ($rule in @($script:IocRun.Catalog.Processes)) {
    $pattern = [string](Get-ObjPropValue $rule 'ImageRegex'); if (-not $pattern) { continue }
    foreach ($process in $processes) {
      Invoke-IocProcessRule -Rule $rule -Process $process
    }
  }
}

function Invoke-IocProcessRule {
  param($Rule,$Process)
  try { $image = $Process.Path } catch { $image = $null }; if (-not $image -or -not $Rule.__IocImageRegex.IsMatch([string]$image)) { return }
  $sha = Get-ProcessImageSha256 -ProcessId $Process.Id; $publisher,$valid = Get-FilePublisher $image; $signer = [string](Get-ObjPropValue $Rule 'Signer')
  if ($signer -and $publisher -and ($publisher -notlike ("*{0}*" -f $signer))) { return }
  $script:IocRun.FoundAny = $true; $finding = [ordered]@{ Name = $Process.Name; Id = $Process.Id; Path = $image; Sha256 = $sha; Publisher = $publisher; Signed = $valid; Action = (Get-ObjPropValue $Rule 'Action') }
  $script:IocRun.Proof.Findings.Processes.Add($finding); [void](Add-Finding -FindingList $script:IocRun.Findings -Code 'IOC-ProcessMatch' -Severity 'High' -Message "IOC process match: $($Process.Name) ($($Process.Id))" -Extra $finding)
}

function Add-IocIpFindings {
  param([Parameter(Mandatory)]$NetworkFindings)
  $ipSet = New-IocMembershipSet -Values @($script:IocRun.Catalog.IPs); if ($ipSet.Count -eq 0) { return }
  try { $connections = @(Get-NetTCPConnection -State Established,SynSent,SynReceived -ErrorAction Stop); Add-IocSourceStatus -Name 'NetworkConnections' -Attempted $true -Succeeded $true }
  catch { Add-IocSourceStatus -Name 'NetworkConnections' -Attempted $true -Succeeded $false -ErrorMessage $_.Exception.Message; Write-Warning "IOC network connection sweep error: $($_.Exception.Message)"; $connections = @() }
  foreach ($connection in $connections) {
    if (-not $ipSet.Contains([string]$connection.RemoteAddress)) { continue }; $script:IocRun.FoundAny = $true; $processName = $null
    try { $processName = (Get-Process -Id $connection.OwningProcess -ErrorAction Stop).Name } catch { $processName = $null }
    $finding = [ordered]@{ Kind = 'IP'; Remote = $connection.RemoteAddress; Local = $connection.LocalAddress; LPort = $connection.LocalPort; RPort = $connection.RemotePort; State = $connection.State; OwningProcess = $connection.OwningProcess; ProcessName = $processName }
    $NetworkFindings.Add($finding); [void](Add-Finding -FindingList $script:IocRun.Findings -Code 'IOC-NetworkIPMatch' -Severity 'High' -Message "IOC network match: IP $($connection.RemoteAddress)" -Extra $finding)
  }
}

function Add-IocDomainFindings {
  param([Parameter(Mandatory)]$NetworkFindings)
  $domains = @($script:IocRun.Catalog.Domains); if ($domains.Count -eq 0) { return }
  try {
    $dns = @(Get-DnsClientCache -ErrorAction Stop); Add-IocSourceStatus -Name 'DnsCache' -Attempted $true -Succeeded $true; $index = New-IocDnsEntryIndex -DnsEntries $dns
    foreach ($hit in Get-IocIndexedDomainMatches -Domains $domains -DnsEntryIndex $index) {
      $entry = Get-IocDnsEntryName -DnsEntry $hit; if (-not $entry) { continue }; $script:IocRun.FoundAny = $true; $type = Get-ObjPropValue $hit 'Type'; if (-not $type) { $type = Get-ObjPropValue $hit 'RecordType' }
      $finding = [ordered]@{ Kind = 'Domain'; Entry = $entry; Type = $type; Data = (Get-ObjPropValue $hit 'Data') }
      $NetworkFindings.Add($finding); [void](Add-Finding -FindingList $script:IocRun.Findings -Code 'IOC-NetworkDomainMatch' -Severity 'High' -Message "IOC network match: Domain $entry" -Extra $finding)
    }
  } catch { Add-IocSourceStatus -Name 'DnsCache' -Attempted $true -Succeeded $false -ErrorMessage $_.Exception.Message; Write-Warning "IOC network DNS cache check error: $($_.Exception.Message)" }
}

function Invoke-IocNetwork {
  $findings = [Collections.Generic.List[object]]::new(); Add-IocIpFindings -NetworkFindings $findings; Add-IocDomainFindings -NetworkFindings $findings
  if ($findings.Count -gt 0) { $script:IocRun.Proof.Findings.Network = $findings }
}

function Save-IocRunProof {
  Save-Json -InputObject $script:IocRun.Proof -Path $script:IocRun.OutFile -Depth 50
  if ($script:IocRun.FoundAny -or $script:IocRun.Proof.Errors.Count -gt 0 -or $Strict) { $message = "IOC sweep: findings/errors detected. Proof: $($script:IocRun.OutFile)"; if ($script:IocRun.Proof.Errors.Count -gt 0) { $message += ' | Errors: ' + ($script:IocRun.Proof.Errors -join ' | ') }; Write-HealthEvent -Id 10010 -Msg $message -Level 'Warning' }
  else { Write-HealthEvent -Id 10000 -Msg ("IOC sweep: OK (no findings). Proof: $($script:IocRun.OutFile)") -Level 'Information' }
}

function Invoke-IocSweepWork {
  try {
    Initialize-IocRunCatalog; Invoke-IocDefenderScan; Invoke-IocFileRules; Invoke-IocGlobRules; Invoke-IocRegistryRules; Invoke-IocServices; Invoke-IocTasks; Invoke-IocProcesses; Invoke-IocNetwork; Save-IocRunProof
  } catch {
    $script:IocRun.Ok = $false; $errorMessage = "IOC sweep failed: $($_.Exception.Message)"; $script:IocRun.Proof.Errors.Add($errorMessage)
    try { Save-Json -InputObject $script:IocRun.Proof -Path $script:IocRun.OutFile -Depth 50 } catch { Write-Verbose ("Partial IOC proof save failed: {0}" -f $_.Exception.Message) }
    Write-HealthEvent -Id 10010 -Msg $errorMessage -Level 'Error'
  }
}

function Set-IocRunSummary {
  $proof = $script:IocRun.Proof; $counts = [ordered]@{ Files = @($proof.Findings.Files).Count; Registry = @($proof.Findings.Registry).Count; Services = @($proof.Findings.Services).Count; Tasks = @($proof.Findings.Tasks).Count; Processes = @($proof.Findings.Processes).Count; Network = @($proof.Findings.Network).Count }
  $total = 0; foreach ($count in $counts.Values) { $total += $count }; $exitCode = if ($script:IocRun.Ok -and -not $script:IocRun.FoundAny -and $proof.Errors.Count -eq 0) { 0 } else { 1 }
  $proof.Summary = @{ CatalogSource = $proof.Catalog.Source; FindingsTotal = $total; Files = $counts.Files; Registry = $counts.Registry; Services = $counts.Services; Tasks = $counts.Tasks; Processes = $counts.Processes; Network = $counts.Network; Actions = $proof.Actions.Count; Errors = $proof.Errors.Count; ExitCode = $exitCode; ProofFile = $script:IocRun.OutFile; EvidenceDir = $script:IocRun.EvidenceDir }
  return [pscustomobject]@{ Counts = $counts; ExitCode = $exitCode }
}

function Write-IocRunHeader {
  param($Summary)
  $proof = $script:IocRun.Proof; Write-UiHeader 'IOC Sweep (Defender) - Result'; Write-KeyValue 'Time' $proof.Time -ValueStyle Gray; Write-KeyValue 'Host' $proof.Hostname -ValueStyle Gray; Write-KeyValue 'User' $proof.User -ValueStyle Gray
  $adminColor = if ($proof.IsAdmin) { [ConsoleColor]::Green } else { [ConsoleColor]::Yellow }; Write-KeyValue 'Admin' ([string]$proof.IsAdmin) -ValueStyle $adminColor
  $catalogColor = if ($proof.Catalog.Source -eq 'Default') { [ConsoleColor]::Yellow } else { [ConsoleColor]::Green }; Write-KeyValue 'Catalog' $proof.Catalog.Source -ValueStyle $catalogColor
  if (@($proof.Catalog.Errors).Count -gt 0) { Write-UiStatus -Label 'Catalog warnings' -State 'WARN' -Detail ("{0} issue(s)" -f @($proof.Catalog.Errors).Count); foreach ($errorMessage in $proof.Catalog.Errors) { Write-UiBullet $errorMessage DarkGray } } else { Write-UiStatus -Label 'Catalog load' -State 'OK' -Detail 'No issues' }
  Write-KeyValue 'Scan' ("{0} -> {1}" -f (Get-OrDefault $proof.Scan.Requested 'n/a'), (Get-OrDefault $proof.Scan.Result 'n/a')) -ValueStyle Cyan; Write-KeyValue 'Proof' $script:IocRun.OutFile -ValueStyle Gray; Write-KeyValue 'Evidence' $script:IocRun.EvidenceDir -ValueStyle Gray; Write-UiLine ''
  if ($Summary.ExitCode -eq 0) { Write-UiStatus -Label 'Overall status' -State 'OK' -Detail 'No findings and no errors' } elseif ($proof.Errors.Count -gt 0) { Write-UiStatus -Label 'Overall status' -State 'FAIL' -Detail 'Errors occurred (check proof file)' } else { Write-UiStatus -Label 'Overall status' -State 'WARN' -Detail 'Findings detected (check proof file)' }
}

function Write-IocRunCounts {
  param($Summary)
  Write-UiLine ''; Write-UiLine 'Findings breakdown:' DarkGray
  foreach ($name in @('Files','Registry','Services','Tasks','Processes','Network')) { Write-IocCount -Name $name -Count $Summary.Counts[$name] }
  Write-UiLine ''; $actionColor = Get-IocCountColor $script:IocRun.Proof.Actions.Count; $errorColor = if ($script:IocRun.Proof.Errors.Count -gt 0) { [ConsoleColor]::Red } else { [ConsoleColor]::Green }; $exitColor = Get-IocCountColor $Summary.ExitCode
  Write-KeyValue 'Actions' ([string]$script:IocRun.Proof.Actions.Count) -ValueStyle $actionColor; Write-KeyValue 'Errors' ([string]$script:IocRun.Proof.Errors.Count) -ValueStyle $errorColor; Write-KeyValue 'ExitCode' ([string]$Summary.ExitCode) -ValueStyle $exitColor
  if ($script:IocRun.Proof.Errors.Count -gt 0) { Write-UiLine ''; Write-UiStatus -Label 'Error details' -State 'FAIL'; foreach ($errorMessage in $script:IocRun.Proof.Errors) { Write-UiBullet $errorMessage Red } }
}

function Get-IocCountColor { param([int]$Count); if ($Count -gt 0) { return [ConsoleColor]::Yellow }; return [ConsoleColor]::Green }
function Write-IocCount { param([string]$Name,[int]$Count); Write-UiBullet ("{0,-10}{1}" -f ("${Name}:"), $Count) (Get-IocCountColor $Count) }

function Write-IocRunConsole {
  param($Summary)
  Write-IocRunHeader -Summary $Summary; Write-IocRunCounts -Summary $Summary
}

function Get-IocResultToken {
  param($Summary)
  if ($Summary.ExitCode -ne 0) { return 'FAIL' }
  if ($script:IocRun.Findings.Count -gt 0) { return 'WARN' }
  return 'OK'
}
