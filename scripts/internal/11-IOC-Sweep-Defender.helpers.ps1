<#
.SYNOPSIS
Internal catalog, collection, and evidence helpers for the Defender IOC sweep.

.DESCRIPTION
Loads bounded IOC rules and collects evidence from supported Windows sources.
The entry script imports shared modules first, making this dot-sourced file's
state dependencies explicit and keeping source failures visible in the result.
#>
function Get-ObjPropValue {
  param([Parameter(Mandatory=$true)] $Obj, [Parameter(Mandatory=$true)] [string] $Name)
  try { if ($null -eq $Obj) { return $null }; $p = $Obj.PSObject.Properties[$Name]; if ($p) { return $p.Value } }
  catch { Write-Verbose ("IOC object property access failed for '{0}': {1}" -f $Name,$_.Exception.Message) }
  return $null
}
function Get-OrDefault([object]$Value, [object]$Default) { if ($null -ne $Value -and "$Value" -ne '') { return $Value }; return $Default }
function Get-DefaultCatalog {
  $cat = New-Object psobject
  Add-Member -InputObject $cat -MemberType NoteProperty -Name Proof -Value ([pscustomobject]@{ OutFile = $DefaultProofOutFile })
  Add-Member -InputObject $cat -MemberType NoteProperty -Name EvidenceDir -Value $DefaultEvidenceDir
  foreach ($name in @('Files','FileGlobs','Registry','Services','ScheduledTasks','Processes','IPs','Domains')) { Add-Member -InputObject $cat -MemberType NoteProperty -Name $name -Value @() }
  return $cat
}
# Resolves the IOC catalog from explicit input, shared configuration, or safe
# defaults while preserving load failures in the returned status object.
function Load-Catalog {
  param([string]$CatalogPath,[string]$ConfigPath)
  $res = [ordered]@{ Catalog = $null; Source = 'Default'; Errors = @() }
  $sanitizedCatalog = if ([string]::IsNullOrWhiteSpace($CatalogPath)) { $null } else { Sanitize-Path -Path $CatalogPath -MustExist }
  if ($sanitizedCatalog) { $c = Read-JsonFileSafe -Path $sanitizedCatalog; if ($c) { $res.Catalog = $c; $res.Source = 'CatalogPath'; return $res }; $res.Errors += ("CatalogPath not loaded: {0}" -f $sanitizedCatalog) }
  $cfg = $null; $sanitizedConfig = if ([string]::IsNullOrWhiteSpace($ConfigPath)) { $null } else { Sanitize-Path -Path $ConfigPath -MustExist }
  if ($sanitizedConfig) { $cfg = Read-JsonFileSafe -Path $sanitizedConfig; if (-not $cfg) { $res.Errors += ("ConfigPath not loaded: {0}" -f $sanitizedConfig) } }
  $p = $null; try { if ($cfg -and $cfg.IOC -and $cfg.IOC.CatalogPath) { $p = [string]$cfg.IOC.CatalogPath } } catch { $p = $null }
  if ($p) { $sanitizedP = Sanitize-Path -Path $p -MustExist; if ($sanitizedP) { $c2 = Read-JsonFileSafe -Path $sanitizedP; if ($c2) { $res.Catalog = $c2; $res.Source = 'Config->IOC.CatalogPath'; return $res }; $res.Errors += ("Config IOC.CatalogPath not loaded: {0}" -f $sanitizedP) } }
  $res.Catalog = Get-DefaultCatalog; return $res
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
  $Proof.SourceStatus[$Name] = [ordered]@{ Attempted = $Attempted; Succeeded = $Succeeded; Error = $ErrorMessage }
  if ($Attempted -and -not $Succeeded -and -not [string]::IsNullOrWhiteSpace($ErrorMessage)) { $msg = "{0} source failed: {1}" -f $Name, $ErrorMessage; $Proof.Errors += $msg; [void](Add-Finding -FindingList $script:Findings -Code 'IOC-SourceFailed' -Severity 'High' -Message $msg -Extra @{ Source = $Name }) }
}
