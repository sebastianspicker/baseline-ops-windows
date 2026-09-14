<#
.SYNOPSIS
Scheduled task hygiene catalog helpers.

.DESCRIPTION
Contains capability-private catalog behavior for scheduled task inventory and policy evaluation.
#>
function Get-TaskTrustedPathRoots {
  $windowsRoot = [Environment]::GetFolderPath([Environment+SpecialFolder]::Windows)
  $programFiles = [Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles)
  $programFilesX86 = [Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFilesX86)
  $nativeWindows = [Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT
  $windowsRoot = Get-TaskPathRootOrFallback -Value $windowsRoot -Fallback 'C:\Windows' -NativeWindows:$nativeWindows
  $programFiles = Get-TaskPathRootOrFallback -Value $programFiles -Fallback 'C:\Program Files' -NativeWindows:$nativeWindows
  $programFilesX86 = Get-TaskPathRootOrFallback -Value $programFilesX86 -Fallback 'C:\Program Files (x86)' -NativeWindows:$nativeWindows
  if ([string]::IsNullOrWhiteSpace($windowsRoot)) { throw 'Trusted Windows directory is unavailable.' }
  return @{
    Windows = $windowsRoot
    ProgramFiles = $programFiles
    ProgramFilesX86 = $programFilesX86
  }
}

function Get-TaskPathRootOrFallback {
  param([string]$Value, [string]$Fallback, [switch]$NativeWindows)
  if ([string]::IsNullOrWhiteSpace($Value) -and -not $NativeWindows) { return $Fallback }
  return $Value
}

function Expand-NormalizePath {
  param([string]$Path)
  if ([string]::IsNullOrWhiteSpace($Path)) { return $null }
  $roots = Get-TaskTrustedPathRoots
  $p2 = $Path
  foreach ($entry in @(
      @{ Pattern = '%(?:SystemRoot|WINDIR)%'; Value = $roots.Windows },
      @{ Pattern = '%ProgramFiles%'; Value = $roots.ProgramFiles },
      @{ Pattern = '%ProgramFiles\(x86\)%'; Value = $roots.ProgramFilesX86 }
    )) {
    if (-not [string]::IsNullOrWhiteSpace([string]$entry.Value)) {
      $replacement = [string]$entry.Value
      $p2 = [regex]::Replace($p2, $entry.Pattern, $replacement, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase, ([TimeSpan]::FromMilliseconds(100)))
    }
  }
  if ($p2 -match '^[\\/](System32|SysWOW64)[\\/]' ) {
    $p2 = "{0}\{1}" -f $roots.Windows.TrimEnd('\'),$p2.TrimStart('\','/')
  }
  return $p2
}

function Match-AnyRegex {
  param([string]$Text,[object]$Patterns)
  if ([string]::IsNullOrWhiteSpace($Text) -or $null -eq $Patterns) { return $false }
  foreach($p in @($Patterns)) {
    if ($p -and $p.IsMatch($Text)) { return $true }
  }
  return $false
}

function New-TaskCatalogRegex { param([string]$Pattern,[string]$Label); if ($Pattern.Length -gt 1024) { throw "Tasks $Label regex exceeds the 1024-character limit." }; try { New-Object System.Text.RegularExpressions.Regex($Pattern, [System.Text.RegularExpressions.RegexOptions]::CultureInvariant, ([TimeSpan]::FromMilliseconds(250))) } catch { throw "Tasks $Label regex is invalid: $($_.Exception.Message)" } }

function Initialize-TaskCatalogRegex { param($Catalog); foreach ($name in @('CriticalTasks','AllowTaskExact','DenyActionPathRegex','DenyCommandLineRegex','AllowPublisherOrgRegex')) { $patterns = @($Catalog.$name | Where-Object { $null -ne $_ }); if ($patterns.Count -gt 256) { throw "Tasks $name supports at most 256 patterns." }; $compiled = foreach ($pattern in $patterns) { if ($pattern -isnot [string]) { throw "Tasks $name must contain strings." }; New-TaskCatalogRegex -Pattern $pattern -Label $name }; $Catalog | Add-Member -NotePropertyName $name -NotePropertyValue @($compiled) -Force } }

function StartsWithAny {
  param([string]$Text,[object]$Prefixes)
  if ([string]::IsNullOrWhiteSpace($Text) -or $null -eq $Prefixes) { return $false }
  foreach($p in @($Prefixes)) {
    if (-not [string]::IsNullOrWhiteSpace([string]$p) -and $Text -like "$p*") { return $true }
  }
  return $false
}

function Get-DefaultCatalog {
  param([string]$QuarantineDir,[string]$ProofOutFile)
  $roots = Get-TaskTrustedPathRoots
  return [pscustomobject]([ordered]@{
    CriticalTasks = @(
      "\\Microsoft\\Windows\\Windows Defender\\.*",
      "\\Microsoft\\Windows\\WindowsUpdate\\Scheduled Start",
      "\\Microsoft\\Windows\\UpdateOrchestrator\\Schedule Scan",
      "\\Microsoft\\Windows\\DiskCleanup\\SilentCleanup",
      "\\Microsoft\\Windows\\StorageSense\\.*",
      "\\Microsoft\\Windows\\Servicing\\StartComponentCleanup"
    )
    AllowTaskExact = @()
    AllowActionPathPrefixes = @(
      "$($roots.Windows)\",
      "$($roots.ProgramFiles)\",
      "$($roots.ProgramFilesX86)\"
    )
    DenyActionPathRegex = @(
      "(?i)\\Users\\[^\\]+\\AppData\\",
      "(?i)\\Users\\[^\\]+\\Downloads\\",
      "(?i)\\Windows\\Temp\\",
      "(?i)\\ProgramData\\Temp\\"
    )
    DenyCommandLineRegex = @(
      "(?i)\bpowershell(\.exe)?\b.*\b-enc(odedcommand)?\b",
      "(?i)\bcmd(\.exe)?\b.*\b/c\b.*(AppData\\|\\Users\\|\\Windows\\Temp\\|\\ProgramData\\Temp\\)"
    )
    AllowPublisherOrgRegex = @(
      "(?i)\bO=Microsoft Corporation\b"
    )
    PurgeUnapproved = $false
    QuarantineDir   = $QuarantineDir
    Proof           = [pscustomobject]([ordered]@{ OutFile = $ProofOutFile })
  })
}

function Add-MissingTaskCatalogCollections {
  param([object]$Catalog, [object]$Fallback)
  foreach($k in @('CriticalTasks','AllowTaskExact','AllowActionPathPrefixes','DenyActionPathRegex','DenyCommandLineRegex','AllowPublisherOrgRegex')) {
    if ($null -eq (Get-PropValue $Catalog $k $null)) {
      $Catalog | Add-Member -NotePropertyName $k -NotePropertyValue (Get-PropValue $Fallback $k @()) -Force
    }
  }
}

function Add-MissingTaskCatalogOutputs {
  param([object]$Catalog, [object]$Fallback)
  if ($null -eq (Get-PropValue $Catalog 'PurgeUnapproved' $null)) {
    $Catalog | Add-Member -NotePropertyName 'PurgeUnapproved' -NotePropertyValue $false -Force
  }
  if ([string]::IsNullOrWhiteSpace([string](Get-PropValue $Catalog 'QuarantineDir' $null))) {
    $Catalog | Add-Member -NotePropertyName 'QuarantineDir' -NotePropertyValue (Get-PropValue $Fallback 'QuarantineDir' $DefaultQuarantineDir) -Force
  }
  $proof = Get-PropValue $Catalog 'Proof' $null
  if ($null -eq $proof) {
    $Catalog | Add-Member -NotePropertyName 'Proof' -NotePropertyValue ([pscustomobject]([ordered]@{ OutFile = (Get-PropValue $Fallback.Proof 'OutFile' $DefaultProofOutFile) })) -Force
  } else {
    $out = Get-PropValue $proof 'OutFile' $null
    if ([string]::IsNullOrWhiteSpace([string]$out)) {
      $proof | Add-Member -NotePropertyName 'OutFile' -NotePropertyValue (Get-PropValue $Fallback.Proof 'OutFile' $DefaultProofOutFile) -Force
    }
  }
}

function Normalize-Catalog {
  param([object]$cat,[object]$fallback)
  if ($null -eq $cat) { return $fallback }
  Add-MissingTaskCatalogCollections -Catalog $cat -Fallback $fallback
  Add-MissingTaskCatalogOutputs -Catalog $cat -Fallback $fallback
  return $cat
}

function Read-RequiredTaskCatalog {
  param([string]$Path, [string]$Source, [object]$DefaultCatalog)
  $catalogResult = Read-JsonFileWithStatus -Path $Path
  if (-not $catalogResult.Meta.Loaded) {
    throw "$Source failed to load ($($catalogResult.Meta.Status)): $($catalogResult.Meta.Error)"
  }
  return (Normalize-Catalog -cat $catalogResult.Data -fallback $DefaultCatalog)
}

function Read-RequiredTaskConfiguration {
  param([string]$Path)
  if ([string]::IsNullOrWhiteSpace($Path)) { return $null }
  $configResult = Read-JsonFileWithStatus -Path $Path
  if (-not $configResult.Meta.Loaded) {
    throw "Explicit task config failed to load ($($configResult.Meta.Status)): $($configResult.Meta.Error)"
  }
  return $configResult.Data
}

function Load-Catalog {
  param([string]$CatalogPath,[string]$ConfigPath,[object]$DefaultCatalog)
  if (-not [string]::IsNullOrWhiteSpace($CatalogPath)) {
    return Read-RequiredTaskCatalog -Path $CatalogPath -Source 'Explicit task catalog' -DefaultCatalog $DefaultCatalog
  }
  $config = Read-RequiredTaskConfiguration -Path $ConfigPath
  $settings = if ($config) { Get-PropValue $config 'TasksHygiene' $null } else { $null }
  $configuredPath = if ($settings) { Get-PropValue $settings 'CatalogPath' $null } else { $null }
  if (-not [string]::IsNullOrWhiteSpace([string]$configuredPath)) {
    return Read-RequiredTaskCatalog -Path ([string]$configuredPath) `
      -Source 'Task catalog referenced by ConfigPath' -DefaultCatalog $DefaultCatalog
  }
  return (Normalize-Catalog -cat $null -fallback $DefaultCatalog)
}
