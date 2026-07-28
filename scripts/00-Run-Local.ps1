#requires -version 5.1
<#
.SYNOPSIS
Run a script from C:\install\mdm\ps1\scripts on the local machine.

.DESCRIPTION
Looks up the script file in C:\install\mdm\ps1\scripts (or an override)
and executes it. Optional -ScriptArgs are passed through to the script.

Supports optional integrity verification via signature check or hash comparison.

.PARAMETER ScriptName
Script file name to run (for example: 18-Firewall-Baseline.ps1).

.PARAMETER ScriptNumber
Script number only (for example: 18). Matches "18-*.ps1".

.PARAMETER ScriptArgs
Optional arguments to pass to the target script.

.PARAMETER RootPath
Override root path (default: C:\install\mdm\ps1).

.PARAMETER RequireSigned
If set, verifies the script has a valid Authenticode signature before execution.

.PARAMETER ExpectedHash
Expected hash value for the script. Format: "ALGORITHM:HASH" or just "HASH" (defaults to SHA256).
Example: "SHA256:ABC123..." or just "ABC123..."

.PARAMETER HashAlgorithm
Hash algorithm to use for verification (default: SHA256).
Valid values: SHA256, SHA384, SHA512

.EXAMPLE
.\00-Run-Local.ps1 -ScriptName 18-Firewall-Baseline.ps1

.EXAMPLE
.\00-Run-Local.ps1 -ScriptNumber 18

.EXAMPLE
.\00-Run-Local.ps1 -ScriptName 31-PowerShell-Logging-Baseline.ps1 -ScriptArgs @('-Mode','Audit')

.EXAMPLE
.\00-Run-Local.ps1 -ScriptNumber 18 -RequireSigned

.EXAMPLE
.\00-Run-Local.ps1 -ScriptName 18-Firewall-Baseline.ps1 -ExpectedHash "SHA256:ABC123DEF456..."

.EXAMPLE
# Verify hash from a hash file
$hash = (Get-Content .\hashes.txt | Where-Object { $_ -like "18-Firewall-Baseline.ps1=*" }).Split('=')[1]
.\00-Run-Local.ps1 -ScriptNumber 18 -ExpectedHash $hash
#>

[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
  [Parameter(Mandatory, ParameterSetName = 'ByName')]
  [ValidateNotNullOrEmpty()]
  [string]$ScriptName,

  [Parameter(Mandatory, ParameterSetName = 'ByNumber')]
  [ValidatePattern('^\d{1,2}$')]
  [string]$ScriptNumber,

  [string[]]$ScriptArgs,

  # Default deployment path. Override with -RootPath to use a different location
  # (for example, -RootPath $KitRoot or a value supplied by the deployment pipeline).
  [string]$RootPath = 'C:\install\mdm\ps1',

  [switch]$RequireSigned,

  [string]$ExpectedHash,

  [ValidateSet('SHA256','SHA384','SHA512')]
  [string]$HashAlgorithm = 'SHA256'

,
  [ValidateSet('Audit','Remediate')][string]$Mode = 'Audit',
  [string]$ConfigPath,
  [ValidateSet('Console','Json','Csv','None')][string]$OutputFormat = 'Console',
  [string]$OutputPath,
  [switch]$PassThru,
  [switch]$Strict,
  [switch]$Quiet,
  [switch]$NoColor
)

$rootPathWasExplicitlyBound = $PSBoundParameters.ContainsKey('RootPath')
$defaultDeploymentPresent = $false
if ([System.Environment]::OSVersion.Platform -eq [System.PlatformID]::Win32NT) {
  $defaultDeploymentPresent = Test-Path -LiteralPath (Join-Path $RootPath 'scripts') -PathType Container
}
if (-not $rootPathWasExplicitlyBound -and
    $RootPath -eq 'C:\install\mdm\ps1' -and
    -not $defaultDeploymentPresent) {
  # Preserve the deployment default. Fall back only when that deployment is
  # absent, which keeps source-tree smoke tests portable without shadowing an
  # installed kit that actually exists.
  $repoRootCandidate = Split-Path -Parent $PSScriptRoot
  if (Test-Path -LiteralPath (Join-Path $repoRootCandidate 'scripts') -PathType Container) {
    $RootPath = $repoRootCandidate
  }
}

function Assert-RunLocalTrustedWindowsAcl {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Path,
    [switch]$CheckAncestors
  )

  $trustedSids = @{
    'S-1-5-18' = $true
    'S-1-5-32-544' = $true
    'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464' = $true
  }
  $writeMask =
    [System.Security.AccessControl.FileSystemRights]::WriteData -bor
    [System.Security.AccessControl.FileSystemRights]::AppendData -bor
    [System.Security.AccessControl.FileSystemRights]::WriteExtendedAttributes -bor
    [System.Security.AccessControl.FileSystemRights]::WriteAttributes -bor
    [System.Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor
    [System.Security.AccessControl.FileSystemRights]::Delete -bor
    [System.Security.AccessControl.FileSystemRights]::ChangePermissions -bor
    [System.Security.AccessControl.FileSystemRights]::TakeOwnership
  $ancestorReplacementMask =
    [System.Security.AccessControl.FileSystemRights]::Delete -bor
    [System.Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor
    [System.Security.AccessControl.FileSystemRights]::ChangePermissions -bor
    [System.Security.AccessControl.FileSystemRights]::TakeOwnership

  $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
  $current = $item.FullName
  $isProtectedItem = $true
  while (-not [string]::IsNullOrWhiteSpace($current)) {
    $currentItem = Get-Item -LiteralPath $current -Force -ErrorAction Stop
    if (($currentItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
      throw "Privileged execution path contains a reparse point: $current"
    }
    $acl = Get-Acl -LiteralPath $currentItem.FullName -ErrorAction Stop
    $ownerSid = $acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value
    if (-not $trustedSids.ContainsKey($ownerSid)) {
      throw "Privileged execution path has an untrusted owner SID: $current"
    }
    $effectiveMask = if ($isProtectedItem) { $writeMask } else { $ancestorReplacementMask }
    foreach ($rule in @($acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]))) {
      if ($rule.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) { continue }
      if (($rule.PropagationFlags -band [System.Security.AccessControl.PropagationFlags]::InheritOnly) -ne 0) { continue }
      $sid = [string]$rule.IdentityReference.Value
      if (-not $trustedSids.ContainsKey($sid) -and
          ([int64]$rule.FileSystemRights -band [int64]$effectiveMask) -ne 0) {
        throw "Privileged execution path grants write/replace rights to an untrusted SID: $current"
      }
    }
    if (-not $CheckAncestors) { break }
    $parent = Split-Path -Parent $currentItem.FullName
    if ([string]::IsNullOrWhiteSpace($parent) -or
        [string]::Equals($parent, $currentItem.FullName, [System.StringComparison]::OrdinalIgnoreCase)) { break }
    $current = $parent
    $isProtectedItem = $false
  }
}

$isWindowsPlatform = [System.Environment]::OSVersion.Platform -eq [System.PlatformID]::Win32NT
$isElevatedWindows = $false
if ($isWindowsPlatform) {
  $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
  $principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
  $isElevatedWindows = $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

if ($isElevatedWindows) {
  # Validate the runner's own bootstrap closure before dot-sourcing or importing
  # any repository-controlled code, then validate the independently selected
  # deployment root. This prevents an already-writable root from becoming a
  # privileged execution source merely because signatures are optional.
  $runnerRoot = Split-Path -Parent $PSScriptRoot
  $runnerLib = Join-Path $runnerRoot 'lib'
  $bootstrapPath = Join-Path $PSScriptRoot '_lib/Bootstrap.ps1'
  $trustedBootstrapPaths = @(
    $runnerRoot,
    $PSScriptRoot,
    $PSCommandPath,
    $runnerLib,
    $bootstrapPath,
    (Join-Path $runnerLib 'Validation.psm1'),
    (Join-Path $runnerLib 'Output.psm1'),
    (Join-Path $runnerLib 'Execution.psm1'),
    (Join-Path $runnerLib 'Serialization.psm1'),
    $RootPath,
    (Join-Path $RootPath 'scripts'),
    (Join-Path $RootPath 'lib')
  ) | Select-Object -Unique
  foreach ($trustedPath in $trustedBootstrapPaths) {
    Assert-RunLocalTrustedWindowsAcl -Path $trustedPath -CheckAncestors:($trustedPath -in @($runnerRoot, $RootPath))
  }
}

. (Join-Path $PSScriptRoot '_lib/Bootstrap.ps1')
Import-Module (Join-Path $script:LibPath 'Validation.psm1') -Force
Import-Module (Join-Path $script:LibPath 'Output.psm1') -Force
Import-Module (Join-Path $script:LibPath 'Execution.psm1') -Force
Import-Module (Join-Path $script:LibPath 'Serialization.psm1') -Force

Set-StrictMode -Version Latest
# v2-init (migrated to Initialize-V2Context)
$script:__V2Context = Initialize-V2Context -ScriptName '00-Run-Local.ps1' -BoundParameters $PSBoundParameters `
  -Mode $Mode -ConfigPath $ConfigPath -OutputFormat $OutputFormat -OutputPath $OutputPath `
  -PassThru:$PassThru -Strict:$Strict -Quiet:$Quiet -NoColor:$NoColor
if ($script:__V2Context.Quiet) { $InformationPreference = 'SilentlyContinue'; $VerbosePreference = 'SilentlyContinue' }
$script:NoColor = [bool]$script:__V2Context.NoColor
$ErrorActionPreference = 'Stop'

$scriptsRoot = Join-Path $RootPath 'scripts'
$runnerBoundParameters = $PSBoundParameters

function Write-RunLocalFailureResult {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Code,
    [Parameter(Mandatory)][string]$Message,
    [AllowNull()][string]$TargetPath
  )

  if (-not $PassThru) {
    throw $Message
  }

  $failureResult = Get-V2ResultObject `
    -ScriptName '00-Run-Local.ps1' `
    -Mode $Mode `
    -Result 'FAIL' `
    -Findings @([pscustomobject]@{ Code = $Code; Severity = 'High'; Message = $Message }) `
    -Summary ([pscustomobject]@{ Target = $TargetPath; Error = $Message }) `
    -Metadata @{}
  Write-ResultObject -ResultObject $failureResult -OutputFormat $OutputFormat -OutputPath $OutputPath
  $failureResult
}

if (-not (Test-Path -LiteralPath $scriptsRoot)) {
  Write-RunLocalFailureResult -Code 'RunLocal-ScriptsRootMissing' -Message "Scripts root not found: $scriptsRoot" -TargetPath $scriptsRoot
  exit (Get-V2ExitCode -Result 'FAIL')
}

function Test-ResolvedPathUnderScriptsRoot {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][string]$ScriptsRootPath
  )

  # Resolve both sides before comparison so relative paths and symlinks cannot
  # escape the deployment scripts directory by string-shape tricks.
  try {
    $resolvedPath = (Resolve-Path -LiteralPath $Path -ErrorAction Stop).Path
    $resolvedRoot = (Resolve-Path -LiteralPath $ScriptsRootPath -ErrorAction Stop).Path
  } catch {
    return $false
  }

  $sepChars = @([System.IO.Path]::DirectorySeparatorChar, [System.IO.Path]::AltDirectorySeparatorChar)
  $rootPrefix = $resolvedRoot.TrimEnd($sepChars) + [System.IO.Path]::DirectorySeparatorChar
  return $resolvedPath.StartsWith($rootPrefix, [System.StringComparison]::OrdinalIgnoreCase)
}

function Test-PathIsSymlink {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Path
  )

  try {
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
  } catch {
    return $false
  }

  return [bool]($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint)
}

function Test-PathOrAncestorIsReparsePoint {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Path,
    [Parameter(Mandatory)][string]$ScriptsRootPath
  )

  # Resolve-Path alone is insufficient here: a junction within scriptsRoot can
  # still resolve to a path that looks in-bounds.  Inspect every component from
  # the root through the leaf before accepting the execution target.
  try {
    $rootFullPath = [System.IO.Path]::GetFullPath($ScriptsRootPath).TrimEnd(@([System.IO.Path]::DirectorySeparatorChar, [System.IO.Path]::AltDirectorySeparatorChar))
    $currentPath = [System.IO.Path]::GetFullPath($Path)
    while ($true) {
      $item = Get-Item -LiteralPath $currentPath -Force -ErrorAction Stop
      if ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
        return $true
      }

      if ([string]::Equals($currentPath, $rootFullPath, [System.StringComparison]::OrdinalIgnoreCase)) {
        return $false
      }

      $parentPath = Split-Path -Parent $currentPath
      if ([string]::IsNullOrWhiteSpace($parentPath)) {
        return $true
      }
      $currentPath = $parentPath
    }
  } catch {
    # A path component disappearing during validation is not safe to execute.
    return $true
  }
}

function Add-RunLocalTrustedCodeClosureLocks {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string[]]$Roots,
    [Parameter(Mandatory)][AllowEmptyCollection()][System.Collections.Generic.List[System.IO.FileStream]]$LockedStreams,
    [ValidateRange(1, 8192)][int]$MaximumItems = 4096
  )

  # The target can dot-source helpers from scripts/_lib and scripts/internal,
  # and import modules from lib.  Walk only those known code roots.  Each
  # directory and file is checked for reparse points and a trusted ACL; every
  # file remains open with no write/delete sharing until target completion.
  $pendingDirectories = New-Object 'System.Collections.Generic.Queue[string]'
  $seenDirectories = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
  $seenFiles = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
  $itemCount = 0

  foreach ($root in $Roots) {
    $rootItem = Get-Item -LiteralPath $root -Force -ErrorAction Stop
    if (-not $rootItem.PSIsContainer) {
      throw "Privileged code closure root is not a directory: $root"
    }
    if ($seenDirectories.Add($rootItem.FullName)) {
      $itemCount++
      if ($itemCount -gt $MaximumItems) { throw "Privileged code closure exceeds the $MaximumItems-item safety limit." }
      $pendingDirectories.Enqueue($rootItem.FullName)
    }
  }

  while ($pendingDirectories.Count -gt 0) {
    $directoryPath = $pendingDirectories.Dequeue()
    $directoryItem = Get-Item -LiteralPath $directoryPath -Force -ErrorAction Stop
    if (($directoryItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
      throw "Privileged code closure contains a reparse-point directory: $directoryPath"
    }
    Assert-RunLocalTrustedWindowsAcl -Path $directoryItem.FullName

    $entryEnumerator = [System.IO.Directory]::EnumerateFileSystemEntries($directoryItem.FullName).GetEnumerator()
    try {
      while ($entryEnumerator.MoveNext()) {
        $child = Get-Item -LiteralPath ([string]$entryEnumerator.Current) -Force -ErrorAction Stop
        if (($child.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
          throw "Privileged code closure contains a reparse-point item: $($child.FullName)"
        }
        if ($child.PSIsContainer) {
          if ($seenDirectories.Add($child.FullName)) {
            $itemCount++
            if ($itemCount -gt $MaximumItems) { throw "Privileged code closure exceeds the $MaximumItems-item safety limit." }
            $pendingDirectories.Enqueue($child.FullName)
          }
          continue
        }
        if (-not $seenFiles.Add($child.FullName)) { continue }
        $itemCount++
        if ($itemCount -gt $MaximumItems) { throw "Privileged code closure exceeds the $MaximumItems-item safety limit." }

        # Validate again after opening the deny-write/delete handle.  The locked
        # stream then pins the exact helper or module entry that PowerShell can
        # load during the target invocation.
        $lockedStream = New-Object System.IO.FileStream($child.FullName, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
        try {
          $lockedItem = Get-Item -LiteralPath $child.FullName -Force -ErrorAction Stop
          if (($lockedItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Privileged code closure contains a reparse-point item: $($child.FullName)"
          }
          Assert-RunLocalTrustedWindowsAcl -Path $lockedItem.FullName
          $LockedStreams.Add($lockedStream)
          $lockedStream = $null
        } finally {
          if ($null -ne $lockedStream) { $lockedStream.Dispose() }
        }
      }
    } finally {
      if ($entryEnumerator -is [System.IDisposable]) { $entryEnumerator.Dispose() }
    }
  }
}

if ($PSCmdlet.ParameterSetName -eq 'ByNumber') {
  $num = [int]$ScriptNumber
  $prefix = '{0:D2}-' -f $num
  $scriptMatches = @(Get-ChildItem -Path $scriptsRoot -Filter "$prefix*.ps1" -File)
  if ($scriptMatches.Count -eq 0) {
    Write-RunLocalFailureResult -Code 'RunLocal-ScriptNumberNotFound' -Message "No script found for number $prefix in $scriptsRoot" -TargetPath $scriptsRoot
    exit (Get-V2ExitCode -Result 'FAIL')
  }
  if ($scriptMatches.Count -gt 1) {
    $names = ($scriptMatches | Select-Object -ExpandProperty Name) -join ', '
    Write-RunLocalFailureResult -Code 'RunLocal-ScriptNumberAmbiguous' -Message "Multiple scripts match number ${prefix}: $names" -TargetPath $scriptsRoot
    exit (Get-V2ExitCode -Result 'FAIL')
  }
  $scriptPath = $scriptMatches[0].FullName
  if (Test-PathIsSymlink -Path $scriptPath) {
    Write-RunLocalFailureResult -Code 'RunLocal-ReparsePointRejected' -Message "Refusing to execute reparse-point script path: $scriptPath" -TargetPath $scriptPath
    exit (Get-V2ExitCode -Result 'FAIL')
  }
  if (-not (Test-ResolvedPathUnderScriptsRoot -Path $scriptPath -ScriptsRootPath $scriptsRoot)) {
    Write-RunLocalFailureResult -Code 'RunLocal-PathOutsideRoot' -Message 'Resolved script path is outside scripts root or invalid.' -TargetPath $scriptPath
    exit (Get-V2ExitCode -Result 'FAIL')
  }
  $scriptPath = (Resolve-Path -LiteralPath $scriptPath).Path
} else {
  # Constrain to basename only to prevent path traversal (§11/§10)
  if ($ScriptName -match '[/\\]' -or $ScriptName -match '\.\.') {
    Write-RunLocalFailureResult -Code 'RunLocal-UnsafeScriptName' -Message 'ScriptName must be a script file name without path components (e.g. 18-Firewall-Baseline.ps1).' -TargetPath $ScriptName
    exit (Get-V2ExitCode -Result 'FAIL')
  }
  $baseName = [System.IO.Path]::GetFileName($ScriptName)
  if ([string]::IsNullOrWhiteSpace($baseName)) {
    Write-RunLocalFailureResult -Code 'RunLocal-InvalidScriptName' -Message 'ScriptName must be a script file name (e.g. 18-Firewall-Baseline.ps1).' -TargetPath $ScriptName
    exit (Get-V2ExitCode -Result 'FAIL')
  }
  if ([System.IO.Path]::GetExtension($baseName) -ne '.ps1') {
    Write-RunLocalFailureResult -Code 'RunLocal-InvalidScriptExtension' -Message 'ScriptName must reference a .ps1 file.' -TargetPath $ScriptName
    exit (Get-V2ExitCode -Result 'FAIL')
  }
  $scriptPath = Join-Path $scriptsRoot $baseName
  if (-not (Test-Path -LiteralPath $scriptPath -PathType Leaf)) {
    Write-RunLocalFailureResult -Code 'RunLocal-ScriptNotFound' -Message "Script not found: $scriptPath" -TargetPath $scriptPath
    exit (Get-V2ExitCode -Result 'FAIL')
  }
  if (Test-PathIsSymlink -Path $scriptPath) {
    Write-RunLocalFailureResult -Code 'RunLocal-ReparsePointRejected' -Message "Refusing to execute reparse-point script path: $scriptPath" -TargetPath $scriptPath
    exit (Get-V2ExitCode -Result 'FAIL')
  }
  if (-not (Test-ResolvedPathUnderScriptsRoot -Path $scriptPath -ScriptsRootPath $scriptsRoot)) {
    Write-RunLocalFailureResult -Code 'RunLocal-PathOutsideRoot' -Message 'Resolved script path is outside scripts root or invalid.' -TargetPath $scriptPath
    exit (Get-V2ExitCode -Result 'FAIL')
  }
  $scriptPath = (Resolve-Path -LiteralPath $scriptPath).Path
}

# The local runner is a leaf-script execution boundary. Allowing it to target
# itself permits an argument vector to recurse until process resources fail.
if ([string]::Equals((Split-Path -Leaf $scriptPath), '00-Run-Local.ps1', [System.StringComparison]::OrdinalIgnoreCase)) {
  Write-RunLocalFailureResult -Code 'RunLocal-ControlPlaneRecursion' -Message '00-Run-Local.ps1 cannot execute itself.' -TargetPath $scriptPath
  exit (Get-V2ExitCode -Result 'FAIL')
}

# Hold the exact target open without write/delete sharing through verification
# and execution.  This binds the pathname used by Get-AuthenticodeSignature,
# Get-FileHash, and the invocation operator to one immutable file entry.
# FileShare.Read intentionally still permits signature/hash readers and the
# PowerShell script loader to read the file.
$maxScriptBytes = 10MB
$lockedScriptStream = $null
$lockedClosureStreams = New-Object 'System.Collections.Generic.List[System.IO.FileStream]'
try {
  if (Test-PathOrAncestorIsReparsePoint -Path $scriptPath -ScriptsRootPath $scriptsRoot) {
    Write-RunLocalFailureResult -Code 'RunLocal-ReparsePointRejected' -Message "Refusing to execute a script beneath a reparse-point path: $scriptPath" -TargetPath $scriptPath
    exit (Get-V2ExitCode -Result 'FAIL')
  }

  $lockedScriptStream = New-Object System.IO.FileStream($scriptPath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
  if ($lockedScriptStream.Length -gt $maxScriptBytes) {
    Write-RunLocalFailureResult -Code 'RunLocal-ScriptTooLarge' -Message "Refusing to execute script larger than $maxScriptBytes bytes: $scriptPath" -TargetPath $scriptPath
    exit (Get-V2ExitCode -Result 'FAIL')
  }

  # Re-check after acquiring the deny-write/delete handle.  If a component was
  # swapped while opening, fail closed; once this succeeds, Windows cannot
  # replace or rename the locked target before execution.
  if (Test-PathOrAncestorIsReparsePoint -Path $scriptPath -ScriptsRootPath $scriptsRoot) {
    Write-RunLocalFailureResult -Code 'RunLocal-ReparsePointRejected' -Message "Refusing to execute a script beneath a reparse-point path: $scriptPath" -TargetPath $scriptPath
    exit (Get-V2ExitCode -Result 'FAIL')
  }

  if ($isElevatedWindows) {
    # This check must follow the target lock: an untrusted principal cannot
    # swap the target between ACL validation and execution once it succeeds.
    Assert-RunLocalTrustedWindowsAcl -Path $scriptPath

    # Keep the bounded load closure trusted and immutable for the entire
    # execution window.  These roots cover repository helper dot-sources and
    # module imports without recursively treating arbitrary data as code.
    Add-RunLocalTrustedCodeClosureLocks -Roots @(
      (Join-Path $RootPath 'scripts/_lib'),
      (Join-Path $RootPath 'scripts/internal'),
      (Join-Path $RootPath 'lib')
    ) -LockedStreams $lockedClosureStreams
  }

# Integrity verification (fixes #25)
if ($RequireSigned) {
  $signature = Get-AuthenticodeSignature -FilePath $scriptPath
  if ($signature.Status -ne 'Valid') {
    Write-RunLocalFailureResult -Code 'RunLocal-SignatureInvalid' -Message "Script signature verification failed for $scriptPath : $($signature.Status)" -TargetPath $scriptPath
    exit (Get-V2ExitCode -Result 'FAIL')
  }
  Write-UiLine "Signature verified: $($signature.SignerCertificate.Subject)" -Style Success
}

if (-not [string]::IsNullOrWhiteSpace($ExpectedHash)) {
  # Parse expected hash - format can be "ALGORITHM:HASH" or just "HASH"
  $allowedHashAlgorithms = @('SHA256','SHA384','SHA512')
  $expectedAlg = $HashAlgorithm
  $expectedHashValue = $ExpectedHash.Trim()
  
  if ($expectedHashValue -match '^(\w+):([A-Fa-f0-9]+)$') {
    $expectedAlg = $Matches[1].ToUpperInvariant()
    $expectedHashValue = $Matches[2]
  }

  if ($allowedHashAlgorithms -notcontains $expectedAlg) {
    Write-RunLocalFailureResult -Code 'RunLocal-HashAlgorithmRejected' -Message "Unsupported hash algorithm '$expectedAlg'. Allowed algorithms: $($allowedHashAlgorithms -join ', ')." -TargetPath $scriptPath
    exit (Get-V2ExitCode -Result 'FAIL')
  }
  
  # Hash the already locked handle rather than reopening the mutable pathname.
  $lockedScriptStream.Position = 0
  $actualHashObj = Get-FileHash -InputStream $lockedScriptStream -Algorithm $expectedAlg
  $actualHash = $actualHashObj.Hash
  
  if (-not [string]::Equals($actualHash, $expectedHashValue, [System.StringComparison]::OrdinalIgnoreCase)) {
    Write-RunLocalFailureResult -Code 'RunLocal-HashMismatch' -Message "Hash mismatch for $scriptPath. Expected ($expectedAlg): $expectedHashValue, Actual: $actualHash" -TargetPath $scriptPath
    exit (Get-V2ExitCode -Result 'FAIL')
  }
  Write-UiLine "Hash verified ($expectedAlg)" -Style Success
}

function Invoke-TargetScript {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Path,
    [string[]]$Arguments = @(),
    [switch]$CaptureV2Result
  )

  # ScriptArgs arrives from profile JSON or CLI token arrays. Parse it once and
  # splat typed named arguments so child scripts see normal PowerShell binding.
  $parsed = Convert-ArgumentTokens -Arguments $Arguments
  $namedArgs = $parsed.Named
  $positionalArgs = @($parsed.Positional)

  foreach ($forwardedName in @('Mode','ConfigPath','Strict','Quiet','NoColor')) {
    if (-not $namedArgs.ContainsKey($forwardedName)) {
      switch ($forwardedName) {
        'Mode' { $namedArgs[$forwardedName] = $Mode }
        'ConfigPath' { if ($runnerBoundParameters.ContainsKey('ConfigPath')) { $namedArgs[$forwardedName] = $ConfigPath } }
        'Strict' { if ($Strict) { $namedArgs[$forwardedName] = $true } }
        'Quiet' { if ($Quiet) { $namedArgs[$forwardedName] = $true } }
        'NoColor' { if ($NoColor) { $namedArgs[$forwardedName] = $true } }
      }
    }
  }

  if ($CaptureV2Result) {
    $namedArgs['PassThru'] = $true
    $namedArgs['OutputFormat'] = 'None'
    if ($namedArgs.ContainsKey('OutputPath')) {
      $namedArgs.Remove('OutputPath')
    }
  }

  if ($positionalArgs.Count -gt 0) {
    & $Path @namedArgs @positionalArgs
  } else {
    & $Path @namedArgs
  }
}

function Test-RunLocalV2ResultObject {
  [CmdletBinding()]
  [OutputType([bool])]
  param([AllowNull()]$InputObject)

  if ($null -eq $InputObject -or $InputObject -is [string] -or $InputObject -is [System.ValueType]) {
    return $false
  }
  $propertyNames = @($InputObject.PSObject.Properties.Name)
  foreach ($required in @('SchemaVersion','ScriptName','Mode','Result','Findings','Summary','Metadata')) {
    if ($propertyNames -notcontains $required) { return $false }
  }
  if ([string]$InputObject.SchemaVersion -ne '2.0') { return $false }
  if ([string]::IsNullOrWhiteSpace([string]$InputObject.ScriptName)) { return $false }
  if (@('Audit','Remediate') -notcontains [string]$InputObject.Mode) { return $false }
  if (@('OK','WARN','FAIL') -notcontains [string]$InputObject.Result) { return $false }
  if ($null -eq $InputObject.Findings -or $InputObject.Findings -is [string] -or
      $InputObject.Findings -isnot [System.Collections.IEnumerable]) { return $false }
  if ($null -eq $InputObject.Metadata -or $InputObject.Metadata -is [string] -or
      $InputObject.Metadata -is [System.ValueType] -or $InputObject.Metadata -is [System.Array]) { return $false }
  return $true
}

if ($WhatIfPreference) {
  Write-UiLine ("[SKIP] {0} (WhatIf/Confirm)" -f (Split-Path -Leaf $scriptPath)) -Style 'Muted'
  $skipResult = Get-V2ResultObject `
    -ScriptName '00-Run-Local.ps1' `
    -Mode $Mode `
    -Result $(if ($Strict) { 'FAIL' } else { 'WARN' }) `
    -Findings @([pscustomobject]@{ Code = 'RunLocal-ExecutionSkipped'; Severity = 'Info'; Message = 'Target execution was skipped by WhatIf or confirmation.' }) `
    -Summary ([pscustomobject]@{ Target = $scriptPath; Executed = $false }) `
    -Metadata @{}
  Write-ResultObject -ResultObject $skipResult -OutputFormat $OutputFormat -OutputPath $OutputPath
  if ($PassThru) { $skipResult }
  exit (Get-V2ExitCode -Result $skipResult.Result)
}

try {
  $targetOutput = @(Invoke-TargetScript -Path $scriptPath -Arguments $ScriptArgs -CaptureV2Result:$PassThru)
  $targetExitCode = if ($null -eq $LASTEXITCODE) { 0 } else { [int]$LASTEXITCODE }
} catch {
  $message = "Target script invocation failed: $($_.Exception.Message)"
  Write-RunLocalFailureResult -Code 'RunLocal-TargetInvocationFailed' -Message $message -TargetPath $scriptPath
  exit (Get-V2ExitCode -Result 'FAIL')
}

if ($PassThru) {
  $v2Results = @(
    $targetOutput | Where-Object {
      Test-RunLocalV2ResultObject -InputObject $_
    }
  )

  if ($v2Results.Count -eq 1 -and $targetOutput.Count -eq 1) {
    $targetResult = $v2Results[0]
    $expectedTargetExitCode = switch ([string]$targetResult.Result) {
      'OK' { 0 }
      'WARN' { 2 }
      'FAIL' { 1 }
    }
    if ($targetExitCode -ne $expectedTargetExitCode) {
      $declaredTargetResult = [string]$targetResult.Result
      $targetResult | Add-Member -NotePropertyName RunnerExitMismatch -NotePropertyValue $true -Force
      $targetResult | Add-Member -NotePropertyName RunnerDeclaredResult -NotePropertyValue $declaredTargetResult -Force
      $targetResult | Add-Member -NotePropertyName RunnerExpectedExitCode -NotePropertyValue $expectedTargetExitCode -Force
      $targetResult | Add-Member -NotePropertyName RunnerActualExitCode -NotePropertyValue $targetExitCode -Force
      Write-Warning "Target V2 result '$($targetResult.Result)' does not match process exit code $targetExitCode. Expected $expectedTargetExitCode."

      # A more severe process result cannot be overridden by an earlier
      # optimistic V2 object. Preserve both sides of the mismatch, then use the
      # more severe contract outcome (0=OK, 2=WARN, anything else=FAIL).
      $processResult = switch ($targetExitCode) {
        0 { 'OK' }
        2 { 'WARN' }
        default { 'FAIL' }
      }
      $resultRank = @{ OK = 0; WARN = 1; FAIL = 2 }
      if ($resultRank[$processResult] -gt $resultRank[[string]$targetResult.Result]) {
        $mismatchFinding = [pscustomobject]@{
          Code = 'RunLocal-ExitContractMismatch'
          Severity = 'High'
          Message = "Target declared '$declaredTargetResult' but exited with code $targetExitCode (expected $expectedTargetExitCode)."
        }
        $targetResult.Findings = @($targetResult.Findings) + @($mismatchFinding)
        $targetResult.Result = $processResult
      }
    }
    if ($Strict -and $targetResult.Result -eq 'WARN') {
      if ($targetResult.PSObject.Properties.Name -notcontains 'RunnerDeclaredResult') {
        $targetResult | Add-Member -NotePropertyName RunnerDeclaredResult -NotePropertyValue 'WARN' -Force
      }
      $targetResult | Add-Member -NotePropertyName RunnerStrictPromotion -NotePropertyValue $true -Force
      $targetResult.Result = 'FAIL'
    }
    $targetResult
    exit (Get-V2ExitCode -Result ([string]$targetResult.Result))
  }

  if ($v2Results.Count -gt 1) {
    $message = "Target script emitted $($v2Results.Count) V2 result objects; exactly one is required."
    $failureCode = 'RunLocal-MultipleV2Results'
  } elseif ($v2Results.Count -eq 1 -and $targetOutput.Count -gt 1) {
    $message = "Target script emitted one V2 result plus $($targetOutput.Count - 1) additional success-stream item(s); exactly one total object is required."
    $failureCode = 'RunLocal-ExtraneousOutput'
  } elseif ($targetOutput.Count -gt 0) {
    $message = 'Target script emitted output but no valid V2 result.'
    $failureCode = 'RunLocal-MissingV2Result'
  } else {
    $message = 'Target script did not emit a V2 result.'
    $failureCode = 'RunLocal-MissingV2Result'
  }
  Write-Warning $message
  Write-RunLocalFailureResult -Code $failureCode -Message $message -TargetPath $scriptPath
  exit (Get-V2ExitCode -Result 'FAIL')
}

exit $targetExitCode
} finally {
  foreach ($lockedClosureStream in $lockedClosureStreams) {
    $lockedClosureStream.Dispose()
  }
  if ($null -ne $lockedScriptStream) {
    $lockedScriptStream.Dispose()
  }
}
