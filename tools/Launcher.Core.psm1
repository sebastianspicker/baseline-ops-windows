#requires -Version 5.1

<#
.SYNOPSIS
  Core services for the BaselineOps for Windows launcher.
.DESCRIPTION
  Validates launcher requests and trusted files before worker processes execute scripts.
#>

Set-StrictMode -Version Latest

Import-Module (Join-Path $PSScriptRoot '../lib/Validation.psm1') -Force

if (-not ('LauncherOutputCollector' -as [type])) {
  Add-Type -TypeDefinition @'
using System;
using System.Collections.Concurrent;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

public sealed class LauncherOutputCollector : IDisposable
{
    private readonly object sync = new object();
    private readonly StreamWriter writer;
    private readonly long maximumBytes;
    private readonly int maximumPending;
    private long bytesWritten;
    private bool truncated;
    private bool logWriteFailed;
    private int pendingCount;

    public LauncherOutputCollector(string logPath, long maximumBytes, int maximumPending)
    {
        this.maximumBytes = maximumBytes;
        this.maximumPending = maximumPending;
        this.Pending = new ConcurrentQueue<string>();
        this.writer = new StreamWriter(logPath, false, new UTF8Encoding(true));
    }

    public ConcurrentQueue<string> Pending { get; private set; }
    public bool LogWriteFailed { get { return this.logWriteFailed; } }

    public void AddLine(string line)
    {
        if (line == null) return;
        lock (this.sync)
        {
            if (!this.truncated && !this.logWriteFailed)
            {
                try
                {
                    long size = Encoding.UTF8.GetByteCount(line + Environment.NewLine);
                    if (this.bytesWritten + size <= this.maximumBytes)
                    {
                        this.writer.WriteLine(line);
                        this.writer.Flush();
                        this.bytesWritten += size;
                    }
                    else
                    {
                        this.writer.WriteLine("[OUTPUT TRUNCATED: temporary full log reached 25 MiB]");
                        this.writer.Flush();
                        this.truncated = true;
                    }
                }
                catch { this.logWriteFailed = true; }
            }
        }

        this.Pending.Enqueue(line);
        int currentCount = Interlocked.Increment(ref this.pendingCount);
        string discarded;
        while (currentCount > this.maximumPending && this.Pending.TryDequeue(out discarded))
        {
            currentCount = Interlocked.Decrement(ref this.pendingCount);
        }
    }

    private async Task Drain(StreamReader reader, string prefix)
    {
        char[] buffer = new char[4096];
        try
        {
            int count;
            while ((count = await reader.ReadAsync(buffer, 0, buffer.Length).ConfigureAwait(false)) > 0)
            {
                string chunk = new string(buffer, 0, count).Replace("\r\n", "\n").Replace('\r', '\n');
                foreach (string piece in chunk.Split(new char[] { '\n' })) this.AddLine(prefix + piece);
            }
        }
        catch (Exception exception)
        {
            this.AddLine("ERROR: output stream drain failed: " + exception.Message);
        }
    }

    public Task DrainOutputAsync(StreamReader reader) { return this.Drain(reader, String.Empty); }
    public Task DrainErrorAsync(StreamReader reader) { return this.Drain(reader, "ERROR: "); }

    public bool TryDequeue(out string line)
    {
        if (!this.Pending.TryDequeue(out line)) return false;
        Interlocked.Decrement(ref this.pendingCount);
        return true;
    }

    public void Flush()
    {
        lock (this.sync) { this.writer.Flush(); }
    }

    public void Dispose()
    {
        lock (this.sync) { this.writer.Dispose(); }
    }
}

public sealed class LauncherProcessJob : IDisposable
{
    private const uint JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000;
    private IntPtr handle;

    [StructLayout(LayoutKind.Sequential)]
    private struct JOBOBJECT_BASIC_LIMIT_INFORMATION
    {
        public long PerProcessUserTimeLimit;
        public long PerJobUserTimeLimit;
        public uint LimitFlags;
        public UIntPtr MinimumWorkingSetSize;
        public UIntPtr MaximumWorkingSetSize;
        public uint ActiveProcessLimit;
        public UIntPtr Affinity;
        public uint PriorityClass;
        public uint SchedulingClass;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct IO_COUNTERS
    {
        public ulong ReadOperationCount;
        public ulong WriteOperationCount;
        public ulong OtherOperationCount;
        public ulong ReadTransferCount;
        public ulong WriteTransferCount;
        public ulong OtherTransferCount;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct JOBOBJECT_EXTENDED_LIMIT_INFORMATION
    {
        public JOBOBJECT_BASIC_LIMIT_INFORMATION BasicLimitInformation;
        public IO_COUNTERS IoInfo;
        public UIntPtr ProcessMemoryLimit;
        public UIntPtr JobMemoryLimit;
        public UIntPtr PeakProcessMemoryUsed;
        public UIntPtr PeakJobMemoryUsed;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr CreateJobObject(IntPtr jobAttributes, string name);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetInformationJobObject(
        IntPtr job,
        int informationClass,
        ref JOBOBJECT_EXTENDED_LIMIT_INFORMATION information,
        uint informationLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool AssignProcessToJobObject(IntPtr job, IntPtr process);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool TerminateJobObject(IntPtr job, uint exitCode);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);

    public LauncherProcessJob()
    {
        if (Environment.OSVersion.Platform != PlatformID.Win32NT)
            throw new PlatformNotSupportedException("Windows Job Objects are only available on Windows.");

        this.handle = CreateJobObject(IntPtr.Zero, null);
        if (this.handle == IntPtr.Zero)
            throw new Win32Exception(Marshal.GetLastWin32Error(), "Could not create launcher Job Object.");

        JOBOBJECT_EXTENDED_LIMIT_INFORMATION information = new JOBOBJECT_EXTENDED_LIMIT_INFORMATION();
        information.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        if (!SetInformationJobObject(
            this.handle,
            9,
            ref information,
            (uint)Marshal.SizeOf(typeof(JOBOBJECT_EXTENDED_LIMIT_INFORMATION))))
        {
            int error = Marshal.GetLastWin32Error();
            CloseHandle(this.handle);
            this.handle = IntPtr.Zero;
            throw new Win32Exception(error, "Could not configure launcher Job Object.");
        }
    }

    public void Assign(Process process)
    {
        if (process == null) throw new ArgumentNullException("process");
        if (this.handle == IntPtr.Zero) throw new ObjectDisposedException("LauncherProcessJob");
        if (!AssignProcessToJobObject(this.handle, process.Handle))
            throw new Win32Exception(Marshal.GetLastWin32Error(), "Could not assign worker to launcher Job Object.");
    }

    public void Terminate(uint exitCode)
    {
        if (this.handle == IntPtr.Zero) return;
        if (!TerminateJobObject(this.handle, exitCode))
            throw new Win32Exception(Marshal.GetLastWin32Error(), "Could not terminate launcher Job Object.");
    }

    public void Dispose()
    {
        if (this.handle == IntPtr.Zero) return;
        CloseHandle(this.handle);
        this.handle = IntPtr.Zero;
        GC.SuppressFinalize(this);
    }

    ~LauncherProcessJob()
    {
        this.Dispose();
    }
}

public sealed class LauncherCatalogItem
{
    public string Number { get; set; }
    public string Name { get; set; }
    public string Task { get; set; }
    public string Synopsis { get; set; }
    public string SupportedModes { get; set; }
}

public static class LauncherCatalogDiscovery
{
    public static Task<LauncherCatalogItem[]> BeginDiscover(string rootPath)
    {
        return Task.Factory.StartNew(() => Discover(rootPath));
    }

    public static LauncherCatalogItem[] Discover(string rootPath)
    {
        if (String.IsNullOrWhiteSpace(rootPath) || rootPath.Contains(".."))
            throw new ArgumentException("Kit root is invalid.");

        string scriptsPath = Path.Combine(rootPath, "scripts");
        if (!Directory.Exists(scriptsPath) ||
            !File.Exists(Path.Combine(scriptsPath, "00-Run-Local.ps1")) ||
            !File.Exists(Path.Combine(scriptsPath, "00-Run-Profile.ps1")))
            throw new DirectoryNotFoundException("Kit root does not contain the required runner scripts.");

        Regex numbered = new Regex(@"^(?!00-)(\d{2})-(.+)\.ps1$", RegexOptions.IgnoreCase);
        Regex synopsisPattern = new Regex(@"(?is)\.SYNOPSIS\s*(?<value>.*?)(?:\r?\n\s*\.[A-Z]+|#>)");
        Regex remediationPattern = new Regex(@"(?:\$Mode\s+-i?eq\s*['""]Remediate['""]|['""]Remediate['""]\s+-i?eq\s*\$Mode|\bif\s*\(\s*\$\w*Remediate\b|['""]Remediate['""]\s*\{)", RegexOptions.IgnoreCase);
        Regex unsupportedRemediationPattern = new Regex(@"Remediate mode is not supported", RegexOptions.IgnoreCase);

        return Directory.GetFiles(scriptsPath, "*.ps1", SearchOption.TopDirectoryOnly)
            .Select(path => new { Path = path, Match = numbered.Match(Path.GetFileName(path)) })
            .Where(item => item.Match.Success)
            .OrderBy(item => Path.GetFileName(item.Path), StringComparer.OrdinalIgnoreCase)
            .Select(item =>
            {
                string content;
                using (FileStream stream = new FileStream(item.Path, FileMode.Open, FileAccess.Read, FileShare.Read))
                {
                    // Catalog discovery is best-effort: do not let an oversized script
                    // consume unbounded memory or prevent smaller scripts from appearing.
                    if (stream.Length > 1048576) return null;
                    using (StreamReader reader = new StreamReader(stream, new UTF8Encoding(false, true), true))
                    {
                        content = reader.ReadToEnd();
                    }
                }
                string task = item.Match.Groups[2].Value.Replace('-', ' ');
                Match synopsis = synopsisPattern.Match(content);
                string synopsisText = synopsis.Success ? synopsis.Groups["value"].Value.Trim() : task;
                if (String.IsNullOrWhiteSpace(synopsisText)) synopsisText = task;
                return new LauncherCatalogItem
                {
                    Number = item.Match.Groups[1].Value,
                    Name = Path.GetFileName(item.Path),
                    Task = task,
                    Synopsis = synopsisText,
                    SupportedModes = remediationPattern.IsMatch(content) && !unsupportedRemediationPattern.IsMatch(content) ? "Audit, Remediate" : "Audit"
                };
            })
            .Where(item => item != null)
            .ToArray();
    }
}
'@
}

$script:LauncherManifestFields = @(
  'schemaVersion', 'operation', 'root', 'target', 'mode', 'argumentTokens',
  'strict', 'requireSigned', 'expectedHash', 'hashAlgorithm', 'remediationApproved'
)
$script:LauncherOperations = @('validate-profile', 'run-script', 'run-profile')
$script:ReservedArgumentNames = @(
  'Mode', 'Remediate', 'RootPath', 'ScriptName', 'ScriptNumber', 'ScriptArgs',
  'ProfilePath', 'Confirm', 'WhatIf', 'PassThru', 'OutputFormat', 'OutputPath',
  'Quiet', 'NoColor', 'RequireSigned', 'ExpectedHash', 'HashAlgorithm', 'Strict',
  'ConfigPath'
)

<#
.SYNOPSIS
  Splits launcher argument text into tokens.
.DESCRIPTION
  Preserves quoted values so the launcher can validate each advanced argument.
#>
function ConvertFrom-LauncherArgumentString {
  [CmdletBinding()]
  param([AllowEmptyString()][string]$Text)

  if ([string]::IsNullOrWhiteSpace($Text)) { return @() }

  $tokens = New-Object System.Collections.ArrayList
  $current = New-Object System.Text.StringBuilder
  $quote = [char]0
  $chars = $Text.ToCharArray()

  for ($i = 0; $i -lt $chars.Length; $i++) {
    $c = $chars[$i]

    if ($quote -ne [char]0) {
      if ($c -eq $quote) {
        $quote = [char]0
      } else {
        [void]$current.Append($c)
      }
      continue
    }

    if ($c -eq [char]39 -or $c -eq [char]34) {
      $quote = $c
      continue
    }

    if ($c -eq ' ' -or $c -eq "`t") {
      if ($current.Length -gt 0) {
        [void]$tokens.Add($current.ToString())
        [void]$current.Clear()
      }
      continue
    }

    if ($c -in @('|', ';', '&', '<', '>', '`', "`r", "`n")) {
      throw "Advanced arguments contain unsupported executable syntax '$c'."
    }

    [void]$current.Append($c)
  }

  if ($quote -ne [char]0) { throw 'Advanced arguments contain an unmatched quote.' }
  if ($current.Length -gt 0) { [void]$tokens.Add($current.ToString()) }

  foreach ($token in @($tokens)) {
    if ($token -match '\$\(' -or $token -match '\$\{' -or $token -match '\$(?!true(?:\b|$)|false(?:\b|$))') {
      throw "Advanced argument '$token' contains unsupported variable or subexpression syntax."
    }
  }

  return @($tokens)
}

<#
.SYNOPSIS
  Extracts the name from a launcher argument token.
.DESCRIPTION
  Supports allowlist checks without interpreting the token's supplied value.
#>
function Get-LauncherArgumentName {
  [CmdletBinding()]
  param([Parameter(Mandatory)][string]$Token)

  if ($Token -notmatch '^--?([^:=]+)(?:(?::|=).*)?$') { return $null }
  return [string]$Matches[1]
}

<#
.SYNOPSIS
  Rejects launcher arguments that override controlled options.
.DESCRIPTION
  Prevents callers from changing security-relevant launcher-owned parameters.
#>
function Assert-LauncherArgumentsAllowed {
  [CmdletBinding()]
  param([string[]]$ArgumentTokens = @())

  foreach ($token in @($ArgumentTokens)) {
    $name = Get-LauncherArgumentName -Token ([string]$token)
    if ($null -ne $name -and $script:ReservedArgumentNames -icontains $name) {
      throw "Advanced argument '-$name' is controlled by the launcher and cannot be overridden."
    }
  }
  return @($ArgumentTokens)
}

<#
.SYNOPSIS
  Tests whether a launcher kit root is trusted.
.DESCRIPTION
  Requires the expected directory structure and safe filesystem ancestry.
#>
function Test-LauncherKitRoot {
  [CmdletBinding()]
  param([Parameter(Mandatory)][string]$RootPath)

  if ([string]::IsNullOrWhiteSpace($RootPath)) { return $false }
  if ($RootPath -match '\.\.') { return $false }
  try {
    Assert-LauncherPathFreeOfReparsePoint -Path $RootPath -RequireDirectory | Out-Null
    $scripts = Join-Path $RootPath 'scripts'
    Assert-LauncherPathFreeOfReparsePoint -Path $scripts -RequireDirectory | Out-Null
    Assert-LauncherPathFreeOfReparsePoint -Path (Join-Path $scripts '00-Run-Local.ps1') -RequireFile | Out-Null
    Assert-LauncherPathFreeOfReparsePoint -Path (Join-Path $scripts '00-Run-Profile.ps1') -RequireFile | Out-Null
    return $true
  } catch {
    Write-Verbose ("Launcher kit root rejected: {0}" -f $_.Exception.Message)
    return $false
  }
}

<#
.SYNOPSIS
  Tests whether the current Windows process is elevated.
.DESCRIPTION
  Reports the administrative state required for privileged launcher operations.
#>
function Test-LauncherElevatedWindows {
  [CmdletBinding()]
  [OutputType([bool])]
  param()

  if ([System.Environment]::OSVersion.Platform -ne [System.PlatformID]::Win32NT) {
    return $false
  }
  try {
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
  } catch {
    throw "Launcher could not determine the Windows elevation state: $($_.Exception.Message)"
  }
}

<#
.SYNOPSIS
  Rejects a launcher path that contains a reparse point.
.DESCRIPTION
  Prevents trusted-file validation from being redirected through filesystem links.
#>
function Assert-LauncherPathFreeOfReparsePoint {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Path,
    [switch]$RequireFile,
    [switch]$RequireDirectory
  )

  $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
  if ($RequireFile -and $item.PSIsContainer) { throw "Expected a regular file: $Path" }
  if ($RequireDirectory -and -not $item.PSIsContainer) { throw "Expected a regular directory: $Path" }
  if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw "Launcher path contains a reparse point: $($item.FullName)"
  }
  return $item
}

<#
.SYNOPSIS
  Opens the launcher trusted-file closure.
.DESCRIPTION
  Keeps validated files read-locked through the validation-to-launch handoff.
#>
function Enter-LauncherTrustedClosure {
  <#
  Keep read handles open with FileShare.Read for every file the launcher can
  consume.  This denies concurrent write/delete/rename until the worker exits,
  closing the validation-to-execution replacement window without weakening the
  inherited manifest boundary.
  #>
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$RootPath,
    [string[]]$AdditionalPaths = @(),
    [ValidateSet('validate-profile', 'run-script', 'run-profile')][string]$Operation,
    [string]$SelectedExecutionPath,
    [switch]$EnforceTrustedWindowsAcl
  )

  $enforceAcl = [bool]($EnforceTrustedWindowsAcl -or (Test-LauncherElevatedWindows))
  $root = Assert-LauncherPathFreeOfReparsePoint -Path $RootPath -RequireDirectory
  $streams = New-Object System.Collections.Generic.List[System.IO.FileStream]
  try {
    if ($enforceAcl) {
      if (-not [string]::IsNullOrWhiteSpace($Operation) -and [string]::IsNullOrWhiteSpace($SelectedExecutionPath)) {
        throw "Selected execution path is required for elevated launcher operation '$Operation'."
      }
      # The root ancestor check prevents replacement of an otherwise protected
      # kit directory. Descendants are checked individually below because a
      # file can carry a weaker explicit ACL than its protected parent.
      Assert-TrustedWindowsPathAcl -Path $root.FullName -CheckAncestors | Out-Null
      $scriptsPath = Join-Path $root.FullName 'scripts'
      $libPath = Join-Path $root.FullName 'lib'
      foreach ($requiredDirectory in @($scriptsPath, $libPath)) {
        $requiredItem = Assert-LauncherPathFreeOfReparsePoint -Path $requiredDirectory -RequireDirectory
        Assert-TrustedWindowsPathAcl -Path $requiredItem.FullName | Out-Null
      }
      foreach ($requiredFile in @(
          (Join-Path $scriptsPath '00-Run-Local.ps1'),
          (Join-Path $scriptsPath '00-Run-Profile.ps1'),
          (Join-Path $scriptsPath '00-Validate-Profile.ps1'),
          (Join-Path $scriptsPath '_lib/Bootstrap.ps1'),
          (Join-Path $libPath 'Validation.psm1')
        )) {
        $requiredItem = Assert-LauncherPathFreeOfReparsePoint -Path $requiredFile -RequireFile
        Assert-TrustedWindowsPathAcl -Path $requiredItem.FullName | Out-Null
      }
      if (-not [string]::IsNullOrWhiteSpace($SelectedExecutionPath)) {
        $selectedItem = Assert-LauncherPathFreeOfReparsePoint -Path $SelectedExecutionPath -RequireFile
        Assert-TrustedWindowsPathAcl -Path $selectedItem.FullName -CheckAncestors | Out-Null
      }
    }

    $items = @($root) + @(Get-ChildItem -LiteralPath $root.FullName -Recurse -Force -ErrorAction Stop)
    foreach ($item in $items) {
      if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Launcher closure contains a reparse point: $($item.FullName)"
      }
      if ($enforceAcl) {
        Assert-TrustedWindowsPathAcl -Path $item.FullName | Out-Null
      }
      if (-not $item.PSIsContainer) {
        $streams.Add([System.IO.File]::Open($item.FullName, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read))
      }
    }
    foreach ($path in @($AdditionalPaths | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })) {
      $item = Assert-LauncherPathFreeOfReparsePoint -Path $path -RequireFile
      if ($enforceAcl) {
        Assert-TrustedWindowsPathAcl -Path $item.FullName -CheckAncestors | Out-Null
      }
      $streams.Add([System.IO.File]::Open($item.FullName, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read))
    }
    return [pscustomobject]@{ Root = $root.FullName; Streams = $streams }
  } catch {
    foreach ($stream in $streams) { try { $stream.Dispose() } catch { Write-Verbose 'Launcher closure cleanup failed.' } }
    throw
  }
}

<#
.SYNOPSIS
  Closes a launcher trusted-file closure.
.DESCRIPTION
  Releases all read handles opened for the validation-to-launch handoff.
#>
function Exit-LauncherTrustedClosure {
  [CmdletBinding()]
  param([AllowNull()][object]$Closure)

  if ($null -eq $Closure) { return }
  foreach ($stream in @($Closure.Streams)) { try { $stream.Dispose() } catch { Write-Verbose 'Launcher closure cleanup failed.' } }
}

<#
.SYNOPSIS
  Gets the trusted System32 taskkill executable path.
.DESCRIPTION
  Verifies the system directory and executable before process-tree cleanup.
#>
function Get-LauncherTrustedSystem32Path {
  [CmdletBinding()]
  param()

  $systemDirectory = [System.Environment]::GetFolderPath([System.Environment+SpecialFolder]::System)
  if ([string]::IsNullOrWhiteSpace($systemDirectory)) { throw 'The .NET System special folder is unavailable.' }
  Assert-LauncherPathFreeOfReparsePoint -Path $systemDirectory -RequireDirectory | Out-Null
  $taskkillPath = Join-Path $systemDirectory 'taskkill.exe'
  Assert-LauncherPathFreeOfReparsePoint -Path $taskkillPath -RequireFile | Out-Null
  return $taskkillPath
}

<#
.SYNOPSIS
  Discovers scripts available to the launcher.
.DESCRIPTION
  Returns a safe catalog only when the requested kit root is trusted.
#>
function Get-LauncherScriptCatalog {
  [CmdletBinding()]
  param([Parameter(Mandatory)][string]$RootPath)

  if (-not (Test-LauncherKitRoot -RootPath $RootPath)) { return @() }
  try {
    $resolvedRoot = (Resolve-Path -LiteralPath $RootPath -ErrorAction Stop).ProviderPath
    return @([LauncherCatalogDiscovery]::Discover($resolvedRoot))
  } catch {
    Write-Verbose ("Launcher catalog discovery failed: {0}" -f $_.Exception.Message)
    return @()
  }
}

<#
.SYNOPSIS
  Reads the safe summary of a launcher profile.
.DESCRIPTION
  Extracts profile metadata and validated step details for display.
#>
function Get-LauncherProfileSummary {
  [CmdletBinding()]
  param([Parameter(Mandatory)][string]$ProfilePath)

  if (-not (Test-Path -LiteralPath $ProfilePath -PathType Leaf)) {
    throw "Profile file not found: $ProfilePath"
  }
  $raw = Get-BoundedUtf8FileContent -Path $ProfilePath -MaximumBytes 1048576
  if ([string]::IsNullOrWhiteSpace($raw)) { throw 'Profile file is empty.' }
  try { $document = $raw | ConvertFrom-Json -ErrorAction Stop } catch { throw "Profile JSON is invalid: $($_.Exception.Message)" }

  foreach ($required in @('ProfileName', 'Version', 'Defaults', 'Steps', 'Integrity')) {
    if ($document.PSObject.Properties.Name -notcontains $required) { throw "Profile is missing required field '$required'." }
  }

  $defaultMode = if ($document.Defaults.PSObject.Properties.Name -contains 'Mode') { [string]$document.Defaults.Mode } else { 'Audit' }
  $strict = [bool](($document.Defaults.PSObject.Properties.Name -contains 'Strict') -and $document.Defaults.Strict)
  $requireSigned = [bool](($document.Integrity.PSObject.Properties.Name -contains 'RequireSigned') -and $document.Integrity.RequireSigned)
  $steps = New-Object System.Collections.ArrayList
  foreach ($step in @($document.Steps)) {
    $depends = if ($step.PSObject.Properties.Name -contains 'DependsOn') { @($step.DependsOn) -join ', ' } else { '' }
    [void]$steps.Add([pscustomobject]@{ Script = [string]$step.Script; DependsOn = $depends })
  }
  return [pscustomobject]@{
    ProfileName = [string]$document.ProfileName
    Version = [string]$document.Version
    DefaultMode = $defaultMode
    Strict = $strict
    RequireSigned = $requireSigned
    StepCount = $steps.Count
    Steps = @($steps)
  }
}

<#
.SYNOPSIS
  Creates the manifest consumed by the launcher worker.
.DESCRIPTION
  Serializes validated launch choices into the worker's constrained contract.
#>
function ConvertTo-LauncherManifest {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][ValidateSet('validate-profile', 'run-script', 'run-profile')][string]$Operation,
    [Parameter(Mandatory)][string]$Root,
    [Parameter(Mandatory)][string]$Target,
    [ValidateSet('Audit', 'Remediate')][string]$Mode = 'Audit',
    [string[]]$ArgumentTokens = @(),
    [switch]$Strict,
    [switch]$RequireSigned,
    [string]$ExpectedHash,
    [ValidateSet('SHA256', 'SHA384', 'SHA512')][string]$HashAlgorithm = 'SHA256',
    [switch]$RemediationApproved
  )

  Assert-LauncherArgumentsAllowed -ArgumentTokens $ArgumentTokens | Out-Null
  if ($Mode -eq 'Remediate' -and -not $RemediationApproved) { throw 'Remediation requires explicit operator approval.' }
  [ordered]@{
    schemaVersion = 1
    operation = $Operation
    root = $Root
    target = $Target
    mode = $Mode
    argumentTokens = @($ArgumentTokens)
    strict = [bool]$Strict
    requireSigned = [bool]$RequireSigned
    expectedHash = [string]$ExpectedHash
    hashAlgorithm = $HashAlgorithm
    remediationApproved = [bool]$RemediationApproved
  }
}

<#
.SYNOPSIS
  Validates a launcher worker manifest.
.DESCRIPTION
  Enforces operation, path, argument, and remediation safety constraints.
#>
function Assert-LauncherManifest {
  [CmdletBinding()]
  param([Parameter(Mandatory)]$Manifest)

  if ($null -eq $Manifest -or $Manifest -is [string] -or $Manifest -is [System.ValueType] -or $Manifest -is [System.Collections.IEnumerable]) {
    throw 'Launcher manifest root must be an object.'
  }
  $names = @($Manifest.PSObject.Properties.Name)
  $normalizedNames = @{}
  foreach ($name in $names) {
    $normalizedName = $name.ToLowerInvariant()
    if ($normalizedNames.ContainsKey($normalizedName)) { throw "Manifest contains duplicate field '$name'." }
    $normalizedNames[$normalizedName] = $true
    if ($script:LauncherManifestFields -notcontains $name) { throw "Manifest contains unknown field '$name'." }
  }
  foreach ($required in $script:LauncherManifestFields) {
    if ($names -notcontains $required) { throw "Manifest is missing required field '$required'." }
  }
  if (
    $Manifest.schemaVersion -isnot [byte] -and $Manifest.schemaVersion -isnot [sbyte] -and
    $Manifest.schemaVersion -isnot [int16] -and $Manifest.schemaVersion -isnot [uint16] -and
    $Manifest.schemaVersion -isnot [int32] -and $Manifest.schemaVersion -isnot [uint32] -and
    $Manifest.schemaVersion -isnot [int64] -and $Manifest.schemaVersion -isnot [uint64]
  ) { throw 'Launcher manifest schemaVersion must be an integer.' }
  if ([int64]$Manifest.schemaVersion -ne 1) { throw 'Unsupported launcher manifest schema version.' }
  foreach ($stringField in @('operation', 'root', 'target', 'mode', 'expectedHash', 'hashAlgorithm')) {
    if ($Manifest.$stringField -isnot [string]) { throw "Launcher manifest field '$stringField' must be a string." }
  }
  foreach ($booleanField in @('strict', 'requireSigned', 'remediationApproved')) {
    if ($Manifest.$booleanField -isnot [bool]) { throw "Launcher manifest field '$booleanField' must be a boolean." }
  }
  if ($Manifest.argumentTokens -is [string] -or $Manifest.argumentTokens -isnot [System.Collections.IEnumerable]) {
    throw "Launcher manifest field 'argumentTokens' must be an array of strings."
  }
  foreach ($argumentToken in @($Manifest.argumentTokens)) {
    if ($argumentToken -isnot [string]) { throw "Launcher manifest field 'argumentTokens' must contain only strings." }
  }
  if ($script:LauncherOperations -notcontains $Manifest.operation) { throw "Unsupported launcher operation '$($Manifest.operation)'." }
  if (-not (Test-LauncherKitRoot -RootPath $Manifest.root)) { throw 'Manifest kit root is invalid.' }
  if (@('Audit', 'Remediate') -notcontains $Manifest.mode) { throw "Unsupported execution mode '$($Manifest.mode)'." }
  if ($Manifest.mode -eq 'Remediate' -and -not $Manifest.remediationApproved) { throw 'Manifest does not contain remediation approval.' }
  if (@('SHA256', 'SHA384', 'SHA512') -notcontains $Manifest.hashAlgorithm) { throw 'Unsupported hash algorithm.' }
  if ($Manifest.operation -eq 'run-script' -and $Manifest.target -notmatch '^\d{2}-[^\\/]+\.ps1$') { throw 'Manifest script target is invalid.' }
  if ($Manifest.operation -in @('validate-profile', 'run-profile') -and -not (Test-Path -LiteralPath $Manifest.target -PathType Leaf)) { throw 'Manifest profile target is invalid.' }
  if (-not [string]::IsNullOrWhiteSpace($Manifest.expectedHash)) {
    $expectedLength = switch ($Manifest.hashAlgorithm) { 'SHA256' { 64 } 'SHA384' { 96 } 'SHA512' { 128 } }
    if ($Manifest.expectedHash -notmatch "^[a-fA-F0-9]{$expectedLength}$") { throw 'Manifest expected hash is invalid for the selected hash algorithm.' }
  }
  if ($Manifest.operation -ne 'run-script' -and -not [string]::IsNullOrWhiteSpace($Manifest.expectedHash)) { throw 'Expected hash is only valid for a single-script run.' }
  if ($Manifest.operation -ne 'run-script' -and @($Manifest.argumentTokens).Count -gt 0) { throw 'Advanced argument tokens are only valid for a single-script run.' }
  Assert-LauncherArgumentsAllowed -ArgumentTokens @($Manifest.argumentTokens) | Out-Null
  return $Manifest
}

<#
.SYNOPSIS
  Adds one output line to a bounded pending queue.
.DESCRIPTION
  Discards oldest entries past the limit to bound launcher memory use.
#>
function Add-LauncherPendingLine {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)]$Queue,
    [AllowEmptyString()][Parameter(Mandatory)][string]$Line,
    [ValidateRange(1, 100000)][int]$Maximum = 5000
  )

  $Queue.Enqueue($Line)
  while ($Queue.Count -gt $Maximum) {
    $discarded = $null
    [void]$Queue.TryDequeue([ref]$discarded)
  }
}

<#
.SYNOPSIS
  Maps worker completion to a launcher terminal state.
.DESCRIPTION
  Converts stop flags and exit codes into stable UI status values.
#>
function Get-LauncherTerminalState {
  [CmdletBinding()]
  param([int]$ExitCode, [switch]$Stopped)

  if ($Stopped) { return 'Stopped' }
  switch ($ExitCode) {
    0 { 'Completed' }
    2 { 'Warning' }
    default { 'Failed' }
  }
}

<#
.SYNOPSIS
  Creates the Windows job used for launcher child processes.
.DESCRIPTION
  Returns null on non-Windows hosts to keep portable checks usable.
#>
function New-LauncherProcessJob {
  [CmdletBinding()]
  param()

  if ([System.Environment]::OSVersion.Platform -ne [System.PlatformID]::Win32NT) {
    return $null
  }
  return [LauncherProcessJob]::new()
}

<#
.SYNOPSIS
  Assigns a process to the launcher job object.
.DESCRIPTION
  Ensures the launcher can terminate the entire child-process tree.
#>
function Add-LauncherProcessToJob {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][LauncherProcessJob]$Job,
    [Parameter(Mandatory)][System.Diagnostics.Process]$Process
  )

  $Job.Assign($Process)
}

<#
.SYNOPSIS
  Stops a launcher worker process and its descendants.
.DESCRIPTION
  Uses the trusted platform process-tree termination path where available.
#>
function Stop-LauncherProcessTree {
  [CmdletBinding()]
  [OutputType([bool])]
  param(
    [Parameter(Mandatory)][System.Diagnostics.Process]$Process,
    [AllowNull()][object]$Job,
    [ValidateRange(100, 30000)][int]$WaitMilliseconds = 5000
  )

  try {
    if ($Process.HasExited) {
      if ($null -ne $Job) { $Job.Dispose() }
      return $true
    }
  } catch {
    return $false
  }

  if ($null -ne $Job) {
    try {
      $Job.Terminate(1)
      $Job.Dispose()
      return $Process.WaitForExit($WaitMilliseconds)
    } catch {
      Write-Verbose ("Job Object termination failed: {0}" -f $_.Exception.Message)
      try { $Job.Dispose() } catch { Write-Verbose ("Job Object disposal failed: {0}" -f $_.Exception.Message) }
    }
  }

  if ([System.Environment]::OSVersion.Platform -eq [System.PlatformID]::Win32NT) {
    $killer = $null
    try {
      $taskkillPath = Get-LauncherTrustedSystem32Path
      $killer = Start-Process -FilePath $taskkillPath `
        -ArgumentList @('/PID', [string]$Process.Id, '/T', '/F') `
        -PassThru -WindowStyle Hidden -ErrorAction Stop
      if (-not $killer.WaitForExit($WaitMilliseconds)) {
        try {
          $killer.Kill()
          [void]$killer.WaitForExit([Math]::Min($WaitMilliseconds, 2000))
        } catch { Write-Verbose ("taskkill timeout cleanup failed: {0}" -f $_.Exception.Message) }
        return $false
      }
      if (-not $Process.WaitForExit($WaitMilliseconds)) { return $false }
      return ($killer.ExitCode -eq 0 -and $Process.HasExited)
    } catch {
      Write-Verbose ("taskkill process-tree fallback failed: {0}" -f $_.Exception.Message)
    } finally {
      if ($null -ne $killer) { $killer.Dispose() }
    }
  }

  try {
    $Process.Kill()
    return $Process.WaitForExit($WaitMilliseconds)
  } catch {
    Write-Verbose ("Worker process termination failed: {0}" -f $_.Exception.Message)
    return $false
  }
}

Export-ModuleMember -Function @(
  'ConvertFrom-LauncherArgumentString', 'Assert-LauncherArgumentsAllowed',
  'Test-LauncherKitRoot', 'Get-LauncherScriptCatalog', 'Get-LauncherProfileSummary',
  'ConvertTo-LauncherManifest', 'Assert-LauncherManifest', 'Get-LauncherTerminalState',
  'Add-LauncherPendingLine', 'New-LauncherProcessJob', 'Add-LauncherProcessToJob',
  'Stop-LauncherProcessTree', 'Enter-LauncherTrustedClosure', 'Exit-LauncherTrustedClosure',
  'Get-LauncherTrustedSystem32Path', 'Test-LauncherElevatedWindows'
)
