#requires -Version 5.1

Set-StrictMode -Version Latest

if (-not ('LauncherOutputCollector' -as [type])) {
  Add-Type -TypeDefinition @'
using System;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.IO;
using System.Linq;
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
    private int pendingCount;

    public LauncherOutputCollector(string logPath, long maximumBytes, int maximumPending)
    {
        this.maximumBytes = maximumBytes;
        this.maximumPending = maximumPending;
        this.Pending = new ConcurrentQueue<string>();
        this.writer = new StreamWriter(logPath, false, new UTF8Encoding(true));
        this.OutputHandler = this.OnOutput;
        this.ErrorHandler = this.OnError;
    }

    public ConcurrentQueue<string> Pending { get; private set; }
    public DataReceivedEventHandler OutputHandler { get; private set; }
    public DataReceivedEventHandler ErrorHandler { get; private set; }

    public void AddLine(string line)
    {
        if (line == null) return;
        lock (this.sync)
        {
            if (!this.truncated)
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
        }

        this.Pending.Enqueue(line);
        int currentCount = Interlocked.Increment(ref this.pendingCount);
        string discarded;
        while (currentCount > this.maximumPending && this.Pending.TryDequeue(out discarded))
        {
            currentCount = Interlocked.Decrement(ref this.pendingCount);
        }
    }

    public void OnOutput(object sender, DataReceivedEventArgs eventArgs)
    {
        if (eventArgs.Data != null) this.AddLine(eventArgs.Data);
    }

    public void OnError(object sender, DataReceivedEventArgs eventArgs)
    {
        if (eventArgs.Data != null) this.AddLine("ERROR: " + eventArgs.Data);
    }

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
                string content = File.ReadAllText(item.Path);
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

function Get-LauncherArgumentName {
  [CmdletBinding()]
  param([Parameter(Mandatory)][string]$Token)

  if ($Token -notmatch '^--?([^:=]+)(?:(?::|=).*)?$') { return $null }
  return [string]$Matches[1]
}

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

function Test-LauncherKitRoot {
  [CmdletBinding()]
  param([Parameter(Mandatory)][string]$RootPath)

  if ([string]::IsNullOrWhiteSpace($RootPath)) { return $false }
  if ($RootPath -match '\.\.') { return $false }
  $scripts = Join-Path $RootPath 'scripts'
  return (
    (Test-Path -LiteralPath $scripts -PathType Container) -and
    (Test-Path -LiteralPath (Join-Path $scripts '00-Run-Local.ps1') -PathType Leaf) -and
    (Test-Path -LiteralPath (Join-Path $scripts '00-Run-Profile.ps1') -PathType Leaf)
  )
}

function Get-LauncherScriptCatalog {
  [CmdletBinding()]
  param([Parameter(Mandatory)][string]$RootPath)

  if (-not (Test-LauncherKitRoot -RootPath $RootPath)) { return @() }
  $items = New-Object System.Collections.ArrayList
  $scriptsPath = Join-Path $RootPath 'scripts'
  $files = Get-ChildItem -LiteralPath $scriptsPath -Filter '*.ps1' -File |
    Where-Object { $_.Name -match '^(?!00-)(\d{2})-' } |
    Sort-Object Name

  foreach ($file in $files) {
    $number = $file.BaseName.Substring(0, 2)
    $task = $file.BaseName.Substring(3) -replace '-', ' '
    $synopsis = ''
    try {
      $help = Get-Help -Name $file.FullName -ErrorAction Stop
      if ($null -ne $help.Synopsis) { $synopsis = ([string]$help.Synopsis).Trim() }
    } catch {
      Write-Verbose ("Could not read help for {0}: {1}" -f $file.Name, $_.Exception.Message)
    }
    if ([string]::IsNullOrWhiteSpace($synopsis)) { $synopsis = $task }

    $content = Get-Content -LiteralPath $file.FullName -Raw -ErrorAction SilentlyContinue
    $supportsRemediate = [bool](
      $content -match '(?is)(?:\$Mode\s+-i?eq\s*[''"]Remediate[''"]|[''"]Remediate[''"]\s+-i?eq\s*\$Mode|\bif\s*\(\s*\$\w*Remediate\b|[''"]Remediate[''"]\s*\{)' -and
      $content -notmatch '(?i)Remediate mode is not supported'
    )
    [void]$items.Add([pscustomobject]@{
        Number = $number
        Name = $file.Name
        Task = $task
        Synopsis = $synopsis
        SupportedModes = if ($supportsRemediate) { 'Audit, Remediate' } else { 'Audit' }
      })
  }
  return @($items)
}

function Get-LauncherProfileSummary {
  [CmdletBinding()]
  param([Parameter(Mandatory)][string]$ProfilePath)

  if (-not (Test-Path -LiteralPath $ProfilePath -PathType Leaf)) {
    throw "Profile file not found: $ProfilePath"
  }
  $raw = Get-Content -LiteralPath $ProfilePath -Raw -Encoding UTF8
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

function Assert-LauncherManifest {
  [CmdletBinding()]
  param([Parameter(Mandatory)]$Manifest)

  $names = @($Manifest.PSObject.Properties.Name)
  foreach ($name in $names) {
    if ($script:LauncherManifestFields -notcontains $name) { throw "Manifest contains unknown field '$name'." }
  }
  foreach ($required in $script:LauncherManifestFields) {
    if ($names -notcontains $required) { throw "Manifest is missing required field '$required'." }
  }
  if ([int]$Manifest.schemaVersion -ne 1) { throw 'Unsupported launcher manifest schema version.' }
  if ($script:LauncherOperations -notcontains [string]$Manifest.operation) { throw "Unsupported launcher operation '$($Manifest.operation)'." }
  if (-not (Test-LauncherKitRoot -RootPath ([string]$Manifest.root))) { throw 'Manifest kit root is invalid.' }
  if (@('Audit', 'Remediate') -notcontains [string]$Manifest.mode) { throw "Unsupported execution mode '$($Manifest.mode)'." }
  if ([string]$Manifest.mode -eq 'Remediate' -and -not [bool]$Manifest.remediationApproved) { throw 'Manifest does not contain remediation approval.' }
  if (@('SHA256', 'SHA384', 'SHA512') -notcontains [string]$Manifest.hashAlgorithm) { throw 'Unsupported hash algorithm.' }
  if ([string]$Manifest.operation -eq 'run-script' -and [string]$Manifest.target -notmatch '^\d{2}-[^\\/]+\.ps1$') { throw 'Manifest script target is invalid.' }
  if ([string]$Manifest.operation -in @('validate-profile', 'run-profile') -and -not (Test-Path -LiteralPath ([string]$Manifest.target) -PathType Leaf)) { throw 'Manifest profile target is invalid.' }
  if ([string]$Manifest.operation -ne 'run-script' -and -not [string]::IsNullOrWhiteSpace([string]$Manifest.expectedHash)) { throw 'Expected hash is only valid for a single-script run.' }
  if ([string]$Manifest.operation -ne 'run-script' -and @($Manifest.argumentTokens).Count -gt 0) { throw 'Advanced argument tokens are only valid for a single-script run.' }
  Assert-LauncherArgumentsAllowed -ArgumentTokens @($Manifest.argumentTokens) | Out-Null
  return $Manifest
}

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

Export-ModuleMember -Function @(
  'ConvertFrom-LauncherArgumentString', 'Assert-LauncherArgumentsAllowed',
  'Test-LauncherKitRoot', 'Get-LauncherScriptCatalog', 'Get-LauncherProfileSummary',
  'ConvertTo-LauncherManifest', 'Assert-LauncherManifest', 'Get-LauncherTerminalState',
  'Add-LauncherPendingLine'
)
