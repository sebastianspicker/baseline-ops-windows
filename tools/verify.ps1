#requires -version 5.1

<#
.SYNOPSIS
  Runs repository static verification gates.
.DESCRIPTION
  Checks public files and configured analyzers to catch release-blocking regressions.
#>

[CmdletBinding()]
param(
  [string]$RootPath = '',
  [switch]$SkipAnalyzer
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path $PSScriptRoot '../lib/Common.psm1') -Force
$RootPath = Resolve-ToolRepositoryRoot -RootPath $RootPath -InvocationPath $MyInvocation.MyCommand.Path -FallbackPath $PSCommandPath

$bootstrapPath = [System.IO.Path]::Combine($RootPath, 'scripts', '_lib', 'Bootstrap.ps1')
if (-not (Test-Path -LiteralPath $bootstrapPath)) {
  Write-Error "Bootstrap not found: $bootstrapPath"
  exit 1
}
. $bootstrapPath
Import-Module (Join-Path $script:LibPath 'Output.psm1') -Force
Import-Module (Join-Path $PSScriptRoot '../lib/External.psm1') -Force -DisableNameChecking
Import-Module (Join-Path $PSScriptRoot '../lib/Validation.psm1')

Write-Section -Title 'verify.ps1 - Static Checks'

$script:GateResults = New-Object System.Collections.Generic.List[object]

<#
.SYNOPSIS
  Records one verification gate outcome.
.DESCRIPTION
  Adds a named status and detail record to the final verification report.
#>
function Add-GateResult {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][string]$Name,
    [Parameter(Mandatory)][ValidateSet('PASS','FAILED','SKIPPED')][string]$Status,
    [string]$Detail = ''
  )

  [void]$script:GateResults.Add([pscustomobject]@{
      Name   = $Name
      Status = $Status
      Detail = $Detail
    })
}

<#
.SYNOPSIS
  Prints the final verification verdict and exits.
.DESCRIPTION
  Reports each gate result before returning the selected process exit code.
#>
function Complete-Verification {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory)][ValidateSet('PASS','FAILED','PARTIAL')][string]$Verdict,
    [Parameter(Mandatory)][int]$ExitCode
  )

  Write-Section -Title 'Verification Gate Summary'
  foreach ($gate in $script:GateResults) {
    Write-UiLine ("{0,-12} {1,-8} {2}" -f $gate.Name, $gate.Status, $gate.Detail)
  }

  switch ($Verdict) {
    'PASS' { Write-Success -Message 'VERDICT: PASS' }
    'PARTIAL' { Write-Warn -Message 'VERDICT: PARTIAL' }
    'FAILED' { Write-ErrorLine -Message 'VERDICT: FAILED' }
  }

  exit $ExitCode
}

<#
.SYNOPSIS
  Gets paths that belong to the repository public surface.
.DESCRIPTION
  Recursively enumerates files while excluding local-only and generated areas.
#>
function Get-PublicSurfacePaths {
  [CmdletBinding()]
  param([Parameter(Mandatory)][string]$Path)

  $gitPaths = Get-GitPublicSurfacePaths -Path $Path
  if ($null -ne $gitPaths) { return $gitPaths }
  return Get-FileSystemPublicSurfacePaths -Path $Path
}

<#
.SYNOPSIS
  Checks whether a native command completed without truncated output.
.DESCRIPTION
  Prevents a partial Git result from becoming a public-surface inventory.
#>
function Test-NativeResultComplete {
  [CmdletBinding()]
  param([Parameter(Mandatory)]$Result)

  if (-not $Result) { return $false }
  if (-not $Result.Success) { return $false }
  if ($Result.TimedOut) { return $false }
  if ($Result.OutputTruncated) { return $false }
  return -not $Result.StderrTruncated
}

<##
.SYNOPSIS
Gets Git-managed and non-ignored paths when Git produces a complete result.
.DESCRIPTION
Returns null when Git cannot provide a safe complete inventory.
#>
function Get-GitPublicSurfacePaths {
  [CmdletBinding()]
  param([Parameter(Mandatory)][string]$Path)

  if (-not (Test-CommandExists -Name 'git')) { return $null }
  $rootResult = Invoke-NativeCommand -Command 'git' -Arguments @('-C', $Path, 'rev-parse', '--is-inside-work-tree') -CaptureOutput -Quiet -TimeoutSeconds 30 -MaxOutputBytes 1048576
  if (-not (Test-NativeResultComplete -Result $rootResult)) { return $null }
  if ($rootResult.Stdout.Trim() -ne 'true') { return $null }
  $filesResult = Invoke-NativeCommand -Command 'git' -Arguments @('-C', $Path, 'ls-files', '-z', '--cached', '--others', '--exclude-standard') -CaptureOutput -Quiet -TimeoutSeconds 30 -MaxOutputBytes 1048576
  if (-not (Test-NativeResultComplete -Result $filesResult)) { return $null }
  $rootFull = [System.IO.Path]::GetFullPath($Path).TrimEnd([char[]]@([System.IO.Path]::DirectorySeparatorChar, [System.IO.Path]::AltDirectorySeparatorChar))
  $verifiedPaths = New-Object System.Collections.Generic.List[string]
  foreach ($relativePath in $filesResult.Stdout.Split([char]0, [System.StringSplitOptions]::RemoveEmptyEntries)) {
    $verifiedPath = ConvertTo-VerifiedGitPath -RelativePath $relativePath -RootPath $rootFull
    if ($null -ne $verifiedPath) { [void]$verifiedPaths.Add($verifiedPath) }
  }
  return @($verifiedPaths | Sort-Object -Unique)
}

<##
.SYNOPSIS
Validates a Git repository-relative path before accepting it.
.DESCRIPTION
Rejects path escapes and omits paths that no longer name files.
#>
function ConvertTo-VerifiedGitPath {
  [CmdletBinding()]
  param([string]$RelativePath, [string]$RootPath)

  if ([System.IO.Path]::IsPathRooted($RelativePath)) { throw 'git returned an unsafe repository-relative path.' }
  if ($RelativePath -match '[\x00-\x1F\x7F]') { throw 'git returned an unsafe repository-relative path.' }
  $candidate = [System.IO.Path]::GetFullPath((Join-Path $RootPath $RelativePath))
  if (-not (Test-PathUnderRoot -Path $candidate -Root $RootPath)) { throw 'git returned a path outside the requested verification root.' }
  if (Test-Path -LiteralPath $candidate -PathType Leaf) { return $RelativePath }
  return $null
}

<##
.SYNOPSIS
Gets public-surface paths directly from the file system.
.DESCRIPTION
Uses the non-Git fallback while omitting the repository Git metadata folder.
#>
function Get-FileSystemPublicSurfacePaths {
  [CmdletBinding()]
  param([Parameter(Mandatory)][string]$Path)

  $trimmedRoot = $Path.TrimEnd([char[]]@([System.IO.Path]::DirectorySeparatorChar, [System.IO.Path]::AltDirectorySeparatorChar))
  return @(Get-ChildItem -LiteralPath $Path -File -Recurse -Force |
      Where-Object { $_.FullName -notmatch '[/\\]\.git[/\\]' } |
      ForEach-Object { $_.FullName.Substring($trimmedRoot.Length).TrimStart([char[]]@([char]'/', [char]92)) })
}

<##
.SYNOPSIS
Normalizes a public-surface path into its comparable segments.
.DESCRIPTION
Removes leading relative separators without resolving filesystem paths.
#>
function Get-PublicSurfacePathParts {
  [CmdletBinding()]
  param([Parameter(Mandatory)][string]$RelativePath)

  $path = $RelativePath.Replace([char]92, [char]47).ToLowerInvariant()
  while ($path.StartsWith('./')) { $path = $path.Substring(2) }
  $path = $path.TrimStart([char]47)
  $segments = @($path.Split('/', [System.StringSplitOptions]::RemoveEmptyEntries))
  return [pscustomobject]@{ Path = $path; Segments = $segments; FileName = $segments[-1] }
}

<##
.SYNOPSIS
Checks public-surface paths for private, agent-state, and credential folders.
.DESCRIPTION
Returns the compatible exclusion reason when a blocked segment is present.
#>
function Test-BlockedPublicSurfaceDirectory {
  [CmdletBinding()]
  param([Parameter(Mandatory)][string[]]$Segments)

  $blocked = @('node_modules', 'private', '.agents', '.codex', '.codacy', '.claude', '.continue', '.cursor', '.aider', '.serena', '.codegraph', '.windsurf', 'credentials', 'secrets', 'keys', 'certs', 'certificates')
  if ($Segments | Where-Object { $blocked -contains $_ }) { return 'private, agent-state, or credential directory' }
  return $null
}

<##
.SYNOPSIS
Checks public-surface paths for agent instruction files.
.DESCRIPTION
Includes standalone and reserved GitHub agent-instruction locations.
#>
function Test-AgentInstructionPublicSurfacePath {
  [CmdletBinding()]
  param([string]$Path, [string]$FileName)

  $instructionFiles = @('agents.md', 'agent.md', 'claude.md', 'codex.md', 'gemini.md', 'audit.md', 'harness_principles.md', 'code_review.md')
  if ($instructionFiles -contains $FileName) { return 'agent instruction or workspace-state file' }
  if ($Path -match '^\.github/(agents|codex|instructions|prompts)(/|$)') { return 'agent instruction or workspace-state file' }
  if ($Path -eq '.github/copilot-instructions.md' -or $Path -eq '.github/workflows/codex.yml') { return 'agent instruction or workspace-state file' }
  return $null
}

<##
.SYNOPSIS
Checks public-surface filenames for sensitive local artifacts.
.DESCRIPTION
Applies environment, credential, database, and keystore filename rules.
#>
function Test-SensitivePublicSurfaceFile {
  [CmdletBinding()]
  param([Parameter(Mandatory)][string]$FileName)

  if ($FileName -match '^\.env($|\.)|^\.envrc$|^(\.npmrc|\.pypirc)$|^client_secret.*\.json$|^service-account.*\.json$|^(id_rsa|id_ed25519)(\.pub)?$|\.(pem|key|pfx|p12|cer|crt|jks|kdbx|ppk|pvk|snk)$') { return 'environment, credential, key, or certificate file' }
  if ($FileName -match '\.local(?:\..*)?$|\.(db|sqlite|sqlite3|keystore)$') { return 'local secret, database, or keystore file' }
  return $null
}

<##
.SYNOPSIS
Checks public-surface paths for local workspace documentation.
.DESCRIPTION
Excludes ledgers, remediation documents, and private documentation trees.
#>
function Test-WorkspacePublicSurfaceDocument {
  [CmdletBinding()]
  param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string[]]$Segments, [Parameter(Mandatory)][string]$FileName)

  $documentExtensions = @('.md', '.txt', '.json', '.jsonl', '.yaml', '.yml')
  $isWorkspaceDocument = $documentExtensions -contains [System.IO.Path]::GetExtension($FileName) -and $FileName -match '(ledger|remediation)'
  if ($isWorkspaceDocument -or $Segments[0] -eq 'archive') { return 'local ledger, remediation, or workspace documentation' }
  if ($Segments[0] -eq 'docs' -and $Path -match '(^|/)(agent|internal|archive|source-audit|tmp|temp)(/|$)') { return 'local ledger, remediation, or workspace documentation' }
  return $null
}

<##
.SYNOPSIS
Checks documentation paths against the reviewed public allowlist.
.DESCRIPTION
Returns the compatible exclusion reason for unreviewed documentation paths.
#>
function Test-ReviewedPublicDocumentationPath {
  [CmdletBinding()]
  param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string[]]$Segments)

  $reviewed = @(
    'docs/readme.md', 'docs/alpha-release.md', 'docs/architecture.md',
    'docs/decisions/0001-single-runtime.md', 'docs/launcher-gui.md', 'docs/rust-v3.md',
    'docs/demo.md', 'docs/demo/index.html', 'docs/demo/styles.css',
    'docs/demo/app.js', 'docs/demo/profiles.json',
    'docs/screenshots/01-profiles.png', 'docs/screenshots/02-command.png',
    'docs/screenshots/03-result.png'
  )
  if ($Segments[0] -eq 'docs' -and $Path -notin $reviewed) { return 'documentation path is not in the reviewed public allowlist' }
  return $null
}

<#
.SYNOPSIS
Tests whether a relative path belongs to the public surface.
.DESCRIPTION
Applies the verifier's explicit exclusions for local and generated content.
#>
function Test-PublicSurfacePath {
  [CmdletBinding()]
  param([Parameter(Mandatory)][string]$RelativePath)

  $parts = Get-PublicSurfacePathParts -RelativePath $RelativePath
  if ($parts.Segments.Count -eq 0) { return $null }
  foreach ($check in @(
      (Test-BlockedPublicSurfaceDirectory -Segments $parts.Segments),
      (Test-AgentInstructionPublicSurfacePath -Path $parts.Path -FileName $parts.FileName),
      (Test-SensitivePublicSurfaceFile -FileName $parts.FileName),
      (Test-WorkspacePublicSurfaceDocument -Path $parts.Path -Segments $parts.Segments -FileName $parts.FileName),
      (Test-ReviewedPublicDocumentationPath -Path $parts.Path -Segments $parts.Segments)
    )) {
    if ($check) { return $check }
  }
  return $null
}

function Invoke-Verification {
  <#
  .SYNOPSIS
  Runs repository verification gates.
  .DESCRIPTION
  Executes the existing public-surface, parse, and analyzer gates in order.
  #>
  param([switch]$SkipAnalyzerRequested)

  $rootIssue = Get-VerificationRootIssue
  if ($rootIssue) { Write-ErrorLine -Message $rootIssue; exit 1 }
  Complete-PublicSurfaceGate
  $targets = Get-VerificationParserTargets
  Complete-ParseGate -Targets $targets
  Complete-AnalyzerGate -SkipAnalyzerRequested:$SkipAnalyzerRequested
  Complete-Verification -Verdict 'PASS' -ExitCode 0
}

<##
.SYNOPSIS
Validates the required verification-root directories.
.DESCRIPTION
Returns the compatible error text for the first missing prerequisite.
#>
function Get-VerificationRootIssue {
  [CmdletBinding()]
  param()

  if (-not (Test-Path -LiteralPath (Join-Path $RootPath 'scripts'))) { return "scripts/ folder not found under $RootPath" }
  if (-not (Test-Path -LiteralPath (Join-Path $RootPath 'lib'))) { return "lib/ folder not found under $RootPath" }
  if (-not (Test-Path -LiteralPath $bootstrapPath)) { return "scripts/_lib/Bootstrap.ps1 not found under $RootPath" }
  return $null
}

<##
.SYNOPSIS
Gets public-surface policy violations from the current repository inventory.
.DESCRIPTION
Pairs every enumerated path with its specific policy exclusion reason.
#>
function Get-PublicSurfaceViolations {
  [CmdletBinding()]
  param()

  $violations = @()
  foreach ($relativePath in Get-PublicSurfacePaths -Path $RootPath) {
    $reason = Test-PublicSurfacePath -RelativePath $relativePath
    if ($reason) { $violations += [pscustomobject]@{ Path = $relativePath; Reason = $reason } }
  }
  return $violations
}

<##
.SYNOPSIS
Completes the public-surface verification gate.
.DESCRIPTION
Writes the compatible failure report or records a successful gate result.
#>
function Complete-PublicSurfaceGate {
  [CmdletBinding()]
  param()

  $violations = @(Get-PublicSurfaceViolations)
  if ($violations.Count -eq 0) {
    Write-Success -Message 'Public surface checks: OK'
    Add-GateResult -Name 'PublicSurface' -Status 'PASS' -Detail 'No prohibited tracked or untracked non-ignored paths'
    return
  }
  Write-ErrorLine -Message ("Public surface violations: {0}" -f $violations.Count)
  $violations | Sort-Object Path | ForEach-Object { Write-UiLine ("- {0} ({1})" -f $_.Path, $_.Reason) -ForegroundColor Yellow }
  Add-GateResult -Name 'PublicSurface' -Status 'FAILED' -Detail ("{0} prohibited public path(s)" -f $violations.Count)
  Complete-Verification -Verdict 'FAILED' -ExitCode 1
}

<##
.SYNOPSIS
Gets parse targets from one existing path.
.DESCRIPTION
Includes maintained PowerShell scripts and modules recursively, excluding Node dependencies.
#>
function Get-VerificationPowerShellTargets {
  [CmdletBinding()]
  param([Parameter(Mandatory)][string]$Path)

  $targets = @(Get-ChildItem -LiteralPath $Path -Filter '*.ps1' -File -Recurse)
  $targets += Get-ChildItem -LiteralPath $Path -Filter '*.psm1' -File -Recurse
  return @($targets | Where-Object { $_.FullName -notmatch '[/\\]node_modules[/\\]' })
}

<##
.SYNOPSIS
Gets all PowerShell parser targets required by the verification contract.
.DESCRIPTION
Preserves the scripts, modules, tools, tests, and Rust-oracle scan set.
#>
function Get-VerificationParserTargets {
  [CmdletBinding()]
  param()

  $targets = @()
  $targets += Get-VerificationPowerShellTargets -Path (Join-Path $RootPath 'scripts')
  $targets += Get-ChildItem -Path (Join-Path $RootPath 'lib') -Filter '*.psm1' -File -Recurse
  foreach ($path in @('tools', 'tests', 'rust/oracles')) {
    $candidate = Join-Path $RootPath $path
    if (Test-Path -LiteralPath $candidate) { $targets += Get-VerificationPowerShellTargets -Path $candidate }
  }
  return $targets
}

<##
.SYNOPSIS
Gets parser diagnostics for the supplied PowerShell targets.
.DESCRIPTION
Returns compatible file, message, line, and column records.
#>
function Get-VerificationParseErrors {
  [CmdletBinding()]
  param([Parameter(Mandatory)]$Targets)

  $parseErrors = @()
  foreach ($target in $Targets) {
    $tokens = $null; $errors = $null
    [System.Management.Automation.Language.Parser]::ParseFile($target.FullName, [ref]$tokens, [ref]$errors) | Out-Null
    foreach ($parseError in @($errors)) {
      $parseErrors += [pscustomobject]@{ File = $target.FullName; Message = $parseError.Message; Line = $parseError.Extent.StartLineNumber; Column = $parseError.Extent.StartColumnNumber }
    }
  }
  return $parseErrors
}

<##
.SYNOPSIS
Completes the parser verification gate.
.DESCRIPTION
Writes parser errors or records the compatible successful gate result.
#>
function Complete-ParseGate {
  [CmdletBinding()]
  param([Parameter(Mandatory)]$Targets)

  Write-Info -Message ("Parsing {0} PowerShell files..." -f $Targets.Count)
  $parseErrors = @(Get-VerificationParseErrors -Targets $Targets)
  if ($parseErrors.Count -eq 0) {
    Write-Success -Message 'Parse checks: OK'
    Add-GateResult -Name 'Parse' -Status 'PASS' -Detail ("{0} file(s)" -f $Targets.Count)
    return
  }
  Write-ErrorLine -Message ("Parse errors: {0}" -f $parseErrors.Count)
  $parseErrors | Sort-Object File,Line,Column | ForEach-Object { Write-UiLine ("- {0}:{1}:{2} {3}" -f $_.File, $_.Line, $_.Column, $_.Message) -ForegroundColor Yellow }
  Add-GateResult -Name 'Parse' -Status 'FAILED' -Detail ("{0} file(s), {1} parse error(s)" -f $Targets.Count, $parseErrors.Count)
  Complete-Verification -Verdict 'FAILED' -ExitCode 1
}

<##
.SYNOPSIS
Gets existing analyzer roots required by the verification contract.
.DESCRIPTION
Preserves the scripts, modules, tools, tests, and Rust-oracle analyzer set.
#>
function Get-VerificationAnalyzerPaths {
  [CmdletBinding()]
  param()

  $paths = @()
  foreach ($path in @('scripts', 'lib', 'tools', 'tests', 'rust/oracles')) {
    $candidate = Join-Path $RootPath $path
    if (Test-Path -LiteralPath $candidate) { $paths += $candidate }
  }
  return $paths
}

<##
.SYNOPSIS
Gets configured PSScriptAnalyzer findings for analyzer roots.
.DESCRIPTION
Uses the shared scan implementation and fails closed on analyzer errors.
#>
function Get-VerificationAnalyzerFindings {
  [CmdletBinding()]
  param([Parameter(Mandatory)][string[]]$Paths, [Parameter(Mandatory)][string]$SettingsPath)

  Import-Module (Join-Path $PSScriptRoot 'quality/QualityScans.psm1') -Force
  $files = @($Paths | ForEach-Object {
      Get-VerificationPowerShellTargets -Path $_ | ForEach-Object FullName
    } | Sort-Object -Unique)
  return @(Invoke-PowerShellAnalyzerScan -RootPath (Split-Path -Parent $SettingsPath) -Paths $files)
}

<##
.SYNOPSIS
Completes the PSScriptAnalyzer verification gate.
.DESCRIPTION
Preserves explicit skip, unavailable analyzer, settings, and finding outcomes.
#>
function Complete-AnalyzerGate {
  [CmdletBinding()]
  param([switch]$SkipAnalyzerRequested)

  if ($SkipAnalyzerRequested) {
    Write-Warn -Message 'PSScriptAnalyzer: SKIPPED (-SkipAnalyzer)'
    Add-GateResult -Name 'Analyzer' -Status 'SKIPPED' -Detail 'Skipped by explicit -SkipAnalyzer request'
    Complete-Verification -Verdict 'PARTIAL' -ExitCode 0
  }
  $settingsPath = Join-Path $RootPath 'PSScriptAnalyzerSettings.psd1'
  if (-not (Get-Command -Name Invoke-ScriptAnalyzer -ErrorAction SilentlyContinue)) {
    Write-ErrorLine -Message 'Invoke-ScriptAnalyzer not available. Analyzer did not run.'
    Add-GateResult -Name 'Analyzer' -Status 'FAILED' -Detail 'Invoke-ScriptAnalyzer not available'
    Complete-Verification -Verdict 'FAILED' -ExitCode 2
  }
  if (-not (Test-Path -LiteralPath $settingsPath)) {
    Write-ErrorLine -Message "PSScriptAnalyzer settings not found: $settingsPath"
    Add-GateResult -Name 'Analyzer' -Status 'FAILED' -Detail 'Settings file missing'
    Complete-Verification -Verdict 'FAILED' -ExitCode 2
  }
  Write-Info -Message 'Running PSScriptAnalyzer...'
  $paths = @(Get-VerificationAnalyzerPaths)
  $findings = @(Get-VerificationAnalyzerFindings -Paths $paths -SettingsPath $settingsPath)
  if ($findings.Count -gt 0) {
    Write-Warn -Message ("PSScriptAnalyzer reported {0} issue(s)." -f $findings.Count)
    $findings | Sort-Object Path,Line,Kind | ForEach-Object { Write-UiLine ("- {0}:{1} {2} ({3})" -f $_.Path, $_.Line, $_.Message, $_.Kind) -ForegroundColor Yellow }
    Add-GateResult -Name 'Analyzer' -Status 'FAILED' -Detail ("{0} issue(s)" -f $findings.Count)
    Complete-Verification -Verdict 'FAILED' -ExitCode 2
  }
  Write-Success -Message 'PSScriptAnalyzer: OK'
  Add-GateResult -Name 'Analyzer' -Status 'PASS' -Detail ("{0} path(s)" -f $paths.Count)
}

Invoke-Verification -SkipAnalyzerRequested:$SkipAnalyzer
