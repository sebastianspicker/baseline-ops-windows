# Release packaging and protected installation

This guide covers two parts of a PowerShell release: how maintainers publish a
tagged package on GitHub, and how operators install that package safely for
privileged use on Windows. The examples use `v2.3.0-alpha.1` because the
protected-install contract and its tests currently use that versioned directory
name.

The release workflow accepts semantic version tags such as
`v2.3.0-alpha.1`. Dispatch it from the tag being packaged. The workflow checks
that the event commit is the commit resolved by that tag.

## Package contents

The operator ZIP contains:

- 52 numbered endpoint scripts, from prefix `01-` through prefix `52-`
- six `00-*` validation, execution, copy, and reporting entry points
- seven example profiles and four example configurations
- shared PowerShell modules and the script scaffolding/verification tools
- the Windows Forms launcher
- public project, contribution, security, changelog, and operator documentation

The ZIP does not include `.github/`, `tests/`, private directories,
`scripts/ci-local.sh`, `tools/quality/`, `tools/demo/`, or
`tools/demo-profiles.mjs`. It includes browser tour assets and screenshots as
documentation, but leaves out the browser test dependencies.

## Release verification

Before it builds a package, `.github/workflows/release.yml` runs these checks
against the resolved tag:

- Installs the official PowerShell 7.6.3 Linux archive after checking its pinned SHA-256 digest.
- Loads PSScriptAnalyzer 1.25.0 and Pester 5.8.0.
- Runs the secret scan, documentation check, static verifier, and complete Pester suite.
- Builds the ZIP with `git archive` from the resolved release commit.
- Verifies the package inventory and expected counts.
- Runs profile validation, profile smoke, secret, documentation, and static checks against an extracted ZIP.

After those checks pass, the publish job verifies the remote tag and confirms
that immutable releases are enabled for the repository. It creates a build
provenance attestation and a new draft release, uploads the assets without
replacing any existing asset, publishes the release, and verifies the final
immutable state.

The repository cannot prove that GitHub has the required environment reviewers,
tag rules, secrets, or immutable-release setting. A maintainer must verify those
controls before creating the tag.

## Release artifacts

For a tag named `v2.3.0-alpha.1`, the workflow creates:

- `baselineops-windows-v2.3.0-alpha.1.zip`
- `baselineops-windows-v2.3.0-alpha.1.zip.sha256`
- `baselineops-windows-v2.3.0-alpha.1.zip.manifest.sha256`
- `baselineops-windows-v2.3.0-alpha.1.zip.intoto.jsonl`

The `.sha256` file records the ZIP digest. The manifest records a SHA-256 digest
for every extracted file. The `.intoto.jsonl` file is the downloaded GitHub
build provenance attestation bundle. This workflow does not generate an SBOM.

### Authenticate provenance first

Download all four assets from the same GitHub release. Open a standard-user
PowerShell session and copy the 40-character source commit from the release
notes. Before reading or extracting the ZIP, use GitHub CLI to authenticate the
ZIP digest, source commit, source tag, and publishing workflow:

```powershell
if (-not (Get-Command gh -CommandType Application -ErrorAction SilentlyContinue)) {
  throw 'GitHub CLI with attestation verification support is required.'
}
gh attestation verify --help | Out-Null
if ($LASTEXITCODE -ne 0) {
  throw 'GitHub CLI with attestation verification support is required.'
}
```

```powershell
$Asset = '.\baselineops-windows-v2.3.0-alpha.1.zip'
$SourceCommit = Read-Host 'Enter the 40-character source commit from the release notes'
if ($SourceCommit -notmatch '^[0-9a-fA-F]{40}$') {
  throw 'SourceCommit must be a 40-character Git commit identifier.'
}
$ExpectedSha256 = [string](& gh attestation verify $Asset `
  --repo sebastianspicker/baseline-ops `
  --bundle "$Asset.intoto.jsonl" `
  --signer-workflow github.com/sebastianspicker/baseline-ops/.github/workflows/release.yml `
  --source-ref refs/tags/v2.3.0-alpha.1 `
  --source-digest $SourceCommit `
  --deny-self-hosted-runners `
  --format json `
  --jq '.[0].verificationResult.statement.subject[0].digest.sha256')
if ($LASTEXITCODE -ne 0 -or $ExpectedSha256 -notmatch '^[0-9a-f]{64}$') {
  throw 'Release provenance verification failed.'
}
$ExpectedSha256
```

Save the printed `$ExpectedSha256` for the protected-install step. The separate
checksum can detect corruption, but it cannot authenticate the publisher. For
that reason, check it only after the attestation succeeds.

### Verify the ZIP and extracted files

PowerShell:

```powershell
$PublishedChecksum = (Get-Content "$Asset.sha256" -Raw).Split()[0].ToLowerInvariant()
$Actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $Asset).Hash.ToLowerInvariant()
if ($PublishedChecksum -cne $ExpectedSha256 -or $Actual -cne $ExpectedSha256) {
  throw 'Release ZIP checksum mismatch.'
}
```

In a POSIX shell or Git Bash, verify both the ZIP and the extracted file
manifest in a new temporary directory:

```bash
asset='baselineops-windows-v2.3.0-alpha.1.zip'
manifest="${PWD}/${asset}.manifest.sha256"
package_dir="$(mktemp -d)"
trap 'rm -rf "${package_dir}"' EXIT
sha256sum -c "${asset}.sha256"
unzip -q "${asset}" -d "${package_dir}"
(cd "${package_dir}" && sha256sum -c "${manifest}")
```

### Check the extracted operator package

The following checks use only files included in the ZIP. From the extracted
package root, run them without elevation and with PowerShell 7.6.3 exactly. They
validate the package contents, but they do not make a user-owned extraction safe
for privileged execution. Install PSScriptAnalyzer 1.25.0 before running the
complete static gate:

```powershell
pwsh -NoProfile -File .\scripts\00-Validate-Profile.ps1 -ProfilePath .\examples\profiles\baseline-audit.json -RootPath .
pwsh -NoProfile -ExecutionPolicy Bypass -File .\tools\secret-scan.ps1 -RootPath .
pwsh -NoProfile -ExecutionPolicy Bypass -File .\tools\Test-Documentation.ps1 -RootPath .
pwsh -NoProfile -ExecutionPolicy Bypass -Command "Import-Module PSScriptAnalyzer -RequiredVersion 1.25.0 -Force; & .\tools\verify.ps1 -RootPath ."
```

`verify.ps1 -SkipAnalyzer` performs only a partial parse check and does not
replace the complete gate. Pester and `scripts/ci-local.sh` require a full
checkout of the release tag. The operator ZIP deliberately excludes both
`scripts/ci-local.sh` and `tests/`.

An extracted ZIP has no Git metadata. The verifier and secret scan therefore
fall back to recursive package scanning. In a Windows checkout, these two tools
accept bare Git only from the standard Program Files locations and enumerate
`git ls-files --cached --others --exclude-standard`. If trusted Git is not
available, the fallback may also scan ignored local files. Use an exact staged
or package surface for release evidence; do not weaken the executable-path
policy. The documentation checker uses the Git application found on `PATH` and
fails when repository discovery cannot complete.

### Install a protected Windows copy

Elevated runners and the launcher refuse a kit root when that root or any of its
ancestors is owned or writable by an untrusted SID. The Downloads extraction is
appropriate for the standard-user checks above, but it is deliberately unsafe
as a privileged execution root.

`00-Copy-Local.ps1` cannot bootstrap trust from an untrusted directory. It
validates its own source before importing it. When using this synchronization
tool, set `-RepoRef` to the full source commit from the verified release
provenance. It refuses an omitted reference, branch name, or tag before
synchronization. `-WhatIf` remains a no-mutation preview and does not require a
ref.

After the attestation succeeds, open a new elevated Windows PowerShell 5.1
session. In the block below, `$ZipPath` points to the current user's Downloads
folder. At the prompt, enter the authenticated digest printed as
`$ExpectedSha256` above.

The block uses only Windows and .NET built-ins. It refuses an existing
destination, creates a protected directory under Program Files, copies and
verifies the ZIP inside that directory, extracts the files, and changes every
extracted owner to `BUILTIN\Administrators`. Users receive read and execute
access, but cannot write or replace the files.

Copy this block from the immutable tagged GitHub page. Do not run a copy from a
local, user-writable extraction, because that copy could have changed after
verification.

```powershell
$ErrorActionPreference = 'Stop'
$Downloads = Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::UserProfile)) 'Downloads'
$ZipPath = Join-Path $Downloads 'baselineops-windows-v2.3.0-alpha.1.zip'
$ExpectedSha256 = Read-Host 'Enter the authenticated 64-character SHA-256 digest'
$ProgramFiles = [Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles)
if ([string]::IsNullOrWhiteSpace($ProgramFiles)) {
  throw 'Windows Program Files could not be resolved.'
}
$ProgramFilesItem = Get-Item -LiteralPath $ProgramFiles -Force -ErrorAction Stop
if (($ProgramFilesItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
  throw 'Refusing a Program Files root that is a reparse point.'
}
$InstallRoot = Join-Path $ProgramFilesItem.FullName 'BaselineOpsForWindows-v2.3.0-alpha.1'

if ($ExpectedSha256 -notmatch '^[0-9a-fA-F]{64}$') {
  throw 'ExpectedSha256 must be the authenticated 64-character digest.'
}
$ZipPath = (Resolve-Path -LiteralPath $ZipPath -ErrorAction Stop).Path
if (Test-Path -LiteralPath $InstallRoot) {
  throw "Refusing existing install root: $InstallRoot"
}

$AdministratorsSid = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')
$SystemSid = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-18')
$UsersSid = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-545')
$Acl = New-Object System.Security.AccessControl.DirectorySecurity
$Acl.SetOwner($AdministratorsSid)
$Acl.SetAccessRuleProtection($true, $false)
$Inheritance = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
  [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
$Propagation = [System.Security.AccessControl.PropagationFlags]::None
$Allow = [System.Security.AccessControl.AccessControlType]::Allow
foreach ($Entry in @(
    [pscustomobject]@{ Sid = $AdministratorsSid; Rights = [System.Security.AccessControl.FileSystemRights]::FullControl },
    [pscustomobject]@{ Sid = $SystemSid; Rights = [System.Security.AccessControl.FileSystemRights]::FullControl },
    [pscustomobject]@{ Sid = $UsersSid; Rights = [System.Security.AccessControl.FileSystemRights]::ReadAndExecute }
  )) {
  $Rule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule -ArgumentList @(
    $Entry.Sid, $Entry.Rights, $Inheritance, $Propagation, $Allow
  )
  [void]$Acl.AddAccessRule($Rule)
}

[void](New-Item -Path $InstallRoot -ItemType Directory -ErrorAction Stop)
Set-Acl -LiteralPath $InstallRoot -AclObject $Acl -ErrorAction Stop
$StagedZip = Join-Path $InstallRoot '.verified-package.zip'
try {
  Copy-Item -LiteralPath $ZipPath -Destination $StagedZip -ErrorAction Stop
  $ActualSha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $StagedZip).Hash
  if ($ActualSha256 -cne $ExpectedSha256.ToUpperInvariant()) {
    throw 'Protected ZIP copy does not match the authenticated digest.'
  }
  Expand-Archive -LiteralPath $StagedZip -DestinationPath $InstallRoot -ErrorAction Stop
  Remove-Item -LiteralPath $StagedZip -Force -ErrorAction Stop

  $InstalledItems = @((Get-Item -LiteralPath $InstallRoot -Force)) +
    @(Get-ChildItem -LiteralPath $InstallRoot -Recurse -Force)
  foreach ($Item in $InstalledItems) {
    if (($Item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
      throw "Installed package contains a reparse point: $($Item.FullName)"
    }
    $ItemAcl = Get-Acl -LiteralPath $Item.FullName -ErrorAction Stop
    $ItemAcl.SetOwner($AdministratorsSid)
    Set-Acl -LiteralPath $Item.FullName -AclObject $ItemAcl -ErrorAction Stop
  }
} catch {
  if (Test-Path -LiteralPath $InstallRoot) {
    Remove-Item -LiteralPath $InstallRoot -Recurse -Force -ErrorAction SilentlyContinue
  }
  throw
}

Write-Host "Protected install ready: $InstallRoot"
```

Execute repository code with elevation only after the installation block
succeeds. From the protected root, the baseline profile returns `0` on success,
`2` when it completes with warnings, and `1` on failure:

```powershell
Set-Location -LiteralPath $InstallRoot
pwsh -NoProfile -File .\scripts\00-Run-Profile.ps1 -ProfilePath .\examples\profiles\baseline-audit.json -RootPath $InstallRoot -Mode Audit -OutputFormat None -Confirm:$false
```

To preview strict remediation control flow without running any endpoint
capability, use the profile with `-WhatIf`:

```powershell
pwsh -NoProfile -File .\scripts\00-Run-Profile.ps1 -ProfilePath .\examples\profiles\hardening-remediate.json -RootPath $InstallRoot -Mode Remediate -Strict -OutputFormat None -WhatIf -Confirm:$false

pwsh -NoProfile -File .\scripts\00-Run-Batch.ps1 -Category Remediation -RootPath $InstallRoot -Mode Remediate -OutputFormat None -WhatIf -Confirm:$false
```

The preview intentionally skips every child script and returns `WARN` / exit
`2`. Strict mode does not promote a warning caused only by these skips. A batch
preview stops before creating its temporary profile workspace. This confirms
selection and no-mutation behavior only; it provides no endpoint audit or
remediation evidence. Use `-OutputFormat None` to avoid creating an artifact.
If a JSON/CSV output path is explicitly requested, it still receives the
terminal result.

## Operational limitations

- Source scripts are not Authenticode-signed. The elevated launcher requires a valid signature by default. Deployment owners must sign the scripts or explicitly record a weaker lab-only decision.
- Expected hashes supplement signature and protected-path checks. They do not make a user-writable execution root trusted.
- The interactive launcher requires environment-specific manual validation. See the [launcher checklist](launcher-gui.md#manual-validation-checklist).
- Endpoint remediation, rollback, feature availability, and failure behavior must be tested on representative disposable devices.
- Stopping a launcher worker terminates its process tree but does not undo completed changes.
- Logs, reports, support bundles, and saved launcher output can contain endpoint details.

## Maintainer release checklist

Repository files cannot enforce settings hosted by GitHub. Before tagging,
enable
[immutable releases](https://docs.github.com/en/code-security/how-tos/secure-your-supply-chain/establish-provenance-and-integrity/prevent-release-changes),
protect release-tag creation with a repository ruleset, and configure the
`alpha-release` environment with required reviewer and deployment-tag controls.
The environment must also provide `RELEASE_SETTINGS_READ_TOKEN`, a fine-grained
token scoped to this repository with read-only Administration permission. The
publish job uses this token only to check the immutable-release setting before
creating a draft. The normal job token handles the release contents.

1. Verify the remote controls and freeze one clean commit containing the intended source and documentation.
2. Run the commands in [CONTRIBUTING.md](../CONTRIBUTING.md#local-checks) under PowerShell 7.6.3 and Windows PowerShell 5.1 with PSScriptAnalyzer 1.25.0 and Pester 5.8.0. Review failures, unexpected skips, and test-discovery changes.
3. Complete the manual launcher and endpoint remediation checks required for the release scope.
4. Create the exact semantic prerelease tag `v2.3.0-alpha.1` at that commit and
   push only the tag intended for publication.
5. Confirm the `Release Package` workflow resolves that commit, passes every
   gate, creates the draft, uploads all four immutable assets, and publishes it.
6. Download the public assets and repeat checksum, manifest, and provenance
   verification independently.
7. Record newly discovered limitations in the changelog and this guide before
   promoting a later alpha or release candidate.

### Failed-draft recovery

The workflow never reuses a release. If it fails after creating an unpublished
draft, preserve the run logs and inspect every draft asset before recovery.
Confirm that `isDraft` is true and that the tag still points to the frozen
commit. Then delete only that draft and rerun the workflow from the same,
unchanged tag:

```bash
tag='v2.3.0-alpha.1'
gh release view "${tag}" --json isDraft,isImmutable,tagName,assets
gh release delete "${tag}" --yes
```

Do not pass `--cleanup-tag`; the verified tag must remain intact. Never delete
or reuse a published or immutable release. If the publication state is unclear
or the tag has moved, stop. After review, create a new prerelease version.
