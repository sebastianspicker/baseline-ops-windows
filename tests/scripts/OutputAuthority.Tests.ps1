#requires -version 5.1
<#
.SYNOPSIS
Guards capability output destinations against configuration authority.
.DESCRIPTION
Verifies each previously vulnerable config or catalog route resolves output
through the shared operator-authority helper before reaching filesystem or
registry sinks.
#>

BeforeAll {
  $script:repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
}

Describe 'Capability output authority' {
  $cases = @(
    @{ Path = 'scripts/internal/04-OfficeBrowser-Hardening-Proof.runtime.ps1'; Setting = 'Proof.OutFile' }
    @{ Path = 'scripts/23-BitLocker-Operations-Audit.ps1'; Setting = 'ExportPathDefault' }
    @{ Path = 'scripts/24-Cert-AutoEnrollment-Health.ps1'; Setting = 'ExportPath' }
    @{ Path = 'scripts/25-WinGet-Config-Baseline-Runner.ps1'; Setting = 'LogPath' }
    @{ Path = 'scripts/28-Join-Identity-Audit.ps1'; Setting = 'ExportPath' }
    @{ Path = 'scripts/31-PowerShell-Logging-Baseline.ps1'; Setting = 'TranscriptOutputDirectory' }
    @{ Path = 'scripts/39-CredentialGuard-VBS-AuditRemediate.ps1'; Setting = 'ExportPath' }
    @{ Path = 'scripts/39-CredentialGuard-VBS-AuditRemediate.ps1'; Setting = 'ExportCsvBasePath' }
    @{ Path = 'scripts/40-AddedLSAProtection-RunAsPPL-AuditRemediate.ps1'; Setting = 'ExportPath' }
    @{ Path = 'scripts/44-Defender-Ransomware-NetworkProtection-AuditRemediate.ps1'; Setting = 'ExportPath' }
    @{ Path = 'scripts/internal/05-WUFB-Proofing.helpers.ps1'; Setting = 'Proof.OutFile' }
    @{ Path = 'scripts/internal/06-UpdateHealth-SSU-Proof.runtime.ps1'; Setting = 'Proof.OutFile' }
    @{ Path = 'scripts/internal/07-ScheduledTasks-Hygiene.runtime.ps1'; Setting = 'QuarantineDir' }
    @{ Path = 'scripts/internal/07-ScheduledTasks-Hygiene.runtime.ps1'; Setting = 'Proof.OutFile' }
    @{ Path = 'scripts/internal/11-IOC-Sweep-Defender.helpers.ps1'; Setting = 'Proof.OutFile' }
    @{ Path = 'scripts/internal/11-IOC-Sweep-Defender.helpers.ps1'; Setting = 'EvidenceDir' }
    @{ Path = 'scripts/internal/15-HardwareTPM-Audit.runtime.ps1'; Setting = 'Proof.OutFile' }
  )

  It '<Path> keeps <Setting> under operator or built-in authority' -TestCases $cases {
    param($Path, $Setting)
    $source = Get-Content -LiteralPath (Join-Path $script:repoRoot $Path) -Raw -Encoding UTF8
    $pattern = '(?s)Resolve-OperatorControlledOutputPath.{0,500}-SettingName\s+''' + [regex]::Escape($Setting) + ''''
    $source | Should -Match $pattern
  }
}
