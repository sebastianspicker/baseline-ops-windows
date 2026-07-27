#requires -version 5.1
<#
.SYNOPSIS
Pester coverage for security-script contracts.

.DESCRIPTION
Verifies safe, repeatable operator behavior and evidence.
#>

Describe 'native command boundaries in audit scripts' {
  It '34-TimeSync-Health uses a bounded native boundary and treats incomplete output as failed evidence' {
    $scriptPath = Join-Path $PSScriptRoot '../../scripts/34-TimeSync-Health.ps1'
    $content = Get-Content -LiteralPath $scriptPath -Raw -Encoding UTF8

    $content | Should -Match 'Import-Module \(Join-Path \$script:LibPath ''External\.psm1''\)'
    $content | Should -Match 'Invoke-NativeCommand -Command \$FilePath -Arguments \$Arguments -CaptureOutput -Quiet -TimeoutSeconds 30 -MaxOutputBytes 262144'
    $content | Should -Match '\$native\.TimedOut.*\$native\.OutputTruncated.*\$native\.StderrTruncated'
    $content | Should -Match 'w32tm evidence is incomplete'
    $content | Should -Not -Match '\&\s*\$FilePath\s*@Arguments'
  }

  It '37-Remote-Surface-Audit uses a bounded native boundary and reports incomplete WinRM listener evidence' {
    $scriptPath = Join-Path $PSScriptRoot '../../scripts/37-Remote-Surface-Audit.ps1'
    $content = Get-Content -LiteralPath $scriptPath -Raw -Encoding UTF8

    $content | Should -Match 'Import-Module \(Join-Path \$script:LibPath ''External\.psm1''\)'
    $content | Should -Match "Invoke-WinrmCommand -Arguments @\('enumerate','winrm/config/listener'\) -CaptureOutput -Quiet -TimeoutSeconds 30 -MaxOutputBytes 262144"
    $content | Should -Match 'REMOTE-WinRMListenerEvidenceIncomplete'
    $content | Should -Match 'WinRM_ListenerEvidenceComplete'
    $content | Should -Not -Match '\&\s*winrm\.cmd'
  }
}
