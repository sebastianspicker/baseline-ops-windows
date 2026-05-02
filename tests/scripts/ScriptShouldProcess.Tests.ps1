#requires -version 5.1

<#
.SYNOPSIS
  Meta-test: verifies that every script declaring SupportsShouldProcess wraps
  all Set-Reg* and Remove-Reg* calls inside a ShouldProcess guard.

.DESCRIPTION
  Reads the raw text of each script that declares SupportsShouldProcess=$true
  AND contains at least one Set-Reg* or Remove-Reg* call, then scans for
  unguarded registry-write calls. Scripts that declare ShouldProcess but do
  not directly invoke registry-write functions are skipped.

  The detection is heuristic (text-based), not AST-based, but catches the
  common pattern where a registry-write call sits outside any ShouldProcess
  guard within the same remediation block.
#>

BeforeDiscovery {
  $scriptsDir = Join-Path $PSScriptRoot '../../scripts'
  $scriptFiles = Get-ChildItem -LiteralPath $scriptsDir -Filter '*.ps1' -File |
    Where-Object { $_.Name -match '^\d{2}-' }

  # Registry-modifying function patterns to look for
  $regWritePatternDisc = '(Set-RegDword|Set-RegString|Set-RegQword|Set-RegExpandString|Set-RegMultiString|Set-RegBinary|Remove-RegValueIfExists|Remove-RegistryKeyIfExists)\s'

  # Filter to scripts that BOTH declare SupportsShouldProcess AND contain
  # registry-write calls. Scripts that only declare ShouldProcess for
  # non-registry operations (e.g., file copies, profile orchestration) are
  # excluded because this meta-test is specifically about registry guards.
  $script:shouldProcessScripts = @()
  foreach ($file in $scriptFiles) {
    $content = Get-Content -LiteralPath $file.FullName -Raw
    if ($content -match 'SupportsShouldProcess\s*=\s*\$true' -and $content -match $regWritePatternDisc) {
      $script:shouldProcessScripts += [pscustomobject]@{ Name = $file.Name; FullName = $file.FullName; Content = $content }
    }
  }
}

Describe 'ShouldProcess guards for registry-write calls' {

  # Registry-modifying function patterns to look for
  BeforeAll {
    $script:regWritePattern = '(Set-RegDword|Set-RegString|Set-RegQword|Set-RegExpandString|Set-RegMultiString|Set-RegBinary|Remove-RegValueIfExists|Remove-RegistryKeyIfExists)\s'
  }

  It '<_.Name> wraps all registry-write calls in ShouldProcess guards' -ForEach $shouldProcessScripts {
    $file = $_
    $lines = $file.Content -split "`n"
    $unguarded = @()

    for ($i = 0; $i -lt $lines.Count; $i++) {
      $line = $lines[$i]

      # Skip comment lines
      if ($line -match '^\s*#') { continue }

      # Check if this line contains a registry-write call
      if ($line -match $script:regWritePattern) {
        # Look backwards from this line to find the nearest enclosing
        # ShouldProcess guard. We check a window of preceding lines
        # for an open if-ShouldProcess block (brace counting).
        $foundGuard = $false
        $braceDepth = 0

        for ($j = $i; $j -ge 0 -and $j -ge ($i - 30); $j--) {
          $checkLine = $lines[$j]

          # Count closing braces (going backwards, these are "openings")
          $braceDepth += ([regex]::Matches($checkLine, '\}')).Count
          $braceDepth -= ([regex]::Matches($checkLine, '\{')).Count

          if ($checkLine -match 'ShouldProcess') {
            # The ShouldProcess guard should be at the same or enclosing scope
            if ($braceDepth -le 0) {
              $foundGuard = $true
              break
            }
          }
        }

        if (-not $foundGuard) {
          $lineNum = $i + 1
          $trimmed = $line.Trim()
          $unguarded += "Line ${lineNum}: $trimmed"
        }
      }
    }

    $unguarded | Should -BeNullOrEmpty -Because "All Set-Reg*/Remove-Reg* calls must be wrapped in `$PSCmdlet.ShouldProcess() guards"
  }
}

Describe 'Direct registry-write paths in audited scripts' {
  It '05-WUFB-Proofing helper writes are protected by ShouldProcess' {
    $path = Join-Path $PSScriptRoot '../../scripts/05-WUFB-Proofing.ps1'
    $content = Get-Content -LiteralPath $path -Raw -Encoding UTF8

    $content | Should -Match 'function Set-WufbDword'
    $content | Should -Match 'function Set-REGSZ'
    $content | Should -Match 'function Remove-REGValue'
    $content | Should -Match '\$PSCmdlet\.ShouldProcess\("\$Path\\\$Name", "Set DWORD'
    $content | Should -Match '\$PSCmdlet\.ShouldProcess\("\$Path\\\$Name", "Set string'
    $content | Should -Match '\$PSCmdlet\.ShouldProcess\("\$Path\\\$Name", "Remove registry value"\)'
  }

  It '04-OfficeBrowser-Hardening-Proof remediation writes are protected by ShouldProcess' {
    $path = Join-Path $PSScriptRoot '../../scripts/04-OfficeBrowser-Hardening-Proof.ps1'
    $content = Get-Content -LiteralPath $path -Raw -Encoding UTF8

    $content | Should -Match 'function Set-RegValueProof'
    $content | Should -Match '\$PSCmdlet\.ShouldProcess\("\$Path\\\$Name", "Set \$Type value"\)'
    $content | Should -Match '\$PSCmdlet\.ShouldProcess\(\$urlsKey, ''Reset Edge startup URLs''\)'
    $content | Should -Match '\$PSCmdlet\.ShouldProcess\("\$urlsKey\\\$name", ''Set Edge startup URL''\)'
  }

  It '21-EmergencyKillSwitch confirms quarantine-flag writes before touching the registry' {
    $path = Join-Path $PSScriptRoot '../../scripts/21-EmergencyKillSwitch.ps1'
    $content = Get-Content -LiteralPath $path -Raw -Encoding UTF8

    $content | Should -Match 'ShouldProcess\(\$Run\.Effective\.RegKey, "Write quarantine registry flag"\)'
  }

  It '38-SecurityOptions-Drift keeps registry writes behind a call-site ShouldProcess guard' {
    $path = Join-Path $PSScriptRoot '../../scripts/38-SecurityOptions-Drift.ps1'
    $content = Get-Content -LiteralPath $path -Raw -Encoding UTF8

    $content | Should -Match 'if \(\$PSCmdlet\.ShouldProcess\("\$path\\\$name", "Set to ''\$want'' \(\$type\)"\)\)'
  }

  It '01-ASR-Defender-Allowlist gates Defender preference changes behind ShouldProcess' {
    $path = Join-Path $PSScriptRoot '../../scripts/01-ASR-Defender-Allowlist.ps1'
    $content = Get-Content -LiteralPath $path -Raw -Encoding UTF8

    $content | Should -Match '\$PSCmdlet\.ShouldProcess\(\$name, "Add Defender allowlist entries"\)'
    $content | Should -Match '\$PSCmdlet\.ShouldProcess\(\$name, "Remove Defender allowlist entries"\)'
  }

  It '06-UpdateHealth-SSU-Proof gates service start-type and runtime state changes behind ShouldProcess' {
    $path = Join-Path $PSScriptRoot '../../scripts/06-UpdateHealth-SSU-Proof.ps1'
    $content = Get-Content -LiteralPath $path -Raw -Encoding UTF8

    $content | Should -Match '\$PSCmdlet\.ShouldProcess\(\$Name, ''Set startup type to AutomaticDelayedStart''\)'
    $content | Should -Match '\$PSCmdlet\.ShouldProcess\(\$Name, "Set startup type to \$StartType"\)'
    $content | Should -Match '\$PSCmdlet\.ShouldProcess\(\$Name, "Set service state to \$State"\)'
  }

  It '08-WinGet-SelfHeal gates VC++ installer launch behind ShouldProcess' {
    $path = Join-Path $PSScriptRoot '../../scripts/08-WinGet-SelfHeal.ps1'
    $content = Get-Content -LiteralPath $path -Raw -Encoding UTF8

    $content | Should -Match '\$PSCmdlet\.ShouldProcess\(\$Path, ''Install VC\+\+ redistributable''\)'
  }

  It '09-SupportBundle gates event-source registration and trigger reset behind ShouldProcess' {
    $path = Join-Path $PSScriptRoot '../../scripts/09-SupportBundle.ps1'
    $content = Get-Content -LiteralPath $path -Raw -Encoding UTF8

    $content | Should -Match '\$PSCmdlet\.ShouldProcess\(\$EventSource, ''Register SupportBundle event source''\)'
    $content | Should -Match '\$PSCmdlet\.ShouldProcess\(\$KeyPath, ''Reset support bundle trigger registry values''\)'
  }

  It '11-IOC-Sweep-Defender gates containment actions behind ShouldProcess' {
    $path = Join-Path $PSScriptRoot '../../scripts/11-IOC-Sweep-Defender.ps1'
    $content = Get-Content -LiteralPath $path -Raw -Encoding UTF8

    $content | Should -Match '\$PSCmdlet\.ShouldProcess\(\$path, ''Neutralize registry value''\)'
    $content | Should -Match '\$PSCmdlet\.ShouldProcess\(\$svc\.Name, "Contain service \(\$action\)"\)'
    $content | Should -Match '\$PSCmdlet\.ShouldProcess\(\$full, ''Disable scheduled task''\)'
  }

  It '12-Suspicious-Artifact-Grabber gates trigger reset behind ShouldProcess' {
    $path = Join-Path $PSScriptRoot '../../scripts/12-Suspicious-Artifact-Grabber.ps1'
    $content = Get-Content -LiteralPath $path -Raw -Encoding UTF8

    $content | Should -Match '\$PSCmdlet\.ShouldProcess\(\$rk, ''Reset artifact grabber trigger registry flag''\)'
  }

  It '17-Sysmon-Rule-Drift-Sensor gates remediation process launch behind ShouldProcess' {
    $path = Join-Path $PSScriptRoot '../../scripts/17-Sysmon-Rule-Drift-Sensor.ps1'
    $content = Get-Content -LiteralPath $path -Raw -Encoding UTF8

    $content | Should -Match '\$PSCmdlet\.ShouldProcess\(\$ScriptPath, ''Launch remediation PowerShell process''\)'
  }

  It '17-Sysmon-Rule-Drift-Sensor rejects unsafe remediation script paths before launch' {
    $path = Join-Path $PSScriptRoot '../../scripts/17-Sysmon-Rule-Drift-Sensor.ps1'
    $content = Get-Content -LiteralPath $path -Raw -Encoding UTF8

    $content | Should -Match 'function Resolve-RemediationScriptPath'
    $content | Should -Match 'Resolve-Path -LiteralPath \$ScriptPath -ErrorAction Stop'
    $content | Should -Match 'Test-PathUnderRoot -Path \$canonicalScriptPath -Root \$canonicalScriptsDir'
    $content | Should -Match '\[System\.IO\.FileAttributes\]::ReparsePoint'
    $content | Should -Match 'Get-AuthenticodeSignature -FilePath \$canonicalScriptPath'
    $content | Should -Match '\$ScriptPath = Resolve-RemediationScriptPath -ScriptPath \$ScriptPath'
    $content | Should -Match 'Start-Process -FilePath "powershell\.exe"'
  }

  It '16-Sysmon-Config-Updater gates Sysmon install and config update behind ShouldProcess' {
    $path = Join-Path $PSScriptRoot '../../scripts/16-Sysmon-Config-Updater.ps1'
    $content = Get-Content -LiteralPath $path -Raw -Encoding UTF8

    $content | Should -Match '\$PSCmdlet\.ShouldProcess\(\$exe, "Install Sysmon with config ''\$cfgPath''"\)'
    $content | Should -Match '\$PSCmdlet\.ShouldProcess\(\$exe, "Update Sysmon config to ''\$cfgPath''"\)'
  }

  It '16-Sysmon-Config-Updater gates Sysmon event channel mutations behind ShouldProcess' {
    $path = Join-Path $PSScriptRoot '../../scripts/16-Sysmon-Config-Updater.ps1'
    $content = Get-Content -LiteralPath $path -Raw -Encoding UTF8

    $content | Should -Match 'function Ensure-SysmonChannel\(\[switch\]\$DoIt,\[int\]\$MiB,\[System\.Management\.Automation\.PSCmdlet\]\$Cmdlet\)'
    $content | Should -Match '\$Cmdlet\.ShouldProcess\(\$name, ''Enable Sysmon Operational event channel''\)'
    $content | Should -Match '\$Cmdlet\.ShouldProcess\(\$name, "Resize Sysmon Operational event channel to \$MiB MiB"\)'
    $content | Should -Match 'Ensure-SysmonChannel -DoIt:\$doIt -MiB \$ChannelSizeMiB -Cmdlet \$PSCmdlet'
  }

  It '21-EmergencyKillSwitch gates scheduled task, firewall-state file, and break-glass removal' {
    $path = Join-Path $PSScriptRoot '../../scripts/21-EmergencyKillSwitch.ps1'
    $content = Get-Content -LiteralPath $path -Raw -Encoding UTF8

    $content | Should -Match '\$PSCmdlet\.ShouldProcess\(\$Run\.Effective\.TaskName, "Schedule automatic rollback task"\)'
    $content | Should -Match '\$PSCmdlet\.ShouldProcess\(\$fwStatePath, "Write pre-kill-switch firewall state"\)'
    $content | Should -Match '\$PSCmdlet\.ShouldProcess\(\$RuleBgName, "Remove break-glass inbound allow rule"\)'
  }

  It '25-WinGet-Config-Baseline-Runner gates apply and keeps Audit mode test-only' {
    $path = Join-Path $PSScriptRoot '../../scripts/25-WinGet-Config-Baseline-Runner.ps1'
    $content = Get-Content -LiteralPath $path -Raw -Encoding UTF8

    $content | Should -Match 'if \(\$Mode -eq ''Audit''\) \{ \$TestOnlyEffective = \$true \}'
    $content | Should -Match 'if \(\(\$Mode -eq ''Remediate''\) -and \(-not \$TestOnlyEffective\)\)'
    $content | Should -Match '\$PSCmdlet\.ShouldProcess\(\$resolvedConfigPath, ''Run winget configure apply''\)'
    $content | Should -Match 'Invoke-WinGet -ArgsWinget \$argsApply -Phase ''apply'''
  }

  It '34-TimeSync-Health gates AutoStartService behind ShouldProcess' {
    $path = Join-Path $PSScriptRoot '../../scripts/34-TimeSync-Health.ps1'
    $content = Get-Content -LiteralPath $path -Raw -Encoding UTF8

    $content | Should -Match '\$PSCmdlet\.ShouldProcess\(''w32time'', ''Start service''\)'
  }
}
