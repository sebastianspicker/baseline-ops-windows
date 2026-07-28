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

$script:SkipNonSystemWindowsIntegration = $false
if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) {
  try {
    $script:SkipNonSystemWindowsIntegration =
      [Security.Principal.WindowsIdentity]::GetCurrent().User.Value -ne 'S-1-5-18'
  } catch {
    $script:SkipNonSystemWindowsIntegration = $true
  }
}

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
  BeforeAll {
    $scriptsDir = Join-Path $PSScriptRoot '../../scripts'
    $script:sysmonExtractionSources = @{}
    foreach ($scriptName in @('16-Sysmon-Config-Updater.ps1', '17-Sysmon-Rule-Drift-Sensor.ps1')) {
      $mainPath = Join-Path $scriptsDir $scriptName
      $helperName = [IO.Path]::GetFileNameWithoutExtension($scriptName) + '.helpers.ps1'
      $helperPath = Join-Path $scriptsDir (Join-Path 'internal' $helperName)
      $script:sysmonExtractionSources[$scriptName] = (Get-Content -LiteralPath $mainPath -Raw -Encoding UTF8), (Get-Content -LiteralPath $helperPath -Raw -Encoding UTF8) -join [Environment]::NewLine
    }
  }

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

    $content | Should -Match '\$PSCmdlet\.ShouldProcess\(\$resolvedPath, "Install VC\+\+ \$Architecture redistributable"\)'
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
    $content = $script:sysmonExtractionSources['17-Sysmon-Rule-Drift-Sensor.ps1']

    $content | Should -Match '\$PSCmdlet\.ShouldProcess\(\$ScriptPath, ''Launch trusted remediation PowerShell process''\)'
  }

  It '17-Sysmon-Rule-Drift-Sensor rejects unsafe remediation script paths before launch' {
    $content = $script:sysmonExtractionSources['17-Sysmon-Rule-Drift-Sensor.ps1']

    $content | Should -Match 'function Resolve-RemediationScriptPath'
    $content | Should -Match 'Resolve-Path -LiteralPath \$ScriptPath -ErrorAction Stop'
    $content | Should -Match 'Test-PathUnderRoot -Path \$canonicalScriptPath -Root \$canonicalScriptsDir'
    $content | Should -Match 'Test-PathContainsReparsePoint -Path \$resolvedScriptPath\.Path -Root \$resolvedScriptsDir\.Path'
    $content | Should -Match '\[System\.IO\.FileAttributes\]::ReparsePoint'
    $content | Should -Match 'Get-AuthenticodeSignature -FilePath \$ScriptPath'
    $content | Should -Match '\$ScriptPath = Resolve-RemediationScriptPath -ScriptPath \$ScriptPath'
    $content | Should -Match '\$closurePaths = Get-SysmonRemediationExecutionClosure -ScriptPath \$ScriptPath'
    $content | Should -Not -Match 'Get-ChildItem -LiteralPath .*''\.\.\\lib''.*-Filter ''\*\.psm1'' -File'
    $content | Should -Match '\[IO\.FileShare\]::Read'
    $content | Should -Match 'Assert-TrustedWindowsPathAcl -Path \$windowsPowerShell -CheckAncestors'
    $content | Should -Not -Match 'New-StagedRemediationScript'
    $content | Should -Not -Match '\[IO\.FileMode\]::CreateNew'
    $content | Should -Match 'Invoke-NativeCommand -Command \$windowsPowerShell'
    $content | Should -Not -Match 'Start-Process -FilePath "powershell\.exe"'
  }

  It '16-Sysmon-Config-Updater gates Sysmon install and config update behind ShouldProcess' {
    $content = $script:sysmonExtractionSources['16-Sysmon-Config-Updater.ps1']

    $content | Should -Match '\$PSCmdlet\.ShouldProcess\(\$exe, "Install Sysmon with staged configuration"\)'
    $content | Should -Match '\$PSCmdlet\.ShouldProcess\(\$exe, "Update Sysmon with staged configuration"\)'
    $content | Should -Match 'Invoke-StagedSysmonCommand -Exe \$exe'
  }

  It '16-Sysmon-Config-Updater gates Sysmon event channel mutations behind ShouldProcess' {
    $content = $script:sysmonExtractionSources['16-Sysmon-Config-Updater.ps1']

    $content | Should -Match 'function Ensure-SysmonChannel'
    $content | Should -Match '\[CmdletBinding\(SupportsShouldProcess = \$true\)\]'
    $content | Should -Match 'param\(\[switch\]\$DoIt,\[int\]\$MiB,\[System\.Management\.Automation\.PSCmdlet\]\$Cmdlet\)'
    $content | Should -Match '\$Cmdlet\.ShouldProcess\(\$name, ''Enable Sysmon Operational event channel''\)'
    $content | Should -Match '\$Cmdlet\.ShouldProcess\(\$name, "Resize Sysmon Operational event channel to \$MiB MiB"\)'
    $content | Should -Match 'Ensure-SysmonChannel -DoIt:\$doIt -MiB \$ChannelSizeMiB -Cmdlet \$PSCmdlet'
  }

  It '21-EmergencyKillSwitch uses ScheduledTasks APIs for its gated rollback task and embedded snapshot' {
    $path = Join-Path $PSScriptRoot '../../scripts/21-EmergencyKillSwitch.ps1'
    $content = Get-Content -LiteralPath $path -Raw -Encoding UTF8

    $content | Should -Match '\$PSCmdlet\.ShouldProcess\(\$rollbackTaskName, "Schedule automatic rollback task"\)'
    $content | Should -Match '\$PSCmdlet\.ShouldProcess\(\$rollbackTaskName, "Capture and validate embedded firewall rollback snapshot"\)'
    $content | Should -Match 'New-ScheduledTaskAction'
    $content | Should -Match 'New-ScheduledTaskTrigger'
    $content | Should -Match 'New-ScheduledTaskSettingsSet'
    $content | Should -Match 'Register-ScheduledTask'
    $content | Should -Not -Match '(?i)\bschtasks(?:\.exe)?\b'
    $content | Should -Match 'Test-NoManagedFirewallRuleConflicts -RulePrefix \$Run\.Effective\.RulePrefix -TaskPrefix \$Run\.Effective\.TaskName'
    $content | Should -Match 'Remove-ExactManagedFirewallRules -Rules @\(\$createdManagedRules\.ToArray\(\)\)'
  }

  It '21-EmergencyKillSwitch keeps mutation execution behind Remediate mode' {
    $path = Join-Path $PSScriptRoot '../../scripts/21-EmergencyKillSwitch.ps1'
    $content = Get-Content -LiteralPath $path -Raw -Encoding UTF8

    $content | Should -Match '(?s)Initialize-V2Context .*?-DeriveRemediate'
    $content | Should -Match 'if \(-not \$Run\.IsAdmin -and \$Remediate\)'
    $content | Should -Match 'if \(-not \$Remediate\)'
    $content | Should -Match 'Audit mode: no kill switch actions applied\.'
    $content | Should -Match 'if \(\$Remediate\) \{\s*if \(-not \(Ensure-EventSource'
  }

  It '21-EmergencyKillSwitch rollback fails closed without an embedded valid firewall snapshot' {
    $path = Join-Path $PSScriptRoot '../../scripts/21-EmergencyKillSwitch.ps1'
    $content = Get-Content -LiteralPath $path -Raw -Encoding UTF8

    $content | Should -Not -Match 'DefaultInboundAction Allow -DefaultOutboundAction Allow'
    $content | Should -Match 'Embedded firewall snapshot has an invalid schema'
    $content | Should -Not -Match 'Get-Content -LiteralPath \$fwStatePath'
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

Describe 'ShouldProcess runtime no-mutation behavior' -Tag 'ShouldProcess' {
  BeforeAll {
    $script:EmergencyKillSwitchPath = Join-Path $PSScriptRoot '../../scripts/21-EmergencyKillSwitch.ps1'
    $script:WinGetSelfHealPath = Join-Path $PSScriptRoot '../../scripts/08-WinGet-SelfHeal.ps1'
    Import-Module (Join-Path $PSScriptRoot '../../lib/Common.psm1') -Force

    $killSwitchHelperPath = Join-Path $PSScriptRoot '../../scripts/internal/21-EmergencyKillSwitch.helpers.ps1'
    $tokens = $null
    $parseErrors = $null
    $helperAst = [System.Management.Automation.Language.Parser]::ParseFile(
      (Resolve-Path $killSwitchHelperPath),
      [ref]$tokens,
      [ref]$parseErrors
    )
    $parseErrors | Should -BeNullOrEmpty
    $lockFunction = @($helperAst.FindAll({
          param($node)
          $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -eq 'Enter-KillSwitchRemediationLock'
        }, $true))[0]
    . ([scriptblock]::Create($lockFunction.Extent.Text))

    function global:Get-NetFirewallProfile { }
    function global:Set-NetFirewallProfile { }
    function global:Get-NetFirewallRule { }
    function global:Get-ScheduledTask { }
    function global:New-NetFirewallRule { }
    function global:Remove-NetFirewallRule { }
    function global:Disable-NetAdapter { }
  }

  AfterAll {
    foreach ($name in @(
        'Get-NetFirewallProfile',
        'Set-NetFirewallProfile',
        'Get-NetFirewallRule',
        'Get-ScheduledTask',
        'New-NetFirewallRule',
        'Remove-NetFirewallRule',
        'Disable-NetAdapter'
      )) {
      Remove-Item -LiteralPath "Function:\$name" -ErrorAction SilentlyContinue
    }
  }

  It '21-EmergencyKillSwitch Audit mode does not mutate registry or firewall state' {
    $oldOS = $env:OS
    try {
      $env:OS = 'Windows_NT'

      Mock -CommandName New-Item -MockWith { throw 'registry mutation should not run in Audit mode' }
      Mock -CommandName Set-ItemProperty -MockWith { throw 'registry mutation should not run in Audit mode' }
      Mock -CommandName Set-NetFirewallProfile -MockWith { throw 'firewall mutation should not run in Audit mode' }
      Mock -CommandName New-NetFirewallRule -MockWith { throw 'firewall mutation should not run in Audit mode' }
      Mock -CommandName Remove-NetFirewallRule -MockWith { throw 'firewall mutation should not run in Audit mode' }
      Mock -CommandName Disable-NetAdapter -MockWith { throw 'adapter mutation should not run in Audit mode' }

      $result = & $script:EmergencyKillSwitchPath -Mode Audit -OutputFormat None -PassThru -Confirm:$false 2>&1 3>&1 6>&1
    } finally {
      if ($null -eq $oldOS) {
        Remove-Item -LiteralPath Env:OS -ErrorAction SilentlyContinue
      } else {
        $env:OS = $oldOS
      }
    }

    $result.Result | Should -Be 'OK'
    Should -Invoke New-Item -Times 0
    Should -Invoke Set-ItemProperty -Times 0
    Should -Invoke Set-NetFirewallProfile -Times 0
    Should -Invoke New-NetFirewallRule -Times 0
    Should -Invoke Remove-NetFirewallRule -Times 0
    Should -Invoke Disable-NetAdapter -Times 0
  }

  It '21-EmergencyKillSwitch WhatIf in Remediate mode does not perform mutations' -Skip:$script:SkipNonSystemWindowsIntegration {
    $oldOS = $env:OS
    $oldTemp = $env:TEMP
    $testLockStream = $null
    try {
      $env:OS = 'Windows_NT'
      $env:TEMP = $TestDrive

      Mock -CommandName Test-IsAdmin -MockWith { $true }
      $testLockPath = Join-Path $TestDrive 'emergency-kill-switch-remediation.lock'
      $testLockStream = [System.IO.File]::Open(
        $testLockPath,
        [System.IO.FileMode]::OpenOrCreate,
        [System.IO.FileAccess]::ReadWrite,
        [System.IO.FileShare]::None
      )
      Mock -CommandName Enter-KillSwitchRemediationLock -MockWith { $testLockStream }
      Mock -CommandName Get-NetFirewallProfile -MockWith {
        [pscustomobject]@{
          Name                  = 'Domain'
          Enabled               = 'True'
          DefaultInboundAction  = 'Allow'
          DefaultOutboundAction = 'Allow'
        }
      }
      Mock -CommandName New-Item -MockWith { throw 'registry mutation should not run under WhatIf' }
      Mock -CommandName Set-ItemProperty -MockWith { throw 'registry mutation should not run under WhatIf' }
      Mock -CommandName Set-Content -MockWith { throw 'firewall state file should not be written under WhatIf' }
      Mock -CommandName Set-NetFirewallProfile -MockWith { throw 'firewall mutation should not run under WhatIf' }
      Mock -CommandName New-NetFirewallRule -MockWith { throw 'firewall mutation should not run under WhatIf' }
      Mock -CommandName Remove-NetFirewallRule -MockWith { throw 'firewall mutation should not run under WhatIf' }
      Mock -CommandName Disable-NetAdapter -MockWith { throw 'adapter mutation should not run under WhatIf' }
      Mock -CommandName Get-NetFirewallRule -MockWith { @() }
      Mock -CommandName Get-ScheduledTask -MockWith { @() }

      $result = & $script:EmergencyKillSwitchPath -Mode Remediate -OutputFormat None -PassThru -Confirm:$false -WhatIf 2>&1 3>&1 6>&1
    } finally {
      if ($null -ne $testLockStream) {
        $testLockStream.Dispose()
      }
      if ($null -eq $oldOS) {
        Remove-Item -LiteralPath Env:OS -ErrorAction SilentlyContinue
      } else {
        $env:OS = $oldOS
      }
      if ($null -eq $oldTemp) {
        Remove-Item -LiteralPath Env:TEMP -ErrorAction SilentlyContinue
      } else {
        $env:TEMP = $oldTemp
      }
    }

    $result.Result | Should -Be 'WARN'
    $result.Summary.Actions.ConfirmDeclined | Should -BeTrue
    Should -Invoke Enter-KillSwitchRemediationLock -Times 1 -Exactly
    Should -Invoke New-Item -Times 0
    Should -Invoke Set-ItemProperty -Times 0
    Should -Invoke Set-Content -Times 0
    Should -Invoke Set-NetFirewallProfile -Times 0
    Should -Invoke New-NetFirewallRule -Times 0
    Should -Invoke Remove-NetFirewallRule -Times 0
    Should -Invoke Disable-NetAdapter -Times 0
  }

  It '08-WinGet-SelfHeal Audit mode does not launch VC redistributable installers' {
    $oldOS = $env:OS
    $oldProgramFiles = $env:ProgramFiles
    $oldComputerName = $env:COMPUTERNAME
    try {
      $env:OS = 'Windows_NT'
      $env:ProgramFiles = $TestDrive
      $env:COMPUTERNAME = 'TEST-HOST'

      $installerPath = Join-Path $TestDrive 'vc_redist.x64.exe'
      Set-Content -LiteralPath $installerPath -Value 'fake installer' -Encoding UTF8
      $configPath = Join-Path $TestDrive 'winget-selfheal.json'
      @{
        VCppRedist = @{
          x64 = $installerPath
          Args = '/quiet'
        }
      } | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $configPath -Encoding UTF8

      Mock -CommandName Start-Process -MockWith { throw 'installer launch should not run in Audit mode' }

      $result = & $script:WinGetSelfHealPath -Mode Audit -ConfigPath $configPath -RequirePrivateSource:$false -OutputFormat None -PassThru -NoConsole -Confirm:$false 2>&1 3>&1 6>&1
    } finally {
      if ($null -eq $oldOS) {
        Remove-Item -LiteralPath Env:OS -ErrorAction SilentlyContinue
      } else {
        $env:OS = $oldOS
      }
      if ($null -eq $oldProgramFiles) {
        Remove-Item -LiteralPath Env:ProgramFiles -ErrorAction SilentlyContinue
      } else {
        $env:ProgramFiles = $oldProgramFiles
      }
      if ($null -eq $oldComputerName) {
        Remove-Item -LiteralPath Env:COMPUTERNAME -ErrorAction SilentlyContinue
      } else {
        $env:COMPUTERNAME = $oldComputerName
      }
    }

    $result.Summary.Mode | Should -Be 'Audit'
    @($result.Metadata.Records | Where-Object { $_.Name -eq 'VcRedistX64Remediation' }) | Should -BeNullOrEmpty
    Should -Invoke Start-Process -Times 0
  }
}
