#requires -version 5.1
<#
.SYNOPSIS
Pester tests for Output.psm1 module

.DESCRIPTION
Unit tests for the Output module. Tests core functions Write-UiLine,
Write-KeyValue, Write-Section, and Write-BlankLine.
Uses Mock Write-Information to capture output for assertions.
#>

[CmdletBinding()]
param()

BeforeAll {
  # Scripts exercised earlier in the full suite import Output into transient
  # script scopes. Remove every stale module instance so Pester's ModuleName
  # target is deterministic instead of failing on an ambiguous module name.
  Get-Module -Name Output -All | Remove-Module -Force -ErrorAction SilentlyContinue
  Import-Module (Join-Path $PSScriptRoot '../../lib/Output.psm1') -Force
  . (Join-Path $PSScriptRoot '../support/OutputAssertions.ps1')
}

Describe 'Output module export surface' {
  It 'Does not export removed decorative console wrappers' {
    $removed = @('Write-Rule', 'Write-ConsoleRule', 'Write-ConsoleSeparator', 'Write-Title', 'Write-Good', 'Write-Bad', 'Write-UiProgress')
    $names = Get-Command -Module Output | Select-Object -ExpandProperty Name

    foreach ($name in $removed) {
      $names | Should -Not -Contain $name
    }
  }

  It 'Exports pass-through compatibility names as aliases' {
    $expectedAliases = @{
      'Write-UiSection' = 'Write-Section'
      'Write-ColorLine' = 'Write-UiLine'
      'Write-InfoLine'  = 'Write-Info'
      'Write-WarnLine'  = 'Write-Warn'
    }

    foreach ($entry in $expectedAliases.GetEnumerator()) {
      $command = Get-Command -Name $entry.Key -Module Output
      $command.CommandType | Should -Be 'Alias'
      $command.ResolvedCommandName | Should -Be $entry.Value
    }
  }

  It 'keeps the shared status helper private and status writer signatures public' {
    Get-Command -Name 'Write-StatusMessage' -Module Output -ErrorAction SilentlyContinue |
      Should -BeNullOrEmpty

    foreach ($name in @('Write-Info', 'Write-Warn', 'Write-ErrorLine', 'Write-Success')) {
      $command = Get-Command -Name $name -Module Output
      $command.CommandType | Should -Be 'Function'
      $command.Parameters['Message'].ParameterType | Should -Be ([string])
      $command.Parameters['NoPrefix'].ParameterType | Should -Be ([switch])
    }
  }
}

Describe 'Write-UiLine' {
  It 'Writes the provided message to the information stream' {
    Mock Write-Information {} -ModuleName Output
    Write-UiLine -Message 'Hello World'
    Should -Invoke Write-Information -ModuleName Output -Times 1 -ParameterFilter { $MessageData -eq 'Hello World' }
  }

  It 'Writes known style messages to the information stream' {
    Mock Write-Information {} -ModuleName Output
    Write-UiLine -Message 'Green text' -Style 'Success'
    Should -Invoke Write-Information -ModuleName Output -Times 1 -ParameterFilter { $MessageData -eq 'Green text' }
  }

  It 'Renders Debug style through the information stream' {
    Mock Write-Information {} -ModuleName Output
    Write-UiLine -Message 'Debug text' -Style 'Debug'
    Should -Invoke Write-Information -ModuleName Output -Times 1 -ParameterFilter { $MessageData -eq 'Debug text' }
  }

  It 'Suppresses output when Quiet switch is set' {
    Mock Write-Information {} -ModuleName Output
    Write-UiLine -Message 'Silent' -Quiet
    Should -Invoke Write-Information -ModuleName Output -Times 0
  }

  It 'Suppresses output when NoConsole switch is set' {
    Mock Write-Information {} -ModuleName Output
    Write-UiLine -Message 'No console' -NoConsole
    Should -Invoke Write-Information -ModuleName Output -Times 0
  }

  It 'Handles empty message without error' {
    Mock Write-Information {} -ModuleName Output
    { Write-UiLine -Message '' } | Should -Not -Throw
    Should -Invoke Write-Information -ModuleName Output -Times 1
  }

  It 'Uses Write-Information when UseWriteInformation is set' {
    Mock Write-Information {} -ModuleName Output
    Write-UiLine -Message 'Info stream' -UseWriteInformation
    Should -Invoke Write-Information -ModuleName Output -Times 1
  }

  It 'Writes plain text when NoColor is set' {
    Mock Write-Information {} -ModuleName Output
    Write-UiLine -Message 'Plain text' -Style 'Success' -NoColor
    Should -Invoke Write-Information -ModuleName Output -Times 1 -ParameterFilter { $MessageData -eq 'Plain text' }
  }
}

Describe 'Write-ConsoleLine' {
  It 'Delegates normal console lines through Write-UiLine behavior' {
    Mock Write-Information {} -ModuleName Output
    Write-ConsoleLine -Message 'Console text' -Style 'Success'
    Should -Invoke Write-Information -ModuleName Output -Times 1 -ParameterFilter { $MessageData -eq 'Console text' }
  }

  It 'Preserves ConsoleUseInformation config behavior' {
    Mock Write-Information {} -ModuleName Output

    Write-ConsoleLine -Message 'Info routed' -Config ([pscustomobject]@{ ConsoleUseInformation = $true })

    Should -Invoke Write-Information -ModuleName Output -Times 1 -ParameterFilter { $MessageData -eq 'Info routed' }
  }
}

Describe 'Write-KeyValue' {
  It 'Outputs key and value text' {
    Mock Write-Information {} -ModuleName Output
    { Write-KeyValue -Key 'Setting' -Value 'Enabled' } | Should -Not -Throw
    Should -Invoke Write-Information -ModuleName Output -Times 1
  }

  It 'Shows empty value text when value is null' {
    Mock Write-Information {} -ModuleName Output
    { Write-KeyValue -Key 'EmptyKey' -Value $null } | Should -Not -Throw
    Should -Invoke Write-Information -ModuleName Output -Times 1
  }

  It 'Handles custom indent' {
    Mock Write-Information {} -ModuleName Output
    { Write-KeyValue -Key 'Indented' -Value 'test' -Indent 4 } | Should -Not -Throw
  }
}

Describe 'Write-Section' {
  It 'Outputs section header with rule lines' {
    Mock Write-Information {} -ModuleName Output
    Write-Section -Title 'Test Section'
    # Should be called 3 times: top rule, title, bottom rule
    Should -Invoke Write-Information -ModuleName Output -Times 3
  }

  It 'Does not throw for any title' {
    Mock Write-Information {} -ModuleName Output
    { Write-Section -Title 'Any Title Here' } | Should -Not -Throw
  }
}

Describe 'Write-BlankLine' {
  It 'Outputs an empty line via Write-Information' {
    Mock Write-Information {} -ModuleName Output
    Write-BlankLine
    Should -Invoke Write-Information -ModuleName Output -Times 1
  }
}

Describe 'Legacy status writers' {
  BeforeEach {
    $script:StatusWriterCases = @(
      [pscustomobject]@{ Command = 'Write-Info';      Style = 'Info';    Text = '[INFO] Information text' }
      [pscustomobject]@{ Command = 'Write-Warn';      Style = 'Warn';    Text = '[WARN] Warning text' }
      [pscustomobject]@{ Command = 'Write-ErrorLine'; Style = 'Error';   Text = '[FAIL] Error text' }
      [pscustomobject]@{ Command = 'Write-Success';   Style = 'Success'; Text = '[OK]   Pass text' }
    )
  }

  It 'preserves exact status tokens and styles' {
    Mock Write-UiLine {} -ModuleName Output

    foreach ($case in $script:StatusWriterCases) {
      $message = $case.Text -replace '^\[[A-Z]+\]\s*', ''
      & $case.Command -Message $message
      Should -Invoke Write-UiLine -ModuleName Output -Times 1 -Exactly -ParameterFilter {
        $Message -ceq $case.Text -and $Style -ceq $case.Style
      }
    }
  }

  It 'preserves NoPrefix while retaining each style' {
    Mock Write-UiLine {} -ModuleName Output

    foreach ($case in $script:StatusWriterCases) {
      $message = 'Unprefixed message'
      & $case.Command -Message $message -NoPrefix
      Should -Invoke Write-UiLine -ModuleName Output -Times 1 -Exactly -ParameterFilter {
        $Message -ceq $message -and $Style -ceq $case.Style
      }
    }
  }

  It 'uses the information stream with Continue action' {
    Mock Write-Information {} -ModuleName Output

    foreach ($case in $script:StatusWriterCases) {
      $message = $case.Text -replace '^\[[A-Z]+\]\s*', ''
      & $case.Command -Message $message
      Should -Invoke Write-Information -ModuleName Output -Times 1 -Exactly -ParameterFilter {
        $MessageData -ceq $case.Text -and $InformationAction -eq 'Continue'
      }
    }
  }
}

Describe 'Status helper alignment' {
  It 'Delegates canonical prefix and rank decisions to Console' {
    InModuleScope Output {
      $cases = @(
        [pscustomobject]@{ Status = 'Pass'; Style = 'Success'; Prefix = '[OK]   ' }
        [pscustomobject]@{ Status = 'Warning'; Style = 'Warn'; Prefix = '[WARN] ' }
        [pscustomobject]@{ Status = 'Failed'; Style = 'Error'; Prefix = '[FAIL] ' }
        [pscustomobject]@{ Status = 'Error'; Style = 'Error'; Prefix = '[ERR]  ' }
        [pscustomobject]@{ Status = 'Critical'; Style = 'Error'; Prefix = '[CRIT] ' }
        [pscustomobject]@{ Status = 'Note'; Style = 'Info'; Prefix = '[INFO] ' }
        [pscustomobject]@{ Status = 'Skipped'; Style = 'Muted'; Prefix = '[SKIP] ' }
        [pscustomobject]@{ Status = 'Unknown'; Style = 'Info'; Prefix = '[INFO] ' }
      )

      foreach ($case in $cases) {
        Resolve-StatusStyle -Status $case.Status | Should -Be $case.Style
        Get-StatusPrefix -Status $case.Status | Should -Be $case.Prefix
        Get-StatusPrefix -Status $case.Status |
          Should -Be (Console\Get-SeverityPrefix -Severity $case.Status)
      }
    }
  }

  It 'Delegates severity colors while retaining non-severity UI roles' {
    InModuleScope Output {
      foreach ($status in @('Passed', 'Warning', 'Failed', 'Note', 'Skipped')) {
        Resolve-UiColor -Style $status |
          Should -Be ([ConsoleColor](Console\Get-StatusColor -Status $status))
      }

      Resolve-UiColor -Style 'Header' | Should -Be ([ConsoleColor]::Cyan)
      Resolve-UiColor -Style 'Accent' | Should -Be ([ConsoleColor]::White)
    }
  }
}

Describe 'Write-UiSummaryTable operator meaning' {
  It 'Renders total findings, severity counts, OK count, and fail result' {
    $findings = @(
      [pscustomobject]@{ Severity = 'Critical'; Code = 'CRIT-1'; Message = 'critical risk' }
      [pscustomobject]@{ Severity = 'High'; Code = 'HIGH-1'; Message = 'high risk' }
      [pscustomobject]@{ Severity = 'Failed'; Code = 'ERR-1'; Message = 'runtime failure' }
      [pscustomobject]@{ Severity = 'Medium'; Code = 'MED-1'; Message = 'partial risk' }
      [pscustomobject]@{ Severity = 'Low'; Code = 'LOW-1'; Message = 'low risk' }
      [pscustomobject]@{ Severity = 'Info'; Code = 'INFO-1'; Message = 'info' }
      [pscustomobject]@{ Severity = 'OK'; Code = 'OK-1'; Message = 'passed' }
    )

    $text = Join-TestOutputText -Output (Write-UiSummaryTable -Findings $findings 6>&1)

    $text | Should -Match 'Total findings\s*:\s*7'
    $text | Should -Match 'Critical\s*:\s*1'
    $text | Should -Match 'High\s*:\s*1'
    $text | Should -Match 'Error\s*:\s*1'
    $text | Should -Match 'Medium\s*:\s*1'
    $text | Should -Match 'Low\s*:\s*1'
    $text | Should -Match 'Info\s*:\s*1'
    $text | Should -Match 'OK\s*:\s*1'
    $text | Should -Match 'Overall result\s*:\s*FAIL'
  }

  It 'Renders skipped and partial state without hiding the warning result' {
    $findings = @(
      [pscustomobject]@{ Severity = 'Skipped'; Code = 'SKIP-1'; Message = 'not applicable' }
      [pscustomobject]@{ Severity = 'Warning'; Code = 'WARN-1'; Message = 'partial' }
    )

    $text = Join-TestOutputText -Output (Write-UiSummaryTable -Findings $findings 6>&1)

    $text | Should -Match 'Total findings\s*:\s*2'
    $text | Should -Match 'Skipped\s*:\s*1'
    $text | Should -Match 'Medium\s*:\s*1'
    $text | Should -Match 'Overall result\s*:\s*WARN'
  }
}
