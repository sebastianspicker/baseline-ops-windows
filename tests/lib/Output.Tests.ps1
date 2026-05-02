#requires -version 5.1
<#
.SYNOPSIS
Pester tests for Output.psm1 module

.DESCRIPTION
Unit tests for the Output module. Tests core functions Write-UiLine,
Write-KeyValue, Write-Section, and Write-BlankLine.
Uses Mock Write-Host to capture output for assertions.
#>

[CmdletBinding()]
param()

BeforeAll {
  Import-Module (Join-Path $PSScriptRoot '../../lib/Output.psm1') -Force
}

Describe 'Output module export surface' {
  It 'Does not export removed decorative console wrappers' {
    $removed = @('Write-Rule', 'Write-ConsoleRule', 'Write-ConsoleSeparator', 'Write-Title', 'Write-Good', 'Write-Bad')
    $names = Get-Command -Module Output | Select-Object -ExpandProperty Name

    foreach ($name in $removed) {
      $names | Should -Not -Contain $name
    }
  }
}

Describe 'Write-UiLine' {
  It 'Calls Write-Host with the provided message' {
    Mock Write-Host {} -ModuleName Output
    Write-UiLine -Message 'Hello World'
    Should -Invoke Write-Host -ModuleName Output -Times 1 -ParameterFilter { $Object -eq 'Hello World' }
  }

  It 'Calls Write-Host with foreground color for known style' {
    Mock Write-Host {} -ModuleName Output
    Write-UiLine -Message 'Green text' -Style 'Success'
    Should -Invoke Write-Host -ModuleName Output -Times 1 -ParameterFilter { $ForegroundColor -eq [ConsoleColor]::Green }
  }

  It 'Suppresses output when Quiet switch is set' {
    Mock Write-Host {} -ModuleName Output
    Write-UiLine -Message 'Silent' -Quiet
    Should -Invoke Write-Host -ModuleName Output -Times 0
  }

  It 'Suppresses output when NoConsole switch is set' {
    Mock Write-Host {} -ModuleName Output
    Write-UiLine -Message 'No console' -NoConsole
    Should -Invoke Write-Host -ModuleName Output -Times 0
  }

  It 'Handles empty message without error' {
    Mock Write-Host {} -ModuleName Output
    { Write-UiLine -Message '' } | Should -Not -Throw
    Should -Invoke Write-Host -ModuleName Output -Times 1
  }

  It 'Uses Write-Information when UseWriteInformation is set' {
    Mock Write-Host {} -ModuleName Output
    Mock Write-Information {} -ModuleName Output
    Write-UiLine -Message 'Info stream' -UseWriteInformation
    Should -Invoke Write-Information -ModuleName Output -Times 1
  }

  It 'Does not apply color when NoColor is set' {
    Mock Write-Host {} -ModuleName Output
    Write-UiLine -Message 'Plain text' -Style 'Success' -NoColor
    # When NoColor is set, Write-Host should be called without ForegroundColor
    Should -Invoke Write-Host -ModuleName Output -Times 1 -ParameterFilter { $null -eq $ForegroundColor }
  }
}

Describe 'Write-KeyValue' {
  It 'Outputs key and value text' {
    Mock Write-Host {} -ModuleName Output
    { Write-KeyValue -Key 'Setting' -Value 'Enabled' } | Should -Not -Throw
    Should -Invoke Write-Host -ModuleName Output -Times 2  # key part + value part (two calls with NoNewLine pattern)
  }

  It 'Shows empty value text when value is null' {
    Mock Write-Host {} -ModuleName Output
    { Write-KeyValue -Key 'EmptyKey' -Value $null } | Should -Not -Throw
    Should -Invoke Write-Host -ModuleName Output -Times 2
  }

  It 'Handles custom indent' {
    Mock Write-Host {} -ModuleName Output
    { Write-KeyValue -Key 'Indented' -Value 'test' -Indent 4 } | Should -Not -Throw
  }
}

Describe 'Write-Section' {
  It 'Outputs section header with rule lines' {
    Mock Write-Host {} -ModuleName Output
    Write-Section -Title 'Test Section'
    # Should be called 3 times: top rule, title, bottom rule
    Should -Invoke Write-Host -ModuleName Output -Times 3
  }

  It 'Does not throw for any title' {
    Mock Write-Host {} -ModuleName Output
    { Write-Section -Title 'Any Title Here' } | Should -Not -Throw
  }
}

Describe 'Write-BlankLine' {
  It 'Outputs an empty line via Write-Host' {
    Mock Write-Host {} -ModuleName Output
    Write-BlankLine
    Should -Invoke Write-Host -ModuleName Output -Times 1
  }
}

Describe 'Write-Info' {
  It 'Outputs info-prefixed message' {
    Mock Write-Host {} -ModuleName Output
    Write-Info -Message 'Information text'
    Should -Invoke Write-Host -ModuleName Output -Times 1 -ParameterFilter { $Object -match 'INFO.*Information text' }
  }
}

Describe 'Write-Warn' {
  It 'Outputs warn-prefixed message' {
    Mock Write-Host {} -ModuleName Output
    Write-Warn -Message 'Warning text'
    Should -Invoke Write-Host -ModuleName Output -Times 1 -ParameterFilter { $Object -match 'WARN.*Warning text' }
  }
}

Describe 'Write-ErrorLine' {
  It 'Outputs fail-prefixed message' {
    Mock Write-Host {} -ModuleName Output
    Write-ErrorLine -Message 'Error text'
    Should -Invoke Write-Host -ModuleName Output -Times 1 -ParameterFilter { $Object -match 'FAIL.*Error text' }
  }
}

Describe 'Write-Success' {
  It 'Outputs ok-prefixed message' {
    Mock Write-Host {} -ModuleName Output
    Write-Success -Message 'Pass text'
    Should -Invoke Write-Host -ModuleName Output -Times 1 -ParameterFilter { $Object -match 'OK.*Pass text' }
  }
}
