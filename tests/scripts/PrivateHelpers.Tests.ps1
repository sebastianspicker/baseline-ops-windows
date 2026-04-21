#requires -version 5.1
<#
.SYNOPSIS
  Pester tests for scripts/private/ helper files.

.DESCRIPTION
  Dot-sources each helper file and validates that all exported functions are
  callable and return expected types. Tests focus on pure/stateless helpers
  with no external OS dependencies.
#>

[CmdletBinding()]
param()

# ---------------------------------------------------------------------------
# 04 - OfficeBrowser helpers
# ---------------------------------------------------------------------------
Describe '04 OfficeBrowser helpers' {
  BeforeAll {
    $helperPath = Join-Path $PSScriptRoot '../../scripts/private/04-OfficeBrowser-Hardening-Proof.helpers.ps1'
    . $helperPath
  }

  Context 'Get-TextOrNull' {
    It 'returns null for null input' {
      Get-TextOrNull -Value $null | Should -BeNullOrEmpty
    }

    It 'returns null for empty string' {
      Get-TextOrNull -Value '' | Should -BeNullOrEmpty
    }

    It 'returns null for whitespace-only string' {
      Get-TextOrNull -Value '   ' | Should -BeNullOrEmpty
    }

    It 'returns the string for non-empty input' {
      Get-TextOrNull -Value 'hello' | Should -Be 'hello'
    }
  }

  Context 'Get-BoolDefault' {
    It 'returns default when value is null' {
      Get-BoolDefault -Value $null -Default $true | Should -Be $true
      Get-BoolDefault -Value $null -Default $false | Should -Be $false
    }

    It 'converts truthy value to true' {
      Get-BoolDefault -Value $true -Default $false | Should -Be $true
    }

    It 'converts falsy value to false' {
      Get-BoolDefault -Value $false -Default $true | Should -Be $false
    }
  }

  Context 'Get-IntDefault' {
    It 'returns default when value is null' {
      Get-IntDefault -Value $null -Default 42 | Should -Be 42
    }

    It 'converts numeric value' {
      Get-IntDefault -Value 7 -Default 0 | Should -Be 7
    }
  }

  Context 'Get-ArrayStrings' {
    It 'returns empty array for null' {
      $result = @(Get-ArrayStrings -Value $null)
      $result.Count | Should -Be 0
    }

    It 'returns string array for array input' {
      $result = Get-ArrayStrings -Value @('a', 'b')
      $result.Count | Should -Be 2
    }
  }

  Context 'New-ProofItem' {
    It 'returns a PSCustomObject' {
      $item = New-ProofItem -Product 'Office' -Area 'Macro' -Policy 'BlockVBA' `
        -Target 'HKLM:\...' -Name 'BlockMacros' -Type 'DWord' -Expected 1 -Actual 1 -Compliant $true
      $item | Should -Not -BeNullOrEmpty
      $item.PSObject.TypeNames | Should -Contain 'System.Management.Automation.PSCustomObject'
    }

    It 'carries the Name field' {
      $item = New-ProofItem -Product 'Edge' -Area 'Security' -Policy 'SmartScreen' `
        -Target 'HKLM:\...' -Name 'SmartScreenEnabled' -Type 'DWord' -Expected 1 -Actual 1 -Compliant $true
      $item.Name | Should -Be 'SmartScreenEnabled'
    }
  }

  Context 'New-ResultSummary' {
    It 'returns a PSCustomObject with Section and Ok fields' {
      $item = New-ProofItem -Product 'Edge' -Area 'Security' -Policy 'SmartScreen' `
        -Target 'HKLM:\...' -Name 'SmartScreenEnabled' -Type 'DWord' -Expected 1 -Actual 1 -Compliant $true
      $s = New-ResultSummary -Section 'Edge' -Items @($item)
      $s | Should -Not -BeNullOrEmpty
      $s.Section | Should -Be 'Edge'
    }
  }

  Context 'functions are dot-sourceable and defined' {
    It 'exports all expected function names' {
      $expected = @(
        'Get-TextOrNull', 'Get-BoolDefault', 'Get-IntDefault', 'Get-ArrayStrings',
        'Convert-RegValue', 'New-ProofItem', 'Get-EdgeBaseKey', 'Has-Prop',
        'Bool-Prop', 'Ensure-ProofItemLike', 'New-ResultSummary', 'Load-Catalog'
      )
      foreach ($fn in $expected) {
        Get-Command -Name $fn -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty -Because "$fn must be defined after dot-sourcing"
      }
    }
  }
}

# ---------------------------------------------------------------------------
# 09 - SupportBundle helpers
# ---------------------------------------------------------------------------
Describe '09 SupportBundle helpers' {
  BeforeAll {
    $helperPath = Join-Path $PSScriptRoot '../../scripts/private/09-SupportBundle.helpers.ps1'
    . $helperPath
  }

  Context 'SB_SafeFileName' {
    It 'replaces path-unsafe characters' {
      $result = SB_SafeFileName -Name 'file<>:"/\\|?*.txt'
      $result | Should -Not -Match '[<>:"/\\|?*]'
    }

    It 'leaves safe names unchanged' {
      SB_SafeFileName -Name 'safe-name_123.txt' | Should -Be 'safe-name_123.txt'
    }
  }

  Context 'SB_IsAdmin' {
    It 'returns a boolean' {
      $r = SB_IsAdmin
      $r | Should -BeOfType [bool]
    }
  }

  Context 'SB_NewRecord' {
    It 'creates a record with Name, Ok, ArtifactPath properties' {
      $rec = SB_NewRecord -Name 'TestRecord' -Ok $true -ArtifactPath 'C:\test.log' -Note ''
      $rec.Name | Should -Be 'TestRecord'
      $rec.Ok   | Should -Be $true
    }

    It 'creates a failed record' {
      $rec = SB_NewRecord -Name 'FailRecord' -Ok $false -ArtifactPath '' -Note 'something failed'
      $rec.Ok | Should -Be $false
    }
  }

  Context 'SB_NewDefaultConfig' {
    It 'returns a config object with Paths.ProofDir set' {
      $cfg = SB_NewDefaultConfig -ProofDirDefault 'C:\Temp\Proof'
      $cfg | Should -Not -BeNullOrEmpty
      $cfg.Paths.ProofDir | Should -Be 'C:\Temp\Proof'
    }
  }

  Context 'functions are dot-sourceable and defined' {
    It 'exports all expected function names' {
      $expected = @(
        'SB_WriteUi', 'SB_WriteLog', 'SB_SafeFileName', 'SB_NewRecord',
        'SB_NewSummary', 'SB_AddRecord', 'SB_IsAdmin', 'SB_NewDefaultConfig',
        'SB_TryStep', 'SB_LoadJsonConfig', 'SB_TryGetRegValue'
      )
      foreach ($fn in $expected) {
        Get-Command -Name $fn -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty -Because "$fn must be defined after dot-sourcing"
      }
    }
  }
}

# ---------------------------------------------------------------------------
# 12 - SuspiciousArtifactGrabber helpers
# ---------------------------------------------------------------------------
Describe '12 SuspiciousArtifactGrabber helpers' {
  BeforeAll {
    $helperPath = Join-Path $PSScriptRoot '../../scripts/private/12-Suspicious-Artifact-Grabber.helpers.ps1'
    . $helperPath
  }

  Context 'Safe-ToInt' {
    It 'returns default for null' {
      Safe-ToInt -Value $null -Default 5 | Should -Be 5
    }

    It 'converts integer string' {
      Safe-ToInt -Value '42' -Default 0 | Should -Be 42
    }

    It 'returns default for unconvertible value' {
      Safe-ToInt -Value 'not-a-number' -Default 99 | Should -Be 99
    }
  }

  Context 'Safe-ToBool' {
    It 'returns default for null' {
      Safe-ToBool -Value $null -Default $true | Should -Be $true
    }

    It 'converts true value' {
      Safe-ToBool -Value $true -Default $false | Should -Be $true
    }
  }

  Context 'New-ResultObject' {
    It 'creates object with correct Name' {
      $obj = New-ResultObject -Name 'TestScan'
      $obj.Name | Should -Be 'TestScan'
    }

    It 'initializes Errors and Notes as empty lists' {
      $obj = New-ResultObject -Name 'X'
      $obj.Errors.Count | Should -Be 0
      $obj.Notes.Count  | Should -Be 0
    }
  }

  Context 'Add-Error / Add-Note' {
    It 'appends an error message' {
      $obj = New-ResultObject -Name 'X'
      Add-Error -res $obj -msg 'something broke'
      $obj.Errors.Count | Should -Be 1
      $obj.Errors[0]    | Should -Be 'something broke'
    }

    It 'appends a note message' {
      $obj = New-ResultObject -Name 'X'
      Add-Note -res $obj -msg 'a note'
      $obj.Notes.Count | Should -Be 1
    }

    It 'ignores null/empty error message' {
      $obj = New-ResultObject -Name 'X'
      Add-Error -res $obj -msg $null
      Add-Error -res $obj -msg ''
      $obj.Errors.Count | Should -Be 0
    }
  }

  Context 'New-RunId' {
    It 'returns a non-empty string in yyyyMMdd-HHmmss format' {
      $id = New-RunId
      $id | Should -Match '^\d{8}-\d{6}$'
    }
  }

  Context 'New-BaseClone' {
    It 'returns a deep copy of the object' {
      $orig = [pscustomobject]@{ Foo = 'bar'; Nested = @{ X = 1 } }
      $clone = New-BaseClone -Obj $orig
      $clone.Foo    | Should -Be 'bar'
      $clone.Nested.X | Should -Be 1
    }
  }

  Context 'functions are dot-sourceable and defined' {
    It 'exports all expected function names' {
      $expected = @(
        'New-ResultObject', 'Add-Error', 'Add-Note', 'Safe-ToInt', 'Safe-ToBool',
        'New-RunId', 'New-BaseClone', 'Merge-Catalog', 'Load-Catalog',
        'Read-Trigger', 'Collect-Processes'
      )
      foreach ($fn in $expected) {
        Get-Command -Name $fn -ErrorAction SilentlyContinue | Should -Not -BeNullOrEmpty -Because "$fn must be defined after dot-sourcing"
      }
    }
  }
}
