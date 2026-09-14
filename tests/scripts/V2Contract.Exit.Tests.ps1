#requires -version 5.1
<#
.SYNOPSIS
  Verifies public v2 script contracts.
.DESCRIPTION
  Retains parameter, result, and process-exit assertions for public scripts.
#>

BeforeAll { . (Join-Path $PSScriptRoot 'V2Contract.Cases.ps1') }

Describe 'numbered script v2 process-exit contract' {
  $v2ExitCases = @(
    Get-ChildItem -LiteralPath (Join-Path $PSScriptRoot '../../scripts') -Filter '*.ps1' -File |
      Where-Object { $_.Name -match '^(?:0[1-9]|[1-4][0-9]|5[0-2])-' } |
      Sort-Object Name |
      ForEach-Object {
        [pscustomobject]@{
          Name = $_.Name
          Path = $_.FullName
        }
      }
  )

  It '<_.Name> maps its final v2 result token to the standard exit code' -ForEach $v2ExitCases { Test-V2NameMapsItsFinalV2ResultTokenToTheStandardExitCode }

  It '<_.Name> does not bypass v2 output on an early top-level exit' -ForEach $v2ExitCases { Test-V2NameDoesNotBypassV2OutputOnAnEarlyTopLevelExit }

  It '<_.Name> does not bypass terminal v2 output with a top-level return' -ForEach $v2ExitCases { Test-V2NameDoesNotBypassTerminalV2OutputWithATopLevelReturn }
}
