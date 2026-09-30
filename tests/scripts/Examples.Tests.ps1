#requires -version 5.1
<#
.SYNOPSIS
Characterizes the shipped examples/profiles and examples/configs files.
.DESCRIPTION
Pins the exact validator exit code, declared mode, and step count of every
reviewed example profile, and the bounded-JSON shape and top-level keys of every
example capability input documented in examples/README.md.
#>

BeforeDiscovery {
  . (Join-Path $PSScriptRoot 'Examples.Cases.ps1')
  $script:profileCases = Get-ExampleProfileCases
  $script:configCases = Get-ExampleConfigCases
}

BeforeAll {
  $script:root = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
  . (Join-Path $PSScriptRoot 'Examples.Cases.ps1')
  Import-Module (Join-Path $script:root 'lib/JsonInput.psm1') -Force
}

Describe 'example inventory' {
  It 'ships exactly the seven documented profiles' { Test-ExampleShipsExactlyTheSevenDocumentedProfiles }

  It 'ships exactly the four documented capability inputs' { Test-ExampleShipsExactlyTheFourDocumentedCapabilityInputs }

  It 'lists every example file in examples/README.md' { Test-ExampleReadmeListsEveryExampleFile }
}

Describe 'example profiles' {
  It '<File> validates with exit code 0 and no findings' -ForEach $script:profileCases {
    Test-ExampleProfileValidatesCleanly -File $File
  }

  It '<File> declares Version 2.0, Defaults.Mode <Mode> and <Steps> steps without Args' -ForEach $script:profileCases {
    Test-ExampleProfileDeclaresModeAndSteps -File $File -Mode $Mode -Steps $Steps
  }

  It '<File> has the profile v2 top-level shape' -ForEach $script:profileCases {
    Test-ExampleProfileHasV2TopLevelShape -File $File
  }
}

Describe 'example capability inputs' {
  It '<File> parses as bounded JSON with top-level keys <Keys>' -ForEach $script:configCases {
    Test-ExampleConfigParsesAsBoundedJson -File $File -Keys $Keys
  }

  It 'rejects an oversized file through the bounded reader' { Test-ExampleBoundedReaderRejectsOversizedFile }
}
