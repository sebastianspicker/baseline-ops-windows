<#
.SYNOPSIS
  Verifies Serialization library contracts.
.DESCRIPTION
  Retains explicit contract cases and shared fixture setup for the library.
#>

BeforeAll {
  Import-Module (Join-Path $PSScriptRoot '../../lib/Serialization.psm1') -Force

  . (Join-Path $PSScriptRoot 'Serialization.Cases.ps1')
}

Describe 'Get-V2ResultObject' {
  It 'Creates required contract fields' { Test-SerializationCreatesRequiredContractFields }

  It 'Includes ComputerName and TimestampUtc' { Test-SerializationIncludesComputerNameAndTimestampUtc }

  It 'Stores Findings as array' { Test-SerializationStoresFindingsAsArray }

  It 'Rejects invalid Mode via ValidateSet' {
    { Get-V2ResultObject -ScriptName 'z.ps1' -Mode 'Invalid' -Result 'OK' -Findings @() -Summary @{} -Metadata @{} } | Should -Throw
  }

  It 'Rejects invalid Result via ValidateSet' {
    { Get-V2ResultObject -ScriptName 'z.ps1' -Mode 'Audit' -Result 'INVALID' -Findings @() -Summary @{} -Metadata @{} } | Should -Throw
  }
}

Describe 'Get-V2ExitCode' {
  It 'Maps <Result> to exit code <ExitCode>' -ForEach @(
    @{ Result = 'OK'; ExitCode = 0 }
    @{ Result = 'WARN'; ExitCode = 2 }
    @{ Result = 'FAIL'; ExitCode = 1 }
  ) {
    Get-V2ExitCode -Result $Result | Should -Be $ExitCode
  }

  It 'Rejects an unknown result token' {
    { Get-V2ExitCode -Result 'UNKNOWN' } | Should -Throw
  }
}

Describe 'Get-V2OutputConfigurationError' {
  It 'accepts non-file formats without an output path' -ForEach @('Console', 'None') {
    Get-V2OutputConfigurationError -OutputFormat $_ | Should -BeNullOrEmpty
  }

  It 'requires an output path for <_>' -ForEach @('Json', 'Csv') {
    Get-V2OutputConfigurationError -OutputFormat $_ | Should -Be "OutputPath is required when OutputFormat is $_."
  }

  It 'rejects traversal before serialization' {
    Get-V2OutputConfigurationError -OutputFormat Json -OutputPath '../escape.json' |
      Should -BeLike '*path traversal*'
  }

  It 'rejects a directory as a file output path' {
    Get-V2OutputConfigurationError -OutputFormat Json -OutputPath ([System.IO.Path]::GetTempPath()) |
      Should -BeLike '*not a directory*'
  }
}
