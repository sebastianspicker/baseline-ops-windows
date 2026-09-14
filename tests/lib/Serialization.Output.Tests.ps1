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

Describe 'Write-ResultObject' {
  It 'Throws for Json without OutputPath' {
    $obj = Get-V2ResultObject -ScriptName 'x.ps1' -Mode 'Audit' -Result 'OK' -Findings @() -Summary @{} -Metadata @{}
    { Write-ResultObject -ResultObject $obj -OutputFormat Json } | Should -Throw
  }

  It 'Throws for Csv without OutputPath' {
    $obj = Get-V2ResultObject -ScriptName 'x.ps1' -Mode 'Audit' -Result 'OK' -Findings @() -Summary @{} -Metadata @{}
    { Write-ResultObject -ResultObject $obj -OutputFormat Csv } | Should -Throw
  }

  It 'Does not throw for None format' {
    $obj = Get-V2ResultObject -ScriptName 'x.ps1' -Mode 'Audit' -Result 'OK' -Findings @() -Summary @{} -Metadata @{}
    { Write-ResultObject -ResultObject $obj -OutputFormat None } | Should -Not -Throw
  }

  It 'Does not throw for Console format' {
    $obj = Get-V2ResultObject -ScriptName 'x.ps1' -Mode 'Audit' -Result 'OK' -Findings @() -Summary @{} -Metadata @{}
    { Write-ResultObject -ResultObject $obj -OutputFormat Console } | Should -Not -Throw
  }

  It 'Treats Console and None formats as intentional no-ops' { Test-SerializationTreatsConsoleAndNoneFormatsAsIntentionalNoOps }

  It 'Writes JSON file when OutputPath is provided' { Test-SerializationWritesJSONFileWhenOutputPathIsProvided }

  It 'Writes CSV file when OutputPath is provided' { Test-SerializationWritesCSVFileWhenOutputPathIsProvided }
}
