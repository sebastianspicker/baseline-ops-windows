<#
.SYNOPSIS
  Provides shared assertions for captured PowerShell test output.
.DESCRIPTION
  Normalizes captured output records into text so tests can assert messages
  consistently across direct strings and structured information records.
#>

  function Join-TestOutputText {
    param([object[]]$Output)

    ($Output | ForEach-Object {
      if ($_.PSObject.Properties['MessageData']) {
        if ($_.MessageData.PSObject.Properties['Message']) {
          [string]$_.MessageData.Message
        } else {
          [string]$_.MessageData
        }
      } else {
        [string]$_
      }
    }) -join "`n"
  }
