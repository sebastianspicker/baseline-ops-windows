<#
.SYNOPSIS
Internal browser and Office policy helpers for the hardening proof script.

.DESCRIPTION
Normalizes catalog input and applies narrowly scoped Edge, Firefox, and Office
policy operations. Keeping these helpers separate makes policy decisions
independently testable while the entry script retains orchestration ownership.
#>
function Get-EdgePolicyDefinitions {
  [CmdletBinding()]
  param([Parameter(Mandatory)][object]$EdgeCfg)

  $trackingPrevention = @{ 'Basic' = 1
    'Balanced' = 2
    'Strict' = 3
  }
  $trackingName = Get-TextOrNull $EdgeCfg.TrackingPrevention
  if (-not $trackingName) {
    $trackingName = 'Balanced'
  }
  $trackingValue = 2
  foreach ($name in $trackingPrevention.Keys) {
    if ($name -ieq $trackingName) {
      $trackingValue = $trackingPrevention[$name]
    }
  }

  $sslMinimum = Get-TextOrNull $EdgeCfg.SSLVersionMin
  if (-not $sslMinimum) {
    $sslMinimum = 'tls1.2'
  }

  @(
    Get-EdgeCorePolicyDefinitions -EdgeCfg $EdgeCfg
    [pscustomobject]@{ Area = 'Security'
      Policy = 'SSLVersionMin'
      Name = 'SSLVersionMin'
      Type = 'String'
      Value = $sslMinimum
    }
    [pscustomobject]@{ Area = 'Privacy'
      Policy = 'TrackingPrevention'
      Name = 'TrackingPrevention'
      Type = 'DWord'
      Value = $trackingValue
    }
  )
}

function Get-EdgeCorePolicyDefinitions {
  param($EdgeCfg)
  @(
    [pscustomobject]@{ Area = 'Core'
      Policy = 'SmartScreenEnabled'
      Name = 'SmartScreenEnabled'
      Type = 'DWord'
      Value = [int](Get-BoolDefault $EdgeCfg.SmartScreen $true)
    }
    [pscustomobject]@{ Area = 'Core'
      Policy = 'SmartScreenPuaEnabled'
      Name = 'SmartScreenPuaEnabled'
      Type = 'DWord'
      Value = [int](Get-BoolDefault $EdgeCfg.PUA $true)
    }
    [pscustomobject]@{ Area = 'Core'
      Policy = 'PasswordManagerEnabled'
      Name = 'PasswordManagerEnabled'
      Type = 'DWord'
      Value = [int](Get-BoolDefault $EdgeCfg.PasswordManager $false)
    }
    [pscustomobject]@{ Area = 'Core'
      Policy = 'AutofillAddressEnabled'
      Name = 'AutofillAddressEnabled'
      Type = 'DWord'
      Value = [int](Get-BoolDefault $EdgeCfg.AutofillAddress $false)
    }
    [pscustomobject]@{ Area = 'Core'
      Policy = 'AutofillCreditCardEnabled'
      Name = 'AutofillCreditCardEnabled'
      Type = 'DWord'
      Value = [int](Get-BoolDefault $EdgeCfg.AutofillCreditCard $false)
    }
    [pscustomobject]@{ Area = 'Core'
      Policy = 'SyncDisabled'
      Name = 'SyncDisabled'
      Type = 'DWord'
      Value = [int](Get-BoolDefault $EdgeCfg.SyncDisabled $true)
    }
  )
}
