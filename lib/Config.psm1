Set-StrictMode -Version Latest

function ConvertTo-Hashtable {
  [CmdletBinding()]
  param([object]$Object)

  if ($null -eq $Object) { return @{} }
  if ($Object -is [hashtable]) { return $Object }

  $ht = @{}
  foreach ($p in $Object.PSObject.Properties) {
    $ht[$p.Name] = $p.Value
  }
  return $ht
}

function Read-ConfigWithDefaults {
  [CmdletBinding()]
  param(
    [AllowNull()][string]$Path,
    [hashtable]$Defaults = @{},
    [switch]$AsHashtable,
    [switch]$ReturnNullWhenMissing,
    [switch]$ReturnNullOnError,
    [scriptblock]$OnWarning
  )

  $meta = [pscustomobject]@{
    Path               = $Path
    Provided           = [bool]$Path
    Loaded             = $false
    UsedDefaults       = $true
    UsedDefaultsBecause= $null
    Error              = $null
  }

  $config = @{}
  foreach ($k in $Defaults.Keys) { $config[$k] = $Defaults[$k] }

  if ([string]::IsNullOrWhiteSpace($Path)) {
    $meta.UsedDefaultsBecause = 'No ConfigPath provided.'
    if ($ReturnNullWhenMissing) {
      return [pscustomobject]@{ Config = $null; Meta = $meta }
    }
    return [pscustomobject]@{ Config = (if ($AsHashtable) { $config } else { [pscustomobject]$config }); Meta = $meta }
  }

  if (-not (Test-Path -LiteralPath $Path)) {
    $meta.Error = 'ConfigPath not found.'
    $meta.UsedDefaultsBecause = $meta.Error
    if ($OnWarning) { & $OnWarning ($meta.Error + ' Using defaults.') }
    if ($ReturnNullWhenMissing -or $ReturnNullOnError) {
      return [pscustomobject]@{ Config = $null; Meta = $meta }
    }
    return [pscustomobject]@{ Config = (if ($AsHashtable) { $config } else { [pscustomobject]$config }); Meta = $meta }
  }

  try {
    $raw = Get-Content -LiteralPath $Path -Raw -ErrorAction Stop
    if ([string]::IsNullOrWhiteSpace($raw)) {
      $meta.Error = 'Config file is empty.'
      $meta.UsedDefaultsBecause = $meta.Error
      if ($OnWarning) { & $OnWarning ($meta.Error + ' Using defaults.') }
      if ($ReturnNullOnError) {
        return [pscustomobject]@{ Config = $null; Meta = $meta }
      }
      return [pscustomobject]@{ Config = (if ($AsHashtable) { $config } else { [pscustomobject]$config }); Meta = $meta }
    }

    $obj = $raw | ConvertFrom-Json -ErrorAction Stop
    if ($null -eq $obj) {
      $meta.Error = 'Config file invalid/unreadable JSON.'
      $meta.UsedDefaultsBecause = $meta.Error
      if ($OnWarning) { & $OnWarning ($meta.Error + ' Using defaults.') }
      if ($ReturnNullOnError) {
        return [pscustomobject]@{ Config = $null; Meta = $meta }
      }
      return [pscustomobject]@{ Config = (if ($AsHashtable) { $config } else { [pscustomobject]$config }); Meta = $meta }
    }

    $meta.Loaded = $true
    $meta.UsedDefaults = $false
    $meta.UsedDefaultsBecause = $null

    $objHash = ConvertTo-Hashtable -Object $obj
    foreach ($k in $objHash.Keys) { $config[$k] = $objHash[$k] }

    return [pscustomobject]@{ Config = (if ($AsHashtable) { $config } else { [pscustomobject]$config }); Meta = $meta }
  } catch {
    $meta.Error = $_.Exception.Message
    $meta.UsedDefaultsBecause = 'Config parse failed.'
    if ($OnWarning) { & $OnWarning ('Config parse failed, using defaults: PATH/TO/JSON') }
    if ($ReturnNullOnError) {
      return [pscustomobject]@{ Config = $null; Meta = $meta }
    }
    return [pscustomobject]@{ Config = (if ($AsHashtable) { $config } else { [pscustomobject]$config }); Meta = $meta }
  }
}

Export-ModuleMember -Function ConvertTo-Hashtable,Read-ConfigWithDefaults
