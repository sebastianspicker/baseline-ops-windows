#requires -version 5.1
<#
.SYNOPSIS
  Provides private artifact collection phases.
.DESCRIPTION
  Preserves protected evidence paths, bounded observations, trigger decisions, and artifact proof ordering within this capability.
#>


function Try-CollectNetworkNetCmdlets {
  param([string]$outDir, [ref]$counts, [ref]$note)

  $note.Value = $null
  try {
    $tcp = Get-NetTCPConnection | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess
    $tcp | Export-Csv -NoTypeInformation -Encoding UTF8 -Path (Join-Path $outDir 'net_tcp.csv')

    $listen = $tcp | Where-Object { $_.State -eq 'Listen' }
    $listen | Export-Csv -NoTypeInformation -Encoding UTF8 -Path (Join-Path $outDir 'net_tcp_listen.csv')

    $counts.Value.Tcp = @($tcp).Count
    $counts.Value.Listeners = @($listen).Count

    try {
      $udp = Get-NetUDPEndpoint | Select-Object LocalAddress, LocalPort, OwningProcess
      $udp | Export-Csv -NoTypeInformation -Encoding UTF8 -Path (Join-Path $outDir 'net_udp.csv')
      $counts.Value.Udp = @($udp).Count
    }
    catch {
      $counts.Value.Udp = 0
      $note.Value = "UDP cmdlet unavailable: " + $_.Exception.Message
    }

    try {
      Get-NetIPConfiguration | Export-Csv -NoTypeInformation -Encoding UTF8 -Path (Join-Path $outDir 'net_ipconfig.csv')
    }
    catch {
      $note.Value = "IP configuration export unavailable: " + $_.Exception.Message
    }
    try {
      Get-NetRoute | Select-Object ifIndex, DestinationPrefix, NextHop, RouteMetric, PolicyStore |
        Export-Csv -NoTypeInformation -Encoding UTF8 -Path (Join-Path $outDir 'net_routes.csv')
    }
    catch {
      $note.Value = "Route export unavailable: " + $_.Exception.Message
    }
    try {
      Get-DnsClientCache | Export-Csv -NoTypeInformation -Encoding UTF8 -Path (Join-Path $outDir 'dns_cache.csv')
    }
    catch {
      $note.Value = "DNS cache export unavailable: " + $_.Exception.Message
    }

    return $true
  }
  catch {
    $note.Value = "NetTCPConnection unavailable: " + $_.Exception.Message
    return $false
  }
}
function Collect-NetworkNetstatFallback {
  param([string]$outDir, [ref]$counts, [ref]$note)

  $note.Value = "Using netstat fallback"
  $counts.Value.Tcp = 0
  $counts.Value.Listeners = 0
  $counts.Value.Udp = 0

  try {
    $native = Invoke-NativeCommand -Command 'netstat.exe' -Arguments @('-ano') -CaptureOutput -Quiet -TimeoutSeconds 30 -MaxOutputBytes 1048576
    Assert-ArtifactNetstatResult -Native $native
    $raw = $native.Stdout -split "`r?`n"
    $rows = foreach ($line in @($raw)) {
      Convert-ArtifactNetstatRow -Line $line
    }

    $rows | Export-Csv -NoTypeInformation -Encoding UTF8 -Path (Join-Path $outDir 'net_netstat_ano.csv')

    $tcp = @($rows | Where-Object { $_.Protocol -eq 'TCP' })
    $udp = @($rows | Where-Object { $_.Protocol -eq 'UDP' })
    $lst = @($tcp | Where-Object { $_.State -eq 'LISTENING' })

    $counts.Value.Tcp = $tcp.Count
    $counts.Value.Udp = $udp.Count
    $counts.Value.Listeners = $lst.Count

    return $true
  }
  catch {
    $note.Value = "netstat fallback failed: " + $_.Exception.Message
    return $false
  }
}
function Convert-ArtifactNetstatRow {
  param($Line)
  $t = ($line -as [string]).Trim()
  if (-not $t) {
    return
  }
  if ($t -match '^(TCP|UDP)\s+') {
    $parts = $t -split '\s+'
    if ($parts.Count -lt 4) {
      return
    }

    $proto = $parts[0]
    $local = $parts[1]
    $remote = $parts[2]

    $state = $null
    $processId = $null

    if ($proto -eq 'TCP') {
      if ($parts.Count -ge 5) {
        $state = $parts[3]
        $processId = $parts[4]
      }
    }
    else {
      $processId = $parts[3]
    }

    $localEndpoint = Convert-ArtifactNetworkEndpoint -Text $local
    $remoteEndpoint = Convert-ArtifactNetworkEndpoint -Text $remote
    [pscustomobject]@{
      Protocol = $proto
      LocalAddress = $localEndpoint.Address
      LocalPort = $localEndpoint.Port
      RemoteAddress = $remoteEndpoint.Address
      RemotePort = $remoteEndpoint.Port
      State = $state
      OwningProcess = $processId
    }
  }

}

function Convert-ArtifactNetworkEndpoint {
  param([string]$Text)
  $address = $Text
  $port = $null
  if ($Text -match '^(.*):(\d+)$') {
    $address = $matches[1]
    $port = [int]$matches[2]
  }
  return @{Address = $address
    Port = $port
  }
}

function Collect-Network {
  param([string]$outDir)

  $res = Get-ResultObject 'Network'
  try {
    [void](Ensure-Directory $outDir)

    $counts = [ref](@{ Tcp = 0
        Listeners = 0
        Udp = 0
      })
    $note = [ref]$null

    $okNet = Try-CollectNetworkNetCmdlets -outDir $outDir -counts $counts -note $note
    if (-not $okNet) {
      $okNet = Collect-NetworkNetstatFallback -outDir $outDir -counts $counts -note $note
    }

    $res.Counts = $counts.Value
    if ($note.Value) {
      Add-Note $res $note.Value
    }

    if (-not $okNet) {
      Add-Error $res "network: no usable collection method"
    }
  }
  catch {
    Add-Error $res ("network: " + $_.Exception.Message)
    $res.Counts = @{ Tcp = 0
      Listeners = 0
      Udp = 0
    }
  }

  return $res
}

function Assert-ArtifactNetstatResult {
  param($Native)
  if ($null -eq $native -or -not $native.Success -or $native.TimedOut -or $native.OutputTruncated -or $native.StderrTruncated) {
    throw 'netstat fallback timed out, failed, or produced truncated output.'
  }
}
