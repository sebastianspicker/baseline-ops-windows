#requires -version 5.1

$script:LibPath = Join-Path $PSScriptRoot '../lib'
Import-Module (Join-Path $script:LibPath 'Common.psm1') -Force -DisableNameChecking
Import-Module (Join-Path $script:LibPath 'Config.psm1') -Force

function Test-Check {
    param([bool]$Condition, [string]$Message)
    if ($Condition) {
        Write-Information -MessageData "[OK] $Message" -InformationAction Continue
    } else {
        Write-Information -MessageData "[FAIL] $Message" -InformationAction Continue
        $script:ExitCode = 1
    }
}

$script:ExitCode = 0

Write-Information -MessageData "--- Testing Sanitize-Path ---" -InformationAction Continue
# Use current directory for portable test
$curr = (Get-Location).Path
$p1 = Sanitize-Path -Path $curr
Test-Check ($null -ne $p1) "Basic path normalization ($curr)"

$p3 = Sanitize-Path -Path '../../Windows/System32'
Test-Check ($null -eq $p3) "Path traversal detection (..)"

Write-Information -MessageData "`n--- Testing Read-ConfigWithDefaults ---" -InformationAction Continue
$tempFile = Join-Path $PSScriptRoot "test_config.json"
$cfgJson = @'
{
    "TestKey": "TestValue",
    "Nested": { "Sub": 123 }
}
'@
$cfgJson | Out-File -FilePath $tempFile -Encoding UTF8

$res = Read-ConfigWithDefaults -Path $tempFile -Defaults @{ "DefaultKey" = "DefaultValue"; "TestKey" = "ShouldOverride" }
if ($null -eq $res -or $null -eq $res.Config) {
    Test-Check $false "Read-ConfigWithDefaults failed to return config object. Meta Error: $($res.Meta.Error)"
} else {
    Test-Check ($res.Config.TestKey -eq 'TestValue') "Override default value"
    Test-Check ($res.Config.DefaultKey -eq 'DefaultValue') "Keep default value"
    Test-Check ($res.Meta.Loaded -eq $true) "Meta: Loaded is true"
}

if (Test-Path $tempFile) { Remove-Item $tempFile }

Write-Information -MessageData "`n--- Testing ConvertTo-Hashtable ---" -InformationAction Continue
$obj = [pscustomobject]@{ A = 1; B = 2 }
$ht = ConvertTo-Hashtable -Object $obj
Test-Check ($ht -is [hashtable]) "Object to hashtable conversion"
Test-Check ($ht.A -eq 1) "Hashtable key A"
Test-Check ($ht.B -eq 2) "Hashtable key B"

if ($script:ExitCode -ne 0) {
    Write-Error "Verification tests failed."
    exit 1
} else {
    Write-Information -MessageData "`nAll verification tests passed!" -InformationAction Continue
}
