#requires -version 5.1

Describe 'v2 parameter contract' {
  $scriptFiles = Get-ChildItem -LiteralPath (Join-Path $PSScriptRoot '../../scripts') -Filter '*.ps1' -File |
    Where-Object { $_.Name -match '^\d{2}-' }
  $cases = @($scriptFiles | ForEach-Object { [pscustomobject]@{ Name = $_.Name; FullName = $_.FullName } })

  $requiredParams = @(
    'Mode',
    'ConfigPath',
    'OutputFormat',
    'OutputPath',
    'PassThru',
    'Strict',
    'Quiet',
    'NoColor'
  )

  It '<_.Name> exposes required v2 params' -ForEach $cases {
    $file = $_
    $errors = $null
    $tokens = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($file.FullName, [ref]$tokens, [ref]$errors)
    $errors | Should -BeNullOrEmpty
    $ast.ParamBlock | Should -Not -BeNullOrEmpty

    $paramNames = @($ast.ParamBlock.Parameters | ForEach-Object { $_.Name.VariablePath.UserPath })
    foreach ($required in $requiredParams) {
      ($paramNames -contains $required) | Should -BeTrue
    }
  }

  It '<_.Name> does not expose legacy Remediate parameter' -ForEach $cases {
    $file = $_
    $errors = $null
    $tokens = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($file.FullName, [ref]$tokens, [ref]$errors)
    $errors | Should -BeNullOrEmpty
    $paramNames = @($ast.ParamBlock.Parameters | ForEach-Object { $_.Name.VariablePath.UserPath })
    ($paramNames -contains 'Remediate') | Should -BeFalse
  }

  It '<_.Name> does not use legacy AuditOnly mode value' -ForEach $cases {
    $file = $_
    $errors = $null
    $tokens = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($file.FullName, [ref]$tokens, [ref]$errors)
    $errors | Should -BeNullOrEmpty
    $modeParameter = $ast.ParamBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -eq 'Mode' } | Select-Object -First 1
    $modeValidateSet = $modeParameter.Attributes |
      Where-Object { $_.TypeName.FullName -eq 'ValidateSet' } |
      Select-Object -First 1
    ($null -eq $modeValidateSet -or (@($modeValidateSet.PositionalArguments.Value) -notcontains 'AuditOnly')) | Should -BeTrue
  }

  It '<_.Name> does not define parameter names that collide with parameter aliases' -ForEach $cases {
    $file = $_
    $errors = $null
    $tokens = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($file.FullName, [ref]$tokens, [ref]$errors)
    $errors | Should -BeNullOrEmpty

    $params = @($ast.ParamBlock.Parameters)
    $paramNames = @($params | ForEach-Object { $_.Name.VariablePath.UserPath })
    $aliases = @(
      foreach ($param in $params) {
        foreach ($attr in @($param.Attributes | Where-Object { $_.TypeName.FullName -eq 'Alias' })) {
          foreach ($arg in @($attr.PositionalArguments)) {
            [string]$arg.SafeGetValue()
          }
        }
      }
    )

    @($paramNames | Where-Object { $aliases -contains $_ }) | Should -BeNullOrEmpty
  }

  It '<_.Name> enforces ShouldProcess when Mode supports Remediate' -ForEach $cases {
    $file = $_
    $errors = $null
    $tokens = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($file.FullName, [ref]$tokens, [ref]$errors)
    $errors | Should -BeNullOrEmpty
    $paramNames = @($ast.ParamBlock.Parameters | ForEach-Object { $_.Name.VariablePath.UserPath })
    if (-not ($paramNames -contains 'Mode')) {
      Set-ItResult -Skipped -Because 'Script has no Mode parameter.'
      return
    }

    $modeParameter = $ast.ParamBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -eq 'Mode' } | Select-Object -First 1
    $modeValidateSet = $modeParameter.Attributes |
      Where-Object { $_.TypeName.FullName -eq 'ValidateSet' } |
      Select-Object -First 1

    $supportsRemediate = $false
    if ($modeValidateSet) {
      $supportsRemediate = @($modeValidateSet.PositionalArguments.Value) -contains 'Remediate'
    }

    if (-not $supportsRemediate) {
      Set-ItResult -Skipped -Because 'Mode does not support Remediate.'
      return
    }

    $content = Get-Content -LiteralPath $file.FullName -Raw -Encoding UTF8
    ($content -match 'SupportsShouldProcess\s*=\s*\$true') | Should -BeTrue
  }

  It 'Audited scripts do not expose stale legacy Remediate help text in the top comment block' {
    $scriptsPath = Join-Path $PSScriptRoot '../../scripts'
    $legacyHelpCases = Get-ChildItem -Path $scriptsPath -File |
      Where-Object { $_.Name -match '^\d{2}-' } |
      Where-Object {
        $errors = $null
        $tokens = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile($_.FullName, [ref]$tokens, [ref]$errors)
        if ($errors) { return $false }

        $paramNames = @($ast.ParamBlock.Parameters | ForEach-Object { $_.Name.VariablePath.UserPath })
        if (($paramNames -notcontains 'Mode') -or ($paramNames -contains 'Remediate')) { return $false }

        $content = Get-Content -LiteralPath $_.FullName -Raw -Encoding UTF8
        $helpBlock = [regex]::Match($content, '(?s)<#.*?#>').Value
        ($helpBlock -match '\.PARAMETER\s+Mode') -and ($helpBlock -match '(?m)-Mode\s+Remediate\b')
      } |
      Select-Object -ExpandProperty Name

    foreach ($name in $legacyHelpCases) {
      $path = Join-Path $scriptsPath $name
      $content = Get-Content -LiteralPath $path -Raw -Encoding UTF8
      $helpBlock = [regex]::Match($content, '(?s)<#.*?#>').Value

      $helpBlock | Should -Not -Match '\.PARAMETER\s+Remediate'
      $helpBlock | Should -Not -Match '(?m)^\s*\..*?-Remediate\b'
    }
  }

  It 'Scripts with filtered finding counts force array semantics before reading Count' {
    foreach ($name in @('47-WDAG-Readiness-Audit.ps1', '49-DriverSigning-Integrity-Audit.ps1')) {
      $path = Join-Path (Join-Path $PSScriptRoot '../../scripts') $name
      $content = Get-Content -LiteralPath $path -Raw -Encoding UTF8

      $content | Should -Match '@\(\$Findings \| Where-Object \{ \$_.Severity -eq ''High'' \}\)\.Count'
      $content | Should -Match '@\(\$Findings \| Where-Object \{ \$_.Severity -eq ''Medium'' \}\)\.Count'
    }
  }

  It '27-Defender-Health-Audit permits an omitted SettingsJsonPath during config load' {
    $path = Join-Path $PSScriptRoot '../../scripts/27-Defender-Health-Audit.ps1'
    $content = Get-Content -LiteralPath $path -Raw -Encoding UTF8

    $content | Should -Match '\[AllowEmptyString\(\)\]\s*\[string\]\$Path'
  }
}
