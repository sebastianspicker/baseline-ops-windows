#requires -version 5.1

BeforeAll {
  Import-Module (Join-Path $PSScriptRoot '../../lib/Validation.psm1') -Force
}

Describe 'Test-PathTraversal' {
  It 'Returns true for traversal path' {
    Test-PathTraversal -Path '..\evil\file.txt' | Should -Be $true
  }

  It 'Returns false for safe path' {
    Test-PathTraversal -Path 'C:\Temp\safe.txt' | Should -Be $false
  }

  It 'Returns false for null or empty input' {
    Test-PathTraversal -Path $null | Should -Be $false
    Test-PathTraversal -Path '' | Should -Be $false
    Test-PathTraversal -Path '   ' | Should -Be $false
  }

  It 'Detects forward-slash traversal' {
    Test-PathTraversal -Path '../etc/passwd' | Should -Be $true
  }

  It 'Detects mid-path traversal' {
    Test-PathTraversal -Path 'C:\Temp\..\Windows' | Should -Be $true
  }
}

Describe 'Test-SafeScriptName' {
  It 'Accepts numbered script names' {
    Test-SafeScriptName -Name '18-Firewall-Baseline.ps1' | Should -Be $true
  }

  It 'Rejects path components' {
    Test-SafeScriptName -Name '..\outside.ps1' | Should -Be $false
  }

  It 'Rejects unsafe characters' {
    Test-SafeScriptName -Name '18-Bad:Name.ps1' | Should -Be $false
    Test-SafeScriptName -Name '18-Bad*Name.ps1' | Should -Be $false
  }

  It 'Rejects null or empty input' {
    Test-SafeScriptName -Name $null | Should -Be $false
    Test-SafeScriptName -Name '' | Should -Be $false
    Test-SafeScriptName -Name '   ' | Should -Be $false
  }

  It 'Rejects non-.ps1 extension' {
    Test-SafeScriptName -Name '01-Script.txt' | Should -Be $false
    Test-SafeScriptName -Name '01-Script.bat' | Should -Be $false
  }

  It 'Rejects names starting with a dot' {
    Test-SafeScriptName -Name '.hidden-script.ps1' | Should -Be $false
  }

  It 'Rejects names starting with a dash' {
    Test-SafeScriptName -Name '-dangerous.ps1' | Should -Be $false
  }

  It 'Rejects names containing backslash or forward slash' {
    Test-SafeScriptName -Name 'sub/script.ps1' | Should -Be $false
    Test-SafeScriptName -Name 'sub\script.ps1' | Should -Be $false
  }

  It 'Rejects names with leading or trailing whitespace' {
    Test-SafeScriptName -Name ' script.ps1' | Should -Be $false
    Test-SafeScriptName -Name 'script.ps1 ' | Should -Be $false
  }
}

Describe 'Test-ValidGitRef' {
  It 'Accepts branch ref' {
    Test-ValidGitRef -Ref 'main' | Should -Be $true
  }

  It 'Rejects unsafe ref' {
    Test-ValidGitRef -Ref '../main' | Should -Be $false
  }

  It 'Rejects null or empty ref' {
    Test-ValidGitRef -Ref $null | Should -Be $false
    Test-ValidGitRef -Ref '' | Should -Be $false
    Test-ValidGitRef -Ref '   ' | Should -Be $false
  }

  It 'Rejects ref with double dot (..)' {
    Test-ValidGitRef -Ref 'main..branch' | Should -Be $false
  }

  It 'Rejects ref with tilde' {
    Test-ValidGitRef -Ref 'HEAD~1' | Should -Be $false
  }

  It 'Rejects ref with caret' {
    Test-ValidGitRef -Ref 'HEAD^2' | Should -Be $false
  }

  It 'Rejects ref with @{' {
    Test-ValidGitRef -Ref 'main@{0}' | Should -Be $false
  }

  It 'Rejects ref starting with dash' {
    Test-ValidGitRef -Ref '-branch' | Should -Be $false
  }

  It 'Rejects ref ending with .lock' {
    Test-ValidGitRef -Ref 'branch.lock' | Should -Be $false
  }

  It 'Rejects ref ending with dot' {
    Test-ValidGitRef -Ref 'branch.' | Should -Be $false
  }

  It 'Rejects ref ending with slash' {
    Test-ValidGitRef -Ref 'branch/' | Should -Be $false
  }

  It 'Rejects ref with backslash' {
    Test-ValidGitRef -Ref 'branch\name' | Should -Be $false
  }

  It 'Rejects ref with colon' {
    Test-ValidGitRef -Ref 'branch:name' | Should -Be $false
  }

  It 'Rejects ref with question mark' {
    Test-ValidGitRef -Ref 'branch?name' | Should -Be $false
  }

  It 'Rejects ref with asterisk' {
    Test-ValidGitRef -Ref 'branch*' | Should -Be $false
  }

  It 'Rejects ref with open bracket' {
    Test-ValidGitRef -Ref 'branch[0]' | Should -Be $false
  }

  It 'Accepts valid feature branch name' {
    Test-ValidGitRef -Ref 'feature/my-branch' | Should -Be $true
  }

  It 'Accepts valid tag format' {
    Test-ValidGitRef -Ref 'v1.2.3' | Should -Be $true
  }

  It 'Accepts ref with hyphen and numbers' {
    Test-ValidGitRef -Ref 'release-2024.01' | Should -Be $true
  }
}

Describe 'Assert-NoPathTraversal' {
  It 'Does not throw for safe path' {
    { Assert-NoPathTraversal -Path 'C:\Temp\safe.txt' } | Should -Not -Throw
  }

  It 'Throws for traversal path' {
    { Assert-NoPathTraversal -Path '..\evil\file.txt' } | Should -Throw '*path traversal*'
  }

  It 'Throws with custom parameter name in message' {
    { Assert-NoPathTraversal -Path '..\escape' -ParameterName 'ConfigPath' } | Should -Throw '*ConfigPath*'
  }
}

Describe 'Test-SafeUrl' {
  It 'Accepts https URL' {
    Test-SafeUrl -Url 'https://example.com/resource' | Should -Be $true
  }

  It 'Accepts http URL' {
    Test-SafeUrl -Url 'http://example.com/resource' | Should -Be $true
  }

  It 'Rejects file:// scheme' {
    Test-SafeUrl -Url 'file:///etc/passwd' | Should -Be $false
  }

  It 'Rejects ftp:// scheme' {
    Test-SafeUrl -Url 'ftp://evil.com/payload' | Should -Be $false
  }

  It 'Rejects null or empty' {
    Test-SafeUrl -Url $null | Should -Be $false
    Test-SafeUrl -Url '' | Should -Be $false
    Test-SafeUrl -Url '   ' | Should -Be $false
  }

  It 'Rejects argument injection via leading dash' {
    Test-SafeUrl -Url '-http://evil.com' | Should -Be $false
  }

  It 'Rejects relative URLs' {
    Test-SafeUrl -Url '/relative/path' | Should -Be $false
  }

  It 'Accepts custom allowed schemes' {
    Test-SafeUrl -Url 'ftp://example.com' -AllowedSchemes @('ftp') | Should -Be $true
  }
}

Describe 'Test-PathUnderRoot' {
  It 'Returns true when path is under root' {
    $tempRoot = if ([string]::IsNullOrWhiteSpace($env:TEMP)) { [System.IO.Path]::GetTempPath() } else { $env:TEMP }
    $child = Join-Path $tempRoot 'subdir/file.txt'
    Test-PathUnderRoot -Path $child -Root $tempRoot | Should -Be $true
  }

  It 'Returns false when path escapes root' {
    $tempRoot = if ([string]::IsNullOrWhiteSpace($env:TEMP)) { [System.IO.Path]::GetTempPath() } else { $env:TEMP }
    $escaped = Join-Path $tempRoot '../../etc/passwd'
    Test-PathUnderRoot -Path $escaped -Root $tempRoot | Should -Be $false
  }

  It 'Returns false for a sibling directory' {
    $tempRoot = if ([string]::IsNullOrWhiteSpace($env:TEMP)) { [System.IO.Path]::GetTempPath() } else { $env:TEMP }
    $sibling = Join-Path (Split-Path $tempRoot -Parent) 'sibling-dir'
    Test-PathUnderRoot -Path $sibling -Root $tempRoot | Should -Be $false
  }
}
