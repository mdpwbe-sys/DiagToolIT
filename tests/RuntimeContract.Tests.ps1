$projectRoot = Split-Path -Parent $PSScriptRoot

Describe 'DiagToolIT runtime contract' {
    It 'parses every tracked root PowerShell script with Windows PowerShell 5.1' {
        $trackedScripts = & git -C $projectRoot ls-files '*.ps1'
        $parseErrors = @()

        foreach ($relativePath in $trackedScripts) {
            $tokens = $null
            $errors = $null
            $fullPath = Join-Path $projectRoot $relativePath
            [System.Management.Automation.Language.Parser]::ParseFile(
                $fullPath,
                [ref]$tokens,
                [ref]$errors
            ) | Out-Null

            foreach ($error in $errors) {
                $parseErrors += '{0}:{1}: {2}' -f $relativePath, $error.Extent.StartLineNumber, $error.Message
            }
        }

        if ($parseErrors.Count -gt 0) {
            throw ($parseErrors -join [Environment]::NewLine)
        }
    }

    It 'exposes the documented command-line parameters' {
        $scriptPath = Join-Path $projectRoot 'Diag-IT-UAA3-V3.ps1'
        $tokens = $null
        $errors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile(
            $scriptPath,
            [ref]$tokens,
            [ref]$errors
        )
        $parameterNames = @($ast.ParamBlock.Parameters | ForEach-Object { $_.Name.VariablePath.UserPath })

        foreach ($expectedParameter in @('NoElevate', 'Lang', 'OutputPath')) {
            if ($parameterNames -notcontains $expectedParameter) {
                throw "Missing documented parameter: $expectedParameter"
            }
        }
    }

    It 'keeps every replacement token inside the HTML template' {
        $scriptPath = Join-Path $projectRoot 'Diag-IT-UAA3-V3.ps1'
        $source = Get-Content -LiteralPath $scriptPath -Raw
        $templateStart = $source.IndexOf("`$htmlTemplate = @'")
        $templateEnd = $source.IndexOf("`n'@", $templateStart)
        if ($templateStart -lt 0 -or $templateEnd -lt 0) {
            throw 'Unable to locate the HTML template boundary.'
        }

        $template = $source.Substring($templateStart, $templateEnd - $templateStart)
        $replacementTokens = [regex]::Matches(
            $source,
            "\.Replace\('(?<token>__[A-Z][A-Z0-9_]+__)'"
        ) | ForEach-Object { $_.Groups['token'].Value } | Sort-Object -Unique

        $missingTokens = @($replacementTokens | Where-Object { $template.IndexOf($_) -lt 0 })
        if ($missingTokens.Count -gt 0) {
            throw "Replacement tokens missing from the template: $($missingTokens -join ', ')"
        }
    }

    It 'generates a self-contained report without automatic network dependencies' {
        $reportPath = Join-Path ([IO.Path]::GetTempPath()) ('diagtoolit-offline-{0}.html' -f [guid]::NewGuid())

        try {
            & (Join-Path $PSScriptRoot 'New-SyntheticReport.ps1') -OutputPath $reportPath -Lang EN | Out-Null
            $report = Get-Content -LiteralPath $reportPath -Raw
            $remoteAutoloadPattern = '(?is)<(?:script|link|img|iframe|audio|video|source)\b[^>]*\b(?:src|href)\s*=\s*["'']https?://|url\(\s*["'']?https?://'
            $networkApiPattern = '(?i)\b(?:fetch|WebSocket|EventSource)\s*\(\s*["'']https?://|\.open\(\s*["''](?:GET|POST|PUT|PATCH|DELETE)["'']\s*,\s*["'']https?://|sendBeacon\s*\(\s*["'']https?://'

            if ($report -match $remoteAutoloadPattern -or $report -match $networkApiPattern) {
                throw 'The generated report still contains an automatic remote network dependency.'
            }
            if ($report -notmatch 'Copyright 2010-2021 Three\.js Authors' -or $report -notmatch 'WebGLRenderer') {
                throw 'The generated report does not embed the pinned Three.js runtime.'
            }
        } finally {
            Remove-Item -LiteralPath $reportPath -Force -ErrorAction SilentlyContinue
        }
    }

    It 'does not bake private machine data into the canonical generator' {
        $scriptPath = Join-Path $projectRoot 'Diag-IT-UAA3-V3.ps1'
        $source = Get-Content -LiteralPath $scriptPath -Raw
        $privateIpv4Pattern = '(?<!\d)(?:10\.\d{1,3}|192\.168|172\.(?:1[6-9]|2\d|3[01]))(?:\.\d{1,3}){2}(?!\d)'
        $macAddressPattern = '(?i)(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}'
        $absoluteUserPathPattern = '(?i)C:\\Users\\[^\\"''<]+'

        if ($source -match $privateIpv4Pattern) {
            throw 'The canonical generator contains a private IPv4 address.'
        }
        if ($source -match $macAddressPattern) {
            throw 'The canonical generator contains a MAC address.'
        }
        if ($source -match $absoluteUserPathPattern) {
            throw 'The canonical generator contains an absolute user profile path.'
        }
        if ($source -match '\$LocalReportPath') {
            throw 'The generator still writes an implicit report copy inside the repository.'
        }
    }

    It 'uses a portable protocol launcher path' {
        $launcherPath = Join-Path $projectRoot 'Run-DiagElevated.bat'
        $launcher = Get-Content -LiteralPath $launcherPath -Raw

        if ($launcher -notmatch '%~dp0') {
            throw 'The launcher does not resolve paths relative to its own directory.'
        }
        if ($launcher -match '(?i)C:\\Users\\') {
            throw 'The launcher contains a machine-specific user path.'
        }
    }

    It 'registers a fixed local protocol command for explicit CVE updates' {
        $registerPath = Join-Path $projectRoot 'Register-DiagProtocol.ps1'
        $definitions = @(& $registerPath -WhatIf -PassThru | Where-Object {
            $_.PSObject.Properties.Name -contains 'Scheme'
        })
        $cveProtocol = @($definitions | Where-Object { $_.Scheme -eq 'diagit-cve' })

        if ($cveProtocol.Count -ne 1) {
            throw 'The dedicated diagit-cve protocol is not defined exactly once.'
        }
        if ($cveProtocol[0].Command -notmatch 'Update-CveDatabase\.ps1') {
            throw 'The CVE protocol does not target the local update script.'
        }
        if ($cveProtocol[0].Command -match '%1|Invoke-Expression') {
            throw 'The CVE protocol accepts untrusted URL input or dynamic code execution.'
        }
    }

    It 'keeps one canonical implementation behind the FULL compatibility entry point' {
        $fullPath = Join-Path $projectRoot 'Diag-IT-UAA3-V3-FULL.ps1'
        $fullSource = Get-Content -LiteralPath $fullPath -Raw

        if ($fullSource.Length -ge 10000) {
            throw 'The FULL entry point still duplicates the complete implementation.'
        }
        if ($fullSource -notmatch 'Diag-IT-UAA3-V3\.ps1') {
            throw 'The FULL entry point does not forward to the canonical script.'
        }
    }

    It 'keeps language support coherent across script, launcher, selector, and README' {
        $expectedLanguages = @('FR', 'NL', 'EN', 'DE')
        $scriptSource = Get-Content -LiteralPath (Join-Path $projectRoot 'Diag-IT-UAA3-V3.ps1') -Raw
        $launcherSource = Get-Content -LiteralPath (Join-Path $projectRoot 'Lancer Diagnostic IT UAA3.bat') -Raw
        $readmeSource = Get-Content -LiteralPath (Join-Path $projectRoot 'README.md') -Raw

        foreach ($language in $expectedLanguages) {
            if ($scriptSource -notmatch ('(?i)<option value="{0}"' -f $language)) {
                throw "Missing selector language: $language"
            }
            if ($launcherSource -notmatch ('(?i)-Lang {0}' -f $language)) {
                throw "Missing launcher language: $language"
            }
        }

        if ($scriptSource -notmatch "ValidateSet\('FR', 'NL', 'EN', 'DE'\)") {
            throw 'The command-line language validation differs from the supported language list.'
        }
        if ($scriptSource -notmatch 'applyLanguage\(currentLang\)') {
            throw 'The requested language is not applied when the report loads.'
        }
        if ($readmeSource -notmatch '4 Langues') {
            throw 'The README does not advertise the actual supported language count.'
        }
    }

    It 'keeps outbound integrations disabled by default' {
        $configPath = Join-Path $projectRoot 'modules_config.json'
        $config = Get-Content -LiteralPath $configPath -Raw | ConvertFrom-Json

        if ($config.settings.rmm_integrations.webhook_enabled -ne $false) {
            throw 'Outbound webhook integration must be disabled in the default product configuration.'
        }
    }

    It 'stores PowerShell scripts as UTF-8 with BOM for Windows PowerShell 5.1' {
        $powerShellFiles = @(
            'Diag-IT-UAA3-V3.ps1',
            'Diag-IT-UAA3-V3-FULL.ps1',
            'Register-DiagProtocol.ps1',
            'Test-EidCertAlert.ps1',
            'Update-CveDatabase.ps1',
            'tests/New-SyntheticReport.ps1',
            'tests/RuntimeContract.Tests.ps1'
        )

        foreach ($relativePath in $powerShellFiles) {
            $bytes = [IO.File]::ReadAllBytes((Join-Path $projectRoot $relativePath))
            $hasUtf8Bom = $bytes.Length -ge 3 -and
                $bytes[0] -eq 0xEF -and
                $bytes[1] -eq 0xBB -and
                $bytes[2] -eq 0xBF
            if (-not $hasUtf8Bom) {
                throw "$relativePath is not UTF-8 with BOM."
            }
        }
    }
}
