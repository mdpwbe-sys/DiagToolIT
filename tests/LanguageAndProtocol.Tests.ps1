$projectRoot = Split-Path -Parent $PSScriptRoot

Describe 'DiagToolIT language propagation' {
    It 'routes every visible console prompt through the centralized translator' {
        $scriptPath = Join-Path $projectRoot 'Diag-IT-UAA3-V3.ps1'
        $source = Get-Content -LiteralPath $scriptPath -Raw
        $start = $source.IndexOf('# --- CONSOLE LOCALIZATION START ---')
        if ($start -lt 0) {
            throw 'The centralized console localization block is missing.'
        }
        $end = $source.IndexOf('# --- CONSOLE LOCALIZATION END ---', $start)
        if ($end -lt 0) {
            throw 'The centralized console localization block is missing.'
        }

        $localizationBlock = $source.Substring($start, $end - $start)
        . ([scriptblock]::Create($localizationBlock))

        $messages = @{}
        foreach ($language in @('FR', 'NL', 'EN', 'DE')) {
            $messages[$language] = Get-DiagConsoleMessage -Language $language -Key 'StageSystem'
            if ([string]::IsNullOrWhiteSpace($messages[$language])) {
                throw "Missing StageSystem console message for $language."
            }
        }
        if (($messages.Values | Sort-Object -Unique).Count -ne 4) {
            throw 'StageSystem is not independently translated in FR, NL, EN, and DE.'
        }

        $tokens = $null
        $errors = $null
        $ast = [System.Management.Automation.Language.Parser]::ParseFile(
            $scriptPath,
            [ref]$tokens,
            [ref]$errors
        )
        $consoleCommands = $ast.FindAll({
            param($node)
            $node -is [System.Management.Automation.Language.CommandAst] -and
                $node.GetCommandName() -in @('Write-Host', 'Write-Warning', 'Read-Host')
        }, $true)

        foreach ($command in $consoleCommands) {
            $text = $command.Extent.Text
            $isDecoration = $text -match '^Write-Host\s+(?:""|''(?:)''|"=+")'
            if (-not $isDecoration -and $text -notmatch 'Get-DiagConsoleMessage') {
                throw "Non-localized console command at line $($command.Extent.StartLineNumber): $text"
            }
        }
    }

    It 'localizes the machine telemetry header labels in all four languages' {
        $source = Get-Content -LiteralPath (Join-Path $projectRoot 'Diag-IT-UAA3-V3.ps1') -Raw
        foreach ($marker in @(
            'telemetry_host', 'telemetry_os', 'telemetry_version', 'telemetry_cpu',
            'telemetry_memory', 'telemetry_uptime', 'telemetry_boot',
            'id="telemetryHostLabel"', 'id="telemetryOsLabel"',
            'id="telemetryVersionLabel"', 'id="telemetryCpuLabel"',
            'id="telemetryMemoryLabel"', 'id="telemetryUptimeLabel"',
            'id="telemetryBootLabel"', 'telemetryLabelIds',
            'id="telemetryMemoryValue"', 'id="telemetryUptimeValue"', 'id="telemetryBootValue"',
            'RamUnit', 'UptimeFormat', 'ScanDateFormat', 'BootUefiOn', 'BootUefiOff', 'BootLegacy',
            '__RAM_UNIT__', '__UPTIME_DAYS__', '__UPTIME_HOURS__', '__UPTIME_MINUTES__', '__BOOTMODE_KEY__'
        )) {
            if ($source.IndexOf($marker, [StringComparison]::Ordinal) -lt 0) {
                throw "Missing localized telemetry header marker: $marker"
            }
        }
    }

    It 'preserves the selected language during UAC elevation' {
        $source = Get-Content -LiteralPath (Join-Path $projectRoot 'Diag-IT-UAA3-V3.ps1') -Raw
        if ($source -notmatch '"-Lang \$Lang"' -or
            $source -notmatch 'Start-Process\s+powershell\.exe.*-ArgumentList\s+\(\$elevationArguments') {
            throw 'The UAC restart does not preserve -Lang.'
        }
    }

    It 'offers Shift+Enter to rerun the diagnostic with the selected language' {
        $source = Get-Content -LiteralPath (Join-Path $projectRoot 'Diag-IT-UAA3-V3.ps1') -Raw
        foreach ($marker in @(
            'PressEnterOrRerun',
            '[Console]::ReadKey($true)',
            '[ConsoleModifiers]::Shift',
            'powershell.exe @rerunArguments',
            "'-Lang'",
            '$Lang'
        )) {
            if ($source.IndexOf($marker, [StringComparison]::Ordinal) -lt 0) {
                throw "Missing Shift+Enter rerun marker: $marker"
            }
        }
    }

    It 'explains automatic dashboard protocol registration in every launcher language' {
        $launcher = Get-Content -LiteralPath (Join-Path $projectRoot 'Lancer Diagnostic IT UAA3.bat') -Raw
        foreach ($message in @(
            'Enregistrement des raccourcis systeme',
            'systeemkoppelingen diagit://',
            'Registering the diagit:// and diagit-cve://',
            'Systemverknuepfungen'
        )) {
            if ($launcher.IndexOf($message, [StringComparison]::Ordinal) -lt 0) {
                throw "Missing localized protocol registration message: $message"
            }
        }
        if ($launcher -notmatch '(?i)diagit-cve') {
            throw 'The launcher does not explain/register the CVE dashboard protocol alongside diagit.'
        }
    }

    It 'replaces the unused refresh action with a database-backed logs archive tab' {
        $source = Get-Content -LiteralPath (Join-Path $projectRoot 'Diag-IT-UAA3-V3.ps1') -Raw
        if ($source -match 'id="btnRefreshTab"|refreshReportView\(') {
            throw 'The unused ACTUALISER action is still exposed in the dashboard.'
        }
        foreach ($requiredMarker in @(
            'switchTab(''tab-archive'')',
            'id="tab-archive"',
            'id="archiveLogBody"',
            'function renderArchiveLogs',
            'renderArchiveLogs();'
        )) {
            if ($source.IndexOf($requiredMarker, [StringComparison]::Ordinal) -lt 0) {
                throw "Missing logs/archive dashboard marker: $requiredMarker"
            }
        }
        if ($source -notmatch "'tab_archive'") {
            throw 'The archive tab is not connected to the language translation map.'
        }
        if ($source -notmatch 'addCell\(run\.CveCount\);[\s\S]{0,120}body\.appendChild\(row\);') {
            throw 'Archive rows are built but never appended to the archive table body.'
        }
    }

    It 'covers dynamic resolution labels and the reported spooler/disk/restart findings' {
        $source = Get-Content -LiteralPath (Join-Path $projectRoot 'Diag-IT-UAA3-V3.ps1') -Raw
        foreach ($phrase in @(
            '🪟 Raccourci GUI :',
            '⚡ Copier PowerShell :',
            '🔍 Constat technique :',
            '🔧 Action corrective :',
            '💡 Explication Formateur / Règle UAA 3 :',
            "Spouleur d'impression (File bloquée)",
            'fichier(s) d''impression bloqué(s) dans le répertoire de spoule (',
            'Redémarrage Système Requis',
            ': seulement',
            ' Go restants (',
            '% de '
        )) {
            if ($source.IndexOf(('"{0}"' -f $phrase), [StringComparison]::Ordinal) -lt 0) {
                throw "Missing report translation key: $phrase"
            }
        }
    }

    It 'accepts only the four exact diagnostic protocol URLs' {
        $handlerPath = Join-Path $projectRoot 'Run-DiagProtocol.ps1'
        if (-not (Test-Path -LiteralPath $handlerPath -PathType Leaf)) {
            throw "Missing protocol handler: $handlerPath"
        }

        foreach ($language in @('FR', 'NL', 'EN', 'DE')) {
            $result = & $handlerPath -Uri "diagit://run?lang=$language" -PassThru
            if ($result.Language -ne $language) {
                throw "Protocol language mismatch for ${language}: $($result.Language)"
            }
        }

        $rejected = $false
        try {
            & $handlerPath -Uri 'diagit://run?lang=EN&command=calc.exe' -PassThru
        } catch {
            $rejected = $true
        }
        if (-not $rejected) {
            throw 'The protocol handler accepted an arbitrary argument.'
        }
    }

    It 'normalizes protocol casing without widening the URL whitelist' {
        $handlerPath = Join-Path $projectRoot 'Run-DiagProtocol.ps1'
        foreach ($uri in @(
            'DIAGIT://RUN?LANG=fr',
            'diagit://run?lang=En',
            'diagit://RUN?LANG=de'
        )) {
            $result = & $handlerPath -Uri $uri -PassThru
            if ($result.Language -notin @('FR', 'EN', 'DE')) {
                throw "Protocol casing normalization returned an invalid language for $uri."
            }
        }
        $quotedResult = & $handlerPath -Uri '  "diagit://run?lang=fr"  ' -PassThru
        if ($quotedResult.Language -ne 'FR') {
            throw 'The protocol handler did not remove transport-only surrounding quotes and whitespace.'
        }
        $slashResult = & $handlerPath -Uri 'diagit://run/?lang=EN' -PassThru
        if ($slashResult.Language -ne 'EN') {
            throw 'The protocol handler did not accept the browser-normalized path slash variant.'
        }

        foreach ($uri in @(
            'diagit://run?lang=en&command=calc.exe',
            'diagit://run?lang=en/',
            'diagit://run?lang=fr#fragment'
        )) {
            $rejected = $false
            try { & $handlerPath -Uri $uri -PassThru } catch { $rejected = $true }
            if (-not $rejected) {
                throw "The protocol handler accepted a widened URL: $uri"
            }
        }
    }

    It 'uses a user-initiated external link for dashboard protocol launches' {
        $source = Get-Content -LiteralPath (Join-Path $projectRoot 'Diag-IT-UAA3-V3.ps1') -Raw
        $start = $source.IndexOf('window.launchLocalProtocol = function(uri)')
        $end = $source.IndexOf('window.launchBatchDiagnostic = function', $start)
        if ($start -lt 0 -or $end -lt $start) {
            throw 'The dashboard protocol launch function is missing.'
        }
        $launchFunction = $source.Substring($start, $end - $start)
        if ($launchFunction -notmatch "createElement\('a'\)") {
            throw 'The dashboard does not create an external protocol link.'
        }
        if ($launchFunction -notmatch 'target\s*=\s*["'']_blank') {
            throw 'The external protocol link does not preserve the dashboard tab.'
        }
        if ($launchFunction -match "createElement\('iframe'\)") {
            throw 'The hidden iframe launch bypasses the browser external-app confirmation.'
        }
    }

    It 'registers the URL handler instead of passing URL input to the main diagnostic' {
        $registerPath = Join-Path $projectRoot 'Register-DiagProtocol.ps1'
        $definitions = @(& $registerPath -WhatIf -PassThru | Where-Object {
            $_.PSObject.Properties.Name -contains 'Scheme'
        })
        $diagProtocol = @($definitions | Where-Object { $_.Scheme -eq 'diagit' })

        if ($diagProtocol.Count -ne 1) {
            throw 'The diagit protocol is not defined exactly once.'
        }
        if ($diagProtocol[0].Command -notmatch 'Run-DiagProtocol\.ps1') {
            throw 'The diagit protocol bypasses the strict URL handler.'
        }
        if ($diagProtocol[0].Command -notmatch '%1') {
            throw 'The diagit protocol does not forward its URL to the strict handler.'
        }
        if ($diagProtocol[0].Command -match 'Diag-IT-UAA3-V3\.ps1') {
            throw 'Untrusted URL input is still sent directly to the main diagnostic.'
        }
    }

    It 'passes only a validated language from the protocol batch launcher to PowerShell' {
        $launcher = Get-Content -LiteralPath (Join-Path $projectRoot 'Run-DiagElevated.bat') -Raw
        foreach ($language in @('FR', 'NL', 'EN', 'DE')) {
            if ($launcher -notmatch ("(?i)DIAG_LANG={0}" -f $language)) {
                throw "The protocol batch launcher does not whitelist $language."
            }
        }
        if ($launcher -notmatch '(?i)-Lang\s+%DIAG_LANG%') {
            throw 'The validated batch language is not passed to the main diagnostic.'
        }
    }
}
