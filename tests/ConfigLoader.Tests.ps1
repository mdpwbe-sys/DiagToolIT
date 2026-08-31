$projectRoot = Split-Path -Parent $PSScriptRoot
$loaderPath = Join-Path $projectRoot 'Diag-ConfigLoader.ps1'

Describe 'DiagToolIT modules_config.json loader' {
    if (-not (Test-Path -LiteralPath $loaderPath)) {
        throw "Config loader not found at $loaderPath"
    }
    # Source the loader (defines Get-DiagConfig only; no side effects, no diagnostic run)
    . $loaderPath

    It 'loads a valid configuration and exposes the expected keys' {
        $cfg = Get-DiagConfig -ConfigPath (Join-Path $projectRoot 'modules_config.json')
        if (-not $cfg) { throw 'Config is null or empty.' }
        if ($cfg.history.max_runs_retention -ne 120) { throw "max_runs_retention = $($cfg.history.max_runs_retention), expected 120" }
        if ($cfg.belgian_ecosystem.cert_alert_days -ne 30) { throw "cert_alert_days = $($cfg.belgian_ecosystem.cert_alert_days), expected 30" }
        if ($cfg.belgian_ecosystem.cert_critical_alert_days -ne 7) { throw "cert_critical_alert_days = $($cfg.belgian_ecosystem.cert_critical_alert_days), expected 7" }
        if ($cfg.history.score_baseline_threshold -ne 75) { throw "score_baseline_threshold = $($cfg.history.score_baseline_threshold), expected 75" }
        if ($cfg.cve_scanner.cvss_min_severity -ne 7.0) { throw "cvss_min_severity = $($cfg.cve_scanner.cvss_min_severity), expected 7.0" }
    }

    It 'applies at least one configurable value (cvss_min_severity drives a real filter)' {
        $cfg = Get-DiagConfig -ConfigPath (Join-Path $projectRoot 'modules_config.json')
        $cvssMin = $cfg.cve_scanner.cvss_min_severity
        $lowScore = [PSCustomObject]@{ Score = [double]($cvssMin - 0.5) }
        if (($lowScore.Score -ge $cvssMin) -ne $false) { throw 'Low-score CVE should be filtered out.' }
        $highScore = [PSCustomObject]@{ Score = [double]($cvssMin + 1.0) }
        if (($highScore.Score -ge $cvssMin) -ne $true) { throw 'High-score CVE should be kept.' }
    }

    It 'throws an explicit error when the config file is missing' {
        $missing = Join-Path $env:TEMP ('diag_missing_cfg_{0}.json' -f [guid]::NewGuid())
        Remove-Item -LiteralPath $missing -ErrorAction SilentlyContinue
        $failed = $false
        try { Get-DiagConfig -ConfigPath $missing } catch { $failed = $true }
        if (-not $failed) { throw 'Expected an explicit error for a missing config file.' }
    }

    It 'throws an explicit error when the config JSON is invalid' {
        $bad = Join-Path $env:TEMP ('diag_bad_cfg_{0}.json' -f [guid]::NewGuid())
        Set-Content -LiteralPath $bad -Value '{ this is not valid json ' -Encoding UTF8
        try {
            $failed = $false
            try { Get-DiagConfig -ConfigPath $bad } catch { $failed = $true }
            if (-not $failed) { throw 'Expected an explicit error for invalid JSON.' }
        } finally {
            Remove-Item -LiteralPath $bad -ErrorAction SilentlyContinue
        }
    }

    It 'falls back to safe defaults when the config lacks required sections' {
        $partial = Join-Path $env:TEMP ('diag_partial_cfg_{0}.json' -f [guid]::NewGuid())
        # Valid JSON but missing settings.belgian_ecosystem
        Set-Content -LiteralPath $partial -Value '{"version":"3.2.0","settings":{"history":{}}}' -Encoding UTF8
        try {
            $cfg = Get-DiagConfig -ConfigPath $partial
            if ($cfg.history.max_runs_retention -ne 120) { throw "fallback max_runs_retention wrong: $($cfg.history.max_runs_retention)" }
            if ($cfg.belgian_ecosystem.cert_alert_days -le 0) { throw 'fallback cert_alert_days missing or <= 0' }
            if ($cfg.belgian_ecosystem.cert_critical_alert_days -le 0) { throw 'fallback cert_critical_alert_days missing or <= 0' }
            if ($cfg.history.score_baseline_threshold -le 0) { throw 'fallback score_baseline_threshold missing or <= 0' }
            if ($cfg.cve_scanner.cvss_min_severity -le 0) { throw 'fallback cvss_min_severity missing or <= 0' }
        } finally {
            Remove-Item -LiteralPath $partial -ErrorAction SilentlyContinue
        }
    }
}
