[CmdletBinding()]
param (
    [Parameter(Mandatory)]
    [string]$OutputPath,

    [ValidateSet('FR', 'NL', 'EN', 'DE')]
    [string]$Lang = 'EN'
)

$projectRoot = Split-Path -Parent $PSScriptRoot
$sourcePath = Join-Path $projectRoot 'Diag-IT-UAA3-V3.ps1'
$source = Get-Content -LiteralPath $sourcePath -Raw
$templateStartMarker = $source.IndexOf("`$htmlTemplate = @'")
$templateEnd = $source.IndexOf("`n'@", $templateStartMarker)
if ($templateStartMarker -lt 0 -or $templateEnd -lt 0) {
    throw 'Unable to locate the HTML template boundary.'
}

$templateStart = $source.IndexOf("`n", $templateStartMarker) + 1
$html = $source.Substring($templateStart, $templateEnd - $templateStart)
$tokens = [regex]::Matches($html, '__[A-Z][A-Z0-9_]+__') |
    ForEach-Object { $_.Value } |
    Sort-Object -Unique

foreach ($token in $tokens) {
    $isJsonToken = $token -match '^__(HISTORY|CVE|BENCH|BELGIAN_APPS|NETWORK_AUDIT|DISK_AUDIT|SECURITY_AUDIT)_JSON__$'
    $value = switch -Regex ($token) {
        '^__THREE_JS__$' { [IO.File]::ReadAllText((Join-Path $projectRoot 'vendor\three\three.min.js'), [Text.Encoding]::UTF8); break }
        '^__INITIAL_LANG__$' { $Lang.ToLowerInvariant(); break }
        '^__(HISTORY|CVE|BENCH|FOSS)_JSON__$' { '[]'; break }
        '^__BELGIAN_APPS_JSON__$' { '{"Apps":[],"Certs":[]}'; break }
        '^__NETWORK_AUDIT_JSON__$' { '{"Shares":[],"Adapters":[],"PrimaryIndex":0}'; break }
        '^__DISK_AUDIT_JSON__$' { '{}'; break }
        '^__SECURITY_AUDIT_JSON__$' { '{"Users":[],"SuspiciousProcesses":[]}'; break }
        '^__(RESOLUTION_CARDS|TABLE_ROWS|RUNTIMES_HTML|PROFILES_HTML|FOSS_DRAWERS|STARTUP_ROWS|LISTENING_ROWS|ADAPTER_OPTIONS_HTML)__$' { ''; break }
        'COLOR__$' { '#34d399'; break }
        '^__(TOTAL|OK|WARN|ERR|HEALTH|ISSUES|APP|SCRIPT|FOLDER|TASK|PUBLIC_PORTS|SUSPICIOUS|CPU|P[1-5])_' { '0'; break }
        default { 'SYNTHETIC' }
    }
    if ($isJsonToken) {
        $value = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes([string]$value))
    }
    $html = $html.Replace($token, [string]$value)
}

$resolvedOutputPath = [IO.Path]::GetFullPath($OutputPath)
$outputDirectory = Split-Path -Parent $resolvedOutputPath
if (-not (Test-Path -LiteralPath $outputDirectory)) {
    New-Item -ItemType Directory -Path $outputDirectory -Force | Out-Null
}

[IO.File]::WriteAllText(
    $resolvedOutputPath,
    $html,
    [Text.UTF8Encoding]::new($false)
)

Write-Output $resolvedOutputPath
