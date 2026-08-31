[CmdletBinding()]
param (
    [Parameter(Mandatory)]
    [string]$OutputPath,

    [ValidateSet('FR', 'NL', 'EN', 'DE')]
    [string]$Lang = 'EN',

    [ValidateSet('None', 'DefenderDisabled')]
    [string]$AntivirusScenario = 'None',

    [ValidateSet('Default', 'SecurityPillarDegraded')]
    [string]$MetricScenario = 'Default'
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
$resolutionCardsHtml = ''
$tableRowsHtml = ''
$totalCount = 0
$okCount = 0
$warnCount = 0
$errCount = 0
$issuesCount = 0
$healthScore = 100
$p1Score = 100
$p2Score = 100
$p3Score = 100
$p4Score = 100
$p5Score = 100
$p1Desc = 'Synthetic security fixture'
$p2Desc = 'Synthetic CPU fixture'
$p3Desc = 'Synthetic storage fixture'
$p4Desc = 'Synthetic network fixture'
$p5Desc = 'Synthetic system fixture'

if ($MetricScenario -eq 'SecurityPillarDegraded') {
    $p1Score = 75
    $p2Score = 100
    $p3Score = 80
    $p4Score = 45
    $p5Score = 65
    $healthScore = [math]::Round(($p1Score + $p2Score + $p3Score + $p4Score + $p5Score) / 5.0)
    $p1Desc = 'SecureBoot désactivé (-15%) • UAC désactivé (-10%)'
}

if ($AntivirusScenario -eq 'DefenderDisabled') {
    . (Join-Path $projectRoot 'Diag-Antivirus.ps1')
    $assessment = Get-DiagAntivirusAssessment -DefenderStatus ([PSCustomObject]@{
        AMServiceEnabled            = $false
        AntivirusEnabled            = $false
        RealTimeProtectionEnabled   = $false
        DefenderSignaturesOutOfDate = $false
    }) -SecurityCenterProducts @(
        [PSCustomObject]@{
            displayName              = 'Microsoft Defender Antivirus'
            productState             = 397568
            pathToSignedProductExe   = ''
            pathToSignedReportingExe = ''
        }
    )
    if ($assessment.Status -ne 'ERROR' -or $assessment.Reason -ne 'NoActiveProtection') {
        throw "Synthetic Defender-disabled fixture produced $($assessment.Status)/$($assessment.Reason)."
    }

    $finding = [PSCustomObject]@{
        Category  = 'Sécurité & GPO'
        TestName  = 'Protection Antivirus Désactivée'
        Status    = 'ERROR'
        Details   = 'Aucune protection antivirus active. Produits inactifs ou non fiables : Microsoft Defender.'
        FixAction = 'Réactiver Microsoft Defender ou un antivirus tiers valide avec protection en temps réel.'
        ExamTip   = "La présence d'un provider SecurityCenter2 ne prouve pas qu'il protège activement le poste."
    }
    $encodedCategory = [Security.SecurityElement]::Escape($finding.Category)
    $encodedTestName = [Security.SecurityElement]::Escape($finding.TestName)
    $encodedDetails = [Security.SecurityElement]::Escape($finding.Details)
    $encodedFixAction = [Security.SecurityElement]::Escape($finding.FixAction)
    $encodedExamTip = [Security.SecurityElement]::Escape($finding.ExamTip)

    $resolutionCardsHtml = '<div class="res-card res-card-err">' +
        '<div class="res-header"><span class="badge badge-err">ERROR</span>' +
        '<strong>' + $encodedTestName + '</strong><span class="tag-cat">' + $encodedCategory + '</span></div>' +
        '<div class="res-body"><p><strong>🔍 Constat technique :</strong> ' + $encodedDetails + '</p>' +
        '<p class="action-highlight"><strong>🔧 Action corrective :</strong> ' + $encodedFixAction + '</p>' +
        '<div class="exam-tip-box"><strong>💡 Explication Formateur / Règle UAA 3 :</strong> ' + $encodedExamTip + '</div></div></div>'
    $tableRowsHtml = '<tr data-category="' + $encodedCategory + '" data-status="ERROR">' +
        '<td><span class="tag-cat">' + $encodedCategory + '</span></td><td><strong>' + $encodedTestName + '</strong></td>' +
        '<td><span class="badge badge-err">ERROR</span></td><td>' + $encodedDetails + '</td><td>' + $encodedFixAction + '</td><td></td><td></td></tr>'
    $totalCount = 1
    $errCount = 1
    $issuesCount = 1
    $healthScore = 0
}

$tokens = [regex]::Matches($html, '__[A-Z][A-Z0-9_]+__') |
    ForEach-Object { $_.Value } |
    Sort-Object -Unique

. (Join-Path $projectRoot 'Diag-SmartTelemetry.ps1')
$syntheticSmartRecord = ConvertTo-DiagSmartTelemetryRecord -PhysicalDisk ([pscustomobject]@{
    FriendlyName = 'Synthetic SMART SSD'
    MediaType = 'SSD'
    Size = 500GB
    HealthStatus = 'Healthy'
    BusType = 'SATA'
    DeviceId = 0
}) -ReliabilityCounter ([pscustomobject]@{
    PowerOnHours = $null
    Wear = 0
    Temperature = 29
    ReadErrorsTotal = 0
}) -DiskMetadata $null
$syntheticSmartJson = ConvertTo-Json -InputObject @($syntheticSmartRecord) -Compress -Depth 5
$syntheticNetworkJson = [PSCustomObject]@{
    Shares = @()
    PrimaryIndex = 1
    Adapters = @([PSCustomObject]@{
        Index = 1
        Name = 'Synthetic Ethernet'
        Description = 'Synthetic 1 GbE adapter'
        Status = 'Up'
        Speed = '1000 Mbps'
        MacAddress = '00-00-00-00-00-00'
        IPv4 = '192.0.2.10'
        PrefixLength = 24
        Gateway = '192.0.2.1'
        DNS = '1.1.1.1, 8.8.8.8'
        HasInternet = $true
        PingGateway = 1
        PingDNS1 = 8
        PingDNS2 = 10
        PingM365 = 18
        LatencyProfiles = @(
            [PSCustomObject]@{ Key='gateway'; Label='Local gateway'; Category='local'; Target='192.0.2.1'; LatencySamples=@(1,1,2); Sent=3; Received=3; PacketLossPct=0; MinimumMs=1; AverageMs=1.3; MaximumMs=2; JitterMs=.5 },
            [PSCustomObject]@{ Key='cloudflare'; Label='Cloudflare DNS'; Category='dns'; Target='1.1.1.1'; LatencySamples=@(7,8,9); Sent=3; Received=3; PacketLossPct=0; MinimumMs=7; AverageMs=8; MaximumMs=9; JitterMs=1 },
            [PSCustomObject]@{ Key='google'; Label='Google DNS'; Category='dns'; Target='8.8.8.8'; LatencySamples=@(9,10,11); Sent=3; Received=3; PacketLossPct=0; MinimumMs=9; AverageMs=10; MaximumMs=11; JitterMs=1 },
            [PSCustomObject]@{ Key='quad9'; Label='Quad9 DNS'; Category='dns'; Target='9.9.9.9'; LatencySamples=@(12,14,13); Sent=3; Received=3; PacketLossPct=0; MinimumMs=12; AverageMs=13; MaximumMs=14; JitterMs=1.5 },
            [PSCustomObject]@{ Key='m365'; Label='Microsoft 365'; Category='cloud'; Target='login.microsoftonline.com'; LatencySamples=@(17,18,19); Sent=3; Received=3; PacketLossPct=0; MinimumMs=17; AverageMs=18; MaximumMs=19; JitterMs=1 }
        )
    })
} | ConvertTo-Json -Compress -Depth 8

foreach ($token in $tokens) {
    $isJsonToken = $token -match '^__(HISTORY|CVE|BENCH|SMART|BELGIAN_APPS|NETWORK_AUDIT|DISK_AUDIT|SECURITY_AUDIT)_JSON__$'
    $value = switch -Regex ($token) {
        '^__THREE_JS__$' { [IO.File]::ReadAllText((Join-Path $projectRoot 'vendor\three\three.min.js'), [Text.Encoding]::UTF8); break }
        '^__INITIAL_LANG__$' { $Lang.ToLowerInvariant(); break }
        '^__RAM_UNIT__$' {
            switch ($Lang) {
                'FR' { 'Go'; break }
                default { 'GB'; break }
            }
            break
        }
        '^__UPTIME_(DAYS|HOURS|MINUTES)__$' { '0'; break }
        '^__BOOTMODE_KEY__$' { 'BootLegacy'; break }
        '^__SMART_JSON__$' { $syntheticSmartJson; break }
        '^__(HISTORY|CVE|BENCH|FOSS)_JSON__$' { '[]'; break }
        '^__BELGIAN_APPS_JSON__$' { '{"Apps":[],"Certs":[]}'; break }
        '^__NETWORK_AUDIT_JSON__$' { $syntheticNetworkJson; break }
        '^__DISK_AUDIT_JSON__$' { '{}'; break }
        '^__SECURITY_AUDIT_JSON__$' { '{"Users":[],"SuspiciousProcesses":[]}'; break }
        '^__RESOLUTION_CARDS__$' { $resolutionCardsHtml; break }
        '^__TABLE_ROWS__$' { $tableRowsHtml; break }
        '^__TOTAL_COUNT__$' { [string]$totalCount; break }
        '^__OK_COUNT__$' { [string]$okCount; break }
        '^__WARN_COUNT__$' { [string]$warnCount; break }
        '^__ERR_COUNT__$' { [string]$errCount; break }
        '^__ISSUES_COUNT__$' { [string]$issuesCount; break }
        '^__HEALTH_SCORE__$' { [string]$healthScore; break }
        '^__P1_SCORE__$' { [string]$p1Score; break }
        '^__P2_SCORE__$' { [string]$p2Score; break }
        '^__P3_SCORE__$' { [string]$p3Score; break }
        '^__P4_SCORE__$' { [string]$p4Score; break }
        '^__P5_SCORE__$' { [string]$p5Score; break }
        '^__P1_DESC__$' { [string]$p1Desc; break }
        '^__P2_DESC__$' { [string]$p2Desc; break }
        '^__P3_DESC__$' { [string]$p3Desc; break }
        '^__P4_DESC__$' { [string]$p4Desc; break }
        '^__P5_DESC__$' { [string]$p5Desc; break }
        '^__(RUNTIMES_HTML|PROFILES_HTML|FOSS_DRAWERS|STARTUP_ROWS|LISTENING_ROWS|ADAPTER_OPTIONS_HTML)__$' { ''; break }
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
