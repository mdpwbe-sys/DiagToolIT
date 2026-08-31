$projectRoot = Split-Path -Parent $PSScriptRoot

Describe 'DiagToolIT runtime contract' {
    It 'parses every tracked root PowerShell script with Windows PowerShell 5.1' {
        $trackedScripts = @(& git -C $projectRoot ls-files '*.ps1')
        foreach ($requiredRootScript in @('Diag-Antivirus.ps1', 'Diag-HardwareTelemetry.ps1', 'Diag-Benchmark.ps1', 'Diag-SmartTelemetry.ps1', 'Run-DiagProtocol.ps1')) {
            if ($trackedScripts -notcontains $requiredRootScript) {
                $trackedScripts += $requiredRootScript
            }
        }
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
            if ($report -notmatch 'id="tab-archive"' -or $report -notmatch 'id="archiveLogBody"' -or $report -match 'id="btnRefreshTab"') {
                throw 'The generated report does not expose the logs/archive tab contract.'
            }
            foreach ($benchmarkMarker in @('id="gpuBenchCard"', 'id="ramBenchCard"', 'id="globalPerfCard"', 'id="diskVolumesContainer"', 'id="smartDisksContainer"')) {
                if ($report.IndexOf($benchmarkMarker, [StringComparison]::Ordinal) -lt 0) {
                    throw "The generated report is missing benchmark/disk marker: $benchmarkMarker"
                }
            }
            if ($report -match '__SMART_JSON__|__GLOBAL_PERF_SCORE__') {
                throw 'The generated report still contains benchmark replacement tokens.'
            }
            foreach ($catalogMarker in @('id="businessCountrySelect"', 'value="be"', 'value="fr"', 'value="uk"', 'value="de"', 'value="es"', 'value="it"', 'value="pt"', 'id="businessCatalogMeta"', 'https://www.csam.be/en/index.html')) {
                if ($report.IndexOf($catalogMarker, [StringComparison]::Ordinal) -lt 0) {
                    throw "The generated report is missing business catalogue marker: $catalogMarker"
                }
            }
            $smartPayloadMatch = [regex]::Match($report, "var rawSmart = decodeBase64Utf8\('([^']+)'\)")
            if (-not $smartPayloadMatch.Success) {
                throw 'The generated report does not expose its encoded SMART payload.'
            }
            $smartJson = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($smartPayloadMatch.Groups[1].Value))
            $smartRows = @($smartJson | ConvertFrom-Json)
            if ($smartRows.Count -ne 1 -or $smartRows[0].Temperature -ne '29 °C' -or $smartRows[0].WearPct -ne 0 -or $smartRows[0].ReadErrors -ne 0 -or $smartRows[0].PowerOnHours -ne '—') {
                throw "The generated SMART payload lost its display characters or numeric zeros: $smartJson"
            }
            if ($smartJson -match 'Â|â€|�') {
                throw "The generated SMART payload contains mojibake: $smartJson"
            }
        } finally {
            Remove-Item -LiteralPath $reportPath -Force -ErrorAction SilentlyContinue
        }
    }

    It 'keeps server-authoritative pillar scores and the five-pillar health average' {
        $source = Get-Content -LiteralPath (Join-Path $projectRoot 'Diag-IT-UAA3-V3.ps1') -Raw
        if ($source -match '(?is)cveCountLive\s*=.*?if\s*\(cveCountLive\s*===\s*0\).*?secPctElem\.innerText\s*=\s*["'']100%') {
            throw 'Client initialization overwrites the authoritative security pillar with 100% when CVE count is zero.'
        }
        foreach ($marker in @(
            '$healthScore = [math]::Round(($p1_security + $p2_perf + $p3_storage + $p4_network + $p5_system) / 5.0)',
            "`$htmlOutput = `$htmlOutput.Replace('__HEALTH_SCORE__', [string]`$healthScore)",
            "`$htmlOutput = `$htmlOutput.Replace('__P1_SCORE__', [string]`$p1_security)",
            '$historyList | Select-Object -Last $cfgHistoryMaxRuns'
        )) {
            if ($source.IndexOf($marker, [StringComparison]::Ordinal) -lt 0) {
                throw "Missing authoritative score marker: $marker"
            }
        }
    }

    It 'renders a 75 security pillar and a 73 health score for the synthetic degraded fixture' {
        $reportPath = Join-Path ([IO.Path]::GetTempPath()) ('diagtoolit-score-{0}.html' -f [guid]::NewGuid())

        try {
            & (Join-Path $PSScriptRoot 'New-SyntheticReport.ps1') -OutputPath $reportPath -Lang EN -MetricScenario SecurityPillarDegraded | Out-Null
            $report = Get-Content -LiteralPath $reportPath -Raw

            if ($report -notmatch '(?s)Sécurité, TPM & eID.*?<strong[^>]*>75%</strong>') {
                throw 'Synthetic degraded report does not render the authoritative security pillar score of 75%.'
            }
            if ($report -notmatch '(?s)id="dynHealthScore"[^>]*>\s*73\s*<') {
                throw 'Synthetic degraded report does not render the five-pillar health score of 73.'
            }
            if ($report -match 'cveCountLive') {
                throw 'Synthetic report still embeds the removed client-side security score overwrite.'
            }
        } finally {
            Remove-Item -LiteralPath $reportPath -Force -ErrorAction SilentlyContinue
        }
    }

    It 'exposes a bounded, explicit network speed test without automatic calls' {
        $scriptPath = Join-Path $projectRoot 'Diag-IT-UAA3-V3.ps1'
        $source = Get-Content -LiteralPath $scriptPath -Raw

        foreach ($marker in @(
            'id="networkSpeedTestCard"',
            'id="networkSpeedTestBtn"',
            'id="networkSpeedTestStatus"',
            'id="networkSpeedTestResult"',
            'id="networkSpeedCanvas"',
            'id="networkSpeedLegend"',
            'id="networkSpeedScale"',
            'id="networkSpeedAxisY"',
            'id="networkSpeedAxisX"',
            'id="networkSpeedDownloadSwatch"',
            'id="networkSpeedUploadSwatch"',
            'id="networkSpeedVisualMode"',
            'id="networkSpeedQuality"',
            'runNetworkSpeedTest',
            'speed.cloudflare.com',
            '/__down',
            '/__up',
            'performance.now',
            'new Uint8Array',
            'network_speed_title',
            'network_speed_download',
            'network_speed_upload',
            'network_speed_done',
            'network_speed_phase_warmup',
            'network_speed_phase_download',
            'network_speed_phase_upload',
            'AbortController',
            'cache: ''no-store''',
            'mode: ''cors''',
            'networkSpeedTotalDurationMs = 20000',
            'networkSpeedPhaseDurationMs = 10000',
            'networkSpeedParallelStreams = 4',
            'networkSpeedMaximumBytesPerPhase = 1280 * 1024 * 1024',
            'warmUpNetworkSpeedConnection',
            'selectNetworkSpeedChunk',
            'runNetworkSpeedWindow',
            'waitForNetworkSpeedPhase',
            'summarizeNetworkSpeedSamples',
            'disposeNetworkSpeedVisualizer',
            'getNetworkSpeedDebugState',
            'buffer = null',
            'body = null',
            'networkSpeedVisualContract',
            'networkSpeedVisualSeed',
            'THREE.OrthographicCamera',
            'THREE.ShaderMaterial',
            'smoothNetworkSpeedPoint',
            'smoothNetworkSpeedTraces',
            'targetPositions',
            'networkSpeedChartY',
            'networkSpeedTraceTimerCache',
            'networkSpeedTraceClockStartMs',
            'networkSpeedReplayDelayMs',
            'networkSpeedTraceCacheSealed',
            'beginReplay',
            'networkSpeedLiveDownloadValue',
            'networkSpeedLiveUploadValue',
            'networkSpeedDisplayFps',
            'networkSpeedElectricTrail',
            'networkSpeedElectricArc',
            'updateProjectileEffects',
            'replayFrameSeries',
            'interpolateReplaySample',
            'projectileEffectDirection',
            'projectileTrailChainFollow',
            'projectileTrailPointFromSparkline',
            'seedProjectileTrailFromTrace',
            'targetPoint',
            'requestAnimationFrame',
            'Promise.all'
        )) {
            if ($source.IndexOf($marker, [StringComparison]::Ordinal) -lt 0) {
                throw "Missing explicit network speed-test marker: $marker"
            }
        }

        if ($source -notmatch '(?is)networkSpeedTestBtn[^>]*onclick="runNetworkSpeedTest\(this\)"') {
            throw 'The network speed test is not wired to an explicit user action.'
        }
        if ($source -notmatch '(?is)runNetworkSpeedTest\s*=\s*function') {
            throw 'The network speed-test entry point is not exposed for the button.'
        }
        if ($source -notmatch '(?is)downloadChunkBytes\s*=\s*8\s*\*\s*1024\s*\*\s*1024') {
            throw 'The download probe does not declare its bounded 8 MiB stream chunk.'
        }
        if ($source -notmatch '(?is)uploadChunkBytes\s*=\s*4\s*\*\s*1024\s*\*\s*1024') {
            throw 'The upload probe does not declare its bounded 4 MiB stream chunk.'
        }
        if ($source -match '(?is)runNetworkSpeedTest\(\s*\)\s*;') {
            throw 'The speed test appears to run automatically instead of after a click.'
        }

        $speedRuntimeStart = $source.IndexOf("var networkSpeedEndpointOrigin = 'https://' + 'speed.cloudflare.com';", [StringComparison]::Ordinal)
        $speedRuntimeEnd = $source.IndexOf("setNetworkSpeedStatus('idle');", $speedRuntimeStart, [StringComparison]::Ordinal)
        $speedRuntime = $source.Substring($speedRuntimeStart, $speedRuntimeEnd - $speedRuntimeStart)
        if ($speedRuntime -match 'createObjectURL|showSaveFilePicker|FileSystem') {
            throw 'The speed test writes a download artifact instead of keeping transient buffers in memory.'
        }
        if ($speedRuntime -match '(?is)preserveDrawingBuffer\s*:\s*true') {
            throw 'The speed visualizer keeps the drawing buffer, which can force GPU synchronization and frame stalls.'
        }
        if ($speedRuntime -match '(?is)new\s+THREE\.CatmullRomCurve3') {
            throw 'The speed trace uses parameter-space spline rebuilding, which moves old vertices whenever a sample arrives.'
        }
        if ($speedRuntime -notmatch '(?is)networkSpeedTraceSampleAtProgress|traceSampleSpacing') {
            throw 'The speed trace has no stable progress-space resampling seam for temporal continuity.'
        }
        if ($speedRuntime -notmatch '(?is)networkSpeedScaleTargetMbps|smoothNetworkSpeedScale') {
            throw 'The speed chart rescales its Y axis abruptly when a new peak arrives.'
        }
        if ($speedRuntime -notmatch '(?is)replayFrameSeries|interpolateReplaySample') {
            throw 'The speed line has no continuous playhead between the discrete network samples.'
        }
        foreach ($vfxMarker in @('electricTrailGeometry', 'electricArcGeometry', 'spawnElectricBurst', 'updateProjectileEffects', 'projectileTrailPointFromSparkline', 'seedProjectileTrailFromTrace')) {
            if ($speedRuntime.IndexOf($vfxMarker, [StringComparison]::Ordinal) -lt 0) {
                throw "The speed projectile is missing its pooled electric VFX layer: $vfxMarker"
            }
        }
        if ($speedRuntime -notmatch '(?is)projectileEffectDirection|projectileTrailChainFollow') {
            throw 'The projectile VFX is still authored on a fixed horizontal axis instead of following the measured trajectory.'
        }
        if ($source -notmatch '(?is)\.speed-detail-grid\s*\{[^}]*grid-template-columns\s*:\s*repeat\(9\s*,\s*minmax\(0\s*,\s*1fr\)\)') {
            throw 'The speed detail cells are allowed to wrap instead of staying on one compact line.'
        }
        if ($source -notmatch '(?is)\.speed-visual-stage\s*\{[^}]*min-height\s*:\s*30[0-9]px[^}]*height\s*:\s*30[0-9]px') {
            throw 'The speed chart stage does not reserve enough vertical room for its HUD.'
        }
        if ($source -notmatch '(?is)#networkSpeedCanvas\s*\{[^}]*position\s*:\s*absolute;[^}]*top\s*:\s*58px;[^}]*height\s*:\s*calc\(100%\s*-\s*58px\)') {
            throw 'The speed canvas is not placed below the reserved HUD band.'
        }
        if ($source -notmatch '(?is)\.speed-visual-controls\s*\{[^}]*pointer-events\s*:\s*auto') {
            throw 'The speed selectors are not interactive after the HUD overlay is layered above the canvas.'
        }
        if ($source -notmatch '(?is)function\s+networkSpeedChartY\s*\([^)]*\).*networkSpeedVisualContract\.curve\.ceilingY\s*\+\s*ratio\s*\*\s*\(networkSpeedVisualContract\.curve\.floorY\s*-\s*networkSpeedVisualContract\.curve\.ceilingY\)') {
            throw 'The speed chart maps high Mbps toward the visual top of the Three.js orthographic viewport.'
        }
        if ($source -notmatch '(?is)networkSpeedTraceTimerCache\.push\s*\(\s*\{[^}]*direction[^}]*atMs') {
            throw 'The speed samples are not cached with a deterministic timeline before rendering.'
        }
        if ($source -notmatch '(?is)networkSpeedVisualizer\.beginReplay\s*\(\s*networkSpeedTraceTimerCache') {
            throw 'The speed chart is still drawn directly during acquisition instead of replaying the cached timeline.'
        }
        if ($source -notmatch '(?is)networkSpeedReplayDelayMs\s*=\s*1000') {
            throw 'The speed chart replay delay is not fixed to one second.'
        }
        if ($source -notmatch '(?is)performance\.now\(\)\s*-\s*networkSpeedTraceClockStartMs') {
            throw 'The speed samples are not timestamped against the measurement clock.'
        }
        $smoothPointStart = $source.IndexOf('function smoothNetworkSpeedPoint', [StringComparison]::Ordinal)
        $smoothPointEnd = $source.IndexOf('function smoothNetworkSpeedTraces', $smoothPointStart, [StringComparison]::Ordinal)
        if ($smoothPointStart -ge 0 -and $smoothPointEnd -gt $smoothPointStart) {
            $smoothPointRuntime = $source.Substring($smoothPointStart, $smoothPointEnd - $smoothPointStart)
            if ($smoothPointRuntime -match 'activeTrace\.positions\[\(activeTrace\.count\s*-\s*1\)') {
                throw 'The projectile animation rewrites the trace tail every frame instead of letting the line converge smoothly.'
            }
            if ($smoothPointRuntime -notmatch '(?is)networkSpeedPointVelocity|smoothDamp|spring') {
                throw 'The projectile animation has no velocity-aware frame-rate-independent damping.'
            }
        }
        $visualizerStart = $source.IndexOf('networkSpeedVisualizer = createNetworkSpeedVisualizer();', [StringComparison]::Ordinal)
        $visualizerStartEnd = $source.IndexOf('var downloadChunkBytes', $visualizerStart, [StringComparison]::Ordinal)
        if ($visualizerStart -ge 0 -and $visualizerStartEnd -gt $visualizerStart) {
            $visualizerStartRuntime = $source.Substring($visualizerStart, $visualizerStartEnd - $visualizerStart)
            if ($visualizerStartRuntime -notmatch '(?is)beginReplay\s*\(\s*networkSpeedTraceTimerCache\s*,\s*networkSpeedReplayDelayMs') {
                throw 'The delayed chart replay starts only after the measurement instead of one second after acquisition begins.'
            }
        }
        $visualUpdateStart = $source.IndexOf('function updateNetworkSpeedVisualizer', [StringComparison]::Ordinal)
        $visualUpdateEnd = $source.IndexOf('window.setNetworkSpeedVisualMode', $visualUpdateStart, [StringComparison]::Ordinal)
        if ($visualUpdateStart -ge 0 -and $visualUpdateEnd -gt $visualUpdateStart) {
            $visualUpdateRuntime = $source.Substring($visualUpdateStart, $visualUpdateEnd - $visualUpdateStart)
            if ($visualUpdateRuntime -match 'networkSpeedVisualizer\.addSample') {
                throw 'The acquisition callback mutates the Three.js trace directly instead of filling the timer cache.'
            }
        }

        foreach ($translationKey in @(
            'network_speed_median',
            'network_speed_cleanup_done',
            'network_speed_visual_particles',
            'network_latency_summary',
            'network_latency_jitter',
            'network_latency_unreachable'
        )) {
            $translationCount = [regex]::Matches($source, "(?m)^\s+$translationKey\s*:").Count
            if ($translationCount -ne 4) {
                throw "Expected four translations for $translationKey, found $translationCount."
            }
        }

        foreach ($marker in @(
            'id="networkLatencyControls"',
            'id="networkLatencyFilter"',
            'id="networkLatencySort"',
            'id="networkLatencySummary"',
            'renderNetworkLatencyMatrix',
            'LatencySamples',
            'PacketLossPct',
            'JitterMs'
        )) {
            if ($source.IndexOf($marker, [StringComparison]::Ordinal) -lt 0) {
                throw "Missing detailed network latency marker: $marker"
            }
        }
    }

    It 'runs the public network speed action through a warmed multi-stream sampling window' {
        $smokePath = Join-Path $PSScriptRoot 'network-speed-smoke.cjs'
        $output = & node $smokePath 2>&1 | Out-String
        if ($LASTEXITCODE -ne 0) {
            throw "Network speed smoke failed: $output"
        }
        if ($output -notmatch '20\.0 s, four parallel streams') {
            throw "Network speed smoke returned no success marker: $output"
        }
    }

    It 'exposes plural disk telemetry and a three-pillar performance benchmark' {
        $source = Get-Content -LiteralPath (Join-Path $projectRoot 'Diag-IT-UAA3-V3.ps1') -Raw
        foreach ($marker in @(
            'Analyses Disques',
            'Get-CimInstance Win32_LogicalDisk',
            '__SMART_JSON__',
            'Get-CimInstance Win32_VideoController',
            'ConfiguredClockSpeed',
            'HardwareInformation.MemorySize',
            'HardwareInformation.qwMemorySize',
            'ConvertTo-DiagGpuMemoryGB',
            'Invoke-DiagCpuBenchmark',
            'MedianMilliseconds',
            'WarmupMilliseconds',
            'PassCount',
            'id="gpuBenchCard"',
            'id="ramBenchCard"',
            'id="globalPerfCard"',
            '__GLOBAL_PERF_SCORE__'
        )) {
            if ($source.IndexOf($marker, [StringComparison]::Ordinal) -lt 0) {
                throw "Missing disk/performance benchmark marker: $marker"
            }
        }
        if ($source -match 'BENCHMARKS\s*&\s*SMART') {
            throw 'The benchmark tab still presents SMART as its primary section.'
        }
        if ($source -match '\$cpuScore\s*=\s*\[math\]::Max\(100') {
            throw 'The displayed CPU score is still clamped to a misleading 100-point floor.'
        }
        foreach ($gpuTestMarker in @(
            'id="gpuQuickTestBtn"',
            'id="gpuQuickTestResult"',
            'function runGpuQuickTest',
            'id="gpuQuickTestViewport"',
            'id="gpuQuickTestQuality"',
            'id="gpuQuickTestViewMode"',
            'id="gpuQuickTestProgress"',
            'id="gpuQuickTestMetrics"',
            'canvas.width = 256',
            'renderer.setSize(256, 256, false)',
            'requestAnimationFrame',
            'renderer.dispose()',
            'gpuQuickTestDurationMs = 10000',
            'gpuStressSeed = 0xD1A61001',
            'gpuStressVisualContract',
            'createGpuSeededRandom',
            'gpuStressProfiles',
            'THREE.InstancedMesh',
            'THREE.MeshPhysicalMaterial',
            'THREE.ShaderMaterial',
            'THREE.WebGLRenderTarget',
            'gpuPostProcessMaterial',
            'uSceneTexture',
            'chromaticOffset',
            'vignette',
            'THREE.ACESFilmicToneMapping',
            'EXT_disjoint_timer_query_webgl2',
            'gpuTimeSamples',
            'onePercentLow',
            'renderPassesPerFrame',
            'window.setGpuQuickTestViewMode',
            'window.getGpuQuickTestDebugState',
            'disposeGpuStressResources',
            'baseline',
            'overdraw'
        )) {
            if ($source.IndexOf($gpuTestMarker, [StringComparison]::Ordinal) -lt 0) {
                throw "Missing lightweight GPU stress-test marker: $gpuTestMarker"
            }
        }
        if ($source -match 'Aucun stress GPU n.?est exécuté') {
            throw 'The GPU card still claims that no stress test is executed.'
        }
        if ($source -match '(?i)ray[ -]?tracing') {
            throw 'The GPU test still markets rasterized effects as ray tracing.'
        }
    }

    It 'collects the latency snapshot at the start of the network stage and reuses it in the matrix' {
        $source = Get-Content -LiteralPath (Join-Path $projectRoot 'Diag-IT-UAA3-V3.ps1') -Raw
        $networkStage = $source.IndexOf("Get-DiagConsoleMessage -Language `$Lang -Key 'StageNetwork'", [StringComparison]::Ordinal)
        $networkAuditTail = $source.IndexOf('# --- 5.4 AUDIT RÉSEAU AVANCÉ', [StringComparison]::Ordinal)
        $snapshotMarker = $source.IndexOf('$networkLatencySnapshot =', $networkStage, [StringComparison]::Ordinal)

        if ($networkStage -lt 0 -or $networkAuditTail -lt 0 -or $snapshotMarker -lt 0 -or $snapshotMarker -gt $networkAuditTail) {
            throw 'The network latency snapshot is not initialized at the beginning of the network diagnostic stage.'
        }
        foreach ($marker in @(
            'Cloudflare = Measure-NetLatencyProfile',
            'Google = Measure-NetLatencyProfile',
            'Quad9 = Measure-NetLatencyProfile',
            'M365 = Measure-NetLatencyProfile',
            '$networkLatencySnapshot.GatewayByAddress',
            '$gatewayLatency = if ($networkLatencySnapshot.GatewayByAddress.ContainsKey($gwAddr))'
        )) {
            if ($source.IndexOf($marker, [StringComparison]::Ordinal) -lt 0) {
                throw "The initial network latency snapshot is missing its reuse marker: $marker"
            }
        }
    }

    It 'keeps the benchmark layout compact around the fixed GPU viewport' {
        $source = Get-Content -LiteralPath (Join-Path $projectRoot 'Diag-IT-UAA3-V3.ps1') -Raw
        foreach ($marker in @(
            '.benchmark-composition',
            '.benchmark-right-rail',
            '.benchmark-top-grid',
            '.benchmark-performance-grid',
            'class="benchmark-composition"',
            'class="benchmark-right-rail"',
            'class="benchmark-top-grid"',
            'class="benchmark-performance-grid"',
            'class="benchmark-gpu-card"',
            'grid-template-rows: repeat(2, minmax(0, 1fr))'
        )) {
            if ($source.IndexOf($marker, [StringComparison]::Ordinal) -lt 0) {
                throw "Missing compact benchmark layout marker: $marker"
            }
        }
    }

    It 'translates dynamic resolution phrases without leaving French suffixes' {
        $smokePath = Join-Path $PSScriptRoot 'translation-smoke.cjs'
        $output = & node $smokePath 2>&1 | Out-String
        if ($LASTEXITCODE -ne 0) {
            throw "Translation smoke failed: $output"
        }
        if ($output -notmatch 'FR/NL/EN/DE') {
            throw "Translation smoke returned no success marker: $output"
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

    It 'keeps the interactive launcher portable and delegates elevation to PowerShell' {
        $launcherPath = Join-Path $projectRoot 'Lancer Diagnostic IT UAA3.bat'
        $launcher = Get-Content -LiteralPath $launcherPath -Raw

        if ($launcher -notmatch '%~dp0') {
            throw 'The launcher does not resolve paths relative to its own directory.'
        }
        if ($launcher -match '(?i)C:\\Users\\') {
            throw 'The launcher contains a machine-specific user path.'
        }
        if ($launcher -match '(?i)net\s+session|Start-Process|Verb\s+RunAs') {
            throw 'The batch launcher still owns a duplicate and fragile UAC elevation path.'
        }
        if ($launcher -match '(?i)-NoElevate') {
            throw 'The batch launcher prevents the PowerShell engine from owning UAC elevation.'
        }
        if ($launcher -notmatch '(?is)DIAG_EXIT.*pause') {
            throw 'The batch launcher does not preserve a visible error path when PowerShell fails.'
        }
    }

    It 'registers dashboard protocols after the language choice and before the diagnostic starts' {
        $launcherPath = Join-Path $projectRoot 'Lancer Diagnostic IT UAA3.bat'
        $launcher = Get-Content -LiteralPath $launcherPath -Raw
        $runIndex = $launcher.IndexOf(':RUN_DIAG', [StringComparison]::OrdinalIgnoreCase)
        $registerIndex = $launcher.IndexOf('Register-DiagProtocol.ps1', [StringComparison]::OrdinalIgnoreCase)
        $mainIndex = $launcher.IndexOf('Diag-IT-UAA3-V3.ps1', [StringComparison]::OrdinalIgnoreCase)

        if ($runIndex -lt 0 -or $registerIndex -lt $runIndex -or $mainIndex -lt 0 -or $registerIndex -ge $mainIndex) {
            throw 'The launcher must register dashboard protocols after language selection and before starting the diagnostic.'
        }
        if ($launcher -notmatch '(?i)-File\s+"%~dp0Register-DiagProtocol\.ps1"') {
            throw 'The launcher does not invoke the protocol registration script portably.'
        }
        if ($launcher -notmatch '(?i)Register-DiagProtocol\.ps1[^\r\n]*-Quiet') {
            throw 'The launcher does not keep protocol registration output concise.'
        }
        $languageIndex = $launcher.IndexOf('DIAG_LANG=', [StringComparison]::OrdinalIgnoreCase)
        if ($languageIndex -lt 0 -or $languageIndex -ge $registerIndex) {
            throw 'The launcher does not select a language before registering dashboard protocols.'
        }
    }

    It 'keeps the batch language message dispatch compatible with cmd parsing' {
        $launcher = Get-Content -LiteralPath (Join-Path $projectRoot 'Lancer Diagnostic IT UAA3.bat') -Raw
        $runIndex = $launcher.IndexOf(':RUN_DIAG', [StringComparison]::OrdinalIgnoreCase)
        $runSection = $launcher.Substring($runIndex)

        if ($runSection -match '(?im)^\s*if\s+"%DIAG_LANG%"\s*==\s*"(?:FR|NL|EN|DE)"\s*\(') {
            throw 'The batch launcher uses parenthesized language blocks that are not reliable with cmd.exe parsing.'
        }
        foreach ($language in @('FR', 'NL', 'EN', 'DE')) {
            if ($runSection -notmatch ("(?im)^:REGISTER_{0}$" -f $language)) {
                throw "The batch launcher has no dedicated registration message label for $language."
            }
        }
    }

    It 'keeps the batch launcher byte-safe for cmd.exe' {
        $launcherPath = Join-Path $projectRoot 'Lancer Diagnostic IT UAA3.bat'
        $bytes = [IO.File]::ReadAllBytes($launcherPath)
        if (@($bytes | Where-Object { $_ -gt 0x7F }).Count -gt 0) {
            throw 'The batch launcher contains non-ASCII bytes; cmd.exe can corrupt subsequent commands without a Unicode BOM.'
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
            if ($launcherSource -notmatch ('(?i)(?:-Lang\s+{0}|DIAG_LANG={0})' -f $language)) {
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

    It 'exposes a unique wireframe SVG icon for every navigation tab and a central emoji migration' {
        $scriptSource = Get-Content -LiteralPath (Join-Path $projectRoot 'Diag-IT-UAA3-V3.ps1') -Raw
        if ($scriptSource -notmatch 'id="diagIconSprite"') {
            throw 'The report does not contain the inline wireframe SVG sprite.'
        }
        $expectedIcons = @(
            'overview', 'health', 'cve', 'network', 'disks', 'startup', 'belgian', 'benchmarks',
            'security', 'foss', 'journal', 'profiles', 'shortcuts', 'export', 'docs', 'archive', 'relaunch', 'print'
        )
        foreach ($iconName in $expectedIcons) {
            if ($scriptSource -notmatch ('symbol id="diag-icon-{0}"' -f $iconName)) {
                throw "Missing wireframe tab icon: $iconName"
            }
        }
        $tabIconBindings = [regex]::Matches($scriptSource, 'data-icon="([a-z-]+)"') |
            ForEach-Object { $_.Groups[1].Value } |
            Select-Object -Unique
        foreach ($iconName in $expectedIcons) {
            if ($tabIconBindings -notcontains $iconName) {
                throw "Navigation tab is not bound to a unique wireframe icon: $iconName"
            }
        }
        if ($scriptSource -notmatch 'function applyWireframeIcons') {
            throw 'The report has no central visible-text emoji migration.'
        }
        if ($scriptSource -notmatch 'MutationObserver') {
            throw 'Dynamic report cards are not covered by the wireframe icon migration.'
        }
        if ($scriptSource -notmatch 'button\.lastElementChild !== icon') {
            throw 'Tab icon binding does not guard against duplicate/reordered icons.'
        }
        if ($scriptSource -notmatch 'cleanOptionText !== optionText') {
            throw 'Select options are rewritten unconditionally and may cause an observer loop.'
        }
        if ($scriptSource -notmatch 'data-icon="overview"[^>]*>■ BILAN') {
            throw 'Navigation tabs no longer preserve the square bullet before their label.'
        }
        if ($scriptSource -notmatch "tabBtns\[i\]\.innerText = '■ ' \+") {
            throw 'Translated tab labels do not preserve the square bullet.'
        }
        if ($scriptSource -notmatch "'⌨': 'shortcuts'" -or $scriptSource -notmatch '\\u2300-\\u23FF') {
            throw 'The keyboard pictogram is not covered by the wireframe migration.'
        }
    }

    It 'keeps the Windows shortcuts module compact and documents PowerToys with official links' {
        $scriptSource = Get-Content -LiteralPath (Join-Path $projectRoot 'Diag-IT-UAA3-V3.ps1') -Raw
        if ($scriptSource -notmatch 'shortcuts-compact') {
            throw 'The Windows shortcuts module has no compact layout contract.'
        }
        if ($scriptSource -notmatch 'id="powertoysBrief"') {
            throw 'The PowerToys column has no dedicated product brief.'
        }
        if ($scriptSource -notmatch 'https://learn\.microsoft\.com/fr-fr/windows/powertoys/install') {
            throw 'The PowerToys brief is missing the official Microsoft installation documentation link.'
        }
        if ($scriptSource -notmatch 'https://github\.com/microsoft/PowerToys') {
            throw 'The PowerToys brief is missing the official open-source repository link.'
        }
        if ($scriptSource -notmatch 'winget install Microsoft\.PowerToys') {
            throw 'The PowerToys brief is missing its copyable WinGet installation command.'
        }
    }

    It 'exposes a country-adaptive business catalogue with an explicit Belgian official scope' {
        $scriptSource = Get-Content -LiteralPath (Join-Path $projectRoot 'Diag-IT-UAA3-V3.ps1') -Raw
        if ($scriptSource -notmatch 'id="businessCountrySelect"') {
            throw 'The business software section has no country selector.'
        }
        foreach ($country in @('be', 'fr', 'uk', 'de', 'es', 'it', 'pt')) {
            if ($scriptSource -notmatch ('value="{0}"' -f $country)) {
                throw "The country selector is missing the whitelist entry: $country"
            }
        }
        if ($scriptSource -notmatch 'function changeBusinessCountry') {
            throw 'Country changes are not routed through a dedicated whitelist function.'
        }
        if ($scriptSource -notmatch 'businessCountryCatalogs') {
            throw 'The report has no country-adaptive business catalogue data.'
        }
        if ($scriptSource -notmatch 'id="businessCatalogMeta"') {
            throw 'The business catalogue has no visible scope/source legend.'
        }
        foreach ($officialUrl in @(
            'https://eid\.belgium\.be/en',
            'https://www\.csam\.be/en/index\.html',
            'https://finances\.belgium\.be',
            'https://www\.nbb\.be'
        )) {
            if ($scriptSource -notmatch $officialUrl) {
                throw "The Belgian official catalogue is missing a verified source: $officialUrl"
            }
        }
        if ($scriptSource -notmatch 'Portail officiel' -or $scriptSource -notmatch 'Référence éditeur') {
            throw 'Official portals and professional editor references are not distinguished in the catalogue.'
        }
        if ($scriptSource -notmatch '<strong>7</strong>[\s\S]{0,800}Catalogue national') {
            throw 'Documentation module 7 does not explain the adaptive national catalogue.'
        }
    }

    It 'keeps KPI cards centered with a restrained neon accent and soft FOSS titles' {
        $scriptSource = Get-Content -LiteralPath (Join-Path $projectRoot 'Diag-IT-UAA3-V3.ps1') -Raw

        foreach ($requiredStyle in @(
            'align-items: center;',
            'text-align: center;',
            '.card::before',
            '.card:hover::before',
            '--card-accent:',
            '.tab-btn::before',
            '.btn-primary::before',
            '.dashboard-neon-button:hover::before',
            '--ui-cyan:',
            '--ui-frame:',
            'border-left: 4px solid var(--ui-cyan);',
            '.foss-card-title',
            '.foss-card-description'
        )) {
            if ($scriptSource -notmatch [regex]::Escape($requiredStyle)) {
                throw "Missing KPI/FOSS visual contract: $requiredStyle"
            }
        }

        if ($scriptSource -match '\.card-tot\s*\{\s*border-top') {
            throw 'KPI cards still use the hard coloured top border instead of the diffused neon accent.'
        }
        if ($scriptSource -match 'font-weight:900; color:#34d399') {
            throw 'FOSS titles still rely on the harsh hard-coded green/white contrast.'
        }
        foreach ($neonMapping in @(
            '[data-icon="overview"] { --button-accent: var(--neon-cyan); }',
            '[data-icon="health"] { --button-accent: var(--neon-emerald); }',
            '[data-icon="foss"] { --button-accent: var(--neon-purple); }',
            '[data-icon="cve"] { --button-accent: var(--neon-rose); }'
        )) {
            if ($scriptSource -notmatch [regex]::Escape($neonMapping)) {
                throw "Missing colour-coded dashboard button contract: $neonMapping"
            }
        }
    }

    It 'documents every dashboard module with a concise multi-line operational guide' {
        $scriptSource = Get-Content -LiteralPath (Join-Path $projectRoot 'Diag-IT-UAA3-V3.ps1') -Raw
        $readmeSource = Get-Content -LiteralPath (Join-Path $projectRoot 'README.md') -Raw
        $documentedModules = [regex]::Matches(
            $scriptSource,
            '(?s)<td><strong>(?<id>1[0-8]|[1-9])</strong></td>.*?<td class="module-doc-detail">(?<detail>.*?)</td>'
        )

        if ($documentedModules.Count -ne 18) {
            throw "Expected 18 detailed dashboard documentation entries, found $($documentedModules.Count)."
        }

        foreach ($entry in $documentedModules) {
            $lineCount = [regex]::Matches($entry.Groups['detail'].Value, 'class="module-doc-line"').Count
            if ($lineCount -lt 3 -or $lineCount -gt 4) {
                throw "Dashboard module $($entry.Groups['id'].Value) must have 3 or 4 documentation lines; found $lineCount."
            }
        }

        $readmeRows = [regex]::Matches($readmeSource, '(?m)^\| \*\*(?<id>1[0-8]|[1-9])\*\* \|.*$')
        if ($readmeRows.Count -ne 18) {
            throw "Expected 18 README dashboard documentation entries, found $($readmeRows.Count)."
        }
        foreach ($row in $readmeRows) {
            if ([regex]::Matches($row.Value, '<br>').Count -lt 2) {
                throw "README module $($row.Groups['id'].Value) must have at least three concise documentation lines."
            }
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
            'Diag-Antivirus.ps1',
            'Diag-Benchmark.ps1',
            'Diag-HardwareTelemetry.ps1',
            'Diag-SmartTelemetry.ps1',
            'Register-DiagProtocol.ps1',
            'Run-DiagProtocol.ps1',
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
