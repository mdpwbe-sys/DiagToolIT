const path = require('path');
const { pathToFileURL } = require('url');
const { chromium } = require('playwright');

async function main() {
  const reportPath = process.argv[2];
  const expectLiveData = process.argv.includes('--expect-live-data');
  const expectAntivirusAlert = process.argv.includes('--expect-antivirus-alert');
  const languageIndex = process.argv.indexOf('--lang');
  const expectedLanguage = languageIndex >= 0 ? process.argv[languageIndex + 1] : 'en';
  const expectedTitles = {
    fr: 'CENTRE DE DIAGNOSTIC',
    nl: 'IT-DIAGNOSE-',
    en: 'IT DIAGNOSTIC',
    de: 'IT-DIAGNOSE-',
  };
  const expectedAntivirusNames = {
    fr: 'Protection Antivirus Désactivée',
    nl: 'Antivirusbescherming Uitgeschakeld',
    en: 'Antivirus Protection Disabled',
    de: 'Virenschutz Deaktiviert',
  };
  if (!reportPath) {
    throw new Error('Usage: node tests/browser-smoke.cjs <report.html> [--lang fr|nl|en|de]');
  }
  if (!Object.prototype.hasOwnProperty.call(expectedTitles, expectedLanguage)) {
    throw new Error(`Unsupported expected language: ${expectedLanguage}`);
  }

  const browser = await chromium.launch({ headless: true });
  const page = await browser.newPage({ viewport: { width: 1440, height: 1000 } });
  const pageErrors = [];
  const outboundRequests = [];

  await page.route(/^https?:\/\//, async (route) => {
    outboundRequests.push(route.request().url());
    await route.abort();
  });

  page.on('pageerror', (error) => pageErrors.push(error.message));
  page.on('console', (message) => {
    if (message.type() === 'error') pageErrors.push(message.text());
  });

  try {
    await page.goto(pathToFileURL(path.resolve(reportPath)).href, {
      waitUntil: 'domcontentloaded',
    });
    await page.waitForTimeout(750);

    const title = await page.locator('.cockpit-title h1').textContent();
    if (!title || !title.includes(expectedTitles[expectedLanguage])) {
      throw new Error(
        `The requested ${expectedLanguage.toUpperCase()} language was not applied: ${title || '<empty>'}`,
      );
    }

    const tabCount = await page.locator('.tabs .tab-btn').count();
    if (tabCount < 15) {
      throw new Error(`Expected at least 15 navigation actions, found ${tabCount}.`);
    }

    const languageValue = await page.locator('#langSelect').inputValue();
    if (languageValue !== expectedLanguage) {
      throw new Error(`Expected the ${expectedLanguage} selector value, found ${languageValue}.`);
    }

    const requestedDiagnosticProtocol = await page.evaluate(() => {
      let requestedUri = null;
      window.launchLocalProtocol = (uri) => {
        requestedUri = uri;
      };
      document.getElementById('btnRunDiagTab').click();
      return requestedUri;
    });
    const expectedProtocol = `diagit://run?lang=${expectedLanguage.toUpperCase()}`;
    if (requestedDiagnosticProtocol !== expectedProtocol) {
      throw new Error(
        `Expected ${expectedProtocol}, found ${requestedDiagnosticProtocol || '<none>'}.`,
      );
    }

    await page.locator('.tab-btn[onclick*="tab-archive"]').click();
    const archiveTitle = await page.locator('#archiveTitle').textContent();
    if (!archiveTitle || !archiveTitle.includes('Chronologie')) {
      throw new Error('The logs/archive tab does not expose the diagnostic timeline.');
    }
    const archiveRows = await page.locator('#archiveLogBody tr').count();
    const archiveEmptyVisible = await page.locator('#archiveLogEmpty').isVisible();
    if (archiveRows === 0 && !archiveEmptyVisible) {
      throw new Error('The logs/archive tab has neither history rows nor an empty-state message.');
    }

    await page.locator('.tab-btn[onclick*="tab-benchmarks"]').click();
    for (const cardId of ['gpuBenchCard', 'ramBenchCard', 'globalPerfCard']) {
      const card = page.locator(`#${cardId}`);
      if ((await card.count()) !== 1 || !(await card.isVisible())) {
        throw new Error(`The benchmark card ${cardId} is missing from the dashboard.`);
      }
    }
    for (const controlId of ['gpuQuickTestQuality', 'gpuQuickTestViewMode', 'gpuQuickTestProgress', 'gpuQuickTestMetrics']) {
      if ((await page.locator(`#${controlId}`).count()) !== 1) {
        throw new Error(`The GPU benchmark control ${controlId} is missing.`);
      }
    }
    await page.locator('#gpuQuickTestBtn').click();
    await page.waitForTimeout(300);
    await page.locator('#gpuQuickTestViewMode').selectOption('baseline');
    let gpuDebug = await page.evaluate(() => window.getGpuQuickTestDebugState());
    if (!gpuDebug.running || !gpuDebug.pbrVisible || gpuDebug.vfxVisible) {
      throw new Error(`The PBR baseline view is not isolated: ${JSON.stringify(gpuDebug)}`);
    }
    await page.locator('#gpuQuickTestViewMode').selectOption('overdraw');
    gpuDebug = await page.evaluate(() => window.getGpuQuickTestDebugState());
    if (!gpuDebug.running || gpuDebug.pbrVisible || !gpuDebug.vfxVisible) {
      throw new Error(`The overdraw view is not isolated: ${JSON.stringify(gpuDebug)}`);
    }
    await page.locator('#gpuQuickTestViewMode').selectOption('final');
    await page.waitForTimeout(10300);
    const gpuQuickResult = await page.locator('#gpuQuickTestResult').textContent();
    if (!gpuQuickResult || gpuQuickResult.includes('Test non lancé') || gpuQuickResult.includes('en cours')) {
      throw new Error(`The lightweight GPU test did not complete: ${gpuQuickResult || '<empty>'}`);
    }
    gpuDebug = await page.evaluate(() => window.getGpuQuickTestDebugState());
    if (gpuDebug.running || !gpuDebug.lastMetrics || gpuDebug.lastMetrics.onePercentLow < 0) {
      throw new Error(`The GPU benchmark did not expose its final metrics: ${JSON.stringify(gpuDebug)}`);
    }
    await page.locator('.tab-btn[onclick*="tab-disk-audit"]').click();
    if ((await page.locator('#diskVolumesContainer').count()) !== 1 || (await page.locator('#smartDisksContainer').count()) !== 1) {
      throw new Error('The disk analyses tab does not expose volumes and SMART telemetry containers.');
    }

    await page.locator('.tab-btn[onclick*="tab-network-audit"]').click();
    if ((await page.locator('#networkSpeedTestCard').count()) !== 1 || (await page.locator('#networkSpeedTestBtn').count()) !== 1) {
      throw new Error('The network tab does not expose the explicit speed-test card.');
    }
    for (const controlId of ['networkSpeedCanvas', 'networkSpeedVisualMode', 'networkSpeedQuality', 'networkSpeedLiveDownloadValue', 'networkSpeedLiveUploadValue', 'networkLatencyFilter', 'networkLatencySort']) {
      if ((await page.locator(`#${controlId}`).count()) !== 1) {
        throw new Error(`The detailed network control ${controlId} is missing.`);
      }
    }
    for (const chartId of ['networkSpeedLegend', 'networkSpeedScale', 'networkSpeedAxisY', 'networkSpeedAxisX', 'networkSpeedDownloadSwatch', 'networkSpeedUploadSwatch']) {
      if ((await page.locator(`#${chartId}`).count()) !== 1) {
        throw new Error(`The speed chart reference ${chartId} is missing.`);
      }
    }
    if ((await page.locator('#networkSpeedLegend .speed-legend-item').count()) !== 2 || (await page.locator('#networkSpeedAxisY span').count()) !== 5 || (await page.locator('#networkSpeedAxisX span').count()) !== 3) {
      throw new Error('The speed chart legend or measurement axes are incomplete.');
    }
    if ((await page.locator('#networkLatencyGrid .latency-card').count()) !== 5) {
      throw new Error('The synthetic latency matrix does not expose its five detailed endpoints.');
    }
    await page.locator('#networkLatencyFilter').selectOption('dns');
    if ((await page.locator('#networkLatencyGrid .latency-card').count()) !== 3) {
      throw new Error('The DNS latency filter does not isolate the three public resolvers.');
    }
    await page.locator('#networkLatencyFilter').selectOption('all');
    await page.locator('#networkSpeedTestBtn').click();
    await page.waitForTimeout(150);
    const speedTestState = await page.evaluate(() => window.networkSpeedTestState || null);
    if (speedTestState !== 'error' && speedTestState !== 'unavailable') {
      throw new Error(`The speed test did not enter a handled state after the request was blocked: ${speedTestState || '<none>'}.`);
    }
    if (!outboundRequests.some((url) => url.includes('speed.cloudflare.com'))) {
      throw new Error('The explicit speed-test click did not target the fixed Cloudflare endpoint.');
    }

    if (expectAntivirusAlert) {
      const resolutionAlert = page.locator('#tab-resolution .res-card.res-card-err');
      if ((await resolutionAlert.count()) !== 1 || !(await resolutionAlert.isVisible())) {
        throw new Error('The Defender-disabled alert is missing from the visible resolution card.');
      }
      const resolutionText = await resolutionAlert.innerText();
      if (!resolutionText.includes(expectedAntivirusNames[expectedLanguage])) {
        throw new Error(`The antivirus card was not translated: ${resolutionText}`);
      }

      await page.locator('.tab-btn[onclick*="tab-journal"]').click();
      await page.locator('.filter-btn[onclick*="ISSUES"]').click();
      const journalAlert = page.locator('#diagTable tbody tr[data-status="ERROR"]');
      if ((await journalAlert.count()) !== 1 || !(await journalAlert.isVisible())) {
        throw new Error('The Defender-disabled alert is hidden from the journal issues filter.');
      }
      const journalText = await journalAlert.innerText();
      if (!journalText.includes(expectedAntivirusNames[expectedLanguage])) {
        throw new Error(`The antivirus journal row was not translated: ${journalText}`);
      }
    }

    const threeRevision = await page.evaluate(() => window.THREE?.REVISION || null);
    if (threeRevision !== '128') {
      throw new Error(`Expected embedded Three.js r128, found ${threeRevision || '<missing>'}.`);
    }

    const unexpectedOutboundRequests = outboundRequests.filter((url) => !url.includes('speed.cloudflare.com'));
    if (unexpectedOutboundRequests.length > 0) {
      throw new Error(`Unexpected outbound requests:\n${unexpectedOutboundRequests.join('\n')}`);
    }

    await page.locator('.tab-btn[onclick*="tab-cve"]').click();
    const updateButton = page.locator('#btnUpdateCve');
    await updateButton.waitFor({ state: 'visible' });
    const requestedProtocol = await page.evaluate(() => {
      let requestedUri = null;
      window.confirm = () => true;
      window.launchLocalProtocol = (uri) => {
        requestedUri = uri;
      };
      document.getElementById('btnUpdateCve').click();
      return requestedUri;
    });
    if (requestedProtocol !== 'diagit-cve://update') {
      throw new Error(`Expected the CVE update protocol, found ${requestedProtocol || '<none>'}.`);
    }

    if (expectLiveData) {
      const liveDataState = await page.evaluate(() => ({
        adapters: window.networkAuditData?.Adapters?.length || 0,
        users: window.securityAuditData?.Users?.length || 0,
        apps: window.belgianData?.Apps?.length || 0,
        securityType: Array.isArray(window.securityAuditData)
          ? 'array'
          : typeof window.securityAuditData,
        securityKeys:
          window.securityAuditData && typeof window.securityAuditData === 'object'
            ? Object.keys(window.securityAuditData)
            : [],
        belgianType: Array.isArray(window.belgianData)
          ? 'array'
          : typeof window.belgianData,
        belgianKeys:
          window.belgianData && typeof window.belgianData === 'object'
            ? Object.keys(window.belgianData)
            : [],
      }));
      if (liveDataState.adapters === 0 || liveDataState.apps === 0) {
        throw new Error(`Live diagnostic data was not parsed: ${JSON.stringify(liveDataState)}`);
      }
    }

    if (pageErrors.length > 0) {
      throw new Error(`Browser errors:\n${pageErrors.join('\n')}`);
    }
  } finally {
    await browser.close();
  }
}

main().catch((error) => {
  console.error(error.stack || error.message);
  process.exit(1);
});
