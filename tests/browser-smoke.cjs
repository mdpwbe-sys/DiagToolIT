const path = require('path');
const { pathToFileURL } = require('url');
const { chromium } = require('playwright');

async function main() {
  const reportPath = process.argv[2];
  const expectLiveData = process.argv.includes('--expect-live-data');
  if (!reportPath) {
    throw new Error('Usage: node tests/browser-smoke.cjs <report.html>');
  }

  const browser = await chromium.launch({ headless: true });
  const page = await browser.newPage({ viewport: { width: 1440, height: 1000 } });
  const pageErrors = [];

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
    if (!title || !title.includes('IT DIAGNOSTIC')) {
      throw new Error(`The requested EN language was not applied: ${title || '<empty>'}`);
    }

    const tabCount = await page.locator('.tabs .tab-btn').count();
    if (tabCount < 15) {
      throw new Error(`Expected at least 15 navigation actions, found ${tabCount}.`);
    }

    const languageValue = await page.locator('#langSelect').inputValue();
    if (languageValue !== 'en') {
      throw new Error(`Expected the EN selector value, found ${languageValue}.`);
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
