const fs = require('fs');
const path = require('path');
const vm = require('vm');

const projectRoot = path.resolve(__dirname, '..');
const source = fs.readFileSync(path.join(projectRoot, 'Diag-IT-UAA3-V3.ps1'), 'utf8');
const startMarker = "var networkSpeedEndpointOrigin = 'https://' + 'speed.cloudflare.com';";
const endMarker = "setNetworkSpeedStatus('idle');";
const start = source.indexOf(startMarker);
const end = source.indexOf(endMarker, start);

if (start < 0 || end < 0) {
  throw new Error('Unable to isolate the public network speed-test runtime.');
}

const runtimeSource = source.slice(start, end + endMarker.length);
let clockMs = 0;
let requestCount = 0;
const elements = {
  networkSpeedTestBtn: { disabled: false, style: {}, innerText: '' },
  networkSpeedTestResult: { innerText: '' },
  networkSpeedTestStatus: { innerText: '', style: {} },
  networkSpeedLiveDownloadValue: { innerText: '—' },
  networkSpeedLiveUploadValue: { innerText: '—' },
  networkSpeedCanvas: null,
  networkSpeedVisualMode: { value: 'final' },
  networkSpeedQuality: { value: 'auto' },
};

const context = {
  AbortController,
  Date,
  Math,
  Promise,
  Uint8Array,
  clearTimeout,
  console,
  currentLang: 'en',
  document: {
    getElementById(id) {
      return elements[id] || null;
    },
  },
  fetch(url) {
    requestCount += 1;
    clockMs += 250;
    const match = /[?&]bytes=(\d+)/.exec(url);
    const bytes = match ? Number(match[1]) : 0;
    return Promise.resolve({
      ok: true,
      status: 200,
      arrayBuffer: () => Promise.resolve({ byteLength: bytes }),
    });
  },
  performance: {
    now: () => clockMs,
  },
  setTimeout,
  translations: {
    en: {
      network_speed_idle: 'idle',
      network_speed_running: 'running',
      network_speed_done: 'done',
      network_speed_unavailable: 'unavailable',
      network_speed_error: 'error',
      network_speed_download: 'Download',
      network_speed_upload: 'Upload',
      network_speed_elapsed: 'Elapsed',
      network_speed_data: 'Data transferred',
    },
  },
};
context.window = context;
vm.createContext(context);
new vm.Script(runtimeSource, { filename: 'network-speed-runtime.js' }).runInContext(context);

async function main() {
  context.window.runNetworkSpeedTest(elements.networkSpeedTestBtn);
  for (let attempt = 0; attempt < 100 && elements.networkSpeedTestBtn.disabled; attempt += 1) {
    await new Promise((resolve) => setImmediate(resolve));
  }

  const result = context.networkSpeedLastResult;
  if (context.window.networkSpeedTestState !== 'done' || !result) {
    throw new Error(`Speed test did not complete: ${context.window.networkSpeedTestState || '<none>'}`);
  }
  if (result.elapsed !== '20.0') {
    throw new Error(`Expected a 20.0 s measurement fixture, found ${result.elapsed || '<empty>'} s.`);
  }
  if (requestCount < 66) {
    throw new Error(`Expected sustained four-stream sampling after warm-up, found only ${requestCount} requests.`);
  }
  if (!Number.isFinite(parseFloat(result.data)) || parseFloat(result.data) < 30) {
    throw new Error(`Expected transferred data to be reported, found ${result.data || '<empty>'}.`);
  }
  if (!elements.networkSpeedTestResult.innerText.includes('Data transferred')) {
    throw new Error('The visible result does not disclose transferred data.');
  }
  if (!/Mbps/.test(elements.networkSpeedLiveDownloadValue.innerText) || !/Mbps/.test(elements.networkSpeedLiveUploadValue.innerText)) {
    throw new Error(`The top-left speed summary is incomplete: down=${elements.networkSpeedLiveDownloadValue.innerText}, up=${elements.networkSpeedLiveUploadValue.innerText}`);
  }
  for (const direction of ['downloadStats', 'uploadStats']) {
    const stats = result[direction];
    if (!stats || !Number.isFinite(stats.medianMbps) || !Number.isFinite(stats.p10Mbps) || !Number.isFinite(stats.p90Mbps)) {
      throw new Error(`Missing robust ${direction} statistics.`);
    }
    if (stats.sampleCount < 8) {
      throw new Error(`Expected at least eight ${direction} samples, found ${stats.sampleCount}.`);
    }
  }
  const debugState = context.window.getNetworkSpeedDebugState();
  if (debugState.activeRequests !== 0 || !debugState.visualizerDisposed || debugState.targetFps !== 60 || debugState.traceCacheSamples < 16 || debugState.replayDelayMs !== 1000) {
    throw new Error(`Network runtime was not fully released: ${JSON.stringify(debugState)}`);
  }
  console.log('Network speed fixture: 20.0 s, four parallel streams, robust samples, clean disposal.');
}

main().catch((error) => {
  console.error(error.stack || error.message);
  process.exitCode = 1;
});
