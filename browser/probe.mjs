import { constants } from 'node:fs';
import { access, readdir } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { performance } from 'node:perf_hooks';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { createRequire } from 'node:module';

export const BODY_LIMIT = 2 * 1024 * 1024;

export function parseArguments(args) {
  const options = { timeoutMs: 30_000, headed: false, waitMs: 0, headers: {} };
  const seen = new Set();
  for (let index = 0; index < args.length; index += 1) {
    const name = args[index];
    if (!['--url', '--timeout-ms', '--executable', '--headed', '--network-proxy', '--header', '--wait-seconds', '--check', '--doctor'].includes(name)) {
      throw new Error(`Unknown option: ${name}`);
    }
    if (seen.has(name) && name !== '--header') throw new Error(`Duplicate option: ${name}`);
    seen.add(name);
    if (name === '--check' || name === '--doctor') {
      options.check = true;
      continue;
    }
    if (name === '--headed') {
      options.headed = true;
      continue;
    }
    const value = args[++index];
    if (!value || value.startsWith('--')) throw new Error(`Missing value for ${name}`);
    if (name === '--url') options.url = value;
    if (name === '--network-proxy') options.networkProxy = value;
    if (name === '--header') {
      const [header, contents] = parseHeader(value);
      options.headers[header] = options.headers[header] === undefined ? contents : `${options.headers[header]}${header === 'cookie' ? '; ' : ', '}${contents}`;
    }
    if (name === '--wait-seconds') {
      const seconds = Number(value);
      if (!/^\d+(?:\.\d+)?$/.test(value) || !Number.isFinite(seconds) || seconds < 0 || seconds > 2147483) {
        throw new Error('--wait-seconds must be a finite nonnegative number');
      }
      options.waitMs = Math.round(seconds * 1000);
    }
    if (name === '--executable') options.executable = value;
    if (name === '--timeout-ms') {
      if (!/^\d+$/.test(value)) throw new Error('--timeout-ms must be a positive integer');
      options.timeoutMs = Number(value);
      if (!Number.isSafeInteger(options.timeoutMs) || options.timeoutMs < 1
        || options.timeoutMs > 2_147_483_647) {
        throw new Error('--timeout-ms must be between 1 and 2147483647');
      }
    }
  }
  if (options.networkProxy) parseNetworkProxy(options.networkProxy);
  if (options.check) return options;
  if (!options.url) throw new Error('--url is required');
  let url;
  try { url = new URL(options.url); } catch { throw new Error('--url must be a valid URL'); }
  if (!['http:', 'https:'].includes(url.protocol)) {
    throw new Error('--url must use HTTP or HTTPS');
  }
  if (url.username || url.password) {
    throw new Error('Credentials in URLs are not supported');
  }
  options.url = url.href;
  return options;
}


export function parseHeader(input) {
  const separator = input.indexOf(':');
  if (separator <= 0) throw new Error('--header must use NAME: VALUE');
  const name = input.slice(0, separator).trim().toLowerCase();
  const value = input.slice(separator + 1).trim();
  if (!/^[!#$%&'*+.^_`|~0-9a-z-]+$/.test(name) || /[\0-\x08\x0a-\x1f\x7f]/.test(value)) {
    throw new Error('--header contains an invalid name or value');
  }
  if (['host', 'content-length', 'transfer-encoding', 'connection', 'proxy-authorization', 'proxy-connection', 'upgrade', 'trailer', 'te'].includes(name)) {
    throw new Error(`--header cannot override ${name}`);
  }
  return [name, value];
}

export function parseNetworkProxy(input) {
  let parsed;
  try { parsed = new URL(input); } catch { throw new Error('Network proxy must be a valid HTTP or HTTPS URL'); }
  if (!['http:', 'https:'].includes(parsed.protocol)) throw new Error('Chromium network proxy supports HTTP or HTTPS only');
  if (!parsed.hostname || (parsed.pathname !== '/' && parsed.pathname !== '') || parsed.search || parsed.hash) {
    throw new Error('Network proxy must specify only a host, optional port, and optional credentials');
  }
  let username, password;
  try { username = decodeURIComponent(parsed.username); password = decodeURIComponent(parsed.password); }
  catch { throw new Error('Network proxy credentials contain invalid percent encoding'); }
  return { server: `${parsed.protocol}//${parsed.host}`, ...(username ? { username, password } : {}) };
}

export function safeError(error, networkProxy) {
  let message = String(error.message || error).split('\n')[0].replace(/https?:\/\/[^\s)]+/g, '[URL]');
  if (networkProxy) {
    try {
      const proxy = new URL(networkProxy);
      for (const secret of [proxy.username, proxy.password, decodeURIComponent(proxy.username), decodeURIComponent(proxy.password)]) {
        if (secret) message = message.split(secret).join('[redacted]');
      }
    } catch { /* Invalid proxy errors contain no supplied value. */ }
  }
  return message;
}

export async function checkBrowser(options = {}) {
  const result = { available: false, executable: null, version: null, playwright_available: false, playwright_version: null, chromium_available: false, chromium_executable: null, error: null };
  try {
    const { chromium } = await import('playwright-core');
    result.playwright_available = true;
    result.playwright_version = createRequire(import.meta.url)('playwright-core/package.json').version;
    result.executable = await discoverChromium({ executable: options.executable, defaultPath: chromium.executablePath() });
    result.chromium_executable = result.executable;
    const { stdout } = await promisify(execFile)(result.executable, ['--version'], { timeout: 5000, maxBuffer: 8192 });
    result.version = stdout.trim();
    result.available = true;
    result.chromium_available = true;
  } catch (error) { result.error = safeError(error); }
  return result;
}

export function chromiumCacheRoots({ env = process.env, home = os.homedir(), platform = process.platform } = {}) {
  const roots = [];
  if (env.PLAYWRIGHT_BROWSERS_PATH && env.PLAYWRIGHT_BROWSERS_PATH !== '0') {
    roots.push(path.resolve(env.PLAYWRIGHT_BROWSERS_PATH));
  }
  if (platform === 'win32') roots.push(path.join(env.LOCALAPPDATA || path.join(home, 'AppData', 'Local'), 'ms-playwright'));
  else if (platform === 'darwin') roots.push(path.join(home, 'Library', 'Caches', 'ms-playwright'));
  else roots.push(path.join(env.XDG_CACHE_HOME || path.join(home, '.cache'), 'ms-playwright'));
  return [...new Set(roots)];
}

async function isExecutable(candidate) {
  try {
    await access(candidate, process.platform === 'win32' ? constants.F_OK : constants.X_OK);
    return true;
  } catch { return false; }
}

export async function discoverChromium({ executable, env = process.env, defaultPath, cacheRoots = chromiumCacheRoots({ env }), headed = false } = {}) {
  const requested = executable || env.FINGERPRINT_LAB_CHROMIUM;
  if (requested) {
    const candidate = path.resolve(requested);
    if (!await isExecutable(candidate)) throw new Error(`Chromium executable is missing or not executable: ${candidate}`);
    return candidate;
  }
  if (defaultPath && await isExecutable(defaultPath)) return defaultPath;
  const candidates = [];
  for (const root of cacheRoots) {
    let directories;
    try { directories = await readdir(root, { withFileTypes: true }); } catch { continue; }
    for (const directory of directories) {
      const match = /^(chromium|chromium_headless_shell)-(\d+)$/.exec(directory.name);
      if (!directory.isDirectory() || !match || (headed && match[1] !== 'chromium')) continue;
      const full = match[1] === 'chromium';
      const names = full
        ? ['chrome-linux64/chrome', 'chrome-linux/chrome', 'chrome-mac-arm64/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing', 'chrome-mac-x64/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing', 'chrome-mac/Chromium.app/Contents/MacOS/Chromium', 'chrome-win64/chrome.exe', 'chrome-win/chrome.exe']
        : ['chrome-headless-shell-linux64/chrome-headless-shell', 'chrome-linux/headless_shell', 'chrome-headless-shell-mac-arm64/chrome-headless-shell', 'chrome-headless-shell-mac-x64/chrome-headless-shell', 'chrome-headless-shell-win64/chrome-headless-shell.exe', 'chrome-win/headless_shell.exe'];
      for (const name of names) {
        candidates.push({ path: path.join(root, directory.name, name), full, revision: Number(match[2]) });
      }
    }
  }
  candidates.sort((a, b) => Number(b.full) - Number(a.full) || b.revision - a.revision);
  for (const candidate of candidates) {
    if (await isExecutable(candidate.path)) return candidate.path;
  }
  throw new Error('No installed Chromium found. Supply --executable or set FINGERPRINT_LAB_CHROMIUM. This probe does not download browsers.');
}

export function normalizeProtocol(protocol) {
  return ({ 'http/1.0': 'HTTP/1.0', 'http/1.1': 'HTTP/1.1', h2: 'HTTP/2', h3: 'HTTP/3' })[protocol?.toLowerCase()] || 'unknown';
}

export function boundedText(bytes) {
  const text = bytes.subarray(0, BODY_LIMIT).toString('utf8');
  const buffer = new Uint8Array(BODY_LIMIT);
  const { written } = new TextEncoder().encodeInto(text, buffer);
  return new TextDecoder().decode(buffer.subarray(0, written));
}

function appendBase64(capture, encoded) {
  const remaining = BODY_LIMIT - capture.length;
  if (!encoded || remaining <= 0) return;
  const chunk = Buffer.from(encoded.slice(0, Math.ceil(remaining / 3) * 4), 'base64').subarray(0, remaining);
  capture.chunks.push(chunk);
  capture.length += chunk.length;
}

export async function probe(options) {
  const started = performance.now();
  const waitMs = options.waitMs || 0;
  const proxy = options.networkProxy ? parseNetworkProxy(options.networkProxy) : undefined;
  const headers = options.headers || {};
  const targetOrigin = new URL(options.url).origin;
  let browserServer;
  let cancelled = false;
  let rejectCancellation;
  const cancellation = new Promise((_, reject) => { rejectCancellation = reject; });
  const abort = (reason) => {
    cancelled = true;
    rejectCancellation(new Error(reason));
    if (browserServer) void browserServer.kill().catch(() => {});
  };
  const timer = setTimeout(() => abort(`Browser probe exceeded ${options.timeoutMs} ms`), options.timeoutMs);
  const signals = new Map(['SIGINT', 'SIGTERM', 'SIGHUP'].map(signal => [signal, () => abort(`Browser probe interrupted by ${signal}`)]));
  for (const [signal, handler] of signals) process.on(signal, handler);
  // A dropped Rust parent closes stdin even when it cannot forward a signal.
  const parentDisconnected = () => abort('Browser probe parent disconnected');
  if (options.monitorParent) {
    process.stdin.once('end', parentDisconnected);
    process.stdin.resume();
  }
  const remaining = () => {
    if (cancelled) throw new Error('Browser probe cancelled');
    const milliseconds = Math.ceil(options.timeoutMs - (performance.now() - started));
    if (milliseconds <= 0) throw new Error(`Browser probe exceeded ${options.timeoutMs} ms`);
    return milliseconds;
  };
  const run = async () => {
    let chromium;
    try { ({ chromium } = await import('playwright-core')); }
    catch { throw new Error('Playwright is not installed. Run npm ci in the browser directory.'); }
    const executablePath = await discoverChromium({ executable: options.executable, defaultPath: chromium.executablePath(), headed: options.headed });
    browserServer = await chromium.launchServer({
      executablePath, headless: !options.headed, timeout: remaining(),
      // Playwright also handles signals while launchServer is still starting.
      handleSIGINT: true, handleSIGTERM: true, handleSIGHUP: true,
      proxy: proxy ? { server: proxy.server } : undefined,
      args: proxy ? ['--proxy-bypass-list=<-loopback>'] : ['--no-proxy-server'],
    });
    if (cancelled) { await browserServer.kill(); throw new Error('Browser probe cancelled'); }
    const browser = await chromium.connect(browserServer.wsEndpoint(), { timeout: remaining() });
    const context = await browser.newContext({ ignoreHTTPSErrors: false, acceptDownloads: false });
    const page = await context.newPage();
    const cdp = await context.newCDPSession(page);
    if (Object.keys(headers).length || proxy?.username) {
      const authenticated = new Set();
      cdp.on('Fetch.authRequired', event => {
        const allowed = event.authChallenge.source === 'Proxy' && proxy?.username && !authenticated.has(event.requestId);
        if (allowed) authenticated.add(event.requestId);
        void cdp.send('Fetch.continueWithAuth', { requestId: event.requestId, authChallengeResponse: allowed
          ? { response: 'ProvideCredentials', username: proxy.username, password: proxy.password }
          : { response: 'CancelAuth' } }).catch(() => {});
      });
      // CDP pauses every redirect hop separately; overrides cannot carry credentials
      // from an allowed origin to a redirected origin.
      cdp.on('Fetch.requestPaused', event => {
        const sameOrigin = new URL(event.request.url).origin === targetOrigin;
        const outgoing = Object.entries(event.request.headers)
          .filter(([name]) => !Object.hasOwn(headers, name.toLowerCase()))
          .map(([name, value]) => ({ name, value: String(value) }));
        if (sameOrigin) {
          for (const [name, value] of Object.entries(headers)) outgoing.push({ name, value });
        }
        void cdp.send('Fetch.continueRequest', { requestId: event.requestId, headers: outgoing })
          .catch(error => { if (!cancelled) abort(`Cannot apply browser headers: ${safeError(error, options.networkProxy)}`); });
      });
      await cdp.send('Fetch.enable', { patterns: [{ urlPattern: '*', requestStage: 'Request' }], handleAuthRequests: true });
    }
    await cdp.send('Network.enable', { maxResourceBufferSize: BODY_LIMIT, maxTotalBufferSize: BODY_LIMIT * 2 });
    const { frameTree } = await cdp.send('Page.getFrameTree');
    let captures = [];
    let latestResponse;
    let latestObservedAt;
    let latestRequest;
    let navigationFailure;
    const redirectChain = [];
    const isMain = request => request.isNavigationRequest() && request.frame() === page.mainFrame();
    page.on('request', request => {
      if (!isMain(request)) return;
      latestRequest = request;
      navigationFailure = undefined;
      if (redirectChain.length >= 32) { abort('Browser exceeded 32 main-document navigations'); return; }
      redirectChain.push(request.url());
    });
    page.on('response', response => {
      if (isMain(response.request())) { latestResponse = response; latestObservedAt = Math.round(performance.now() - started); }
    });
    page.on('requestfailed', request => {
      if (isMain(request) && request === latestRequest) navigationFailure = request.failure()?.errorText || 'Main-document navigation failed';
    });
    cdp.on('Network.responseReceived', event => {
      if (event.type !== 'Document' || event.frameId !== frameTree.frame.id) return;
      const capture = { requestId: event.requestId, url: event.response.url, protocol: event.response.protocol, observedAt: Math.round(performance.now() - started), chunks: [], length: 0, buffered: [], bufferedLength: 0, streaming: false };
      captures = [...captures.slice(-1), capture];
      capture.ready = cdp.send('Network.streamResourceContent', { requestId: event.requestId })
        .then(({ bufferedData }) => {
          appendBase64(capture, bufferedData);
          for (const data of capture.buffered) appendBase64(capture, data);
          capture.buffered = [];
          capture.streaming = true;
          return true;
        }).catch(() => false);
    });
    cdp.on('Network.dataReceived', event => {
      if (!event.data) return;
      const capture = captures.find(item => item.requestId === event.requestId);
      if (!capture) return;
      if (capture.streaming) appendBase64(capture, event.data);
      else {
        const available = Math.ceil(BODY_LIMIT / 3) * 4 - capture.bufferedLength;
        if (available > 0) {
          const data = event.data.slice(0, available);
          capture.buffered.push(data);
          capture.bufferedLength += data.length;
        }
      }
    });
    const initial = await page.goto(options.url, { waitUntil: 'domcontentloaded', timeout: remaining() });
    if (!initial) throw new Error('Navigation did not return an HTTP response');
    const initialObservedAt = latestObservedAt;
    if (waitMs) {
      await new Promise(resolve => {
        const waitTimer = setTimeout(resolve, waitMs);
        cancellation.catch(() => { clearTimeout(waitTimer); resolve(); });
      });
      remaining();
    }
    if (navigationFailure) throw new Error(`Final navigation failed: ${navigationFailure}`);
    if (latestRequest && latestResponse?.request() !== latestRequest) {
      latestResponse = await page.waitForResponse(response => isMain(response.request()) && response.request() === latestRequest, { timeout: remaining() });
    }
    const response = latestResponse || initial;
    const responseHeaders = await response.allHeaders();
    const capture = captures.findLast(item => item.url === response.url());
    const streamed = capture && await capture.ready;
    let body;
    if (streamed) {
      const failure = await response.finished();
      if (failure) throw failure;
      body = boundedText(Buffer.concat(capture.chunks, capture.length));
    } else {
      const bytes = await response.body();
      body = boundedText(bytes);
    }
    return {
      status: response.status(), http_version: normalizeProtocol(capture?.protocol),
      final_url: response.url(), headers: responseHeaders, body,
      duration_ms: Math.round(performance.now() - started), client_version: browser.version(),
      ...(waitMs ? { initial_status: initial.status(), initial_url: initial.url(), initial_observed_at_ms: initialObservedAt } : {}),
      final_observed_at_ms: capture?.observedAt ?? latestObservedAt,
      redirect_chain: redirectChain,
    };
  };
  try { return await Promise.race([run(), cancellation]); }
  finally {
    clearTimeout(timer);
    cancelled = true;
    for (const [signal, handler] of signals) process.off(signal, handler);
    if (options.monitorParent) { process.stdin.off('end', parentDisconnected); process.stdin.pause(); }
    if (browserServer) await browserServer.kill().catch(() => {});
  }
}

async function main() {
  let options;
  try {
    options = parseArguments(process.argv.slice(2));
    const result = options.check ? await checkBrowser(options) : await probe({ ...options, monitorParent: process.env.FINGERPRINT_LAB_MONITOR_PARENT === '1' });
    process.stdout.write(`${JSON.stringify(result)}\n`);
  } catch (error) {
    // URLs may include secret query parameters; do not echo Playwright's navigation log.
    const message = safeError(error, options?.networkProxy);
    process.stderr.write(`Chromium probe failed: ${message}\n`);
    process.exitCode = 1;
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) await main();
