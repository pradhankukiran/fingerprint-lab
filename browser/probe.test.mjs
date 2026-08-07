import assert from 'node:assert/strict';
import { chmod, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import http from 'node:http';
import https from 'node:https';
import { execFile, spawn } from 'node:child_process';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { BODY_LIMIT, boundedText, chromiumCacheRoots, discoverChromium, normalizeProtocol, parseArguments, parseNetworkProxy, parseHeader, safeError, checkBrowser, probe } from './probe.mjs';

test('arguments accept only an HTTP target and bounded positive timeout', () => {
  assert.deepEqual(parseArguments(['--url', 'https://example.com', '--timeout-ms', '5000', '--headed']), {
    url: 'https://example.com/', timeoutMs: 5000, headed: true, waitMs: 0, headers: {},
  });
  for (const args of [[], ['--url', 'file:///etc/passwd'], ['--url', 'https://user:secret@example.com'], ['--url', 'https://example.com', '--timeout-ms', '0'], ['--url', 'https://example.com', '--timeout-ms', 'Infinity'], ['--url', 'https://example.com', '--timeout-ms', '2147483648'], ['--url', 'https://example.com', '--headed', '--headed'], ['--url', '--headed'], ['--unknown']]) {
    assert.throws(() => parseArguments(args));
  }
});

test('cache roots honor Playwright and platform conventions', () => {
  assert.deepEqual(chromiumCacheRoots({ env: {}, home: '/users/test', platform: 'linux' }), ['/users/test/.cache/ms-playwright']);
  assert.deepEqual(chromiumCacheRoots({ env: { XDG_CACHE_HOME: '/cache', PLAYWRIGHT_BROWSERS_PATH: '/custom' }, home: '/users/test', platform: 'linux' }), ['/custom', '/cache/ms-playwright']);
  assert.deepEqual(chromiumCacheRoots({ env: {}, home: '/users/test', platform: 'darwin' }), ['/users/test/Library/Caches/ms-playwright']);
});

test('discovery selects full Chromium, respects overrides, and rejects unavailable binaries', async t => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'fingerprint-lab-browser-test-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const executable = async relative => {
    const target = path.join(directory, relative);
    await mkdir(path.dirname(target), { recursive: true });
    await writeFile(target, '');
    await chmod(target, 0o700);
    return target;
  };
  const older = await executable('chromium-100/chrome-linux64/chrome');
  const newer = await executable('chromium-101/chrome-linux64/chrome');
  await executable('chromium_headless_shell-102/chrome-headless-shell-linux64/chrome-headless-shell');
  const options = { env: {}, cacheRoots: [directory] };
  assert.equal(await discoverChromium(options), newer);
  assert.equal(await discoverChromium({ ...options, headed: true }), newer);
  assert.equal(await discoverChromium({ ...options, defaultPath: older }), older);
  assert.equal(await discoverChromium({ ...options, env: { FINGERPRINT_LAB_CHROMIUM: older } }), older);
  assert.equal(await discoverChromium({ ...options, env: { FINGERPRINT_LAB_CHROMIUM: older }, executable: newer }), newer);
  await assert.rejects(discoverChromium({ ...options, executable: path.join(directory, 'missing') }), /missing or not executable/);
  await assert.rejects(discoverChromium({ env: {}, cacheRoots: [] }), /No installed Chromium/);
});

test('protocol names report unknown rather than an assumed HTTP version', () => {
  assert.equal(normalizeProtocol('h2'), 'HTTP/2');
  assert.equal(normalizeProtocol('h3'), 'HTTP/3');
  assert.equal(normalizeProtocol('http/1.1'), 'HTTP/1.1');
  assert.equal(normalizeProtocol(undefined), 'unknown');
  assert.equal(normalizeProtocol('QUIC'), 'unknown');
});

test('bounded text handles UTF-8 and invalid binary without exceeding the byte cap', () => {
  for (const bytes of [Buffer.alloc(BODY_LIMIT + 20, 'x'), Buffer.alloc(BODY_LIMIT, 0xff), Buffer.from('€'.repeat(BODY_LIMIT))]) {
    assert.ok(Buffer.byteLength(boundedText(bytes), 'utf8') <= BODY_LIMIT);
  }
  assert.equal(boundedText(Buffer.from('hello €')), 'hello €');
});

test('real browser follows redirects, isolates cookies, captures protocol and caps body', { skip: !process.env.BROWSER_PROBE_INTEGRATION, timeout: 30_000 }, async t => {
  const requests = [];
  const server = http.createServer((request, response) => {
    requests.push(request);
    if (request.url === '/redirect') {
      response.writeHead(302, { Location: '/page', 'Set-Cookie': 'fixture=session; Path=/' });
      response.end();
    } else if (request.url === '/large') {
      response.writeHead(200, { 'Content-Type': 'text/html' });
      response.end(`<html><body>${'x'.repeat(BODY_LIMIT + 100_000)}</body></html>`);
    } else if (request.url === '/slow') {
      response.writeHead(200, { 'Content-Type': 'text/html' });
      response.write('<html><body>unfinished');
    } else {
      response.writeHead(200, { 'Content-Type': 'text/html', 'X-Fixture': 'yes' });
      response.end(`<html><body>${request.headers.cookie || 'no-cookie'}<script>document.title = 'executed';</script></body></html>`);
    }
  });
  server.listen(0, '127.0.0.1');
  await new Promise(resolve => server.once('listening', resolve));
  t.after(() => { server.closeAllConnections(); server.close(); });
  const base = `http://127.0.0.1:${server.address().port}`;
  const result = await probe({ url: `${base}/redirect`, timeoutMs: 10_000, headed: false });
  assert.equal(result.status, 200);
  assert.equal(result.http_version, 'HTTP/1.1');
  assert.equal(result.final_url, `${base}/page`);
  assert.equal(result.headers['x-fixture'], 'yes');
  assert.match(result.body, /fixture=session/);
  assert.match(result.client_version, /^\d+\./);
  assert.ok(requests.some(request => request.headers['sec-fetch-mode'] === 'navigate' && /Chrome/.test(request.headers['user-agent'])));
  const fresh = await probe({ url: `${base}/page`, timeoutMs: 10_000, headed: false });
  assert.match(fresh.body, /no-cookie/);
  const large = await probe({ url: `${base}/large`, timeoutMs: 10_000, headed: false });
  assert.equal(Buffer.byteLength(large.body), BODY_LIMIT);
  const started = Date.now();
  await assert.rejects(probe({ url: `${base}/slow`, timeoutMs: 1500, headed: false }), /exceeded|Timeout/);
  assert.ok(Date.now() - started < 4000);
});


test('proxy parsing separates credentials and rejects unsupported schemes without echoing input', () => {
  assert.deepEqual(parseNetworkProxy('http://test:p%40ss@127.0.0.1:8080'), { server: 'http://127.0.0.1:8080', username: 'test', password: 'p@ss' });
  assert.deepEqual(parseNetworkProxy('https://proxy.example:8443'), { server: 'https://proxy.example:8443' });
  for (const proxy of ['socks5://user:secret@proxy:1080', 'http://proxy/path', 'invalid-secret-value']) {
    assert.throws(() => parseNetworkProxy(proxy), error => !error.message.includes('secret'));
  }
  assert.equal(safeError(new Error('failure for http://user:secret@proxy/ secret user'), 'http://user:secret@proxy/'), 'failure for [URL] [redacted] [redacted]');
});

test('repeatable headers and observation wait parse without accepting framing headers', () => {
  const options = parseArguments(['--url', 'https://example.com', '--header', 'X-Test: first', '--header', 'X-Test: second', '--header', 'Cookie: session=value', '--wait-seconds', '1.25']);
  assert.deepEqual(options.headers, { 'x-test': 'first, second', cookie: 'session=value' });
  assert.equal(options.waitMs, 1250);
  for (const header of ['Host: other', 'Content-Length: 8', 'Invalid Name: secret', 'X-Test: value\r\nInjected: yes']) assert.throws(() => parseHeader(header));
});

test('real browser routes through authenticated proxy, scopes headers, and reports final wait outcome', { skip: !process.env.BROWSER_PROBE_INTEGRATION, timeout: 30_000 }, async t => {
  const finalRequests = [];
  const second = http.createServer((request, response) => {
    finalRequests.push(request);
    response.end('<html>cross-origin destination</html>');
  });
  second.listen(0, '127.0.0.1');
  await new Promise(resolve => second.once('listening', resolve));
  t.after(() => { second.closeAllConnections(); second.close(); });
  const crossUrl = `http://127.0.0.1:${second.address().port}/destination`;
  const originRequests = [];
  const origin = http.createServer((request, response) => {
    originRequests.push(request);
    if (request.url === '/cross') {
      response.writeHead(302, { Location: crossUrl });
      response.end();
    } else if (request.url === '/wait') {
      response.writeHead(200, { 'content-type': 'text/html' });
      response.end('<html><script>setTimeout(() => location.href = "/denied", 100)</script>initial</html>');
    } else if (request.url === '/denied') {
      response.writeHead(403, { 'content-type': 'text/html' });
      response.end('<html>final denied</html>');
    } else { response.end('<html>proxy fixture</html>'); }
  });
  origin.listen(0, '127.0.0.1');
  await new Promise(resolve => origin.once('listening', resolve));
  t.after(() => { origin.closeAllConnections(); origin.close(); });
  const base = `http://127.0.0.1:${origin.address().port}`;
  const forwarded = [];
  const proxy = http.createServer((request, response) => {
    if (request.headers['proxy-authorization'] !== `Basic ${Buffer.from('fixture:secret').toString('base64')}`) {
      response.writeHead(407, { 'Proxy-Authenticate': 'Basic realm="fixture"' });
      response.end();
      return;
    }
    forwarded.push(request.url);
    const target = new URL(request.url);
    const headers = { ...request.headers };
    delete headers['proxy-authorization'];
    const upstream = http.request(target, { method: request.method, headers }, result => { response.writeHead(result.statusCode, result.headers); result.pipe(response); });
    upstream.on('error', () => { response.writeHead(502); response.end(); });
    request.pipe(upstream);
  });
  proxy.listen(0, '127.0.0.1');
  await new Promise(resolve => proxy.once('listening', resolve));
  t.after(() => { proxy.closeAllConnections(); proxy.close(); });
  const networkProxy = `http://fixture:secret@127.0.0.1:${proxy.address().port}`;
  const cross = await probe({ url: `${base}/cross`, timeoutMs: 10_000, headed: false, networkProxy, headers: { authorization: 'Bearer fixture-token', cookie: 'manual=value', 'x-api-key': 'fixture-key' } });
  assert.equal(cross.status, 200);
  assert.ok(forwarded.includes(`${base}/cross`));
  assert.ok(forwarded.includes(crossUrl));
  const initial = originRequests.find(request => request.url === '/cross');
  assert.equal(initial.headers.authorization, 'Bearer fixture-token');
  assert.equal(initial.headers.cookie, 'manual=value');
  assert.equal(initial.headers['x-api-key'], 'fixture-key');
  const final = finalRequests.find(request => request.url === '/destination');
  assert.equal(final.headers.authorization, undefined);
  assert.equal(final.headers.cookie, undefined);
  assert.equal(final.headers['x-api-key'], undefined);
  assert.equal(final.headers['proxy-authorization'], undefined);
  assert.ok(!JSON.stringify(cross).includes('secret'));
  const waited = await probe({ url: `${base}/wait`, timeoutMs: 10_000, headed: false, waitMs: 600 });
  assert.equal(waited.initial_status, 200);
  assert.equal(waited.initial_url, `${base}/wait`);
  assert.equal(waited.status, 403);
  assert.equal(waited.final_url, `${base}/denied`);
  assert.match(waited.body, /final denied/);
  assert.ok(waited.initial_observed_at_ms >= 0);
  assert.ok(waited.final_observed_at_ms > waited.initial_observed_at_ms);
  assert.deepEqual(waited.redirect_chain, [`${base}/wait`, `${base}/denied`]);
  const check = await checkBrowser();
  assert.equal(check.available, true);
  assert.match(check.version, /Chrome|Chromium/);
});


test('real browser rejects self-signed TLS certificates', { skip: !process.env.BROWSER_PROBE_INTEGRATION, timeout: 10_000 }, async t => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'fingerprint-lab-browser-tls-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  await promisify(execFile)('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', path.join(directory, 'key.pem'), '-out', path.join(directory, 'cert.pem'), '-days', '1', '-subj', '/CN=localhost'], { timeout: 5000 });
  const server = https.createServer({ key: await readFile(path.join(directory, 'key.pem')), cert: await readFile(path.join(directory, 'cert.pem')) }, (_, response) => response.end('untrusted'));
  server.listen(0, '127.0.0.1');
  await new Promise(resolve => server.once('listening', resolve));
  t.after(() => { server.closeAllConnections(); server.close(); });
  await assert.rejects(probe({ url: `https://127.0.0.1:${server.address().port}`, timeoutMs: 5000, headed: false }), /CERT_AUTHORITY_INVALID/);
});

test('CLI closes Chromium on SIGTERM and parent-pipe closure', { skip: !process.env.BROWSER_PROBE_INTEGRATION || process.platform !== 'linux', timeout: 20_000 }, async t => {
  let arrived;
  const server = http.createServer((request, response) => {
    response.writeHead(200, { 'content-type': 'text/html' });
    response.write('<html>unfinished');
    arrived(request.socket);
  });
  server.listen(0, '127.0.0.1');
  await new Promise(resolve => server.once('listening', resolve));
  t.after(() => { server.closeAllConnections(); server.close(); });
  for (const mode of ['signal', 'parent-disconnect']) {
    const navigation = new Promise(resolve => { arrived = resolve; });
    const child = spawn(process.execPath, [fileURLToPath(new URL('./probe.mjs', import.meta.url)), '--url', `http://127.0.0.1:${server.address().port}`, '--timeout-ms', '5000'], {
      env: { ...process.env, FINGERPRINT_LAB_MONITOR_PARENT: '1' }, stdio: ['pipe', 'pipe', 'pipe'],
    });
    t.after(() => { child.stdin.destroy(); child.kill('SIGTERM'); });
    let stdout = '', stderr = '';
    child.stdout.on('data', data => { stdout += data; });
    child.stderr.on('data', data => { stderr += data; });
    const closed = new Promise(resolve => child.once('close', (code, signal) => resolve({ code, signal })));
    const socket = await navigation;
    const socketClosed = new Promise(resolve => socket.once('close', resolve));
    const { stdout: processes } = await promisify(execFile)('ps', ['-o', 'pid=', '--ppid', String(child.pid)]);
    const browserPids = processes.trim().split(/\s+/).filter(Boolean).map(Number);
    assert.ok(browserPids.length > 0);
    if (mode === 'signal') child.kill('SIGTERM');
    else child.stdin.end();
    const result = await closed;
    await socketClosed;
    assert.notEqual(result.code, 0);
    assert.equal(stdout, '');
    assert.match(stderr, mode === 'signal' ? /SIGTERM/ : /parent disconnected/);
    for (const pid of browserPids) assert.throws(() => process.kill(pid, 0), { code: 'ESRCH' });
  }
});
