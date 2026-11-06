import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { configuredTurnstile, requestHostname, SITEVERIFY, NOT_CONFIRMED } from '../turnstile-verify.mjs';
import { createRegistry } from '../registry.mjs';
import { verifyPublicationUpload } from '../publications.mjs';

// Cloudflare's published testing keys, and a made-up "real" pair. siteverify is always stubbed: no network.
const TEST_SITE = '1x00000000000000000000AA', TEST_SECRET = '1x0000000000000000000000000000000AA';
const SITE = '0x4AAAAAAAexampleSiteKey', SECRET = '0x4AAAAAAAexample-secret-never-shown';
const hash = bytes => createHash('sha256').update(bytes).digest('hex');

/** A stand-in for siteverify: answers by token, and records what was sent where. */
function siteverify(answers) {
  const calls = [];
  const fetch = async (url, init) => {
    const body = JSON.parse(init.body);
    calls.push({ url, body, method: init.method });
    const answer = answers[body.response];
    if (answer instanceof Error) throw answer;
    return { json: async () => answer ?? { success: false, 'error-codes': ['invalid-input-response'] } };
  };
  return { fetch, calls };
}
const passed = (action, hostname = 'huma.social') => ({ success: true, action, hostname, challenge_ts: new Date().toISOString(), 'error-codes': [] });

test('Turnstile is off unless both keys are set, and then never asks Cloudflare', async () => {
  const { fetch, calls } = siteverify({});
  for (const env of [{}, { HUMA_TURNSTILE_SITE_KEY: SITE }, { TURNSTILE_SECRET_KEY: SECRET }]) {
    const turnstile = configuredTurnstile(env, { fetch });
    assert.equal(turnstile.enabled, false);
    assert.equal(turnstile.siteKey, null);
    assert.deepEqual(await turnstile.verify(undefined, 'publish', { hostname: 'huma.social' }), { ok: true, off: true });
  }
  assert.equal(calls.length, 0);
});

test('a token counts only when Cloudflare passed it for this action on this site', async () => {
  const { fetch, calls } = siteverify({ good: passed('publish'), start: passed('start'), elsewhere: passed('publish', 'evil.example'),
    alias: passed('publish', 'www.huma.social'), failed: { success: false, 'error-codes': ['invalid-input-response'] }, down: new Error('offline'),
    testing: { success: true, hostname: 'example.com', metadata: { result_with_testing_key: true } } });
  const turnstile = configuredTurnstile({ HUMA_TURNSTILE_SITE_KEY: SITE, TURNSTILE_SECRET_KEY: SECRET, HUMA_TURNSTILE_HOSTNAMES: 'www.huma.social' }, { fetch });
  assert.equal(turnstile.enabled, true);
  assert.equal(turnstile.siteKey, SITE);
  const check = (token, action = 'publish', hostname = 'huma.social') => turnstile.verify(token, action, { hostname });
  assert.deepEqual(await check('good'), { ok: true });
  assert.deepEqual(await check('good', 'publish', 'HUMA.social'), { ok: true });
  assert.equal((await check('start')).reason, 'action'); // a Start token can't publish
  assert.deepEqual(await check('start', 'start'), { ok: true });
  assert.equal((await check('elsewhere')).reason, 'hostname');
  assert.deepEqual(await check('alias'), { ok: true }); // listed in HUMA_TURNSTILE_HOSTNAMES
  assert.deepEqual(await check('failed'), { ok: false, status: 403, reason: 'failed' });
  assert.deepEqual(await check('down'), { ok: false, status: 503, reason: 'unreachable' });
  // A testing answer only counts with a testing secret.
  assert.equal((await check('testing')).ok, false);
  for (const token of [undefined, '', 42, 'x'.repeat(2049)]) assert.deepEqual(await check(token), { ok: false, status: 403, reason: 'missing' });
  assert.equal((await check('good', 'login')).status, 400);
  // The secret goes to siteverify only, and never out of the closure.
  assert.ok(calls.length > 0 && calls.every(call => call.url === SITEVERIFY && call.method === 'POST' && call.body.secret === SECRET));
  assert.doesNotMatch(JSON.stringify(turnstile), /example-secret/);
});

test('Cloudflare testing keys pass locally (their answers name example.com and no action)', async () => {
  const { fetch } = siteverify({ 'XXXX.DUMMY.TOKEN.XXXX': { success: true, hostname: 'example.com', 'error-codes': [], metadata: { result_with_testing_key: true } } });
  const turnstile = configuredTurnstile({ HUMA_TURNSTILE_SITE_KEY: TEST_SITE, TURNSTILE_SECRET_KEY: TEST_SECRET }, { fetch });
  assert.deepEqual(await turnstile.verify('XXXX.DUMMY.TOKEN.XXXX', 'start', { hostname: 'localhost' }), { ok: true });
  assert.equal((await turnstile.verify('another', 'start', { hostname: 'localhost' })).ok, false);
});

test('requestHostname drops the port', () => {
  assert.equal(requestHostname({ headers: { host: 'localhost:4320' } }), 'localhost');
  assert.equal(requestHostname({ headers: { host: 'huma.social' } }), 'huma.social');
  assert.equal(requestHostname({ headers: {} }), null);
});

// A browser page starts with this server's session nonce (sessions.mjs), and claims no writing time yet.
const started = async base => ({ nonce: [BigInt('0x' + (await (await fetch(base + '/api/sessions', { method: 'POST' })).json()).nonce).toString(), '0'],
  elapsed: '0', start_unix: '0', end_unix: '0' });
async function running(t, { turnstile, browser = true } = {}) {
  const directory = await mkdtemp(path.join(tmpdir(), 'huma-turnstile-'));
  let base;
  const server = await createRegistry({ store: directory, publicationOptions: {
    authenticate: async token => { if (token !== 'test-owner-session') throw Object.assign(new Error('Sign in required.'), { status: 401 }); return hash('test-owner'); },
    // The real check, with the page's journal saying where it was written (origin_present 0: in a browser).
    verifyUpload: async source => {
      const checked = await verifyPublicationUpload(source);
      return browser ? { ...checked, scoring: { ...checked.scoring, journal: { ...checked.scoring.journal, origin_present: 0, ...await started(base) } } } : checked;
    },
    ...(turnstile ? { turnstile } : {}),
  } });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(async () => { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); await rm(directory, { recursive: true, force: true }); });
  base = `http://127.0.0.1:${server.address().port}`;
  return (route, options) => fetch(base + route, options);
}
async function prepared(request) {
  const proof = await readFile(new URL('../../extra/experiments/noir-compact/browser/test/fixtures/Long400V3.json', import.meta.url), 'utf8');
  const response = await request('/api/publications/prepare', { method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ kind: 'huma-publication-upload-v1', access: 'link', proof,
      master: { mediaType: 'text/plain;charset=utf-8', base64: Buffer.from(JSON.parse(proof).text).toString('base64') } }) });
  assert.equal(response.status, 201, await response.clone().text());
  return response.json();
}
const publish = (request, pending, body = {}) => request('/api/publications/pending/' + pending.id + '/publish', { method: 'POST',
  headers: { Authorization: 'Bearer test-owner-session', 'X-Huma-Ticket': pending.ticket, 'Content-Type': 'application/json' }, body: JSON.stringify(body) });

test('the write page gets the site key, keeps its isolation and lets in only Cloudflare’s widget', async t => {
  const { fetch } = siteverify({ good: passed('start', '127.0.0.1') });
  const request = await running(t, { turnstile: configuredTurnstile({ HUMA_TURNSTILE_SITE_KEY: SITE, TURNSTILE_SECRET_KEY: SECRET }, { fetch }) });
  assert.deepEqual(await (await request('/api/turnstile')).json(), { siteKey: SITE });
  const page = await request('/write');
  assert.equal(page.headers.get('cross-origin-opener-policy'), 'same-origin');
  assert.equal(page.headers.get('cross-origin-embedder-policy'), 'require-corp');
  const csp = page.headers.get('content-security-policy');
  for (const directive of ['script-src', 'frame-src', 'connect-src']) assert.match(csp, new RegExp(directive + " [^;]*https://challenges\\.cloudflare\\.com"));
  assert.match(csp, /frame-ancestors 'none'/);
  // The page's own gate at Start and Finish.
  const check = (body, type = 'application/json') => request('/api/turnstile/verify', { method: 'POST', headers: { 'Content-Type': type }, body });
  assert.deepEqual(await (await check(JSON.stringify({ token: 'good', action: 'start' }))).json(), { ok: true });
  const refused = await check(JSON.stringify({ token: 'good', action: 'finish' }));
  assert.equal(refused.status, 403);
  assert.deepEqual(await refused.json(), { ok: false, error: NOT_CONFIRMED });
  assert.equal((await check('{', 'application/json')).status, 400);
  assert.equal((await check('{}', 'text/plain')).status, 415);
  assert.equal((await request('/api/turnstile/verify')).status, 405);
});

test('with Turnstile off the write page is as before and the gate says off', async t => {
  const request = await running(t, { turnstile: configuredTurnstile({}) });
  assert.deepEqual(await (await request('/api/turnstile')).json(), { siteKey: null });
  assert.doesNotMatch((await request('/write')).headers.get('content-security-policy'), /cloudflare/);
  const reply = await request('/api/turnstile/verify', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ action: 'start' }) });
  assert.deepEqual(await reply.json(), { ok: true, off: true });
});

test('a page written in a browser is shared only with a fresh Turnstile token for publish', { timeout: 60000 }, async t => {
  const { fetch, calls } = siteverify({ good: passed('publish', '127.0.0.1'), start: passed('start', '127.0.0.1'), down: new Error('offline') });
  const request = await running(t, { turnstile: configuredTurnstile({ HUMA_TURNSTILE_SITE_KEY: SITE, TURNSTILE_SECRET_KEY: SECRET }, { fetch }) });
  const pending = await prepared(request);
  for (const [body, status] of [[{}, 403], [{ turnstile: 'forged' }, 403], [{ turnstile: 'start' }, 403], [{ turnstile: 'down' }, 503]]) {
    const refused = await publish(request, pending, body);
    assert.equal(refused.status, status);
    assert.equal((await refused.json()).error, NOT_CONFIRMED);
  }
  const shared = await publish(request, pending, { turnstile: 'good' });
  assert.equal(shared.status, 200, await shared.clone().text());
  // A retry of the same request isn't asked again (Cloudflare tokens work once).
  const before = calls.length;
  assert.equal((await publish(request, pending, {})).status, 200);
  assert.equal(calls.length, before);
});

test('Mac pages, and every page with Turnstile off, are shared as before', { timeout: 60000 }, async t => {
  const { fetch, calls } = siteverify({});
  const mac = await running(t, { browser: false, turnstile: configuredTurnstile({ HUMA_TURNSTILE_SITE_KEY: SITE, TURNSTILE_SECRET_KEY: SECRET }, { fetch }) });
  assert.equal((await publish(mac, await prepared(mac))).status, 200);
  assert.equal(calls.length, 0);
  const off = await running(t, { turnstile: configuredTurnstile({}) });
  assert.equal((await publish(off, await prepared(off))).status, 200);
});

// The page's module (frontend/write/turnstile.mjs) against a stand-in DOM, Cloudflare script and server.
test('the write page’s humanToken: null when off, a token from the widget drawn in the open dialog, NOT_CONFIRMED on failure', async t => {
  const saved = { window: globalThis.window, document: globalThis.document, fetch: globalThis.fetch };
  t.after(() => Object.assign(globalThis, saved));
  const element = tag => ({ tag, children: [], parent: null, className: '', append(child) { child.parent = this; this.children.push(child); if (child.tag === 'script') queueMicrotask(() => { globalThis.window.turnstile = widget; child.onload(); }); },
    remove() { if (this.parent) this.parent.children.splice(this.parent.children.indexOf(this), 1); this.parent = null; } });
  const dialog = element('dialog'), head = element('head'), body = element('body'), rendered = [], removed = [];
  let answer = 'token';
  const widget = { render(box, options) { rendered.push({ box, options }); queueMicrotask(() => (answer === 'error' ? options['error-callback']('300030') : options.callback(answer))); return 'w' + rendered.length; },
    remove(id) { removed.push(id); } };
  globalThis.window = { turnstile: element('div') }; // the page's <div id="turnstile">, until Cloudflare's script replaces it
  globalThis.document = { head, body, createElement: element, getElementById: () => null, querySelectorAll: selector => (selector === 'dialog[open]' ? [dialog] : []) };
  let siteKey = null; const posted = [];
  globalThis.fetch = async (url, init) => {
    if (url === '/api/turnstile') return { ok: true, json: async () => ({ siteKey }) };
    posted.push(JSON.parse(init.body));
    return { json: async () => ({ ok: JSON.parse(init.body).token === 'token' }) };
  };
  const off = await import('../write/turnstile.mjs?off');
  assert.equal(await off.humanToken('start'), null);
  assert.equal(await off.confirmHuman('start'), true);
  assert.equal(head.children.length, 0); // nothing from Cloudflare is loaded when it's off
  await assert.rejects(off.humanToken('login'));

  siteKey = TEST_SITE;
  const on = await import('../write/turnstile.mjs?on');
  assert.equal(await on.humanToken('publish'), 'token');
  assert.equal(head.children.length, 1);
  assert.equal(rendered[0].box.parent, null); // drawn in the open dialog, then taken away
  assert.deepEqual([rendered[0].options.sitekey, rendered[0].options.action], [TEST_SITE, 'publish']);
  assert.deepEqual(removed, ['w1']);
  assert.equal(await on.confirmHuman('finish'), true);
  assert.deepEqual(posted, [{ token: 'token', action: 'finish' }]);
  answer = 'error';
  await assert.rejects(on.humanToken('start'), { message: NOT_CONFIRMED });
  assert.equal(await on.confirmHuman('start'), false);
  assert.equal(head.children.length, 1); // the script loads once
  assert.equal(dialog.children.length, 0);
});
