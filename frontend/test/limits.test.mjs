// One client can't fill what everyone shares (prepare, sign-in, Turnstile), a key is kept as an account's only by
// whoever holds it, and the daily allowance isn't spent by sharing one page again.
import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { createHash, generateKeyPairSync, randomBytes, sign } from 'node:crypto';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { privateKeyToAccount } from 'viem/accounts';
import { LocalObjectStore } from '../object-store.mjs';
import { createRegistry } from '../registry.mjs';
import { deviceOwnerKey } from '../documents.mjs';
import { verifyPublicationUpload, publicationMessage } from '../publications.mjs';
import { deviceAuthorizationMessage, signinMessage, replayMessage } from '../publication-contract.mjs';
import { clientIP } from '../client-ip.mjs';
import { configuredTurnstile, turnstileRoutes } from '../turnstile-verify.mjs';

const hash = value => createHash('sha256').update(value).digest('hex');
const { proof, text } = await readFile(new URL('../../extra/experiments/noir-compact/browser/test/fixtures/Long400V3.json', import.meta.url), 'utf8')
  .then(source => ({ proof: source, text: JSON.parse(source).text }));
const upload = (access = 'link') => JSON.stringify({ kind: 'huma-publication-upload-v1', access, proof, master: { mediaType: 'text/plain;charset=utf-8', base64: Buffer.from(text).toString('base64') } });
const verified = await verifyPublicationUpload(upload());
const wallets = Object.fromEntries(['victim', 'attacker', 'other'].map((who, i) => [who, privateKeyToAccount('0x' + String(i + 4).repeat(64))]));

async function running(t, publicationOptions = {}) {
  const directory = await mkdtemp(path.join(tmpdir(), 'huma-limits-'));
  const server = await createRegistry({ store: directory, publicationOptions: {
    verifyUpload: async source => { const value = structuredClone(verified);
      Object.assign(value.manifest, { publicationNonce: randomBytes(32).toString('hex'), access: JSON.parse(source).access }); return value; },
    authenticate: async token => ({ owner: hash(token), wallets: [(wallets[token] ?? wallets.other).address], account: token + '@example.com' }),
    ...publicationOptions } });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(async () => { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); await rm(directory, { recursive: true, force: true }); });
  const port = server.address().port;
  return { port, store: new LocalObjectStore(path.join(directory, 'publications')),
    request: (route, { from = '9.9.9.9', ...options } = {}) => fetch(`http://127.0.0.1:${port}` + route, { ...options, headers: { 'X-Forwarded-For': from, ...options.headers } }) };
}
const prepare = (request, from, access = 'link') => request('/api/publications/prepare', { from, method: 'POST', headers: { 'Content-Type': 'application/json' }, body: upload(access) });
/** An upload that sends its headers and a few bytes, then stalls. */
function stalled(port, from) {
  const req = http.request({ port, host: '127.0.0.1', method: 'POST', path: '/api/publications/prepare',
    headers: { 'Content-Type': 'application/json', 'Content-Length': 1000000, 'X-Forwarded-For': from } });
  req.on('error', () => {}); req.write('{"kind":'); return req;
}
const keyPair = () => {
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' }), jwk = publicKey.export({ format: 'jwk' });
  return { privateKey, point: '04' + Buffer.from(jwk.x, 'base64url').toString('hex') + Buffer.from(jwk.y, 'base64url').toString('hex') };
};

test('the client address is Caddy’s last X-Forwarded-For entry only from loopback, IPv6 by /64, never CF-Connecting-IP', () => {
  const req = (remoteAddress, headers = {}) => ({ socket: { remoteAddress }, headers });
  assert.equal(clientIP(req('127.0.0.1', { 'x-forwarded-for': '1.1.1.1, 8.8.8.8' })), '8.8.8.8');
  assert.equal(clientIP(req('::ffff:127.0.0.1', { 'x-forwarded-for': '2001:db8:1:2:3:4:5:6' })), '2001:db8:1:2::/64');
  assert.equal(clientIP(req('2001:db8:1:2::9')), clientIP(req('2001:db8:1:2:ffff::1')));
  assert.equal(clientIP(req('5.5.5.5', { 'x-forwarded-for': '8.8.8.8', 'cf-connecting-ip': '1.1.1.1' })), '5.5.5.5');
  assert.equal(clientIP(req('127.0.0.1', { 'cf-connecting-ip': '1.1.1.1' })), '127.0.0.1');
  assert.equal(clientIP(req('127.0.0.1', { 'x-forwarded-for': 'not-an-address' })), '127.0.0.1');
});

test('stalled uploads hold no one else up, and one client has only a few pages waiting', { timeout: 30000 }, async t => {
  const { request, port } = await running(t);
  const slow = [stalled(port, '6.6.6.6'), stalled(port, '6.6.6.6'), stalled(port, '6.6.6.7')];
  t.after(() => slow.forEach(req => req.destroy()));
  await new Promise(resolve => setTimeout(resolve, 200));
  assert.equal((await prepare(request, '6.6.6.6')).status, 429); // a third upload at once from the stalled client
  for (let i = 0; i < 4; i++) assert.equal((await prepare(request, '7.7.7.7')).status, 201); // others aren't held up
  assert.equal((await prepare(request, '7.7.7.7')).status, 429); // four waiting from one client is its share
  assert.equal((await prepare(request, '8.8.8.8')).status, 201);
});

test('a client holds only a few live sign-in codes; an account isn’t limited', async t => {
  const { request } = await running(t);
  const post = (token, from) => request('/api/publications/signin', { from, method: 'POST', headers: { Authorization: 'Bearer ' + token, 'X-Huma-Signin': randomBytes(32).toString('hex') } });
  for (let i = 0; i < 5; i++) assert.equal((await post('writer', '1.0.0.' + i)).status, 200);
  for (let i = 0; i < 20; i++) assert.equal((await post('person' + i, '2.0.0.1')).status, 200);
  assert.equal((await post('person-more', '2.0.0.1')).status, 429); // a crowd from one address
  assert.equal((await post('person-more', '2.0.0.2')).status, 200);
});

test('a publishing key is kept as an account’s only when its holder signs for it; the Mac’s sign-in is unchanged', { timeout: 30000 }, async t => {
  const { request, store } = await running(t), { privateKey, point } = keyPair();
  const authorize = async who => ({ wallet: wallets[who].address, publicKey: point, signature: await wallets[who].signMessage({ message: deviceAuthorizationMessage(wallets[who].address, point) }) });
  const post = async (who, code) => request('/api/publications/signin', { method: 'POST',
    headers: { Authorization: 'Bearer ' + who, 'X-Huma-Signin': code, 'Content-Type': 'application/json' }, body: JSON.stringify(await authorize(who)) });
  const poll = (code, signature) => request('/api/publications/signin', { headers: { 'X-Huma-Signin': code, ...(signature ? { 'X-Huma-Signature': signature } : {}) } });
  const owners = async () => { try { return JSON.parse(await store.get(deviceOwnerKey(point), 16384)).owner; } catch { return null; } };
  // Someone who saw this key in a receipt links it to their account: the Mac flow still answers, but the key isn't theirs.
  const theirs = 'a'.repeat(64);
  assert.equal((await post('attacker', theirs)).status, 200);
  assert.equal((await (await poll(theirs)).json()).device, true);
  assert.equal((await poll(theirs, sign('sha256', Buffer.from(signinMessage(theirs, point)), keyPair().privateKey).toString('base64'))).status, 403);
  assert.equal(await owners(), null);
  // Its holder signs in and reads back with the key's signature: now it is their account's.
  const mine = 'b'.repeat(64), proof = sign('sha256', Buffer.from(signinMessage(mine, point)), privateKey).toString('base64');
  assert.equal((await post('victim', mine)).status, 200);
  const read = await poll(mine, proof); assert.equal(read.status, 200);
  assert.deepEqual([(await read.json()).device, await owners()], [true, hash('victim')]);
  // From then on another account is turned away before it writes anything.
  const later = 'c'.repeat(64);
  assert.equal((await post('other', later)).status, 409);
  await assert.rejects(store.get('devices/' + hash('huma-device-v1\0' + point + '\0' + wallets.other.address.toLowerCase()), 16384));
});

test('a replay change is refused before its body is read when the page wasn’t shared by a device', { timeout: 30000 }, async t => {
  const { request, port } = await running(t, { authenticate: async () => hash('wallet-writer') });
  const pending = await (await prepare(request, '3.3.3.3')).json();
  const shared = await request('/api/publications/pending/' + pending.id + '/publish', { method: 'POST', headers: { Authorization: 'Bearer x', 'X-Huma-Ticket': pending.ticket } });
  const id = (await shared.json()).path.slice('/original/'.length).split('#')[0];
  // Headers that promise 8 MB, and no body: the answer comes anyway.
  const status = await new Promise((resolve, reject) => {
    const req = http.request({ port, host: '127.0.0.1', method: 'POST', path: '/api/publications/' + id + '/replay', headers: { 'Content-Type': 'application/json', 'Content-Length': 8 * 1024 * 1024 } }, res => { resolve(res.statusCode); req.destroy(); });
    req.on('error', reject); req.flushHeaders();
  });
  assert.equal(status, 403);
  assert.equal(replayMessage(id, null).startsWith('Huma replay v1'), true); // the Mac's message is unchanged
});

test('sharing one page again is free for everyone else’s allowance', { timeout: 30000 }, async t => {
  const { request } = await running(t, { authenticate: async token => hash(token),
    quotaLimits: { globalCount: 1, globalBytes: 1024 ** 3, uploaderCount: 3, uploaderBytes: 1024 ** 3 } });
  const share = async who => {
    const pending = await (await prepare(request, '4.4.4.' + who.length)).json();
    return (await request('/api/publications/pending/' + pending.id + '/publish', { method: 'POST', headers: { Authorization: 'Bearer ' + who, 'X-Huma-Ticket': pending.ticket } })).status;
  };
  assert.equal(await share('writer'), 200);
  assert.equal(await share('writer'), 200); // the same proof again: within the writer's own allowance only
  assert.equal(await share('writer'), 200);
  assert.equal(await share('writer'), 429); // ...which still ends
});

test('the open Turnstile check is limited per client and can’t crowd out publishing', async t => {
  let release; const held = new Promise(resolve => { release = resolve; });
  const send = async (url, { body }) => { if (JSON.parse(body).response === 'hold') await held;
    return { json: async () => ({ success: true, action: 'publish', hostname: '127.0.0.1' }) }; };
  const turnstile = configuredTurnstile({ HUMA_TURNSTILE_SITE_KEY: 'site-key-123', TURNSTILE_SECRET_KEY: 'secret' }, { fetch: send });
  const waiting = Array.from({ length: 32 }, () => turnstile.verify('hold', 'publish', { hostname: '127.0.0.1' }));
  assert.deepEqual(await turnstile.verify('x', 'publish', { hostname: '127.0.0.1' }), { ok: false, status: 429, reason: 'busy' });
  assert.deepEqual(await turnstile.verify('x', 'publish', { hostname: '127.0.0.1', pool: 'publish' }), { ok: true });
  release(); await Promise.all(waiting);
  // The route: a client gets 30 checks a minute.
  let minute = 0;
  const route = turnstileRoutes(turnstile, { now: () => minute * 60000 });
  const server = http.createServer(async (req, res) => {
    await route(req, res, new URL(req.url, 'http://x').pathname, { json: (r, status, data) => { r.writeHead(status, { 'Content-Type': 'application/json' }); r.end(JSON.stringify(data)); } });
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const check = from => fetch(`http://127.0.0.1:${server.address().port}/api/turnstile/verify`, { method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Forwarded-For': from }, body: JSON.stringify({ token: 't', action: 'publish' }) }).then(r => r.status);
  for (let i = 0; i < 30; i++) assert.equal(await check('5.5.5.5'), 200);
  assert.equal(await check('5.5.5.5'), 429);
  assert.equal(await check('5.5.5.6'), 200);
  minute++;
  assert.equal(await check('5.5.5.5'), 200);
});
