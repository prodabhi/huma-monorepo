import { fileURLToPath } from 'node:url';
import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { createHash } from 'node:crypto';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { S3Client } from '@aws-sdk/client-s3';
import { LocalObjectStore, R2ObjectStore, configuredObjectStore } from '../object-store.mjs';
import { createRegistry } from '../registry.mjs';
import { checkDownloadedPublication, expectedMaster } from '../publication-contract.mjs';
import { verify } from '../verify-core/node.mjs';
import { shareAssetFiles } from '../share-assets.mjs';

const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const fixture = async (name = 'Assurance250') => {
  const proof = await readFile(new URL('../../extra/experiments/noir-compact/browser/test/fixtures/'+name+'.json', import.meta.url), 'utf8');
  return { proof, text: JSON.parse(proof).text };
};
async function running(t, options = {}) {
  const directory = await mkdtemp(path.join(tmpdir(), 'huma-publications-'));
  const server = await createRegistry({ store: directory, publicationOptions: {
    authenticate: async token => { if (token !== 'test-owner-session') throw Object.assign(new Error('Sign in required.'), { status: 401 }); return hash('test-owner'); }, ...options,
  } });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(async () => { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); await rm(directory, { recursive: true, force: true }); });
  const base = `http://127.0.0.1:${server.address().port}`;
  return { base, directory, request: (route, options) => fetch(base + route, options) };
}
const upload = (proof, text, access = 'link') => JSON.stringify({ kind: 'huma-publication-upload-v1', access, proof,
  master: { mediaType: 'text/plain;charset=utf-8', base64: Buffer.from(text).toString('base64') } });
const prepare = (request, body) => request('/api/publications/prepare', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body });
const approve = (request, pending, token = 'test-owner-session') => request('/api/publications/pending/' + pending.id + '/publish', {
  method: 'POST', headers: { Authorization: 'Bearer ' + token, 'X-Huma-Ticket': pending.ticket },
});

test('master and real V5 proof require approval, persist and verify after protected download', { timeout: 30000 }, async t => {
  const { request, directory } = await running(t), { proof, text } = await fixture('AssuranceV5');
  const prepared = await prepare(request, upload(proof, text));
  assert.equal(prepared.status, 201, await prepared.clone().text());
  const pending = await prepared.json();
  const store = new LocalObjectStore(path.join(directory, 'publications'));
  assert.equal((await request('/api/publications/pending/' + pending.id)).status, 404);
  const before = await request('/api/publications/pending/' + pending.id, { headers: { Authorization: 'Bearer ' + pending.ticket } });
  const staged = await before.json();
  assert.equal(staged.status, 'awaiting-approval');
  await assert.rejects(store.get('objects/' + staged.manifest.master.hash, 65536)); // No object publication at prepare.
  assert.equal((await approve(request, pending, 'invalid-owner-session')).status, 401);
  const published = await approve(request, pending);
  assert.equal(published.status, 200, await published.clone().text());
  const value = await published.json(), [pathname, token] = value.path.split('#'), id = pathname.slice('/original/'.length);
  assert.equal((await request('/original/' + id)).status, 200);
  for (const part of ['', '/master', '/proof']) assert.equal((await request('/api/publications/' + id + part)).status, 404);
  const headers = { Authorization: 'Bearer ' + token };
  const source = await (await request('/api/publications/' + id, { headers })).text();
  const master = new Uint8Array(await (await request('/api/publications/' + id + '/master', { headers })).arrayBuffer());
  const downloaded = new Uint8Array(await (await request('/api/publications/' + id + '/proof', { headers })).arrayBuffer());
  // Downloads travel compressed when the reader accepts it, and decode to the same bytes.
  for (const [accepts, encoding] of [['br, gzip', 'br'], ['gzip', 'gzip'], ['identity', null]]) {
    const response = await request('/api/publications/' + id + '/proof', { headers: { ...headers, 'Accept-Encoding': accepts } });
    assert.equal(response.headers.get('content-encoding'), encoding);
    assert.deepEqual(new Uint8Array(await response.arrayBuffer()), downloaded);
  }
  const manifest = await checkDownloadedPublication(source, id, master, downloaded);
  const report = await verify(new TextDecoder().decode(downloaded), { requirePolicy: 'huma-writing-rules-v1' }, expectedMaster(manifest, master));
  assert.equal(report.verified, true); assert.equal(report.statementHash, manifest.statementHash);
  assert.equal(report.proofReport.signaturesVerified, 7);
  assert.equal(report.proofReport.presenceSignaturesVerified, 2);
  assert.equal(new TextDecoder().decode(master), text);
  assert.equal(source.includes('test-owner'), false);
  assert.equal(source.includes('tokenHash'), false);
  const again = await (await approve(request, pending)).json(); assert.equal(again.path, value.path);
  const changed = Uint8Array.from(master); changed[0] ^= 1;
  await assert.rejects(checkDownloadedPublication(source, id, changed, downloaded));
  const changedProof = Uint8Array.from(downloaded); changedProof[0] ^= 1;
  await assert.rejects(checkDownloadedPublication(source, id, master, changedProof));
  await writeFile(path.join(directory, 'publications/objects', manifest.master.hash), 'swapped');
  assert.notEqual((await request('/api/publications/' + id + '/master', { headers })).status, 200);
});

test('shipped server rejects retired uploads while existing proof records stay readable', async t => {
  const { request, directory } = await running(t), { proof } = await fixture('AssuranceV5');
  const id = hash(proof);
  await writeFile(path.join(directory, id + '.json'), proof);
  const existing = await request('/api/proofs/' + id);
  assert.equal(existing.status, 200);
  assert.equal(await existing.text(), proof);
  for (const Authorization of [undefined, 'Bearer test-owner-session']) {
    const rejected = await request('/api/proofs', { method: 'POST',
      headers: { 'Content-Type': 'application/json', ...(Authorization ? { Authorization } : {}) }, body: proof });
    assert.equal(rejected.status, 410);
    assert.match((await rejected.json()).error, /master and proof together/);
  }
  assert.equal((await request('/verify/' + id)).status, 200);
  assert.equal(await readFile(path.join(directory, id + '.json'), 'utf8'), proof);
});

test('all declared approval chunks including lazy wallet assets are served; traversal stays rejected', async t => {
  const { request } = await running(t);
  const files = await shareAssetFiles(fileURLToPath(new URL('../', import.meta.url)));
  // World ID sign-in, loaded lazily (Privy's wallet screens, off for now, were here before).
  assert.ok(files.some(name => name.includes('WorldSignIn')));
  for (const name of files.filter(name => name.startsWith('assets/'))) {
    const response = await request('/share/' + name);
    assert.equal(response.status, 200, name);
    if (name.endsWith('.wasm')) assert.equal(response.headers.get('content-type'), 'application/wasm');
  }
  for (const name of ['..%2f..%2f.env.local', '%2e%2e%2fregistry.mjs', '.env.js', '../.vite/manifest.json']) {
    assert.equal((await request('/share/assets/' + name)).status, 404);
  }
});

test('incorrect master, unknown private fields and foreign origins never become a publication', { timeout: 30000 }, async t => {
  const { request } = await running(t), { proof, text } = await fixture();
  assert.equal((await prepare(request, upload(proof, text + '!'))).status, 422);
  const leaked = JSON.parse(upload(proof, text)); leaked.privateHistory = 'must-not-be-retained';
  assert.equal((await prepare(request, JSON.stringify(leaked))).status, 422);
  const response = await request('/api/publications/prepare', { method: 'POST', headers: { 'Content-Type': 'application/json', Origin: 'https://other.invalid' }, body: upload(proof, text) });
  assert.equal(response.status, 403);
  const empty = JSON.parse(upload(proof, text)); empty.master.base64 = '';
  assert.equal((await prepare(request, JSON.stringify(empty))).status, 422);
});

test('public master keeps exact final whitespace, and expired staging cannot approve', { timeout: 30000 }, async t => {
  let now = Date.now();
  const { request } = await running(t, { now: () => now }), { proof, text } = await fixture();
  const pending = await (await prepare(request, upload(proof, text + ' \t', 'public'))).json();
  const value = await (await approve(request, pending)).json(), id = value.id;
  const master = await (await request('/api/publications/' + id + '/master')).text();
  assert.equal(master, text + ' \t'); // Exact stored master; proof text policy is separately canonicalized.
  assert.equal((await request('/api/publications/' + id + '/proof')).status, 200);
  const another = await (await prepare(request, upload(proof, text))).json();
  now += 11 * 60 * 1000;
  assert.equal((await approve(request, another)).status, 404);
});

test('R2 adapter sends signed S3 requests, handles duplicate writes and rejects swapped/oversized objects', { timeout: 15000 }, async t => {
  const objects = new Map(), seen = [];
  const server = http.createServer(async (req, res) => {
    seen.push(req.headers);
    assert.match(req.headers.authorization, /Credential=test-r2-access\/[0-9]{8}\/auto\/s3\/aws4_request/);
    const key = new URL(req.url, 'http://localhost').pathname;
    if (req.method === 'PUT') {
      const chunks = []; for await (const chunk of req) chunks.push(chunk);
      if (objects.has(key)) { res.writeHead(412, { 'Content-Type': 'application/xml' }); res.end('<Error><Code>PreconditionFailed</Code></Error>'); }
      else { assert.equal(req.headers['if-none-match'], '*'); objects.set(key, Buffer.concat(chunks)); res.writeHead(200); res.end(); }
    } else {
      const bytes = objects.get(key); if (!bytes) { res.writeHead(404); res.end(); }
      else { res.writeHead(200, { 'Content-Length': bytes.length }); res.end(bytes); }
    }
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const client = new S3Client({ endpoint: `http://127.0.0.1:${server.address().port}`, region: 'auto', forcePathStyle: true, maxAttempts: 1,
    credentials: { accessKeyId: 'test-r2-access', secretAccessKey: 'test-r2-secret' }, requestChecksumCalculation: 'WHEN_REQUIRED', responseChecksumValidation: 'WHEN_REQUIRED' });
  const store = new R2ObjectStore({ bucket: 'test-masters', client });
  t.after(async () => { store.close(); server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); });
  const bytes = Buffer.from('exact master'), key = 'objects/' + hash(bytes);
  await store.put(key, bytes); await store.put(key, bytes);
  assert.deepEqual(await store.get(key, bytes.length), bytes);
  await assert.rejects(store.get(key, 1));
  objects.set('/test-masters/' + key, Buffer.from('swapped'));
  await assert.rejects(store.get(key, 65536));
  await assert.rejects(store.put(key, Buffer.from('wrong hash')));
  assert.ok(seen.length >= 5);
  assert.throws(() => configuredObjectStore('/unused', { HUMA_STORAGE_BACKEND: 'r2' }));
  assert.throws(() => new R2ObjectStore({ bucket: 'test-masters', endpoint: 'http://untrusted.invalid', accessKeyId: 'x', secretAccessKey: 'y' }));
});

test('storage retry reuses a durable grant and a new publication cannot bypass the allowance', { timeout: 30000 }, async t => {
  const storage = await mkdtemp(path.join(tmpdir(), 'huma-publication-quota-'));
  t.after(() => rm(storage, { recursive: true, force: true }));
  class InterruptedStore extends LocalObjectStore {
    failNext = true; writes = 0;
    async put(key, bytes) {
      this.writes++;
      if (this.failNext) { this.failNext = false; throw new Error('Simulated storage interruption.'); }
      return super.put(key, bytes);
    }
  }
  const objectStore = new InterruptedStore(storage);
  const { request } = await running(t, { objectStore,
    quotaLimits: { globalCount: 1, globalBytes: 2 * 1024 * 1024, uploaderCount: 1, uploaderBytes: 2 * 1024 * 1024 } });
  const { proof, text } = await fixture(), pending = await (await prepare(request, upload(proof, text))).json();
  assert.notEqual((await approve(request, pending)).status, 200);
  const approved = await approve(request, pending);
  assert.equal(approved.status, 200, await approved.clone().text());
  const before = objectStore.writes;
  const another = await (await prepare(request, upload(proof, text))).json();
  assert.equal((await approve(request, another)).status, 429);
  assert.equal(objectStore.writes, before); // No master/proof/record writes when quota denies.
});

test('a quota-denied request reports its limit and can retry after UTC rollover while its ticket is live', { timeout: 30000 }, async t => {
  let now = Date.parse('2026-10-23T23:59:00Z');
  const { request } = await running(t, { now: () => now,
    quotaLimits: { globalCount: 1, globalBytes: 2 * 1024 * 1024, uploaderCount: 1, uploaderBytes: 2 * 1024 * 1024 } });
  const { proof, text } = await fixture();
  const first = await (await prepare(request, upload(proof, text))).json();
  assert.equal((await approve(request, first)).status, 200);
  const next = await (await prepare(request, upload(proof, text))).json();
  assert.equal((await approve(request, next)).status, 429);
  const status = await (await request('/api/publications/pending/' + next.id, { headers: { Authorization: 'Bearer ' + next.ticket } })).json();
  assert.equal(status.approvalError, 'daily-limit'); assert.equal(status.status, 'awaiting-approval'); assert.equal(status.path, undefined);
  now += 2 * 60 * 1000;
  const retried = await approve(request, next); assert.equal(retried.status, 200, await retried.clone().text());
  assert.equal((await retried.json()).approvalError, undefined);
});

test('receipts follow the link token and say who shared the page; there is no on-chain record', { timeout: 60000 }, async t => {
  const { privateKeyToAccount } = await import('viem/accounts');
  const { publicationMessage } = await import('../publications.mjs');
  const wallet = privateKeyToAccount('0x' + '11'.repeat(32));
  const { request } = await running(t, { authenticate: async token => {
    if (token !== 'test-owner-session') throw Object.assign(new Error('Sign in required.'), { status: 401 });
    return { owner: hash('test-owner'), wallets: [wallet.address] };
  } });
  const { proof, text } = await fixture('Long400V2');
  const prepared = await prepare(request, upload(proof, text)); assert.equal(prepared.status, 201, await prepared.clone().text());
  const pending = await prepared.json();
  const { manifest } = await (await request('/api/publications/pending/' + pending.id, { headers: { Authorization: 'Bearer ' + pending.ticket } })).json();
  const published = await (await request('/api/publications/pending/' + pending.id + '/publish', { method: 'POST',
    headers: { Authorization: 'Bearer test-owner-session', 'X-Huma-Ticket': pending.ticket, 'Content-Type': 'application/json' },
    body: JSON.stringify({ wallet: wallet.address, signature: await wallet.signMessage({ message: publicationMessage(manifest) }) }) })).json();
  const [id, token] = published.path.slice('/original/'.length).split('#');
  const receipt = tok => request('/api/publications/' + id + '/receipt', { headers: { Authorization: 'Bearer ' + tok } });
  assert.equal((await receipt('0'.repeat(64))).status, 404); // link-only pages keep their token
  const body = await (await receipt(token)).json();
  assert.equal(body.owner.wallet, wallet.address); assert.equal(body.chain, undefined);
  assert.equal((await request('/api/publications/' + id + '/chain', { method: 'POST', headers: { Authorization: 'Bearer ' + token } })).status, 404);
  assert.equal((await (await request('/api/publication-config')).json()).chain, undefined);
});

test('a page copied from another writer can’t be shared again under a second account', { timeout: 60000 }, async t => {
  const owners = { 'alice-session': hash('alice'), 'mallory-session': hash('mallory') };
  const { request } = await running(t, { authenticate: async token => {
    if (!owners[token]) throw Object.assign(new Error('Sign in required.'), { status: 401 });
    return owners[token];
  } });
  const { proof, text } = await fixture('Long400V3');
  const share = async token => approve(request, await (await prepare(request, upload(proof, text))).json(), token);
  assert.equal((await share('alice-session')).status, 200);
  const copied = await share('mallory-session');
  assert.equal(copied.status, 403); assert.match((await copied.json()).error, /first shared from another Huma account/);
  assert.equal((await share('alice-session')).status, 200); // the writer can still share it again
  // A first-format long page can be re-signed by anyone, so it isn't accepted at all.
  const old = await fixture('Long600');
  assert.equal((await prepare(request, upload(old.proof, old.text))).status, 422);
});

test('onboarding sign-in hands the account to the app only through its secret code', async t => {
  const { request } = await running(t, { authenticate: async token => {
    if (token !== 'test-owner-session') throw Object.assign(new Error('Sign in required.'), { status: 401 });
    return { owner: hash('test-owner'), wallets: ['0x' + 'a'.repeat(40)], account: 'writer@example.com' };
  } });
  const code = 'c'.repeat(64), poll = (value = code) => request('/api/publications/signin', { headers: { 'X-Huma-Signin': value } }).then(r => r.json());
  assert.deepEqual(await poll(), { status: 'waiting' });
  const post = (token, value = code) => request('/api/publications/signin', { method: 'POST', headers: { Authorization: 'Bearer ' + token, 'X-Huma-Signin': value } });
  assert.equal((await post('forged')).status, 401);
  assert.deepEqual(await poll(), { status: 'waiting' });
  assert.equal((await post('test-owner-session')).status, 200);
  assert.deepEqual(await poll(), { status: 'signed-in', account: 'writer@example.com', wallet: '0x' + 'a'.repeat(40), device: false });
  assert.deepEqual(await poll('d'.repeat(64)), { status: 'waiting' });
  assert.equal((await request('/api/publications/signin', { headers: { 'X-Huma-Signin': 'short' } })).status, 400);
});

test('the account name comes from the first sign-in account, never a wallet', async () => {
  const { accountName } = await import('../publications.mjs');
  assert.equal(accountName([{ type: 'wallet', address: '0x1' }, { type: 'google_oauth', email: 'a@b.co' }]), 'a@b.co');
  assert.equal(accountName([{ type: 'email', address: 'e@x.io' }]), 'e@x.io');
  assert.equal(accountName([{ type: 'github_oauth', username: 'writer' }]), 'writer');
  assert.equal(accountName([{ type: 'wallet', address: '0x1' }]), null);
});

test('after one sign-in that authorizes this Mac, Finish publishes with the Mac key and no browser', { timeout: 60000 }, async t => {
  const { generateKeyPairSync, sign } = await import('node:crypto');
  const { privateKeyToAccount } = await import('viem/accounts');
  const { publicationMessage } = await import('../publications.mjs');
  const { deviceAuthorizationMessage } = await import('../publication-contract.mjs');
  const wallet = privateKeyToAccount('0x' + '22'.repeat(32));
  // The real replay check is covered by the upload test below; here a replay is this page's when it says so.
  const { request } = await running(t, { checkReplay: async replay => { if (replay !== '{"this":"page"}') throw new Error('Not this page.'); },
    authenticate: async token => {
      if (token !== 'test-owner-session') throw Object.assign(new Error('Sign in required.'), { status: 401 });
      return { owner: hash('test-owner'), wallets: [wallet.address], account: 'writer@example.com' };
    } });
  const { publicKey: keyObject, privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const jwk = keyObject.export({ format: 'jwk' }), publicKey = '04' + Buffer.from(jwk.x, 'base64url').toString('hex') + Buffer.from(jwk.y, 'base64url').toString('hex');
  const code = 'e'.repeat(64);
  const signIn = signature => request('/api/publications/signin', { method: 'POST',
    headers: { Authorization: 'Bearer test-owner-session', 'X-Huma-Signin': code, 'Content-Type': 'application/json' },
    body: JSON.stringify({ wallet: wallet.address, publicKey, signature }) });
  assert.equal((await signIn('0x' + '1'.repeat(130))).status, 403); // not the wallet's signature
  assert.equal((await signIn(await wallet.signMessage({ message: deviceAuthorizationMessage(wallet.address, publicKey) }))).status, 200);
  const status = await (await request('/api/publications/signin', { headers: { 'X-Huma-Signin': code } })).json();
  assert.deepEqual([status.wallet, status.device], [wallet.address, true]);

  // The current page proof (v3: parts proved on their own); pages proved with 0.1 (v2) publish in the receipts test.
  const { proof, text } = await fixture('Long400V3');
  const pending = await (await prepare(request, upload(proof, text))).json();
  const { manifest } = await (await request('/api/publications/pending/' + pending.id, { headers: { Authorization: 'Bearer ' + pending.ticket } })).json();
  const publish = (signature, key = publicKey, profile = { name: '  Swayam   Karle ', avatar: 'swayam-3' }) => request('/api/publications/pending/' + pending.id + '/publish-device', { method: 'POST',
    headers: { 'X-Huma-Ticket': pending.ticket, 'Content-Type': 'application/json' }, body: JSON.stringify({ wallet: wallet.address, publicKey: key, signature, profile }) });
  const signature = sign('sha256', Buffer.from(publicationMessage(manifest)), privateKey).toString('base64');
  assert.equal((await publish(sign('sha256', Buffer.from('another page'), privateKey).toString('base64'))).status, 403);
  assert.equal((await publish(signature, '04' + 'ab'.repeat(64))).status, 401); // an unlinked key
  const published = await publish(signature); assert.equal(published.status, 200, await published.clone().text());
  const answer = await published.json(), [id, token] = answer.path.slice('/original/'.length).split('#');
  // The short link comes with the answer, the same one asking for it gives.
  assert.match(answer.short, /^\/p\/[0-9A-Za-z]{8,12}#[0-9A-Za-z]+$/);
  assert.equal((await (await request('/api/publications/' + id + '/short', { method: 'POST', headers: { Authorization: 'Bearer ' + token } })).json()).path, answer.short);
  const { owner } = await (await request('/api/publications/' + id + '/receipt', { headers: { Authorization: 'Bearer ' + token } })).json();
  assert.equal(owner.wallet, wallet.address);
  assert.equal(owner.device.publicKey, publicKey);
  assert.equal(owner.authorization.message, deviceAuthorizationMessage(wallet.address, publicKey));
  // The writer's name and face come back with the page, tidied.
  const { profile } = await (await request('/api/publications/' + id + '/receipt', { headers: { Authorization: 'Bearer ' + token } })).json();
  assert.deepEqual(profile, { name: 'Swayam Karle', avatar: 'swayam-3' });
  // A pasted link previews as the writer's page, without its text or token.
  const preview = await (await request('/original/' + id)).text();
  assert.match(preview, /<meta property="og:title" content="Swayam Karle typed this · Huma">/);
  // One card only: none of the verify page's own tags, and kept out of search.
  assert.equal(preview.match(/og:title/g).length, 1); assert.doesNotMatch(preview, /rel="canonical"/); assert.match(preview, /<meta name="robots" content="noindex">/);
  assert.match(preview, /og-page\.png/); assert.doesNotMatch(preview, new RegExp(text.slice(0, 20).replace(/[.*+?^${}()|[\]\\]/g, '\\$&')));

  // Sent to a writing request from this Mac, the inbox says so; a signature for another request doesn't count.
  const { requestMessage } = await import('../publication-contract.mjs');
  const made = await (await request('/api/requests', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ title: 'Essay', from: 'Ms. Lee' }) })).json();
  const submit = signature => request('/api/requests/' + made.id + '/submit', { method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ link: 'https://huma.social/original/' + id + '#' + token, signature }) });
  assert.equal((await submit(sign('sha256', Buffer.from(requestMessage('0'.repeat(32), id)), privateKey).toString('base64'))).status, 200);
  const first = await (await request('/api/requests/' + made.id + '/inbox', { headers: { Authorization: 'Bearer ' + made.key } })).json();
  assert.equal(first.submissions[0].fromMac, false);
  assert.equal(first.submissions[0].name, 'Swayam Karle');
  const signed = await (await request('/api/requests', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ title: 'Essay 2', from: 'Ms. Lee' }) })).json();
  assert.equal((await request('/api/requests/' + signed.id + '/submit', { method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ link: 'https://huma.social/original/' + id + '#' + token, signature: sign('sha256', Buffer.from(requestMessage(signed.id, id)), privateKey).toString('base64') }) })).status, 200);
  assert.equal((await (await request('/api/requests/' + signed.id + '/inbox', { headers: { Authorization: 'Bearer ' + signed.key } })).json()).submissions[0].fromMac, true);

  // The same page shared again is a second link to the same stored files.
  const again = await (await prepare(request, upload(proof, text))).json();
  const { manifest: againManifest } = await (await request('/api/publications/pending/' + again.id, { headers: { Authorization: 'Bearer ' + again.ticket } })).json();
  const second = await request('/api/publications/pending/' + again.id + '/publish-device', { method: 'POST',
    headers: { 'X-Huma-Ticket': again.ticket, 'Content-Type': 'application/json' },
    body: JSON.stringify({ wallet: wallet.address, publicKey, signature: sign('sha256', Buffer.from(publicationMessage(againManifest)), privateKey).toString('base64') }) });
  assert.equal(second.status, 200, await second.clone().text());
  const [secondID, secondToken] = (await second.json()).path.slice('/original/'.length).split('#');
  assert.notEqual(secondID, id);

  // The writer turns the replay on and off whenever they like, from the Mac that shared the page.
  const { replayMessage } = await import('../publication-contract.mjs');
  const digest = value => createHash('sha256').update(value).digest('hex');
  const setReplay = (replay, signature, key = publicKey) => request('/api/publications/' + id + '/replay', { method: 'POST',
    headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ publicKey: key, signature, replay }) });
  const signReplay = (replay, page = id) => sign('sha256', Buffer.from(replayMessage(page, replay === null ? null : digest(replay))), privateKey).toString('base64');
  const auth = { headers: { Authorization: 'Bearer ' + token } };
  const mine = '{"this":"page"}';
  assert.equal((await setReplay(mine, signReplay(mine, '0'.repeat(64)))).status, 403);                 // signed for another page
  assert.equal((await setReplay(mine, signReplay(null))).status, 403);                                  // signed to turn it off
  assert.equal((await setReplay(mine, signReplay(mine), '04' + 'ab'.repeat(64))).status, 403);         // not the sharing Mac
  assert.equal((await setReplay('{"other":"page"}', signReplay('{"other":"page"}'))).status, 422);      // not this page's replay
  const on = await setReplay(mine, signReplay(mine)); assert.equal(on.status, 200, await on.clone().text());
  assert.equal((await (await request('/api/publications/' + id + '/receipt', auth)).json()).replay, true);
  assert.equal(await (await request('/api/publications/' + id + '/replay', auth)).text(), mine);
  const off = await setReplay(null, signReplay(null)); assert.equal(off.status, 200, await off.clone().text());
  assert.equal((await (await request('/api/publications/' + id + '/receipt', auth)).json()).replay, false);
  assert.equal((await request('/api/publications/' + id + '/replay', auth)).status, 404);

  // Only the Mac that shared the page can take its link down; then the link and its files are gone.
  const { removalMessage } = await import('../publication-contract.mjs');
  const remove = (signature, key = publicKey) => request('/api/publications/' + id + '/remove', { method: 'POST',
    headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ publicKey: key, signature }) });
  const other = generateKeyPairSync('ec', { namedCurve: 'P-256' }).publicKey.export({ format: 'jwk' });
  assert.equal((await remove(sign('sha256', Buffer.from(removalMessage(id)), privateKey).toString('base64'),
    '04' + Buffer.from(other.x, 'base64url').toString('hex') + Buffer.from(other.y, 'base64url').toString('hex'))).status, 403);
  assert.equal((await remove(sign('sha256', Buffer.from(removalMessage('0'.repeat(64))), privateKey).toString('base64'))).status, 403);
  assert.equal((await request('/api/publications/' + id + '/master', { headers: { Authorization: 'Bearer ' + token } })).status, 200);
  const removed = await remove(sign('sha256', Buffer.from(removalMessage(id)), privateKey).toString('base64'));
  assert.equal(removed.status, 200, await removed.clone().text());
  for (const part of ['', '/master', '/proof', '/receipt']) {
    const response = await request('/api/publications/' + id + part, { headers: { Authorization: 'Bearer ' + token } });
    assert.equal(response.status, 410); assert.match((await response.json()).error, /removed/);
  }
  // Removing one link never breaks another that shares its files.
  for (const part of ['/master', '/proof']) {
    assert.equal((await request('/api/publications/' + secondID + part, { headers: { Authorization: 'Bearer ' + secondToken } })).status, 200);
  }
});

test('writer profiles are checked, and faces are drawn only for plain seeds', async t => {
  const { writerProfile } = await import('../publication-contract.mjs');
  assert.equal(writerProfile(undefined), null);
  // Spaces tidied and accents composed, so the same name is always the same characters.
  assert.deepEqual(writerProfile({ name: ' Ada\u0301  L ', avatar: 'a_b-1' }), { name: 'Ad\u00e1 L', avatar: 'a_b-1' });
  for (const bad of [{ name: '', avatar: 'x' }, { name: 'x'.repeat(41), avatar: 'x' }, { name: 'a\u0000b', avatar: 'x' }, { name: 'Ada', avatar: '../x' }, 'Ada'])
    assert.throws(() => writerProfile(bad), /40 characters/);
  const { request } = await running(t);
  const face = await request('/avatar/swayam.svg');
  assert.equal(face.status, 200); assert.equal(face.headers.get('content-type'), 'image/svg+xml');
  assert.match(face.headers.get('content-security-policy'), /default-src 'none'/);
  const svg = await face.text(); assert.match(svg, /^<svg/); assert.doesNotMatch(svg, /<script/); assert.match(svg, /CC BY 4\.0|creativecommons/i);
  assert.equal((await request('/avatar/a.b.svg')).status, 404);
});

test('a replay is checked on upload and served only to link holders', { timeout: 60000 }, async t => {
  const { proof, text } = await fixture('Long400V2');
  // The Mac-made replay belongs to another page, so the real check turns it away.
  const replay = await readFile(new URL('./fixtures/replay-swift.json', import.meta.url), 'utf8');
  const strict = await running(t);
  const withReplay = JSON.stringify({ ...JSON.parse(upload(proof, text)), replay });
  assert.equal((await prepare(strict.request, withReplay)).status, 422);
  // Past that check (stubbed here), the replay is stored by content and served to link holders.
  const { verifyPublicationUpload } = await import('../publications.mjs');
  const { request } = await running(t, { verifyUpload: async source => {
    const parsed = JSON.parse(source), { replay: sent, ...rest } = parsed;
    return { ...await verifyPublicationUpload(JSON.stringify(rest)), replay: sent };
  } });
  const pending = await (await prepare(request, withReplay)).json();
  const published = await approve(request, pending); assert.equal(published.status, 200, await published.clone().text());
  const [id, token] = (await published.json()).path.slice('/original/'.length).split('#');
  const auth = { headers: { Authorization: 'Bearer ' + token } };
  assert.equal((await (await request('/api/publications/' + id + '/receipt', auth)).json()).replay, true);
  assert.equal(await (await request('/api/publications/' + id + '/replay', auth)).text(), replay);
  assert.equal((await request('/api/publications/' + id + '/replay')).status, 404); // the link's token is required
  // A page shared without one says so.
  const plain = await (await prepare(request, upload(proof, text))).json();
  const [plainID, plainToken] = (await (await approve(request, plain)).json()).path.slice('/original/'.length).split('#');
  const plainAuth = { headers: { Authorization: 'Bearer ' + plainToken } };
  assert.equal((await (await request('/api/publications/' + plainID + '/receipt', plainAuth)).json()).replay, false);
  assert.equal((await request('/api/publications/' + plainID + '/replay', plainAuth)).status, 404);
  assert.match(await (await request('/original/' + plainID)).text(), /<title>Typed by a person · Huma<\/title>/);
});

test('a writing request collects shared pages; only its creator opens the inbox', { timeout: 60000 }, async t => {
  const { request } = await running(t);
  const post = (route, body) => request(route, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
  assert.equal((await post('/api/requests', { title: '  ', from: 'Ms. Lee' })).status, 400);
  const made = await post('/api/requests', { title: 'Essay:\u0007 My summer ', from: ' Ms.  Lee', note: '500 words.' });
  assert.equal(made.status, 201);
  const { id, key } = await made.json();
  assert.deepEqual(Object.keys(await (await request('/api/requests/' + id)).json()).sort(), ['created', 'from', 'note', 'title']);
  assert.equal((await (await request('/api/requests/' + id)).json()).title, 'Essay: My summer');
  assert.equal((await request('/r/' + id)).status, 200);

  const { proof, text } = await fixture('Long400V2');
  const pending = await (await prepare(request, upload(proof, text))).json();
  const link = 'https://huma.social' + (await (await approve(request, pending)).json()).path;
  // Links that don't open a page, or a page's link without its token, are turned away.
  assert.equal((await post('/api/requests/' + id + '/submit', { link: 'https://example.com/hello' })).status, 400);
  assert.equal((await post('/api/requests/' + id + '/submit', { link: link.replace(/#.*/, '#' + '0'.repeat(64)) })).status, 404);
  const sent = await post('/api/requests/' + id + '/submit', { link });
  assert.deepEqual(await sent.json(), { status: 'sent', from: 'Ms. Lee' });
  assert.equal((await (await post('/api/requests/' + id + '/submit', { link })).json()).status, 'already-sent');

  const inbox = (token = key) => request('/api/requests/' + id + '/inbox', { headers: { Authorization: 'Bearer ' + token } });
  assert.equal((await inbox('1'.repeat(64))).status, 404);
  const { submissions } = await (await inbox()).json();
  assert.equal(submissions.length, 1);
  assert.equal(submissions[0].words, text.split(/\s+/).filter(Boolean).length);
  assert.equal(submissions[0].fromMac, false); // pasted in the browser, not sent from the writer's Mac
  assert.equal('/original/' + submissions[0].page + '#' + submissions[0].token, new URL(link).pathname + new URL(link).hash);
});

test('a shared page has one short link, opened by its code and the key after the #', { timeout: 30000 }, async t => {
  const { request } = await running(t), { proof, text } = await fixture('AssuranceV5');
  const pending = await (await prepare(request, upload(proof, text))).json();
  const [id, token] = (await (await approve(request, pending)).json()).path.slice('/original/'.length).split('#');
  const shorten = bearer => request('/api/publications/' + id + '/short', { method: 'POST', headers: bearer ? { Authorization: 'Bearer ' + bearer } : {} });
  assert.equal((await shorten()).status, 404); // only someone who can open the page gets its short link
  const { path: link } = await (await shorten(token)).json();
  assert.match(link, /^\/p\/[A-Za-z0-9]{8}#[A-Za-z0-9]{16}$/);
  assert.equal((await (await shorten(token)).json()).path, link); // asking again gives the same link
  const [pathname, key] = link.split('#'), code = pathname.slice(3);
  assert.equal((await (await shorten(code + '.' + key)).json()).path, link);
  // The short page is the reader for that page; the key never reaches the server, so the page needs it to read.
  const page = await request(pathname);
  assert.equal(page.status, 200);
  assert.match(await page.text(), new RegExp(`<meta name="huma-page" content="${id}">`));
  assert.equal((await request('/p/' + 'Zz9'.repeat(3))).status, 404);
  const read = bearer => request('/api/publications/' + id + '/master', { headers: { Authorization: 'Bearer ' + bearer } });
  assert.equal(await (await read(code + '.' + key)).text(), text);
  assert.equal((await read(code + '.' + 'A'.repeat(16))).status, 404);
  assert.equal((await read(key)).status, 404);
  assert.equal((await request('/api/publications/' + id + '/short', { headers: { Authorization: 'Bearer ' + token } })).status, 405);
  // A writing request takes the short link like the full one, and its inbox opens it the same way.
  const made = await (await request('/api/requests', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ title: 'Essay', from: 'Ms. Lee' }) })).json();
  const sent = await request('/api/requests/' + made.id + '/submit', { method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ link: 'https://huma.social' + link }) });
  assert.equal(sent.status, 200, await sent.clone().text());
  const { submissions } = await (await request('/api/requests/' + made.id + '/inbox', { headers: { Authorization: 'Bearer ' + made.key } })).json();
  assert.equal(submissions[0].page, id); assert.equal(submissions[0].token, code + '.' + key);
});
