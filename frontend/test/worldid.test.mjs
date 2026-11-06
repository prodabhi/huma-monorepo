import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, randomBytes, sign } from 'node:crypto';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { hashSignal } from '@worldcoin/idkit-core/hashing';
import { createRegistry } from '../registry.mjs';
import { statementHash, TEXT_POLICY } from '../verify-core/contract.mjs';
import { configuredWorldID, publicWorldID, worldIDRoutes, pageSignal, accountSignal, VERIFY_URL } from '../worldid-verify.mjs';
import { LocalObjectStore } from '../object-store.mjs';
import { deviceOwnerKey } from '../documents.mjs';
import { documentRequestMessage, publicationMessage, worldIDSigninMessage } from '../publication-contract.mjs';

// Made-up app, RP and signing key. World's verify endpoint is always stubbed: no network.
const ENV = { HUMA_WORLD_APP_ID: 'app_example1234', HUMA_WORLD_RP_ID: 'rp_example1234', WORLD_RP_SIGNING_KEY: '0x' + '11'.repeat(32) };
const manifest = { master: { hash: 'a'.repeat(64) }, proof: { hash: 'b'.repeat(64) } };
const signal = pageSignal(manifest);
const NULLIFIER = '0x' + 'ab'.repeat(32);

/** An IDKit result as the browser would send it, for `signal`. */
const proofFor = (over = {}, item = {}) => ({ protocol_version: '4.0', nonce: '0x01', action: 'verify-publisher', environment: 'production',
  responses: [{ identifier: 'proof_of_human', signal_hash: hashSignal(signal), proof: ['1', '2', '3', '4', '5'], nullifier: NULLIFIER, issuer_schema_id: 1, expires_at_min: 1, ...item }], ...over });
/** A stand-in for World's verify endpoint: answers with `answer`, and records what was sent where. */
function world(answer = { success: true, environment: 'production' }, status = 200) {
  const calls = [];
  const fetch = async (url, init) => {
    calls.push({ url, body: JSON.parse(init.body), method: init.method });
    if (answer instanceof Error) throw answer;
    return { ok: status < 400, status, json: async () => answer };
  };
  return { fetch, calls };
}
const configured = (stub, env = ENV) => configuredWorldID(env, { fetch: stub.fetch, now: () => 1700000000000 });

test('World ID is off unless app, RP and signing key are all set, and then never asks World', async () => {
  const stub = world();
  for (const env of [{}, { HUMA_WORLD_APP_ID: ENV.HUMA_WORLD_APP_ID }, { ...ENV, WORLD_RP_SIGNING_KEY: 'short' }, { ...ENV, HUMA_WORLD_APP_ID: 'nope' }]) {
    const check = configured(stub, env);
    assert.equal(check.enabled, false);
    assert.equal(check.context(), null);
    assert.deepEqual(await check.verify(proofFor(), signal), { ok: true, off: true });
  }
  assert.equal(stub.calls.length, 0);
});

test('World ID is required to share by default, and HUMA_WORLD_REQUIRED=false makes it a badge', () => {
  assert.equal(configured(world()).required, true);
  assert.equal(configured(world(), { ...ENV, HUMA_WORLD_REQUIRED: 'false' }).required, false);
  assert.equal(configured(world(), {}).required, false); // off: nothing is required
});

test('the request context is signed here, and carries no key', () => {
  const check = configured(world());
  const context = check.context();
  assert.equal(check.enabled, true);
  assert.equal(context.rp_id, 'rp_example1234');
  assert.match(context.signature, /^0x[0-9a-f]+$/i);
  assert.ok(context.expires_at > context.created_at);
  assert.notEqual(check.context().nonce, context.nonce);
  assert.ok(!JSON.stringify([context, check.appId, check.rpId]).includes('11'.repeat(32)));
});

test('a proof of a unique human for this page is kept, with what World confirmed', async () => {
  const stub = world();
  const result = await configured(stub).verify(proofFor(), signal);
  assert.equal(result.ok, true);
  assert.equal(result.record.credential, 'proof_of_human');
  assert.equal(result.record.nullifier, NULLIFIER);
  assert.equal(result.record.verifiedAt, 1700000000000);
  assert.equal(stub.calls[0].url, VERIFY_URL + 'rp_example1234');
  assert.equal(stub.calls[0].method, 'POST');
  assert.equal(stub.calls[0].body.environment, 'production');
  // The Orb fallback of World ID 3.0 counts as the same credential.
  const legacy = await configured(world()).verify(proofFor({ protocol_version: '3.0' }, { identifier: 'orb' }), signal);
  assert.equal(legacy.record.credential, 'proof_of_human');
});

test('a proof that is not a unique human’s for this page is refused before and after World', async () => {
  const check = (answer, status) => { const stub = world(answer, status); return { stub, run: result => configured(stub).verify(result, signal) }; };
  // Never reaches World: wrong environment, action, credential, signal, or shape.
  const local = check();
  assert.equal((await local.run(proofFor({ environment: 'staging' }))).reason, 'environment');
  assert.equal((await local.run(proofFor({ action: 'other-action' }))).reason, 'action');
  assert.equal((await local.run(proofFor({}, { identifier: 'selfie' }))).reason, 'credential'); // a face is not a unique person
  assert.equal((await local.run(proofFor({}, { identifier: 'passport' }))).reason, 'credential');
  assert.equal((await local.run(proofFor({}, { signal_hash: hashSignal('huma-page:other') }))).reason, 'signal'); // made for another page
  assert.equal((await local.run(proofFor({}, { nullifier: 'nope' }))).reason, 'nullifier');
  assert.equal((await local.run(proofFor({ responses: [] }))).reason, 'responses');
  assert.equal((await local.run(proofFor({ responses: [proofFor().responses[0], proofFor().responses[0]] }))).reason, 'responses');
  for (const bad of [null, 'x', [], undefined]) assert.equal((await local.run(bad)).status, 400);
  assert.equal(local.stub.calls.length, 0);
  // World's own answer decides the rest.
  assert.deepEqual(await check({ success: false }).run(proofFor()), { ok: false, status: 403, reason: 'failed' });
  assert.deepEqual(await check({ code: 'invalid_proof' }, 400).run(proofFor()), { ok: false, status: 403, reason: 'rejected' });
  assert.deepEqual(await check({ success: true, environment: 'staging' }).run(proofFor()), { ok: false, status: 403, reason: 'failed' });
  assert.deepEqual(await check({}, 502).run(proofFor()), { ok: false, status: 503, reason: 'unreachable' });
  assert.deepEqual(await check(new Error('offline')).run(proofFor()), { ok: false, status: 503, reason: 'unreachable' });
});

test('a reader is shown a fingerprint, never the proof or the nullifier', async () => {
  const { record } = await configured(world()).verify(proofFor(), signal);
  const shown = publicWorldID(record);
  assert.equal(shown.verified, true);
  assert.match(shown.fingerprint, /^[0-9a-f]{12}$/);
  const text = JSON.stringify(shown);
  assert.ok(!text.includes(NULLIFIER) && !text.includes('"proof"'));
  assert.equal(publicWorldID(null), null);
  assert.equal(publicWorldID({}), null);
});

test('the routes tell the page the public config, sign for it, and limit a client', async () => {
  const sent = [];
  const json = (res, status, body) => sent.push({ status, body });
  const request = (method, headers = { 'content-type': 'application/json' }) => ({ method, headers, socket: { remoteAddress: '203.0.113.9' },
    async *[Symbol.asyncIterator]() { yield Buffer.from('{}'); } });
  let time = 0;
  const routes = worldIDRoutes(configured(world()), { now: () => time });
  assert.equal(await routes(request('GET'), {}, '/api/worldid', { json }), true);
  assert.deepEqual(sent.pop(), { status: 200, body: { appId: 'app_example1234', rpId: 'rp_example1234', action: 'verify-publisher', environment: 'production', required: true } });
  assert.equal(await routes(request('GET'), {}, '/api/elsewhere', { json }), false);
  assert.equal(await routes(request('GET'), {}, '/api/worldid/context', { json }), true);
  assert.equal(sent.pop().status, 405);
  assert.equal(await routes(request('POST', {}), {}, '/api/worldid/context', { json }), true);
  assert.equal(sent.pop().status, 415);
  await routes(request('POST'), {}, '/api/worldid/context', { json });
  const signed = sent.pop();
  assert.equal(signed.status, 200);
  assert.equal(signed.body.rp_context.rp_id, 'rp_example1234');
  for (let i = 0; i < 25; i++) await routes(request('POST'), {}, '/api/worldid/context', { json });
  assert.equal(sent.pop().status, 429);
  time += 60000; // a new minute
  await routes(request('POST'), {}, '/api/worldid/context', { json });
  assert.equal(sent.pop().status, 200);
  // Off: the page is told so, and nothing is signed.
  const off = worldIDRoutes(configured(world(), {}));
  await off(request('GET'), {}, '/api/worldid', { json });
  assert.deepEqual(sent.pop().body, { appId: null, rpId: null, action: null, environment: null, required: false });
  await off(request('POST'), {}, '/api/worldid/context', { json });
  assert.equal(sent.pop().status, 404);
});

// Sharing a page, end to end: the real registry and publication routes, with World's verify endpoint stubbed and the
// page's own proof check replaced by one that accepts a made-up page (so this runs without the Rust and Noir tools).
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const TEXT = 'A short page about one real person.';
async function madeUpPage(source) {
  const master = Buffer.from(TEXT), proof = JSON.stringify({ made: 'up', nonce: randomBytes(8).toString('hex') });
  const statement = { version: 1, contentKind: 'text', contentPolicy: TEXT_POLICY, contentHash: sha(master), byteLength: String(master.length),
    captureScheme: 'poseidon2-capture-v4', sessionBinding: sha('session'), captureHead: sha('head'), checkpointBinding: null, captureKeyHash: null,
    policyID: null, policySatisfied: null };
  const manifest = { kind: 'huma-publication-v1', publicationNonce: randomBytes(32).toString('hex'),
    master: { hash: sha(master), byteLength: master.length, mediaType: 'text/plain;charset=utf-8' },
    proof: { hash: sha(proof), byteLength: Buffer.byteLength(proof) }, statement, statementHash: await statementHash(statement), access: JSON.parse(source).access };
  return { manifest, proof, scoring: null };
}
const started = async base => ({ nonce: [BigInt('0x' + (await (await fetch(base + '/api/sessions', { method: 'POST' })).json()).nonce).toString(), '0'],
  elapsed: '0', start_unix: '0', end_unix: '0' });
async function running(t, worldId, { browser = true } = {}) {
  const directory = await mkdtemp(path.join(tmpdir(), 'huma-worldid-'));
  let base;
  const server = await createRegistry({ store: directory, publicationOptions: {
    authenticate: async token => { if (token !== 'test-owner-session') throw Object.assign(new Error('Sign in required.'), { status: 401 }); return sha('test-owner'); },
    // A browser page's journal says it was written in one (origin_present 0) and starts from this server's session nonce.
    verifyUpload: async source => ({ ...await madeUpPage(source), scoring: browser ? { journal: { origin_present: 0, ...await started(base) } } : null }), worldId } });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(async () => { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); await rm(directory, { recursive: true, force: true }); });
  base = `http://127.0.0.1:${server.address().port}`;
  const request = (route, options) => fetch(base + route, options);
  request.store = new LocalObjectStore(path.join(directory, 'publications'));
  return request;
}
/** A browser's publishing key, linked to `owner` as sign-in links it (the test sign-in's account by default), and its
 *  signed account requests. */
async function browser(request, owner = sha('test-owner')) {
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const raw = publicKey.export({ format: 'jwk' }), point = '04' + Buffer.from(raw.x, 'base64url').toString('hex') + Buffer.from(raw.y, 'base64url').toString('hex');
  await request.store.put(deviceOwnerKey(point), Buffer.from(JSON.stringify({ owner, wallet: '0x' + '1'.repeat(40) })));
  const send = (method, route, body = '') => {
    const time = Date.now(), signature = sign('sha256', Buffer.from(documentRequestMessage(method, route, time, sha(body))), { key: privateKey, dsaEncoding: 'der' }).toString('base64');
    return request(route, { method, ...(method === 'POST' ? { body } : {}),
      headers: { 'Content-Type': 'application/json', 'X-Huma-Key': point, 'X-Huma-Time': String(time), 'X-Huma-Signature': signature } });
  };
  return { point, send, link: proof => send('POST', '/api/documents/worldid', JSON.stringify({ proof })) };
}
/** A World ID made for linking the account of the browser with publishing key `point`. */
const linkProof = (point, item = {}) => proofFor({}, { signal_hash: hashSignal(accountSignal(point)), ...item });
async function prepared(request) {
  const response = await request('/api/publications/prepare', { method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ kind: 'huma-publication-upload-v1', access: 'link', proof: '{}',
      master: { mediaType: 'text/plain;charset=utf-8', base64: Buffer.from(TEXT).toString('base64') } }) });
  assert.equal(response.status, 201, await response.clone().text());
  const ticket = await response.json();
  const { manifest } = await (await request('/api/publications/pending/' + ticket.id, { headers: { Authorization: 'Bearer ' + ticket.ticket } })).json();
  return { ...ticket, signal: pageSignal(manifest) };
}
const publish = (request, pending, body = {}) => request('/api/publications/pending/' + pending.id + '/publish', { method: 'POST',
  headers: { Authorization: 'Bearer test-owner-session', 'X-Huma-Ticket': pending.ticket, 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
const proofOf = pending => {
  const proof = proofFor();
  proof.responses[0].signal_hash = hashSignal(pending.signal);
  return proof;
};

test('a page shared with a World ID shows a verified human, and anyone can fetch the proof to check it', { timeout: 60000 }, async t => {
  const stub = world();
  const request = await running(t, configured(stub));
  const pending = await prepared(request);
  const shared = await publish(request, pending, { worldId: proofOf(pending) });
  assert.equal(shared.status, 200, await shared.clone().text());
  assert.equal(stub.calls.length, 1);
  const [, id, key] = (await shared.json()).path.match(/^\/original\/([a-f0-9]{64})#([a-f0-9]{64})$/);
  const asReader = { headers: { Authorization: 'Bearer ' + key } };
  const receipt = await (await request(`/api/publications/${id}/receipt`, asReader)).json();
  assert.equal(receipt.worldId.verified, true);
  assert.match(receipt.worldId.fingerprint, /^[0-9a-f]{12}$/);
  assert.ok(!JSON.stringify(receipt).includes(NULLIFIER));
  const evidence = await (await request(`/api/publications/${id}/worldid`, asReader)).json();
  assert.equal(evidence.rpId, 'rp_example1234');
  assert.equal(evidence.signal, pending.signal);
  assert.equal(evidence.result.responses[0].nullifier, NULLIFIER);
  // Not without the page's link key.
  assert.equal((await request(`/api/publications/${id}/worldid`)).status, 404);
});

test('a page written in a browser can’t be shared without a World ID, and nothing is stored', { timeout: 60000 }, async t => {
  const stub = world();
  const request = await running(t, configured(stub));
  const pending = await prepared(request);
  const refused = await publish(request, pending, {});
  assert.equal(refused.status, 403);
  assert.match((await refused.json()).error, /Verify you’re human with World ID to share this page/);
  assert.equal(stub.calls.length, 0);
  // The same page, with its World ID, is shared.
  assert.equal((await publish(request, pending, { worldId: proofOf(pending) })).status, 200);
});

test('a Mac page is shared without a World ID, and so is a browser page when it is only a badge', { timeout: 60000 }, async t => {
  const mac = await running(t, configured(world()), { browser: false });
  const macPage = await prepared(mac);
  const shared = await publish(mac, macPage, {});
  assert.equal(shared.status, 200, await shared.clone().text());
  const [, id, key] = (await shared.json()).path.match(/^\/original\/([a-f0-9]{64})#([a-f0-9]{64})$/);
  const asReader = { headers: { Authorization: 'Bearer ' + key } };
  assert.equal((await (await mac(`/api/publications/${id}/receipt`, asReader)).json()).worldId, undefined);
  assert.equal((await mac(`/api/publications/${id}/worldid`, asReader)).status, 404);
  const optional = await running(t, configured(world(), { ...ENV, HUMA_WORLD_REQUIRED: 'false' }));
  assert.equal((await publish(optional, await prepared(optional), {})).status, 200);
});

test('a World ID that is not a unique human’s for this page stops the share, and a retry can still succeed', { timeout: 60000 }, async t => {
  const request = await running(t, configured(world({ success: true, environment: 'production' })));
  const pending = await prepared(request);
  const other = await prepared(request); // a proof made for a different page
  const refused = await publish(request, pending, { worldId: proofOf(other) });
  assert.equal(refused.status, 403);
  const staging = await publish(request, pending, { worldId: { ...proofOf(pending), environment: 'staging' } });
  assert.equal(staging.status, 403);
  assert.equal((await publish(request, pending, { worldId: proofOf(pending) })).status, 200);
  // World down: 503, and where it is required the page isn't shared without it; where it is only a badge it can be.
  const down = await running(t, configured(world(new Error('offline'))));
  const pendingDown = await prepared(down);
  assert.equal((await publish(down, pendingDown, { worldId: proofOf(pendingDown) })).status, 503);
  assert.equal((await publish(down, pendingDown, {})).status, 403);
  const soft = await running(t, configured(world(new Error('offline')), { ...ENV, HUMA_WORLD_REQUIRED: 'false' }));
  const pendingSoft = await prepared(soft);
  assert.equal((await publish(soft, pendingSoft, { worldId: proofOf(pendingSoft) })).status, 503);
  assert.equal((await publish(soft, pendingSoft, {})).status, 200);
});

test('with World ID off the write page is as before, and a proof sent anyway is refused', { timeout: 60000 }, async t => {
  const request = await running(t, configured(world(), {}));
  assert.deepEqual(await (await request('/api/worldid')).json(), { appId: null, rpId: null, action: null, environment: null, required: false });
  assert.doesNotMatch((await request('/write')).headers.get('content-security-policy') ?? '', /worldcoin/);
  const pending = await prepared(request);
  assert.equal((await publish(request, pending, { worldId: proofOf(pending) })).status, 409);
  assert.equal((await publish(request, pending, {})).status, 200);
});

test('with World ID on the write page may reach only World’s bridge', { timeout: 60000 }, async t => {
  const request = await running(t, configured(world()));
  const csp = (await request('/write')).headers.get('content-security-policy');
  assert.match(csp, /connect-src 'self' https:\/\/bridge\.worldcoin\.org;/);
  assert.match(csp, /frame-src 'none'/);
  assert.match(csp, /frame-ancestors 'none'/);
});

test('a writer links World ID once, and every page they share and their writer page show that same World ID', { timeout: 60000 }, async t => {
  const stub = world();
  const request = await running(t, configured(stub));
  const me = await browser(request);
  assert.deepEqual(await (await me.send('GET', '/api/documents/worldid')).json(), { worldId: null });
  // A proof made for another browser's key can't link this account, and World isn't asked.
  const other = await browser(request, sha('someone-else'));
  assert.equal((await me.link(linkProof(other.point))).status, 403);
  assert.equal(stub.calls.length, 0);
  const linked = await me.link(linkProof(me.point));
  assert.equal(linked.status, 200, await linked.clone().text());
  const { worldId } = await linked.json();
  assert.equal(worldId.fingerprint, publicWorldID({ nullifier: NULLIFIER }).fingerprint);
  assert.ok(!JSON.stringify(worldId).includes(NULLIFIER));
  assert.deepEqual((await (await me.send('GET', '/api/documents/worldid')).json()).worldId, worldId);
  // Linking again changes nothing and asks World nothing.
  assert.equal((await me.link(linkProof(me.point))).status, 200);
  assert.equal(stub.calls.length, 1);
  // Two pages shared with no proof of their own: both carry the account's World ID, checkable by anyone with the link.
  for (let i = 0; i < 2; i++) {
    const shared = await publish(request, await prepared(request), {});
    assert.equal(shared.status, 200, await shared.clone().text());
    const [, id, key] = (await shared.json()).path.match(/^\/original\/([a-f0-9]{64})#([a-f0-9]{64})$/);
    const asReader = { headers: { Authorization: 'Bearer ' + key } };
    assert.equal((await (await request(`/api/publications/${id}/receipt`, asReader)).json()).worldId.fingerprint, worldId.fingerprint);
    const evidence = await (await request(`/api/publications/${id}/worldid`, asReader)).json();
    assert.equal(evidence.signal, accountSignal(me.point));
    assert.equal(evidence.result.responses[0].signal_hash, hashSignal(accountSignal(me.point)));
  }
  assert.equal(stub.calls.length, 1);
  // The writer's page says the same: a writer can point at it to claim their pages.
  const route = '/api/documents/profile', body = JSON.stringify({ name: 'Ada', avatar: 'ada-1', handle: 'ada' });
  assert.equal((await me.send('POST', route, body)).status, 200);
  assert.equal((await (await request('/api/writers/ada')).json()).worldId.fingerprint, worldId.fingerprint);
});

test('one World ID links to one account, and another browser of that account finds it linked', { timeout: 60000 }, async t => {
  const request = await running(t, configured(world()));
  const me = await browser(request), someoneElse = await browser(request, sha('someone-else'));
  assert.equal((await me.link(linkProof(me.point))).status, 200);
  const taken = await someoneElse.link(linkProof(someoneElse.point));
  assert.equal(taken.status, 409);
  assert.match((await taken.json()).error, /already linked to another Huma account/);
  assert.deepEqual(await (await someoneElse.send('GET', '/api/documents/worldid')).json(), { worldId: null });
  const myLaptop = await browser(request);
  assert.equal((await (await myLaptop.send('GET', '/api/documents/worldid')).json()).worldId.fingerprint, publicWorldID({ nullifier: NULLIFIER }).fingerprint);
  // Not without a signed request from a linked browser.
  assert.equal((await request('/api/documents/worldid')).status, 401);
});

test('a link that isn’t a unique human’s, or from the wrong environment, links nothing; with World ID off nothing links', { timeout: 60000 }, async t => {
  const request = await running(t, configured(world({ success: false })));
  const me = await browser(request);
  assert.equal((await me.link(linkProof(me.point))).status, 403);
  assert.equal((await me.link(linkProof(me.point, { identifier: 'face' }))).status, 403);
  assert.equal((await me.link({ ...linkProof(me.point), environment: 'staging' })).status, 403);
  assert.deepEqual(await (await me.send('GET', '/api/documents/worldid')).json(), { worldId: null });
  // Unlinked, a browser page still needs a World ID of its own to be shared.
  assert.equal((await publish(request, await prepared(request), {})).status, 403);
  const off = await running(t, configured(world(), {}));
  const mine = await browser(off);
  assert.equal((await mine.link(linkProof(mine.point))).status, 404);
  assert.deepEqual(await (await mine.send('GET', '/api/documents/worldid')).json(), { worldId: null });
});

/** A browser's publishing key that nothing has linked yet, and its World ID sign-in. */
function newBrowser(request) {
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const raw = publicKey.export({ format: 'jwk' }), point = '04' + Buffer.from(raw.x, 'base64url').toString('hex') + Buffer.from(raw.y, 'base64url').toString('hex');
  const signs = text => sign('sha256', Buffer.from(text), { key: privateKey, dsaEncoding: 'der' }).toString('base64');
  const signIn = (proof = linkProof(point), { as = point, signature } = {}) => {
    const body = JSON.stringify({ publicKey: as, proof });
    return request('/api/worldid/signin', { method: 'POST', headers: { 'Content-Type': 'application/json',
      'X-Huma-Signature': signature ?? signs(worldIDSigninMessage(as, sha(body))) }, body });
  };
  const send = (method, route, body = '') => {
    const time = Date.now();
    return request(route, { method, ...(method === 'POST' ? { body } : {}), headers: { 'Content-Type': 'application/json', 'X-Huma-Key': point,
      'X-Huma-Time': String(time), 'X-Huma-Signature': signs(documentRequestMessage(method, route, time, sha(body))) } });
  };
  return { point, signs, signIn, send };
}

test('a writer signs in with World ID alone: one account per World ID, the same on every browser, and every page they share carries it', { timeout: 60000 }, async t => {
  const stub = world();
  const request = await running(t, configured(stub));
  const laptop = newBrowser(request);
  const signedIn = await laptop.signIn();
  assert.equal(signedIn.status, 200, await signedIn.clone().text());
  const me = await signedIn.json();
  const fingerprint = publicWorldID({ nullifier: NULLIFIER }).fingerprint;
  assert.equal(me.status, 'signed-in');
  assert.match(me.wallet, /^0x[0-9a-fA-F]{40}$/);
  assert.equal(me.account, 'World ID ' + fingerprint);
  assert.equal(me.worldId.fingerprint, fingerprint);
  assert.ok(!JSON.stringify(me).includes(NULLIFIER));
  // The browser's key now speaks for the account, which already has its World ID.
  assert.equal((await (await laptop.send('GET', '/api/documents/worldid')).json()).worldId.fingerprint, fingerprint);
  // The same person on another browser gets the same account.
  const phone = newBrowser(request);
  assert.equal((await (await phone.signIn()).json()).wallet, me.wallet);
  // A page shared from the browser itself (no Privy, no bearer token) carries the World ID.
  const pending = await prepared(request);
  const { manifest } = await (await request('/api/publications/pending/' + pending.id, { headers: { Authorization: 'Bearer ' + pending.ticket } })).json();
  const shared = await request('/api/publications/pending/' + pending.id + '/publish-device', { method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Huma-Ticket': pending.ticket },
    body: JSON.stringify({ publicKey: laptop.point, wallet: me.wallet, signature: laptop.signs(publicationMessage(manifest)) }) });
  assert.equal(shared.status, 200, await shared.clone().text());
  const [, id, key] = (await shared.json()).path.match(/^\/original\/([a-f0-9]{64})#([a-f0-9]{64})$/);
  const receipt = await (await request(`/api/publications/${id}/receipt`, { headers: { Authorization: 'Bearer ' + key } })).json();
  assert.equal(receipt.worldId.fingerprint, fingerprint);
  assert.equal(stub.calls.length, 2); // one check with World per sign-in, none at the share
});

test('a World ID sign-in is refused unless this browser signed it, for its own key, as a unique human', { timeout: 60000 }, async t => {
  const request = await running(t, configured(world()));
  const mine = newBrowser(request), other = newBrowser(request);
  // Signed by another key, or made for another browser's key.
  assert.equal((await mine.signIn(undefined, { signature: other.signs('anything') })).status, 403);
  assert.equal((await mine.signIn(linkProof(other.point))).status, 403);
  assert.equal((await mine.signIn(linkProof(mine.point, { identifier: 'face' }))).status, 403);
  assert.equal((await mine.signIn({ ...linkProof(mine.point), environment: 'staging' })).status, 403);
  assert.equal((await mine.signIn('not a proof')).status, 400);
  // A browser already linked to another account stays with it.
  const theirs = newBrowser(request);
  await request.store.put(deviceOwnerKey(theirs.point), Buffer.from(JSON.stringify({ owner: sha('someone-else'), wallet: '0x' + '1'.repeat(40) })));
  assert.equal((await theirs.signIn()).status, 409);
  // World says no, or World ID is off here.
  const refused = await running(t, configured(world({ success: false })));
  assert.equal((await newBrowser(refused).signIn()).status, 403);
  const off = await running(t, configured(world(), {}));
  assert.equal((await newBrowser(off).signIn()).status, 404);
});

test('the Mac signs in with World ID through the sign-in page, reads it back with its code, and shares by itself', { timeout: 60000 }, async t => {
  const stub = world();
  const request = await running(t, configured(stub));
  const mac = newBrowser(request), code = randomBytes(32).toString('hex');
  const signIn = (body, signin = code) => request('/api/publications/signin', { method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Huma-Signin': signin }, body: JSON.stringify(body) });
  // Waiting until the page signs in; a World ID made for another key links nothing.
  assert.equal((await (await request('/api/publications/signin', { headers: { 'X-Huma-Signin': code } })).json()).status, 'waiting');
  assert.equal((await signIn({ publicKey: mac.point, worldId: linkProof(newBrowser(request).point) })).status, 403);
  const signed = await signIn({ publicKey: mac.point, worldId: linkProof(mac.point) });
  assert.equal(signed.status, 200, await signed.clone().text());
  const fingerprint = publicWorldID({ nullifier: NULLIFIER }).fingerprint;
  // What the Mac reads back (HostedPublicationClient.signedIn): signed in, its wallet, and linked.
  const back = await (await request('/api/publications/signin', { headers: { 'X-Huma-Signin': code } })).json();
  assert.deepEqual([back.status, back.account, back.device], ['signed-in', 'World ID ' + fingerprint, true]);
  assert.match(back.wallet, /^0x[0-9a-fA-F]{40}$/);
  // The code is used once.
  assert.equal((await signIn({ publicKey: mac.point, worldId: linkProof(mac.point) })).status, 409);
  // The same person in a browser is the same account.
  assert.equal((await (await newBrowser(request).signIn()).json()).wallet, back.wallet);
  // Finish on the Mac shares with its own key, and the page carries the account's World ID.
  const pending = await prepared(request);
  const { manifest } = await (await request('/api/publications/pending/' + pending.id, { headers: { Authorization: 'Bearer ' + pending.ticket } })).json();
  const shared = await request('/api/publications/pending/' + pending.id + '/publish-device', { method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Huma-Ticket': pending.ticket },
    body: JSON.stringify({ publicKey: mac.point, wallet: back.wallet, signature: mac.signs(publicationMessage(manifest)) }) });
  assert.equal(shared.status, 200, await shared.clone().text());
  const [, id, key] = (await shared.json()).path.match(/^\/original\/([a-f0-9]{64})#([a-f0-9]{64})$/);
  assert.equal((await (await request(`/api/publications/${id}/receipt`, { headers: { Authorization: 'Bearer ' + key } })).json()).worldId.fingerprint, fingerprint);
  // The sign-in page may reach World's bridge, and nothing of Privy's.
  const csp = (await request('/share/signin')).headers.get('content-security-policy') ?? '';
  assert.match(csp, /connect-src 'self' https:\/\/bridge\.worldcoin\.org;/);
  assert.doesNotMatch(csp, /privy/);
});
