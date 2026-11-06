import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import http from 'node:http';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { LocalObjectStore } from '../object-store.mjs';
import { createRegistry } from '../registry.mjs';
import { deviceOwnerKey, ACCOUNT_BYTES, ACCOUNT_FULL } from '../documents.mjs';
import { documentRequestMessage } from '../publication-contract.mjs';

const hash = value => createHash('sha256').update(value).digest('hex');
async function running(t) {
  const directory = await mkdtemp(path.join(tmpdir(), 'huma-documents-'));
  const server = await createRegistry({ store: directory });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(async () => { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); await rm(directory, { recursive: true, force: true }); });
  return { base: `http://127.0.0.1:${server.address().port}`, store: new LocalObjectStore(path.join(directory, 'publications')) };
}
/** A browser's publishing key, linked to `owner` as sign-in links it. */
async function browser(store, owner) {
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const raw = publicKey.export({ format: 'jwk' }), point = '04' + Buffer.from(raw.x, 'base64url').toString('hex') + Buffer.from(raw.y, 'base64url').toString('hex');
  if (owner) await store.put(deviceOwnerKey(point), Buffer.from(JSON.stringify({ owner, wallet: '0x' + '1'.repeat(40) })));
  return { point, headers: (method, pathname, body = '', time = Date.now()) => ({ 'Content-Type': 'application/json', 'X-Huma-Key': point, 'X-Huma-Time': String(time),
    'X-Huma-Signature': sign('sha256', Buffer.from(documentRequestMessage(method, pathname, time, hash(body))), { key: privateKey, dsaEncoding: 'der' }).toString('base64') }) };
}
const doc = (id, extra = {}) => JSON.stringify({ id, title: 'Essay', text: 'Hello there', words: 2, status: 'draft', created: 1, updated: 2,
  doc: { type: 'doc', content: [{ type: 'paragraph', content: [{ type: 'text', text: 'Hello there' }] }] }, ...extra });

test('a linked browser keeps, lists, reopens and deletes its account’s documents', async t => {
  const { base, store } = await running(t), me = await browser(store, hash('me'));
  const id = 'a'.repeat(20), route = '/api/documents/' + id, body = doc(id);
  const saved = await fetch(base + route, { method: 'POST', headers: me.headers('POST', route, body), body });
  assert.equal(saved.status, 200, await saved.clone().text());
  const list = await (await fetch(base + '/api/documents', { headers: me.headers('GET', '/api/documents') })).json();
  assert.deepEqual(list.documents.map(d => [d.id, d.title, d.status, d.words]), [[id, 'Essay', 'draft', 2]]);
  assert.equal(list.documents[0].doc, undefined); // the list carries no text beyond its preview
  const opened = await (await fetch(base + route, { headers: me.headers('GET', route) })).json();
  assert.equal(opened.doc.content[0].content[0].text, 'Hello there');
  // Finished stays finished, with what it proved but never the keystroke recording.
  const proved = doc(id, { status: 'proved', score: 43, shared: '/original/' + 'b'.repeat(64) + '#' + 'c'.repeat(64), publication: 'b'.repeat(64),
    proof: { envelope: '{"kind":"x"}', report: { verified: true }, text: 'Hello there', replay: '{"kind":"r"}', recording: 'keystrokes' } });
  const provedSave = await fetch(base + route, { method: 'POST', headers: me.headers('POST', route, proved), body: proved });
  assert.equal(provedSave.status, 200, await provedSave.clone().text());
  const finished = await (await fetch(base + route, { headers: me.headers('GET', route) })).json();
  assert.equal(finished.status, 'proved'); assert.equal(finished.publication, 'b'.repeat(64)); assert.equal(finished.proof.recording, undefined); assert.equal(finished.proof.envelope, '{"kind":"x"}');
  assert.equal((await fetch(base + route, { method: 'POST', headers: me.headers('POST', route, body), body })).status, 409);
  const remove = route + '/delete';
  assert.equal((await fetch(base + remove, { method: 'POST', headers: me.headers('POST', remove) })).status, 200);
  assert.deepEqual((await (await fetch(base + '/api/documents', { headers: me.headers('GET', '/api/documents') })).json()).documents, []);
});

test('documents need a linked key, a fresh signature and the right account', async t => {
  const { base, store } = await running(t), me = await browser(store, hash('me')), them = await browser(store, hash('them')), stranger = await browser(store, null);
  const id = 'd'.repeat(20), route = '/api/documents/' + id, body = doc(id);
  assert.equal((await fetch(base + '/api/documents')).status, 401);
  assert.equal((await fetch(base + '/api/documents', { headers: stranger.headers('GET', '/api/documents') })).status, 401);
  assert.equal((await fetch(base + '/api/documents', { headers: me.headers('GET', '/api/documents', '', Date.now() - 10 * 60 * 1000) })).status, 401);
  // A signature is for its own body and path.
  const headers = me.headers('POST', route, body);
  assert.equal((await fetch(base + route, { method: 'POST', headers, body: doc(id, { title: 'Changed' }) })).status, 401);
  assert.equal((await fetch(base + route, { method: 'POST', headers: me.headers('POST', route, body), body })).status, 200);
  // The same signed request can't be sent twice.
  const once = me.headers('GET', '/api/documents');
  assert.equal((await fetch(base + '/api/documents', { headers: once })).status, 200);
  assert.equal((await fetch(base + '/api/documents', { headers: once })).status, 401);
  // Another account sees none of it.
  assert.deepEqual((await (await fetch(base + '/api/documents', { headers: them.headers('GET', '/api/documents') })).json()).documents, []);
  assert.equal((await fetch(base + route, { headers: them.headers('GET', route) })).status, 404);
});

test('an account keeps one profile, which only its own browsers can read or change', async t => {
  const { base, store } = await running(t), me = await browser(store, hash('me')), them = await browser(store, hash('them'));
  const route = '/api/documents/profile', send = (who, value) => { const body = JSON.stringify(value); return fetch(base + route, { method: 'POST', headers: who.headers('POST', route, body), body }); };
  const read = async who => (await (await fetch(base + route, { headers: who.headers('GET', route) })).json()).profile;
  assert.equal(await read(me), null);
  assert.equal((await send(me, { name: '  Swayam   K ', avatar: 'abc23' })).status, 200);
  assert.deepEqual(await read(me), { name: 'Swayam K', avatar: 'abc23' });
  assert.equal((await send(me, { name: 'Swayam', avatar: 'xyz45' })).status, 200); // changed, not write-once
  assert.deepEqual(await read(me), { name: 'Swayam', avatar: 'xyz45' });
  assert.equal(await read(them), null);
  assert.equal((await send(me, { name: '', avatar: 'abc' })).status, 400);
  assert.equal((await send(me, { name: 'x'.repeat(41), avatar: 'abc' })).status, 400);
  assert.equal((await send(me, { name: 'Ok', avatar: '../x' })).status, 400);
  assert.equal((await fetch(base + route)).status, 401);
});

test('an account keeps up to 10 passkeys, strictly checked, which only its own browsers can read or add', async t => {
  const { base, store } = await running(t), me = await browser(store, hash('me')), them = await browser(store, hash('them'));
  const route = '/api/documents/passkeys', send = (who, value) => { const body = JSON.stringify(value); return fetch(base + route, { method: 'POST', headers: who.headers('POST', route, body), body }); };
  const read = async who => (await (await fetch(base + route, { headers: who.headers('GET', route) })).json()).passkeys;
  const point = () => { const jwk = generateKeyPairSync('ec', { namedCurve: 'P-256' }).publicKey.export({ format: 'jwk' });
    return Buffer.concat([Buffer.from([4]), Buffer.from(jwk.x, 'base64url'), Buffer.from(jwk.y, 'base64url')]).toString('base64'); };
  const passkey = (n, extra = {}) => ({ id: Buffer.from('credential-' + n + '-' + 'x'.repeat(12)).toString('base64url'), publicKey: point(), rpId: 'huma.social', ...extra });
  assert.deepEqual(await read(me), []);
  const first = passkey(0);
  assert.equal((await send(me, first)).status, 200);
  assert.deepEqual(await read(me), [first]);
  assert.equal((await send(me, first)).status, 200); // the same credential again replaces it
  assert.deepEqual(await read(me), [first]);
  assert.deepEqual(await read(them), []);
  // Strict: exact keys, a base64url id, a hostname, and a 65-byte uncompressed P-256 point that's on the curve.
  const bad = [{ ...passkey(1), extra: 1 }, { id: first.id, publicKey: first.publicKey }, passkey(1, { id: 'short' }), passkey(1, { id: 'has+plus/' + 'x'.repeat(20) }),
    passkey(1, { rpId: 'Huma.Social' }), passkey(1, { rpId: 'https://huma.social' }), passkey(1, { publicKey: Buffer.alloc(65, 4).toString('base64') }),
    passkey(1, { publicKey: Buffer.concat([Buffer.from([2]), Buffer.alloc(64, 1)]).toString('base64') }), passkey(1, { publicKey: Buffer.alloc(33, 4).toString('base64') }),
    passkey(1, { publicKey: 'not base64' }), [first], 'text', null];
  for (const value of bad) assert.equal((await send(me, value)).status, 400, JSON.stringify(value));
  const notJSON = 'nope';
  assert.equal((await fetch(base + route, { method: 'POST', headers: me.headers('POST', route, notJSON), body: notJSON })).status, 400);
  for (let n = 1; n < 10; n++) assert.equal((await send(me, passkey(n))).status, 200);
  assert.equal((await read(me)).length, 10);
  assert.equal((await send(me, passkey(10))).status, 429);
  assert.equal((await send(me, { ...first, publicKey: point() })).status, 200); // a known one can still be replaced at the limit
  assert.equal((await fetch(base + route)).status, 401);
  assert.equal((await fetch(base + route, { method: 'POST', body: JSON.stringify(first) })).status, 401);
  const body = JSON.stringify(first);
  assert.equal((await fetch(base + route, { method: 'POST', headers: me.headers('POST', route, JSON.stringify(passkey(11))), body })).status, 401);
});

// The same P-256 signature with s replaced by n − s: just as valid, other bytes.
const N = BigInt('0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551');
function highS(signature) {
  const der = Buffer.from(signature, 'base64'), rLength = der[3], r = der.subarray(4, 4 + rLength);
  const s = BigInt('0x' + der.subarray(6 + rLength, 6 + rLength + der[5 + rLength]).toString('hex'));
  let hex = (N - s).toString(16); if (hex.length % 2) hex = '0' + hex;
  let other = Buffer.from(hex, 'hex'); if (other[0] & 0x80) other = Buffer.concat([Buffer.from([0]), other]);
  const body = Buffer.concat([Buffer.from([2, rLength]), r, Buffer.from([2, other.length]), other]);
  return Buffer.concat([Buffer.from([0x30, body.length]), body]).toString('base64');
}

test('a signed request counts once, however its signature is written and however fast it’s sent again', async t => {
  const { base, store } = await running(t), me = await browser(store, hash('me'));
  const list = headers => fetch(base + '/api/documents', { headers });
  const once = me.headers('GET', '/api/documents');
  assert.equal((await list(once)).status, 200);
  const signature = once['X-Huma-Signature'], error = async response => [response.status, (await response.json()).error];
  // Other spellings of the same base64 are refused (non-canonical, or bytes added after it); the same signature in other
  // bytes counts as used.
  // Last, the same bytes with the padding's spare bits set (when the signature has padding).
  const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/', last = signature.replace(/=+$/, '').length - 1;
  const spare = signature.endsWith('=') ? signature.slice(0, last) + ALPHABET[ALPHABET.indexOf(signature[last]) ^ 1] + signature.slice(last + 1) : signature + '==';
  assert.deepEqual(Buffer.from(spare, 'base64'), Buffer.from(signature, 'base64'));
  for (const other of [signature + '=', signature.replace(/=+$/, ''), signature.replace(/=*$/, '') + 'AAAA', spare].filter(other => other !== signature))
    assert.equal((await list({ ...once, 'X-Huma-Signature': other })).status, 401, other);
  assert.deepEqual(await error(await list({ ...once, 'X-Huma-Signature': highS(signature) })), [401, 'This request was already used.']);
  // Sent twice at once, it goes through once.
  const id = 'e'.repeat(20), route = '/api/documents/' + id, body = doc(id), headers = me.headers('POST', route, body);
  const statuses = await Promise.all([1, 2, 3].map(() => fetch(base + route, { method: 'POST', headers, body }).then(r => r.status)));
  assert.deepEqual(statuses.sort(), [200, 401, 401]);
});

/** A POST whose headers go but whose body never does: the status, if the server answers without waiting for it. */
const headersOnly = (base, pathname, headers) => new Promise((resolve, reject) => {
  const timer = setTimeout(() => { request.destroy(); reject(new Error('The server waited for the body.')); }, 3000);
  const request = http.request(base + pathname, { method: 'POST', headers }, response => { clearTimeout(timer); response.resume(); resolve(response.statusCode); request.destroy(); });
  request.on('error', () => {}); request.flushHeaders();
});

test('a body is read only once its headers show a linked key, and never past its limit', async t => {
  const { base, store } = await running(t), me = await browser(store, hash('me')), stranger = await browser(store, null);
  const route = '/api/documents/' + 'f'.repeat(20), length = { 'Content-Length': String(3 * 1024 * 1024) };
  assert.equal(await headersOnly(base, route, { 'Content-Type': 'application/json', ...length }), 401);
  assert.equal(await headersOnly(base, route, { ...stranger.headers('POST', route), ...length }), 401);
  assert.equal(await headersOnly(base, route, { ...me.headers('POST', route), 'Content-Length': String(5 * 1024 * 1024) }), 413);
  assert.equal(await headersOnly(base, '/api/documents/profile', { ...me.headers('POST', '/api/documents/profile'), 'Content-Length': '5000' }), 413);
});

test('an account keeps up to 50 MB of documents', async t => {
  const { base, store } = await running(t), owner = hash('me'), me = await browser(store, owner);
  const save = (id, body = doc(id)) => fetch(base + '/api/documents/' + id, { method: 'POST', headers: me.headers('POST', '/api/documents/' + id, body), body });
  // Nearly full already: one big document, as the list counts it.
  const big = 'b'.repeat(20), listKey = 'documents/' + hash('huma-documents-v1\0' + owner);
  await store.quotaCAS(listKey, null, Buffer.from(JSON.stringify([{ id: big, title: 'Big', text: '', words: 0, status: 'draft', score: null, created: 1, updated: 1,
    key: 'documents/' + hash('big'), size: ACCOUNT_BYTES - 1000 }])));
  const small = 'a'.repeat(20);
  assert.equal((await save(small)).status, 200);
  const larger = doc('c'.repeat(20), { doc: { type: 'doc', content: [{ type: 'paragraph', content: [{ type: 'text', text: 'x'.repeat(2000) }] }] } }), refused = await save('c'.repeat(20), larger);
  assert.equal(refused.status, 413); assert.deepEqual(await refused.json(), { error: ACCOUNT_FULL });
  // A document saved again counts once, not twice.
  assert.equal((await save(small, doc(small, { title: 'Edited' }))).status, 200);
  const shown = (await (await fetch(base + '/api/documents', { headers: me.headers('GET', '/api/documents') })).json()).documents;
  assert.deepEqual(shown.map(d => d.id), [small, big]);
  assert.ok(shown.every(d => !('size' in d) && !('key' in d)));
  assert.ok(JSON.parse((await store.quotaRead(listKey)).bytes)[0].size > 0);
  // Deleting makes room.
  const remove = '/api/documents/' + big + '/delete';
  assert.equal((await fetch(base + remove, { method: 'POST', headers: me.headers('POST', remove) })).status, 200);
  assert.equal((await save('c'.repeat(20), larger)).status, 200);
});
