import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { ArkivObjectStore, CHUNK_BYTES, TX_BYTES, seal, open } from '../arkiv-store.mjs';
import { LocalObjectStore, configuredObjectStore } from '../object-store.mjs';
import { createRegistry } from '../registry.mjs';
import { statementHash, TEXT_POLICY } from '../verify-core/contract.mjs';

const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const SECRET = randomBytes(32).toString('hex');
const id = label => sha('id:' + label);

/** An in-memory stand-in for Arkiv: entities by key, a transaction per write, and nothing else. `lag` makes deleted entities still listed. */
function fakeChain() {
  const entities = new Map(); let counter = 0;
  const chain = { entities, writes: [], lists: 0, lag: false, failAt: null,
    network: { network: 'Rabdi', chainId: 7794095, explorer: 'https://rabdi.explorer.arkiv.network', rpc: 'https://rpc.rabdi.db-chain.testnet.arkiv.network', owner: '0x' + 'ab'.repeat(20) },
    async list(k) { chain.lists++; return [...entities.values()].filter(e => e.k === k).map(e => ({ ...e })); },
    async listKeys(kind) { return [...entities.values()].filter(e => e.p === kind).map(e => e.k); },
    // What the real query does: one row per key (its first chunk), filtered by the indexed columns, newest first.
    async find({ kind, owner, since, limit }) {
      return [...entities.values()].filter(e => e.p === kind && e.i === 0 && (!owner || e.owner === owner) && (since === undefined || e.at >= since))
        .sort((a, b) => b.at - a.at).slice(0, limit).map(e => ({ key: e.k, at: e.at, owner: e.owner ?? null, size: e.size }));
    },
    async write({ creates, deletes }) {
      chain.writes.push({ creates: creates.length, deletes: deletes.length });
      if (chain.failAt !== null && chain.writes.length === chain.failAt) throw new Error('transaction failed');
      for (const key of deletes) if (!entities.has(key)) throw new Error('no such entity');
      // What Rabdi enforces (measured): a bytes value up to 128 KiB, and no more than about 128 KiB of payload in a transaction.
      for (const c of creates) if (c.body.length > 128 * 1024) throw new Error('bytes value too large');
      if (creates.reduce((sum, c) => sum + c.body.length, 0) > 128 * 1024) throw new Error('Execution error without revert data');
      if (!chain.lag) for (const key of deletes) entities.delete(key);
      // Like executeBatch: the transaction's hash and the created entities' keys, in order.
      const created = creates.map(c => { const key = '0x' + (++counter).toString(16).padStart(64, '0'); entities.set(key, { key, ...c, body: Buffer.from(c.body) }); return key; });
      return { tx: '0x' + sha('tx' + chain.writes.length), entities: created };
    } };
  return chain;
}
async function running(t, { chain = fakeChain() } = {}) {
  const directory = await mkdtemp(path.join(tmpdir(), 'huma-arkiv-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const local = new LocalObjectStore(directory);
  const store = new ArkivObjectStore({ local, chain, env: { ARKIV_ENCRYPTION_KEY: SECRET } });
  return { store, chain, local, directory, again: () => new ArkivObjectStore({ local, chain, env: { ARKIV_ENCRYPTION_KEY: SECRET } }) };
}
const objectKeyFor = bytes => 'objects/' + sha(bytes);

test('a put says where the object is kept: its first entity, the transaction, and when it expires', async t => {
  const { store, chain, again } = await running(t);
  const small = Buffer.from('Kept where anyone can look it up.');
  const stored = await store.put(objectKeyFor(small), small);
  const [first] = [...chain.entities.values()];
  assert.equal(stored.entity, first.key);
  assert.equal(stored.tx, '0x' + sha('tx1'));
  assert.equal(stored.chunks, 1);
  assert.equal(stored.expires - stored.at, 180 * 86400000);
  // Stored already: the same entity, from the cache and after a restart (where the transaction isn't known).
  assert.deepEqual(await store.put(objectKeyFor(small), small), stored);
  assert.deepEqual(await again().put(objectKeyFor(small), small), { ...stored, tx: null });
  // In chunks: the entity of the first chunk, and the transaction that holds it.
  const large = randomBytes(CHUNK_BYTES * 2 + 5000);
  const chunked = await store.put(objectKeyFor(large), large);
  assert.equal(chain.entities.get(chunked.entity).i, 0);
  assert.equal(chunked.tx, '0x' + sha('tx2'));
  assert.equal(chunked.chunks, 3);
  assert.equal((await store.network()).owner, chain.network.owner);
});

test('an object round-trips, whole or in chunks, and a new store (after a restart) reads it back', async t => {
  const { store, chain, again } = await running(t);
  const small = Buffer.from('A short page about one real person.');
  await store.put(objectKeyFor(small), small);
  assert.deepEqual(await store.get(objectKeyFor(small), 1024), small);
  assert.deepEqual(chain.writes, [{ creates: 1, deletes: 0 }]);
  // More than a bytes value holds: split into chunks, and no more than a transaction can carry in each.
  const large = randomBytes(CHUNK_BYTES * 2 + 5000);
  await store.put(objectKeyFor(large), large);
  assert.equal(chain.entities.size, 1 + 3);
  assert.deepEqual(chain.writes.slice(1), [{ creates: 1, deletes: 0 }, { creates: 1, deletes: 0 }, { creates: 1, deletes: 0 }]);
  assert.ok(TX_BYTES <= 128 * 1024);
  // The cache is empty after a restart: everything is read from the chain.
  const restarted = again();
  assert.deepEqual(await restarted.get(objectKeyFor(large), large.length), large);
  assert.deepEqual(await restarted.get(objectKeyFor(small), 1024), small);
  // The limit is the caller's.
  await assert.rejects(restarted.get(objectKeyFor(large), 1000), /integrity|limit/);
  // Missing is "not found" the way the other stores say it.
  await assert.rejects(restarted.get(id('missing').replace(/^/, 'objects/'), 10), error => error.code === 'ENOENT' && error.$metadata.httpStatusCode === 404);
});

test('what is on Arkiv is encrypted, tied to its key, and tampering is caught', async t => {
  const { store, chain, again } = await running(t);
  const secret = Buffer.from('the private text of a link-only page, readable only by link holders');
  await store.put(objectKeyFor(secret), secret);
  for (const e of chain.entities.values()) assert.ok(!e.body.includes('private text'), 'plaintext reached the chain');
  // The logical key is the only thing public about it.
  assert.deepEqual([...chain.entities.values()].map(e => [e.k, e.p]), [[objectKeyFor(secret), 'objects']]);
  // A payload can't be passed off under another key (the key name is authenticated).
  const sealed = seal(Buffer.from(SECRET, 'hex'), 'records/' + id('a'), Buffer.from('x'));
  assert.throws(() => open(Buffer.from(SECRET, 'hex'), 'records/' + id('b'), sealed), /integrity/);
  // Changed on the chain: refused.
  const [entity] = chain.entities.values();
  entity.body[entity.body.length - 1] ^= 1;
  await assert.rejects(again().get(objectKeyFor(secret), 1024), /integrity/);
  // A page whose bytes don't match its hash is refused before it is written.
  await assert.rejects(store.put('objects/' + id('wrong'), Buffer.from('not that hash')), /integrity/);
  // The key is required, and must be a real one.
  for (const key of [undefined, '', 'short', 'z'.repeat(64)]) assert.throws(() => new ArkivObjectStore({ local: {}, chain, env: { ARKIV_ENCRYPTION_KEY: key } }), /ARKIV_ENCRYPTION_KEY/);
});

test('a page is written once: the same bytes again do nothing, different bytes are refused', async t => {
  const { store, chain } = await running(t);
  const record = 'records/' + id('page');
  await store.put(record, Buffer.from('one'));
  await store.put(record, Buffer.from('one'));
  assert.equal(chain.writes.length, 1);
  await assert.rejects(store.put(record, Buffer.from('two')), /Immutable object differs/);
  for (const bad of ['records/short', 'unknown/' + id('x'), '../etc/passwd', 'records/' + 'G'.repeat(64)]) await assert.rejects(store.put(bad, Buffer.from('x')));
});

test('changeable state is replaced by compare-and-swap, one writer at a time', async t => {
  const { store, chain } = await running(t);
  const key = 'documents/' + id('list');
  assert.equal(await store.quotaRead(key), null);
  assert.equal(await store.quotaCAS(key, 'not-there', Buffer.from('[]')), false); // expects something that isn't there
  assert.equal(await store.quotaCAS(key, null, Buffer.from('[1]')), true);
  assert.equal(await store.quotaCAS(key, null, Buffer.from('[2]')), false);      // already created
  const first = await store.quotaRead(key);
  assert.equal(first.bytes.toString(), '[1]');
  assert.equal(first.version, sha(Buffer.from('[1]')));
  assert.equal(await store.quotaCAS(key, 'stale', Buffer.from('[3]')), false);
  assert.equal(await store.quotaCAS(key, first.version, Buffer.from('[1,2]')), true);
  // The old chunk is deleted in the same transaction as the new one is created: one entity, not two.
  assert.deepEqual(chain.writes.at(-1), { creates: 1, deletes: 1 });
  assert.equal([...chain.entities.values()].filter(e => e.k === key).length, 1);
  // Ten callers adding to one list at once: every one of them lands.
  const counter = 'sessions/' + id('counter');
  const add = async () => {
    for (let attempt = 0; attempt < 50; attempt++) {
      const read = await store.quotaRead(counter), n = read ? JSON.parse(read.bytes) : 0;
      if (await store.quotaCAS(counter, read?.version ?? null, Buffer.from(JSON.stringify(n + 1)))) return;
    }
    throw new Error('never landed');
  };
  await Promise.all(Array.from({ length: 10 }, add));
  assert.equal(JSON.parse((await store.quotaRead(counter)).bytes), 10);
  assert.equal([...chain.entities.values()].filter(e => e.k === counter).length, 1);
  for (const bad of ['objects/' + id('x'), 'nope/' + id('x')]) await assert.rejects(store.quotaCAS(bad, null, Buffer.from('x')));
});

test('the daily upload counters stay in the local folder, never on Arkiv', async t => {
  const { store, chain, directory } = await running(t);
  const key = 'quotas/' + id('day');
  assert.equal(await store.quotaCAS(key, null, Buffer.from('{"n":1}')), true);
  assert.equal((await store.quotaRead(key)).bytes.toString(), '{"n":1}');
  assert.equal(chain.writes.length, 0);
  assert.equal(chain.entities.size, 0);
  assert.equal((await readFile(path.join(directory, key))).toString(), '{"n":1}');
});

test('half a write is ignored, and the next write of that key clears it away', async t => {
  const { store, chain } = await running(t);
  const big = randomBytes(CHUNK_BYTES * 20); // 21 chunks: more than one transaction
  chain.failAt = 2;                           // the second transaction fails
  await assert.rejects(store.put(objectKeyFor(big), big), /transaction failed/);
  chain.failAt = null;
  assert.ok(chain.entities.size > 0 && chain.entities.size < 21, 'some chunks were written');
  const restarted = new ArkivObjectStore({ local: store.local, chain, env: { ARKIV_ENCRYPTION_KEY: SECRET } });
  await assert.rejects(restarted.get(objectKeyFor(big), big.length), error => error.code === 'ENOENT'); // incomplete is not readable
  await restarted.put(objectKeyFor(big), big);
  assert.deepEqual(await restarted.get(objectKeyFor(big), big.length), big);
  assert.equal(chain.entities.size, 21); // the leftovers were deleted
  assert.ok(chain.writes.every(w => w.creates <= 16), 'big objects go in batches');
});

test('records are listed, and only page files and documents can be removed', async t => {
  const { store, chain } = await running(t);
  const a = id('a'), b = id('b'), file = Buffer.from('a page file');
  await store.put('records/' + a, Buffer.from('{}'));
  await store.put('records/' + b, Buffer.from('{}'));
  await store.put('writers/' + a, Buffer.from('{}'));
  await store.put(objectKeyFor(file), file);
  assert.deepEqual((await store.recordIDs()).sort(), [a, b].sort());
  await assert.rejects(store.remove('records/' + a), /Only page files and documents/);
  await store.remove(objectKeyFor(file));
  await assert.rejects(store.get(objectKeyFor(file), 100), error => error.code === 'ENOENT');
  assert.equal([...chain.entities.values()].filter(e => e.k === objectKeyFor(file)).length, 0);
  await store.remove(objectKeyFor(file)); // already gone: not an error
  // The index can lag a moment behind a deletion: the store doesn't serve a page it just removed.
  const lagging = await running(t, { chain: Object.assign(fakeChain(), { lag: true }) });
  await lagging.store.put(objectKeyFor(file), file);
  await lagging.store.remove(objectKeyFor(file));
  assert.equal(lagging.chain.entities.size, 1);
  await assert.rejects(lagging.store.get(objectKeyFor(file), 100), error => error.code === 'ENOENT');
});

test('what is stored can be queried by its typed columns, with the sensitive parts still encrypted', async t => {
  const { chain, local } = await running(t);
  let clock = 1000;
  const store = new ArkivObjectStore({ local, chain, env: { ARKIV_ENCRYPTION_KEY: SECRET }, now: () => (clock += 10) });
  const [alice, bob] = [id('alice'), id('bob')];
  const record = (name, owner, extra = {}) => store.put('records/' + id(name), Buffer.from(JSON.stringify({ ownerHash: owner, title: 'A private title', ...extra })));
  await record('p1', alice); await record('p2', bob); await record('p3', alice); await record('p4', alice);
  const file = Buffer.from('a file'); await store.put(objectKeyFor(file), file);
  // A writer's pages, newest first.
  const mine = await store.find({ kind: 'records', owner: alice });
  assert.deepEqual(mine.map(r => r.key), ['records/' + id('p4'), 'records/' + id('p3'), 'records/' + id('p1')]);
  assert.ok(mine.every(r => r.owner === alice && r.size > 0 && r.at > 1000));
  // By time, and a limit.
  assert.deepEqual((await store.find({ kind: 'records', since: mine[1].at })).map(r => r.key), ['records/' + id('p4'), 'records/' + id('p3')]);
  assert.equal((await store.find({ kind: 'records', limit: 2 })).length, 2);
  // Files and other kinds have no owner; a kind with nothing in it is empty.
  assert.deepEqual((await store.find({ kind: 'objects' })).map(r => [r.key, r.owner]), [[objectKeyFor(file), null]]);
  assert.deepEqual(await store.find({ kind: 'sessions' }), []);
  // One row per key, even for a file of several chunks.
  const large = randomBytes(CHUNK_BYTES * 2 + 10); await store.put(objectKeyFor(large), large);
  assert.equal((await store.find({ kind: 'objects' })).filter(r => r.key === objectKeyFor(large)).length, 1);
  // The owner hash is the one readable column; the title and everything else stay in the encrypted payload.
  for (const e of chain.entities.values()) assert.ok(!e.body.includes('A private title') && !e.body.includes('ownerHash'));
  assert.deepEqual([...new Set([...chain.entities.values()].filter(e => e.owner).map(e => e.owner))].sort(), [alice, bob].sort());
  for (const bad of [{}, { kind: 'Records' }, { kind: 'records', owner: 'nope' }, { kind: 'records', since: -1 }, { kind: 'records', limit: 0 }, { kind: 'records', limit: 5000 }]) await assert.rejects(store.find(bad));
});

test('a read after a write comes from memory, not another trip to the chain', async t => {
  const { store, chain } = await running(t);
  const bytes = Buffer.from('cached');
  await store.put(objectKeyFor(bytes), bytes);
  const lists = chain.lists;
  for (let i = 0; i < 5; i++) assert.deepEqual(await store.get(objectKeyFor(bytes), 100), bytes);
  assert.equal(chain.lists, lists);
});

test('HUMA_STORAGE_BACKEND=arkiv picks this store, and says what it is missing', async t => {
  const directory = await mkdtemp(path.join(tmpdir(), 'huma-arkiv-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const store = configuredObjectStore(directory, { HUMA_STORAGE_BACKEND: 'arkiv', ARKIV_ENCRYPTION_KEY: SECRET });
  assert.equal(store.kind, 'arkiv');
  assert.throws(() => configuredObjectStore(directory, { HUMA_STORAGE_BACKEND: 'arkiv' }), /ARKIV_ENCRYPTION_KEY/);
  // Without an access key or a funded account the first use says so, rather than failing somewhere deeper.
  await assert.rejects(store.get('records/' + id('x'), 10), /ARKIV_ACCESS_KEY/);
  const keyless = configuredObjectStore(directory, { HUMA_STORAGE_BACKEND: 'arkiv', ARKIV_ENCRYPTION_KEY: SECRET, ARKIV_ACCESS_KEY: 'a-key' });
  await assert.rejects(keyless.get('records/' + id('x'), 10), /ARKIV_PRIVATE_KEY/);
});

// The whole app on Arkiv: a page is shared through the real registry, stored on the (in-memory) chain, and read back by
// a link holder, also after the server restarts. Nothing on the chain is readable.
const TEXT = 'A short page that lives on Arkiv, written by one real person.';
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
async function server(t, objectStore, directory) {
  const registry = await createRegistry({ store: directory, publicationOptions: { objectStore, verifyUpload: madeUpPage,
    authenticate: async token => { if (token !== 'test-owner-session') throw Object.assign(new Error('Sign in required.'), { status: 401 }); return sha('test-owner'); } } });
  await new Promise(resolve => registry.listen(0, '127.0.0.1', resolve));
  t.after(async () => { registry.closeAllConnections(); await new Promise(resolve => registry.close(resolve)); });
  const base = `http://127.0.0.1:${registry.address().port}`;
  return (route, options) => fetch(base + route, options);
}

test('a page shared through the app is kept on Arkiv, read by its link, and still there after a restart', { timeout: 60000 }, async t => {
  const { store, chain, again, directory } = await running(t);
  const request = await server(t, store, directory);
  const prepared = await request('/api/publications/prepare', { method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ kind: 'huma-publication-upload-v1', access: 'link', proof: '{}', master: { mediaType: 'text/plain;charset=utf-8', base64: Buffer.from(TEXT).toString('base64') } }) });
  assert.equal(prepared.status, 201, await prepared.clone().text());
  const pending = await prepared.json();
  const shared = await request('/api/publications/pending/' + pending.id + '/publish', { method: 'POST',
    headers: { Authorization: 'Bearer test-owner-session', 'X-Huma-Ticket': pending.ticket, 'Content-Type': 'application/json' }, body: '{}' });
  assert.equal(shared.status, 200, await shared.clone().text());
  const [, pageID, key] = (await shared.json()).path.match(/^\/original\/([a-f0-9]{64})#([a-f0-9]{64})$/);
  // On Arkiv: a record, the page's files, the writer's claims... and none of it readable.
  const kinds = new Set([...chain.entities.values()].map(e => e.p));
  assert.ok(kinds.has('records') && kinds.has('objects'), [...kinds].join());
  for (const e of chain.entities.values()) { assert.ok(!e.body.includes('lives on Arkiv'), 'page text on the chain'); assert.ok(!e.body.includes(key), 'link key on the chain'); }
  // Read by the link, from this server and from a fresh one on the same chain (a restart: no cache).
  const asReader = { headers: { Authorization: 'Bearer ' + key } };
  assert.equal(await (await request(`/api/publications/${pageID}/master`, asReader)).text(), TEXT);
  const restartedRequest = await server(t, again(), directory);
  assert.equal(await (await restartedRequest(`/api/publications/${pageID}/master`, asReader)).text(), TEXT);
  assert.equal((await restartedRequest(`/api/publications/${pageID}/master`)).status, 404); // no link key: not found
  // Its receipt says where the text and proof are kept, so a reader can look them up on Arkiv.
  const { stored } = await (await restartedRequest(`/api/publications/${pageID}/receipt`, asReader)).json();
  assert.equal(stored.owner, chain.network.owner);
  assert.equal(stored.explorer, chain.network.explorer);
  for (const [part, file] of [['master', stored.master], ['proof', stored.proof]]) {
    const entity = chain.entities.get(file.entity);
    assert.equal(entity.k, 'objects/' + (part === 'master' ? sha(TEXT) : entity.v));
    assert.equal(entity.i, 0);
    assert.match(file.tx, /^0x[0-9a-f]{64}$/);
  }
});

// The signed hash record (hash-record.mjs): hashes and the writer's signature, public and unencrypted on Arkiv.
test('a signed page is anchored as a public hash record that checks against its manifest', { timeout: 60000 }, async t => {
  const { privateKeyToAccount, generatePrivateKey } = await import('viem/accounts');
  const { publicationMessage } = await import('../publication-contract.mjs');
  const { checkHashRecord } = await import('../hash-record.mjs');
  const wallet = privateKeyToAccount(generatePrivateKey());
  const { store, chain, directory } = await running(t);
  const registry = await createRegistry({ store: directory, publicationOptions: { objectStore: store, verifyUpload: madeUpPage,
    authenticate: async () => ({ owner: sha('test-owner'), wallets: [wallet.address], account: null }) } });
  await new Promise(resolve => registry.listen(0, '127.0.0.1', resolve));
  t.after(async () => { registry.closeAllConnections(); await new Promise(resolve => registry.close(resolve)); });
  const base = `http://127.0.0.1:${registry.address().port}`;
  const prepared = await (await fetch(base + '/api/publications/prepare', { method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ kind: 'huma-publication-upload-v1', access: 'public', proof: '{}', master: { mediaType: 'text/plain;charset=utf-8', base64: Buffer.from(TEXT).toString('base64') } }) })).json();
  const pending = await (await fetch(base + '/api/publications/pending/' + prepared.id, { headers: { Authorization: 'Bearer ' + prepared.ticket } })).json();
  const signature = await wallet.signMessage({ message: publicationMessage(pending.manifest) });
  const shared = await fetch(base + '/api/publications/pending/' + prepared.id + '/publish', { method: 'POST',
    headers: { Authorization: 'Bearer x', 'X-Huma-Ticket': prepared.ticket, 'Content-Type': 'application/json' }, body: JSON.stringify({ wallet: wallet.address, signature }) });
  assert.equal(shared.status, 200, await shared.clone().text());
  const pageID = (await shared.json()).path.match(/^\/original\/([a-f0-9]{64})/)[1];
  // On the chain in the clear: hashes, no page text.
  const anchored = [...chain.entities.values()].filter(e => e.p === 'attestations');
  assert.equal(anchored.length, 1);
  assert.equal(anchored[0].k, 'attestations/' + pageID);
  const record = JSON.parse(anchored[0].body.toString('utf8'));
  assert.equal(record.textHash, sha(TEXT));
  assert.ok(!anchored[0].body.includes('lives on Arkiv'));
  // The receipt returns it, checked against the manifest and the wallet's signature.
  const { attestation } = await (await fetch(`${base}/api/publications/${pageID}/receipt`)).json();
  assert.deepEqual(attestation.check, { ok: true, signature: 'wallet' });
  assert.equal(attestation.record.wallet, wallet.address);
  // A record for other hashes, or with a changed signer message, doesn't check.
  const manifestSource = JSON.stringify(pending.manifest);
  assert.equal((await checkHashRecord({ ...record, textHash: sha('other') }, manifestSource)).ok, false);
  assert.equal((await checkHashRecord({ ...record, proofHash: sha('other') }, manifestSource)).ok, false);
  assert.equal((await checkHashRecord({ ...record, wallet: privateKeyToAccount(generatePrivateKey()).address }, manifestSource)).ok, false);
});

test('anchoring the same record twice writes one entity, and only attestation keys are accepted', async t => {
  const { store, chain } = await running(t);
  const key = 'attestations/' + id('page'), bytes = Buffer.from('{"version":1}');
  const first = await store.anchor(key, bytes);
  assert.deepEqual(await store.anchor(key, bytes), { ...first, tx: null, expires: null, at: first.at });
  assert.equal([...chain.entities.values()].filter(e => e.p === 'attestations').length, 1);
  await assert.rejects(store.anchor(key, Buffer.from('{"version":2}')), /differs/);
  await assert.rejects(store.anchor('records/' + id('page'), bytes), /Invalid attestation key/);
});
