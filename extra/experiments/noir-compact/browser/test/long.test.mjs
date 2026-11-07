import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { KEYS, KEYS2, KEYS3, KIND3, KIND3P, assembleLong3, createLongVerifier, deviceRoot, passkeyBinding, passkeyChallenge,
  poseidon2Permute, verifyLongNode } from '../../../../../backend/integrations/noir/long/reader.mjs';
import { hash } from '../final-text.mjs';

// A software-key 600-character session recorded through the Swift app path (8 parts, closed at pauses).
const source = await readFile(new URL('./fixtures/Long600.json', import.meta.url), 'utf8');
const { text } = JSON.parse(source);
const rejects = async (proof, input = text) => { await assert.rejects(verifyLongNode(proof, { text: input })); };
const edit = change => { const p = JSON.parse(source); change(p); return JSON.stringify(p); };
const flip = b => { const raw = Buffer.from(b, 'base64'); raw[raw.length >> 1] ^= 1; return raw.toString('base64'); };

test('long proof verifies every chunk, signature and the reader text', async () => {
  const report = await verifyLongNode(source, { text });
  assert.equal(report.verified, true); assert.equal(report.chunks, 8);
  assert.equal(report.signaturesVerified, 13); assert.equal(report.presenceSignaturesVerified, 2);
  assert.equal(report.journal.policy_satisfied, true);
  assert.equal((await verifyLongNode(source, { text: text + ' \t' })).verified, true);
});
test('changed text, chunks, proofs, signatures or keys are rejected', async () => {
  await rejects(source, text.slice(0, -1)); await rejects(source, text + '\n');
  await rejects(edit(p => { p.chunks.splice(2, 1); p.chunkInputs.splice(2, 1); }));
  await rejects(edit(p => { [p.chunkInputs[1], p.chunkInputs[2]] = [p.chunkInputs[2], p.chunkInputs[1]]; [p.chunks[1], p.chunks[2]] = [p.chunks[2], p.chunks[1]]; }));
  await rejects(edit(p => { p.chunks[3] = flip(p.chunks[3]); }));
  await rejects(edit(p => { p.final = flip(p.final); }));
  await rejects(edit(p => { p.signatures[5] = flip(p.signatures[5]); }));
  await rejects(edit(p => { p.presenceRoots[0] = String(BigInt(p.presenceRoots[0]) + 1n); }));
  await rejects(edit(p => { p.events = p.events.split('').reverse().join(''); }));
  await rejects(edit(p => { const k = Buffer.from(p.publicKey, 'base64'); k[30] ^= 1; p.publicKey = k.toString('base64'); }));
  await assert.rejects(verifyLongNode(source, { text, expectedKey: '0'.repeat(64) }));
});

// Passkey check-ins (v3-passkey): a test-only software authenticator (WebCrypto P-256) approves each check-in, and the writing key
// binds each approval to that passkey. The fixture's writing key isn't available, so passing pages are the same real v3 page re-keyed
// (fresh writing key, nonce re-bound, signatures and event digest redone) and read with a ZK verifier that accepts: every check but the
// ZK proofs is real. The untouched real page still verifies with every proof, and a passkey bound by any other key is rejected on it.
const v3 = await readFile(new URL('./fixtures/Long400V3.json', import.meta.url), 'utf8'), v3Text = JSON.parse(v3).text;
const b64 = b => Buffer.from(b).toString('base64'), sha = async b => new Uint8Array(await crypto.subtle.digest('SHA-256', b));
const p256 = () => crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
function der(raw) {
  const int = b => { let i = 0; while (i < b.length - 1 && b[i] === 0) i++; const v = b[i] & 0x80 ? [0, ...b.subarray(i)] : [...b.subarray(i)]; return [2, v.length, ...v]; };
  const r = int(raw.subarray(0, 32)), s = int(raw.subarray(32)); return Uint8Array.from([0x30, r.length + s.length, ...r, ...s]);
}
const signDer = async (key, bytes) => b64(der(new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key, bytes))));
async function authenticator() {
  const pair = await p256(), raw = new Uint8Array(await crypto.subtle.exportKey('raw', pair.publicKey));
  return { raw, publicKey: b64(raw), key: pair.privateKey,
    // One check-in: the passkey's assertion over the root's challenge, and the writer's binding of root and passkey key.
    async assert(root, { writer, rpId = 'huma.social', origin = 'https://huma.social', type = 'webauthn.get', flags = 0x05, counter = 0, forRoot = root,
      crossOrigin = false, key = this.key, client, bindWith = writer, bindRoot = root, bindKey = this.raw } = {}) {
      const clientDataJSON = Buffer.from(client ?? JSON.stringify({ type, challenge: Buffer.from(await passkeyChallenge(forRoot)).toString('base64url'), origin, crossOrigin }));
      const authData = Buffer.concat([await sha(Buffer.from(rpId)), Buffer.from([flags]), Buffer.alloc(4)]); authData.writeUInt32BE(counter, 33);
      return { authenticatorData: b64(authData), clientDataJSON: b64(clientDataJSON), signature: await signDer(key, Buffer.concat([authData, await sha(clientDataJSON)])),
        ...(bindWith ? { binding: await signDer(bindWith, await passkeyBinding(bindRoot, bindKey)) } : {}) };
    } };
}
const auth = await authenticator(), other = await authenticator();
// The session summary the recorder hands the prover, read back from a page.
const unhex = v => Buffer.from(v, 'base64').toString('hex');
const summaryOf = f => ({ publicKeyHex: unhex(f.publicKey), events: f.events, checkpointRoots: f.checkpointRoots, presenceRoots: f.presenceRoots,
  signaturesHex: f.signatures.map(unhex), presenceSignaturesHex: f.presenceSignatures.map(unhex), text: f.text });
const assemble = (f, passkey) => assembleLong3({ ...summaryOf(f), ...(passkey ? { passkey } : {}) },
  f.chunks.map((proof, i) => ({ proof, publicInputs: f.chunkInputs[i] })), { proof: f.final, publicInputs: f.finalInputs });
// The real page with a fresh writing key and `approved` approved check-ins.
async function rekey(approved) {
  const f = JSON.parse(v3), writer = await p256();
  const key = new Uint8Array(await crypto.subtle.exportKey('raw', writer.publicKey)), field = n => Buffer.from(BigInt(n).toString(16).padStart(64, '0'), 'hex');
  while (f.presenceRoots.length < approved) { f.presenceRoots.push(String(BigInt(f.presenceRoots.at(-1)) * 7n % 2n ** 250n)); f.events = f.events.slice(0, -1) + '21'; }
  f.publicKey = b64(key);
  f.signatures = await Promise.all(f.checkpointRoots.map(r => signDer(writer.privateKey, Buffer.concat([Buffer.from('HUMA_LONG_ASSURANCE_CHECKPOINT_V1\0'), field(r)]))));
  f.presenceSignatures = await Promise.all(f.presenceRoots.map(r => signDer(writer.privateKey, Buffer.concat([Buffer.from('HUMA_LONG_ASSURANCE_PRESENCE_V1\0'), field(r)]))));
  const inputs = Buffer.from(f.finalInputs, 'base64'), set = (slot, n) => field(n).copy(inputs, slot * 32), get = slot => BigInt('0x' + inputs.subarray(slot * 32, slot * 32 + 32).toString('hex'));
  set(1, await hash([0x48554d410802n, await deviceRoot(key), get(0)], poseidon2Permute) % (1n << 128n)); // nonce binds the writing key
  set(26, approved);
  let digest = 0n; const next = [0, 0], roots = [f.checkpointRoots, f.presenceRoots];
  for (const kind of [...f.events].map(Number)) digest = await hash([0x48554d410703n, digest, BigInt(kind), BigInt(roots[kind - 1][next[kind - 1]++])], poseidon2Permute);
  set(43, digest); f.finalInputs = inputs.toString('base64');
  return { source: JSON.stringify(f), writer: writer.privateKey };
}
const asset = n => readFile(new URL('../assets/' + n + '.vk', import.meta.url)).then(b => new Uint8Array(b));
const load = async (prefix, names) => Object.fromEntries(await Promise.all(Object.keys(names).map(async n => [n, await asset(prefix + n)])));
const pinned = { keys: await load('long-', KEYS), keys2: await load('long2-', KEYS2), keys3: await load('long3-', KEYS3) };
const accepting = passkeyRelyingParties => createLongVerifier({ ...pinned, verifyZk: async () => true, passkeyRelyingParties });
const one = await rekey(1), two = await rekey(2);
const passkeyPage = async ({ source, writer }, each = () => ({}), change = () => {}) => {
  const f = JSON.parse(source), passkey = { publicKey: auth.publicKey, assertions: await Promise.all(f.presenceRoots.map((r, i) => auth.assert(r, { writer, ...each(i) }))) };
  const p = JSON.parse(assemble(f, passkey)); change(p); return JSON.stringify(p);
};

test('v3 pages keep their bytes; with every check-in approved by the passkey they become v3-passkey and verify', async () => {
  const f = JSON.parse(v3);
  assert.equal(assemble(f), v3);
  const plain = await verifyLongNode(v3, { text: v3Text }); // every proof, real keys
  assert.equal(plain.verified, true); assert.ok(!plain.passkeyVerified); assert.equal(plain.passkeyKeyHash, undefined);
  assert.equal((await verifyLongNode(v3, { text: v3Text }, { passkeyRelyingParties: [{ id: 'localhost', origin: 'http://localhost:5173' }] })).verified, true);
  await assert.rejects(verifyLongNode(v3, { text: v3Text }, { passkeyRelyingParties: [] }));
  // On the real page no one but its writer can add a passkey: a binding by any other key fails, with every proof checked.
  const stranger = (await p256()).privateKey;
  await assert.rejects(verifyLongNode(await passkeyPage({ source: v3, writer: stranger }), { text: v3Text }));
  const page = await passkeyPage(one), p = JSON.parse(page);
  assert.equal(p.kind, KIND3P); assert.equal(p.profile, 'assurance-long-v3'); assert.deepEqual(Object.keys(p.passkey), ['publicKey', 'assertions']);
  assert.deepEqual(Object.keys(p.passkey.assertions[0]), ['authenticatorData', 'clientDataJSON', 'signature', 'binding']);
  const report = await accepting()(page, { text: v3Text }), rekeyed = await accepting()(one.source, { text: v3Text });
  assert.equal(report.verified, true); assert.equal(report.passkeyVerified, true);
  assert.equal(report.passkeyKeyHash, Buffer.from(await sha(auth.raw)).toString('hex'));
  assert.equal(report.profile, rekeyed.profile); assert.equal(report.proofIdentity, rekeyed.proofIdentity); assert.ok(!rekeyed.passkeyVerified);
});
test('a passkey check-in that is not exactly this page’s, at this party, verified by the user and bound by its writer, is rejected', async () => {
  const no = async (each, change, parties) => assert.rejects(accepting(parties)(await passkeyPage(one, each, change), { text: v3Text }));
  const root = JSON.parse(one.source).presenceRoots[0], another = String(BigInt(root) + 1n), stranger = (await p256()).privateKey;
  assert.equal((await accepting()(await passkeyPage(one), { text: v3Text })).passkeyVerified, true); // the same path passes untouched
  await no(() => ({ flags: 0x01 })); // UV cleared
  await no(() => ({ flags: 0x04 })); // UP cleared
  await no(() => ({ rpId: 'evil.example' }));
  await no(() => ({ rpId: 'localhost' }));
  await no(() => ({ origin: 'https://evil.example' }));
  await no(() => ({ origin: 'https://huma.social.evil.example' }));
  await no(() => ({ type: 'webauthn.create' }));
  await no(() => ({ crossOrigin: true }));
  await no(() => ({ forRoot: another })); // challenge for another root
  await no(undefined, p => { p.passkey.assertions = []; }); // fewer than approved
  await no(undefined, p => { p.passkey.assertions.push(p.passkey.assertions[0]); }); // more than approved
  await no(undefined, p => { p.passkey.assertions[0].signature = flip(p.passkey.assertions[0].signature); });
  await no(undefined, p => { p.passkey.assertions[0].authenticatorData = flip(p.passkey.assertions[0].authenticatorData); });
  await no(() => ({ key: other.key })); // another passkey signed it
  await no(undefined, p => { p.passkey.publicKey = other.publicKey; });
  // Binding: missing, by another key, for another root, for another passkey key, or damaged.
  await no(() => ({ bindWith: null }));
  await no(() => ({ bindWith: stranger }));
  await no(() => ({ bindRoot: another }));
  await no(() => ({ bindKey: other.raw }));
  await no(undefined, p => { p.passkey.assertions[0].binding = flip(p.passkey.assertions[0].binding); });
  await no(undefined, p => { p.passkey.assertions[0].binding = p.passkey.assertions[0].signature; });
  // Exact shapes.
  await no(undefined, p => { p.extra = 1; });
  await no(undefined, p => { p.passkey.extra = 1; });
  await no(undefined, p => { p.passkey.assertions[0].extra = 'x'; });
  await no(undefined, p => { delete p.passkey; });
  await no(undefined, p => { p.kind = KIND3; }); // a plain v3 page doesn't carry assertions
  await no(undefined, p => { p.profile = 'assurance-long-v1'; });
  await no(undefined, p => { const a = p.passkey.assertions[0]; a.clientDataJSON = b64(Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from(a.clientDataJSON, 'base64')])); });
  // clientDataJSON with a repeated member name (a parser that keeps the first would read another origin or type).
  const challenge = Buffer.from(await passkeyChallenge(root)).toString('base64url');
  await no(() => ({ client: `{"type":"webauthn.get","challenge":"${challenge}","origin":"https://evil.example","origin":"https://huma.social"}` }));
  await no(() => ({ client: `{"type":"webauthn.create","\\u0074ype":"webauthn.get","challenge":"${challenge}","origin":"https://huma.social"}` }));
  const nested = `{"type":"webauthn.get","challenge":"${challenge}","origin":"https://huma.social","other":{"origin":"x","origin":"y"},"tag":["a,\\"origin\\":1"]}`;
  assert.equal((await accepting()(await passkeyPage(one, () => ({ client: nested })), { text: v3Text })).passkeyVerified, true); // nested names don't count
  // A local dev page's passkey (localhost) is not huma.social's, unless the reader names it.
  const dev = [{ id: 'localhost', origin: 'http://localhost:5173' }], local = () => ({ rpId: 'localhost', origin: 'http://localhost:5173' });
  await no(local);
  assert.equal((await accepting(dev)(await passkeyPage(one, local), { text: v3Text })).passkeyVerified, true);
  await no(undefined, undefined, dev);
  await no(() => ({ rpId: 'localhost', origin: 'http://localhost:5174' }), undefined, dev);
  // The origin's party, not another listed one, scopes the key.
  await no(() => ({ rpId: 'localhost' }), undefined, [...dev, { id: 'huma.social', origin: 'https://huma.social' }]);
});
test('the reader takes only well-formed relying parties', async () => {
  const keys = { chunk: new Uint8Array(1), final1024: new Uint8Array(1), final4096: new Uint8Array(1), final10000: new Uint8Array(1) }, verifyZk = async () => true;
  const make = passkeyRelyingParties => createLongVerifier({ keys, verifyZk, passkeyRelyingParties });
  assert.equal(typeof make(undefined), 'function');
  assert.equal(typeof make([{ id: 'huma.social', origin: 'https://www.huma.social' }]), 'function');
  for (const bad of [[], {}, 'huma.social', [null], [{ id: 'huma.social' }], [{ id: 'huma.social', origin: 'https://huma.social', extra: 1 }],
    [{ id: 'huma.social', origin: 'https://evil.example' }], [{ id: 'huma.social', origin: 'http://huma.social' }], [{ id: 'huma.social', origin: 'https://huma.social/' }],
    [{ id: 'Huma.Social', origin: 'https://huma.social' }], [{ id: 'social', origin: 'https://huma.social:8443/x' }], [{ id: 'evil.example', origin: 'http://evil.example' }],
    [{ id: 'localhost', origin: 'https://localhost.evil.example' }], Array(17).fill({ id: 'huma.social', origin: 'https://huma.social' })])
    assert.throws(() => make(bad));
});
test('swapped check-ins and passkey counters that go backwards are rejected', async () => {
  const ok = async (each, change) => accepting()(await passkeyPage(two, each, change), { text: v3Text });
  const roots = JSON.parse(two.source).presenceRoots;
  assert.equal(roots.length, 2);
  assert.equal((await ok()).passkeyVerified, true);
  assert.equal((await ok(i => ({ counter: [0, 5][i] }))).passkeyVerified, true);
  assert.equal((await ok(i => ({ counter: [4, 9][i] }))).passkeyVerified, true);
  assert.equal((await ok(i => ({ counter: [5, 0][i] }))).passkeyVerified, true); // an authenticator may report no counter
  await assert.rejects(ok(undefined, p => p.passkey.assertions.reverse())); // swapped
  await assert.rejects(ok(undefined, p => { const [a, b] = p.passkey.assertions; [a.binding, b.binding] = [b.binding, a.binding]; })); // bindings swapped
  await assert.rejects(ok(i => ({ counter: [9, 4][i] }))); // backwards
  await assert.rejects(ok(i => ({ counter: [5, 5][i] })));
  await assert.rejects(ok(undefined, p => p.passkey.assertions.pop())); // fewer than approved
  await assert.rejects(ok(i => ({ key: i ? other.key : auth.key }))); // a different key on one check-in
  await assert.rejects(ok(i => ({ bindKey: i ? other.raw : auth.raw }))); // one approval bound to another passkey
  await assert.rejects(ok(i => ({ forRoot: roots[1 - i] })));
  // Signatures are kept exactly as the authenticator gave them, so a high-S one (s > n/2) verifies too.
  const n = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n, int = b => BigInt('0x' + Buffer.from(b).toString('hex'));
  const high = sig => { const d = Buffer.from(sig, 'base64'), rl = d[3], r = d.subarray(4, 4 + rl), s = int(d.subarray(6 + rl)), hs = s > n / 2n ? s : n - s;
    return b64(der(Uint8Array.from(Buffer.concat([Buffer.from(int(r).toString(16).padStart(64, '0'), 'hex'), Buffer.from(hs.toString(16).padStart(64, '0'), 'hex')])))); };
  assert.equal((await ok(undefined, p => p.passkey.assertions.forEach(a => { a.signature = high(a.signature); a.binding = high(a.binding); }))).passkeyVerified, true);
});
