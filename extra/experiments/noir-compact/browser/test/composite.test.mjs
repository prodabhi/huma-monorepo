import test, { after } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { webcrypto } from 'node:crypto';
import { createCompactVerifier, decodeJournal, derToP1363, canonicalTextBytes } from '../core.mjs';
import { createWasmVerifier } from '../wasm.mjs';
import { checkAsset } from '../profile.mjs';

if (!globalThis.crypto) globalThis.crypto = webcrypto;
const load = async name => new Uint8Array(await readFile(new URL('../assets/' + name, import.meta.url)));
const fixture = async name => JSON.parse(await readFile(new URL('./fixtures/' + name + '.json', import.meta.url)));
const [verificationKey, journalABI, g2, manifest] = await Promise.all([
  load('cast256.vk'), load('journal-abi.json'), load('g2.dat'), fixture('manifest'),
]);
// SDK initialization and every real proof check must succeed without a network request.
const originalFetch = globalThis.fetch;
globalThis.fetch = () => { throw new Error('External networking forbidden in verification tests.'); };
const backend = await createWasmVerifier(g2);
const verify = await createCompactVerifier({ verificationKey, journalABI, verifyZk: backend.verify });
after(async () => { await backend.destroy(); globalThis.fetch = originalFetch; });
const valid = await fixture('Bucket250');
const clone = value => structuredClone(value);
const bytes = b64 => Uint8Array.from(Buffer.from(b64, 'base64'));
const encoded = raw => Buffer.from(raw).toString('base64');
const rejects = async value => assert.rejects(() => verify(JSON.stringify(value)));

for (const expected of manifest) test('native proof and composite identity: ' + expected.name, async () => {
  const input = await fixture(expected.name);
  const result = await verify(JSON.stringify(input), { text: input.text + ' \t', expectedKey: expected.keyHash });
  assert.equal(result.proofIdentity, expected.proofIdentity);
  assert.equal(result.signaturesVerified, expected.signatures);
  assert.equal(result.journal.elapsed, expected.elapsedMillis);
  assert.equal(result.textCompared, true);
  assert.equal(result.attestationVerified, false);
  assert.equal(result.trustedTime, false);
  assert.equal(result.humanAuthorshipProven, false);
  assert.doesNotThrow(() => JSON.stringify(result));
});

for (const offset of [0, 31, 32, 128, 512, 4096, 14655]) test('reject changed real proof byte ' + offset, async () => {
  const bad = clone(valid), raw = bytes(bad.proof); raw[offset] ^= 1; bad.proof = encoded(raw);
  await rejects(bad);
});

for (let i = 0; i < valid.signatures.length; i++) test('reject changed checkpoint signature ' + i, async () => {
  const bad = clone(valid), raw = bytes(bad.signatures[i]); raw[raw.length - 1] ^= 1; bad.signatures[i] = encoded(raw);
  await rejects(bad);
});

test('missing, extra and reordered signatures reject despite valid SNARK', async () => {
  for (const mutate of [s => s.pop(), s => s.push(s[0]), s => s.reverse(), s => { s[1] = s[0]; }]) {
    const bad = clone(valid); mutate(bad.signatures); await rejects(bad);
  }
});

const order = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
function derInteger(n) {
  let hex = n.toString(16); if (hex.length % 2) hex = '0' + hex;
  if (parseInt(hex.slice(0, 2), 16) & 128) hex = '00' + hex;
  const body = Buffer.from(hex, 'hex'); return Buffer.concat([Buffer.from([2, body.length]), body]);
}
test('both low-S and high-S signatures retain native protocol validity', async () => {
  for (const high of [false, true]) {
    const input = clone(valid);
    input.signatures = input.signatures.map(s => {
      const raw = derToP1363(bytes(s));
      const r = BigInt('0x' + Buffer.from(raw.subarray(0, 32)).toString('hex'));
      let value = BigInt('0x' + Buffer.from(raw.subarray(32)).toString('hex'));
      if ((value > order / 2n) !== high) value = order - value;
      const body = Buffer.concat([derInteger(r), derInteger(value)]);
      return encoded(Buffer.concat([Buffer.from([0x30, body.length]), body]));
    });
    assert.equal((await verify(JSON.stringify(input))).verified, true);
  }
});

test('strict DER excludes negative, zero, oversized, nonminimal and trailing values', () => {
  for (const raw of [
    [0x30, 6, 2, 1, 0, 2, 1, 1], [0x30, 6, 2, 1, 128, 2, 1, 1],
    [0x30, 7, 2, 2, 0, 1, 2, 1, 1], [0x30, 6, 2, 1, 1, 2, 1, 1, 0],
    [0x30, 6, 3, 1, 1, 2, 1, 1], [0x30, 0x81, 2, 1, 1, 2, 1, 1],
    Buffer.concat([Buffer.from([0x30, 38]), derInteger(order), derInteger(1n)]),
  ]) assert.throws(() => derToP1363(new Uint8Array(raw)));
});

test('expected key and actual curve point are checked', async () => {
  await assert.rejects(() => verify(JSON.stringify(valid), { expectedKey: '0'.repeat(64) }));
  await assert.rejects(() => verify(JSON.stringify(valid), { expectedKey: 'X'.repeat(64) }));
  const bad = clone(valid); bad.publicKey = (await fixture('Bucket50')).publicKey; await rejects(bad);
  const point = bytes(valid.publicKey); point.fill(0, 1); bad.publicKey = encoded(point); await rejects(bad);
});

test('exact character policy and Unicode rejection', async () => {
  for (const text of [valid.text + '\n', valid.text + '\u00a0', ' ' + valid.text, valid.text + '!', valid.text + '\ud800', valid.text + '\udc00']) {
    await assert.rejects(() => verify(JSON.stringify(valid), { text }));
  }
  const bad = clone(valid); bad.text += '\ud800'; await rejects(bad);
  const noText = clone(valid); delete noText.text;
  assert.equal((await verify(JSON.stringify(noText))).textCompared, false);
});

test('canonicalization trims only the absolute end, preserving spaces before a final newline', () => {
  const decode = bytes => new TextDecoder().decode(bytes);
  for (const [input, expected] of [['a \t', 'a'], ['a \n', 'a \n'], ['a\t\r\n', 'a\t\r\n'], ['a\n \t', 'a\n'], ['a\u00a0', 'a\u00a0'], [' e\u0301 ', ' e\u0301']]) {
    assert.equal(decode(canonicalTextBytes(input)), expected);
  }
});

function fieldChange(input, index, value) {
  const changed = clone(input), raw = bytes(changed.publicInputs);
  raw.set(Buffer.from(value.toString(16).padStart(64, '0'), 'hex'), index * 32);
  changed.publicInputs = encoded(raw); return changed;
}
const abi = JSON.parse(new TextDecoder().decode(journalABI));
function fieldIndex(name) {
  let i = 0;
  for (const f of abi.fields) { if (f.name === name) return i; i += f.type.kind === 'array' ? f.type.length : 1; }
  throw Error(name);
}
test('public u64 values remain exact and forged metadata fails the actual proof', async () => {
  const elapsed = fieldIndex('elapsed'), maximum = (1n << 64n) - 1n;
  const input = fieldChange(valid, elapsed, maximum);
  assert.equal(decodeJournal(bytes(input.publicInputs), abi).elapsed, maximum.toString());
  await rejects(input);
  assert.throws(() => decodeJournal(bytes(fieldChange(valid, elapsed, 1n << 64n).publicInputs), abi));
});

test('public integer, field, boolean, checkpoint and padding boundaries reject', async () => {
  const attacks = [
    ['byte_length', 1n << 32n], ['session_nonce', 1n << 128n],
    ['capture_root', 21888242871839275222246405745257275088548364400416034343698204186575808495617n],
    ['clock_back', 2n], ['checkpoint_count', 0n], ['checkpoint_count', 1n], ['checkpoint_count', 9n],
    ['start_unix', 253402300800000n], ['op_count', 1537n],
  ];
  for (const [name, value] of attacks) await rejects(fieldChange(valid, fieldIndex(name), value));
  await rejects(fieldChange(valid, fieldIndex('checkpoint_roots') + 7, 1n));
  await rejects(fieldChange(valid, fieldIndex('checkpoint_count'), 6n));
  await rejects(fieldChange(valid, fieldIndex('typing'), 249n)); // Plausible display change: the SNARK must reject it.
});

test('wire format cannot choose its key, program, journal or unrecognized private fields', async () => {
  for (const extra of ['verificationKey', 'journal', 'private', '__proto__']) {
    const bad = clone(valid); Object.defineProperty(bad, extra, { value: {}, enumerable: true }); await rejects(bad);
  }
  for (const change of [{ kind: 'other' }, { profile: 'other' }, { proof: valid.proof + '=' }, { publicInputs: valid.publicInputs.slice(4) }]) await rejects({ ...valid, ...change });
  await assert.rejects(() => verify(' '.repeat(512 * 1024 + 1)));
  await assert.rejects(() => verify('null'));
  await assert.rejects(() => verify(JSON.stringify(valid), { verificationKey: 'attacker' }));
});

test('trusted VK, ABI and CRS pins cannot be replaced', async () => {
  for (const [name, raw] of [['cast256.vk', verificationKey], ['journal-abi.json', journalABI], ['g2.dat', g2]]) {
    const bad = raw.slice(); bad[0] ^= 1; await assert.rejects(() => checkAsset(name, bad));
  }
  const bad = verificationKey.slice(); bad[0] ^= 1;
  await assert.rejects(() => createCompactVerifier({ verificationKey: bad, journalABI, verifyZk: backend.verify }));
});
