import test, { after } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { Barretenberg, BackendType } from '@aztec/bb.js';
import { finalTextStatement, matchFinalText, bbPermute } from '../final-text.mjs';

const fixtures = JSON.parse(await readFile(new URL('./fixtures/final-text.json', import.meta.url)));
const api = await Barretenberg.new({ backend: BackendType.Wasm, threads: 1 });
after(() => api.destroy());
const permute = bbPermute(api);
const bytes = text => new TextEncoder().encode(text);

test('reader recomputes the native raw and canonical commitments from the master bytes', async () => {
  for (const f of fixtures.filter(f => f.accepted)) {
    const master = bytes(f.text);
    assert.equal(createHash('sha256').update(master).digest('hex'), f.rawSha256, f.case + ' master bytes');
    const mine = await finalTextStatement(master, f.capacity, permute);
    for (const [k, v] of Object.entries(f.expected)) assert.equal(String(mine[k]), String(v), f.case + ' ' + k);
    assert.deepEqual(await matchFinalText(master, f.capacity, f.expected, permute), { exact: true, canonical: true, match: true });
  }
});

test('empty and whitespace-only masters are never provable', async () => {
  for (const f of fixtures.filter(f => !f.accepted))
    await assert.rejects(finalTextStatement(bytes(f.text), f.capacity, permute), /Empty canonical text/, f.case);
});

test('trailing ASCII space/tab is the only tolerated difference', async () => {
  const f = fixtures.find(f => f.case === 'master-trailing');
  const trimmed = f.text.replace(/[ \t]+$/, '');
  assert.deepEqual(await matchFinalText(bytes(trimmed + ' \t \t'), f.capacity, f.expected, permute), { exact: false, canonical: true, match: true });
  // A no-break space, newline or changed character is content, not ignorable whitespace.
  for (const other of [trimmed + ' ', trimmed + '\n', 'B' + trimmed.slice(1), trimmed.normalize('NFC')])
    assert.equal((await matchFinalText(bytes(other), f.capacity, f.expected, permute)).match, false, JSON.stringify(other));
});

test('normalization forms, BOM, NUL and line endings stay distinct', async () => {
  const get = name => fixtures.find(f => f.case === name);
  const nfc = get('master-nfc'), nfd = get('master-nfd');
  assert.equal((await matchFinalText(bytes(nfd.text), nfc.capacity, nfc.expected, permute)).match, false);
  const bom = get('master-bom');
  assert.equal((await matchFinalText(bytes(bom.text.slice(1)), bom.capacity, bom.expected, permute)).match, false);
  const crlf = get('master-crlf');
  assert.equal((await matchFinalText(bytes(crlf.text.replace('\r\n', '\n')), crlf.capacity, crlf.expected, permute)).match, false);
});

test('the reader binds the master to its capacity and rejects invalid UTF-8', async () => {
  const f = fixtures.find(f => f.case === 'master-gap');
  assert.equal((await matchFinalText(bytes(f.text), f.capacity * 2, f.expected, permute)).match, false);
  await assert.rejects(finalTextStatement(new Uint8Array([0x61, 0xff]), f.capacity, permute));
  await assert.rejects(finalTextStatement(bytes('a'.repeat(65)), 64, permute), /exceeds the proven capacity/);
});
