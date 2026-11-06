import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile, mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { createRegistry } from '../registry.mjs';

test('real compact public proof, text and signatures survive registry transport; tampering rejects', { timeout: 30000 }, async t => {
  const store = await mkdtemp(path.join(tmpdir(), 'huma-compact-registry-'));
  const server = await createRegistry({ store, allowLegacyUploads: true });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(async () => { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); await rm(store, { recursive: true, force: true }); });
  const base = `http://127.0.0.1:${server.address().port}`;
  const record = JSON.parse(await readFile(new URL('../../extra/experiments/noir-compact/browser/test/fixtures/Bucket250.json', import.meta.url)));
  const upload = file => fetch(base + '/api/proofs', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(file) });
  const response = await upload(record);
  assert.equal(response.status, 201, await response.clone().text());
  const { id } = await response.json();
  const stored = await (await fetch(base + '/api/proofs/' + id)).text();
  assert.equal(createHash('sha256').update(stored).digest('hex'), id);
  assert.deepEqual(JSON.parse(stored), record);
  assert.equal((await upload(record)).status, 201);
  assert.equal((await fetch(base + '/verify/' + id)).status, 200);
  for (const change of [
    { text: record.text + '!' }, { signatures: record.signatures.slice(0, -1) },
    { signatures: record.signatures.toReversed ? record.signatures.toReversed() : [...record.signatures].reverse() },
    { privateHistory: 'MUST-NOT-BE-STORED' }, { verificationKey: record.proof },
    { profile: 'another-profile' }, { text: undefined },
    { proof: Buffer.from(new Uint8Array(14656)).toString('base64') },
  ]) assert.equal((await upload({ ...record, ...change })).status, 422);
});
