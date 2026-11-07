// node --test backend/integrations/noir/batch/batch.test.mjs   (HUMA_BATCH_PROVE=1 also proves a real batch)
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile, writeFile, mkdir } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { slotOf, layout, proveBatch, leafOf } from './prove.mjs';

const here = path.dirname(fileURLToPath(import.meta.url)), repo = path.resolve(here, '../../../..');
const fixture = async name => slotOf(JSON.parse(await readFile(path.join(repo, 'extra/experiments/noir-compact/browser/test/fixtures', name + '.json'), 'utf8')));
const noirJs = path.join(repo, 'extra/experiments/noir-replay/runtime/node_modules/@noir-lang/noir_js/lib/index.mjs');

test('slots accept every pinned short-page circuit and refuse anything else', async () => {
  for (const [name, size] of [['Assurance64Unicode', 'small'], ['AssuranceV5', 'small'], ['Assurance250', 'small'],
    ['Assurance128Unicode', 'large'], ['AssuranceCP32', 'large']]) assert.equal((await fixture(name)).size, size, name);
  assert.equal(await fixture('Bucket50'), null); // a different circuit family
  assert.equal(slotOf({ profile: 'assurance-long-v1', proof: '', publicInputs: '' }), null);
  await assert.rejects(layout([await fixture('AssuranceV5'), await fixture('Assurance250'), await fixture('Assurance64Unicode')]), /Too many/);
});

test('the reader-side commitment equals the circuit output, and binds every statement', async () => {
  const pages = [await fixture('AssuranceV5'), await fixture('AssuranceCP32')];
  const batch = await layout(pages);
  assert.deepEqual(batch.filler, [false, true, false, true]);
  const circuit = JSON.parse(await readFile(path.join(here, 'circuit.json'), 'utf8'));
  const { Noir } = await import(noirJs);
  const hex = v => '0x' + BigInt(v).toString(16).padStart(64, '0');
  const part = (a, b) => batch.slots.slice(a, b);
  const { returnValue } = await new Noir(circuit).execute({
    small_keys: part(0, 2).map(s => s.keyFields), small_proofs: part(0, 2).map(s => s.proof.map(hex)), small: part(0, 2).map(s => s.statement.map(hex)),
    large_keys: part(2, 4).map(s => s.keyFields), large_proofs: part(2, 4).map(s => s.proof.map(hex)), large: part(2, 4).map(s => s.statement.map(hex)) });
  assert.equal(hex(returnValue), batch.root);
  const tampered = { ...pages[0], statement: pages[0].statement.map((v, i) => i === 5 ? v + 1n : v) };
  assert.notEqual(await leafOf(tampered), batch.leaves[0]);
  assert.notEqual((await layout([tampered, pages[1]])).root, batch.root);
});

test('proves a real batch for the registry contract', { skip: !process.env.HUMA_BATCH_PROVE, timeout: 300000 }, async () => {
  const started = performance.now();
  const batch = await proveBatch([await fixture('AssuranceV5'), await fixture('Assurance64Unicode'), await fixture('AssuranceCP32')]);
  const seconds = (performance.now() - started) / 1000;
  assert.match(batch.proof, /^0x[0-9a-f]+$/);
  await mkdir(path.join(repo, 'contracts/test/fixtures'), { recursive: true });
  await writeFile(path.join(repo, 'contracts/test/fixtures/batch.json'), JSON.stringify({ root: batch.root, proof: batch.proof }) + '\n');
  console.log(`batch proved in ${seconds.toFixed(1)} s; proof ${(batch.proof.length - 2) / 2} bytes; root ${batch.root}`);
});

test('readers can check a receipt off-chain; key pins agree with the circuit data', async () => {
  const { checkReceipt, KEY_HASHES } = await import('./commit.mjs');
  const keys = JSON.parse(await readFile(path.join(here, 'keys.json'), 'utf8')).profiles;
  const circuit = await readFile(path.join(here, 'src/main.nr'), 'utf8');
  for (const [profile, [hash, size]] of Object.entries(KEY_HASHES)) {
    assert.equal(keys[profile].hash, hash, profile); assert.ok(circuit.includes(hash), profile);
    assert.equal(keys[profile].publicInputs, size === 'small' ? 94 : 142, profile);
  }
  const raw = name => readFile(path.join(repo, 'extra/experiments/noir-compact/browser/test/fixtures', name + '.json'), 'utf8').then(JSON.parse);
  const [page, other] = [await raw('AssuranceV5'), await raw('AssuranceCP32')];
  const batch = await layout([slotOf(page), slotOf(other)]);
  const receipt = { index: 0, leaves: batch.leaves, root: batch.root };
  assert.equal(await checkReceipt(page, receipt), batch.root);
  assert.equal(await checkReceipt(other, { ...receipt, index: 2 }), batch.root);
  await assert.rejects(checkReceipt(page, { ...receipt, index: 1 }), /not in that batch/);   // the filler's slot
  await assert.rejects(checkReceipt(page, { ...receipt, index: 2 }), /Malformed/);         // a large slot
  await assert.rejects(checkReceipt(page, { ...receipt, root: '0x' + '0'.repeat(64) }), /does not match/);
  await assert.rejects(checkReceipt({ ...page, profile: 'cast256-v1' }, receipt), /not batched/);
});
