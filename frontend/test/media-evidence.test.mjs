import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { verify, envelope } from '../verify-core/node.mjs';
const fixtures = new URL('../../extra/experiments/noir-media/reader/test/fixtures/', import.meta.url);
const load = name => readFile(new URL(name, fixtures));
const mutate = (source, field, operation) => {
  const value = JSON.parse(source), bytes = Buffer.from(value[field], 'base64'); operation(bytes);
  value[field] = bytes.toString('base64'); return JSON.stringify(value);
};
for (const [kind, extension] of [['image', 'png'], ['audio', 'flac'], ['video', 'mp4']]) {
  test(`real ${kind} proof verifies exact master, seal and sampled membership`, async () => {
    const source = await load(kind + '.json').then(String), master = new Uint8Array(await load(kind + '.' + extension));
    const report = await verify(source, {}, master);
    assert.equal(report.verified, true); assert.equal(report.statement.contentKind, kind);
    assert.equal(report.statement.contentPolicy, 'exact-bytes-v1');
    assert.equal(report.proofReport.decodingProven, false); assert.equal(report.proofReport.scenePolicyChecked, false);
    assert.equal(report.proofReport.samplingFreshnessVerified, false); assert.equal(report.proofReport.signaturesVerified, 1);
    assert.ok(report.facts.some(f => f.id === 'sample-membership'));
    assert.ok(!report.facts.some(f => f.id === 'signed-capture'));
    const wrapped = await envelope(source, {}, master);
    assert.equal(wrapped.report.statementHash, report.statementHash);
    assert.equal((await verify(wrapped.envelope, { expectedKey: report.statement.captureKeyHash,
      expectedSamplingChallenge: Buffer.from(report.proofReport.journal.challenge).toString('hex') }, master)).verified, true);
  });
}
test('tampered media proof, public input, signature and key fail', async () => {
  const source = await load('audio.json').then(String), master = new Uint8Array(await load('audio.flac'));
  for (const [field, offset] of [['proof', 500], ['publicInputs', 95], ['signature', 10], ['publicKey', 10]]) {
    assert.equal((await verify(mutate(source, field, bytes => { bytes[offset] ^= 1; }), {}, master)).verified, false, field);
  }
});
test('reader rejects wrong/missing master, key/challenge and unsupported claims', async () => {
  const source = await load('image.json').then(String), master = new Uint8Array(await load('image.png'));
  const changed = master.slice(); changed[changed.length - 1] ^= 1;
  for (const content of [undefined, 'image.png', changed, master.subarray(1)]) assert.equal((await verify(source, {}, content)).verified, false);
  for (const policy of [{expectedKey:'0'.repeat(64)}, {expectedSamplingChallenge:'0'.repeat(64)},
    {requireSignedCapture:true}, {requireDevice:true}, {requireAccount:true}, {requirePolicy:'huma-scene-v1'}]) {
    assert.equal((await verify(source, policy, master)).verified, false);
  }
  const unknown = JSON.parse(source); unknown.journal = { scenePolicyChecked:true };
  assert.equal((await verify(JSON.stringify(unknown), {}, master)).verified, false);
  const wrapped = JSON.parse((await envelope(source, {}, master)).envelope);
  wrapped.statement.contentKind = 'video';
  assert.equal((await verify(JSON.stringify(wrapped), {}, master)).verified, false);
  wrapped.statement.contentKind = 'image'; wrapped.attachments.device = '{}';
  assert.equal((await verify(JSON.stringify(wrapped), {}, master)).verified, false);
});
test('reader refuses noncanonical public integers and future profiles', async () => {
  const source = await load('video.json').then(String), master = new Uint8Array(await load('video.mp4'));
  const invalid = mutate(source, 'publicInputs', bytes => { bytes[0] = 1; }); // >u8, not a new kind
  assert.equal((await verify(invalid, {}, master)).verified, false);
  const future = JSON.parse(source); future.profile = 'media-membership-v2';
  assert.equal((await verify(JSON.stringify(future), {}, master)).verified, false);
});
test('master size is checked before worker cloning and sliced views stay exact', async () => {
  const source = await load('image.json').then(String), master = await load('image.png');
  await assert.rejects(verify(source, {}, new Uint8Array(32 * 1024 * 1024 + 1)), /Invalid evidence input/);
  const backing = new Uint8Array(master.length + 8192); backing.set(master, 4096);
  assert.equal((await verify(source, {}, backing.subarray(4096, 4096 + master.length))).verified, true);
});
