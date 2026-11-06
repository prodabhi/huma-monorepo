import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { existsSync } from 'node:fs';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import path from 'node:path';
import { tmpdir } from 'node:os';
import { createRegistry } from '../registry.mjs';
import { PROGRAMS, POINTS } from '../write/pins.mjs';
import { KEYS3 } from '../../backend/integrations/noir/long/reader.mjs';
import { der, loadRecorder, Recording } from '../write/recorder.mjs';
import { keyCode, modifiers } from '../write/keys.mjs';

const W = new URL('../', import.meta.url).pathname, hash = b => createHash('sha256').update(b).digest('hex');

test('the browser prover pins the same programs and keys as the Mac engine and the reader', async () => {
  const worker = await readFile(W + '../backend/integrations/noir/worker.mjs', 'utf8');
  const block = worker.slice(worker.indexOf('const long3={'), worker.indexOf('const TIERS='));
  for (const [name, pin] of Object.entries(PROGRAMS)) {
    assert.match(block, new RegExp(`${name}:\\{bytecode:'${pin.bytecode}',vk:'${pin.vk}'\\}`), name);
    assert.equal(KEYS3[name], pin.vk, name);
  }
  assert.deepEqual(Object.keys(PROGRAMS).sort(), Object.keys(KEYS3).sort());
  assert.equal(POINTS.g2, '01797bfc4de5a96f0e516a9ea4537d18786dc30cb991aca4274c95822b69c32f');
});

test('WebCrypto signatures become the DER the recorder and readers check', () => {
  const raw = new Uint8Array(64); raw[0] = 0x80; raw[33] = 0x01; raw[63] = 0x02; // r with its top bit set; s with leading zeros
  const encoded = der(raw);
  assert.deepEqual([...encoded.subarray(0, 4)], [0x30, encoded.length - 2, 0x02, 33]);
  assert.equal(encoded[4], 0); // a zero keeps r positive
  const s = encoded.subarray(4 + 33);
  assert.deepEqual([...s.subarray(0, 2)], [0x02, 31]);
  assert.equal(keyCode('KeyA'), 0); assert.equal(keyCode('Space'), 49); assert.equal(keyCode('NoSuchKey'), 255);
  assert.equal(modifiers({ shiftKey: true, metaKey: true }), (1 << 17) | (1 << 20));
});

test('/write is cross-origin isolated and serves only its own files', { timeout: 60000 }, async t => {
  const directory = await mkdtemp(path.join(tmpdir(), 'huma-write-'));
  const server = await createRegistry({ store: directory });
  await new Promise(r => server.listen(0, '127.0.0.1', r));
  t.after(async () => { server.closeAllConnections(); await new Promise(r => server.close(r)); await rm(directory, { recursive: true, force: true }); });
  const base = `http://127.0.0.1:${server.address().port}`;
  const page = await fetch(base + '/write');
  assert.equal(page.status, 200);
  assert.equal(page.headers.get('cross-origin-opener-policy'), 'same-origin');
  assert.equal(page.headers.get('cross-origin-embedder-policy'), 'require-corp');
  assert.match(page.headers.get('content-security-policy'), /script-src 'self' 'wasm-unsafe-eval'/);
  for (const bad of ['/write/../registry.mjs', '/write/%2e%2e/registry.mjs', '/write/pins.mjs', '/write/build.mjs', '/write/points/18', '/write/points/21', '/write/X.js'])
    assert.equal((await fetch(base + bad)).status, 404, bad);
  if (existsSync(W + 'dist/write/write.js')) {
    const script = await fetch(base + '/write/write.js');
    assert.equal(script.status, 200); assert.equal(script.headers.get('cross-origin-resource-policy'), 'same-origin');
  }
  // The proving points come from the setup the Mac app uses, checked against their pin.
  if (existsSync(W + '../build/research/noir-crs/bn254_g1_compressed.dat')) {
    const points = new Uint8Array(await (await fetch(base + '/write/points/19')).arrayBuffer());
    assert.equal(points.length, 32 << 19); assert.equal(hash(points), POINTS[19]);
  }
});

test('a recording made through the page code gives the proof inputs the Mac prover accepts', { timeout: 60000,
  skip: !existsSync(W + 'dist/write/recorder.wasm') && 'Build web/dist/write first (node write/build.mjs).' }, async () => {
  const call = await loadRecorder(await readFile(W + 'dist/write/recorder.wasm'));
  const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign', 'verify']);
  const recording = await Recording.start(call, pair);
  const text = 'Typed in a browser, recorded the way the Mac app records it. '.repeat(3);
  let page = '', clock = 0;
  for (const [i, c] of [...text].entries()) {
    clock += i % 23 === 22 ? 900 : 150 + (i * 37) % 90;
    await recording.key('down', keyCode(c === ' ' ? 'Space' : 'KeyA'), 0, clock);
    page += c; await recording.edit(page, i % 50 === 0 ? 'typing-external' : 'typing', clock + 5);
    await recording.key('up', keyCode(c === ' ' ? 'Space' : 'KeyA'), 0, clock + 60); clock += 60;
    await recording.checkpoint(clock);
    if (i % 40 === 39) await recording.cut(450);
  }
  // Text that arrives in the middle of a check-in is refused, and the recording carries on.
  await recording.presenceIssue('interval', clock + 100);
  await assert.rejects(recording.edit(page + 'x', 'typing', clock + 200));
  await recording.presenceRespond('approved', clock + 1500); clock += 2000;
  await recording.cut(1); await recording.presenceIssue('seal', clock); await recording.presenceRespond('approved', clock + 800);
  assert.equal((await recording.finish(clock + 900)).sealed, true);
  const { summary, recording: saved } = await recording.proveInput();
  assert.equal(summary.format, 'v3'); assert.equal(summary.tier, 1024); assert.equal(summary.text, page);
  assert.ok(summary.chunks.length >= 2);
  // Kept as exact text: its 64-bit integers would round as JavaScript numbers.
  assert.equal(typeof saved, 'string'); assert.ok(JSON.parse(saved).witness.session.signedCheckpoints.length > 2);
  const part = await recording.chunk(0);
  assert.equal(typeof part.input, 'string'); assert.equal(part.tier, 1024);
});

// The recorder as just built (frontend/write/build.mjs copies it into dist/write/recorder.wasm).
const BUILT = W + '../build/web-recorder-target/wasm32-unknown-unknown/release/huma_compact_experiment.wasm';
test('the server’s session nonce from Start becomes the page’s public nonce; a bad one is refused', { timeout: 60000,
  skip: !existsSync(BUILT) && 'Build the recorder first (cargo rustc … --target-dir build/web-recorder-target).' }, async () => {
  const call = await loadRecorder(await readFile(BUILT));
  const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign', 'verify']);
  for (const nonce of ['0'.repeat(32), 'ABCDEF0123456789ABCDEF0123456789', 'abc', 'zz' + '0'.repeat(30)]) await assert.rejects(Recording.start(call, pair, { nonce }), /Invalid session nonce/);
  const nonce = '00ff112233445566778899aabbccddee', recording = await Recording.start(call, pair, { nonce });
  const text = 'Started on the server’s clock. '.repeat(4);
  let page = '', clock = 0;
  for (const [i, c] of [...text].entries()) {
    clock += 150 + (i * 37) % 90;
    await recording.key('down', keyCode('KeyA'), 0, clock); page += c; await recording.edit(page, 'typing', clock + 5);
    await recording.key('up', keyCode('KeyA'), 0, clock + 60); clock += 60; await recording.checkpoint(clock);
    if (i % 40 === 39) await recording.cut(450);
  }
  await recording.presenceIssue('interval', clock + 100); await recording.presenceRespond('approved', clock + 1500); clock += 2000;
  await recording.cut(1); await recording.presenceIssue('seal', clock); await recording.presenceRespond('approved', clock + 800);
  assert.equal((await recording.finish(clock + 900)).sealed, true);
  const { summary } = await recording.proveInput();
  assert.equal(summary.final.nonce[0], BigInt('0x' + nonce).toString());
  // Without one the recorder still makes its own, as the Mac's sessions and older pages did.
  assert.ok(await Recording.start(call, pair));
});
