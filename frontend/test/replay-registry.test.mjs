import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { once } from 'node:events';
import { createHash } from 'node:crypto';
import { readFile, mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { createRegistry, MAX_UPLOAD_BYTES } from '../registry.mjs';

const hash = bytes => createHash('sha256').update(bytes).digest('hex');

test('real replay receipt publishes only verified public fields and round trips by content hash', { timeout: 60000 }, async t => {
    const store = await mkdtemp(path.join(tmpdir(), 'huma-registry-'));
    const server = await createRegistry({ store, allowLegacyUploads: true });
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    t.after(async () => { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); await rm(store, { recursive: true, force: true }); });
    const base = `http://127.0.0.1:${server.address().port}`;
    const source = await readFile(new URL('../../backend/zkvm/verifier/tests/fixtures/timed-receipt.json', import.meta.url), 'utf8');
    const record = JSON.parse(source);
    const upload = value => fetch(base + '/api/proofs', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: typeof value === 'string' ? value : JSON.stringify(value) });
    const privateMarker = 'PRIVATE-HISTORY-MUST-NEVER-PUBLISH';
    const polluted = structuredClone(record);
    const addMetadata = value => {
        if (Array.isArray(value)) value.forEach(addMetadata);
        else if (value && typeof value === 'object') {
            Object.values(value).forEach(addMetadata);
            if (!Object.keys(value).some(key => ['Value', 'Pruned', 'Succinct', 'Halted', 'Paused', 'SystemSplit'].includes(key))) value.privateHistory = privateMarker;
        }
    };
    addMetadata(polluted);
    polluted.session = { privateHistory: privateMarker };
    polluted.capturePublicKey = { privateHistory: privateMarker };
    const response = await upload(polluted);
    assert.equal(response.status, 201, await response.clone().text());
    const { id } = await response.json();
    const received = await (await fetch(base + '/api/proofs/' + id)).text();
    assert.equal(hash(received), id);
    assert.equal(received.includes(privateMarker), false);
    assert.deepEqual(JSON.parse(received), record);
    assert.equal(await readFile(path.join(store, id + '.json'), 'utf8'), received);
    const duplicate = await upload(record);
    assert.equal(duplicate.status, 201);
    assert.equal((await duplicate.json()).id, id);
    const page = await fetch(base + '/verify/' + id);
    assert.equal(page.status, 200);
    for (const route of ['/', '/verify', '/download', '/prove-you-didnt-use-ai', '/ai-detector-false-positive']) assert.equal((await fetch(base + route)).headers.get('content-type'), 'text/html');
    // What search engines and AI assistants read: the rules, the map of pages and the plain summary.
    assert.match(await (await fetch(base + '/robots.txt')).text(), /Sitemap: https:\/\/huma\.social\/sitemap\.xml/);
    assert.match(await (await fetch(base + '/sitemap.xml')).text(), /<loc>https:\/\/huma\.social\/prove-you-didnt-use-ai<\/loc>/);
    assert.match(await (await fetch(base + '/llms.txt')).text(), /^# Huma\n/);
    assert.equal((await fetch(base + '/deck', { redirect: 'manual' })).headers.get('location'), '/deck/');
    for (const escape of ['/deck/..%2fpackage.json', '/deck/..%2f..%2fREADME.md', '/deck/%2e%2e%2fregistry.mjs']) assert.equal((await fetch(base + escape)).status, 404);
    for (const asset of ['/site.css', '/verify.js', '/device-verifier.js', '/replay-worker.js', '/replay/huma_replay_browser.js', '/replay/huma_replay_browser_bg.wasm']) assert.equal((await fetch(base + asset)).status, 200);
    for (const asset of ['/compact/compact-verifier.js', '/compact/compact-worker.js', '/compact/assets/cast256.vk', '/compact/assets/g2.dat', '/compact/assets/barretenberg.wasm']) assert.equal((await fetch(base + asset)).status, 200);
    assert.equal((await fetch(base + '/compact/assets/barretenberg.wasm')).headers.get('content-type'), 'application/wasm');
    for (const hidden of ['/compact/core.mjs', '/compact/private.json', '/compact/..%2f..%2fexperiments/noir-compact/browser/core.mjs']) assert.equal((await fetch(base + hidden)).status, 404);
    assert.equal((await upload({ text: record.text, bundle: { system: 'groth16' } })).status, 422);
    assert.equal((await fetch(base + '/snarkjs.min.js')).status, 404);
    assert.equal((await upload({ ...record, text: record.text + '!' })).status, 422);
    const fake = structuredClone(record); fake.bundle.receipt.inner = { Fake: { claim: fake.bundle.receipt.inner.Succinct.claim } };
    assert.equal((await upload(fake)).status, 422);
    const badPin = structuredClone(record); badPin.bundle.imageId = '0'.repeat(64);
    assert.equal((await upload(badPin)).status, 422);
    for (let attempt = 0; attempt < 3; attempt++) assert.equal((await upload('x'.repeat(MAX_UPLOAD_BYTES + 1))).status, 413);
    const chunked = await fetch(base + '/api/proofs', { method: 'POST', headers: { 'Content-Type': 'application/json' }, duplex: 'half',
        body: new ReadableStream({ start(controller) { controller.enqueue(new Uint8Array(MAX_UPLOAD_BYTES)); controller.enqueue(new Uint8Array(1)); controller.close(); } }) });
    assert.equal(chunked.status, 413);
    assert.equal((await fetch(base + '/api/proofs/' + '0'.repeat(64))).status, 404);
});

test('two incomplete uploads reserve admission before body verification', { timeout: 15000 }, async t => {
    const store = await mkdtemp(path.join(tmpdir(), 'huma-admission-'));
    const server = await createRegistry({ store, allowLegacyUploads: true });
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    const held = [];
    t.after(async () => { held.forEach(req => req.destroy()); server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); await rm(store, { recursive: true, force: true }); });
    const base = `http://127.0.0.1:${server.address().port}`;
    for (let i = 0; i < 2; i++) {
        const admitted = once(server, 'request');
        const req = http.request(base + '/api/proofs', { method: 'POST', headers: { 'Content-Type': 'application/json' } });
        req.on('error', () => {}); req.write('{'); held.push(req); await admitted;
    }
    const response = await fetch(base + '/api/proofs', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' });
    assert.equal(response.status, 429);
});
