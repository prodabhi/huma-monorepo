import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { createRegistry } from '../registry.mjs';
import { configuredWorldID, WORLD_ID_UNCONFIGURED } from '../worldid-verify.mjs';

// A production host without its World ID keys never falls back to sharing without the human check: it refuses every
// share (web and Mac alike), says so to the write page at Start and to the Mac before recording, and logs it.
const hash = value => createHash('sha256').update(value).digest('hex');
const proof = await readFile(new URL('../../extra/experiments/noir-compact/browser/test/fixtures/Long400V3.json', import.meta.url), 'utf8');

test('without World ID keys, a production host says so and shares nothing', { timeout: 60000 }, async t => {
  const missing = configuredWorldID({ NODE_ENV: 'production' });
  assert.equal(missing.enabled, false); assert.equal(missing.missing, true); assert.equal(missing.required, false);
  assert.equal(configuredWorldID({ NODE_ENV: 'production', HUMA_WORLD_OPTIONAL: 'true' }).missing, false);
  assert.equal(configuredWorldID({}).missing, false); // development and tests run without it
  const directory = await mkdtemp(path.join(tmpdir(), 'huma-worldid-missing-'));
  const server = await createRegistry({ store: directory, publicationOptions: { worldId: missing,
    authenticate: async () => hash('owner') } });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(async () => { server.streams.close(); server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); await rm(directory, { recursive: true, force: true }); });
  const base = `http://127.0.0.1:${server.address().port}`;
  // What both clients ask first.
  assert.deepEqual(await (await fetch(base + '/api/worldid')).json(), { appId: null, rpId: null, action: null, environment: null, required: false, missing: true });
  // A Mac page (the fixture) through prepare and publish: refused at publish, before anything is stored.
  const prepared = await fetch(base + '/api/publications/prepare', { method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ kind: 'huma-publication-upload-v1', access: 'link', proof, master: { mediaType: 'text/plain;charset=utf-8', base64: Buffer.from(JSON.parse(proof).text).toString('base64') } }) });
  assert.equal(prepared.status, 201);
  const ticket = await prepared.json();
  const published = await fetch(base + '/api/publications/pending/' + ticket.id + '/publish', { method: 'POST',
    headers: { Authorization: 'Bearer any', 'X-Huma-Ticket': ticket.ticket, 'Content-Type': 'application/json' }, body: '{}' });
  assert.equal(published.status, 503); assert.equal((await published.json()).error, WORLD_ID_UNCONFIGURED);
});
