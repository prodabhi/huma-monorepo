import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { createHash } from 'node:crypto';
import { mkdtemp, readdir, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { S3Client } from '@aws-sdk/client-s3';
import { LocalObjectStore, R2ObjectStore } from '../object-store.mjs';
import { PublicationQuotas, publicationLimits } from '../upload-quotas.mjs';

const hash = value => createHash('sha256').update(String(value)).digest('hex');
const policy = { globalCount: 3, globalBytes: 200, uploaderCount: 2, uploaderBytes: 100 };
const request = (id, owner, bytes) => ({ id: hash(id), owner: hash(owner), bytes });
async function local(t) {
  const directory = await mkdtemp(path.join(tmpdir(), 'huma-quotas-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  return directory;
}

test('global/uploader byte and count allowances survive restart and retries preserve their day', async t => {
  const directory = await local(t); let time = Date.parse('2026-10-23T23:59:00Z');
  const quota = () => new PublicationQuotas(new LocalObjectStore(directory), { limits: policy, now: () => time });
  await quota().reserve(request('a', 'alice', 60));
  await assert.rejects(quota().reserve(request('b', 'alice', 50)), { status: 429 });
  await quota().reserve(request('b', 'alice', 40));
  await assert.rejects(quota().reserve(request('c', 'alice', 1)), { status: 429 });
  await quota().reserve(request('c', 'bob', 100));
  await assert.rejects(quota().reserve(request('d', 'charlie', 1)), { status: 429 });
  await quota().reserve(request('a', 'alice', 60)); // Re-created service, same grant: no extra charge.
  await assert.rejects(quota().reserve(request('a', 'alice', 61)), { status: 503 });
  await assert.rejects(quota().reserve(request('a', 'other-owner', 60)), { status: 503 });
  time += 2 * 60 * 1000;
  await quota().reserve(request('next-day', 'alice', 100));
  await quota().reserve({ ...request('a', 'alice', 60), day: '2026-10-23' }); // Existing retry stays in original window.
  await assert.rejects(quota().reserve(request('new', 'alice', 1)), { status: 429 });
  const files = await readdir(path.join(directory, 'quotas'));
  assert.equal(files.length, 2); // Both UTC windows persist, without lock/temp files.
});

test('independent local service instances cannot oversubscribe a shared allowance', async t => {
  const directory = await local(t), limits = { ...policy, globalBytes: 1000, uploaderBytes: 1000, uploaderCount: 3 };
  const quotas = [0, 1].map(() => new PublicationQuotas(new LocalObjectStore(directory), { limits }));
  const outcomes = await Promise.allSettled(Array.from({ length: 8 }, (_, i) => quotas[i % 2].reserve(request('concurrent-' + i, 'same-owner', 10))));
  assert.equal(outcomes.filter(r => r.status === 'fulfilled').length, 3);
  for (const result of outcomes.filter(r => r.status === 'rejected')) assert.equal(result.reason.status, 429);
  const file = (await readdir(path.join(directory, 'quotas')))[0];
  assert.equal(JSON.parse(await readFile(path.join(directory, 'quotas', file))).reservations.length, 3);
});

test('corrupt state, abandoned local lock and invalid configuration fail closed', async t => {
  const directory = await local(t), store = new LocalObjectStore(directory), quota = new PublicationQuotas(store, { limits: policy });
  await quota.reserve(request('a', 'alice', 1));
  const file = path.join(directory, 'quotas', (await readdir(path.join(directory, 'quotas')))[0]), original = await readFile(file);
  await writeFile(file, '{broken');
  await assert.rejects(quota.reserve(request('b', 'bob', 1)), { status: 503 });
  assert.equal(await readFile(file, 'utf8'), '{broken');
  await writeFile(file, original); await writeFile(file + '.lock', 'abandoned-fixture-lock');
  await assert.rejects(quota.reserve(request('b', 'bob', 1)), { status: 503 });
  assert.deepEqual(await readFile(file), original);
  assert.equal((await readdir(path.join(directory, 'quotas'))).filter(name => name.includes('.tmp-')).length, 0);
  for (const value of ['', '0', '-1', '1.5', 'Infinity', '2001']) assert.throws(() => publicationLimits({ HUMA_DAILY_PUBLICATION_LIMIT: value }));
});

test('official S3 transport uses conditional ETags for competing R2 quota writers', { timeout: 15000 }, async t => {
  const states = new Map(), clients = [], conditions = []; let conflicts = 0, initialReads = 0, unblock;
  const firstReads = new Promise(resolve => { unblock = resolve; });
  const server = http.createServer(async (req, res) => {
    assert.match(req.headers.authorization, /Credential=quota-test-access\/[0-9]{8}\/auto\/s3\/aws4_request/);
    const key = new URL(req.url, 'http://localhost').pathname;
    if (req.method === 'GET') {
      if (initialReads < 2) { initialReads++; if (initialReads === 2) unblock(); await firstReads; }
      const value = states.get(key);
      if (!value) { res.writeHead(404, { 'Content-Type': 'application/xml' }); res.end('<Error><Code>NoSuchKey</Code></Error>'); }
      else { res.writeHead(200, { ETag: value.version, 'Content-Length': value.bytes.length }); res.end(value.bytes); }
      return;
    }
    const chunks = []; for await (const chunk of req) chunks.push(chunk);
    const value = states.get(key), version = req.headers['if-match'];
    conditions.push({ absent: req.headers['if-none-match'], version });
    if ((req.headers['if-none-match'] === '*' && value) || (version && version !== value?.version)) {
      conflicts++; res.writeHead(412, { 'Content-Type': 'application/xml' }); res.end('<Error><Code>PreconditionFailed</Code></Error>'); return;
    }
    const bytes = Buffer.concat(chunks), etag = '"' + hash(bytes) + '"';
    states.set(key, { bytes, version: etag }); res.writeHead(200, { ETag: etag }); res.end();
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(async () => { for (const client of clients) client.destroy(); server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); });
  function quota() {
    const client = new S3Client({ endpoint: `http://127.0.0.1:${server.address().port}`, region: 'auto', forcePathStyle: true, maxAttempts: 1,
      credentials: { accessKeyId: 'quota-test-access', secretAccessKey: 'quota-test-secret' }, requestChecksumCalculation: 'WHEN_REQUIRED', responseChecksumValidation: 'WHEN_REQUIRED' });
    clients.push(client);
    return new PublicationQuotas(new R2ObjectStore({ bucket: 'test-quota', client }), { limits: { ...policy, globalCount: 2, uploaderCount: 2 } });
  }
  await Promise.all([quota().reserve(request('a', 'alice', 80)), quota().reserve(request('b', 'bob', 90))]);
  await assert.rejects(quota().reserve(request('c', 'charlie', 1)), { status: 429 });
  await quota().reserve(request('a', 'alice', 80));
  assert.equal(states.size, 1);
  assert.equal(JSON.parse([...states.values()][0].bytes).reservations.length, 2);
  assert.ok(conflicts > 0); assert.ok(conditions.some(c => c.version)); assert.ok(conditions.some(c => c.absent === '*'));
});
