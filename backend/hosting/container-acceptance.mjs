// Runs INSIDE a disposable, network-none test container. Never packaged for hosting.
import assert from 'node:assert/strict';
import http from 'node:http';
import { createHash } from 'node:crypto';
import { S3Client } from '@aws-sdk/client-s3';
import { R2ObjectStore } from './web/object-store.mjs';
import { createRegistry } from './web/registry.mjs';
import { checkDownloadedPublication, expectedMaster } from './web/publication-contract.mjs';
import { verify } from './web/verify-core/node.mjs';
import { shareAssetFiles } from './web/share-assets.mjs';

const chunks = []; for await (const chunk of process.stdin) chunks.push(chunk);
const fixtures = JSON.parse(Buffer.concat(chunks)).fixtures;
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const objects = new Map(); let signedRequests = 0;
const s3 = http.createServer(async (req, res) => {
  const key = new URL(req.url, 'http://localhost').pathname.slice('/fixture-bucket/'.length);
  if (!req.headers.authorization?.startsWith('AWS4-HMAC-SHA256 ')) { res.writeHead(403); res.end(); return; }
  signedRequests++;
  const old = objects.get(key), etag = old ? '"' + hash(old) + '"' : undefined;
  if (req.method === 'GET' && old) { res.writeHead(200, { ETag: etag, 'Content-Length': old.length }); res.end(old); }
  else if (req.method === 'GET') { res.writeHead(404, { 'Content-Type': 'application/xml' }); res.end('<Error><Code>NoSuchKey</Code></Error>'); }
  else if (req.method === 'PUT') {
    if ((req.headers['if-none-match'] === '*' && old) || (req.headers['if-match'] && req.headers['if-match'] !== etag)) {
      res.writeHead(412, { 'Content-Type': 'application/xml' }); res.end('<Error><Code>PreconditionFailed</Code></Error>'); return;
    }
    const body = []; for await (const chunk of req) body.push(chunk);
    const bytes = Buffer.concat(body); objects.set(key, bytes);
    res.writeHead(200, { ETag: '"' + hash(bytes) + '"' }); res.end();
  } else { res.writeHead(405); res.end(); }
});
await new Promise(resolve => s3.listen(0, '127.0.0.1', resolve));
const objectStore = new R2ObjectStore({ bucket: 'fixture-bucket', client: new S3Client({
  endpoint: 'http://127.0.0.1:' + s3.address().port, region: 'auto', forcePathStyle: true, maxAttempts: 1,
  credentials: { accessKeyId: 'fixture-access-id', secretAccessKey: 'fixture-secret-value' },
  requestChecksumCalculation: 'WHEN_REQUIRED', responseChecksumValidation: 'WHEN_REQUIRED',
}) });
const server = await createRegistry({ store: '/app/web/data', publicationOptions: { objectStore,
  authenticate: async token => {
    if (token !== 'fixture-owner') throw Object.assign(Error('Fixture authorization required.'), { status: 401 });
    return hash('fixture-owner');
  },
} });
const reports = []; let last;
try {
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const base = 'http://127.0.0.1:' + server.address().port;
  const request = (route, options) => fetch(base + route, options);
  assert.equal((await request('/api/proofs', { method: 'POST', body: '{}' })).status, 410);
  for (const name of (await shareAssetFiles('/app/web')).filter(name => name.startsWith('assets/'))) {
    assert.equal((await request('/share/' + name)).status, 200, name);
  }
  for (const fixture of fixtures) {
    const master = Buffer.from(fixture.master, 'base64'), before = objects.size;
    const body = JSON.stringify({ kind: 'huma-publication-upload-v1', access: 'link', proof: fixture.proof,
      master: { mediaType: fixture.mediaType, base64: fixture.master } });
    const prepared = await request('/api/publications/prepare', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body });
    assert.equal(prepared.status, 201, fixture.name);
    const pending = await prepared.json(); assert.equal(pending.storage, 'r2');
    assert.equal(objects.size, before);
    const approve = token => request('/api/publications/pending/' + pending.id + '/publish', { method: 'POST',
      headers: { Authorization: 'Bearer ' + token, 'X-Huma-Ticket': pending.ticket } });
    assert.equal((await approve('invalid-owner')).status, 401); assert.equal(objects.size, before);
    const accepted = await approve('fixture-owner'); assert.equal(accepted.status, 200);
    const result = await accepted.json(), [pathname, token] = result.path.split('#');
    const id = pathname.slice('/original/'.length), headers = { Authorization: 'Bearer ' + token };
    assert.equal((await request('/api/publications/' + id + '/master')).status, 404);
    const source = await (await request('/api/publications/' + id, { headers })).text();
    const downloaded = new Uint8Array(await (await request('/api/publications/' + id + '/master', { headers })).arrayBuffer());
    const proof = new Uint8Array(await (await request('/api/publications/' + id + '/proof', { headers })).arrayBuffer());
    const manifest = await checkDownloadedPublication(source, id, downloaded, proof);
    assert.deepEqual(Buffer.from(downloaded), master);
    const report = await verify(new TextDecoder().decode(proof), {}, expectedMaster(manifest, downloaded));
    assert.equal(report.verified, true); assert.equal(report.statementHash, manifest.statementHash);
    if (fixture.checkpointSignatures !== undefined) assert.equal(report.proofReport.signaturesVerified, fixture.checkpointSignatures);
    const altered = downloaded.slice(); altered[0] ^= 1;
    await assert.rejects(checkDownloadedPublication(source, id, altered, proof));
    assert.equal((await (await approve('fixture-owner')).json()).path, result.path);
    reports.push({ name: fixture.name, verified: true, contentKind: report.statement.contentKind,
      exactMaster: true, approvalRequired: true, privateLink: true, tamperRejected: true,
      checkpointSignatures: report.proofReport.signaturesVerified });
    last = { manifest, id, headers };
  }
  objects.set('objects/' + last.manifest.master.hash, Buffer.from('swapped'));
  assert.equal((await request('/api/publications/' + last.id + '/master', { headers: last.headers })).status, 400);
  assert.ok([...objects.keys()].some(key => key.startsWith('quotas/'))); assert.ok(signedRequests > 20);
  console.log(JSON.stringify({ passed: true, platform: process.platform, architecture: process.arch, uid: process.getuid(),
    node: process.version, fixtureOnly: true, newProofGenerated: false, realR2Accepted: false,
    signedS3Requests: signedRequests, cases: reports }));
} finally {
  server.closeAllConnections(); await new Promise(resolve => server.close(resolve));
  s3.closeAllConnections(); await new Promise(resolve => s3.close(resolve));
}
