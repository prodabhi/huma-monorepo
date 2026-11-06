import { fileURLToPath, pathToFileURL } from 'node:url';
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import path from 'node:path';
import { tmpdir } from 'node:os';
const W = fileURLToPath(new URL('../', import.meta.url));
const { createRegistry } = await import(pathToFileURL(W + 'registry.mjs').href);
const { publicationMessage } = await import(pathToFileURL(W + 'publications.mjs').href);
const { deviceAuthorizationMessage } = await import(pathToFileURL(W + 'publication-contract.mjs').href);
const { privateKeyToAccount } = await import(pathToFileURL(W + 'node_modules/viem/_esm/accounts/index.js').href);
const hash = b => createHash('sha256').update(b).digest('hex');

test('a sign-in code cannot be taken over and a Mac publication signature cannot be replayed', { timeout: 90000 }, async t => {
  const victimWallet = privateKeyToAccount('0x' + '22'.repeat(32)), attackerWallet = privateKeyToAccount('0x' + '33'.repeat(32));
  const users = { victim: { owner: hash('victim'), wallets: [victimWallet.address], account: 'victim@example.com' },
                  attacker: { owner: hash('attacker'), wallets: [attackerWallet.address], account: 'attacker@example.com' } };
  const directory = await mkdtemp(path.join(tmpdir(), 'huma-audit-'));
  const server = await createRegistry({ store: directory, publicationOptions: {
    authenticate: async token => { if (!users[token]) throw Object.assign(new Error('x'), { status: 401 }); return users[token]; } } });
  await new Promise(r => server.listen(0, '127.0.0.1', r));
  t.after(async () => { server.closeAllConnections(); await new Promise(r => server.close(r)); await rm(directory, { recursive: true, force: true }); });
  const base = `http://127.0.0.1:${server.address().port}`, request = (p, o) => fetch(base + p, o);
  // Victim links their Mac.
  const { publicKey: ko, privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const jwk = ko.export({ format: 'jwk' }), publicKey = '04' + Buffer.from(jwk.x, 'base64url').toString('hex') + Buffer.from(jwk.y, 'base64url').toString('hex');
  const signin = (who, code, body) => request('/api/publications/signin', { method: 'POST', headers: { Authorization: 'Bearer ' + who, 'X-Huma-Signin': code, 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
  const code = 'e'.repeat(64);
  assert.equal((await signin('victim', code, { wallet: victimWallet.address, publicKey, signature: await victimWallet.signMessage({ message: deviceAuthorizationMessage(victimWallet.address, publicKey) }) })).status, 200);
  // Someone who sees the code can't swap the account the Mac links to: the first sign-in wins.
  assert.equal((await signin('attacker', code, {})).status, 409);
  const polled = await (await request('/api/publications/signin', { headers: { 'X-Huma-Signin': code } })).json();
  assert.equal(polled.wallet, victimWallet.address);
  // Victim publishes a LINK-only page from the Mac.
  const proof = await readFile(W + '../extra/experiments/noir-compact/browser/test/fixtures/Long400V2.json', 'utf8'), text = JSON.parse(proof).text;
  const up = access => JSON.stringify({ kind: 'huma-publication-upload-v1', access, proof, master: { mediaType: 'text/plain;charset=utf-8', base64: Buffer.from(text).toString('base64') } });
  const prep = async access => (await request('/api/publications/prepare', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: up(access) })).json();
  const p1 = await prep('link');
  const { manifest } = await (await request('/api/publications/pending/' + p1.id, { headers: { Authorization: 'Bearer ' + p1.ticket } })).json();
  const sig = sign('sha256', Buffer.from(publicationMessage(manifest)), privateKey).toString('base64');
  const devicePublish = (p, s) => request('/api/publications/pending/' + p.id + '/publish-device', { method: 'POST', headers: { 'X-Huma-Ticket': p.ticket, 'Content-Type': 'application/json' }, body: JSON.stringify({ wallet: victimWallet.address, publicKey, signature: s }) });
  const r1 = await devicePublish(p1, sig); assert.equal(r1.status, 200);
  const [id1, token] = (await r1.json()).path.slice('/original/'.length).split('#');
  // A link recipient reads the receipt (owner.device.signature is in it) and republishes as PUBLIC, no sign-in.
  const { owner } = await (await request('/api/publications/' + id1 + '/receipt', { headers: { Authorization: 'Bearer ' + token } })).json();
  const p2 = await prep('public');
  // A link recipient can read the receipt's device signature, but it can't publish the page again or make it public.
  assert.equal((await devicePublish(p2, owner.device.signature)).status, 403);
  const p3 = await prep('link');
  assert.equal((await devicePublish(p3, owner.device.signature)).status, 403);
});

test('every response carries HSTS and a permissions policy, and the CSP allows no outside connections', async t => {
  const directory = await mkdtemp(path.join(tmpdir(), 'huma-audit-'));
  const server = await createRegistry({ store: directory });
  await new Promise(r => server.listen(0, '127.0.0.1', r));
  t.after(async () => { server.closeAllConnections(); await new Promise(r => server.close(r)); await rm(directory, { recursive: true, force: true }); });
  for (const route of ['/verify', '/download', '/api/publication-config', '/nope']) {
    const response = await fetch(`http://127.0.0.1:${server.address().port}${route}`);
    assert.equal(response.headers.get('strict-transport-security'), 'max-age=31536000', route);
    assert.match(response.headers.get('permissions-policy') ?? '', /camera=\(\)/, route);
    assert.ok(!/base\.org/.test(response.headers.get('content-security-policy') ?? ''), route);
  }
});
