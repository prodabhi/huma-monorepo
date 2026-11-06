import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { LocalObjectStore } from '../object-store.mjs';
import { createRegistry } from '../registry.mjs';
import { verifyPublicationUpload } from '../publications.mjs';
import { createSessions, nonceHex, sessionClaim, clientAddress, networkOf, TIME_NOT_CONFIRMED, SESSION_LIFETIME } from '../sessions.mjs';

const hash = value => createHash('sha256').update(value).digest('hex');
const MINUTE = 60 * 1000;
const field = hex => BigInt('0x' + hex).toString();

async function store(t) {
  const directory = await mkdtemp(path.join(tmpdir(), 'huma-sessions-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  return new LocalObjectStore(directory);
}
const refused = error => error.status === 403 && error.message === TIME_NOT_CONFIRMED;

test('a page’s journal gives its session nonce as issued and the longer of its two writing times', () => {
  const hex = '00ff112233445566778899aabbccddee';
  assert.equal(nonceHex(field(hex)), hex);
  for (const bad of ['0', '-1', '01', (1n << 128n).toString(), 'x', 7, undefined]) assert.equal(nonceHex(bad), null, String(bad));
  assert.deepEqual(sessionClaim({ nonce: [field(hex), '5'], elapsed: '600000', start_unix: '1000', end_unix: '901000' }), { nonce: hex, claimed: 900000 });
  assert.deepEqual(sessionClaim({ nonce: [field(hex), '5'], elapsed: '1200000', start_unix: '1000', end_unix: '901000' }), { nonce: hex, claimed: 1200000 });
  assert.deepEqual(sessionClaim({ origin_present: 0 }), { nonce: null, claimed: Infinity }); // a journal without them can't pass
});

test('a nonce passes once real time covers the claimed writing time, for one proof, within a day', async t => {
  let now = Date.parse('2026-10-31T12:00:00Z');
  const sessions = createSessions({ objectStore: await store(t), now: () => now });
  const { nonce } = await sessions.issue('client'), issued = now;
  assert.match(nonce, /^[a-f0-9]{32}$/);
  // Thirty minutes claimed: refused before 29 minutes (a minute's slack) have passed, then accepted.
  now += 28 * MINUTE + 59000;
  await assert.rejects(sessions.confirm({ nonce, claimed: 30 * MINUTE }, 'proof-a'), refused);
  now += 1000;
  assert.equal(await sessions.confirm({ nonce, claimed: 30 * MINUTE }, 'proof-a'), issued);
  // The same proof may be shared again after a failed try; another proof with this nonce may not.
  assert.equal(await sessions.confirm({ nonce, claimed: 30 * MINUTE }, 'proof-a'), issued);
  await assert.rejects(sessions.confirm({ nonce, claimed: 0 }, 'proof-b'), refused);
  // Unknown, malformed or missing nonces are refused.
  for (const bad of [{ nonce: '1'.repeat(32), claimed: 0 }, { nonce: 'xyz', claimed: 0 }, { nonce: null, claimed: 0 }, {}])
    await assert.rejects(sessions.confirm(bad, 'proof-a'), refused);
  // A nonce over a day old is refused, even unused.
  const late = (await sessions.issue('client')).nonce;
  now += SESSION_LIFETIME;
  await assert.rejects(sessions.confirm({ nonce: late, claimed: 0 }, 'proof-c'), refused);
});

test('nonces are handed out at a modest rate, and old ones are dropped as their state is written', async t => {
  let now = Date.parse('2026-10-31T12:00:00Z');
  const objectStore = await store(t), sessions = createSessions({ objectStore, now: () => now });
  for (let i = 0; i < 30; i++) await sessions.issue('one');
  await assert.rejects(sessions.issue('one'), error => error.status === 429);
  await sessions.issue('another');
  now += 10 * MINUTE;
  await sessions.issue('one');
  // A day on, writing the first nonce's state drops it.
  const { nonce: old } = await sessions.issue('first'), oldHash = hash(old);
  const shardKey = 'sessions/' + hash('huma-sessions-v1\0' + parseInt(oldHash[0], 16));
  assert.ok(JSON.parse((await objectStore.quotaRead(shardKey)).bytes)[oldHash]);
  now += SESSION_LIFETIME + MINUTE;
  let fresh;
  for (let i = 0; i < 400 && !fresh; i++) {
    const { nonce } = await sessions.issue('c' + i);
    if (hash(nonce)[0] === oldHash[0]) fresh = hash(nonce);
  }
  const state = JSON.parse((await objectStore.quotaRead(shardKey)).bytes);
  assert.ok(state[fresh]); assert.equal(state[oldHash], undefined);
});

test('the address limited is Caddy’s forwarded client (never CF-Connecting-IP), an IPv6 /64 at a time', () => {
  const req = (remoteAddress, headers = {}) => ({ socket: { remoteAddress }, headers });
  assert.equal(clientAddress(req('127.0.0.1', { 'x-forwarded-for': '9.9.9.9, 203.0.113.7', 'cf-connecting-ip': '1.1.1.1' })), '203.0.113.7');
  assert.equal(clientAddress(req('198.51.100.2', { 'x-forwarded-for': '203.0.113.7', 'cf-connecting-ip': '1.1.1.1' })), '198.51.100.2');
  assert.equal(clientAddress(req('::1', { 'x-forwarded-for': '2001:db8:1:2:aaaa::1' })), clientAddress(req('::1', { 'x-forwarded-for': '2001:db8:1:2:bbbb::9' })));
  assert.equal(networkOf(clientAddress(req('::1', { 'x-forwarded-for': '2001:db8:1:2::1' }))), '2001:db8:1::/48');
  assert.equal(networkOf('203.0.113.7'), null);
});

test('one network can’t take every nonce: per /48, and past the overall budget newcomers still get a few', async t => {
  const now = Date.parse('2026-10-31T12:00:00Z');
  const sessions = createSessions({ objectStore: await store(t), now: () => now, limits: { overall: 121 } });
  // Four /64s of one /48 take 120 between them; a fifth /64 there waits, another network doesn't.
  for (const n of [1, 2, 3, 4]) for (let i = 0; i < 30; i++) await sessions.issue(`2001:db8:1:${n}::/64`);
  await assert.rejects(sessions.issue('2001:db8:1:5::/64'), error => error.status === 429);
  // The overall budget (121 here) is spent: an address that's had a few waits, a new one still starts.
  for (let i = 0; i < 3; i++) await sessions.issue('203.0.113.9');
  await assert.rejects(sessions.issue('203.0.113.9'), error => error.status === 429);
  assert.match((await sessions.issue('198.51.100.1')).nonce, /^[a-f0-9]{32}$/);
});

test('one client keeps only a few unused nonces, and a full shard drops its oldest rather than refuse', async t => {
  let now = Date.parse('2026-10-31T12:00:00Z');
  const objectStore = await store(t), sessions = createSessions({ objectStore, now: () => now, limits: { shards: 1, own: 3, shardLimit: 6 } });
  const shard = async () => JSON.parse((await objectStore.quotaRead('sessions/' + hash('huma-sessions-v1\0' + 0))).bytes);
  const tick = () => { now += 1000; };
  const others = [];
  for (let i = 0; i < 2; i++) { others.push((await sessions.issue('other-' + i)).nonce); tick(); }
  // A busy client: past 3 unused, its own oldest go, and nobody else's.
  const mine = [];
  for (let i = 0; i < 5; i++) { mine.push((await sessions.issue('busy')).nonce); tick(); }
  let state = await shard();
  assert.deepEqual(mine.map(n => Boolean(state[hash(n)])), [false, false, true, true, true]);
  assert.ok(others.every(n => state[hash(n)]));
  await assert.rejects(sessions.confirm({ nonce: mine[0], claimed: 0 }, 'p0'), refused);
  // Used: the first other client's page is shared.
  assert.equal(await sessions.confirm({ nonce: others[0], claimed: 0 }, 'p1'), Date.parse('2026-10-31T12:00:00Z'));
  // Full (6): a new client still gets a nonce; the used entry goes first, then the oldest unused.
  const late = [];
  for (let i = 0; i < 3; i++) { late.push((await sessions.issue('late-' + i)).nonce); tick(); }
  state = await shard();
  assert.equal(Object.keys(state).length, 6);
  assert.equal(state[hash(others[0])], undefined); // used, dropped first
  assert.equal(state[hash(others[1])], undefined); // then the oldest unused
  assert.ok(late.every(n => state[hash(n)]) && mine.slice(2).every(n => state[hash(n)]));
  // Stored per client: a salted hash, never the address.
  assert.ok(Object.values(state).every(entry => entry.used || /^[a-f0-9]{16}$/.test(entry.by)));
  assert.equal(JSON.stringify(state).includes('busy'), false);
});

// The real proof check, with the journal saying the page was written in a browser (origin_present 0) with `claim`.
async function running(t, clock, claim) {
  const directory = await mkdtemp(path.join(tmpdir(), 'huma-sessions-route-'));
  const server = await createRegistry({ store: directory, publicationOptions: {
    authenticate: async token => { if (token !== 'test-owner-session') throw Object.assign(new Error('Sign in required.'), { status: 401 }); return hash('test-owner'); },
    now: () => clock.now,
    verifyUpload: async source => {
      const checked = await verifyPublicationUpload(source);
      return claim.browser ? { ...checked, scoring: { ...checked.scoring, journal: { ...checked.scoring.journal, origin_present: 0,
        nonce: [claim.nonce ? field(claim.nonce) : '0', '0'], elapsed: String(claim.elapsed), start_unix: '1000', end_unix: '1000' } } } : checked;
    },
  } });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(async () => { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); await rm(directory, { recursive: true, force: true }); });
  const base = `http://127.0.0.1:${server.address().port}`;
  return (route, options) => fetch(base + route, options);
}
const proof = await readFile(new URL('../../extra/experiments/noir-compact/browser/test/fixtures/Long400V3.json', import.meta.url), 'utf8');
async function prepared(request) {
  const response = await request('/api/publications/prepare', { method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ kind: 'huma-publication-upload-v1', access: 'link', proof,
      master: { mediaType: 'text/plain;charset=utf-8', base64: Buffer.from(JSON.parse(proof).text).toString('base64') } }) });
  assert.equal(response.status, 201, await response.clone().text());
  return response.json();
}
const publish = (request, pending) => request('/api/publications/pending/' + pending.id + '/publish', { method: 'POST',
  headers: { Authorization: 'Bearer test-owner-session', 'X-Huma-Ticket': pending.ticket, 'Content-Type': 'application/json' }, body: '{}' });
const receipt = async (request, response) => {
  const [pathname, token] = (await response.json()).path.split('#');
  return (await request('/api/publications/' + pathname.slice('/original/'.length) + '/receipt', { headers: { Authorization: 'Bearer ' + token } })).json();
};

test('a browser page is shared only once real time since its session nonce covers its writing time', { timeout: 60000 }, async t => {
  const clock = { now: Date.parse('2026-10-31T12:00:00Z') }, claim = { browser: true, nonce: null, elapsed: 30 * MINUTE };
  const request = await running(t, clock, claim);
  // Start: a POST from this site gets a nonce; nothing else does.
  assert.equal((await request('/api/sessions')).status, 405);
  assert.equal((await request('/api/sessions', { method: 'POST', headers: { Origin: 'https://other.invalid' } })).status, 403);
  const issued = await request('/api/sessions', { method: 'POST' });
  assert.equal(issued.status, 200);
  const { nonce } = await issued.json(), start = clock.now;
  assert.match(nonce, /^[a-f0-9]{32}$/);
  // A nonce this server never issued.
  claim.nonce = 'ab'.repeat(16);
  let response = await publish(request, await prepared(request));
  assert.equal(response.status, 403); assert.equal((await response.json()).error, TIME_NOT_CONFIRMED);
  // Thirty minutes of writing claimed ten minutes after Start.
  claim.nonce = nonce; clock.now += 10 * MINUTE;
  response = await publish(request, await prepared(request));
  assert.equal(response.status, 403); assert.equal((await response.json()).error, TIME_NOT_CONFIRMED);
  // Thirty minutes on, it's shared, and its receipt says when the server started it.
  clock.now = start + 30 * MINUTE;
  response = await publish(request, await prepared(request));
  assert.equal(response.status, 200, await response.clone().text());
  assert.equal((await receipt(request, response)).serverStart, start);
});

test('Mac pages publish as before, with no session nonce and no serverStart', { timeout: 60000 }, async t => {
  const clock = { now: Date.parse('2026-10-31T12:00:00Z') };
  const request = await running(t, clock, { browser: false });
  const response = await publish(request, await prepared(request));
  assert.equal(response.status, 200, await response.clone().text());
  assert.equal('serverStart' in await receipt(request, response), false);
});
