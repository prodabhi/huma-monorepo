import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, randomBytes, sign } from 'node:crypto';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { LocalObjectStore } from '../object-store.mjs';
import { createRegistry } from '../registry.mjs';
import { deviceOwnerKey, writerPage } from '../documents.mjs';
import { verifyPublicationUpload, verifiedScore } from '../publications.mjs';
import { documentRequestMessage, publicationMessage, listedMessage, titleMessage, removalMessage, writerHandle, writerLevel, writerProfile, SHORT_LINK } from '../publication-contract.mjs';

const hash = value => createHash('sha256').update(value).digest('hex');
const wallet = '0x' + '1'.repeat(40);
const { proof, text } = await readFile(new URL('../../extra/experiments/noir-compact/browser/test/fixtures/Long400V3.json', import.meta.url), 'utf8')
  .then(source => ({ proof: source, text: JSON.parse(source).text }));
const upload = (access = 'link') => JSON.stringify({ kind: 'huma-publication-upload-v1', access, proof, master: { mediaType: 'text/plain;charset=utf-8', base64: Buffer.from(text).toString('base64') } });
// The real verifier once (a Mac page: 7 of 7 checks, Touch ID 1 of 2, no replay: 67); each upload then gets its own nonce.
const verified = await verifyPublicationUpload(upload());

// A browser page starts with this server's session nonce (sessions.mjs), and claims no writing time yet.
const started = async base => ({ nonce: [BigInt('0x' + (await (await fetch(base + '/api/sessions', { method: 'POST' })).json()).nonce).toString(), '0'],
  elapsed: '0', start_unix: '0', end_unix: '0' });
async function running(t, scoring = () => verified.scoring) {
  const directory = await mkdtemp(path.join(tmpdir(), 'huma-writers-'));
  let base;
  const server = await createRegistry({ store: directory, publicationOptions: { verifyUpload: async source => {
    const value = structuredClone(verified);
    Object.assign(value.manifest, { publicationNonce: randomBytes(32).toString('hex'), access: JSON.parse(source).access });
    const scored = scoring();
    return { ...value, scoring: scored?.journal?.origin_present === 0 ? { ...scored, journal: { ...scored.journal, ...await started(base) } } : scored };
  } } });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(async () => { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); await rm(directory, { recursive: true, force: true }); });
  base = `http://127.0.0.1:${server.address().port}`;
  return { request: (route, options) => fetch(base + route, options), store: new LocalObjectStore(path.join(directory, 'publications')) };
}
/** A browser linked to `owner`: it signs document requests and publishes and lists pages with the same key. */
async function writer({ request, store }, owner) {
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const raw = publicKey.export({ format: 'jwk' }), point = '04' + Buffer.from(raw.x, 'base64url').toString('hex') + Buffer.from(raw.y, 'base64url').toString('hex');
  await store.put(deviceOwnerKey(point), Buffer.from(JSON.stringify({ owner, wallet })));
  await store.put('devices/' + hash('huma-device-v1\0' + point + '\0' + wallet), Buffer.from(JSON.stringify({ wallet, owner, publicKey: point,
    authorization: { message: 'authorized', signature: '0x' } })));
  const signed = message => sign('sha256', Buffer.from(message), privateKey).toString('base64');
  const headers = (method, pathname, body = '') => { const time = Date.now(); return { 'Content-Type': 'application/json', 'X-Huma-Key': point, 'X-Huma-Time': String(time),
    'X-Huma-Signature': signed(documentRequestMessage(method, pathname, time, hash(body))) }; };
  const route = '/api/documents/profile';
  return { point, signed,
    profile: value => { const body = JSON.stringify(value); return request(route, { method: 'POST', headers: headers('POST', route, body), body }); },
    readProfile: async () => (await (await request(route, { headers: headers('GET', route) })).json()).profile,
    publish: async (extra = {}, access = 'link') => {
      const pending = await (await request('/api/publications/prepare', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: upload(access) })).json();
      const { manifest } = await (await request('/api/publications/pending/' + pending.id, { headers: { Authorization: 'Bearer ' + pending.ticket } })).json();
      return request('/api/publications/pending/' + pending.id + '/publish-device', { method: 'POST', headers: { 'X-Huma-Ticket': pending.ticket, 'Content-Type': 'application/json' },
        body: JSON.stringify({ wallet, publicKey: point, signature: signed(publicationMessage(manifest)), profile: { name: 'Ada', avatar: 'ada-1' }, ...extra }) });
    },
    listed: (id, listed, { time = Date.now(), signature = signed(listedMessage(id, listed, time)), key = point } = {}) => request('/api/publications/' + id + '/listed', { method: 'POST',
      headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ publicKey: key, listed, time, signature }) }),
  };
}
const page = async response => { assert.equal(response.status, 200, await response.clone().text()); const [id, token] = (await response.json()).path.slice('/original/'.length).split('#'); return { id, token }; };

test('handles are checked, reserved words refused, and taken handles turned away', () => {
  assert.equal(writerHandle(' Ada_L '), 'ada_l');
  for (const bad of ['ab', 'a'.repeat(21), 'ada!', 'ada l', 'write', 'API', 'p', 'signin', '', null, 7])
    assert.throws(() => writerHandle(bad), error => error.status === 400 && /3 to 20/.test(error.message), String(bad));
  assert.deepEqual(writerProfile({ name: 'Ada', avatar: 'a1' }), { name: 'Ada', avatar: 'a1' }); // the Mac's profiles have none
  assert.deepEqual(writerProfile({ name: 'Ada', avatar: 'a1', handle: 'Ada_L' }), { name: 'Ada', avatar: 'a1', handle: 'ada_l' });
  assert.throws(() => writerProfile({ name: 'Ada', avatar: 'a1', handle: 'admin' }), /3 to 20/);
  // Words that would pass for the site or its staff.
  for (const bad of ['staff', 'Security', 'moderator', 'official', 'humasocial', 'huma_official', 'root', 'system', 'null', 'undefined', 'everyone', 'all', 'you'])
    assert.throws(() => writerHandle(bad), /3 to 20/, bad);
});

test('racing profile saves leave the account holding only the handle its profile shows', async t => {
  const server = await running(t), me = await writer(server, hash('me')), them = await writer(server, hash('them'));
  const handles = ['race_a', 'race_b', 'race_c', 'race_d', 'race_e', 'race_f'];
  const statuses = await Promise.all(handles.map(handle => me.profile({ name: 'Ada', avatar: 'ada-1', handle }).then(r => r.status)));
  assert.ok(statuses.includes(200) && statuses.every(status => status === 200 || status === 409), String(statuses));
  const { handle: kept } = await me.readProfile();
  assert.ok(handles.includes(kept));
  assert.equal((await server.request('/api/writers/' + kept)).status, 200);
  // Every other handle is free: another writer can take each in turn.
  for (const handle of handles.filter(h => h !== kept)) {
    assert.equal((await server.request('/api/writers/' + handle)).status, 404, handle);
    assert.equal((await them.profile({ name: 'Bo', avatar: 'bo-1', handle })).status, 200, handle);
  }
  assert.equal((await them.profile({ name: 'Bo', avatar: 'bo-1', handle: kept })).status, 409);
  // The same save sent twice at once is still one writer's handle.
  const twice = await Promise.all([1, 2].map(() => me.profile({ name: 'Ada', avatar: 'ada-1', handle: 'twice' }).then(r => r.status)));
  assert.ok(twice.includes(200), String(twice));
  assert.equal((await me.readProfile()).handle, 'twice');
  assert.equal((await (await server.request('/api/writers/twice')).json()).profile.name, 'Ada');
});

test('a writer claims one handle; changing or clearing it lets the old one go', async t => {
  const server = await running(t), me = await writer(server, hash('me')), them = await writer(server, hash('them'));
  assert.equal((await me.profile({ name: 'Ada', avatar: 'ada-1', handle: 'Ada' })).status, 200);
  assert.deepEqual(await me.readProfile(), { name: 'Ada', avatar: 'ada-1', handle: 'ada' });
  const taken = await them.profile({ name: 'Bo', avatar: 'bo-1', handle: 'ada' });
  assert.equal(taken.status, 409); assert.equal((await taken.json()).error, 'That handle is taken.');
  for (const handle of ['ab', 'verify', 'no spaces']) assert.equal((await them.profile({ name: 'Bo', avatar: 'bo-1', handle })).status, 400, handle);
  // A profile sent without a handle keeps it; the same handle again is still this writer's.
  assert.equal((await me.profile({ name: 'Ada L', avatar: 'ada-2' })).status, 200);
  assert.deepEqual(await me.readProfile(), { name: 'Ada L', avatar: 'ada-2', handle: 'ada' });
  assert.equal((await me.profile({ name: 'Ada L', avatar: 'ada-2', handle: 'ada' })).status, 200);
  assert.equal((await server.request('/api/writers/ada')).status, 200);
  // A new handle releases the old one, which another writer can then take.
  assert.equal((await me.profile({ name: 'Ada L', avatar: 'ada-2', handle: 'ada_l' })).status, 200);
  const gone = await server.request('/api/writers/ada');
  assert.equal(gone.status, 404); assert.deepEqual(await gone.json(), { error: 'No writer with that handle.' });
  assert.equal((await them.profile({ name: 'Bo', avatar: 'bo-1', handle: 'ada' })).status, 200);
  assert.equal((await (await server.request('/api/writers/ada')).json()).profile.name, 'Bo');
  assert.equal((await me.profile({ name: 'Ada L', avatar: 'ada-2', handle: 'ada' })).status, 409);
  // null clears it.
  assert.equal((await me.profile({ name: 'Ada L', avatar: 'ada-2', handle: null })).status, 200);
  assert.deepEqual(await me.readProfile(), { name: 'Ada L', avatar: 'ada-2' });
  assert.equal((await them.profile({ name: 'Bo', avatar: 'bo-1', handle: 'ada_l' })).status, 200);
  for (const route of ['/api/writers/nobody', '/api/writers/ab', '/api/writers/%E0%A4%A', '/api/writers/write']) assert.equal((await server.request(route)).status, 404, route);
});

test('a writer page shows the record of every shared page, but only the listed ones, without other links', { timeout: 60000 }, async t => {
  const server = await running(t), me = await writer(server, hash('me'));
  assert.equal((await me.profile({ name: 'Ada', avatar: 'ada-1', handle: 'ada' })).status, 200);
  // A client's own score, tier or handle count for nothing: the server works the score out from the verified proof.
  const shown = await page(await me.publish({ listed: true, title: '  My\u0007 first   essay ', score: 100, tier: 'mac', profile: { name: 'Ada', avatar: 'ada-1', handle: 'eve' } }));
  const hidden = await page(await me.publish({ listed: false, title: 'Private' }));
  const mac = await page(await me.publish()); // from the Mac: no title, not listed
  const publicPage = await page(await me.publish({ listed: true, title: 'Open letter' }, 'public'));
  assert.equal((await me.publish({ listed: 'yes' })).status, 400);
  const response = await server.request('/api/writers/ada');
  assert.equal(response.status, 200);
  const body = await response.text(), view = JSON.parse(body);
  assert.deepEqual(view.profile, { name: 'Ada', avatar: 'ada-1', handle: 'ada' });
  assert.equal(view.record.pages, 4); assert.equal(view.record.average, 67); assert.equal(view.record.best, 'mac');
  assert.ok(Math.abs(view.record.since - Date.now()) < 60000);
  assert.deepEqual(view.level, { level: 1, name: 'New writer' });
  assert.deepEqual(view.pages.map(p => [p.title, p.words, p.score, p.tier]), [['Open letter', text.split(/\s+/).filter(Boolean).length, 67, 'mac'],
    ['My first essay', text.split(/\s+/).filter(Boolean).length, 67, 'mac']]);
  for (const p of view.pages) assert.deepEqual(Object.keys(p).sort(), ['at', 'path', 'score', 'tier', 'title', 'words']);
  // A listed page's path is its short link, which opens it.
  const [link, publicLink] = [view.pages[1].path, view.pages[0].path];
  assert.match(link, SHORT_LINK); assert.match(link, /#/); assert.doesNotMatch(publicLink, /#/);
  const [pathname, key] = link.split('#');
  assert.equal(await (await server.request('/api/publications/' + shown.id + '/master', { headers: { Authorization: 'Bearer ' + pathname.slice(3) + '.' + key } })).text(), text);
  // Nothing about the unlisted pages: no id, token or short key.
  for (const secret of [hidden.id, hidden.token, mac.id, mac.token, shown.id, shown.token]) assert.equal(body.includes(secret), false);
  const short = async ({ id, token }) => (await (await server.request('/api/publications/' + id + '/short', { method: 'POST', headers: { Authorization: 'Bearer ' + token } })).json()).path;
  for (const unlisted of [hidden, mac]) assert.equal(body.includes((await short(unlisted)).split('#')[1]), false);
  // The receipt names the writer's handle (their own, not what a page said) and whether the page is listed.
  const receipt = async ({ id, token }) => (await server.request('/api/publications/' + id + '/receipt', { headers: { Authorization: 'Bearer ' + token } })).json();
  assert.deepEqual([(await receipt(shown)).handle, (await receipt(shown)).listed, (await receipt(hidden)).listed, (await receipt(mac)).listed], ['ada', true, false, false]);
  assert.deepEqual((await receipt(shown)).profile, { name: 'Ada', avatar: 'ada-1' });
  assert.equal((await (await server.request('/api/publications/' + publicPage.id + '/receipt')).json()).listed, true);
  // Without a handle, a page's receipt says so.
  await me.profile({ name: 'Ada', avatar: 'ada-1', handle: null });
  assert.equal((await receipt(shown)).handle, null);
  assert.equal((await server.request('/api/writers/ada')).status, 404);
});

test('only the writer’s own browsers list, unlist or remove a page, and a removed page leaves the record', { timeout: 60000 }, async t => {
  const server = await running(t), me = await writer(server, hash('me')), them = await writer(server, hash('them'));
  await me.profile({ name: 'Ada', avatar: 'ada-1', handle: 'ada' });
  const first = await page(await me.publish({ title: 'One' })), second = await page(await me.publish({ title: 'Two', listed: true }));
  const shown = async () => (await (await server.request('/api/writers/ada')).json());
  assert.deepEqual((await shown()).pages.map(p => p.title), ['Two']);
  const time = Date.now();
  assert.equal((await me.listed(first.id, true, { time, signature: me.signed(listedMessage(first.id, false, time)) })).status, 403); // signed for "no"
  assert.equal((await me.listed(first.id, true, { time, signature: me.signed(listedMessage(second.id, true, time)) })).status, 403); // signed for another page
  assert.equal((await me.listed(first.id, true, { time, signature: them.signed(listedMessage(first.id, true, time)), key: them.point })).status, 403); // not the sharing device
  assert.equal((await me.listed(first.id, true, { time: time - 6 * 60 * 1000 })).status, 403); // signed too long ago
  assert.equal((await me.listed(first.id, true, { signature: me.signed(`Huma listed v1\npublication ${first.id}\nlisted yes`) })).status, 403); // the old, timeless message
  assert.equal((await me.listed(first.id, 'yes')).status, 400);
  const on = await me.listed(first.id, true, { time });
  assert.equal(on.status, 200); assert.deepEqual(await on.json(), { listed: true });
  assert.equal((await me.listed(first.id, true, { time })).status, 409); // the same signed request, sent again
  // A rename is signed with its time too, and taken once.
  const rename = { publicKey: me.point, title: 'Uno', time, signature: me.signed(titleMessage(first.id, 'Uno', time)) };
  const renamed = () => server.request('/api/publications/' + first.id + '/title', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(rename) });
  assert.equal((await renamed()).status, 200); assert.equal((await renamed()).status, 409);
  assert.equal((await me.listed(second.id, true, { time })).status, 200); // another page's signature at the same time is its own
  assert.deepEqual((await shown()).pages.map(p => p.title).sort(), ['Two', 'Uno']);
  assert.equal((await (await server.request('/api/publications/' + first.id + '/receipt', { headers: { Authorization: 'Bearer ' + first.token } })).json()).listed, true);
  assert.deepEqual(await (await me.listed(second.id, false)).json(), { listed: false });
  assert.deepEqual((await shown()).pages.map(p => p.title), ['Uno']);
  // Removing the page takes it off the writer page and out of the record; it can't be listed again.
  const removed = await server.request('/api/publications/' + first.id + '/remove', { method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ publicKey: me.point, signature: me.signed(removalMessage(first.id)) }) });
  assert.equal(removed.status, 200, await removed.clone().text());
  const after = await shown();
  assert.equal(after.record.pages, 1); assert.deepEqual(after.pages, []);
  assert.equal((await me.listed(first.id, true)).status, 410);
  assert.equal((await me.listed('0'.repeat(64), true)).status, 404);
  // Another browser signed in to the same account (a private window, a second computer) can change and delete it too;
  // one from another account still can't.
  const also = await writer(server, hash('me')), remove = (who, id) => server.request('/api/publications/' + id + '/remove', { method: 'POST',
    headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ publicKey: who.point, signature: who.signed(removalMessage(id)) }) });
  assert.equal((await also.listed(second.id, true)).status, 200);
  assert.equal((await remove(them, second.id)).status, 403);
  assert.equal((await remove(also, second.id)).status, 200);
  assert.deepEqual((await shown()).pages, []);
});

test('a short link’s code names its page’s id, which a writer’s browser uses to change the page', { timeout: 60000 }, async t => {
  const server = await running(t), me = await writer(server, hash('me'));
  const { id, token } = await page(await me.publish({ title: 'One' }));
  const short = await (await server.request('/api/publications/' + id + '/short', { method: 'POST', headers: { Authorization: 'Bearer ' + token } })).json();
  const code = short.path.match(/^\/p\/([A-Za-z0-9]+)#/)[1];
  assert.deepEqual(await (await server.request('/api/publications/short/' + code)).json(), { id });
  assert.equal((await server.request('/api/publications/short/Zz' + code.slice(2))).status, 404);
  assert.equal((await server.request('/api/publications/short/' + code, { method: 'POST' })).status !== 200, true);
});

test('browser pages score as a reader works them out, and their tier is checked, never sent', { timeout: 60000 }, async t => {
  // A browser page (origin_present 0) whose replay shows 90% typed; the second also had its passkey approve every check-in.
  const browser = { ...verified.scoring.journal, origin_present: 0 }, composition = { typed: 90, external: 0, pasted: 10, before: 0, other: 0, total: 100 };
  let next = { journal: browser, passkey: false, composition };
  const server = await running(t, () => next), me = await writer(server, hash('me'));
  await me.profile({ name: 'Ada', avatar: 'ada-1', handle: 'ada' });
  await page(await me.publish({ listed: true, title: 'Web', score: 3, tier: 'mac' }));
  next = { journal: browser, passkey: true, composition: null };
  await page(await me.publish({ listed: true, title: 'Passkey' }));
  const view = await (await server.request('/api/writers/ada')).json();
  // 90% typed: 63 + 20 + 5; without a replay a browser page counts its typing edits whole: 70 + 20 + 5.
  assert.deepEqual(view.pages.map(p => [p.title, p.score, p.tier]), [['Passkey', 95, 'passkey'], ['Web', 88, 'web']]);
  assert.deepEqual(view.record, { ...view.record, pages: 2, average: 92, best: 'passkey' });
  assert.deepEqual(verifiedScore(null), { score: null, tier: null });
  assert.deepEqual(verifiedScore({ journal: browser, passkey: true, composition }), { score: 88, tier: 'passkey' });
});

test('levels follow the record: pages, average, days writing and best tier', () => {
  const day = 86400000, now = 400 * day;
  const level = (pages, score, days, tier = 'mac') => writerPage({ name: 'Ada', avatar: 'a', handle: 'ada' },
    Array.from({ length: pages }, (_, i) => ({ id: String(i), title: 't', words: 1, score, tier, at: now - (i ? days * day : 0), listed: false, path: '/p/AAAAAAAA' })), now).level.level;
  assert.equal(level(0, null, 0), 1);
  assert.equal(level(1, 10, 0), 1);
  assert.equal(level(5, 70, 0), 2); assert.equal(level(5, 69, 0), 1);
  assert.equal(level(15, 80, 30), 3); assert.equal(level(15, 80, 29), 2);
  assert.equal(level(40, 85, 90), 4); assert.equal(level(40, 85, 90, 'web'), 3); assert.equal(level(40, 85, 90, 'passkey'), 4); assert.equal(level(39, 99, 400), 3);
  assert.deepEqual(writerLevel({ pages: 40, average: 85, days: 90, best: 'mac' }), { level: 4, name: 'Trusted writer' });
  assert.deepEqual(writerLevel({ pages: 15, average: 80, days: 30, best: 'web' }), { level: 3, name: 'Steady writer' });
  assert.deepEqual(writerLevel({ pages: 5, average: 70, days: 0, best: 'web' }), { level: 2, name: 'Writer' });
  const many = writerPage({ name: 'Ada', avatar: 'a', handle: 'ada' }, Array.from({ length: 250 }, (_, i) => ({ id: String(i), title: 't' + i, words: 1, score: 50, tier: 'web', at: i, listed: true, path: '/p/AAAAAAAA#' + 'A'.repeat(16) })), 1000);
  assert.equal(many.pages.length, 200); assert.equal(many.pages[0].title, 't249'); assert.equal(many.record.pages, 250); assert.equal(many.record.since, 0);
});

test('/@handle serves the writer page for any well-formed handle, and /writer.mjs its script', async t => {
  const { request } = await running(t);
  for (const route of ['/@ada', '/@Nobody_here']) {
    const response = await request(route);
    assert.equal(response.status, 200, route); assert.match(response.headers.get('content-type'), /text\/html/);
  }
  for (const route of ['/@ab', '/@write', '/@a!b', '/@ada/x']) assert.equal((await request(route)).status, 404, route);
  const script = await request('/writer.mjs');
  assert.equal(script.status, 200); assert.match(script.headers.get('content-type'), /text\/javascript/);
});
