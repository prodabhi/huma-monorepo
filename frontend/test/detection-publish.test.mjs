import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { createRegistry } from '../registry.mjs';
import { verifyPublicationUpload, verifiedScore } from '../publications.mjs';
import { batchMAC } from '../detection/stream.mjs';
import { judgeSession, publicDetection, replayFrames, holdsScore } from '../detection/judge.mjs';
import { canaryWord } from '../detection/traps.mjs';
import { GENERATORS, SAMPLE_TEXT, simulateTyping, humanModel } from '../detection/eval/synthetic.mjs';

// A browser page shared with its session streamed live (the proof fixture, its journal made a browser's with the
// session's nonce), through prepare and publish: the verdict is judged at prepare, kept with the record, and shown
// in the receipt; in enforce mode it holds the score.
const hash = value => createHash('sha256').update(value).digest('hex');
const field = hex => BigInt('0x' + hex).toString();
const wait = ms => new Promise(resolve => setTimeout(resolve, ms));
const until = async (test, ms = 3000) => { const end = Date.now() + ms; while (!(await test()) && Date.now() < end) await wait(10); assert.ok(await test(), 'timed out'); };
const proof = await readFile(new URL('../../extra/experiments/noir-compact/browser/test/fixtures/Long400V3.json', import.meta.url), 'utf8');

async function running(t, claim, options = {}) {
  const directory = await mkdtemp(path.join(tmpdir(), 'huma-detection-'));
  const server = await createRegistry({ store: directory, publicationOptions: {
    authenticate: async token => { if (token !== 'test-owner-session') throw Object.assign(new Error('Sign in required.'), { status: 401 }); return hash('test-owner'); },
    verifyUpload: async source => {
      const checked = await verifyPublicationUpload(source);
      return { ...checked, scoring: { ...checked.scoring, journal: { ...checked.scoring.journal, origin_present: 0,
        nonce: [field(claim.nonce), '0'], elapsed: String(claim.elapsed), start_unix: '1000', end_unix: '1000' } } };
    }, ...options } });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(async () => { server.streams.close(); server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); await rm(directory, { recursive: true, force: true }); });
  const base = `http://127.0.0.1:${server.address().port}`;
  return { request: (route, init) => fetch(base + route, init), base, server };
}
async function prepared(request) {
  const response = await request('/api/publications/prepare', { method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ kind: 'huma-publication-upload-v1', access: 'link', proof, master: { mediaType: 'text/plain;charset=utf-8', base64: Buffer.from(JSON.parse(proof).text).toString('base64') } }) });
  assert.equal(response.status, 201, await response.clone().text());
  const ticket = await response.json();
  // What the page is told while it waits: the verdict is in it.
  const summary = await (await request('/api/publications/pending/' + ticket.id, { headers: { Authorization: 'Bearer ' + ticket.ticket } })).json();
  return { ...ticket, detection: summary.detection };
}
const publish = (request, pending) => request('/api/publications/pending/' + pending.id + '/publish', { method: 'POST',
  headers: { Authorization: 'Bearer test-owner-session', 'X-Huma-Ticket': pending.ticket, 'Content-Type': 'application/json' }, body: '{}' });
const receipt = async (request, response) => {
  const [pathname, token] = (await response.json()).path.split('#');
  return (await request('/api/publications/' + pathname.slice('/original/'.length) + '/receipt', { headers: { Authorization: 'Bearer ' + token } })).json();
};
/** Streams a synthetic session's events to the server as the page would, in its batches (sent now, so a short one). */
async function streamed(base, issued, typed) {
  const ws = new WebSocket(base.replace('http', 'ws') + '/api/sessions/stream', { headers: { Origin: base } });
  const acks = []; ws.onmessage = e => acks.push(JSON.parse(e.data));
  await new Promise((resolve, reject) => { ws.onopen = resolve; ws.onerror = reject; });
  const first = typed.events[0].t; let index = 0;
  for (let at = first + 2500; at - 2500 <= typed.events.at(-1).t; at += 2500) {
    const events = typed.events.filter(e => e.t >= at - 2500 && e.t < at);
    const batch = { session: issued.nonce, index, sentAt: at, hmac: batchMAC(issued.key, index, events), events, ...(index === 0 ? { meta: typed.meta } : {}) };
    ws.send(JSON.stringify(batch)); index++;
    await wait(15);
  }
  await until(() => acks.length === index);
  ws.close();
  return index;
}

test('a browser page with no stream is unverified: judged, kept, shown, and held at 50', { timeout: 60000 }, async t => {
  const claim = { nonce: null, elapsed: 20000 };
  const { request } = await running(t, claim);
  const issued = await (await request('/api/sessions', { method: 'POST' })).json();
  claim.nonce = issued.nonce;
  const pending = await prepared(request);
  assert.equal(pending.detection.integrity, 'fail'); assert.equal(pending.detection.band, 'uncertain'); assert.equal(pending.detection.enforced, true);
  const response = await publish(request, pending);
  assert.equal(response.status, 200, await response.clone().text());
  const got = await receipt(request, response);
  assert.equal(got.detection.integrity, 'fail'); assert.equal(got.detection.band, 'uncertain'); assert.ok(got.detection.humanProbability <= 0.5);
  assert.match(got.detection.reasons[0].detail, /no live event stream/); assert.equal(got.detection.enforced, true);
  assert.deepEqual(Object.keys(got.detection).sort(), ['band', 'enforced', 'humanProbability', 'integrity', 'modality', 'modelVersion', 'platform', 'reasons']);
});

test('a browser page whose session streamed live is judged on it; shadow mode keeps the score', { timeout: 60000 }, async t => {
  const claim = { nonce: null, elapsed: 20000 };
  const { request, base } = await running(t, claim, { detectionMode: 'shadow' });
  const issued = await (await request('/api/sessions', { method: 'POST' })).json();
  claim.nonce = issued.nonce;
  const typed = simulateTyping(SAMPLE_TEXT.slice(0, 220), humanModel({ typos: 0 }), { seed: 3 });
  const batches = await streamed(base, issued, typed);
  assert.ok(batches >= 8);
  const pending = await prepared(request);
  assert.equal(pending.detection.integrity, 'pass', JSON.stringify(pending.detection));
  assert.notEqual(pending.detection.band, 'likely_automated'); assert.equal(pending.detection.enforced, false);
  const response = await publish(request, pending);
  assert.equal(response.status, 200, await response.clone().text());
  const got = await receipt(request, response);
  assert.equal(got.detection.integrity, 'pass'); assert.equal(got.detection.enforced, false); assert.equal(got.detection.modality, 'physical_keyboard');
  assert.ok(got.detection.reasons.length >= 3);
});

test('the score is held at 50 only for a verdict that isn’t a verified person, and only when enforced', () => {
  const journal = { rules: Array(9).fill(true), typing: 100, edits: 100, presence_count: 0, on_time: 0, origin_present: 0 };
  const composition = { typed: 100, external: 0, pasted: 0, before: 0, other: 0, total: 100 };
  const scoring = { journal, passkey: false, composition };
  assert.equal(verifiedScore(scoring).score, 100);
  assert.equal(verifiedScore(scoring, { band: 'likely_human', integrity: 'pass' }).score, 100);
  assert.equal(verifiedScore(scoring, { band: 'uncertain', integrity: 'pass' }).score, 50);
  assert.equal(verifiedScore(scoring, { band: 'likely_automated', integrity: 'pass' }).score, 50);
  assert.equal(verifiedScore(scoring, { band: 'likely_human', integrity: 'fail' }).score, 50);
  assert.equal(verifiedScore(scoring, { band: 'likely_automated', integrity: 'fail' }, false).score, 100);
  // A Mac page (judged on its replay alone, its keys checked by the Mac) is held only when its replay looked automated.
  const mac = { ...scoring, journal: { ...journal, origin_present: 1 } };
  assert.equal(verifiedScore(mac, { platform: 'mac', band: 'likely_automated', integrity: 'pass' }).score, 50);
  assert.equal(verifiedScore(mac, { platform: 'mac', band: 'uncertain', integrity: 'pass' }).score, 100);
  assert.equal(verifiedScore(mac, { platform: 'mac', band: 'likely_human', integrity: 'pass' }).score, 100);
  assert.equal(verifiedScore(mac, { platform: 'mac', band: 'likely_automated', integrity: 'pass' }, false).score, 100);
  assert.deepEqual([true, false].map(h => holdsScore({ platform: 'mac', band: h ? 'likely_automated' : 'uncertain', integrity: 'pass' })), [true, false]);
  assert.equal(holdsScore(null), false);
});

test('a Mac page is judged on its replay alone: a person’s passes, a humanised harness or a replayed rhythm is held', async () => {
  const secret = Buffer.alloc(32, 2), streams = { read: async () => { throw new Error('never read for a Mac page'); } };
  const replayOf = s => JSON.stringify({ kind: 'huma-replay-v1', session: 'S', initialText: '', events: s.frames.map(f => [f.time, f.kind, f.location, f.length, f.inserted]),
    checkpoint: { version: 2, kind: 'unattested-p256', isFinal: true, sessionID: 'S', sequence: 1, captureCount: 0, editCount: s.frames.length, sampleCount: 0, reportedTime: { unixMilliseconds: 1, elapsedMilliseconds: 1 },
      captureHead: '0'.repeat(64), editHead: '0'.repeat(64), textHash: '0'.repeat(64), previousCheckpoint: '', challenge: '', publicKey: 'AA==', signature: 'AA==' } });
  for (const [generator, band] of [['human', 'likely_human'], ['cdp_dispatch_humanized', 'likely_automated'], ['replay_human', 'likely_automated'], ['computer_use_agent', 'likely_automated']]) {
    for (const seed of [1, 2]) {
      const s = GENERATORS[generator](SAMPLE_TEXT, seed);
      const v = await judgeSession({ streams, secret, nonce: null, journal: s.journal, replay: replayOf(s), text: s.text, platform: 'mac' });
      assert.equal(v.platform, 'mac'); assert.equal(v.integrity, 'pass'); assert.equal(v.streamed, false); assert.deepEqual(v.traps, {});
      assert.equal(v.band, band, generator + ' ' + seed + ' ' + v.humanProbability);
      assert.equal(holdsScore(v), band === 'likely_automated');
    }
  }
  // Without a replay there's nothing to judge; a browser page without its session likewise.
  assert.equal(await judgeSession({ streams, secret, nonce: null, replay: null, platform: 'mac' }), null);
  assert.equal(publicDetection(await judgeSession({ streams, secret, nonce: null, journal: null, replay: replayOf(GENERATORS.human(SAMPLE_TEXT, 3)), text: '', platform: 'mac' })).platform, 'mac');
});

test('judging a session: frames from the replay, the canary in the text, the honeypot in the stream', async () => {
  const secret = Buffer.alloc(32, 1), nonce = 'ab'.repeat(16), word = canaryWord(secret, nonce);
  const s = GENERATORS.human(SAMPLE_TEXT, 1);
  const streams = { read: async n => (n === nonce ? s.stream : null) };
  const plain = await judgeSession({ streams, secret, nonce, journal: s.journal, text: s.text });
  assert.equal(plain.integrity, 'pass'); assert.equal(plain.band, 'likely_human'); assert.equal(plain.streamed, true);
  assert.deepEqual(plain.traps, { canary: false, honeypot: false }); assert.ok(plain.features.rollover_rate[0] > 0 && plain.features.rollover_rate[1] === 1);
  const canary = await judgeSession({ streams, secret, nonce, journal: s.journal, text: s.text + '\n' + word + ' is where this paragraph starts.' });
  assert.equal(canary.band, 'likely_automated'); assert.equal(canary.humanProbability, 0.01); assert.equal(canary.traps.canary, true);
  const filled = await judgeSession({ streams: { read: async () => ({ ...s.stream, trap: 'Essay' }) }, secret, nonce, journal: s.journal, text: s.text });
  assert.equal(filled.traps.honeypot, true); assert.equal(filled.band, 'likely_automated');
  assert.equal(await judgeSession({ streams, secret, nonce: null }), null);
  const shown = publicDetection(plain, false);
  assert.deepEqual(Object.keys(shown).sort(), ['band', 'enforced', 'humanProbability', 'integrity', 'modality', 'modelVersion', 'platform', 'reasons']);
  assert.equal(shown.enforced, false); assert.equal(publicDetection(null), null);
  // Frames from a replay file.
  const replay = JSON.stringify({ kind: 'huma-replay-v1', session: 'S', initialText: '', events: [[10, 'typing', 0, 0, 'a'], [20, 'typing', 1, 0, 'b']],
    checkpoint: { version: 2, kind: 'unattested-p256', isFinal: true, sessionID: 'S', sequence: 1, captureCount: 0, editCount: 2, sampleCount: 0, reportedTime: { unixMilliseconds: 1, elapsedMilliseconds: 20 },
      captureHead: '0'.repeat(64), editHead: '0'.repeat(64), textHash: '0'.repeat(64), previousCheckpoint: '', challenge: '', publicKey: 'AA==', signature: 'AA==' } });
  assert.deepEqual(replayFrames(replay), [{ time: 10, kind: 'typing', location: 0, length: 0, inserted: 'a' }, { time: 20, kind: 'typing', location: 1, length: 0, inserted: 'b' }]);
  assert.deepEqual(replayFrames('nonsense'), []);
});
