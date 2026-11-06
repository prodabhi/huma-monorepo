import test from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto as crypto } from 'node:crypto';
import { replayRhythm, humaScore, RHYTHM } from '../publication-contract.mjs';
import { verifyReplay, swiftJSON, REPLAY_KIND } from '../replay-core.mjs';
import { verifiedScore } from '../publications.mjs';

// A replay's rhythm (replayRhythm): software typing a page, from crude to careful, against a rhythm modelled on people.
// The thresholds were set on 323 real essays typed in a browser (a public keystroke dataset, not kept here): none of
// them, whole or cut short, is held. These cases keep the behaviour in place.
const TEXT = ('The river ran low that summer, and the farms along it waited for rain. People spoke of the old floods as if ' +
  'they missed them. In the evenings we walked to the bridge and watched the water slide over the stones. My father ' +
  'said the fish had gone downstream to find deeper pools, and that they would come back when the weather turned. ' +
  'Nobody believed him, but nobody argued either. We counted the days by the height of the grass on the bank, and ' +
  'by the number of times the old dog went down to drink and came back with nothing to show for it. ').repeat(2);

function random(seed) { let s = seed >>> 0; return () => ((s = (s * 1664525 + 1013904223) >>> 0) / 2 ** 32); }
const normal = rand => Math.sqrt(-2 * Math.log(1 - rand())) * Math.cos(2 * Math.PI * rand());
const hash = s => { let h = 2166136261; for (const c of s) h = Math.imul(h ^ c.charCodeAt(0), 16777619) >>> 0; return h; };
/** Frames as verifyReplay returns them, typing `text` one character per edit: `gap(previous, char)` is the delay. */
function typeOut(text, gap, kind = 'typing-external') {
  const frames = []; let t = 1000, previous;
  for (const c of text) {
    if (previous !== undefined) t += Math.floor(gap(previous, c));
    frames.push({ time: t, kind, location: frames.length, length: 0, inserted: c });
    previous = c;
  }
  return frames;
}
/** People: each letter pair at its own speed, slower at word starts, varying a lot, with the odd long pause. */
const person = seed => { const rand = random(seed); return (p, c) => (90 + hash(p + c) % 160) * (p === ' ' ? 1.8 : 1) * Math.exp(0.4 * normal(rand)) + (rand() < 0.03 ? 2500 : 0); };

test('a rhythm like a person’s passes, with what it measured', () => {
  for (const seed of [1, 2, 3, 4, 5]) {
    const r = replayRhythm(typeOut(TEXT, person(seed)));
    assert.equal(r.automated, false); assert.equal(r.reason, null);
    assert.ok(r.measures.gaps >= RHYTHM.minRandomGaps);
    assert.ok(r.measures.pairShift > 5 && r.measures.wordStartShift > 3 && r.measures.pairVariation > 0.2);
  }
});

test('a metronome, a fixed table and random delays are each caught', () => {
  const rand = random(9);
  assert.equal(replayRhythm(typeOut(TEXT, () => 120 + 2 * rand())).reason, 'a perfectly even rhythm');
  assert.equal(replayRhythm(typeOut(TEXT, (p, c) => 80 + hash(c) % 200 + 3 * rand())).reason, 'each letter pair took the same time');
  assert.equal(replayRhythm(typeOut(TEXT, (p, c) => 70 + hash(p + c) % 220 + 3 * rand())).reason, 'each letter pair took the same time');
  // Delays drawn at random, however human their spread, ignore letters and words (caught about 19 times in 20).
  let caught = 0;
  for (let seed = 1; seed <= 40; seed++) {
    const r = random(seed), result = replayRhythm(typeOut(TEXT, () => 170 * Math.exp(0.45 * normal(r))));
    if (result.automated) { caught++; assert.equal(result.reason, 'a rhythm that ignored letters and words'); }
  }
  assert.ok(caught >= 34, `caught ${caught} of 40`);
});

test('the same frames always get the same answer', () => {
  const rand = random(3), frames = typeOut(TEXT, () => 50 + 200 * rand());
  assert.deepEqual(replayRhythm(frames), replayRhythm(structuredClone(frames)));
});

test('too little typing is never judged, and random-looking typing needs 500 gaps', () => {
  const rand = random(5);
  assert.equal(replayRhythm(typeOut(TEXT.slice(0, 120), () => 120)).automated, false);
  const r = random(17), short = replayRhythm(typeOut(TEXT.slice(0, 400), () => 170 * Math.exp(0.45 * normal(r))));
  assert.ok(short.measures.gaps < RHYTHM.minRandomGaps); assert.equal(short.automated, false);
  // But an even rhythm is plain from 150 gaps.
  assert.equal(replayRhythm(typeOut(TEXT.slice(0, 200), () => 100 + rand())).reason, 'a perfectly even rhythm');
  assert.deepEqual(replayRhythm([]).automated, false); assert.equal(replayRhythm(undefined).measures.gaps, 0);
});

test('only typing counts: pastes, input methods, held keys and jumps elsewhere are left out', () => {
  // A person's page with a long run of a held key (the keyboard repeating "-" every 33 ms) and pasted text.
  const frames = typeOut(TEXT, person(7));
  const at = frames.at(-1).location + 1;
  let t = frames.at(-1).time;
  for (let i = 0; i < 400; i++) frames.push({ time: t += 33, kind: 'typing-external', location: at + i, length: 0, inserted: '-' });
  for (let i = 0; i < 400; i++) frames.push({ time: t += 120, kind: 'paste', location: at + 400 + i, length: 0, inserted: 'x' });
  assert.equal(replayRhythm(frames).automated, false);
  // A metronome through an input method, or as pastes, isn't typing, so there's nothing to judge.
  assert.equal(replayRhythm(typeOut(TEXT, () => 120, 'input-method')).measures.gaps, 0);
  assert.equal(replayRhythm(typeOut(TEXT, () => 120, 'paste')).measures.gaps, 0);
  // Characters typed one at a time but each somewhere else (no run) give no gaps either.
  const scattered = typeOut(TEXT, () => 120).map((f, i) => ({ ...f, location: 0 }));
  assert.equal(replayRhythm(scattered).measures.gaps, 0);
  // Mac typing counts like browser typing.
  assert.equal(replayRhythm(typeOut(TEXT, () => 120, 'typing')).reason, 'a perfectly even rhythm');
});

test('a backspace keeps the run going but its gap is left out', () => {
  const frames = [];
  let t = 0, at = 0;
  for (let i = 0; i < 300; i++) {
    frames.push({ time: t += 100, kind: 'typing', location: at++, length: 0, inserted: 'ab'[i % 2] });
    frames.push({ time: t += 100, kind: 'typing', location: --at, length: 1, inserted: '' });
  }
  assert.equal(replayRhythm(frames).measures.gaps, 0);
});

test('an automated rhythm holds a browser page at 50, and nothing else changes', () => {
  const all = Array(9).fill(true), composition = { typed: 100, external: 0, pasted: 0, before: 0, other: 0, total: 100 };
  const page = { composition, typingEdits: 100, edits: 100, rules: all, presenceCount: 2, onTime: 2, browser: true };
  assert.equal(humaScore(page).value, 100); assert.equal(humaScore(page).capped, false);
  assert.deepEqual(humaScore({ ...page, rhythmAutomated: false }), humaScore(page));
  const held = humaScore({ ...page, rhythmAutomated: true });
  assert.equal(held.value, 50); assert.equal(held.capped, true);
  assert.equal(held.points.typed + held.points.checks + held.points.touch, 50);
  // A Mac page's score ignores it, as HumaScore.swift does.
  assert.deepEqual(humaScore({ ...page, browser: false, rhythmAutomated: true }), humaScore({ ...page, browser: false }));
  // A page already under 50 stays where it is.
  const pasted = { ...page, composition: { ...composition, typed: 20, pasted: 80 } };
  assert.equal(humaScore({ ...pasted, rhythmAutomated: true }).value, humaScore(pasted).value);
  // The server's score for a shared page does the same with what its verifier found.
  const journal = { rules: all, typing: 100, edits: 100, presence_count: 2, on_time: 2, origin_present: 0 };
  assert.deepEqual(verifiedScore({ journal, passkey: false, composition }), { score: 100, tier: 'web' });
  assert.deepEqual(verifiedScore({ journal, passkey: false, composition, rhythmAutomated: true }), { score: 50, tier: 'web' });
  assert.deepEqual(verifiedScore({ journal: { ...journal, origin_present: 1 }, composition, rhythmAutomated: true }).score,
    verifiedScore({ journal: { ...journal, origin_present: 1 }, composition }).score);
});

// A signed replay, as the writer's browser or Mac makes one, so the check runs on what verifyReplay returns.
async function signedReplay(frames) {
  const sha = async v => Buffer.from(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(v))).toString('hex');
  const keys = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
  const publicKey = Buffer.from(await crypto.subtle.exportKey('raw', keys.publicKey)).toString('base64');
  const session = 'S1', events = frames.map(f => [f.time, f.kind, f.location, f.length, f.inserted]);
  let page = '', head = await sha('huma-session-v1:' + session + ':');
  for (const [index, [time, kind, location, length, inserted]] of events.entries()) {
    page = page.slice(0, location) + inserted + page.slice(location + length);
    head = await sha(swiftJSON([String(index), String(time), kind, String(location), String(length), inserted, head, await sha(page)]));
  }
  const c = { version: 2, kind: 'unattested-p256', sessionID: session, sequence: 1, isFinal: true, captureCount: 0, editCount: events.length,
    sampleCount: 0, captureHead: '0'.repeat(64), editHead: head, textHash: await sha(page), previousCheckpoint: '', challenge: '', publicKey,
    reportedTime: { unixMilliseconds: 1, elapsedMilliseconds: frames.at(-1).time } };
  const payload = swiftJSON(['huma-signed-checkpoint-v2', c.kind, c.sessionID, String(c.sequence), 'true', String(c.captureCount),
    String(c.editCount), String(c.sampleCount), c.captureHead, c.editHead, c.textHash, c.previousCheckpoint, c.challenge, c.publicKey,
    'device-clock-v1', String(c.reportedTime.unixMilliseconds), String(c.reportedTime.elapsedMilliseconds)]);
  const raw = new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, keys.privateKey, new TextEncoder().encode(payload)));
  const integer = bytes => { let i = 0; while (i < 31 && bytes[i] === 0) i++; const v = bytes.slice(i); return v[0] & 0x80 ? [2, v.length + 1, 0, ...v] : [2, v.length, ...v]; };
  const body = [...integer(raw.slice(0, 32)), ...integer(raw.slice(32))];
  c.signature = Buffer.from([0x30, body.length, ...body]).toString('base64');
  return { source: JSON.stringify({ kind: REPLAY_KIND, session, initialText: '', events, checkpoint: c }), publicKey, text: page };
}

test('the check runs on a verified replay’s frames', async () => {
  const text = TEXT.slice(0, 700);
  const robot = await signedReplay(typeOut(text, () => 110, 'typing-external'));
  const checked = await verifyReplay(robot.source, { publicKey: robot.publicKey, text: robot.text });
  assert.equal(replayRhythm(checked.frames).reason, 'a perfectly even rhythm');
  const human = await signedReplay(typeOut(text, person(11), 'typing-external'));
  assert.equal(replayRhythm((await verifyReplay(human.source, { publicKey: human.publicKey, text: human.text })).frames).automated, false);
});
