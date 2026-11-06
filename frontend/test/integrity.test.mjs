import test from 'node:test';
import assert from 'node:assert/strict';
import { checkIntegrity, INTEGRITY } from '../detection/integrity.mjs';
import { describeSession, nearest } from '../detection/session.mjs';
import { GENERATORS, SAMPLE_TEXT, simulateTyping, humanModel, session, toBatches } from '../detection/eval/synthetic.mjs';

const check = s => checkIntegrity({ stream: s.stream, frames: s.frames, text: s.text, journal: s.journal });
const checks = result => result.failures.map(f => f.check);

test('a person’s session, on a keyboard, a touch screen or through an input method, passes every integrity check', () => {
  for (const [name, seed] of [['human', 1], ['human', 2], ['human_touch', 3], ['human_ime', 4]]) {
    const s = GENERATORS[name](SAMPLE_TEXT, seed), result = check(s);
    assert.equal(result.status, 'pass', name + ': ' + JSON.stringify(result.failures));
    assert.deepEqual(result.penalties, []);
    assert.equal(result.measures.orphanFrames, 0);
    assert.ok(result.measures.liveShare > 0.95);
  }
});

test('the session view joins the stream and the replay on one clock and tells the modality', () => {
  const s = GENERATORS.human(SAMPLE_TEXT, 5), view = describeSession({ events: s.stream.events, meta: s.stream.meta, frames: s.frames });
  assert.equal(view.modality, 'physical_keyboard'); assert.ok(Math.abs(view.offset - 498) < 5, String(view.offset));
  assert.equal(describeSession({ events: GENERATORS.human_touch(SAMPLE_TEXT, 5).stream.events, meta: { coarse: true }, frames: [] }).modality, 'touch');
  const ime = GENERATORS.human_ime(SAMPLE_TEXT, 5);
  assert.equal(describeSession({ events: ime.stream.events, meta: ime.stream.meta, frames: ime.frames }).modality, 'ime');
  assert.equal(describeSession().modality, 'physical_keyboard');
  assert.equal(nearest([1, 5, 9], 6), 1); assert.equal(nearest([1, 5, 9], 8), 2); assert.equal(nearest([], 1), null);
});

test('a log posted all at once fails as a burst and for its clock; no stream at all fails', () => {
  const posted = check(GENERATORS.fabricated_post(SAMPLE_TEXT, 6));
  assert.equal(posted.status, 'fail'); assert.ok(checks(posted).includes('burst')); assert.ok(checks(posted).includes('clock'));
  assert.ok(posted.measures.liveShare < 0.1);
  const none = checkIntegrity({ stream: null, frames: [], text: '' });
  assert.equal(none.status, 'fail'); assert.deepEqual(checks(none), ['stream']);
  // A short burst (under a minute) isn't judged for liveness, but its clock still is.
  const short = GENERATORS.fabricated_post(SAMPLE_TEXT.slice(0, 120), 6);
  assert.ok(check(short).measures.clientSpanMs < INTEGRITY.burstMinSpanMs);
  assert.ok(!checks(check(short)).includes('burst'));
});

test('text that arrives without key presses, or more text than keys, fails the binding to the replay', () => {
  const inserted = check(GENERATORS.cdp_inserttext(SAMPLE_TEXT, 7));
  assert.equal(inserted.status, 'fail'); assert.ok(checks(inserted).includes('binding')); assert.equal(inserted.measures.orphanFrameRate, 1);
  // A person's stream with half its key presses dropped.
  const s = GENERATORS.human(SAMPLE_TEXT, 8);
  const thinned = { ...s.stream, events: s.stream.events.filter((e, i) => !(e.ev === 'kd' && i % 2)) };
  const result = checkIntegrity({ stream: thinned, frames: s.frames, text: s.text, journal: s.journal });
  assert.ok(checks(result).includes('binding'), JSON.stringify(result.failures));
  assert.ok(result.measures.orphanFrameRate > 0.3);
});

test('a replaced console, or a patched Function.prototype.toString, fails as tampering with the page’s checks', () => {
  const s = GENERATORS.human(SAMPLE_TEXT, 13);
  for (const meta of [{ ...s.stream.meta, consoleNative: false }, { ...s.stream.meta, toStringNative: false }]) {
    const result = checkIntegrity({ stream: { ...s.stream, meta }, frames: s.frames, text: s.text, journal: s.journal });
    assert.equal(result.status, 'fail'); assert.deepEqual(checks(result), ['environment']);
  }
  assert.equal(check(s).status, 'pass');
  // The Mac streams nothing, so the check doesn't apply there.
  assert.equal(checkIntegrity({ stream: null, frames: s.frames, text: s.text, platform: 'mac' }).status, 'pass');
});

test('a proof claiming far more writing time than the stream spans, or a client clock running fast, fails', () => {
  const s = GENERATORS.human(SAMPLE_TEXT, 9);
  const claimed = checkIntegrity({ stream: s.stream, frames: s.frames, text: s.text, journal: { elapsed: String(40 * 60 * 1000), start_unix: '0', end_unix: '0' } });
  assert.ok(checks(claimed).includes('clock'), JSON.stringify(claimed.failures));
  const fast = { ...s.stream, batches: s.stream.batches.map(b => ({ ...b, sentAt: b.sentAt * 3 })) };
  assert.ok(checks(checkIntegrity({ stream: fast, frames: s.frames, text: s.text })).includes('clock'));
});

test('speed no hand keeps fails; long text with no pause is a penalty', () => {
  const racing = session('racing', simulateTyping(SAMPLE_TEXT, { ...humanModel({ pauses: false, typos: 0 }), gap: () => 40, hold: () => 60 }, { seed: 10 }));
  const fast = check(racing);
  assert.ok(checks(fast).includes('speed'), JSON.stringify(fast.measures)); assert.ok(fast.measures.peakWPM > INTEGRITY.wpmCeiling);
  const steady = check(session('steady', simulateTyping(SAMPLE_TEXT.repeat(2), humanModel({ pauses: false, typos: 0, pointer: 'none' }), { seed: 11 })));
  assert.equal(steady.status, 'pass');
  assert.deepEqual(steady.penalties.map(p => p.check), ['pauses']);
});

test('batches are cut every few seconds, and a burst arrives together', () => {
  const typed = simulateTyping(SAMPLE_TEXT.slice(0, 300), humanModel(), { seed: 12 });
  const live = toBatches(typed.events, { meta: typed.meta, trap: 'x' }), burst = toBatches(typed.events, { live: false });
  assert.ok(live.length >= 5); assert.deepEqual(live.map(b => b.index), live.map((_, i) => i));
  assert.equal(live.flatMap(b => b.events).length, typed.events.length);
  assert.equal(live[0].meta.ua.length > 0, true); assert.equal(live[1].trap, 'x');
  assert.ok(burst.at(-1).receivedAt - burst[0].receivedAt < 1000);
  assert.deepEqual(toBatches([]), []);
});
