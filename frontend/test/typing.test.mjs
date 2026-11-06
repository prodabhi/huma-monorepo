import test from 'node:test';
import assert from 'node:assert/strict';
import { analyse, robotic, natural } from '../write/typing.mjs';

// Software typing a page, from crude to careful, against what the typing checks catch. The careful one passes: a
// rhythm modelled on how people type can't be told from a person by timing alone, which is why the proof, not this
// page, is where typing is finally judged.
const CODES = { a: 0, s: 1, d: 2, f: 3, h: 4, g: 5, z: 6, x: 7, c: 8, v: 9, b: 11, q: 12, w: 13, e: 14, r: 15, y: 16, t: 17, o: 31, u: 32,
  i: 34, p: 35, l: 37, j: 38, "'": 39, k: 40, ',': 43, n: 45, m: 46, '.': 47, ' ': 49 };
const LEFT = new Set('qwertasdfgzxcvb');
const TEXT = ('The river ran low that summer, and the farms along it waited for rain. People spoke of the old floods as if ' +
  'they missed them. In the evenings we walked to the bridge and watched the water slide over the stones. ').repeat(3).toLowerCase();

function random(seed) { let s = seed >>> 0; return () => ((s = (s * 1664525 + 1013904223) >>> 0) / 2 ** 32); }
function normal(rand) { return Math.sqrt(-2 * Math.log(1 - rand())) * Math.cos(2 * Math.PI * rand()); }
/** Key events for TEXT: `gap(previous, char, i)` is the time to the next key going down, `hold(char)` how long it's held. */
function typeOut(gap, hold) {
  const events = []; let t = 1000, previous = null;
  for (const [i, ch] of [...TEXT].entries()) {
    const code = CODES[ch]; if (code === undefined) continue;
    t += previous === null ? 0 : gap(previous, ch, i);
    events.push([t, code, 'down'], [t + hold(ch), code, 'up']);
    previous = ch;
  }
  return events.sort((a, b) => a[0] - b[0] || (a[2] === 'up' ? -1 : 1));
}

test('keys sent all at once, or on a metronome, stop the recording at once', () => {
  const instant = analyse(typeOut(() => 0.1, () => 0.1));
  assert.ok(instant.blatant.includes('keys released instantly'));
  assert.ok(instant.blatant.includes('keys pressed faster than fingers move'));
  const metronome = analyse(typeOut(() => 120, () => 80));
  assert.ok(metronome.blatant.includes('a perfectly even rhythm'));
  assert.ok(metronome.blatant.includes('every key held the same time'));
});

test('random delays, however human their spread, ignore words and hands', () => {
  const rand = random(7);
  const jitter = analyse(typeOut(() => 170 * Math.exp(0.45 * normal(rand)), () => Math.max(30, 95 + 25 * normal(rand))));
  assert.deepEqual(jitter.blatant, []);
  assert.equal(jitter.signals.wordStarts, false);
  assert.equal(jitter.signals.hands, false);
  assert.ok(robotic(jitter.signals));
});

test('a rhythm modelled on people (slower word starts, faster across hands, rollover) passes: the limit of timing', () => {
  const rand = random(11);
  const careful = analyse(typeOut((previous, ch) => {
    let base = 150 * Math.exp(0.35 * normal(rand));
    if (previous === ' ') base *= 1.7;
    else if (ch !== ' ' && LEFT.has(previous) !== LEFT.has(ch)) base *= 0.75;
    return base;
  }, () => Math.max(35, 105 + 30 * normal(rand))));
  assert.deepEqual(careful.blatant, []);
  assert.equal(robotic(careful.signals), false);
  assert.equal(natural(careful.signals).met, natural(careful.signals).judged);
});

test('short stretches are never judged', () => {
  const few = analyse(typeOut(() => 0.1, () => 0.1).slice(0, 30));
  assert.deepEqual(few.blatant, []);
});

test('Shift moved in lockstep with its letter is blatant; a hand’s Shift comes early and leaves late', () => {
  const rand = random(11), gap = () => 90 + 120 * rand(), hold = () => 60 + 40 * rand();
  // Key events for a text with capitals: Shift (56) around each capital, `lead` ms before it and `trail` ms after it.
  const capitals = (lead, trail) => {
    const events = []; let t = 1000;
    for (const ch of 'The Quick Brown Fox Jumps Over The Lazy Dog And Runs Far Away From Here Today'.repeat(2)) {
      const code = CODES[ch.toLowerCase()]; if (code === undefined) continue;
      t += gap(); const upper = ch !== ch.toLowerCase(), h = hold();
      if (upper) events.push([t - lead(), 56, 'down']);
      events.push([t, code, 'down'], [t + h, code, 'up']);
      if (upper) events.push([t + h + trail(), 56, 'up']);
    }
    return events.sort((a, b) => a[0] - b[0]);
  };
  const scripted = analyse(capitals(() => 1, () => 1));
  assert.ok(scripted.blatant.includes('the Shift key moved in lockstep with its letter'), JSON.stringify(scripted.measures));
  const hand = analyse(capitals(() => 40 + 160 * rand(), () => 20 + 100 * rand()));
  assert.equal(hand.blatant.length, 0);
  assert.ok(hand.measures.shiftLead >= 40 && hand.measures.shiftTrail >= 20);
});

test('gaps spread flat with no rollover and no sign of words or hands are robotic; a skewed spread is a person’s', () => {
  const rand = random(12);
  // Every gap between 60 and 190 ms equally likely, holds 30 to 80 ms, keys never overlapping: a scripted browser.
  const flat = analyse(typeOut(() => 60 + 130 * rand(), () => 30 + 50 * rand()));
  assert.equal(flat.signals.spread, false, JSON.stringify(flat.measures));
  assert.equal(flat.signals.rollover, false);
  assert.ok(robotic(flat.signals), JSON.stringify(flat.signals));
  // The same keys at a hand's skewed pace (log-normal), slower at word starts and from one hand: never robotic.
  const r2 = random(13), hand = analyse(typeOut((p, c) => 110 * Math.exp(0.45 * normal(r2)) * (p === ' ' ? 1.6 : 1) * (LEFT.has(p) === LEFT.has(c) ? 1.25 : 1), () => 80 + 30 * normal(r2)));
  assert.equal(hand.signals.spread, true, JSON.stringify(hand.measures));
  assert.equal(robotic(hand.signals), false);
});
