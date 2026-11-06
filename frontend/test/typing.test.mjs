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
