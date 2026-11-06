import test from 'node:test';
import assert from 'node:assert/strict';
import { analyse, robotic } from '../write/typing.mjs';
import { odd, oddTyping, retypePhrase, judgeRetype, retypeCheck, MISTYPED } from '../write/retype.mjs';

const CODES = { a: 0, s: 1, d: 2, f: 3, h: 4, g: 5, z: 6, x: 7, c: 8, v: 9, b: 11, q: 12, w: 13, e: 14, r: 15, y: 16, t: 17, o: 31, u: 32,
  i: 34, p: 35, l: 37, j: 38, "'": 39, k: 40, ',': 43, n: 45, m: 46, '.': 47, ' ': 49 };
const NAMES = Object.fromEntries(Object.entries(CODES).map(([ch]) => [ch, ch === ' ' ? 'Space' : ch === '.' ? 'Period' : ch === ',' ? 'Comma' : ch === "'" ? 'Quote' : 'Key' + ch.toUpperCase()]));
const LEFT = new Set('qwertasdfgzxcvb');
const TEXT = ('The river ran low that summer, and the farms along it waited for rain. People spoke of the old floods as if ' +
  'they missed them. In the evenings we walked to the bridge and watched the water slide over the stones. ').repeat(3).toLowerCase();

function random(seed) { let s = seed >>> 0; return () => ((s = (s * 1664525 + 1013904223) >>> 0) / 2 ** 32); }
function normal(rand) { return Math.sqrt(-2 * Math.log(1 - rand())) * Math.cos(2 * Math.PI * rand()); }
/** Key events for `text`, starting at `t`: `gap(previous, char)` to the next key going down, `hold(char)` how long it's held. */
function typeOut(text, gap, hold, t = 1000) {
  const events = []; let previous = null;
  for (const ch of text) {
    const code = CODES[ch]; if (code === undefined) continue;
    t += previous === null ? 0 : gap(previous, ch);
    events.push([t, code, 'down', ch], [t + hold(ch), code, 'up', ch]);
    previous = ch;
  }
  return events.sort((a, b) => a[0] - b[0] || (a[2] === 'up' ? -1 : 1));
}
/** A person, as typing.test.mjs models one: slower word starts, faster across hands, holds that vary. */
const person = (seed, text = TEXT, t) => {
  const rand = random(seed);
  return typeOut(text, (previous, ch) => {
    let base = 150 * Math.exp(0.35 * normal(rand));
    if (previous === ' ') base *= 1.7; else if (ch !== ' ' && LEFT.has(previous) !== LEFT.has(ch)) base *= 0.75;
    return base;
  }, () => Math.max(35, 105 + 30 * normal(rand)), t);
};

test('people’s typing never looks odd; smooth software does', () => {
  for (let seed = 1; seed <= 40; seed++) assert.equal(oddTyping(person(seed)), null, `seed ${seed}`);
  const rand = random(3);
  // Gaps of 130 ± 18 ms and holds of 80 ± 5: not blatant (typing.mjs), but no hand is that steady.
  const smooth = typeOut(TEXT, () => 130 + 18 * normal(rand), () => 80 + 5 * normal(rand));
  assert.deepEqual(analyse(smooth).blatant, []);
  assert.equal(oddTyping(smooth), 'a very even rhythm');
  const steadyHolds = typeOut(TEXT, () => 160 * Math.exp(0.5 * normal(rand)), () => 90 + 6 * normal(rand));
  assert.deepEqual(analyse(steadyHolds).blatant, []);
  assert.equal(oddTyping(steadyHolds), 'keys held for about the same time');
  // Faster across hands, as people are, but quicker at word starts than inside words: not robotic, still odd.
  const handsOnly = typeOut(TEXT, (previous, ch) => 150 * Math.exp(0.35 * normal(rand)) * (previous === ' ' ? 0.75 : ch !== ' ' && LEFT.has(previous) !== LEFT.has(ch) ? 0.7 : 1),
    () => Math.max(35, 105 + 30 * normal(rand)));
  assert.equal(robotic(analyse(handsOnly).signals), false);
  assert.equal(oddTyping(handsOnly), 'words started no slower than letters');
  // Too little to judge, and blatant typing left to typing.mjs.
  assert.equal(oddTyping(smooth.slice(0, 120)), null);
  assert.equal(odd(analyse(typeOut(TEXT, () => 120, () => 80))), null);
});

test('phrases are four or five different common words', () => {
  const rand = random(9);
  for (let i = 0; i < 200; i++) {
    const words = retypePhrase(rand).split(' ');
    assert.ok(words.length === 4 || words.length === 5);
    assert.equal(new Set(words).size, words.length);
    assert.ok(words.every(w => /^[a-z]+$/.test(w)));
  }
});

test('a retyped phrase passes as a person types it, and fails as drivers type it', () => {
  const phrase = 'quiet river under stone';
  for (let seed = 1; seed <= 40; seed++) assert.equal(judgeRetype(phrase, phrase, person(seed, phrase), 0), null, `seed ${seed}`);
  // Case and spacing don't matter; the words do.
  assert.equal(judgeRetype(phrase, '  Quiet  river under Stone ', person(1, phrase), 0), null);
  assert.equal(judgeRetype(phrase, 'quiet river under stones', person(1, phrase), 0), MISTYPED);
  // Set by a script, or pasted: no key presses.
  assert.equal(judgeRetype(phrase, phrase, [], 0), 'the words weren’t typed');
  // Typed the moment it showed.
  assert.equal(judgeRetype(phrase, phrase, person(1, phrase, 1100), 1000), 'typing began before the words could be read');
  // Puppeteer's and Playwright's type(): with no delay, keys released at once; with { delay: 100 }, every key held 100 ms.
  assert.equal(judgeRetype(phrase, phrase, typeOut(phrase, () => 0.4, () => 0.1), 0), 'keys released instantly');
  const rand = random(5);
  assert.equal(judgeRetype(phrase, phrase, typeOut(phrase, () => 200 + 2 * rand(), () => 100 + 2 * rand()), 0), 'every key held the same time');
  // xdotool: 12 ms between keys, held for none.
  assert.equal(judgeRetype(phrase, phrase, typeOut(phrase, () => 12, () => 0.5), 0), 'keys released instantly');
  // Key downs only (a repeated letter then reads as a key still held).
  assert.equal(judgeRetype(phrase, phrase, person(1, phrase).filter(e => e[2] === 'down'), 0), 'the words weren’t typed');
  assert.equal(judgeRetype('lamp cloud fish', 'lamp cloud fish', person(1, 'lamp cloud fish').filter(e => e[2] === 'down'), 0), 'keys released at once');
  // Random holds, but gaps on a beat.
  assert.equal(judgeRetype(phrase, phrase, typeOut(phrase, () => 150 + rand(), () => 60 + 60 * rand()), 0), 'a perfectly even rhythm');
});

// The dialog, with stand-ins for its elements.
class Target {
  listeners = {};
  addEventListener(type, f) { (this.listeners[type] ??= new Set()).add(f); }
  removeEventListener(type, f) { this.listeners[type]?.delete(f); }
  fire(type, props = {}) { const e = { type, isTrusted: true, preventDefault() { this.prevented = true; }, ...props }; for (const f of this.listeners[type] ?? []) f(e); return e; }
}
function parts() {
  const dialog = Object.assign(new Target(), { open: false, showModal() { this.open = true; }, close() { this.open = false; this.fire('close'); } });
  const input = Object.assign(new Target(), { value: '', focus() {} });
  return { dialog, input, phraseEl: { textContent: '' }, note: { textContent: '' }, go: new Target(), cancel: new Target(), random: random(2), now: () => 0 };
}
/** Types the phrase shown into the input as `events` would, through the input's own key events. */
function typeInto(p, events, trusted = true) {
  for (const [t, , kind, ch] of events) {
    p.input.fire(kind === 'down' ? 'keydown' : 'keyup', { isTrusted: trusted, timeStamp: t, code: NAMES[ch], key: ch });
    if (kind === 'down') p.input.value += ch;
  }
}

test('the retype dialog passes a person, and gives new words after a slip', async () => {
  const p = parts(), checked = retypeCheck(p);
  assert.ok(p.dialog.open);
  typeInto(p, person(4, 'wrong words entirely here'));
  p.go.fire('click');
  assert.equal(p.note.textContent, 'Those didn’t match. Type these.');
  assert.equal(p.input.value, '');
  typeInto(p, person(4, p.phraseEl.textContent));
  const enter = p.input.fire('keydown', { key: 'Enter', code: 'Enter', timeStamp: 1e6 });
  assert.ok(enter.prevented);
  assert.equal(await checked, 'passed');
  assert.equal(p.dialog.open, false);
  assert.equal(p.input.listeners.keydown.size, 0);
});

test('the retype dialog fails keys a script sends, and pastes', async () => {
  const p = parts(), checked = retypeCheck({ ...p, attempts: 2 });
  typeInto(p, person(4, p.phraseEl.textContent), false); // untrusted: ignored, so the words weren't typed
  p.go.fire('click');
  assert.ok(p.input.fire('paste').prevented);
  p.input.value = p.phraseEl.textContent;
  p.go.fire('click');
  assert.equal(await checked, 'failed');
});

test('the retype dialog is cancelled by Cancel, Escape or being closed', async () => {
  for (const close of [p => p.cancel.fire('click'), p => p.dialog.fire('cancel'), p => p.dialog.close()]) {
    const p = parts(), checked = retypeCheck(p);
    close(p);
    assert.equal(await checked, 'cancelled');
  }
});
