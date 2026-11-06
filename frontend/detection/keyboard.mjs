// A US keyboard, for the features (typo adjacency) and the synthetic sessions: rows of keys, the characters Shift
// gives, codes, which keys sit next to which, and a hand's typical latency between two keys by the fingers involved.
// A US keyboard: rows of keys, the characters Shift gives, codes, and which keys sit next to which.
const ROWS = ['`1234567890-=', 'qwertyuiop[]\\', "asdfghjkl;'", 'zxcvbnm,./'];
const SHIFTED = { '~': '`', '!': '1', '@': '2', '#': '3', '$': '4', '%': '5', '^': '6', '&': '7', '*': '8', '(': '9', ')': '0', '_': '-', '+': '=', '{': '[', '}': ']', '|': '\\', ':': ';', '"': "'", '<': ',', '>': '.', '?': '/' };
const NAMES = { '`': 'Backquote', '-': 'Minus', '=': 'Equal', '[': 'BracketLeft', ']': 'BracketRight', '\\': 'Backslash', ';': 'Semicolon', "'": 'Quote', ',': 'Comma', '.': 'Period', '/': 'Slash', ' ': 'Space', '\n': 'Enter' };
const place = new Map();
ROWS.forEach((row, r) => [...row].forEach((ch, c) => place.set(ch, [r, c + (r === 2 ? 0.5 : r === 3 ? 1 : 0)])));
/** The unshifted key a character is on, lower case. */
export const baseKey = ch => SHIFTED[ch] ?? ch.toLowerCase();
export const codeOf = ch => { const k = baseKey(ch); return /^[a-z]$/.test(k) ? 'Key' + k.toUpperCase() : /^[0-9]$/.test(k) ? 'Digit' + k : NAMES[k] ?? 'Unidentified'; };
export const needsShift = ch => /^[A-Z]$/.test(ch) || ch in SHIFTED;
/** Whether two characters sit on neighbouring keys. */
export function adjacent(a, b) {
  const p = place.get(baseKey(a)), q = place.get(baseKey(b));
  return Boolean(p && q && Math.abs(p[0] - q[0]) <= 1 && Math.abs(p[1] - q[1]) <= 1.5 && !(p[0] === q[0] && p[1] === q[1]));
}
/** A neighbouring letter on the keyboard, for a typo. */
/** A neighbouring letter on the keyboard, for a typo; `rand.pick` chooses. */
export function neighbour(ch, rand) {
  const options = [...'abcdefghijklmnopqrstuvwxyz'].filter(k => k !== ch.toLowerCase() && adjacent(k, ch));
  return options.length ? rand.pick(options) : 'x';
}
const FINGER = new Map();
for (const [finger, keys] of [[0, 'qaz1'], [1, 'wsx2'], [2, 'edc3'], [3, 'rfvtgb45'], [4, 'yhnujm67'], [5, 'ik,8'], [6, 'ol.9'], [7, "p;/0-=[]'\\"]]) for (const k of keys) FINGER.set(k, finger);
const hand = ch => { const f = FINGER.get(baseKey(ch)); return f === undefined ? null : f < 4 ? 'L' : 'R'; };
/** A hand's typical latency between two characters, by the fingers involved (the shape of a bigram table). */
export function fingerLatency(prev, ch) {
  if (prev === ' ' || ch === ' ') return 150;
  const fp = FINGER.get(baseKey(prev)), fc = FINGER.get(baseKey(ch));
  if (fp === undefined || fc === undefined) return 190;
  if (fp === fc) return baseKey(prev) === baseKey(ch) ? 170 : 230;
  if (hand(prev) !== hand(ch)) return 115;
  return 160;
}

