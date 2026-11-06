// How typing looks: signals that tell a person at a keyboard from software sending keys, worked out from key presses
// alone (key codes, down and up, times in milliseconds), the way the Mac records them. No characters are needed: word
// and sentence starts come from the Space and full-stop keys, hands and fingers from where keys sit.
// Two outcomes: `blatant`, typing no person can produce (keys released in no time, a metronome's rhythm), for which a
// recording stops; and `signals`, the ways typing can look natural, which only count with enough key presses.

// Mac virtual key codes (ANSI) by finger: 0-3 left pinky to index, 4-7 right index to pinky, 8 thumbs.
const FINGER = new Map();
const place = (finger, codes) => codes.forEach(code => FINGER.set(code, finger));
place(0, [12, 0, 6, 50, 18]);            // Q A Z ` 1
place(1, [13, 1, 7, 19]);                // W S X 2
place(2, [14, 2, 8, 20]);                // E D C 3
place(3, [15, 3, 9, 17, 5, 11, 21, 23]); // R F V T G B 4 5
place(4, [16, 4, 45, 32, 38, 46, 22, 26]); // Y H N U J M 6 7
place(5, [34, 40, 43, 28]);              // I K , 8
place(6, [31, 37, 47, 25]);              // O L . 9
place(7, [35, 41, 44, 39, 33, 30, 42, 29, 27, 24]); // P ; / ' [ ] \ 0 - =
place(8, [49]);                          // Space
const SPACE = 49, BACKSPACE = 51, PERIOD = 47, RETURN = 36;
const MODIFIERS = new Set([54, 55, 56, 57, 58, 59, 60, 61, 62, 63]);
const hand = code => { const f = FINGER.get(code); return f === undefined || f === 8 ? null : f < 4 ? 'L' : 'R'; };

const median = values => { if (!values.length) return null; const s = [...values].sort((a, b) => a - b), m = s.length >> 1; return s.length % 2 ? s[m] : (s[m - 1] + s[m]) / 2; };
const mean = values => values.reduce((a, b) => a + b, 0) / values.length;
const cv = values => { if (values.length < 2) return null; const m = mean(values); return m ? Math.sqrt(mean(values.map(v => (v - m) ** 2))) / m : null; };
const share = (values, test) => (values.length ? values.filter(test).length / values.length : null);
/**
 * How strongly the values in `a` run larger than those in `b` (Mann-Whitney U, as a z-score): about 0 when they're
 * alike, as when delays are drawn at random; 2 or more when the difference is real. null when either is short.
 */
export function shift(a, b, min = 8) {
  if (a.length < min || b.length < min) return null;
  const all = [...a.map(v => [v, 0]), ...b.map(v => [v, 1])].sort((x, y) => x[0] - y[0]);
  let rankA = 0;
  for (let i = 0; i < all.length;) {
    let j = i; while (j < all.length && all[j][0] === all[i][0]) j++;
    const rank = (i + j + 1) / 2; // tied values share their average rank
    for (let k = i; k < j; k++) if (all[k][1] === 0) rankA += rank;
    i = j;
  }
  const n1 = a.length, n2 = b.length, u = rankA - n1 * (n1 + 1) / 2;
  return (u - n1 * n2 / 2) / Math.sqrt(n1 * n2 * (n1 + n2 + 1) / 12);
}

/** Typing at least this long is judged; shorter stretches say nothing either way. */
export const MIN_KEYS = 40;
/** The longest gap between two key presses that still counts as typing (longer ones are pauses to think). */
export const PAUSE = 2000;

/**
 * Signals from a list of key events `[elapsed ms, key code, 'down' | 'up']`, in order.
 * Returns the measures, the blatant reasons (empty when there are none), and the natural-typing signals.
 */
export function analyse(events) {
  const downs = [], dwells = [], held = new Map();
  let rolled = 0, rollable = 0;
  for (const [t, code, kind] of events) {
    if (MODIFIERS.has(code)) continue;
    if (kind === 'down') {
      if (held.has(code)) continue; // a held key's repeats
      // Another key still down when this one goes down: rollover, as fast typists do.
      if (downs.length && t - downs.at(-1).t < PAUSE) { rollable++; if (held.size) rolled++; }
      held.set(code, t); downs.push({ t, code });
    } else if (kind === 'up' && held.has(code)) {
      dwells.push(t - held.get(code)); held.delete(code);
    }
  }
  const gaps = [];
  for (let i = 1; i < downs.length; i++) {
    const gap = downs[i].t - downs[i - 1].t;
    if (gap < PAUSE) gaps.push({ gap, from: downs[i - 1].code, to: downs[i].code, before: downs[i - 2]?.code });
  }
  const iki = gaps.map(g => g.gap), typingGap = median(iki);
  // Gaps by what kind of key comes next: the first letter of a word, the first of a sentence, or one inside a word.
  const letter = code => FINGER.has(code) && code !== SPACE && !(code >= 18 && code <= 29);
  const inWord = gaps.filter(g => letter(g.from) && letter(g.to)).map(g => g.gap);
  const wordStart = gaps.filter(g => g.from === SPACE && letter(g.to) && g.before !== PERIOD).map(g => g.gap);
  const sentenceStart = gaps.filter(g => g.from === SPACE && g.before === PERIOD && letter(g.to)).map(g => g.gap);
  // Inside words: keys from alternate hands come faster than keys from one hand, and two from one finger slowest.
  const alternate = gaps.filter(g => letter(g.from) && letter(g.to) && hand(g.from) && hand(g.to) && hand(g.from) !== hand(g.to)).map(g => g.gap);
  const sameHand = gaps.filter(g => letter(g.from) && letter(g.to) && g.from !== g.to && hand(g.from) === hand(g.to) && FINGER.get(g.from) !== FINGER.get(g.to)).map(g => g.gap);
  const sameFinger = gaps.filter(g => letter(g.from) && letter(g.to) && g.from !== g.to && FINGER.get(g.from) === FINGER.get(g.to)).map(g => g.gap);
  const backspaces = downs.filter(d => d.code === BACKSPACE).length;
  const pauses = downs.slice(1).filter((d, i) => d.t - downs[i].t >= PAUSE).length;
  const ratio = (a, b, min) => (a.length >= min && b.length >= min ? median(a) / median(b) : null);
  const measures = {
    keys: downs.length, typingGap, gapVariation: cv(iki), holdTime: median(dwells), holdVariation: cv(dwells),
    instantHolds: share(dwells, d => d < 12), instantGaps: share(iki, g => g < 12),
    // A metronome: gaps within 3 ms of the usual gap.
    evenGaps: typingGap === null ? null : share(iki, g => Math.abs(g - typingGap) <= 3),
    rollover: rollable ? rolled / rollable : null,
    wordStart: ratio(wordStart, inWord, 8), sentenceStart: ratio(sentenceStart, inWord, 3),
    alternateHands: ratio(alternate, sameHand, 10), sameFinger: ratio(sameFinger, sameHand, 6),
    // The same two, as how sure the difference is: word starts slower than inside words; one hand slower than two.
    wordStartShift: shift(wordStart, inWord), handShift: shift(sameHand, alternate, 10),
    corrections: downs.length ? backspaces / downs.length : null, pauses,
  };
  const blatant = [];
  if (downs.length >= 20) {
    if (measures.instantHolds !== null && dwells.length >= 20 && measures.instantHolds >= 0.5) blatant.push('keys released instantly');
    if (measures.instantGaps >= 0.5) blatant.push('keys pressed faster than fingers move');
    if (iki.length >= 60 && (measures.evenGaps >= 0.6 || measures.gapVariation < 0.1)) blatant.push('a perfectly even rhythm');
    if (dwells.length >= 60 && measures.holdVariation !== null && measures.holdVariation < 0.05) blatant.push('every key held the same time');
  }
  // Natural typing, each a yes or no once there's enough of it (null until then, and while it's unclear).
  const clear = z => (z === null ? null : z >= 2 ? true : z < 1 ? false : null);
  const signals = {
    wordStarts: clear(measures.wordStartShift),
    hands: clear(measures.handShift),
    rollover: measures.rollover === null || downs.length < MIN_KEYS || typingGap > 160 ? null : measures.rollover >= 0.04,
    holds: measures.holdVariation === null || dwells.length < MIN_KEYS ? null : measures.holdVariation >= 0.15,
    rhythm: measures.gapVariation === null || iki.length < MIN_KEYS ? null : measures.gapVariation >= 0.3,
  };
  return { measures, blatant, signals };
}

/** Typing whose rhythm follows neither words nor hands, as delays drawn at random do: never a person's. */
export const robotic = signals => signals.wordStarts === false && signals.hands === false;

/** The natural-typing signals met and judged, as "met of judged". */
export function natural(signals) {
  const judged = Object.values(signals).filter(v => v !== null);
  return { met: judged.filter(Boolean).length, judged: judged.length };
}
