// When typing looks odd but not impossible (typing.mjs stops a recording only for typing no person can produce), the
// writer retypes a few common words: exact words, typed by keys whose timing looks like a hand's. Simple drivers fail it
// at once (Puppeteer's and Playwright's typing hold every key for the same time, or none; xdotool's barely at all);
// a careful one can pass, as it can pass the typing checks.
import { analyse } from './typing.mjs';
import { keyCode } from './keys.mjs';

const WORDS = ('apple autumn basket beach bell blue boat book bread bridge bright brown cake calm candle chair cloud coat ' +
  'coffee corner cotton cup daisy dinner door dream early earth evening field fire flower forest friend garden gentle glass ' +
  'gold grass green happy harbor hill honey house island kettle kind lamp leaf lemon letter light little meadow milk moon ' +
  'morning music narrow night ocean orange paper park pencil pepper pillow plain quiet rain river road rock round salt sand ' +
  'school shell silver simple slow small smooth snow soft song spring star stone story summer sun table tall tea tiny town ' +
  'tree valley warm water window winter wood yellow').split(' ');
const randomUnit = () => crypto.getRandomValues(new Uint32Array(1))[0] / 2 ** 32;
const tidy = text => text.toLowerCase().trim().split(/\s+/).join(' ');

/** Four or five different common words, lowercase. */
export function retypePhrase(random = randomUnit) {
  const pool = [...WORDS], words = [];
  for (let n = random() < 0.5 ? 4 : 5; words.length < n;) words.push(pool.splice(Math.floor(random() * pool.length), 1)[0]);
  return words.join(' ');
}

/**
 * Typing that looks odd, though not blatantly so, from an analyse() result: a reason, or null. Thresholds sit well
 * inside what people type (gaps vary 40–100% around their middle, holds 20–45%; word starts come clearly slower), and
 * well short of typing.mjs's blatant ones, which stop the recording. Judged only with 80 key presses or more.
 */
export function odd({ measures: m, blatant }) {
  if (blatant.length || m.keys < 80) return null;
  if (m.instantHolds >= 0.2) return 'keys released almost at once';
  if (m.instantGaps >= 0.25) return 'keys pressed almost together';
  if ((m.gapVariation !== null && m.gapVariation < 0.2) || m.evenGaps >= 0.25) return 'a very even rhythm';
  if (m.holdVariation !== null && m.holdVariation < 0.1) return 'keys held for about the same time';
  // People pause before a word; random delays don't. With 300 keys (some 50 words) a person's shows clearly.
  if (m.keys >= 300 && m.wordStartShift !== null && m.wordStartShift < 0.5) return 'words started no slower than letters';
  return null;
}
/** The same, from key events `[ms, key code, 'down' | 'up']`. */
export const oddTyping = events => odd(analyse(events));

/** The reason given when the words typed aren't the words shown. */
export const MISTYPED = 'the words didn’t match';
/**
 * Whether `typed` is `phrase` (case and spacing aside), typed by the key events `events` as a person types: null when it
 * is, otherwise the reason. `shown` is when the phrase appeared, on the events' clock.
 */
export function judgeRetype(phrase, typed, events, shown = null) {
  if (tidy(typed) !== tidy(phrase)) return MISTYPED;
  const { measures: m, blatant } = analyse(events);
  const ups = events.filter(e => e[2] === 'up').length, first = events.find(e => e[2] === 'down')?.[0];
  // Every letter needs its key press: pasted, filled in or set by a script, the words come without.
  if (m.keys < phrase.replace(/\s/g, '').length) return 'the words weren’t typed';
  // Reading four words takes a person longer than this.
  if (shown !== null && first - shown < 250) return 'typing began before the words could be read';
  if (blatant.length) return blatant[0];
  if (ups < m.keys / 2 || m.holdTime < 20 || m.instantHolds >= 0.25) return 'keys released at once';
  if (m.holdVariation !== null && m.holdVariation < 0.08) return 'every key held the same time';
  if (m.typingGap < 35 || m.instantGaps >= 0.25) return 'keys pressed faster than fingers move';
  if ((m.gapVariation !== null && m.gapVariation < 0.15) || m.evenGaps >= 0.4) return 'a perfectly even rhythm';
  return null;
}

/**
 * Shows `dialog` with a phrase in `phraseEl` for the writer to type into `input`, then Continue (`go`) or Enter.
 * Only trusted key presses with a key code count; pasting and dropping are refused. Words that don't match, or
 * timing that doesn't look like a hand's, get new words, `attempts` times in all. Resolves 'passed', 'failed' or
 * 'cancelled' (Cancel, Escape, or the dialog closed by anything else).
 */
export function retypeCheck({ dialog, phraseEl, input, go, cancel, note, attempts = 3, random = randomUnit, now = () => performance.now() }) {
  return new Promise(resolve => {
    let phrase, log, shown, tries = 0, settled = false;
    const fresh = message => {
      phrase = retypePhrase(random); phraseEl.textContent = phrase; input.value = ''; log = []; shown = now();
      if (note) note.textContent = message;
      input.focus();
    };
    const key = kind => e => {
      if (!e.isTrusted) return;
      if (kind === 'down' && e.key === 'Enter') { e.preventDefault(); submit(); return; }
      if (!e.code || e.key === 'Unidentified' || (kind === 'down' && e.repeat)) return;
      log.push([e.timeStamp, keyCode(e.code), kind]);
    };
    const refuse = e => e.preventDefault();
    const listeners = [[input, 'keydown', key('down')], [input, 'keyup', key('up')], [input, 'paste', refuse], [input, 'drop', refuse],
      [go, 'click', () => submit()], [cancel, 'click', () => end('cancelled')], [dialog, 'cancel', e => { e.preventDefault(); end('cancelled'); }],
      [dialog, 'close', () => end('cancelled')]];
    function end(outcome) {
      if (settled) return; settled = true;
      for (const [target, type, listener] of listeners) target?.removeEventListener(type, listener);
      if (dialog.open) dialog.close();
      resolve(outcome);
    }
    function submit() {
      if (settled || !input.value.trim()) return;
      const reason = judgeRetype(phrase, input.value, log, shown);
      if (!reason) end('passed');
      else if (++tries >= attempts) end('failed');
      else fresh(reason === MISTYPED ? 'Those didn’t match. Type these.' : 'Type these instead.');
    }
    for (const [target, type, listener] of listeners) target?.addEventListener(type, listener);
    dialog.showModal();
    fresh('');
  });
}
