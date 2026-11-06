// Synthetic writing sessions, in the shape the server sees (a stream of editor events with their batches, the replay's
// frames, the text): a model of a person at a keyboard, and the ways software types. The unit tests use them to check
// that each feature separates the two in the expected direction, and the evaluation harness (report.mjs) uses them as
// a sanity set beside real sessions. None of this is real data: a model of a person is only as good as its author's
// knowledge of typing, which is why the acceptance numbers come from recorded sessions.
import { mean } from '../stats.mjs';

export function random(seed) { let s = (seed >>> 0) || 1; const next = () => ((s = (s * 1664525 + 1013904223) >>> 0) / 2 ** 32); next.normal = () => Math.sqrt(-2 * Math.log(1 - next())) * Math.cos(2 * Math.PI * next()); next.lognormal = (median, sigma) => median * Math.exp(sigma * next.normal()); next.uniform = (lo, hi) => lo + (hi - lo) * next(); next.pick = list => list[Math.floor(next() * list.length)]; return next; }

import { baseKey, codeOf, needsShift, adjacent, neighbour, fingerLatency } from '../keyboard.mjs';
export { baseKey, codeOf, needsShift, adjacent, neighbour, fingerLatency };

export const SAMPLE_TEXT = 'The river ran low that summer, and the farms along it waited for rain. People spoke of the old floods as if they missed them. ' +
  'In the evenings we walked to the bridge and watched the water slide over the stones. My father said the fish had gone downstream to find deeper pools, and that they would come back when the weather turned. ' +
  'Nobody believed him, but nobody argued either. We counted the days by the height of the grass on the bank, and by the number of times the old dog went down to drink and came back with nothing to show for it.\n' +
  'By August the bridge stood over a bed of pale rocks. Children played where the current had been, building walls that no water would ever test. The older people stayed away from it. ' +
  'They said a dry river was worse than a flooded one, because a flood at least told you something had happened. A dry bed only told you what had stopped.\n' +
  'When the rain finally came it fell for three days without pause. We stood at the window and watched the yard fill, then the road, then the field beyond it. ' +
  'The river came back all at once, brown and loud, carrying branches and a chair from somewhere upstream. My father went down to the bridge and stood there a long time. When he came back he said nothing, and we asked nothing.';
/** A second text, so a replayed person's timings come from different words than they're laid over. */
export const OTHER_TEXT = 'Every morning the baker opened the shutters before the street lamps went out. He had done it for thirty years and saw no reason to stop. ' +
  'The ovens were older than he was, and he spoke to them the way other men speak to dogs. By seven the first loaves were on the counter, and by eight the queue reached the corner. ' +
  'Nobody in the town could say what made the bread different. The flour came from the same mill as everyone else\u2019s. The water came from the same tap. ' +
  'When asked, the baker shrugged and said that bread knows when you are in a hurry. His daughter, who kept the accounts, said it was the price.\n' +
  'In the winter the shop was the warmest room in the street, and people came in who had no intention of buying anything. He let them stand by the oven door and did not mind. ' +
  'Some of them had been coming for decades. He knew their names and the names of their children, and he knew which of them could not pay and would not ask. ' +
  'Those loaves were marked in the book with a small cross, and the book was never shown to anyone, not even the daughter.';
const FILLERS = ['really', 'quietly', 'almost', 'suddenly', 'later', 'again', 'perhaps', 'slowly', 'somehow', 'finally'];

/**
 * Types `text` under `model`, producing the stream's events (seq-numbered, in time order), the replay's frames and the
 * final text. `started`: the recording's start on the page's clock (frames count from it). The model:
 *   gap(prev, ch, i) ms to the next key; hold(ch) dwell; shift: 'keys' (a Shift key press around the letter, with
 *   lead() and trail()), 'flag' (shiftKey set, no Shift key), 'none' (neither); pause(prev, ch, i) extra ms before
 *   a key, or 0; typo(i) null or { fixAfter }; rewrite(word) a word to replace one just typed, or null; revise(i)
 *   true to go back and insert a word; insertText: true types nothing, inserting chunks with no keys;
 *   chunk(): characters per chunk and the pause after it, for an agent loop; modality: 'physical_keyboard' | 'touch' | 'ime'.
 */
export function simulateTyping(text, model, { seed = 1, started = 500, startAt = 2500, trusted = true } = {}) {
  const rand = random(seed), events = [], frames = [];
  const doc = []; let caret = 0, t = startAt, lastDown = startAt, lastUp = startAt, chunkLeft = model.chunk ? model.chunk().size : Infinity;
  // When each key's release is due: a keyboard can't press a key that's still down, so a repeat of the same key
  // releases it first (a hand lifts and strikes again).
  const heldUntil = new Map();
  const modality = model.modality ?? 'physical_keyboard';
  const push = e => events.push({ trusted, ...e });
  const frame = (time, kind, location, length, inserted) => frames.push({ time: Math.max(0, Math.round(time - started)), kind, location, length, inserted });
  /** One key press that inserts `ch` at the caret (or deletes before it, for Backspace), at time `at`. */
  function key(ch, at, { shifted = false } = {}) {
    const backspace = ch === '\b', code = backspace ? 'Backspace' : codeOf(ch);
    let hold = model.hold(ch, rand);
    if (heldUntil.get(code) >= at) { const early = events.find(e => e.ev === 'ku' && e.code === code && e.t === heldUntil.get(code)); if (early) early.t = at - 1; }
    heldUntil.set(code, at + hold);
    if (modality === 'touch') push({ ev: 'kd', t: at, code: '', key: 'Unidentified', kc: 229, shift: false, mod: 0, rep: false, comp: false });
    else if (modality !== 'ime') {
      if (shifted && model.shift === 'keys') push({ ev: 'kd', t: at - model.lead(rand), code: 'ShiftLeft', key: 'Shift', kc: 16, shift: true, mod: 0, rep: false, comp: false });
      push({ ev: 'kd', t: at, code, key: backspace ? 'Backspace' : ch === '\n' ? 'Enter' : ch, kc: backspace ? 8 : ch.toUpperCase().charCodeAt(0), shift: shifted && model.shift !== 'none', mod: 0, rep: false, comp: false });
    }
    if (backspace) {
      push({ ev: 'bi', t: at + 1, it: 'deleteContentBackward', data: null, comp: false, caret: caret + 1, size: doc.length + 2 });
      if (caret > 0) { doc.splice(caret - 1, 1); caret--; frame(at + 2, 'typing-external', caret, 1, ''); }
    } else {
      push({ ev: 'bi', t: at + 1, it: 'insertText', data: ch, comp: false, caret: caret + 1, size: doc.length + 2 });
      doc.splice(caret, 0, ch); frame(at + 2, 'typing-external', caret, 0, ch); caret++;
    }
    if (modality === 'physical_keyboard') {
      push({ ev: 'ku', t: at + hold, code, key: backspace ? 'Backspace' : ch, shift: shifted && model.shift !== 'none', comp: false });
      if (shifted && model.shift === 'keys') push({ ev: 'ku', t: at + hold + model.trail(rand), code: 'ShiftLeft', key: 'Shift', shift: false, comp: false });
    } else if (modality === 'touch') push({ ev: 'ku', t: at + 1, code: '', key: 'Unidentified', shift: false, comp: false });
    lastDown = at; lastUp = Math.max(lastUp, at + hold);
  }
  /** Moves the caret with a click at a text position (a jump, on the page). */
  function clickTo(position, at) {
    const x = 200 + (position % 70) * 8, y = 150 + Math.floor(position / 70) * 20;
    if (model.pointer === 'human') movePointer(events, rand, at - 700, at, x, y);
    push({ ev: 'pd', t: at, x, y, pt: 'mouse', inside: true }); push({ ev: 'pu', t: at + 90, x, y, pt: 'mouse', inside: true });
    push({ ev: 'sc', t: at + 2, hidden: false, focused: true });
    caret = position;
  }
  // A composed word (input method): keys with keyCode 229, composition text, one frame at the end.
  function compose(word, at) {
    push({ ev: 'cs', t: at });
    let time = at;
    for (const ch of word) {
      time += model.gap(' ', ch, 0, rand);
      push({ ev: 'kd', t: time, code: codeOf(ch), key: 'Process', kc: 229, shift: false, mod: 0, rep: false, comp: true });
      push({ ev: 'bi', t: time + 1, it: 'insertCompositionText', data: word.slice(0, [...word].indexOf(ch) + 1), comp: true, caret: caret + 1, size: doc.length + 2 });
      push({ ev: 'ku', t: time + model.hold(ch, rand), code: codeOf(ch), key: 'Process', shift: false, comp: true });
    }
    time += model.gap(' ', ' ', 0, rand);
    push({ ev: 'ce', t: time, data: word });
    for (const ch of word) doc.splice(caret++, 0, ch);
    frame(time + 2, 'input-method', caret - word.length, 0, word);
    lastDown = time; lastUp = time;
    return time;
  }
  if (model.pointer === 'human') { movePointer(events, rand, startAt - 1500, startAt - 400, 420, 300); push({ ev: 'pd', t: startAt - 380, x: 420, y: 300, pt: 'mouse', inside: true }); push({ ev: 'pu', t: startAt - 300, x: 420, y: 300, pt: 'mouse', inside: true }); }
  else if (model.pointer === 'teleport') { push({ ev: 'pd', t: startAt - 380, x: 420, y: 300, pt: 'mouse', inside: true }); push({ ev: 'pu', t: startAt - 379, x: 420, y: 300, pt: 'mouse', inside: true }); }
  push({ ev: 'focus', t: startAt - 2000, hidden: false, focused: true });
  const chars = [...text];
  let pendingFix = null, word = '', prev = ' ';
  if (model.insertText) {
    // Software inserting text with no keys: chunks of words, every so often.
    let at = startAt, from = 0;
    while (from < chars.length) {
      const size = Math.min(chars.length - from, Math.round(rand.uniform(20, 160))), chunk = chars.slice(from, from + size).join('');
      push({ ev: 'bi', t: at, it: 'insertText', data: chunk.slice(0, 200), comp: false, caret: caret + 1, size: doc.length + 2 });
      for (const ch of chunk) doc.splice(caret++, 0, ch);
      frame(at + 2, 'typing-external', caret - size, 0, chunk);
      from += size; at += rand.uniform(300, 2500);
    }
    return finish(at);
  }
  for (let i = 0; i < chars.length; i++) {
    const ch = chars[i];
    if (modality === 'ime' && /\p{L}/u.test(ch)) {
      // Letters come as whole words through the input method.
      let j = i; while (j < chars.length && /\p{L}/u.test(chars[j])) j++;
      t = compose(chars.slice(i, j).join(''), lastDown + model.gap(prev, ch, i, rand) + (model.pause?.(prev, ch, i, rand) ?? 0));
      prev = chars[j - 1]; i = j - 1; continue;
    }
    let gap = model.gap(prev, ch, i, rand) + (model.pause?.(prev, ch, i, rand) ?? 0);
    if (--chunkLeft <= 0 && model.chunk) { const next = model.chunk(); gap += next.pause; chunkLeft = next.size; }
    t = lastDown + gap;
    const shifted = needsShift(ch), typo = !pendingFix && /[a-z]/.test(ch) ? model.typo?.(i, rand) : null;
    if (typo) { key(neighbour(ch, rand), t, { shifted }); pendingFix = { wrong: ch, typed: [], after: typo.fixAfter }; }
    else key(ch, t, { shifted });
    if (pendingFix && !typo) {
      pendingFix.typed.push(ch);
      if (pendingFix.typed.length >= pendingFix.after || ch === ' ' || i === chars.length - 1) {
        const back = pendingFix.typed.length + 1, retype = [pendingFix.wrong, ...pendingFix.typed];
        let at = lastDown + model.gap(ch, '\b', i, rand) * 1.6;
        for (let k = 0; k < back; k++) { key('\b', at); at += model.gap('\b', '\b', i, rand) * 0.8; }
        for (const c of retype) { key(c, at, { shifted: needsShift(c) }); at += model.gap(c, c, i, rand); }
        pendingFix = null;
      }
    }
    if (/[\s.,;:!?]/.test(ch)) {
      if (word && model.rewrite) {
        const other = model.rewrite(word, rand);
        if (other) {
          let at = lastDown + model.gap(ch, '\b', i, rand) * 2;
          for (let k = 0; k < word.length + 1; k++) { key('\b', at); at += model.gap('\b', '\b', i, rand) * 0.8; }
          for (const c of other + ch) { key(c, at, { shifted: needsShift(c) }); at += model.gap(c, c, i, rand); }
        }
      }
      word = '';
    } else word += ch;
    if (ch === '.' && model.revise?.(i, rand) && caret > 60) {
      // Back to an earlier word boundary to add a word, then to the end again.
      const spaces = doc.map((c, k) => (c === ' ' ? k : -1)).filter(k => k > 0 && k < caret - 40);
      if (spaces.length) {
        const to = rand.pick(spaces) + 1, end = caret;
        clickTo(to, lastDown + 1200 + rand.uniform(0, 800));
        let at = lastDown + 1500; const added = rand.pick(FILLERS) + ' ';
        for (const c of added) { key(c, at); at += model.gap(c, c, i, rand); }
        clickTo(end + added.length, at + 900);
        lastDown = at + 900;
      }
    }
    prev = ch;
  }
  return finish(lastUp + 100);
  function finish(at) {
    events.sort((a, b) => a.t - b.t || (a.ev === 'ku' ? 1 : 0) - (b.ev === 'ku' ? 1 : 0));
    events.forEach((e, s) => { e.s = s; });
    return { events, frames, text: doc.join(''), ended: at, started, meta: modelMeta(model) };
  }
}
/** Pointer samples from (x0, y0) at `from` to (x1, y1) at `to`: a minimum-jerk path with a hand's tremor and a small overshoot. */
export function movePointer(events, rand, from, to, x1, y1, { x0 = x1 - rand.uniform(80, 300), y0 = y1 - rand.uniform(-120, 120), straight = false } = {}) {
  const dt = 8, n = Math.max(8, Math.round((to - from) / dt)), dx = x1 - x0, dy = y1 - y0, len = Math.hypot(dx, dy) || 1;
  const nx = -dy / len, ny = dx / len;
  for (let i = 0; i <= n; i++) {
    const u = i / n, s = straight ? u : 10 * u ** 3 - 15 * u ** 4 + 6 * u ** 5, over = straight ? 0 : 0.06 * Math.sin(Math.PI * Math.min(1, u * 1.15)) ** 8;
    const tremor = straight ? 0 : 0.7 * Math.sin(2 * Math.PI * 10 * (from + u * (to - from)) / 1000) + 0.3 * rand.normal();
    events.push({ ev: 'pm', t: from + u * (to - from), x: x0 + dx * (s + over) + nx * tremor, y: y0 + dy * (s + over) + ny * tremor, pt: 'mouse', trusted: true });
  }
}
function modelMeta(model) {
  return { ua: model.ua ?? 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36', platform: 'MacIntel', lang: 'en-US',
    webdriver: model.webdriver ?? false, timer: model.timer ?? 0.005, coarse: model.modality === 'touch', touch: model.modality === 'touch', coi: true, cores: 8, origin: 1700000000000,
    consoleNative: model.consoleWrapped ? false : true, toStringNative: true };
}

/** The batches the stream keeps for `events`: every 2.5 s of the page's clock, received live (a little later each) or
 *  all at once (`burst`), with the server's clock starting at `serverStart`. */
export function toBatches(events, { live = true, serverStart = 1700000000000, flushMs = 2500, meta = null, trap = null, rand = random(99) } = {}) {
  const batches = [];
  if (!events.length) return batches;
  const first = events[0].t, last = events.at(-1).t;
  let index = 0;
  for (let at = first + flushMs; at - flushMs <= last; at += flushMs) {
    const slice = events.filter(e => e.t >= at - flushMs && e.t < at);
    const sentAt = at, receivedAt = live ? serverStart + sentAt + 40 + rand.uniform(0, 60) : serverStart + 5 * index;
    const batch = { index, sentAt, receivedAt, events: slice };
    if (index === 0 && meta) batch.meta = meta;
    if (index === 1 && trap) batch.trap = trap;
    batches.push(batch); index++;
  }
  return batches;
}
/** A whole session as the server sees one: stream, frames, text and the proof's claimed times. */
export function session(label, typed, { live = true, trap = null } = {}) {
  const batches = toBatches(typed.events, { live, meta: typed.meta, trap });
  const elapsed = Math.round(typed.ended - typed.started);
  return { label, modality: typed.meta.coarse ? 'touch' : 'physical_keyboard', stream: { batches, events: batches.flatMap(b => b.events), meta: typed.meta, trap, started: batches[0]?.receivedAt ?? null },
    frames: typed.frames, text: typed.text, journal: { elapsed: String(elapsed), start_unix: '1700000000000', end_unix: String(1700000000000 + elapsed) } };
}

// ---- Models ----------------------------------------------------------------------------------------------------
/** A person at a physical keyboard: latencies by the fingers involved, slower at word starts and before capitals,
 *  a slowly drifting tempo, pauses at sentence ends and to think, adjacent-key typos fixed after a varying number of
 *  keys, the odd rewritten word and inserted word, and a hand on the mouse. */
export function humanModel({ speed = 1, pauses = true, pointer = 'human', typos = 0.03, modality = 'physical_keyboard', tempoDrift = true } = {}) {
  let tempo = 1;
  return {
    modality, pointer,
    gap(prev, ch, i, rand) {
      // A tempo that wanders slowly (tiredness, attention), which is what gives a hand's gaps their long memory.
      if (tempoDrift) tempo = 0.99 * tempo + 0.01 * (1 + 2.5 * rand.normal());
      let base = fingerLatency(prev, ch) * speed * Math.max(0.5, tempo);
      if (prev === ' ') base *= 1.7;
      if (needsShift(ch)) base += 90;
      if (/[.,;!?]/.test(ch)) base *= 1.25;
      return base * Math.exp(0.33 * rand.normal());
    },
    hold: (ch, rand) => Math.max(35, (ch === ' ' ? 80 : 95) * Math.exp(0.28 * rand.normal())),
    shift: 'keys', lead: rand => rand.uniform(40, 220), trail: rand => rand.uniform(15, 140),
    pause: pauses ? (prev, ch, i, rand) => {
      if (/[.!?]/.test(prev) && ch === ' ') return rand() < 0.75 ? rand.lognormal(1400, 0.6) : 0;
      if (prev === ' ' && rand() < 0.02) return rand.lognormal(3500, 0.7);
      if (prev === ' ' && rand() < 0.1) return rand.lognormal(700, 0.5);
      if (prev === ',' && rand() < 0.4) return rand.lognormal(450, 0.5);
      return 0;
    } : null,
    typo: typos ? (i, rand) => (rand() < typos ? { fixAfter: rand() < 0.5 ? 1 : rand() < 0.7 ? Math.round(rand.uniform(2, 4)) : Math.round(rand.uniform(5, 9)) } : null) : null,
    rewrite: (word, rand) => (word.length >= 4 && rand() < 0.015 ? rand.pick(FILLERS.filter(f => f !== word)) : null),
    revise: (i, rand) => rand() < 0.12,
  };
}
/** Playwright's page.keyboard.type with a random delay: down and up back to back, uniform delays, capitals with no Shift. */
export const playwrightModel = () => ({ gap: (p, c, i, rand) => rand.uniform(30, 150), hold: (c, rand) => rand.uniform(0.5, 3), shift: 'none', pointer: 'none', webdriver: true });
/** CDP Input.insertText in chunks: no keys at all. */
export const insertTextModel = () => ({ insertText: true, gap: () => 0, hold: () => 0, shift: 'none', pointer: 'teleport' });
/** CDP dispatchKeyEvent with log-normal delays, Shift handling and adjacent-key typos fixed at once. */
export const humanizedModel = ({ typos = 0.03, pauses = true } = {}) => ({
  consoleWrapped: true,
  gap: (p, c, i, rand) => rand.lognormal(110, 0.5), hold: (c, rand) => rand.lognormal(75, 0.35), shift: 'keys', lead: rand => rand.uniform(20, 80), trail: rand => rand.uniform(10, 60),
  pause: pauses ? (p, c, i, rand) => (rand() < 0.015 ? rand.uniform(1000, 3000) : 0) : null,
  typo: typos ? (i, rand) => (rand() < typos ? { fixAfter: 1 } : null) : null, pointer: 'teleport' });
/** xdotool / osascript: the OS types with random sleeps; keys released at once; Shift in lockstep with its letter. */
export const osTypeModel = () => ({ gap: (p, c, i, rand) => 12 + rand.uniform(30, 130), hold: () => 1, shift: 'keys', lead: () => 0.5, trail: () => 0.5, pointer: 'none', timer: 0.005 });
/** A recorded person's timings replayed over different text: the rhythm no longer follows the words. */
export function replayModel(recordedGaps, recordedHolds) {
  let g = 0, h = 0;
  return { gap: () => recordedGaps[g++ % recordedGaps.length], hold: () => recordedHolds[h++ % recordedHolds.length], shift: 'keys', lead: rand => rand.uniform(40, 200), trail: rand => rand.uniform(15, 120), pointer: 'teleport' };
}
/** An agent loop: chunks typed quickly and smoothly, a long regular pause between them (act, look, think). */
export const agentLoopModel = (seed = 7) => {
  const base = humanizedModel({ typos: 0, pauses: false }), chunks = random(seed); let fresh = 0;
  return { ...base, gap: (p, c, i, rand) => rand.lognormal(fresh-- > 0 ? 70 : 100, 0.35),
    chunk: () => { fresh = 25; return { size: Math.round(chunks.uniform(60, 140)), pause: chunks.uniform(6000, 8500) }; } };
};
/** The gaps and holds a human model produced, for the replay model. */
export function recordedTimings(typed) {
  const downs = typed.events.filter(e => e.ev === 'kd' && e.code !== 'ShiftLeft'), gaps = [], holds = [];
  for (let i = 1; i < downs.length; i++) { const gap = downs[i].t - downs[i - 1].t; if (gap < 2000) gaps.push(gap); }
  const ups = new Map(typed.events.filter(e => e.ev === 'ku').map(e => [e.t + ':' + e.code, e]));
  for (const d of downs) { const up = typed.events.find(e => e.ev === 'ku' && e.code === d.code && e.t >= d.t); if (up) holds.push(up.t - d.t); }
  return { gaps: gaps.length ? gaps : [120], holds: holds.length ? holds : [90], meanGap: mean(gaps) };
}

/** Every generator the harness knows, each making a session for `text` from a seed. */
export const GENERATORS = {
  human: (text, seed, options = {}) => session('human', simulateTyping(text, humanModel(options), { seed })),
  human_touch: (text, seed) => session('human', simulateTyping(text, humanModel({ modality: 'touch', pointer: 'none', typos: 0.02 }), { seed })),
  human_ime: (text, seed) => session('human', simulateTyping(text, humanModel({ modality: 'ime', pointer: 'human', typos: 0 }), { seed })),
  playwright_type: (text, seed) => session('playwright_type', simulateTyping(text, playwrightModel(), { seed })),
  cdp_inserttext: (text, seed) => session('cdp_inserttext', simulateTyping(text, insertTextModel(), { seed })),
  cdp_dispatch_humanized: (text, seed) => session('cdp_dispatch_humanized', simulateTyping(text, humanizedModel(), { seed })),
  os_type: (text, seed) => session('os_type', simulateTyping(text, osTypeModel(), { seed })),
  replay_human: (text, seed) => { const recorded = recordedTimings(simulateTyping(text === OTHER_TEXT ? SAMPLE_TEXT : OTHER_TEXT, humanModel(), { seed: seed + 1000 })); return session('replay_human', simulateTyping(text, replayModel(recorded.gaps, recorded.holds), { seed })); },
  computer_use_agent: (text, seed) => session('computer_use_agent', simulateTyping(text, agentLoopModel(), { seed })),
  fabricated_post: (text, seed) => session('fabricated_post', simulateTyping(text, humanizedModel(), { seed }), { live: false }),
};
