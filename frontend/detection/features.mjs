// The behavioural features of a writing session, from its streamed events (frontend/write/collector.mjs), its signed replay
// (replay-core.mjs) and its text: how the keys were pressed, how the rhythm runs, how it follows the words, whether it
// comes in an agent's act-look-think loop, and how the pointer moved. Each feature is a value with a confidence (how
// much of it there was to measure), or null where it doesn't apply: key physics on a touch keyboard, pointer kinematics
// with no mouse. The scoring (score.mjs) weighs them with thresholds.json. Nothing here is decisive on its own.
import { readFileSync } from 'node:fs';
import { describeSession, printable, MODIFIER_CODES, PAUSE_MS, nearest } from './session.mjs';
import { mean, cv, median, quantile, share, spearman, autocorrelation, shiftZ, linearFit, dfaHurst, exGaussianFit, logNormalKS, bandPowerShare, clamp } from './stats.mjs';
import { adjacent } from './keyboard.mjs';

const BIGRAMS = JSON.parse(readFileSync(new URL('./bigrams.json', import.meta.url), 'utf8')).latencies;
const WORDS = JSON.parse(readFileSync(new URL('./wordfreq.json', import.meta.url), 'utf8'));
const RANK = new Map(WORDS.ranked.map((w, i) => [w.toLowerCase(), i + 1]));
/** An estimate of a word's Zipf frequency (7 is "the"; 3 is rare). */
export const zipf = word => { const w = word.toLowerCase(), rank = RANK.get(w); return rank ? 7.8 - 1.15 * Math.log10(rank) : Math.max(2.5, 5.6 - 0.28 * (w.length - 4)); };
export const FEATURE_VERSION = 'features-1';
/** Every feature name, by section, in the order they're reported. */
export const FEATURES = Object.freeze({
  physics: ['dwell_mean', 'dwell_cv', 'missing_keyup_rate', 'rollover_rate', 'shift_mismatch_rate', 'code_key_mismatch', 'orphan_input_rate', 'untrusted_rate'],
  timing: ['iki_lag1_ac', 'iki_hurst', 'iki_exgauss_fit', 'iki_lognorm_ks', 'bigram_corr', 'quantization_score', 'drift_slope', 'window_stationarity'],
  content: ['word_onset_ratio', 'word_onset_shift', 'word_freq_corr', 'boundary_pause_ratio', 'linearity_ratio', 'revision_depth', 'correction_rate', 'typo_fix_latency', 'typo_fix_spread', 'typo_adjacency', 'semantic_rewrite_rate'],
  loop: ['pause_periodicity', 'burst_len_cv', 'burst_speed_after_long_pause', 'hidden_input_rate', 'preface_activity', 'copy_rate'],
  pointer: ['teleport_click_rate', 'path_straightness', 'jerk_profile', 'tremor_power', 'overshoot_rate', 'idle_pointer_ratio'],
  environment: ['webdriver', 'console_wrapped'],
});
const feature = (value, n, needed) => ({ value: value === null || value === undefined || Number.isNaN(value) ? null : value, confidence: value === null || value === undefined || Number.isNaN(value) ? 0 : clamp(n / needed, 0, 1), n });
const unavailable = () => ({ value: null, confidence: 0, n: 0 });
const SHIFTED_SYMBOLS = new Set('~!@#$%^&*()_+{}|:"<>?');

/**
 * `events`, `meta`: the stream. `frames`: the verified replay's frames. `text`: the page's text. Returns
 * { modality, features: { name: { value, confidence, n } }, windows: [{ from, to, iki_median, keys }], version }.
 */
export function extractFeatures({ events = [], meta = null, frames = [], text = '' } = {}) {
  const view = describeSession({ events, meta, frames });
  const typed = typedStream(view), features = {};
  Object.assign(features, view.modality === 'physical_keyboard' ? keyPhysics(view) : Object.fromEntries(FEATURES.physics.map(n => [n, unavailable()])));
  if (view.modality !== 'physical_keyboard') { features.orphan_input_rate = unavailable(); features.untrusted_rate = untrustedRate(view); }
  Object.assign(features, timing(typed, view));
  Object.assign(features, content(view, typed));
  Object.assign(features, agentLoop(view, typed));
  Object.assign(features, meta?.coarse ? Object.fromEntries(FEATURES.pointer.map(n => [n, unavailable()])) : pointerKinematics(view));
  features.webdriver = feature(meta?.webdriver === true ? 1 : meta?.webdriver === false ? 0 : null, 1, 1);
  // A console whose methods aren't the browser's own, or a Function.prototype.toString that isn't: something on the
  // page is hiding from the DevTools probe (write/automation.mjs), which a person's browser never needs to.
  features.console_wrapped = feature(meta?.consoleNative === false || meta?.toStringNative === false ? 1 : meta?.consoleNative === true ? 0 : null, 1, 1);
  return { modality: view.modality, features, windows: windows(typed), version: FEATURE_VERSION };
}

/** The characters as they were typed, with their times: key presses on a physical keyboard, else the input events. */
export function typedStream(view) {
  if (view.modality === 'physical_keyboard' || view.modality === 'mixed') {
    const keys = view.keydowns.filter(e => printable(e) && !e.comp).map(e => ({ t: e.t, ch: e.key, code: e.code }));
    if (keys.length >= 10 || view.modality === 'physical_keyboard') return keys;
  }
  return view.insertions.filter(e => e.data.length === 1).map(e => ({ t: e.t, ch: e.data, code: null }));
}
/** Inter-key intervals of the typed stream, pauses left out. */
export const intervals = typed => { const out = []; for (let i = 1; i < typed.length; i++) { const g = typed[i].t - typed[i - 1].t; if (g >= 0 && g < PAUSE_MS) out.push(g); } return out; };

// ---- 3.1 Key physics --------------------------------------------------------------------------------------------
export function keyPhysics(view) {
  const downs = view.keydowns.filter(e => !MODIFIER_CODES.has(e.code) && e.code), ups = view.keyups;
  // Each press matched to the first release of the same key after it.
  const upsByCode = new Map();
  for (const u of ups) { if (!upsByCode.has(u.code)) upsByCode.set(u.code, []); upsByCode.get(u.code).push(u.t); }
  for (const list of upsByCode.values()) list.sort((a, b) => a - b);
  const dwells = []; let missing = 0; const releases = [];
  for (const d of downs) {
    const list = upsByCode.get(d.code) ?? [];
    let lo = 0, hi = list.length; while (lo < hi) { const m = (lo + hi) >> 1; if (list[m] < d.t) lo = m + 1; else hi = m; }
    if (lo < list.length && list[lo] - d.t < 5000) { dwells.push(list[lo] - d.t); releases.push(list[lo]); } else { missing++; releases.push(null); }
  }
  let rolled = 0, rollable = 0;
  for (let i = 1; i < downs.length; i++) {
    if (downs[i].t - downs[i - 1].t >= PAUSE_MS) continue;
    rollable++; if (releases[i - 1] !== null && downs[i].t < releases[i - 1]) rolled++;
  }
  // Shift: a capital or shifted symbol needs the Shift flag and a Shift key held (unless Caps Lock was ever pressed).
  const shiftDowns = view.keydowns.filter(e => e.code === 'ShiftLeft' || e.code === 'ShiftRight').map(e => e.t).sort((a, b) => a - b);
  const shiftUps = ups.filter(e => e.code === 'ShiftLeft' || e.code === 'ShiftRight').map(e => e.t).sort((a, b) => a - b);
  const capsLock = view.keydowns.some(e => e.code === 'CapsLock');
  const shiftHeld = t => { const i = nearest(shiftDowns, t); if (i === null) return false; let k = i; while (k >= 0 && shiftDowns[k] > t) k--; if (k < 0) return false; const down = shiftDowns[k]; const j = nearest(shiftUps, down); let up = Infinity; for (let m = Math.max(0, (j ?? 0) - 2); m < shiftUps.length; m++) if (shiftUps[m] >= down) { up = shiftUps[m]; break; } return t >= down - 5 && t <= up + 5; };
  let shifted = 0, mismatched = 0;
  for (const d of downs) {
    if (typeof d.key !== 'string' || d.key.length !== 1) continue;
    const upper = /^[A-Z]$/.test(d.key) && !capsLock, symbol = SHIFTED_SYMBOLS.has(d.key);
    if (!upper && !symbol) continue;
    shifted++;
    if (d.shift === false || !shiftHeld(d.t)) mismatched++;
  }
  // Code and key: the same key (unshifted letter) must always come from the same code, and vice versa.
  const byCode = new Map(), byKey = new Map(); let pairs = 0, inconsistent = 0;
  for (const d of downs) {
    if (!/^[a-z]$/.test(d.key ?? '') || !/^Key[A-Z]$/.test(d.code)) continue;
    pairs++;
    if (byCode.has(d.code) && byCode.get(d.code) !== d.key) inconsistent++; else byCode.set(d.code, d.key);
    if (byKey.has(d.key) && byKey.get(d.key) !== d.code) inconsistent++; else byKey.set(d.key, d.code);
  }
  // Text inserted with no key press just before it (CDP insertText), compositions left out.
  const pressTimes = downs.map(d => d.t).sort((a, b) => a - b);
  let orphans = 0, inserts = 0;
  for (const e of view.insertions) {
    inserts++;
    const i = nearest(pressTimes, e.t); let k = i ?? -1; while (k >= 0 && pressTimes[k] > e.t + 2) k--;
    if (k < 0 || e.t - pressTimes[k] > 100) orphans++;
  }
  return {
    dwell_mean: feature(dwells.length ? mean(dwells) : null, dwells.length, 60),
    dwell_cv: feature(dwells.length >= 2 ? cv(dwells) : null, dwells.length, 60),
    missing_keyup_rate: feature(downs.length ? missing / downs.length : null, downs.length, 60),
    rollover_rate: feature(rollable ? rolled / rollable : null, rollable, 80),
    shift_mismatch_rate: feature(shifted ? mismatched / shifted : null, shifted, 5),
    code_key_mismatch: feature(pairs ? inconsistent / pairs : null, pairs, 60),
    orphan_input_rate: feature(inserts ? orphans / inserts : null, inserts, 40),
    untrusted_rate: untrustedRate(view),
  };
}
const untrustedRate = view => feature(view.events.length ? view.untrusted / view.events.length : null, view.events.length, 40);

// ---- 3.2 Timing ---------------------------------------------------------------------------------------------------
export function timing(typed, view) {
  const iki = intervals(typed), n = iki.length;
  const fit = n >= 30 ? exGaussianFit(iki) : null;
  // Each bigram's median latency against the reference table.
  const byBigram = new Map();
  for (let i = 1; i < typed.length; i++) {
    const a = typed[i - 1].ch.toLowerCase(), b = typed[i].ch.toLowerCase(), g = typed[i].t - typed[i - 1].t;
    if (g < 0 || g >= PAUSE_MS || !(a + b in BIGRAMS)) continue;
    if (!byBigram.has(a + b)) byBigram.set(a + b, []); byBigram.get(a + b).push(g);
  }
  const judged = [...byBigram].filter(([, g]) => g.length >= 3), ours = judged.map(([, g]) => median(g)), ref = judged.map(([k]) => BIGRAMS[k]);
  // Quantisation: only with a fine timer (0.1 ms or better); the share of gaps within 0.05 ms of a grid, above chance.
  let quantization = null;
  if (Number.isFinite(view.meta?.timer) && view.meta.timer <= 0.1 && n >= 60) {
    quantization = 0;
    for (const step of [1, 4, 8, 10, 15.625]) {
      const near = share(iki, g => { const r = g / step; return Math.abs(r - Math.round(r)) * step <= 0.05; }), chance = Math.min(1, 0.1 / step);
      quantization = Math.max(quantization, (near - chance) / (1 - chance));
    }
    quantization = clamp(quantization, 0, 1);
  }
  const w = windows(typed), medians = w.map(x => x.iki_median).filter(v => v !== null), overall = median(iki);
  const drift = medians.length >= 3 && overall ? linearFit(w.filter(x => x.iki_median !== null).map(x => x.from / 60000), medians)?.slope / overall : null;
  return {
    iki_lag1_ac: feature(n >= 30 ? autocorrelation(iki, 1) : null, n, 200),
    iki_hurst: feature(n >= 64 ? dfaHurst(iki) : null, n, 300),
    iki_exgauss_fit: feature(fit?.ks ?? null, n, 200),
    iki_lognorm_ks: feature(n >= 30 ? logNormalKS(iki) : null, n, 200),
    bigram_corr: feature(judged.length >= 8 ? spearman(ours, ref) : null, judged.length, 80),
    quantization_score: feature(quantization, quantization === null ? 0 : n, 200),
    drift_slope: feature(drift, medians.length, 8),
    window_stationarity: feature(medians.length >= 3 ? cv(medians) : null, medians.length, 8),
  };
}
/** Sixty-second windows of the typed stream: when, how many keys, the median gap. */
export function windows(typed, size = 60000) {
  if (!typed.length) return [];
  const out = [], start = typed[0].t;
  for (let from = start; from <= typed.at(-1).t; from += size) {
    const inside = typed.filter(k => k.t >= from && k.t < from + size), gaps = intervals(inside);
    out.push({ from: from - start, to: from - start + size, keys: inside.length, iki_median: gaps.length >= 10 ? median(gaps) : null });
  }
  return out;
}

// ---- 3.3 Content coupling -----------------------------------------------------------------------------------------
const isLetter = c => typeof c === 'string' && /\p{L}/u.test(c);
const isBoundary = c => c === undefined || /[\s.,;:!?"'()\n—–-]/.test(c);
export function content(view, typed) {
  // Runs of single typed characters in the replay (where the text and the caret are exact), with their gaps.
  const frames = view.frames, deleted = rebuildDeletions(frames), inWord = [], onset = [], onsetWords = [], pauses = [], depths = [], fixes = [], adjacency = [];
  let run = null, length = 0, insertIndex = [], sequence = 0, atEnd = 0, edits = 0, rewrites = 0, words = 0, deleting = null, typedCount = 0, deletions = 0;
  const typedKinds = new Set(['typing', 'typing-external']);
  /** A deletion run ends with what's typed in its place: a typo fixed, a word rewritten, or neither. */
  const closeDeletion = next => {
    if (!deleting) return;
    const { text, since, from } = deleting; deleting = null;
    if (!next || next.location !== from || !text.length) return;
    const wrong = text[0], right = next.inserted[0];
    if (text.trim().length >= 4 && /\p{L}{3,}/u.test(text) && right !== wrong) rewrites++;
    else if (isLetter(wrong) && isLetter(right) && wrong !== right) { fixes.push(since); adjacency.push(adjacent(wrong, right) ? 1 : 0); }
  };
  for (let i = 0; i < frames.length; i++) {
    const f = frames[i];
    if (typedKinds.has(f.kind) && f.length === 0 && typeof f.inserted === 'string' && f.inserted.length === 1) {
      closeDeletion(f);
      edits++; typedCount++;
      if (f.location === length) atEnd++; else depths.push(length - f.location);
      const ch = f.inserted;
      if (run && f.location === run.end) {
        const gap = f.time - run.last;
        if (run.counts && gap < PAUSE_MS) {
          if (isLetter(ch) && isLetter(run.prev)) inWord.push(gap);
          else if (isLetter(ch) && run.prev === ' ' && isLetter(run.prev2)) { onset.push(gap); onsetWords.push({ at: onset.length - 1, word: ch }); }
        }
        if (run.counts && gap >= 500) pauses.push({ gap, boundary: isBoundary(run.prev) });
        if (onsetWords.length && isLetter(ch) && run.prev !== ' ' && onsetWords.at(-1).open) onsetWords.at(-1).word += ch;
        if (!isLetter(ch) && onsetWords.length) onsetWords.at(-1).open = false;
        if (isLetter(ch) && run.prev === ' ' && onsetWords.length) onsetWords.at(-1).open = true;
      }
      run = { end: f.location + 1, last: f.time, prev: ch, prev2: run && f.location === run.end ? run.prev : undefined, counts: true };
      if (ch === ' ') words++;
      insertIndex.splice(f.location, 0, sequence++); length++;
    } else if (f.length > 0 && f.inserted === '' && f.location + f.length <= length) {
      // A deletion: what was removed, and how many characters were typed since the first of them.
      const removed = insertIndex.splice(f.location, f.length), text = deleted[i] ?? '?'.repeat(f.length);
      deletions++;
      const since = removed.length ? sequence - removed[0] - 1 : 0;
      if (deleting && f.location + f.length === deleting.from) { deleting.from = f.location; deleting.text = text + deleting.text; deleting.since = Math.max(deleting.since, since); }
      else { closeDeletion(null); deleting = { from: f.location, text, since }; }
      length -= f.length; edits++;
      if (run) { run.end = f.location; run.last = f.time; run.counts = false; run.prev = undefined; }
    } else {
      closeDeletion(null);
      if (typeof f.inserted === 'string' && f.location + f.length <= length) { insertIndex.splice(f.location, f.length, ...[...f.inserted].map(() => sequence++)); length += f.inserted.length - f.length; }
      run = null; edits++;
    }
  }
  closeDeletion(null);
  // Pre-word pause against the word's rarity.
  const rarity = onsetWords.map(w => -zipf(w.word)), onsetGaps = onsetWords.map(w => onset[w.at]);
  return {
    word_onset_ratio: feature(onset.length >= 8 && inWord.length >= 20 ? median(onset) / median(inWord) : null, Math.min(onset.length, inWord.length / 2), 60),
    word_onset_shift: feature(shiftZ(onset, inWord, 8), Math.min(onset.length, inWord.length), 200),
    word_freq_corr: feature(onsetGaps.length >= 20 ? spearman(onsetGaps, rarity) : null, onsetGaps.length, 150),
    boundary_pause_ratio: feature(pauses.length >= 5 ? share(pauses, p => p.boundary) : null, pauses.length, 25),
    linearity_ratio: feature(edits ? atEnd / edits : null, edits, 200),
    revision_depth: feature(depths.length ? median(depths) : edits >= 200 ? 0 : null, edits, 400),
    // Deletions per typed character: people correct themselves; software that never backspaces doesn't.
    correction_rate: feature(typedCount >= 100 ? deletions / typedCount : null, typedCount, 400),
    typo_fix_latency: feature(fixes.length ? median(fixes) : null, fixes.length, 8),
    typo_fix_spread: feature(fixes.length >= 3 ? quantile(fixes, 0.9) - quantile(fixes, 0.1) : null, fixes.length, 8),
    typo_adjacency: feature(fixes.length >= 3 ? mean(adjacency) : null, fixes.length, 10),
    semantic_rewrite_rate: feature(words >= 50 ? rewrites / words : null, words, 300),
  };
}
/** For each deletion frame (by index), the text it removed, by replaying the frames once (UTF-16 units, as the replay applies them). */
export function rebuildDeletions(frames) {
  const out = {}; let page = '';
  for (const [i, f] of frames.entries()) {
    if (typeof f.inserted !== 'string' || f.location > page.length || f.length > page.length - f.location) break;
    if (f.length > 0) out[i] = page.slice(f.location, f.location + f.length);
    page = page.slice(0, f.location) + f.inserted + page.slice(f.location + f.length);
  }
  return out;
}

// ---- 3.4 Agent-loop signatures -----------------------------------------------------------------------------------
export function agentLoop(view, typed) {
  const onsets = [], bursts = []; let burst = 0, lastT = null, afterLong = [], overall = [];
  for (let i = 0; i < typed.length; i++) {
    const gap = lastT === null ? 0 : typed[i].t - lastT;
    if (i > 0 && gap > 1500) { onsets.push(lastT); bursts.push(burst); burst = 0; }
    if (i > 0 && gap < PAUSE_MS) overall.push(gap);
    burst++; lastT = typed[i].t;
  }
  if (burst) bursts.push(burst);
  // The speed of the first twenty keys after a pause over five seconds, against the session's median gap.
  for (let i = 1; i < typed.length; i++) {
    if (typed[i].t - typed[i - 1].t > 5000) { const next = intervals(typed.slice(i, i + 21)); if (next.length >= 10) afterLong.push(median(next)); }
  }
  const spacing = []; for (let i = 1; i < onsets.length; i++) spacing.push(onsets[i] - onsets[i - 1]);
  const periodicity = spacing.length >= 5 ? clamp(1 - cv(spacing), 0, 1) : null;
  // Keys and input while the page was hidden or unfocused.
  let hidden = 0, total = 0, state = { hidden: false, focused: true }; const marks = [...view.focus].sort((a, b) => a.t - b.t); let m = 0;
  for (const e of [...view.keydowns, ...view.insertions].sort((a, b) => a.t - b.t)) {
    while (m < marks.length && marks[m].t <= e.t) { state = { hidden: marks[m].hidden === true, focused: marks[m].focused !== false }; m++; }
    total++; if (state.hidden || !state.focused) hidden++;
  }
  const sessionMedian = overall.length ? median(overall) : null;
  // Reading before writing: a person at a mouse looks around (pointer, wheel, selection) before the first key; software
  // reads the page some other way and starts typing cold. Mouse sessions only; a touch screen is left out.
  const firstKey = typed[0]?.t ?? null;
  const preface = firstKey === null || view.meta?.coarse ? null : view.events.filter(e => e.t < firstKey && e.t >= firstKey - 60000 && (e.ev === 'pm' || e.ev === 'wh' || e.ev === 'sc')).length;
  const copies = view.events.filter(e => e.ev === 'copy' || e.ev === 'cut').length;
  return {
    preface_activity: feature(preface, firstKey === null ? 0 : 1, 1),
    copy_rate: feature(typed.length >= 50 ? copies / typed.length * 100 : null, typed.length, 200),
    pause_periodicity: feature(periodicity, spacing.length, 12),
    burst_len_cv: feature(bursts.length >= 5 ? cv(bursts) : null, bursts.length, 12),
    burst_speed_after_long_pause: feature(afterLong.length && sessionMedian ? sessionMedian / median(afterLong) : null, afterLong.length, 6),
    hidden_input_rate: feature(total ? hidden / total : null, total, 40),
  };
}

// ---- 3.5 Pointer kinematics ---------------------------------------------------------------------------------------
export function pointerKinematics(view) {
  const moves = view.pointer.filter(e => e.ev === 'pm' && e.pt === 'mouse' && Number.isFinite(e.x) && Number.isFinite(e.y)).sort((a, b) => a.t - b.t);
  const clicks = view.pointer.filter(e => e.ev === 'pd' && (e.pt === 'mouse' || e.pt == null)).sort((a, b) => a.t - b.t);
  const touchOnly = view.pointer.length && view.pointer.every(e => e.pt === 'touch' || e.pt === 'pen');
  if (touchOnly) return Object.fromEntries(FEATURES.pointer.map(n => [n, unavailable()]));
  // Segments: runs of samples no more than 100 ms apart.
  const segments = []; let seg = [];
  for (const p of moves) { if (seg.length && p.t - seg.at(-1).t > 100) { segments.push(seg); seg = []; } seg.push(p); }
  if (seg.length) segments.push(seg);
  const long = segments.filter(s => s.length >= 8 && pathLength(s) >= 40);
  const straightness = long.map(s => Math.hypot(s.at(-1).x - s[0].x, s.at(-1).y - s[0].y) / pathLength(s));
  const jerk = long.filter(s => s.length >= 12).map(s => jerkDistance(s));
  const tremor = segments.filter(s => s.length >= 24 && s.at(-1).t - s[0].t >= 400).map(s => tremorShare(s)).filter(v => v !== null);
  // A click: did the pointer move to it (within 300 ms, ending within 50 px)? Did the path pass the target and come back?
  let teleports = 0, judged = 0, overshoots = 0, ended = 0;
  const moveTimes = moves.map(p => p.t);
  for (const c of clicks.slice(1)) {
    judged++;
    const i = nearest(moveTimes, c.t); let k = i ?? -1; while (k >= 0 && moveTimes[k] > c.t) k--;
    const recent = k >= 0 && c.t - moves[k].t <= 300 && Math.hypot(moves[k].x - c.x, moves[k].y - c.y) <= 50;
    if (!recent) { teleports++; continue; }
    const segment = segments.find(s => s.includes(moves[k]));
    if (segment && segment.length >= 8) { ended++; if (overshot(segment, c)) overshoots++; }
  }
  // Time with no pointer, wheel or selection at all while keys were typed, over the whole session.
  const span = view.events.length ? view.events.at(-1).t - view.events[0].t : 0;
  const activity = [...view.pointer, ...view.events.filter(e => e.ev === 'sc' || e.ev === 'wh')].map(e => e.t).sort((a, b) => a - b);
  let active = 0, last = null; for (const t of activity) { if (last !== null && t - last < 5000) active += t - last; last = t; }
  return {
    teleport_click_rate: feature(judged ? teleports / judged : null, judged, 4),
    path_straightness: feature(straightness.length ? median(straightness) : null, straightness.length, 5),
    jerk_profile: feature(jerk.length ? median(jerk) : null, jerk.length, 5),
    tremor_power: feature(tremor.length ? median(tremor) : null, tremor.length, 3),
    overshoot_rate: feature(ended ? overshoots / ended : null, ended, 4),
    idle_pointer_ratio: feature(span > 60000 ? 1 - clamp(active / span, 0, 1) : null, span / 60000, 10),
  };
}
const pathLength = s => { let d = 0; for (let i = 1; i < s.length; i++) d += Math.hypot(s[i].x - s[i - 1].x, s[i].y - s[i - 1].y); return d; };
/** How far the speed profile is from a minimum-jerk bell (0 is a perfect bell; hands are 0.1–0.4 away). */
function jerkDistance(s) {
  const speeds = []; for (let i = 1; i < s.length; i++) { const dt = s[i].t - s[i - 1].t || 1; speeds.push(Math.hypot(s[i].x - s[i - 1].x, s[i].y - s[i - 1].y) / dt); }
  const peak = Math.max(...speeds) || 1, total = s.at(-1).t - s[0].t || 1; let err = 0;
  for (let i = 0; i < speeds.length; i++) { const u = (s[i + 1].t - s[0].t) / total, bell = 30 * u * u * (1 - u) * (1 - u) / 1.875; err += (speeds[i] / peak - bell) ** 2; }
  return Math.sqrt(err / speeds.length);
}
/** The share of a segment's movement power at 8–12 Hz (a hand's tremor), from samples resampled at 100 Hz. */
function tremorShare(s) {
  const dt = 0.01, from = s[0].t, to = s.at(-1).t, n = Math.floor((to - from) / 10);
  if (n < 32) return null;
  const xs = [], ys = []; let k = 0;
  for (let i = 0; i < n; i++) {
    const t = from + i * 10; while (k < s.length - 2 && s[k + 1].t < t) k++;
    const a = s[k], b = s[k + 1] ?? a, u = b.t === a.t ? 0 : (t - a.t) / (b.t - a.t);
    xs.push(a.x + (b.x - a.x) * u); ys.push(a.y + (b.y - a.y) * u);
  }
  const px = bandPowerShare(xs, dt, 8, 12, 3), py = bandPowerShare(ys, dt, 8, 12, 3);
  return px === null && py === null ? null : Math.max(px ?? 0, py ?? 0);
}
function overshot(segment, click) {
  const x0 = segment[0].x, y0 = segment[0].y, dx = click.x - x0, dy = click.y - y0, len = Math.hypot(dx, dy) || 1;
  let farthest = 0; for (const p of segment) farthest = Math.max(farthest, ((p.x - x0) * dx + (p.y - y0) * dy) / len);
  return farthest > len + 4;
}
