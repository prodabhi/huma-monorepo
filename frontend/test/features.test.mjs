import test from 'node:test';
import assert from 'node:assert/strict';
import { extractFeatures, FEATURES, rebuildDeletions, windows, zipf, intervals, typedStream } from '../detection/features.mjs';
import { describeSession } from '../detection/session.mjs';
import { dfaHurst, exGaussianFit, logNormalKS, spearman, shiftZ, bandPowerShare, quantile, erf } from '../detection/stats.mjs';
import { GENERATORS, SAMPLE_TEXT, random, simulateTyping, humanModel, session } from '../detection/eval/synthetic.mjs';

// Every feature, with a synthetic person and the software it should tell apart, asserted in the expected direction.
// These sessions come from one model of typing (synthetic.mjs), so they check the code, not the world: the thresholds
// are judged on recorded sessions (detection/eval/REPORT.md).
const cache = new Map();
const features = (generator, seed = 1) => {
  const key = generator + seed;
  if (!cache.has(key)) { const s = GENERATORS[generator](SAMPLE_TEXT, seed); cache.set(key, extractFeatures({ events: s.stream.events, meta: s.stream.meta, frames: s.frames, text: s.text })); }
  return cache.get(key);
};
const value = (generator, name, seed = 1) => { const f = features(generator, seed).features[name]; assert.ok(f, name); return f.value; };
const confident = (generator, name, seed = 1) => features(generator, seed).features[name].confidence;

test('every feature is reported, with a confidence, and the modality is told', () => {
  const human = features('human');
  assert.equal(human.modality, 'physical_keyboard'); assert.equal(human.version, 'features-1');
  for (const name of Object.values(FEATURES).flat()) { assert.ok(name in human.features, name); const f = human.features[name]; assert.ok(f.confidence >= 0 && f.confidence <= 1, name); }
  assert.ok(human.windows.length >= 3); assert.ok(human.windows.every(w => w.keys >= 0));
  assert.equal(features('human_touch').modality, 'touch'); assert.equal(features('human_ime').modality, 'ime');
  assert.deepEqual(extractFeatures().modality, 'physical_keyboard');
});

test('3.1 key physics: dwell, releases, rollover, Shift, codes, orphan input, trust', () => {
  assert.ok(value('human', 'dwell_mean') > 60 && value('playwright_type', 'dwell_mean') < 5 && value('os_type', 'dwell_mean') < 5);
  assert.ok(value('human', 'dwell_cv') > 0.2 && value('os_type', 'dwell_cv') < 0.01);
  assert.equal(value('human', 'missing_keyup_rate'), 0);
  assert.ok(value('human', 'rollover_rate') > 0.05 && value('playwright_type', 'rollover_rate') === 0 && value('os_type', 'rollover_rate') === 0);
  assert.equal(value('human', 'shift_mismatch_rate'), 0); assert.equal(value('playwright_type', 'shift_mismatch_rate'), 1);
  assert.equal(value('human', 'code_key_mismatch'), 0); assert.equal(value('human', 'orphan_input_rate'), 0); assert.equal(value('cdp_inserttext', 'orphan_input_rate'), 1);
  assert.equal(value('human', 'untrusted_rate'), 0);
  // Script-dispatched events, and a key whose code and key disagree.
  const s = GENERATORS.human(SAMPLE_TEXT, 2);
  let flip = 0;
  const forged = s.stream.events.map(e => (e.ev === 'kd' && e.code === 'KeyE' ? { ...e, trusted: false, key: flip++ % 2 ? 'q' : 'e' } : e));
  const f = extractFeatures({ events: forged, meta: s.stream.meta, frames: s.frames }).features;
  assert.ok(f.untrusted_rate.value > 0.02 && f.code_key_mismatch.value > 0.05, JSON.stringify([f.untrusted_rate, f.code_key_mismatch]));
  // Key physics don't apply to a touch keyboard or an input method.
  for (const name of FEATURES.physics.filter(n => n !== 'untrusted_rate')) { assert.equal(value('human_touch', name), null, name); assert.equal(confident('human_touch', name), 0); }
  // A missing release for every other key.
  const dropped = s.stream.events.filter((e, i) => !(e.ev === 'ku' && i % 2));
  assert.ok(extractFeatures({ events: dropped, meta: s.stream.meta, frames: s.frames }).features.missing_keyup_rate.value > 0.2);
});

test('3.2 timing: memory, fit, bigrams, quantisation, drift', () => {
  // Independent delays: Hurst about 0.5, no lag-1 correlation. (The synthetic person's pauses hide its slow tempo
  // drift from this estimator, so the human side of these two is judged on recorded sessions, not here.)
  for (const bot of ['playwright_type', 'os_type', 'cdp_dispatch_humanized']) {
    assert.ok(Math.abs(value(bot, 'iki_hurst') - 0.5) < 0.15, bot + ' ' + value(bot, 'iki_hurst'));
    assert.ok(Math.abs(value(bot, 'iki_lag1_ac')) < 0.1, bot + ' ' + value(bot, 'iki_lag1_ac'));
  }
  assert.ok(value('human', 'iki_hurst') > 0.4 && value('human', 'iki_hurst') < 0.9);
  assert.ok(value('human', 'bigram_corr') > 0.5 && Math.abs(value('cdp_dispatch_humanized', 'bigram_corr')) < 0.2 && Math.abs(value('replay_human', 'bigram_corr')) < 0.2);
  assert.ok(value('human', 'iki_exgauss_fit') !== null && value('human', 'iki_lognorm_ks') !== null);
  // Gaps on a 4 ms grid from a scheduler, against the same gaps jittered; only with a fine timer.
  const s = GENERATORS.cdp_dispatch_humanized(SAMPLE_TEXT, 3), base = s.stream.events[0].t;
  const gridded = s.stream.events.map(e => (e.ev === 'kd' ? { ...e, t: base + Math.round((e.t - base) / 4) * 4 } : e));
  const grid = extractFeatures({ events: gridded, meta: s.stream.meta, frames: s.frames }).features.quantization_score;
  assert.ok(grid.value > 0.6, String(grid.value)); assert.ok(value('cdp_dispatch_humanized', 'quantization_score', 3) < 0.1);
  assert.equal(extractFeatures({ events: gridded, meta: { ...s.stream.meta, timer: 1 }, frames: s.frames }).features.quantization_score.value, null);
  assert.ok(value('human', 'window_stationarity') !== null && value('human', 'drift_slope') !== null);
  assert.equal(value('playwright_type', 'window_stationarity'), null); // too short for windows
});

test('3.3 content coupling: words, pauses, linearity, revisions, typos, rewrites', () => {
  assert.ok(value('human', 'word_onset_ratio') > 1.5, String(value('human', 'word_onset_ratio')));
  for (const bot of ['playwright_type', 'cdp_dispatch_humanized', 'os_type', 'replay_human']) assert.ok(value(bot, 'word_onset_ratio') < 1.15, bot + ' ' + value(bot, 'word_onset_ratio'));
  assert.ok(value('human', 'word_onset_shift') > 5 && value('replay_human', 'word_onset_shift') < 2);
  assert.ok(value('human', 'boundary_pause_ratio') > 0.8 && value('cdp_dispatch_humanized', 'boundary_pause_ratio') < 0.4 && value('replay_human', 'boundary_pause_ratio') < 0.3);
  assert.ok(value('human', 'linearity_ratio') < 0.98 && value('playwright_type', 'linearity_ratio') === 1);
  assert.ok(value('human', 'revision_depth') > 20 && value('playwright_type', 'revision_depth') === 0);
  assert.ok(value('human', 'typo_fix_spread') >= 1 && value('cdp_dispatch_humanized', 'typo_fix_spread') === 0);
  assert.equal(value('cdp_dispatch_humanized', 'typo_fix_latency'), 1);
  assert.ok(value('human', 'typo_adjacency') > 0.5);
  assert.ok(value('human', 'semantic_rewrite_rate') > 0.005 && value('cdp_dispatch_humanized', 'semantic_rewrite_rate') === 0);
  assert.ok(value('human', 'correction_rate') > 0.02 && value('playwright_type', 'correction_rate') === 0 && value('replay_human', 'correction_rate') === 0);
  assert.ok(value('human', 'word_freq_corr') !== null);
  // Words and their rarity.
  assert.ok(zipf('the') > 7 && zipf('river') > zipf('xylophone') && zipf('a') > zipf('between'));
  assert.deepEqual(rebuildDeletions([{ location: 0, length: 0, inserted: 'abc' }, { location: 1, length: 1, inserted: '' }, { location: 0, length: 2, inserted: '' }]), { 1: 'b', 2: 'ac' });
});

test('3.4 agent loop: periodic pauses, even bursts, fast after a pause, hidden input', () => {
  assert.ok(value('computer_use_agent', 'pause_periodicity') > 0.75, String(value('computer_use_agent', 'pause_periodicity')));
  assert.ok(value('human', 'pause_periodicity') < 0.7);
  assert.ok(value('computer_use_agent', 'burst_len_cv') < value('human', 'burst_len_cv'));
  assert.ok(value('computer_use_agent', 'burst_speed_after_long_pause') > 1.2 && value('human', 'burst_speed_after_long_pause') < 1.2);
  assert.equal(value('human', 'hidden_input_rate'), 0);
  // Reading before writing: a hand looks around first; software starts cold, and one that hides from the DevTools probe
  // has replaced the console.
  assert.ok(value('human', 'preface_activity') > 20 && value('cdp_dispatch_humanized', 'preface_activity') === 0, String(value('human', 'preface_activity')));
  assert.equal(value('human', 'console_wrapped'), 0); assert.equal(value('cdp_dispatch_humanized', 'console_wrapped'), 1);
  assert.equal(value('human', 'copy_rate'), 0);
  const s = GENERATORS.human(SAMPLE_TEXT, 4), mid = s.stream.events[Math.floor(s.stream.events.length / 2)].t;
  const hidden = [...s.stream.events, { s: 1e6, ev: 'vc', t: mid, hidden: true, focused: false }].sort((a, b) => a.t - b.t);
  assert.ok(extractFeatures({ events: hidden, meta: s.stream.meta, frames: s.frames }).features.hidden_input_rate.value > 0.3);
});

test('3.5 pointer: teleports, straightness, jerk, tremor, overshoot, idleness', () => {
  assert.ok(value('human', 'tremor_power') > 0.05 && value('human', 'path_straightness') < 0.99);
  assert.ok(value('human', 'jerk_profile') > 0.03 && value('human', 'jerk_profile') < 0.5);
  assert.equal(value('human', 'teleport_click_rate'), 0);
  // Clicks that land with no movement, and straight, perfectly smooth moves.
  const typed = simulateTyping(SAMPLE_TEXT.slice(0, 400), { ...humanModel({ typos: 0 }), pointer: 'teleport', revise: (i, rand) => rand() < 0.6 }, { seed: 5 });
  const teleports = extractFeatures({ events: typed.events, meta: typed.meta, frames: typed.frames }).features;
  assert.ok(teleports.teleport_click_rate.value > 0.9, String(teleports.teleport_click_rate.value));
  const straight = [];
  for (let k = 0; k < 6; k++) for (let i = 0; i <= 40; i++) straight.push({ s: straight.length, ev: 'pm', t: 1000 + k * 2000 + i * 10, x: 100 + k * 50 + i * 5, y: 100 + i * 3, pt: 'mouse' });
  const f = extractFeatures({ events: straight, meta: {}, frames: [] }).features;
  assert.ok(f.path_straightness.value > 0.999 && f.tremor_power.value < 0.02, JSON.stringify([f.path_straightness, f.tremor_power]));
  assert.ok(f.jerk_profile.value > 0.5); // a constant speed is nothing like a hand's bell
  for (const name of FEATURES.pointer) assert.equal(value('human_touch', name), null, name);
  assert.ok(value('human', 'idle_pointer_ratio') !== null);
});

test('the statistics behave on known series', () => {
  const rand = random(3), gauss = Array.from({ length: 1000 }, () => rand.normal());
  assert.ok(Math.abs(dfaHurst(gauss) - 0.5) < 0.1);
  let x = 0; const ar = Array.from({ length: 1000 }, () => (x = 0.9 * x + rand.normal()));
  assert.ok(dfaHurst(ar) > 0.8);
  assert.equal(dfaHurst([1, 2, 3]), null);
  const exg = Array.from({ length: 500 }, () => 100 + 20 * rand.normal() - 60 * Math.log(1 - rand()));
  assert.ok(exGaussianFit(exg).ks < 0.08); assert.ok(logNormalKS(exg.map(v => Math.exp(v / 50))) > 0.0);
  assert.ok(Math.abs(spearman([1, 2, 3, 4, 5], [2, 4, 6, 8, 10]) - 1) < 1e-9 && spearman([1, 2, 3, 4, 5], [5, 4, 3, 2, 1]) < -0.99);
  assert.ok(shiftZ([5, 6, 7, 8, 9, 10, 11, 12], [1, 2, 3, 4, 5, 6, 7, 8]) > 2);
  const sine = Array.from({ length: 200 }, (_, i) => Math.sin(2 * Math.PI * 10 * i / 100));
  assert.ok(bandPowerShare(sine, 0.01, 8, 12) > 0.9);
  assert.equal(quantile([1, 2, 3, 4], 0.5), 2.5); assert.ok(Math.abs(erf(1) - 0.8427) < 1e-4);
});

test('the typed stream and its intervals come from keys, or from input on a touch keyboard', () => {
  const human = GENERATORS.human(SAMPLE_TEXT, 1), view = describeSession({ events: human.stream.events, meta: human.stream.meta, frames: human.frames });
  const typed = typedStream(view);
  assert.ok(typed.length > 1000 && typed.every(k => k.ch.length === 1 && k.code));
  const gaps = intervals(typed); assert.ok(gaps.every(g => g >= 0 && g < 2000));
  const touch = GENERATORS.human_touch(SAMPLE_TEXT, 1), touchView = describeSession({ events: touch.stream.events, meta: touch.stream.meta, frames: touch.frames });
  assert.ok(typedStream(touchView).length > 1000 && typedStream(touchView).every(k => k.code === null));
  assert.deepEqual(windows([]), []);
});
