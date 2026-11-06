import test from 'node:test';
import assert from 'node:assert/strict';
import { scoreSession, contribution, detailFor, verifiedHuman, DEFAULT_THRESHOLDS, BANDS } from '../detection/score.mjs';
import { extractFeatures, FEATURES } from '../detection/features.mjs';
import { checkIntegrity } from '../detection/integrity.mjs';
import { GENERATORS, SAMPLE_TEXT } from '../detection/eval/synthetic.mjs';

const verdict = (generator, seed = 1, extra = {}) => {
  const s = GENERATORS[generator](SAMPLE_TEXT, seed);
  const features = extractFeatures({ events: s.stream.events, meta: s.stream.meta, frames: s.frames, text: s.text });
  const integrity = checkIntegrity({ stream: s.stream, frames: s.frames, text: s.text, journal: s.journal });
  return scoreSession({ features, integrity, ...extra });
};

test('the rules map a value to a bounded logit, and say why in words', () => {
  const ramp = { kind: 'ramp', low: 0, high: 0.1, logit: [-1.5, 1.5], detail: '{percent} of keys rolled over ({value2})' };
  assert.equal(contribution(ramp, -1), -1.5); assert.equal(contribution(ramp, 0.05), 0); assert.equal(contribution(ramp, 5), 1.5); assert.equal(contribution(ramp, null), 0);
  assert.equal(contribution({ kind: 'band', inside: [0.2, 0.8], logit: [0.5, -1] }, 0.5), 0.5); assert.equal(contribution({ kind: 'band', inside: [0.2, 0.8], logit: [0.5, -1] }, 0.9), -1);
  assert.equal(contribution({ kind: 'step', above: 0.5, logit: [0, -3] }, 0.5), -3); assert.equal(contribution({ kind: 'step', above: 0.5, logit: [0, -3] }, 0.4), 0);
  assert.equal(detailFor(ramp, 0.0712), '7% of keys rolled over (0.07)');
  // Every feature has a rule with a detail line.
  for (const name of Object.values(FEATURES).flat()) { const rule = DEFAULT_THRESHOLDS.features[name]; assert.ok(rule, name); assert.ok(rule.detail, name); assert.ok(detailFor(rule, 0.5).length > 0); }
});

test('the verdict has the schema, is never 0 or 100, and names its reasons', () => {
  const v = verdict('human');
  assert.deepEqual(Object.keys(v).sort(), ['band', 'contributions', 'humanProbability', 'integrity', 'logit', 'modality', 'modelVersion', 'reasons'].sort());
  assert.ok(v.humanProbability >= 0.01 && v.humanProbability <= 0.99); assert.ok(BANDS.includes(v.band));
  assert.equal(v.band, 'likely_human'); assert.equal(v.integrity, 'pass'); assert.equal(v.modality, 'physical_keyboard'); assert.match(v.modelVersion, /^rules-.*\+features-1$/);
  assert.ok(v.reasons.length >= 3 && v.reasons.every(r => ['human', 'automated'].includes(r.direction) && typeof r.detail === 'string' && r.feature));
  assert.ok(v.reasons.filter(r => r.direction === 'human').length >= 3);
  assert.ok(verifiedHuman(v));
  // A session that looks like a person's in every behavioural way but hides from the DevTools probe: uncertain, not automated.
  const hiding = GENERATORS.human(SAMPLE_TEXT, 2);
  const hidingFeatures = extractFeatures({ events: hiding.stream.events, meta: { ...hiding.stream.meta, consoleNative: false }, frames: hiding.frames, text: hiding.text });
  const hidden = scoreSession({ features: hidingFeatures, integrity: checkIntegrity({ stream: hiding.stream, frames: hiding.frames, text: hiding.text, journal: hiding.journal }) });
  assert.ok(hidden.contributions.console_wrapped === -5 && hidden.logit < verdict('human', 2).logit - 4);
  // Nothing measured at all: uncertain, not a verdict either way.
  const empty = scoreSession({ features: extractFeatures(), integrity: { status: 'pass', failures: [], penalties: [] } });
  assert.equal(empty.band, 'uncertain'); assert.ok(empty.humanProbability > 0.3 && empty.humanProbability < 0.7);
});

test('each way software types ends likely automated, and no single feature decides it', () => {
  for (const generator of ['playwright_type', 'cdp_dispatch_humanized', 'os_type', 'replay_human', 'computer_use_agent']) {
    for (const seed of [1, 2, 3]) {
      const v = verdict(generator, seed);
      assert.equal(v.band, 'likely_automated', generator + ' ' + seed + ' ' + v.humanProbability);
      assert.ok(v.reasons.some(r => r.direction === 'automated'));
      // No behavioural feature outweighs the rest; the environment tells (webdriver, a replaced console) carry more, and alone leave a session uncertain.
      const biggest = Math.max(...Object.entries(v.contributions).filter(([k]) => !['webdriver', 'console_wrapped'].includes(k)).map(([, c]) => Math.abs(c)));
      assert.ok(biggest <= 3, generator + ': ' + biggest);
      assert.ok(!verifiedHuman(v));
    }
  }
  for (const generator of ['human', 'human_touch', 'human_ime']) for (const seed of [1, 2, 3]) assert.equal(verdict(generator, seed).band, 'likely_human', generator + ' ' + seed);
});

test('integrity and the traps override everything', () => {
  const posted = verdict('fabricated_post');
  assert.equal(posted.integrity, 'fail'); assert.equal(posted.band, 'likely_automated'); assert.ok(posted.humanProbability <= 0.3);
  assert.ok(posted.reasons[0].feature.startsWith('integrity:') && posted.reasons.some(r => r.feature === 'integrity:burst'));
  const inserted = verdict('cdp_inserttext');
  assert.equal(inserted.integrity, 'fail'); assert.equal(inserted.band, 'likely_automated');
  // No stream at all: not verifiable, so uncertain, never automated on that alone.
  const s = GENERATORS.human(SAMPLE_TEXT, 2), features = extractFeatures({ events: [], meta: null, frames: s.frames, text: s.text });
  const none = scoreSession({ features, integrity: checkIntegrity({ stream: null, frames: s.frames, text: s.text }) });
  assert.equal(none.integrity, 'fail'); assert.equal(none.band, 'uncertain'); assert.ok(none.humanProbability <= 0.5);
  // A trap hit on a session that looks like a person's.
  const trapped = verdict('human', 1, { traps: { canary: true } });
  assert.equal(trapped.band, 'likely_automated'); assert.equal(trapped.humanProbability, 0.01); assert.equal(trapped.reasons[0].feature, 'trap:canary');
  assert.equal(verdict('human', 1, { traps: { honeypot: true } }).humanProbability, 0.01);
  assert.equal(verdict('human', 1, { traps: { canary: false, honeypot: false } }).band, 'likely_human');
  // The long-text-no-pause penalty, and a personal baseline far from this session.
  const steady = scoreSession({ features: extractFeatures(), integrity: { status: 'pass', failures: [], penalties: [{ check: 'pauses', detail: 'no pause' }] } });
  assert.ok(steady.contributions['integrity:pauses'] < 0 && steady.reasons.some(r => r.feature === 'integrity:pauses'));
  const far = verdict('human', 1, { baseline: { distance: 9, confidence: 1 } }), near = verdict('human', 1, { baseline: { distance: 1, confidence: 1 } });
  assert.ok(far.logit < near.logit && near.contributions.baseline_distance > 0);
});
