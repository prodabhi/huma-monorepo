import test from 'node:test';
import assert from 'node:assert/strict';
import { updateBaseline, baselineDistance, emptyBaseline, valuesOf, BASELINE_FEATURES, BASELINE_MIN_SESSIONS } from '../detection/baseline.mjs';
import { judgeSession, withBaseline, storableDetection } from '../detection/judge.mjs';
import { GENERATORS, SAMPLE_TEXT, OTHER_TEXT } from '../detection/eval/synthetic.mjs';

const secret = Buffer.alloc(32, 3), nonce = 'cd'.repeat(16);
/** The session's replay as the page uploads it (its frames are what the content features read). */
const replayOf = s => JSON.stringify({ kind: 'huma-replay-v1', session: 'S', initialText: '', events: s.frames.map(f => [f.time, f.kind, f.location, f.length, f.inserted]),
  checkpoint: { version: 2, kind: 'unattested-p256', isFinal: true, sessionID: 'S', sequence: 1, captureCount: 0, editCount: s.frames.length, sampleCount: 0, reportedTime: { unixMilliseconds: 1, elapsedMilliseconds: 1 },
    captureHead: '0'.repeat(64), editHead: '0'.repeat(64), textHash: '0'.repeat(64), previousCheckpoint: '', challenge: '', publicKey: 'AA==', signature: 'AA==' } });
const judged = s => judgeSession({ streams: { read: async () => s.stream }, secret, nonce, journal: s.journal, replay: replayOf(s), text: s.text });

test('a profile grows from sessions and measures a later one’s distance in standard deviations', () => {
  let baseline = emptyBaseline();
  assert.equal(baselineDistance(baseline, { dwell_mean: 90 }), null);
  for (const dwell of [90, 100, 110]) baseline = updateBaseline(baseline, { dwell_mean: dwell, rollover_rate: 0.12, word_onset_ratio: 1.8, bigram_corr: 0.5, nothing: 1 });
  assert.equal(baseline.sessions, 3); assert.deepEqual(Object.keys(baseline.features).sort(), ['bigram_corr', 'dwell_mean', 'rollover_rate', 'word_onset_ratio']);
  assert.ok(Math.abs(baseline.features.dwell_mean.mean - 100) < 1e-9 && Math.abs(baseline.features.dwell_mean.m2 / 2 - 100) < 1e-9);
  const near = baselineDistance(baseline, { dwell_mean: 102, rollover_rate: 0.13, word_onset_ratio: 1.75, bigram_corr: 0.48 });
  const far = baselineDistance(baseline, { dwell_mean: 2, rollover_rate: 0, word_onset_ratio: 1.0, bigram_corr: 0 });
  assert.ok(near.distance < 1 && far.distance > 3, JSON.stringify([near, far]));
  assert.equal(near.features, 4); assert.ok(near.confidence > 0 && near.confidence <= 1);
  // Too few features in common: nothing to say. Missing values are skipped, not zero.
  assert.equal(baselineDistance(baseline, { dwell_mean: 100 }), null);
  assert.equal(baselineDistance(updateBaseline(emptyBaseline(), { dwell_mean: 1 }), { dwell_mean: 1 }), null);
  assert.deepEqual(valuesOf({ dwell_mean: [95.5, 1], rollover_rate: null }), { dwell_mean: 95.5, rollover_rate: null });
  assert.ok(BASELINE_FEATURES.length >= 6 && BASELINE_MIN_SESSIONS === 3);
});

test('a writer’s own sessions sit close to their profile; a harness writing under their account sits far from it', async () => {
  let baseline = emptyBaseline();
  for (const seed of [1, 2, 3]) {
    const v = await judged(GENERATORS.human(SAMPLE_TEXT, seed));
    assert.equal(v.band, 'likely_human');
    baseline = updateBaseline(baseline, valuesOf(v.features));
  }
  const own = await judged(GENERATORS.human(OTHER_TEXT, 4)), rescored = withBaseline(own, baseline);
  assert.ok(rescored.baseline.distance < 2.5, String(rescored.baseline.distance));
  assert.ok(rescored.contributions.baseline_distance > 0); assert.equal(rescored.band, 'likely_human');
  // A harness with human-like dwell and rollover still sits further off (its word starts and letter pairs don't match);
  // with three sessions in the profile the distances are noisy, so the test asks for the ordering, not a cut.
  const harness = await judged(GENERATORS.cdp_dispatch_humanized(OTHER_TEXT, 4)), rescoredHarness = withBaseline(harness, baseline);
  assert.ok(rescoredHarness.baseline.distance > rescored.baseline.distance + 1 && rescoredHarness.baseline.distance > 2, JSON.stringify([rescored.baseline, rescoredHarness.baseline]));
  assert.ok(rescoredHarness.contributions.baseline_distance < rescored.contributions.baseline_distance); assert.equal(rescoredHarness.band, 'likely_automated');
  // A profile too new says nothing; and what's kept with the page has no raw material in it.
  assert.equal(withBaseline(own, updateBaseline(emptyBaseline(), valuesOf(own.features))), own);
  assert.equal(withBaseline(own, null), own);
  const kept = storableDetection(rescored);
  assert.equal('raw' in kept, false); assert.ok(kept.features && kept.baseline && kept.reasons);
  assert.equal(storableDetection(null), null);
});
