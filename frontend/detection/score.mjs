// The verdict on a session: a calibrated probability that a person typed it, with the reasons, from the features
// (features.mjs) under the thresholds file (thresholds.json), the integrity checks (integrity.mjs) and the traps
// (traps.mjs). Phase A, a rule ensemble: every available feature adds a bounded amount to a logit, weighted by its
// confidence; a sigmoid makes the probability; it's clamped so it never reads 0% or 100%. Traps and integrity are
// hard overrides, the only decisive signals. The output follows one schema, kept with the page's record.
import { readFileSync } from 'node:fs';
import { clamp } from './stats.mjs';

export const DEFAULT_THRESHOLDS = JSON.parse(readFileSync(new URL('./thresholds.json', import.meta.url), 'utf8'));
export const BANDS = Object.freeze(['likely_human', 'uncertain', 'likely_automated']);

/** One feature's logit contribution under its rule, before confidence. */
export function contribution(rule, value) {
  if (!rule || value === null || value === undefined || !Number.isFinite(value)) return 0;
  const [a, b] = rule.logit;
  if (rule.kind === 'ramp') { const u = rule.high === rule.low ? 1 : clamp((value - rule.low) / (rule.high - rule.low), 0, 1); return a + (b - a) * u; }
  if (rule.kind === 'band') return value >= rule.inside[0] && value <= rule.inside[1] ? a : b;
  if (rule.kind === 'step') return value >= rule.above ? b : a;
  return 0;
}
const sigmoid = x => 1 / (1 + Math.exp(-x));
/** A rule's detail line for a value: {value} whole, {value1..3} to that many decimals, {percent} as a percentage. */
export function detailFor(rule, value) {
  if (!rule?.detail) return '';
  return rule.detail.replace(/\{(value\d?|percent)\}/g, (_, kind) => kind === 'percent' ? Math.round(value * 100) + '%' : kind === 'value' ? String(Math.round(value)) : value.toFixed(Number(kind.slice(5))));
}

/**
 * `features`: extractFeatures' result. `integrity`: checkIntegrity's. `traps`: { canary, honeypot } (booleans).
 * `baseline`: { distance } from the writer's own profile (baseline.mjs), or null. Returns the verdict:
 * { humanProbability, band, reasons: [{ feature, direction, detail }], integrity, modality, modelVersion, logit, contributions }.
 */
export function scoreSession({ features, integrity = null, traps = {}, baseline = null, thresholds = DEFAULT_THRESHOLDS } = {}) {
  const T = thresholds, contributions = {}, all = { ...(features?.features ?? {}) };
  if (Number.isFinite(baseline?.distance)) all.baseline_distance = { value: baseline.distance, confidence: baseline.confidence ?? 1 };
  let logit = T.prior;
  for (const [name, f] of Object.entries(all)) {
    const rule = T.features[name];
    if (!rule || f.value === null || f.value === undefined || !(f.confidence > 0)) continue;
    const c = contribution(rule, f.value) * f.confidence;
    if (c !== 0) contributions[name] = c;
    logit += c;
  }
  const reasons = [];
  for (const penalty of integrity?.penalties ?? []) {
    const c = T.penalties[penalty.check] ?? -1;
    contributions['integrity:' + penalty.check] = c; logit += c;
    reasons.push({ feature: 'integrity:' + penalty.check, direction: 'automated', detail: penalty.detail });
  }
  const trapHits = Object.entries(traps).filter(([, hit]) => hit === true).map(([name]) => name);
  for (const name of trapHits) { contributions['trap:' + name] = T.penalties.trap; logit += T.penalties.trap; reasons.push({ feature: 'trap:' + name, direction: 'automated', detail: name === 'canary' ? 'the text followed an instruction hidden from people' : 'a hidden field was filled in' }); }
  let probability = clamp(sigmoid(logit), T.clamp[0], T.clamp[1]);
  const ranked = Object.entries(contributions).filter(([name]) => !name.includes(':')).sort((a, b) => Math.abs(b[1]) - Math.abs(a[1])).slice(0, T.reasons);
  for (const [name, c] of ranked) reasons.push({ feature: name, direction: c > 0 ? 'human' : 'automated', detail: detailFor(T.features[name], all[name].value) });
  let band = probability >= T.bands.likely_human ? 'likely_human' : probability <= T.bands.likely_automated ? 'likely_automated' : 'uncertain';
  const status = integrity?.status === 'fail' ? 'fail' : 'pass';
  if (status === 'fail') {
    // Not verifiable as a person's: at best uncertain (no stream at all), otherwise automated.
    const onlyNoStream = integrity.failures.every(f => f.check === 'stream');
    probability = Math.min(probability, onlyNoStream ? 0.5 : T.bands.likely_automated);
    band = onlyNoStream ? 'uncertain' : 'likely_automated';
    reasons.unshift(...integrity.failures.map(f => ({ feature: 'integrity:' + f.check, direction: 'automated', detail: f.detail })));
  }
  if (trapHits.length) { probability = T.clamp[0]; band = 'likely_automated'; }
  return { humanProbability: Number(probability.toFixed(3)), band, reasons: reasons.slice(0, T.reasons + 4), integrity: status, modality: features?.modality ?? 'physical_keyboard',
    modelVersion: T.modelVersion + '+' + (features?.version ?? 'features-0'), logit: Number(logit.toFixed(3)), contributions };
}
/** Whether a verdict earns the full score: likely a person, with its integrity intact. */
export const verifiedHuman = verdict => verdict?.band === 'likely_human' && verdict?.integrity === 'pass';
