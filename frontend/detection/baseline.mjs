// A writer's own typing profile (World ID–linked, by account): after three sessions scored as a person's, the running
// mean and variance of a few stable features are kept; later sessions get one more feature, their distance from that
// profile (a diagonal Mahalanobis distance, in standard deviations). Only these aggregates are kept, never events.
export const BASELINE_FEATURES = Object.freeze(['dwell_mean', 'dwell_cv', 'rollover_rate', 'word_onset_ratio', 'bigram_corr', 'iki_hurst', 'typo_adjacency', 'burst_len_cv']);
export const BASELINE_MIN_SESSIONS = 3, BASELINE_VERSION = 1;
/** A session counts toward the profile when the verdict is this sure it was a person's. */
export const BASELINE_PROBABILITY = 0.85;
const CAP_SESSIONS = 50;

/** An empty profile. */
export const emptyBaseline = () => ({ version: BASELINE_VERSION, sessions: 0, features: {} });
/** The feature values a verdict kept (judge.mjs: [value, confidence]) as plain numbers. */
export const valuesOf = features => Object.fromEntries(Object.entries(features ?? {}).map(([name, kept]) => [name, Array.isArray(kept) ? kept[0] : kept?.value ?? kept]));

/** Adds one session's feature values to the profile (Welford's running mean and variance, capped so old sessions fade). */
export function updateBaseline(baseline, values) {
  const next = structuredClone(baseline ?? emptyBaseline());
  next.sessions = Math.min(CAP_SESSIONS, (next.sessions ?? 0) + 1);
  for (const name of BASELINE_FEATURES) {
    const value = values?.[name];
    if (!Number.isFinite(value)) continue;
    const f = next.features[name] ?? { n: 0, mean: 0, m2: 0 };
    const n = Math.min(CAP_SESSIONS, f.n + 1), delta = value - f.mean, mean = f.mean + delta / n;
    next.features[name] = { n, mean, m2: f.m2 + delta * (value - mean) };
  }
  return next;
}
/**
 * How far a session sits from the writer's profile: the root mean square of each feature's z-score, over the features
 * both have (null until the profile has BASELINE_MIN_SESSIONS sessions). Variances have a floor, so a writer who is
 * very consistent isn't flagged by a tiny change. Returns { distance, features, confidence }.
 */
export function baselineDistance(baseline, values) {
  if (!baseline || (baseline.sessions ?? 0) < BASELINE_MIN_SESSIONS) return null;
  const zs = [];
  for (const name of BASELINE_FEATURES) {
    const f = baseline.features[name], value = values?.[name];
    if (!f || f.n < BASELINE_MIN_SESSIONS || !Number.isFinite(value)) continue;
    const variance = f.m2 / (f.n - 1), floor = (0.15 * Math.abs(f.mean) + 0.02) ** 2;
    zs.push((value - f.mean) / Math.sqrt(Math.max(variance, floor)));
  }
  if (zs.length < 3) return null;
  return { distance: Math.sqrt(zs.reduce((a, z) => a + z * z, 0) / zs.length), features: zs.length, confidence: Math.min(1, zs.length / BASELINE_FEATURES.length) };
}
