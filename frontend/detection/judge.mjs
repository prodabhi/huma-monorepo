// A browser page's verdict at Finish: its streamed session (stream.mjs) against its signed replay and text, through
// the integrity checks, the features, the traps and the score. What publications.mjs keeps with the page's record,
// and what a reader sees of it (publicDetection).
import { parseReplay } from '../replay-core.mjs';
import { checkIntegrity } from './integrity.mjs';
import { extractFeatures } from './features.mjs';
import { scoreSession } from './score.mjs';
import { canaryHit, canaryWord, honeypotHit } from './traps.mjs';
import { baselineDistance, valuesOf } from './baseline.mjs';

/** The replay's frames, as verifyReplay returns them, from a replay the verifier has already checked. */
export function replayFrames(replay) {
  if (typeof replay !== 'string') return [];
  try { return parseReplay(replay).events.map(([time, kind, location, length, inserted]) => ({ time, kind, location, length, inserted })); } catch { return []; }
}
/**
 * `streams`: the stream receiver. `secret`: the sessions' secret. `nonce`: the page's session nonce (sessions.mjs).
 * `journal`, `replay`, `text`: from the verified upload. `baseline`: the writer's own profile distance, if any.
 * Returns the verdict (score.mjs) with the feature values, the integrity measures and the traps, or null when the
 * page has no session to judge.
 */
export async function judgeSession({ streams, secret, nonce, journal = null, replay = null, text = '', baseline = null, thresholds, platform = 'web' } = {}) {
  // A Mac page is judged on its replay alone (it streams nothing, and sets no traps); a browser page needs its session.
  if (platform === 'mac' ? !replay : !nonce) return null;
  const frames = replayFrames(replay), stream = platform === 'mac' ? null : await streams.read(nonce);
  const integrity = checkIntegrity({ stream, frames, text, journal, platform });
  const features = extractFeatures({ events: stream?.events ?? [], meta: stream?.meta ?? null, frames, text });
  const traps = platform === 'mac' ? {} : { canary: canaryHit(text, canaryWord(secret, nonce)), honeypot: honeypotHit(stream?.trap) };
  const verdict = scoreSession({ features, integrity, traps, baseline, ...(thresholds ? { thresholds } : {}) });
  const values = Object.fromEntries(Object.entries(features.features).map(([name, f]) => [name, f.value === null ? null : [Number(f.value.toFixed(4)), Number(f.confidence.toFixed(2))]]));
  // `raw` is for rescoring against the writer's profile at publish (withBaseline); it isn't kept with the page.
  return { ...verdict, platform, traps, features: values, measures: integrity.measures, streamed: Boolean(stream), judgedAt: Date.now(), raw: { features, integrity, traps } };
}
/** The verdict scored again with the writer's own profile (baseline.mjs): one more feature, the session's distance
 *  from it. The same verdict when the profile is too new to say anything. */
export function withBaseline(detection, baseline, thresholds) {
  const distance = detection?.raw ? baselineDistance(baseline, valuesOf(detection.features)) : null;
  if (!distance) return detection;
  const verdict = scoreSession({ features: detection.raw.features, integrity: detection.raw.integrity, traps: detection.raw.traps, baseline: distance, ...(thresholds ? { thresholds } : {}) });
  return { ...detection, ...verdict, baseline: { distance: Number(distance.distance.toFixed(3)), features: distance.features } };
}
/** The verdict as the page's record keeps it: everything but the raw material it was scored from. */
export const storableDetection = detection => { if (!detection) return null; const { raw, ...kept } = detection; return kept; };
/** Whether a verdict holds a page's score: a browser page keeps the full score only as a likely person with its stream
 *  intact; a Mac page (judged on its replay alone, its keys already checked by the Mac) only when likely automated. */
export const holdsScore = detection => Boolean(detection) && (detection.platform === 'mac' ? detection.band === 'likely_automated' : !(detection.band === 'likely_human' && detection.integrity === 'pass'));
/** What a reader is told: the verdict and its reasons, never the raw measures. `enforced`: whether it held the score. */
export function publicDetection(detection, enforced = true) {
  if (!detection || typeof detection !== 'object') return null;
  const { humanProbability, band, reasons, integrity, modality, modelVersion, platform = 'web' } = detection;
  return { humanProbability, band, reasons: Array.isArray(reasons) ? reasons.slice(0, 10) : [], integrity, modality, modelVersion, platform, enforced: enforced === true };
}
