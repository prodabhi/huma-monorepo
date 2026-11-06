// Whether a session's event stream can be what it claims: typed live in the page it came from. A capable attacker
// skips the editor and posts a log it made up; these checks close that path. Each is judged on the server from what
// stream.mjs kept (every batch with its arrival time), the page's signed replay and its text. A failed check means the
// page can't be verified as a person's, whatever the behavioural features say (score.mjs).
import { describeSession, printable, MODIFIER_CODES, nearest } from './session.mjs';
import { sessionClaim } from '../sessions.mjs';

export const INTEGRITY = Object.freeze({
  /** A batch arrived live when the server saw at least this share of the client's gap before it (less a second). */
  liveRatio: 0.5, liveSlackMs: 1000,
  /** A session is judged for bursts once it spans this long, and fails when less than this share of it arrived live. */
  burstMinSpanMs: 60000, liveShareMin: 0.5,
  /** The client's clock may run ahead of the server's by this share plus this slack before the session fails. */
  clockRatio: 1.1, clockSlackMs: 60000,
  /** Typed text needs a key press (or input) this close before it; past this share of frames without one, it fails. */
  bindWindowMs: 250, orphanFrameMax: 0.05, orphanFramesMin: 10,
  /** Sustained speed no hand keeps: words per minute over a window of this length. */
  wpmCeiling: 180, wpmWindowMs: 30000, wpmMinChars: 150,
  /** Long text with no pause at all: a strong penalty, not a failure. */
  noPauseChars: 1500, pauseMs: 2000,
});

/**
 * `stream`: what streams.read gave (null when nothing was streamed). `frames`: the verified replay's frames. `text`:
 * the page's text. `journal`: the proof's journal (its claimed writing time). Returns { status: 'pass' | 'fail',
 * failures: [{ check, detail }], penalties: [{ check, detail }], measures }.
 */
export function checkIntegrity({ stream, frames = [], text = '', journal = null, limits = {}, platform = 'web' } = {}) {
  const L = { ...INTEGRITY, ...limits };
  const failures = [], penalties = [], measures = {};
  const fail = (check, detail) => failures.push({ check, detail });
  // A Mac page streams nothing (its keys carry the Mac's own input origin, checked in the proof): only its replay's
  // plausibility is judged here.
  if (platform === 'mac') { plausibility(frames, L, fail, penalties, measures); return { status: failures.length ? 'fail' : 'pass', failures, penalties, measures }; }
  if (!stream || !stream.batches?.length) {
    fail('stream', 'no live event stream reached the server for this session');
    return { status: 'fail', failures, penalties, measures };
  }
  const batches = stream.batches;
  // 0. The page's own checks were tampered with: a console whose methods aren't the browser's own (or a patched
  //    Function.prototype.toString, which hides that) is how software gets past the DevTools probe (write/automation.mjs).
  //    A person's browser never needs to; an extension that does is told so at Start (automationSigns), before any typing.
  if (stream.meta && (stream.meta.consoleNative === false || stream.meta.toStringNative === false)) fail('environment', 'the page’s own checks were tampered with: its console was replaced');
  // 1. Live streaming: compare each batch's arrival gap with the client's sending gap.
  let liveMs = 0, clientSpan = 0;
  for (let i = 1; i < batches.length; i++) {
    const client = batches[i].sentAt - batches[i - 1].sentAt, server = batches[i].receivedAt - batches[i - 1].receivedAt;
    if (!(client > 0)) continue;
    clientSpan += client;
    if (server >= L.liveRatio * client - L.liveSlackMs) liveMs += client;
  }
  measures.liveShare = clientSpan ? liveMs / clientSpan : 1;
  measures.clientSpanMs = clientSpan;
  if (clientSpan >= L.burstMinSpanMs && measures.liveShare < L.liveShareMin) fail('burst', `only ${Math.round(measures.liveShare * 100)}% of the session arrived while it was being written`);
  // 2. Clock consistency: the client's clock against the server's, over the whole stream.
  const serverSpan = batches.at(-1).receivedAt - batches[0].receivedAt;
  measures.serverSpanMs = serverSpan;
  if (clientSpan > L.clockRatio * serverSpan + L.clockSlackMs) fail('clock', `the page claims ${Math.round(clientSpan / 1000)} s of events that reached the server in ${Math.round(serverSpan / 1000)} s`);
  const claimed = journal ? sessionClaim(journal).claimed : null;
  if (Number.isFinite(claimed) && claimed > L.clockRatio * serverSpan + L.clockSlackMs && claimed > L.clockRatio * clientSpan + L.clockSlackMs)
    fail('clock', `the proof claims ${Math.round(claimed / 1000)} s of writing but the stream spans ${Math.round(Math.max(serverSpan, clientSpan) / 1000)} s`);
  // 3. Binding to the replay: every typed frame needs a key press (or an input event, on a touch keyboard or through
  //    an input method) just before it on the stream's clock; and no more text than keys.
  const view = describeSession({ events: stream.events, meta: stream.meta, frames });
  const presses = (view.modality === 'physical_keyboard' ? view.keydowns.filter(e => !MODIFIER_CODES.has(e.code)) : [...view.keydowns.filter(e => !MODIFIER_CODES.has(e.code)), ...view.insertions])
    .map(e => e.t).sort((a, b) => a - b);
  const composed = view.compositions.filter(e => e.ev === 'ce').map(e => e.t).sort((a, b) => a - b);
  let orphans = 0;
  for (const f of view.typedFrames) {
    const at = f.time + view.offset, i = nearest(presses, at), j = nearest(composed, at);
    const press = i === null ? -Infinity : presses[i], ce = j === null ? -Infinity : composed[j];
    const bound = (press <= at + 50 && at - press <= L.bindWindowMs) || (ce <= at + 50 && at - ce <= L.bindWindowMs) || f.kind === 'input-method' && Math.abs(ce - at) <= 1000;
    if (!bound) orphans++;
  }
  measures.orphanFrames = orphans; measures.typedFrames = view.typedFrames.length;
  measures.orphanFrameRate = view.typedFrames.length ? orphans / view.typedFrames.length : 0;
  if (orphans >= L.orphanFramesMin && measures.orphanFrameRate > L.orphanFrameMax) fail('binding', `${orphans} of ${view.typedFrames.length} typed characters arrived with no key press before them`);
  const typedChars = view.typedFrames.reduce((n, f) => n + f.inserted.length, 0);
  const keys = view.modality === 'physical_keyboard' ? view.keydowns.filter(printable).length + view.compositions.filter(e => e.ev === 'ce').reduce((n, e) => n + (e.data?.length ?? 0), 0)
    : view.insertions.reduce((n, e) => n + e.data.length, 0) + view.keydowns.filter(printable).length + view.compositions.filter(e => e.ev === 'ce').reduce((n, e) => n + (e.data?.length ?? 0), 0);
  measures.typedChars = typedChars; measures.keyChars = keys;
  if (typedChars > keys * 1.1 + 20) fail('binding', `${typedChars} characters were typed from ${keys} key presses`);
  plausibility(frames, L, fail, penalties, measures);
  return { status: failures.length ? 'fail' : 'pass', failures, penalties, measures };
}
/** 4. Plausibility: speed no hand sustains, and long text with no pause to think, from the replay's typed frames. */
function plausibility(frames, L, fail, penalties, measures) {
  const view = describeSession({ frames }), times = view.typedFrames.map(f => f.time);
  const typedChars = view.typedFrames.reduce((n, f) => n + f.inserted.length, 0);
  let bestWPM = 0;
  for (let i = 0, j = 0; i < times.length; i++) {
    while (times[i] - times[j] > L.wpmWindowMs) j++;
    const chars = i - j + 1, span = times[i] - times[j];
    if (chars >= L.wpmMinChars && span >= L.wpmWindowMs * 0.8) bestWPM = Math.max(bestWPM, (chars / 5) / (span / 60000));
  }
  measures.peakWPM = Math.round(bestWPM);
  if (bestWPM > L.wpmCeiling) fail('speed', `${Math.round(bestWPM)} words per minute sustained over ${Math.round(L.wpmWindowMs / 1000)} s`);
  let longest = 0;
  for (let i = 1; i < times.length; i++) longest = Math.max(longest, times[i] - times[i - 1]);
  measures.longestPauseMs = longest;
  if (typedChars >= L.noPauseChars && longest < L.pauseMs) penalties.push({ check: 'pauses', detail: `${typedChars} characters typed without a single pause over ${L.pauseMs / 1000} s` });
}
