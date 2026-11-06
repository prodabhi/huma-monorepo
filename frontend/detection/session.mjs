// One writing session as the detection sees it: the editor's streamed events (frontend/write/collector.mjs, as
// detection/stream.mjs keeps them), the page's signed replay frames (replay-core.mjs verifyReplay) and its final text,
// joined on one clock. Everything downstream (integrity.mjs, features.mjs) reads this view.
import { median } from './stats.mjs';

/** Keys that aren't typing: modifiers, navigation, function keys. */
export const MODIFIER_CODES = new Set(['ShiftLeft', 'ShiftRight', 'ControlLeft', 'ControlRight', 'AltLeft', 'AltRight', 'MetaLeft', 'MetaRight', 'CapsLock', 'Fn', 'FnLock', 'OSLeft', 'OSRight']);
export const TYPED_KINDS = new Set(['typing', 'typing-external', 'input-method']);
/** How long a gap between two keys can be before it's a pause to think rather than rhythm. */
export const PAUSE_MS = 2000;
/** A printable key: one character, typed without ⌘ or Ctrl. */
export const printable = e => typeof e.key === 'string' && e.key.length === 1 && !((e.mod ?? 0) & 3);

/**
 * `events`: the stream's events in order. `meta`: its once-per-session facts. `frames`: the replay's frames.
 * Returns the session view: its modality, the key presses (repeats dropped), key releases, input events, compositions,
 * the typed frames, and `offset` (stream time − frame time, so frame.time + offset is on the stream's clock).
 */
export function describeSession({ events = [], meta = null, frames = [] } = {}) {
  const keydowns = [], keyups = [], inputs = [], compositions = [], pointer = [], focus = [];
  let untrusted = 0, imeKeys = 0, codeless = 0;
  for (const e of events) {
    if (e.trusted === false) untrusted++;
    switch (e.ev) {
      case 'kd': if (!e.rep) { keydowns.push(e); if (e.kc === 229 || e.comp) imeKeys++; if (!e.code || e.key === 'Unidentified') codeless++; } break;
      case 'ku': keyups.push(e); break;
      case 'bi': inputs.push(e); break;
      case 'cs': case 'ce': compositions.push(e); break;
      case 'pm': case 'pd': case 'pu': case 'wh': pointer.push(e); break;
      case 'vc': case 'focus': case 'blur': focus.push(e); break;
      default: break;
    }
  }
  const typedFrames = frames.filter(f => TYPED_KINDS.has(f.kind) && f.length === 0 && typeof f.inserted === 'string' && f.inserted.length >= 1);
  const insertions = inputs.filter(e => e.it === 'insertText' && typeof e.data === 'string' && e.data.length > 0 && !e.comp);
  // Modality: a physical keyboard gives every key a code; a touch keyboard gives none (or key 'Unidentified', keyCode
  // 229); an input method composes. Mixed when it's some of each.
  const total = keydowns.length;
  const imeShare = total ? imeKeys / total : 0, codelessShare = total ? codeless / total : 0;
  const composed = compositions.filter(e => e.ev === 'ce').length;
  let modality;
  if (total === 0 && insertions.length === 0) modality = composed ? 'ime' : meta?.coarse ? 'touch' : 'physical_keyboard';
  else if (composed >= 3 && (imeShare >= 0.3 || composed * 3 >= typedFrames.length)) modality = imeShare > 0.9 || total === 0 ? 'ime' : 'mixed';
  else if (codelessShare >= 0.8 && (meta?.coarse || meta?.touch)) modality = 'touch';
  else if (codelessShare <= 0.1 && imeShare <= 0.1) modality = 'physical_keyboard';
  else modality = 'mixed';
  // The offset between the two clocks: the stream's events are stamped from the page's time origin, the frames from
  // the recording's start. Each typed frame follows its key press (or input) within a few milliseconds, so the median
  // of (press time − frame time) over the nearest presses is the offset.
  // Composed words (an input method) land at their composition's end, so they're matched to those; everything else to
  // key presses (or, with no key codes, to the input events themselves).
  const presses = (modality === 'touch' || modality === 'ime' ? insertions : keydowns.filter(printable)).map(e => e.t).sort((a, b) => a - b);
  const ends = compositions.filter(e => e.ev === 'ce').map(e => e.t).sort((a, b) => a - b);
  const diffs = [];
  for (const [list, matched] of [[presses, typedFrames.filter(f => f.kind !== 'input-method')], [ends, typedFrames.filter(f => f.kind === 'input-method')]]) {
    if (!list.length || !matched.length) continue;
    const guess = list[0] - matched[0].time;
    for (const f of matched.slice(0, 4000)) {
      const target = f.time + guess, at = nearest(list, target);
      if (at !== null && Math.abs(list[at] - target) < 1500) diffs.push(list[at] - f.time);
    }
  }
  const offset = diffs.length ? median(diffs) : (presses.length && typedFrames.length ? presses[0] - typedFrames[0].time : 0);
  return { modality, keydowns, keyups, inputs, insertions, compositions, pointer, focus, typedFrames, frames, offset, untrusted, events, meta,
    imeShare, codelessShare };
}
/** The index of the value in sorted `values` nearest to `target`, or null when empty. */
export function nearest(values, target) {
  if (!values.length) return null;
  let lo = 0, hi = values.length - 1;
  while (lo < hi) { const mid = (lo + hi) >> 1; if (values[mid] < target) lo = mid + 1; else hi = mid; }
  if (lo > 0 && Math.abs(values[lo - 1] - target) <= Math.abs(values[lo] - target)) return lo - 1;
  return lo;
}
