// The writer's report for a page written here: the same PDF a reader saves (report-pdf.mjs), made in this browser
// from what it just proved, with the proof and the signed writing replay attached so the PDF alone checks out at
// huma.social/verify. A recording that stopped gets a report too: no score or proof, and why it stopped.
import { makeReport, REPLAY_FILE, VERIFY_URL } from '../pages/report-pdf.mjs';
import { humaScore, replayRhythm, percentLabel, checkTier, passkeyRow, duration, digest, WRITING_RULES } from '../publication-contract.mjs';
import { fromBase64 } from '../verify-core/contract.mjs';
import { verifyReplay, REPLAY_KIND } from '../replay-core.mjs';

const encoder = new TextEncoder();
const sha256 = value => digest(typeof value === 'string' ? encoder.encode(value) : value);

/** The signed writing replay (replay-core.mjs) from a finished recording: every edit and the final signed checkpoint. */
export function replayOf(recording) {
  const session = JSON.parse(recording).witness.session;
  const checkpoint = session.signedCheckpoints.filter(c => c.isFinal).at(-1);
  if (!checkpoint) throw new Error('The recording has no final signature.');
  return JSON.stringify({ kind: REPLAY_KIND, session: session.id, initialText: session.initialText,
    events: session.events.map(e => [e.elapsedMilliseconds, e.source, e.location, e.removedLength, e.insertedText]), checkpoint });
}

/**
 * What a proved page shows: its journal, the replay checked against the proof's key and text, the score and the
 * result, as a reader works them out (verify.mjs).
 */
export async function provedPage({ envelope, report, recording, text, replay: kept }) {
  const outer = JSON.parse(envelope), inner = outer.proof, page = JSON.parse(inner), j = report.proofReport.journal;
  // A page opened from the account carries its replay, not the recording it came from.
  const replay = kept ?? replayOf(recording), checked = await verifyReplay(replay, { publicKey: page.publicKey, text });
  const unmet = WRITING_RULES.filter((_, i) => j.rules?.[i] === false), notTyped = unmet.includes(WRITING_RULES[0]) || unmet.includes(WRITING_RULES[1]);
  const score = humaScore({ composition: checked.composition, typingEdits: Number(j.typing), edits: Number(j.edits), rules: j.rules,
    presenceCount: Number(j.presence_count), onTime: Number(j.on_time), browser: true, passkey: report.proofReport?.passkeyVerified === true,
    rhythmAutomated: replayRhythm(checked.frames).automated });
  // The result in a few words; the typing checks say the rest.
  const c = checked.composition, share = part => percentLabel(c.total ? part / c.total : 0);
  const mix = c.pasted ? `${share(c.typed + c.external)} typed, ${share(c.pasted)} pasted. Unchanged since.` : 'Unchanged since it was written.';
  const status = { verified: !unmet.length, headline: !unmet.length ? 'Typed in Huma' : notTyped ? 'Written in Huma, not all typed' : 'Typed in Huma, not all checks met', detail: mix };
  return { envelope, inner, page, journal: j, replay, composition: checked.composition, origin: checked.origin, text, unmet, score, status };
}

/** Paragraphs as runs of text, pasted or not, one per line of the page. */
function paragraphs(text, origin) {
  const out = [];
  let at = 0;
  for (const line of text.split('\n')) {
    const runs = [];
    for (let i = 0, run = 0; i <= line.length; i++) {
      const pasted = index => origin?.[at + index] === 'p';
      if (i < line.length && pasted(i) === pasted(run)) continue;
      if (i > run) runs.push({ text: line.slice(run, i), pasted: pasted(run) });
      run = i;
    }
    out.push(runs.length ? runs : [{ text: '', pasted: false }]);
    at += line.length + 1;
  }
  return out;
}

/** The PDF library and the report's fonts, for the page's own PDF too (export.mjs). */
export const pdfTools = () => tools().then(t => t.options);
async function tools() {
  // Loaded only when a report is made: the PDF library and its font tool, the QR code, the fonts and the mark.
  const at = path => new URL(path, location.origin).href;
  const script = src => new Promise((resolve, reject) => {
    if (globalThis.fontkit) return resolve();
    const tag = Object.assign(document.createElement('script'), { src, onload: resolve, onerror: reject }); document.head.append(tag);
  });
  const bytes = async path => new Uint8Array(await (await fetch(at(path))).arrayBuffer());
  const [PDFLib, { default: encodeQR }, , serif, bold, mark] = await Promise.all([import(at('/vendor/pdf-lib/pdf-lib.mjs')), import(at('/vendor/qr/qr.mjs')),
    script(at('/vendor/pdf-lib/fontkit.js')), bytes('/fonts/tinos-report.ttf'), bytes('/fonts/tinos-bold-report.ttf'), fetch(at('/brand/huma-mark.svg')).then(r => r.text())]);
  return { encodeQR, options: { PDFLib, fontkit: globalThis.fontkit, fonts: { serif, bold }, mark: mark.match(/ d="([^"]+)"/)[1] } };
}

/** The report for a proved page, as PDF bytes. */
/** `link`: the page's shared link, which the code opens; a page that isn't shared gets no code. */
export async function provedReport(proved, title, link) {
  const { encodeQR, options } = await tools(), j = proved.journal, c = proved.composition, s = proved.score;
  return makeReport({
    title: title || proved.text.trim().split('\n')[0].slice(0, 140), where: 'browser', tier: checkTier(true, s.passkey).label, status: proved.status,
    rules: WRITING_RULES.map(rule => !proved.unmet.includes(rule)),
    started: new Date(Number(j.start_unix)), ended: new Date(Number(j.end_unix)), savedAt: new Date(), madeBy: 'Huma',
    score: { value: s.value, weights: s.weights, rows: [
      ['Typed', percentLabel(s.handTyped ?? 0), `${s.points.typed} / ${s.weights[0]}`],
      ['Typing checks', `${s.checksMet} of 7 met`, `${s.points.checks} / ${s.weights[1]}`],
      ['Check-ins', s.presenceCount ? `${s.presenceOnTime} of ${s.presenceCount} on time` : 'None needed', `${s.points.touch} / ${s.weights[2]}`]],
      terms: { typed: s.typedShare, checks: [s.checksMet, 7], touch: [s.presenceOnTime, s.presenceCount] } },
    session: [['Writing time', duration(j.elapsed)], ['Key presses', Number(j.samples).toLocaleString('en-US')],
      ['Typed', percentLabel(c.total ? (c.typed + c.external) / c.total : 0)], ['Pasted', percentLabel(c.total ? c.pasted / c.total : 0)],
      ...(s.passkey ? [passkeyRow(proved.page)] : [])],
    proof: { fingerprint: await sha256(proved.inner), textHash: JSON.parse(proved.envelope).statement?.contentHash,
      signingKey: await sha256(fromBase64(proved.page.publicKey)), parts: (proved.page.chunks?.length ?? 0) + 1,
      size: Math.max(1, Math.round(proved.envelope.length / 1024)) + ' KB' },
    link: link ?? undefined, qr: link ? encodeQR(link, 'raw', { ecc: 'medium', border: 0 }) : undefined, paragraphs: paragraphs(proved.text, proved.origin),
    mix: c.total ? { typed: percentLabel((c.typed + c.external) / c.total), pasted: percentLabel(c.pasted / c.total), share: c.pasted / c.total } : undefined,
    attachment: { name: 'Huma-evidence.json', bytes: encoder.encode(proved.envelope) },
    replay: { name: REPLAY_FILE, bytes: encoder.encode(proved.replay) },
  }, options);
}

/** The report for a recording that stopped: why, the typing measured, and the text, with no score or proof. */
export async function stoppedReport({ title, text, reason, measures, started, elapsed }) {
  const { options } = await tools(), m = measures ?? {}, ms = v => (v === null || v === undefined ? '–' : `${Math.round(v)} ms`);
  const pct = v => (v === null || v === undefined ? '–' : percentLabel(v));
  return makeReport({
    title: title || text.trim().split('\n')[0].slice(0, 140) || 'Untitled document', where: 'browser', tier: checkTier(true).label,
    status: { verified: false, headline: 'Not proved: recording stopped', detail: reason },
    stopped: [['Key presses', String(m.keys ?? 0)], ['Typical key hold', ms(m.holdTime)], ['Keys released at once', pct(m.instantHolds)],
      ['Typical gap between keys', ms(m.typingGap)], ['Gaps within 3 ms of each other', pct(m.evenGaps)],
      ['Slower at word starts', m.wordStartShift === null || m.wordStartShift === undefined ? 'Not enough typing' : m.wordStartShift >= 2 ? 'Yes' : 'No'],
      ['Faster across hands', m.handShift === null || m.handShift === undefined ? 'Not enough typing' : m.handShift >= 2 ? 'Yes' : 'No']],
    started, ended: new Date(), savedAt: new Date(), madeBy: 'Huma',
    session: [['Writing time', duration(elapsed)], ['Key presses', String(m.keys ?? 0)]], paragraphs: paragraphs(text, null), textHash: await sha256(text),
  }, options);
}
