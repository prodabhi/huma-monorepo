// The evaluation report: every saved session (detection/eval/sessions/, from harness.mjs and label.mjs) judged with
// the current thresholds, and the synthetic sessions beside them as a labelled sanity set. Writes REPORT.md and
// features.csv (one row per session, for Phase B training). Usage (from frontend/): node detection/eval/report.mjs
import { readdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { judge } from './harness.mjs';
import { scoreSession, DEFAULT_THRESHOLDS } from '../score.mjs';
import { FEATURES, extractFeatures } from '../features.mjs';
import { checkIntegrity } from '../integrity.mjs';
import { GENERATORS, SAMPLE_TEXT, OTHER_TEXT } from './synthetic.mjs';

const here = path.dirname(fileURLToPath(import.meta.url)), sessionsDir = path.join(here, 'sessions');
const NAMES = Object.values(FEATURES).flat();
const pct = (n, d) => (d ? Math.round((100 * n) / d) + '%' : 'n/a');
const caught = v => v.band === 'likely_automated' || v.integrity === 'fail';
/** A recorded run is caught when its verdict says so, or when the page itself stopped the recording (no page results). */
const caughtRun = s => caught(s.verdict) || /^halted/.test(s.outcome ?? '');

/** A saved session's verdict: judged from its raw stream and frames, or scored from its kept feature values. */
function verdictOf(session) {
  // A harness run is judged even when the page stopped it before anything streamed (no stream fails integrity).
  if (session.stream || session.frames?.length || session.outcome) return judge(session);
  if (session.features) {
    const features = { modality: session.modality ?? 'physical_keyboard', version: 'features-1',
      features: Object.fromEntries(NAMES.map(name => { const kept = session.features[name]; return [name, kept ? { value: kept[0], confidence: kept[1] } : { value: null, confidence: 0 }]; })) };
    return scoreSession({ features, integrity: session.integrity ?? { status: 'pass', failures: [], penalties: [] }, traps: session.traps ?? {} });
  }
  return null;
}
/** The detection rate per generator at a probability cut that keeps the human false-positive rate at or under 1%. */
function cutFor(humans, bots) {
  // The cut: the highest probability at which at most 1% of human sessions fall below it (a human below the cut is a
  // false positive); without human sessions the thresholds' own band cut applies.
  if (!humans.length) return { cut: DEFAULT_THRESHOLDS.bands.likely_automated, basis: 'the thresholds file (no human sessions yet)' };
  const sorted = humans.map(v => v.humanProbability).sort((a, b) => a - b), allowed = Math.floor(0.01 * sorted.length);
  return { cut: sorted[allowed] - 1e-9, basis: `${humans.length} human sessions at 1% false positives` };
}

export async function buildReport() {
  const files = (await readdir(sessionsDir).catch(() => [])).filter(name => name.endsWith('.json'));
  const sessions = [];
  for (const name of files) { try { sessions.push({ file: name, ...JSON.parse(await readFile(path.join(sessionsDir, name), 'utf8')) }); } catch {} }
  // A generator that couldn't run (no permission, no API key) is reported, never counted.
  const skippedRuns = sessions.filter(s => /^skipped/.test(s.outcome ?? ''));
  const rows = sessions.filter(s => !/^skipped/.test(s.outcome ?? '')).map(s => ({ ...s, verdict: verdictOf(s) })).filter(s => s.verdict);
  const humans = rows.filter(s => s.label === 'human'), bots = rows.filter(s => s.label !== 'human');
  const { cut, basis } = cutFor(humans.map(s => s.verdict), bots.map(s => s.verdict));
  const byGenerator = {};
  for (const s of bots) (byGenerator[s.generator] ??= []).push(s);
  const lines = [];
  lines.push('# Detection evaluation report', '', `Generated ${new Date().toISOString()} by \`node detection/eval/report.mjs\` with thresholds \`${DEFAULT_THRESHOLDS.modelVersion}\`.`, '');
  lines.push('## Recorded sessions', '', `${rows.length} sessions in \`detection/eval/sessions/\`: ${humans.length} human, ${bots.length} from generators.`,
    `Detection cut: human probability below ${cut.toFixed(2)}, from ${basis}; a session also counts as caught when its integrity fails.`, '');
  lines.push('| Generator | Sessions | Caught (page halt, band or integrity) | Caught at the cut | Halted by the page itself | Median p(human) | Outcome notes |', '| --- | --- | --- | --- | --- | --- | --- |');
  for (const [generator, list] of Object.entries(byGenerator)) {
    const ps = list.map(s => s.verdict.humanProbability).sort((a, b) => a - b);
    const halted = list.filter(s => /^halted/.test(s.outcome ?? '')).length;
    lines.push(`| ${generator} | ${list.length} | ${pct(list.filter(caughtRun).length, list.length)} | ${pct(list.filter(s => s.verdict.humanProbability < cut || s.verdict.integrity === 'fail' || /^halted/.test(s.outcome ?? '')).length, list.length)} | ${halted} | ${ps[Math.floor(ps.length / 2)]?.toFixed(2) ?? ''} | |`);
  }
  for (const generator of new Set(skippedRuns.map(s => s.generator))) if (!byGenerator[generator]) lines.push(`| ${generator} | 0 | n/a | n/a | 0 | | not run: ${skippedRuns.find(s => s.generator === generator).outcome.replace(/^skipped: /, '')} |`);
  lines.push('', '### Human false positives by modality', '');
  if (!humans.length) lines.push('No human sessions recorded yet. Record consented sessions on huma.social (or a local registry) and label them with `node detection/eval/label.mjs`; until then the human side of every number below comes from the synthetic model only, which is not evidence.', '');
  else {
    lines.push('| Modality | Sessions | Below the cut | Likely automated | Integrity failed |', '| --- | --- | --- | --- | --- |');
    const byModality = {}; for (const s of humans) (byModality[s.verdict.modality] ??= []).push(s);
    for (const [modality, list] of Object.entries(byModality)) lines.push(`| ${modality} | ${list.length} | ${pct(list.filter(s => s.verdict.humanProbability < cut).length, list.length)} | ${pct(list.filter(s => s.verdict.band === 'likely_automated').length, list.length)} | ${pct(list.filter(s => s.verdict.integrity === 'fail').length, list.length)} |`);
    lines.push('');
  }
  lines.push('### Feature importance (mean |logit contribution| over recorded sessions)', '');
  const importance = {};
  for (const s of rows) for (const [name, c] of Object.entries(s.verdict.contributions)) { importance[name] ??= { sum: 0, n: 0 }; importance[name].sum += Math.abs(c); importance[name].n++; }
  lines.push('| Feature | Sessions measured | Mean |contribution| |', '| --- | --- | --- |');
  for (const [name, { sum, n }] of Object.entries(importance).sort((a, b) => b[1].sum / b[1].n - a[1].sum / a[1].n)) lines.push(`| ${name} | ${n} | ${(sum / n).toFixed(2)} |`);
  lines.push('', '### Reasons per generator (how often each feature is among a session’s top reasons)', '');
  for (const [generator, list] of Object.entries(byGenerator)) {
    const counts = {};
    for (const s of list) for (const r of s.verdict.reasons) if (r.direction === 'automated') counts[r.feature] = (counts[r.feature] ?? 0) + 1;
    lines.push(`- **${generator}**: ` + (Object.entries(counts).sort((a, b) => b[1] - a[1]).slice(0, 6).map(([f, n]) => `${f} (${n}/${list.length})`).join(', ') || 'none'));
  }
  // The synthetic sanity set: the same code on the model of typing in synthetic.mjs.
  lines.push('', '## Synthetic sanity set', '', 'The generators of `detection/eval/synthetic.mjs` (a model of a person, and of each way software types), 6 seeds each on two texts, judged by the same code. This checks the code, not the world: the person here is a model.', '');
  lines.push('| Generator (synthetic) | Sessions | Likely automated or integrity failed | Median p(human) | Web (stream + replay) | Mac (replay only) |', '| --- | --- | --- | --- | --- | --- |');
  const synthetic = [];
  for (const [name, make] of Object.entries(GENERATORS)) {
    const web = [], mac = [];
    for (const text of [SAMPLE_TEXT, OTHER_TEXT]) for (let seed = 1; seed <= 6; seed++) {
      const s = make(text, seed);
      const f = extractFeatures({ events: s.stream.events, meta: s.stream.meta, frames: s.frames, text: s.text });
      const i = checkIntegrity({ stream: s.stream, frames: s.frames, text: s.text, journal: s.journal });
      const v = scoreSession({ features: f, integrity: i }); web.push(v);
      v.values = Object.fromEntries(Object.entries(f.features).map(([name, x]) => [name, x.value]));
      synthetic.push({ label: s.label === 'human' ? 'human' : 'bot', generator: name, modality: f.modality, verdict: v, synthetic: true });
      if (!name.includes('touch') && !name.includes('ime') && name !== 'fabricated_post') {
        const fm = extractFeatures({ events: [], meta: null, frames: s.frames, text: s.text });
        const im = checkIntegrity({ stream: null, frames: s.frames, text: s.text, journal: s.journal, platform: 'mac' });
        mac.push(scoreSession({ features: fm, integrity: im }));
      }
    }
    const ps = web.map(v => v.humanProbability).sort((a, b) => a - b);
    lines.push(`| ${name} | ${web.length} | ${pct(web.filter(caught).length, web.length)} | ${ps[Math.floor(ps.length / 2)].toFixed(2)} | ${pct(web.filter(caught).length, web.length)} | ${mac.length ? pct(mac.filter(v => v.band === 'likely_automated').length, mac.length) : 'n/a'} |`);
  }
  lines.push('', '## Acceptance criteria', '');
  const criteria = [];
  for (const [generator, list] of Object.entries(byGenerator)) {
    const target = ['replay_human', 'computer_use_agent'].includes(generator) ? 0.8 : 0.95, rate = list.filter(caughtRun).length / list.length;
    criteria.push(`- ${generator}: ${pct(list.filter(caughtRun).length, list.length)} caught, target ${target * 100}%: ${rate >= target ? 'met' : 'NOT met'} (${list.length} recorded sessions; three runs is a smoke test, not a rate).`);
  }
  if (!criteria.length) criteria.push('- No generator sessions recorded yet: run `node detection/eval/harness.mjs`.');
  for (const generator of new Set(skippedRuns.map(s => s.generator))) if (!byGenerator[generator]) criteria.push(`- ${generator}: not run (${skippedRuns.find(s => s.generator === generator).outcome.replace(/^skipped: /, '')}).`);
  criteria.push('- The Mac app: scripted keys are refused at the event source (HumaTextViewTests); a keyboard-like device is judged on the replay alone, see the synthetic table’s Mac column. No live Mac harness ran here (recording needs Touch ID and World ID at the keyboard).');
  criteria.push(humans.length ? `- Human false-positive rate: ${pct(humans.filter(s => s.verdict.humanProbability < cut || s.verdict.band === 'likely_automated').length, humans.length)} overall (target ≤ 1%).` : '- Human false-positive rate: not measurable yet (no human sessions).');
  criteria.push('- Collector handler time and input lag: measured by hand with a Performance panel trace while typing at 100+ WPM; not automated here.');
  criteria.push('- Traps: the DOM is asserted by test/collector.test.mjs; the VoiceOver, NVDA and autofill pass is a manual checklist (see below) and has not been run by the implementing agent.');
  lines.push(...criteria, '', '## Manual checklist (not run)', '', '- VoiceOver (macOS) and NVDA (Windows): open /write, start recording, read through the page: the canary note and the “Alternate title” field must never be announced or reachable.',
    '- Autofill: with a password manager and browser autofill on, open /write and sign in: the `title_alt` field must stay empty (the server would record a honeypot hit).',
    '- Performance: Chrome DevTools Performance trace while typing fast; the collector’s listeners must stay under 1 ms each.', '');
  await writeFile(path.join(here, 'REPORT.md'), lines.join('\n'));
  // Phase B training data: one row per session, feature values (blank when unavailable) and the label.
  const csvRows = [...rows.map(s => ({ ...s, synthetic: false })), ...synthetic].map(s => {
    const value = name => s.verdict.values?.[name] ?? s.features?.[name]?.[0] ?? null;
    return [s.label === 'human' ? 1 : 0, s.generator ?? 'human', s.verdict.modality, s.synthetic ? 1 : 0, s.verdict.integrity === 'pass' ? 1 : 0,
      ...NAMES.map(name => (value(name) === null ? '' : value(name)))].join(',');
  });
  await writeFile(path.join(here, 'features.csv'), ['human,generator,modality,synthetic,integrity_pass,' + NAMES.join(',')].concat(csvRows).join('\n') + '\n');
  return { sessions: rows.length, humans: humans.length, bots: bots.length };
}
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  buildReport().then(summary => { console.log('REPORT.md written:', summary); process.exit(0); }, error => { console.error(error); process.exit(1); });
}
