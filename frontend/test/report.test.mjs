import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
import * as PDFLib from '../pages/vendor/pdf-lib/pdf-lib.mjs';
import encodeQR from '../pages/vendor/qr/qr.mjs';
import { makeReport, attachedProof, references } from '../pages/report-pdf.mjs';

// The shared page's report: a real PDF, with the page proof inside that the verify page reads back out.
test('the report is a PDF that carries its page proof', { timeout: 30000 }, async () => {
  const fontkit = createRequire(import.meta.url)('@pdf-lib/fontkit/dist/fontkit.umd.min.js');
  const read = name => readFile(new URL('../pages/' + name, import.meta.url));
  const [serif, bold, svg] = await Promise.all(['fonts/tinos-report.ttf', 'fonts/tinos-bold-report.ttf', 'brand/huma-mark.svg'].map(read));
  const tools = { PDFLib, fontkit, fonts: { serif, bold }, mark: String(svg).match(/ d="([^"]+)"/)[1] };
  const evidence = JSON.stringify({ kind: 'huma-evidence-envelope-v1', proof: '{"text":"Hello."}' });
  const report = (link, words) => ({
    title: 'A letter to my sister', writer: 'Swayam', started: new Date(0), ended: new Date(60000), savedAt: new Date(0), madeBy: 'a test',
    status: { verified: true, headline: 'Verified: typed in Huma', detail: 'Typed key by key in the Huma app. Unchanged since.' }, rules: Array(9).fill(true),
    score: { value: 100, rows: [['Typed by hand', '100% of the text', '70 / 70'], ['Typing checks', '7 of 7 met', '20 / 20'], ['Touch ID', '1 of 1 answered within 10 seconds', '10 / 10']],
      terms: { typed: 1, checks: [7, 7], touch: [1, 1] } },
    session: [['Writing time', '2 min'], ['Key presses', '310'], ['Pasted', '0%'], ['Replay', 'Shared']],
    proof: { fingerprint: 'd'.repeat(64), textHash: 'f'.repeat(64), signingKey: 'e'.repeat(64), parts: 9, size: '179 KB' },
    link, qr: encodeQR(link ?? 'https://huma.social/verify', 'raw', { ecc: 'medium', border: 0 }),
    paragraphs: [[{ text: 'Typed words. '.repeat(words), pasted: false }, { text: 'Pasted words.', pasted: true }]], mix: { typed: '95%', pasted: '5%', share: 0.05 },
    attachment: { name: 'Huma-evidence.json', bytes: new TextEncoder().encode(evidence) },
  });
  // Every address the report cites is a link, and the references list it in full.
  const links = async bytes => (await PDFLib.PDFDocument.load(bytes)).getPages().flatMap(page => (page.node.Annots()?.asArray() ?? [])
    .map(ref => page.doc.context.lookup(ref)).map(annot => annot.lookup(PDFLib.PDFName.of('A'))?.lookup(PDFLib.PDFName.of('URI'))?.decodeText()).filter(Boolean));
  const shared = await makeReport(report('https://huma.social/p/Ab3xK9q2#V8nq2LxP0aZt7Ru4', 20), tools);
  assert.equal(new TextDecoder().decode(shared.slice(0, 5)), '%PDF-');
  assert.equal(await attachedProof(shared, PDFLib), evidence);
  // A cover, the text, then one page that verifies it; the cover's contents lead to each.
  const loaded = await PDFLib.PDFDocument.load(shared);
  assert.equal(loaded.getPageCount(), 3);
  const cover = loaded.getPage(0).node.Annots().asArray().map(ref => loaded.context.lookup(ref)).map(annot => annot.lookup(PDFLib.PDFName.of('Dest')))
    .filter(Boolean).map(dest => loaded.getPages().findIndex(page => page.ref === dest.get(0)));
  assert.deepEqual(cover, [1, 2]);
  const cited = new Set(await links(shared));
  for (const url of ['https://huma.social/p/Ab3xK9q2#V8nq2LxP0aZt7Ru4', 'https://huma.social/verify', 'https://huma.social',
    'https://support.apple.com/guide/security/secure-enclave-sec59b0b31ff/web', 'https://noir-lang.org/docs', 'https://barretenberg.aztec.network/docs']) assert.ok(cited.has(url), url);
  assert.deepEqual(references({ link: 'x' }).map(item => item.key), ['site', 'noir', 'barretenberg', 'enclave', 'page', 'verify']);
  assert.ok(!cited.has(undefined) && ![...cited].some(url => url.includes('basescan')));
  // A long page runs onto more pages; a page not shared yet points at the verify page instead of a link.
  const long = await makeReport(report(undefined, 900), tools);
  assert.ok((await PDFLib.PDFDocument.load(long)).getPageCount() > 3);
  assert.ok(!(await links(long)).includes('https://huma.social/p/Ab3xK9q2#V8nq2LxP0aZt7Ru4'));
  assert.equal(await attachedProof(long, PDFLib), evidence);
  // Parentheses in a link stay inside its string: no PDF keys can be added through the link.
  const sneaky = 'https://huma.social/p/Ab3xK9q2?x=)/S/JavaScript/JS(app.alert(1)\\#V8nq2LxP0aZt7Ru4';
  const escaped = await makeReport(report(sneaky, 20), tools);
  assert.ok((await links(escaped)).includes(sneaky));
  assert.ok(!new TextDecoder('latin1').decode(escaped).includes('/S /JavaScript') && !new TextDecoder('latin1').decode(escaped).includes('/S/JavaScript'));
});
