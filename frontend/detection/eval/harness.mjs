// The evaluation harness: each way software types, run against the real write page in Chrome on a registry started
// here, with the editor's own collector streaming to it. Every run is saved as a labelled session under
// detection/eval/sessions/ for report.mjs. Usage (from frontend/, after node write/build.mjs):
//   node detection/eval/harness.mjs [generator ...] [--runs N] [--text short|long] [--headless]
// Generators: playwright_type cdp_inserttext cdp_dispatch_humanized agent_read_type cdp_replay_model os_type replay_human computer_use_agent fabricated_post.
// Chrome is the installed one (Playwright's "chrome" channel: nothing is downloaded). os_type needs Accessibility
// permission for this terminal (it types through System Events); computer_use_agent needs ANTHROPIC_API_KEY.
import { mkdir, writeFile, readFile, readdir } from 'node:fs/promises';
import { execFile } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRegistry } from '../../registry.mjs';
import { checkIntegrity } from '../integrity.mjs';
import { extractFeatures } from '../features.mjs';
import { scoreSession } from '../score.mjs';
import { batchMAC } from '../stream.mjs';
import { GENERATORS, SAMPLE_TEXT, OTHER_TEXT, random, recordedTimings, simulateTyping, humanModel } from './synthetic.mjs';
import { codeOf, needsShift, neighbour } from '../keyboard.mjs';

const here = path.dirname(fileURLToPath(import.meta.url)), sessionsDir = path.join(here, 'sessions');
const args = process.argv.slice(2), flag = name => { const i = args.indexOf(name); return i >= 0 ? args[i + 1] : null; };
// Headed, as a harness must be: a headless Chrome says so in its user agent, and the page refuses it at once.
const RUNS = Number(flag('--runs') ?? 3), HEADED = !args.includes('--headless');
const TEXT = flag('--text') === 'long' ? SAMPLE_TEXT : SAMPLE_TEXT.slice(0, 420);
const wanted = args.filter(a => !a.startsWith('--') && !/^\d+$/.test(a) && !['short', 'long'].includes(a));
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));

/** The write page, recording: Start Recording pressed, the editor focused. Returns the page and a reader of its session. */
async function openWriter(browser, base) {
  const context = await browser.newContext({ viewport: { width: 1200, height: 900 } });
  const page = await context.newPage();
  const errors = [];
  page.on('pageerror', e => errors.push(String(e)));
  await page.goto(base + '/write', { waitUntil: 'load' });
  await page.waitForFunction(() => document.body.dataset.state && document.body.dataset.state !== 'loading', null, { timeout: 60000 });
  // The page's own checks that a harness gets past: the DevTools probe (write/automation.mjs runtimeProbe) is skipped
  // once console.groupEnd isn't the browser's own.
  await page.evaluate(() => { const original = console.groupEnd; console.groupEnd = function (...a) { return original.apply(console, a); }; });
  await page.click('#startGo');
  // Recording, or stopped at Start by the page's own checks (a halt is a catch too: the run is recorded as such).
  await page.waitForFunction(() => document.body.dataset.state === 'writing' || document.getElementById('halt').open || document.getElementById('message')?.textContent?.includes('software'), null, { timeout: 60000 });
  const stoppedAtStart = await page.evaluate(() => document.getElementById('halt').open ? document.getElementById('haltText').textContent : document.body.dataset.state !== 'writing' ? document.getElementById('message')?.textContent : null);
  if (!stoppedAtStart) await page.click('.ProseMirror');
  const session = () => page.evaluate(() => window.__humaEval.session());
  return { context, page, session, errors, stoppedAtStart };
}
const END_KEY = process.platform === 'darwin' ? 'Meta+ArrowDown' : 'Control+End';
/** The page's dialogs, as a harness meets them: a halt ends the run; a retype check is answered with the same typist. */
async function dialogs(page, typeChar) {
  const state = await page.evaluate(() => ({ halted: document.getElementById('halt').open, retype: document.getElementById('retype').open ? document.getElementById('retypePhrase').textContent : null }));
  if (state.halted) return 'halted';
  if (state.retype) {
    await page.click('#retypeInput', { force: true });
    for (const c of state.retype) await typeChar(c);
    await page.click('#retypeGo', { force: true }); await sleep(800);
    const after = await page.evaluate(() => ({ halted: document.getElementById('halt').open, retype: document.getElementById('retype').open }));
    if (after.halted) return 'halted';
    if (after.retype) { await page.click('#retypeCancel', { force: true }).catch(() => {}); await sleep(300); }
    await page.click('.ProseMirror', { force: true }); await page.keyboard.press(END_KEY);
  }
  return 'ok';
}
/** Types `text` through `typeChar(ch)`, answering a retype check with the same typist, stopping when the page halts. */
async function typeWith(page, text, typeChar, { between = async () => {} } = {}) {
  for (const ch of text) {
    if (await dialogs(page, typeChar) === 'halted') return 'halted';
    await typeChar(ch);
    await between(ch);
  }
  return 'typed';
}
const keyFor = ch => ch === '\n' ? { key: 'Enter', code: 'Enter', text: '\r', vk: 13 } : ch === '\b' ? { key: 'Backspace', code: 'Backspace', text: undefined, vk: 8 }
  : { key: ch, code: codeOf(ch), text: ch, vk: ch.toUpperCase().charCodeAt(0) };

// ---- Generators -------------------------------------------------------------------------------------------------
const generators = {
  /** page.keyboard.type with a random delay per character. */
  async playwright_type({ page, rand }) {
    return typeWith(page, TEXT, async ch => { await page.keyboard.type(ch, { delay: 0 }); await sleep(rand.uniform(30, 150)); });
  },
  /** CDP Input.insertText in chunks: no keys at all. */
  async cdp_inserttext({ page, context, rand }) {
    const cdp = await context.newCDPSession(page);
    let from = 0;
    while (from < TEXT.length) {
      if (await page.evaluate(() => document.getElementById('halt').open)) return 'halted';
      const size = Math.min(TEXT.length - from, Math.round(rand.uniform(20, 120)));
      await cdp.send('Input.insertText', { text: TEXT.slice(from, from + size) }); from += size;
      await sleep(rand.uniform(300, 1500));
    }
    return 'typed';
  },
  /** CDP Input.dispatchKeyEvent with log-normal delays, Shift around capitals, adjacent-key typos fixed at once. */
  async cdp_dispatch_humanized({ page, context, rand }) {
    const cdp = await context.newCDPSession(page);
    const down = async (k, modifiers = 0) => cdp.send('Input.dispatchKeyEvent', { type: 'keyDown', key: k.key, code: k.code, text: k.text, unmodifiedText: k.text, windowsVirtualKeyCode: k.vk, nativeVirtualKeyCode: k.vk, modifiers });
    const up = async (k, modifiers = 0) => cdp.send('Input.dispatchKeyEvent', { type: 'keyUp', key: k.key, code: k.code, windowsVirtualKeyCode: k.vk, nativeVirtualKeyCode: k.vk, modifiers });
    const shift = { key: 'Shift', code: 'ShiftLeft', text: undefined, vk: 16 };
    const press = async ch => {
      const k = keyFor(ch), shifted = needsShift(ch);
      if (shifted) { await down(shift); await sleep(rand.uniform(20, 80)); }
      await down(k, shifted ? 8 : 0); await sleep(rand.lognormal(75, 0.35)); await up(k, shifted ? 8 : 0);
      if (shifted) { await sleep(rand.uniform(10, 60)); await up(shift); }
    };
    return typeWith(page, TEXT, async ch => {
      if (/[a-z]/.test(ch) && rand() < 0.03) { await press(neighbour(ch, rand)); await sleep(rand.lognormal(110, 0.5)); await press('\b'); await sleep(rand.lognormal(110, 0.5)); }
      await press(ch); await sleep(rand.lognormal(110, 0.5) + (rand() < 0.015 ? rand.uniform(1000, 3000) : 0));
    });
  },
  /** The OS types (System Events on macOS, xdotool on Linux) with random sleeps between keys. */
  async os_type({ page, rand }) {
    await page.bringToFront();
    const osa = text => new Promise((resolve, reject) => execFile('osascript', ['-e', `tell application "System Events" to keystroke ${JSON.stringify(text)}`], (error, out, err) => (error ? reject(new Error(err || error.message)) : resolve())));
    const xdo = text => new Promise((resolve, reject) => execFile('xdotool', ['type', '--delay', '12', text], error => (error ? reject(error) : resolve())));
    const type = process.platform === 'darwin' ? osa : xdo;
    try { await type('x'); } catch (error) { return 'skipped: ' + error.message.split('\n')[0]; }
    await page.keyboard.press('Backspace');
    return typeWith(page, TEXT, async ch => { await type(ch === '\n' ? '\r' : ch); await sleep(rand.uniform(30, 130)); });
  },
  /** A recorded person's timings (a labelled human session if there is one, else the synthetic person) over this text. */
  async replay_human({ page, context, rand, humanTimings }) {
    const timings = humanTimings ?? recordedTimings(simulateTyping(OTHER_TEXT, humanModel(), { seed: 17 }));
    const cdp = await context.newCDPSession(page);
    let g = 0, h = 0;
    const down = (k, modifiers = 0) => cdp.send('Input.dispatchKeyEvent', { type: 'keyDown', key: k.key, code: k.code, text: k.text, unmodifiedText: k.text, windowsVirtualKeyCode: k.vk, nativeVirtualKeyCode: k.vk, modifiers });
    const up = (k, modifiers = 0) => cdp.send('Input.dispatchKeyEvent', { type: 'keyUp', key: k.key, code: k.code, windowsVirtualKeyCode: k.vk, nativeVirtualKeyCode: k.vk, modifiers });
    const shift = { key: 'Shift', code: 'ShiftLeft', vk: 16 };
    return typeWith(page, TEXT, async ch => {
      const k = keyFor(ch), shifted = needsShift(ch);
      if (shifted) { await down(shift); await sleep(rand.uniform(40, 200)); }
      await down(k, shifted ? 8 : 0); await sleep(timings.holds[h++ % timings.holds.length]); await up(k, shifted ? 8 : 0);
      if (shifted) { await sleep(rand.uniform(15, 120)); await up(shift); }
      await sleep(Math.max(0, timings.gaps[g++ % timings.gaps.length] - 1));
    });
  },
  /** An agent that reads before it writes: the page's text, DOM and accessibility tree before each chunk (as an agent
   *  loop does: look, think, act), then a chunk typed with humanised CDP keys; reading copies from the editor too. */
  async agent_read_type({ page, context, rand }) {
    const cdp = await context.newCDPSession(page);
    const down = (k, modifiers = 0) => cdp.send('Input.dispatchKeyEvent', { type: 'keyDown', key: k.key, code: k.code, text: k.text, unmodifiedText: k.text, windowsVirtualKeyCode: k.vk, nativeVirtualKeyCode: k.vk, modifiers });
    const up = (k, modifiers = 0) => cdp.send('Input.dispatchKeyEvent', { type: 'keyUp', key: k.key, code: k.code, windowsVirtualKeyCode: k.vk, nativeVirtualKeyCode: k.vk, modifiers });
    const shift = { key: 'Shift', code: 'ShiftLeft', vk: 16 };
    const read = async () => {
      await page.content(); await page.locator('.ProseMirror').innerText(); await cdp.send('Accessibility.getFullAXTree').catch(() => {});
      await page.screenshot({ type: 'png' }).catch(() => {});
      // Reads the editor by selecting and copying it, as an agent might to get its text back.
      await page.keyboard.press(process.platform === 'darwin' ? 'Meta+a' : 'Control+a'); await page.keyboard.press(process.platform === 'darwin' ? 'Meta+c' : 'Control+c');
      await page.keyboard.press(END_KEY);
    };
    let sinceRead = 0, next = Math.round(rand.uniform(40, 90));
    await read(); await sleep(rand.uniform(4000, 7000));
    const press = async ch => {
      const k = keyFor(ch), shifted = needsShift(ch);
      if (shifted) { await down(shift); await sleep(rand.uniform(20, 80)); }
      await down(k, shifted ? 8 : 0); await sleep(rand.lognormal(75, 0.35)); await up(k, shifted ? 8 : 0);
      if (shifted) { await sleep(rand.uniform(10, 60)); await up(shift); }
    };
    return typeWith(page, TEXT, async ch => { await press(ch); await sleep(rand.lognormal(100, 0.4)); },
      { between: async () => { if (++sinceRead >= next && await dialogs(page, press) === 'ok') { sinceRead = 0; next = Math.round(rand.uniform(40, 90)); await read(); await sleep(rand.uniform(4000, 7000)); } } });
  },
  /** The strongest attacker this harness knows: a perfect model of a person (synthetic.mjs humanModel: word starts,
   *  letter pairs, pauses at boundaries, typos fixed late, rewrites, dwell, rollover) replayed key for key over CDP,
   *  with the mouse moved in steps to the editor first. Shows where timing alone stops telling. */
  async cdp_replay_model({ page, context, rand, seed }) {
    const cdp = await context.newCDPSession(page);
    const model = humanModel({ pointer: 'none' }); model.revise = () => false;
    const typed = simulateTyping(TEXT, model, { seed, startAt: 0 });
    const keys = typed.events.filter(e => e.ev === 'kd' || e.ev === 'ku');
    const box = await page.locator('.ProseMirror').boundingBox();
    await page.mouse.move(box.x - 200, box.y - 150); await page.mouse.move(box.x + 60, box.y + 30, { steps: 40 }); await page.mouse.click(box.x + 60, box.y + 30);
    await sleep(rand.uniform(2000, 4000));
    const started = performance.now();
    for (const e of keys) {
      if (await page.evaluate(() => document.getElementById('halt').open)) return 'halted';
      const wait = started + e.t - performance.now(); if (wait > 0) await sleep(wait);
      const key = e.code === 'ShiftLeft' ? 'Shift' : e.code === 'Backspace' ? 'Backspace' : e.key, text = key.length === 1 ? key : undefined;
      const vk = key === 'Shift' ? 16 : key === 'Backspace' ? 8 : key.toUpperCase().charCodeAt(0);
      await cdp.send('Input.dispatchKeyEvent', { type: e.ev === 'kd' ? 'keyDown' : 'keyUp', key, code: e.code, ...(e.ev === 'kd' && text ? { text, unmodifiedText: text } : {}), windowsVirtualKeyCode: vk, nativeVirtualKeyCode: vk, modifiers: e.shift ? 8 : 0 });
      if (e.ev === 'kd' && await page.evaluate(() => document.getElementById('retype').open)) {
        const phrase = await page.evaluate(() => document.getElementById('retypePhrase').textContent);
        await page.click('#retypeInput', { force: true }); await page.keyboard.type(phrase, { delay: 90 }); await page.click('#retypeGo', { force: true }); await sleep(800);
        await page.click('.ProseMirror', { force: true }); await page.keyboard.press(END_KEY);
      }
    }
    return 'typed';
  },
  /** A real computer-use agent writing an essay: Claude with the computer tool over this page's screenshots. */
  async computer_use_agent({ page, context }) {
    if (!process.env.ANTHROPIC_API_KEY) return 'skipped: ANTHROPIC_API_KEY is not set';
    const { computerUseAgent } = await import('./computer-use.mjs');
    return computerUseAgent({ page, context, essay: 'Write a short essay (about 350 characters) about a river in a dry summer, in the editor on screen. Click into the editor first, then type it.' });
  },
  /** A synthetic log posted straight to the stream: it must fail integrity. Needs no page. */
  async fabricated_post({ base, issued, seed }) {
    const typed = simulateTyping(TEXT, humanModel(), { seed });
    const ws = new WebSocket(base.replace('http', 'ws') + '/api/sessions/stream', { headers: { Origin: base } });
    const acks = []; ws.onmessage = e => acks.push(JSON.parse(e.data));
    await new Promise((resolve, reject) => { ws.onopen = resolve; ws.onerror = reject; });
    const first = typed.events[0].t; let index = 0;
    for (let at = first + 2500; at - 2500 <= typed.events.at(-1).t; at += 2500) {
      const events = typed.events.filter(e => e.t >= at - 2500 && e.t < at);
      ws.send(JSON.stringify({ session: issued.nonce, index, sentAt: at, hmac: batchMAC(issued.key, index, events), events, ...(index === 0 ? { meta: typed.meta } : {}) })); index++;
    }
    const until = Date.now() + 10000; while (acks.length < index && Date.now() < until) await sleep(20);
    ws.close();
    return { outcome: 'posted', text: typed.text, frames: typed.frames, nonce: issued.nonce };
  },
};

async function main() {
  await mkdir(sessionsDir, { recursive: true });
  const store = path.join(here, 'store');
  const server = await createRegistry({ store, publicationOptions: { detectionMode: 'shadow' } });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const base = `http://localhost:${server.address().port}`;
  const names = wanted.length ? wanted : Object.keys(generators);
  // A labelled human session's timings, for replay_human, if any were recorded.
  let humanTimings = null;
  for (const name of await readdir(sessionsDir).catch(() => [])) {
    if (!name.startsWith('human')) continue;
    try { const s = JSON.parse(await readFile(path.join(sessionsDir, name), 'utf8')); if (s.stream?.events?.length > 200) { humanTimings = recordedTimings({ events: s.stream.events }); break; } } catch {}
  }
  let browser = null;
  const { chromium } = await import('playwright-core');
  const results = [];
  try {
    for (const name of names) {
      const generator = generators[name];
      if (!generator) { console.error('Unknown generator', name); continue; }
      for (let run = 1; run <= RUNS; run++) {
        const seed = run * 7919 + name.length, rand = random(seed), started = Date.now();
        let outcome, text = '', frames = [], nonce = null, errors = [];
        if (name === 'fabricated_post') {
          const issued = await (await fetch(base + '/api/sessions', { method: 'POST' })).json();
          ({ outcome, text, frames, nonce } = await generator({ base, issued, seed }));
        } else {
          // Chrome's automation flag off, as a harness would have it: with it on, the page stops at once ("the browser says it
          // is automated", write/automation.mjs), so only the server's analysis is being tested here.
          browser ??= await chromium.launch({ channel: 'chrome', headless: !HEADED, args: ['--disable-blink-features=AutomationControlled'] });
          const writer = await openWriter(browser, base);
          try {
            outcome = writer.stoppedAtStart ? 'halted at Start: ' + writer.stoppedAtStart : await generator({ ...writer, base, rand, humanTimings });
            await sleep(3500); // the last batch flushes
            const session = await writer.session();
            ({ text, frames, nonce } = session); errors = writer.errors;
            if (session.halted) outcome = 'halted: ' + session.halted;
          } finally { await writer.context.close().catch(() => {}); }
        }
        const stream = nonce ? await server.streams.read(nonce) : null;
        const session = { label: 'bot', generator: name, modality: 'physical_keyboard', platform: 'web', outcome, seed, recordedAt: new Date(started).toISOString(), durationMs: Date.now() - started,
          pointerOwn: ['computer_use_agent', 'cdp_replay_model'].includes(name),
          nonce, text, frames, stream: stream ? { batches: stream.batches, meta: stream.meta, trap: stream.trap } : null, errors };
        const file = path.join(sessionsDir, `${name}-${run}.json`);
        await writeFile(file, JSON.stringify(session));
        const verdict = judge(session);
        results.push({ name, run, outcome, verdict });
        console.log(`${name} #${run}: ${outcome} → ${verdict.band} ${verdict.humanProbability} integrity ${verdict.integrity} (${Math.round(session.durationMs / 1000)} s)`);
      }
    }
  } finally {
    await browser?.close().catch(() => {});
    server.streams.close(); server.closeAllConnections(); server.close();
  }
  return results;
}
/** A saved session's verdict, as report.mjs scores it. */
export function judge(session) {
  // A harness run on a visible Chrome shares the screen with whoever is at the computer: pointer input over its window is
  // theirs, not the generator's, so it's left out for generators that never move the pointer (pointerOwn says which).
  const own = session.pointerOwn !== false;
  const stream = session.stream ? { ...session.stream, events: session.stream.batches.flatMap(b => b.events).filter(e => own || !['pm', 'pd', 'pu', 'wh'].includes(e.ev)), started: session.stream.batches[0]?.receivedAt ?? null } : null;
  const integrity = checkIntegrity({ stream, frames: session.frames ?? [], text: session.text ?? '', journal: session.journal ?? null, platform: session.platform ?? 'web' });
  const features = extractFeatures({ events: stream?.events ?? [], meta: stream?.meta ?? null, frames: session.frames ?? [], text: session.text ?? '' });
  const verdict = scoreSession({ features, integrity, traps: session.traps ?? {} });
  verdict.values = Object.fromEntries(Object.entries(features.features).map(([name, f]) => [name, f.value]));
  return verdict;
}
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().then(() => process.exit(0), error => { console.error(error); process.exit(1); });
}
