// Proves a page written here the way the Mac app does (LongChunkProver, and prove-long in integrations/noir/worker.mjs):
// closed parts prove in the background while the writer types, and Finish proves what's left and the final step,
// checks every proof and wraps them in the evidence file any reader checks (huma.social/verify).
import { assembleLong3, createLongVerifier, decodeFinal, KEYS, KEYS2, KEYS3 } from '../../backend/integrations/noir/long/reader.mjs';
import { createEvidenceVerifier } from '../verify-core/core.mjs';

const hex = bytes => Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
const b64 = bytes => btoa(Array.from(bytes, b => String.fromCharCode(b)).join(''));
const sha256 = async bytes => hex(new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)));
const fieldHex = value => BigInt(value).toString(16).padStart(64, '0');
/** A part proof's public inputs: the state it starts at, the one it ends at, and whether it starts the session. */
const boundary = input => fieldHex(input.expected.start_root) + fieldHex(input.expected.end_root) + fieldHex(input.expected.genesis ? 1 : 0);
// On this computer's own server (development), passkeys belong to localhost, which readers accept only when told to
// (an address like 127.0.0.1 can't hold a passkey).
const LOCAL = location.hostname === 'localhost';
// Half the cores, so the page stays quick to type in while parts prove behind it. (Past 8 threads a proof is barely
// quicker: 2.7 s a part on 16 against 3.0 s on 8.)
const CORES = navigator.hardwareConcurrency || 4;
export const THREADS = Math.max(2, Math.min(8, Math.floor(CORES / 2)));
// At Finish the writer has stopped typing, so a computer with the cores and memory (each prover holds about 1.5 GB;
// Chrome says how much there is, up to 8 GB, other browsers don't) gets a second prover on its other cores: the final
// step and the last parts prove at the same time instead of one after another.
const SECOND = CORES >= 4 && (navigator.deviceMemory ?? 8) >= 8 ? Math.max(2, Math.min(8, CORES - THREADS)) : 0;

// How long each step takes on this computer, learnt from the pages it proves, so Finish can say how long is left.
// Kept for each length of page (1024, 4096 or 10,000 characters): a longer page's final step takes a few times as
// long. A length this computer hasn't proved yet starts from the shortest one's times, scaled as measured.
const TIMES = 'huma-prove-times', DEFAULT_TIMES = { part: 12000, final: 12000, check: 3000 };
const SCALE = { 1024: { part: 1, final: 1 }, 4096: { part: 1.1, final: 2.7 }, 10000: { part: 2.2, final: 5.5 } };
const stored = tier => { try { return JSON.parse(localStorage.getItem(tier === 1024 ? TIMES : TIMES + '-' + tier) ?? 'null'); } catch { return null; } };
export function stepTimes(tier = 1024) {
  const own = stored(tier);
  if (own) return { ...DEFAULT_TIMES, ...own };
  const base = { ...DEFAULT_TIMES, ...stored(1024) }, scale = SCALE[tier] ?? SCALE[1024];
  return { part: Math.round(base.part * scale.part), final: Math.round(base.final * scale.final), check: base.check };
}
function learn(step, ms, tier = 1024) {
  try {
    const t = stepTimes(tier); t[step] = Math.round(t[step] * 0.4 + ms * 0.6);
    localStorage.setItem(tier === 1024 ? TIMES : TIMES + '-' + tier, JSON.stringify(t));
  } catch {}
}

/** One prover worker (prover-worker.mjs) on `threads` threads, answering one request at a time. */
class ProverWorker {
  constructor(url, threads) {
    this.worker = new Worker(url, { type: 'module' }); this.threads = threads; this.pending = new Map(); this.id = 0; this.ready = false;
    this.worker.onmessage = ({ data }) => { const done = this.pending.get(data.id); this.pending.delete(data.id); done?.(data); };
    this.worker.onerror = () => { for (const done of this.pending.values()) done({ ok: false, error: 'The prover stopped.' }); this.pending.clear(); };
  }
  ask(message) {
    return new Promise((resolve, reject) => {
      const id = ++this.id, started = performance.now();
      this.pending.set(id, reply => {
        if (reply.ok && message.type === 'prove') learn(message.name.startsWith('chunk') ? 'part' : 'final', performance.now() - started, Number(message.name.match(/\d+$/)[0]));
        reply.ok ? resolve(reply) : reject(new Error(reply.error));
      });
      this.worker.postMessage({ ...message, id, threads: this.threads });
    });
  }
  warm() { return this.ask({ type: 'warm' }).then(() => { this.ready = true; }); }
  prove(name, input) { return this.ask({ type: 'prove', name, input }); }
}

export class PageProver {
  constructor(workerURL, assets) {
    this.main = new ProverWorker(workerURL, THREADS);
    this.second = SECOND ? new ProverWorker(workerURL, SECOND) : null;
    this.assets = assets;
    this.parts = []; this.next = 0; this.closed = 0; this.failures = 0; this.task = null; this.stopped = false; this.recording = null; this.tier = 1024;
    this.onchange = () => {};
  }
  /** Gets the prover ready while the writer types, so the first part doesn't wait for it; then the second, used only
   *  at Finish, so its start never slows the first. */
  warm() { this.main.warm().then(() => this.second?.warm()).catch(() => {}); }
  /** About how long proving `parts` more parts and the final step takes, and the check: with a second prover ready,
   *  it starts on the final step and both take parts as they come free. */
  estimate(parts) {
    const t = this.times();
    if (!this.second?.ready) return parts * t.part + t.final + t.check;
    const free = [0, t.final];
    for (let i = 0; i < parts; i++) free[free[0] <= free[1] ? 0 : 1] += t.part;
    return Math.max(...free) + t.check;
  }
  /** This computer's times for the length of page being written. */
  times() { return stepTimes(this.tier); }
  /** About how long Finish takes from here. */
  remainingMs() { return this.estimate(Math.max(0, this.closed - this.parts.length)); }
  /** Parts proved so far, of the parts written. */
  get progress() { return { done: this.parts.length, total: Math.max(this.parts.length, this.closed), working: Boolean(this.task) }; }
  /** The recorder closed parts up to `closed`: prove the next one if nothing is proving. */
  offer(recording, closed) {
    this.recording = recording;
    // A newly closed part gets fresh tries, so a few failures don't stop proving for the page.
    if (closed > this.closed) this.failures = 0;
    this.closed = closed; this.startIfIdle();
  }
  async startIfIdle() {
    if (this.task || this.stopped || this.failures >= 3 || !this.recording || this.next >= this.closed) return;
    this.task = (async () => {
      let part = await this.recording.chunk(this.next);
      // The text outgrew its tier: every part is proved again at the next one, from the first.
      if (this.parts.length && this.parts[0].tier !== part.tier) { this.parts = []; this.next = 0; part = await this.recording.chunk(0); }
      this.tier = part.tier;
      const proved = await this.main.prove('chunk' + part.tier, part.input);
      this.parts.push({ index: part.index, tier: part.tier, proof: proved.proof, publicInputs: proved.publicInputs });
      this.next = part.index + 1; this.failures = 0;
    })().catch(() => { this.failures++; }).finally(() => { this.task = null; this.onchange(); this.startIfIdle(); });
    this.onchange();
  }
  async keys() {
    const load = async (prefix, pins) => Object.fromEntries(await Promise.all(Object.entries(pins).map(async ([name, pin]) => {
      const response = await fetch(new URL(prefix + name + '.vk', this.assets), { credentials: 'omit' });
      const bytes = new Uint8Array(await response.arrayBuffer());
      if (await sha256(bytes) !== pin) throw new Error('A checking key doesn’t match its pin.');
      return [name, bytes];
    })));
    const [keys, keys2, keys3] = await Promise.all([load('long-', KEYS), load('long2-', KEYS2), load('long3-', KEYS3)]);
    return { keys, keys2, keys3 };
  }
  /**
   * Finish, after the recording sealed: proves the parts still missing and the final step, then checks the page
   * proof like any reader would. Returns the evidence file and the full recording.
   */
  async finish(recording, onStep = () => {}) {
    this.stopped = true;
    if (this.task) onStep({ finishing: true });
    // The recorder answers in order, so the page's inputs come while a part may still be proving.
    const { summary, recording: saved } = await recording.proveInput();
    const tier = summary.tier, count = summary.chunks.length, started = performance.now();
    this.tier = tier;
    // The final step doesn't need the parts' proofs: a second prover starts on it now.
    const second = this.second?.ready ? this.second : null;
    const sealing = second ? second.prove('final' + tier, JSON.stringify(summary.final)).catch(() => null) : null;
    await this.task;
    const parts = summary.chunks.map((input, i) => {
      const proved = this.parts.find(p => p.index === i && p.tier === tier);
      return proved && hex(proved.publicInputs) === boundary(input) ? proved : null;
    });
    const reused = parts.filter(Boolean).length, missing = parts.flatMap((p, i) => (p ? [] : [i]));
    // Each prover takes the next part still missing; one the second prover fails goes back for the first.
    const work = async (prover, spare = false) => {
      for (let i; (i = missing.shift()) !== undefined;) {
        onStep({ done: parts.filter(Boolean).length, total: count + 1 });
        let proved;
        try { proved = await prover.prove('chunk' + tier, JSON.stringify(summary.chunks[i])); }
        catch (error) { if (!spare) throw error; missing.unshift(i); return; }
        if (hex(proved.publicInputs) !== boundary(summary.chunks[i])) throw new Error('A part proved a different boundary.');
        parts[i] = proved;
      }
    };
    await Promise.all([work(this.main), sealing?.then(done => done && work(second, true))]);
    await work(this.main);
    onStep({ done: count, total: count + 1 });
    const sealed = (await sealing) ?? await this.main.prove('final' + tier, JSON.stringify(summary.final));
    const { owner: _, ...statement } = decodeFinal(sealed.publicInputs);
    if (Object.keys(statement).length !== Object.keys(summary.statement).length || statement.text_capacity !== tier
        || Object.entries(statement).some(([k, v]) => String(v) !== String(summary.statement[k]))) throw new Error('The final step proved a different page.');
    const source = assembleLong3(summary, parts.map(p => ({ proof: b64(p.proof), publicInputs: b64(p.publicInputs) })),
      { proof: b64(sealed.proof), publicInputs: b64(sealed.publicInputs) });
    onStep({ done: count + 1, total: count + 1, checking: true });
    const checkStarted = performance.now();
    const verifyLong = createLongVerifier({ ...(await this.keys()), ...(LOCAL ? { passkeyRelyingParties: [{ id: location.hostname, origin: location.origin }] } : {}),
      verifyZk: async (proof, publicInputs, key) => (await this.main.ask({ type: 'verify', proof, publicInputs, key })).verified });
    const publicKey = Uint8Array.from(summary.publicKeyHex.match(/../g), h => parseInt(h, 16));
    const { envelope, report } = await createEvidenceVerifier({ verifyLong })
      .envelope(source, { requireSignedCapture: true, expectedKey: await sha256(publicKey) }, summary.text);
    if (!report.verified) throw new Error('The page proof didn’t check.');
    learn('check', performance.now() - checkStarted, tier);
    return { envelope, report, recording: saved, text: summary.text, parts: count, reused, proveMs: performance.now() - started };
  }
}
