// Proves a page written here the way the Mac app does (LongChunkProver, and prove-long in backend/integrations/noir/worker.mjs):
// closed parts prove in the background while the writer types, and Finish proves what's left and the final step,
// checks every proof and wraps them in the evidence file any reader checks (huma.social/verify).
import { assembleLong3, createLongVerifier, decodeFinal, KEYS, KEYS2, KEYS3 } from '../../backend/integrations/noir/long/reader.mjs';
import { createEvidenceVerifier } from '../verify-core/core.mjs';
import { hex } from '../verify-core/contract.mjs';
import { digest } from '../publication-contract.mjs';
import { b64 } from './recorder.mjs';

const sha256 = digest;
const fieldHex = value => BigInt(value).toString(16).padStart(64, '0');
/** A part proof's public inputs: the state it starts at, the one it ends at, and whether it starts the session. */
const boundary = input => fieldHex(input.expected.start_root) + fieldHex(input.expected.end_root) + fieldHex(input.expected.genesis ? 1 : 0);
// On this computer's own server (development), passkeys belong to localhost, which readers accept only when told to
// (an address like 127.0.0.1 can't hold a passkey).
const LOCAL = location.hostname === 'localhost';
// Brave hides the real numbers (its fingerprinting protection): hardwareConcurrency is a random value no higher than
// the real one, deviceMemory a random one, both different each session. A lower bound is still a lower bound, so a
// Brave is taken to have at least 8 cores and 8 GB, as every Mac and most laptops of recent years do; otherwise it
// proved on 2 threads with no second prover, three to four times slower than Chrome on the same computer.
const BRAVE = typeof navigator.brave?.isBrave === 'function';
// Half the cores, so the page stays quick to type in while parts prove behind it. (Past 8 threads a proof is barely
// quicker: 2.7 s a part on 16 against 3.0 s on 8.)
const CORES = Math.max(navigator.hardwareConcurrency || 4, BRAVE ? 8 : 0);
export const THREADS = Math.max(2, Math.min(8, Math.floor(CORES / 2)));
// At Finish the writer has stopped typing, so a computer with the cores and memory (each prover holds about 1.5 GB;
// Chrome says how much there is, up to 8 GB, other browsers don't) gets a second prover on its other cores: the final
// step and the last parts prove at the same time instead of one after another.
const MEMORY = BRAVE ? 8 : navigator.deviceMemory ?? 8;
const SECOND = CORES >= 4 && MEMORY >= 8 ? Math.max(2, Math.min(8, CORES - THREADS)) : 0;

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

// A prover that fails this way crashed (a WebAssembly trap such as `unreachable`, memory it couldn't get, or the worker
// itself gone) rather than refused the step: it can't go on, and a fresh prover gets to try the step once more.
const CRASH = /unreachable|out of bounds|out of memory|memory access|RuntimeError|The prover stopped|Aborted\(/i;
const crashed = error => CRASH.test(typeof error === 'string' ? error : error?.message ?? '');
/** `error` named with the step it stopped at, as Finish shows it ("Part 3 couldn’t be proved (unreachable)"). */
const named = (step, error) => Object.assign(new Error(`${step} (${error?.message ?? 'unknown error'})`), { cause: error });

/** One prover worker (prover-worker.mjs) on `threads` threads, answering one request at a time. */
class ProverWorker {
  constructor(url, threads) {
    this.worker = new Worker(url, { type: 'module' }); this.threads = threads; this.pending = new Map(); this.id = 0; this.ready = false; this.dead = false;
    this.worker.onmessage = ({ data }) => { const done = this.pending.get(data.id); this.pending.delete(data.id); done?.(data); };
    this.worker.onerror = () => this.stop();
  }
  ask(message, transfer = []) {
    return new Promise((resolve, reject) => {
      const id = ++this.id, started = performance.now();
      this.pending.set(id, reply => {
        if (reply.ok && message.type === 'prove') learn(message.name.startsWith('chunk') ? 'part' : 'final', performance.now() - started, Number(message.name.match(/\d+$/)[0]));
        // Crashed, bb.js is in no state to go on: this prover is done (PageProver.revive makes the next).
        if (!reply.ok && crashed(reply.error)) this.dead = true;
        reply.ok ? resolve(reply) : reject(new Error(reply.error));
      });
      this.worker.postMessage({ ...message, id, threads: this.threads }, transfer);
    });
  }
  warm() { return this.ask({ type: 'warm' }).then(() => { this.ready = true; }); }
  /** Proves `input` to program `name`; with `witness` (made ahead by solve) the worker skips making its own. */
  prove(name, input, witness = null) { return witness?.byteLength ? this.ask({ type: 'prove', name, input, witness }, [witness.buffer]) : this.ask({ type: 'prove', name, input }); }
  /** Only the witness for `input` to program `name`: for a worker that never proves, making witnesses ahead. */
  solve(name, input) { return this.ask({ type: 'witness', name, input }).then(reply => reply.witness); }
  /** Ends this prover and its threads; whatever it was asked fails as stopped. */
  stop() {
    this.dead = true; this.worker.terminate();
    for (const done of this.pending.values()) done({ ok: false, error: 'The prover stopped.' });
    this.pending.clear();
  }
}

export class PageProver {
  constructor(workerURL, assets) {
    this.url = workerURL;
    this.main = new ProverWorker(workerURL, THREADS);
    this.second = SECOND ? new ProverWorker(workerURL, SECOND) : null;
    this.assets = assets;
    this.parts = []; this.next = 0; this.closed = 0; this.failures = 0; this.task = null; this.stopped = false; this.recording = null; this.tier = 1024;
    // Proofs bb.js has checked already, by program: each one the prover makes (checked right after, prover-worker.mjs)
    // and each one the page's check asks about, so nothing is checked twice.
    this.verified = new Set();
    this.onchange = () => {};
  }
  /** Notes `proved` (a prove reply for program `name`) as checked. */
  known(name, proved) { this.verified.add(name + '|' + b64(proved.proof) + '|' + b64(proved.publicInputs)); }
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
      this.known('chunk' + part.tier, proved);
      this.parts.push({ index: part.index, tier: part.tier, proof: proved.proof, publicInputs: proved.publicInputs });
      this.next = part.index + 1; this.failures = 0;
    })().catch(error => { this.failures++; if (crashed(error)) this.revive().catch(() => {}); }).finally(() => { this.task = null; this.onchange(); this.startIfIdle(); });
    this.onchange();
  }
  /** The main prover, fresh and warmed again, once it has crashed: the one asked from then on. Asked while one is
   *  already on its way, that same one. */
  revive() {
    if (!this.main.dead) return Promise.resolve(this.main);
    this.reviving ??= (async () => {
      const threads = this.main.threads;
      this.main.stop();
      const fresh = new ProverWorker(this.url, threads);
      this.main = fresh;
      await fresh.warm();
      return fresh;
    })().finally(() => { this.reviving = null; });
    return this.reviving;
  }
  /** A step the main prover failed with `error`: once more on a fresh prover when it crashed; otherwise, or failing
   *  again, the error named with its step. */
  async again(step, error, run) {
    if (!crashed(error)) throw named(step, error);
    let fresh;
    try { fresh = await this.revive(); } catch { throw named(step, error); }
    try { return await run(fresh); } catch (again) { throw named(step, again); }
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
    const { summary, recording: saved } = await recording.proveInput().catch(error => { throw named('The recording couldn’t be prepared for proving', error); });
    const tier = summary.tier, count = summary.chunks.length, started = performance.now();
    this.tier = tier;
    // The final step doesn't need the parts' proofs: a second prover starts on it now. One that crashed is let go.
    if (this.second?.dead) { this.second.stop(); this.second = null; }
    const second = this.second?.ready ? this.second : null;
    const sealing = second ? second.prove('final' + tier, JSON.stringify(summary.final)).catch(() => null) : null;
    await this.task;
    const parts = summary.chunks.map((input, i) => {
      const proved = this.parts.find(p => p.index === i && p.tier === tier);
      return proved && hex(proved.publicInputs) === boundary(input) ? proved : null;
    });
    const reused = parts.filter(Boolean).length, missing = parts.flatMap((p, i) => (p ? [] : [i]));
    // A witness worker (the same code, never asked to prove) makes each missing part's witness while a prover is
    // busy with the one before, so a prover's threads don't idle on the single-threaded solver between parts. One it
    // can't make, the prover makes itself.
    const solver = this.solver ??= new ProverWorker(this.url, 1), witnesses = new Map();
    const witnessFor = i => {
      if (!witnesses.has(i)) witnesses.set(i, solver.solve('chunk' + tier, JSON.stringify(summary.chunks[i])).catch(() => null));
      return witnesses.get(i);
    };
    // A witness goes to the prover for good (its buffer is handed over), so a part that comes back for another try
    // gets a new one.
    const takeWitness = async i => { const made = await witnessFor(i); witnesses.delete(i); return made; };
    // Each prover takes the next part still missing; one the second prover fails goes back for the first, and one the
    // first crashes on is tried once more on a fresh prover.
    const work = async (prover, spare = false) => {
      for (let i; (i = missing.shift()) !== undefined;) {
        onStep({ done: parts.filter(Boolean).length, total: count + 1 });
        const part = () => JSON.stringify(summary.chunks[i]);
        if (missing.length) witnessFor(missing[0]); // ahead, for whichever prover takes the next
        let proved;
        try { proved = await prover.prove('chunk' + tier, part(), await takeWitness(i)); }
        catch (error) {
          if (spare) { missing.unshift(i); return; }
          proved = await this.again(`Part ${i + 1} couldn’t be proved`, error, fresh => fresh.prove('chunk' + tier, part()));
          prover = this.main;
        }
        if (hex(proved.publicInputs) !== boundary(summary.chunks[i])) throw new Error(`Part ${i + 1} proved a different boundary.`);
        parts[i] = proved; this.known('chunk' + tier, proved);
      }
    };
    const final = () => JSON.stringify(summary.final);
    const working = Promise.all([work(this.main), sealing?.then(done => done && work(second, true))]);
    // Without a second prover the final step is the first prover's, after the parts: its witness is made meanwhile.
    const finalAhead = second ? null : solver.solve('final' + tier, final()).catch(() => null);
    await working;
    await work(this.main);
    onStep({ done: count, total: count + 1 });
    let sealed = await sealing;
    if (!sealed) {
      try { sealed = await this.main.prove('final' + tier, final(), await finalAhead); }
      catch (error) { sealed = await this.again('The final step couldn’t be proved', error, fresh => fresh.prove('final' + tier, final())); }
    }
    this.solver.stop(); this.solver = null;
    this.known('final' + tier, sealed);
    const { owner: _, ...statement } = decodeFinal(sealed.publicInputs);
    if (Object.keys(statement).length !== Object.keys(summary.statement).length || statement.text_capacity !== tier
        || Object.entries(statement).some(([k, v]) => String(v) !== String(summary.statement[k]))) throw new Error('The final step proved a different page.');
    const source = assembleLong3(summary, parts.map(p => ({ proof: b64(p.proof), publicInputs: b64(p.publicInputs) })),
      { proof: b64(sealed.proof), publicInputs: b64(sealed.publicInputs) });
    onStep({ done: count + 1, total: count + 1, checking: true });
    const checkStarted = performance.now();
    const keys = await this.keys().catch(error => { throw named('The checking keys couldn’t be loaded', error); });
    // The check asks about every proof twice (the export, then the envelope), and the prover checked each as it made
    // it: a proof bb.js has passed once, for the program this key belongs to, isn't sent to it again.
    const named3 = Object.entries(KEYS3), keyNames = new Map();
    const verifyZk = async (proof, publicInputs, key) => {
      const pin = await sha256(key), name = keyNames.get(pin) ?? named3.find(([, vk]) => vk === pin)?.[0] ?? pin;
      keyNames.set(pin, name);
      const id = name + '|' + b64(proof) + '|' + b64(publicInputs);
      if (this.verified.has(id)) return true;
      const check = prover => prover.ask({ type: 'verify', proof, publicInputs, key }).then(reply => reply.verified);
      let ok;
      try { ok = await check(this.main); }
      catch (error) { ok = await this.again('The proof couldn’t be checked', error, check); }
      if (ok === true) this.verified.add(id);
      return ok;
    };
    const verifyLong = createLongVerifier({ ...keys, ...(LOCAL ? { passkeyRelyingParties: [{ id: location.hostname, origin: location.origin }] } : {}), verifyZk });
    const publicKey = Uint8Array.from(summary.publicKeyHex.match(/../g), h => parseInt(h, 16));
    const { envelope, report } = await createEvidenceVerifier({ verifyLong })
      .envelope(source, { requireSignedCapture: true, expectedKey: await sha256(publicKey) }, summary.text);
    if (!report.verified) throw new Error('The page proof didn’t check.');
    learn('check', performance.now() - checkStarted, tier);
    return { envelope, report, recording: saved, text: summary.text, parts: count, reused, proveMs: performance.now() - started };
  }
}
