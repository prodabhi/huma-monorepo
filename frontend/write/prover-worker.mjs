// Proves a page's parts in this browser, in a worker: the witness from Noir's own solver (witness.wasm, Rust, the
// same code as the Mac's witness tool) and the proof from bb.js (Barretenberg as WebAssembly) on several threads.
// Programs and keys are pinned; the proving points come from this site. Nothing about the writing leaves the browser.
import { Barretenberg, BackendType } from '@aztec/bb.js';
import { ungzip } from 'pako';
import { PROGRAMS, POINTS } from './pins.mjs';

const hex = bytes => Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
const sha256 = async bytes => hex(new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)));
async function fetched(path) {
  const response = await fetch(new URL(path, self.location.href), { credentials: 'omit', redirect: 'error' });
  if (!response.ok) throw new Error('Couldn’t load ' + path.split('/').pop() + '.');
  return new Uint8Array(await response.arrayBuffer());
}
const programs = new Map();
/** A pinned program: its circuit and verification key, checked against the same pins the Mac engine uses. */
function program(name) {
  if (!Object.hasOwn(PROGRAMS, name)) throw new Error('Unknown program.');
  if (!programs.has(name)) programs.set(name, (async () => {
    const [json, key] = await Promise.all([fetched('long3-' + name + '.json'), fetched('long3-' + name + '.vk')]);
    const { bytecode } = JSON.parse(new TextDecoder().decode(json));
    if (await sha256(new TextEncoder().encode(bytecode)) !== PROGRAMS[name].bytecode || await sha256(key) !== PROGRAMS[name].vk)
      throw new Error('A proving program doesn’t match its pin.');
    return { json, key, circuit: ungzip(Uint8Array.from(atob(bytecode), c => c.charCodeAt(0))) };
  })().catch(error => { programs.delete(name); throw error; }));
  return programs.get(name);
}

let solver;
async function witness(json, input) {
  solver ??= (await WebAssembly.instantiate(await fetched('witness.wasm'), {})).instance.exports;
  const put = bytes => { const p = solver.huma_alloc(bytes.length); new Uint8Array(solver.memory.buffer, p, bytes.length).set(bytes); return p; };
  const inputBytes = new TextEncoder().encode(input), pp = put(json), ip = put(inputBytes);
  const reply = solver.huma_witness(pp, json.length, ip, inputBytes.length);
  solver.huma_free(pp, json.length); solver.huma_free(ip, inputBytes.length);
  const head = new DataView(solver.memory.buffer, reply, 4).getUint32(0, true), length = head & 0x7fffffff;
  const body = new Uint8Array(solver.memory.buffer, reply + 4, length).slice();
  solver.huma_free(reply, 4 + length);
  // The solver names only the step that failed, never a value from the writing.
  if (head >>> 31) throw new Error('The writing doesn’t satisfy the proof (' + new TextDecoder().decode(body) + ').');
  return ungzip(body);
}

let api, pointsLoaded = 0;
const SETTINGS = { ipaAccumulation: false, oracleHashType: 'poseidon2', disableZk: false, optimizedSolidityVerifier: false };
/** bb.js on `threads` threads with the first 2^`log` proving points, which a program of that size needs. */
async function backend(threads, log) {
  api ??= await Barretenberg.new({ backend: BackendType.Wasm, threads, skipSrsInit: true, memory: { initial: 37, maximum: 65536 } });
  if (log === 0 && pointsLoaded === 0) {
    // Checking needs only the second-group point; the API still wants one first-group point, the generator (1, 2).
    const g2 = await fetched('g2.dat'), generator = new Uint8Array(64); generator[31] = 1; generator[63] = 2;
    if (await sha256(g2) !== POINTS.g2) throw new Error('The proving points don’t match their pin.');
    await api.srsInitSrs({ pointsBuf: generator, numPoints: 1, g2Point: g2 });
    pointsLoaded = -1;
  } else if (pointsLoaded < log) {
    const [points, g2] = await Promise.all([fetched('points/' + log), fetched('g2.dat')]);
    if (points.length !== 32 << log || await sha256(points) !== POINTS[log] || await sha256(g2) !== POINTS.g2)
      throw new Error('The proving points don’t match their pin.');
    await api.srsInitSrs({ pointsBuf: points, numPoints: 1 << log, g2Point: g2 });
    pointsLoaded = log;
  }
  return api;
}
const fields = bytes => Array.from({ length: bytes.length / 32 }, (_, i) => bytes.slice(i * 32, i * 32 + 32));
const flat = list => { const out = new Uint8Array(list.length * 32); list.forEach((f, i) => out.set(f, i * 32)); return out; };

async function prove({ name, input, threads }) {
  const started = performance.now();
  const { json, key, circuit } = await program(name);
  const solved = await witness(json, input), witnessMs = performance.now() - started;
  const bb = await backend(threads, PROGRAMS[name].log);
  const { proof, publicInputs } = await bb.circuitProve({ witness: solved, circuit: { name, bytecode: circuit, verificationKey: key }, settings: SETTINGS });
  const result = { proof: flat(proof), publicInputs: flat(publicInputs) };
  // Checked here before anything uses it, like the Mac engine checks each proof it makes.
  if (!(await bb.circuitVerify({ verificationKey: key, publicInputs, proof, settings: SETTINGS })).verified) throw new Error('A part proof didn’t check.');
  return { ...result, witnessMs, totalMs: performance.now() - started };
}
async function verify({ proof, publicInputs, key, threads }) {
  const bb = await backend(threads, 0);
  return (await bb.circuitVerify({ verificationKey: key, publicInputs: fields(publicInputs), proof: fields(proof), settings: SETTINGS })).verified;
}

// One request at a time, in order: a part can't start bb.js a second time while the warm-up is starting it.
let queue = Promise.resolve();
self.onmessage = ({ data }) => { queue = queue.then(() => handle(data)); };
async function handle(data) {
  try {
    if (data.type === 'prove') {
      const result = await prove(data);
      self.postMessage({ id: data.id, ok: true, ...result }, [result.proof.buffer, result.publicInputs.buffer]);
    } else if (data.type === 'verify') self.postMessage({ id: data.id, ok: true, verified: await verify(data) });
    else if (data.type === 'warm') {
      // While the writer starts typing: the first tier's programs, bb.js and its proving points, about 8 s that
      // would otherwise wait for the first part.
      await Promise.all([program('chunk1024'), program('final1024')]);
      await backend(data.threads, PROGRAMS.chunk1024.log);
      self.postMessage({ id: data.id, ok: true });
    }
    else throw new Error('Unknown request.');
  } catch (error) {
    self.postMessage({ id: data.id, ok: false, error: String(error?.message ?? error).slice(0, 200) });
  }
}
