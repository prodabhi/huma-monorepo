// assurance-long-v3 tooling. Programs, all from prover.nr, one of each per text tier (1024, 4096, 10000):
//   chunk<N>   one part of a session: its operations and signed events, from the state it starts at to the one it ends at
//   final<N>   the sealed session's public statement, from the last part's end state and the seal
// No program verifies another proof; a reader links the parts by their roots and checks every signature itself.
//   build                              compile all programs and write their keys
//   check <case.json> [--mutations]    witnesses only (software-key fixtures from experiments/noir-compact/native/examples/long_cases.rs)
//   chain <case.json>                  prove every part and the final step, then verify each proof
//   bundle <case.json>                 the public proof from `chain`'s proofs, checked by the reader, then altered copies
import { readFile, writeFile, mkdir, copyFile, rm } from 'node:fs/promises';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import os from 'node:os';
import path from 'node:path';
const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, '../../../..');
const target = path.join(root, 'build/research/noir-long3');
const nargo = path.join(root, 'build/research/noir-tools/noir/nargo');
const bb = path.join(root, 'build/research/noir-tools/bb/bb');
const crs = path.join(root, 'build/research/noir-crs');
const out = s => process.stdout.write(s + '\n');
export const TIERS = [1024, 4096, 10000];
export const NAMES = TIERS.flatMap(t => ['chunk' + t, 'final' + t]);
const entries = {
  chunk: `use prover::{Boundary,Event,Op,State,OPS,SLOTS};
fn main(nonce:[Field;2],salt:[Field;2],state:State,ops:[Op;OPS],origins:[Origin;OPS],op_count:u32,events:[Event;SLOTS],text:[Field;2],
        expected:pub Boundary) {
    prover::chunk(nonce,salt,state,ops,origins,op_count,events,text,expected);
}`,
  final: `use prover::{Event,Final,State,SLOTS};
fn main(nonce:[Field;2],salt:[Field;2],state:State,events:[Event;SLOTS],text:[Field;2],expected:pub Final) {
    prover::finalize(nonce,salt,state,events,text,expected);
}`,
};
export const programPath = name => path.join(target, name, `target/huma_long3_${name}.json`);
export const keyPath = name => path.join(target, name, 'target/vk');
const run = (args, threads = 2) => execFileSync('/usr/bin/nice', ['-n', '10', bb, ...args],
  { env: { ...process.env, RAYON_NUM_THREADS: String(threads), HARDWARE_CONCURRENCY: String(threads) }, stdio: ['ignore', 'ignore', 'pipe'] });

async function build() {
  for (const name of NAMES) {
    const tier = name.replace(/^\D+/, ''), kind = name.replace(/\d+$/, '');
    const dir = path.join(target, name); await rm(dir, { recursive: true, force: true }); await mkdir(path.join(dir, 'src'), { recursive: true });
    await writeFile(path.join(dir, 'Nargo.toml'), `[package]\nname="huma_long3_${name}"\ntype="bin"\nauthors=[]\n[dependencies]\n`);
    const source = await readFile(path.join(here, 'prover.nr'), 'utf8');
    if (!source.includes('pub global SCALARS:u32=10000;')) throw Error('SCALARS tier declaration changed');
    await writeFile(path.join(dir, 'src/prover.nr'), source.replace('pub global SCALARS:u32=10000;', `pub global SCALARS:u32=${tier};`));
    for (const m of ['commit.nr', 'assurance.nr']) await copyFile(path.join(root, 'extra/experiments/noir-compact/src', m), path.join(dir, 'src', m));
    await writeFile(path.join(dir, 'src/main.nr'), 'mod commit;\nmod assurance;\nmod prover;\nuse assurance::Origin;\n' + entries[kind] + '\n');
    execFileSync(nargo, ['compile', '--silence-warnings'], { cwd: dir, stdio: 'inherit' });
    run(['write_vk', '-b', programPath(name), '-t', 'noir-recursive', '-c', crs, '-o', path.dirname(keyPath(name))]);
    const gates = JSON.parse(execFileSync(bb, ['gates', '-b', programPath(name)], { stdio: ['ignore', 'pipe', 'ignore'] })).functions[0].circuit_size;
    out(`built ${name}: ${gates} gates (2^${Math.ceil(Math.log2(gates))})`);
  }
}

const noir = async name => {
  const { Noir } = await import(path.join(root, 'extra/experiments/noir-replay/runtime/node_modules/@noir-lang/noir_js/lib/index.mjs'));
  for (const method of ['debug', 'error', 'info', 'log', 'warn']) console[method] = () => {};
  return new Noir(JSON.parse(await readFile(programPath(name), 'utf8')));
};
const noForeign = async () => { throw Error('foreign calls disabled'); };

async function check(file, flags) {
  const fixture = JSON.parse(await readFile(file, 'utf8')), tier = fixture.tier;
  const programs = { chunk: await noir('chunk' + tier), final: await noir('final' + tier) };
  // noir_js may rewrite nested input objects, and inputs share them with the fixture.
  const accepts = async (program, input) => { try { await program.execute(structuredClone(input), noForeign); return true; } catch { return false; } };
  const results = [];
  for (const [i, input] of fixture.chunks.entries()) results.push({ case: 'part' + i, expected: true, accepted: await accepts(programs.chunk, input) });
  results.push({ case: 'final', expected: true, accepted: await accepts(programs.final, fixture.final) });
  if (flags.includes('--mutations')) {
    const bump = v => String(BigInt(v) + 1n);
    const last = fixture.chunks.length - 1;
    const cases = {
      ChangedOperation: [0, v => { v.ops[5].arg = bump(v.ops[5].arg); }],
      ForgedEndRoot: [1, v => { v.expected.end_root = bump(v.expected.end_root); }],
      ForgedStartRoot: [1, v => { v.expected.start_root = bump(v.expected.start_root); }],
      GenesisLater: [1, v => { v.expected.genesis = true; }],
      NotGenesisFirst: [0, v => { v.expected.genesis = false; }],
      ChangedCarriedText: [last, v => { v.state.buffer[0] = bump(v.state.buffer[0]); }],
      ChangedNonce: [0, v => { v.nonce[1] = bump(v.nonce[1]); }],
      DroppedEvent: [0, v => { const j = v.events.findIndex(e => e.kind !== '0'); if (j >= 0) v.events[j] = { ...v.events.at(-1), kind: '0', offset: '0' }; else v.op_count = bump(v.op_count); }],
      FinalForgedDigest: ['final', v => { v.expected.event_digest = bump(v.expected.event_digest); }],
      FinalForgedRawCommitment: ['final', v => { v.expected.raw_commitment = bump(v.expected.raw_commitment); }],
      FinalForgedStateRoot: ['final', v => { v.expected.state_root = bump(v.expected.state_root); }],
      FinalForgedRule: ['final', v => { v.expected.rules[2] = !v.expected.rules[2]; }],
      FinalOtherTier: ['final', v => { v.expected.text_capacity = String(tier === 1024 ? 4096 : 1024); }],
      FinalChangedText: ['final', v => { v.state.buffer[0] = bump(v.state.buffer[0]); }],
    };
    for (const [name, [which, change]] of Object.entries(cases)) {
      const input = structuredClone(which === 'final' ? fixture.final : fixture.chunks[which]); change(input);
      results.push({ case: 'Reject' + name, expected: false, accepted: await accepts(which === 'final' ? programs.final : programs.chunk, input) });
    }
  }
  const failed = results.filter(r => r.expected !== r.accepted);
  out(JSON.stringify({ file: path.basename(file), tier, checks: results.length, failed }));
  process.exitCode = failed.length ? 1 : 0;
}

/** Proves every part and the final step (parts can run side by side), and verifies each proof. */
export async function proveChain(fixture, dir, { reuse = false, jobs = Math.max(1, Math.floor(os.availableParallelism() / 4)) } = {}) {
  await mkdir(dir, { recursive: true });
  const tier = fixture.tier, programs = { chunk: await noir('chunk' + tier), final: await noir('final' + tier) };
  const timings = [];
  const prove = async (label, name, program, input) => {
    const o = path.join(dir, label);
    if (reuse) try { return { proof: await readFile(path.join(o, 'proof')), inputs: await readFile(path.join(o, 'public_inputs')) }; } catch {}
    const t = performance.now(); const { witness } = await program.execute(structuredClone(input), noForeign);
    const w = path.join(dir, label + '.gz'); await writeFile(w, witness);
    const witnessMs = Math.round(performance.now() - t);
    run(['prove', '-b', programPath(name), '-w', w, '-k', keyPath(name), '-t', 'noir-recursive', '-c', crs, '-o', o], 4);
    run(['verify', '-p', path.join(o, 'proof'), '-i', path.join(o, 'public_inputs'), '-k', keyPath(name), '-t', 'noir-recursive', '-c', crs]);
    timings.push({ label, witnessMs, ms: Math.round(performance.now() - t) });
    return { proof: await readFile(path.join(o, 'proof')), inputs: await readFile(path.join(o, 'public_inputs')) };
  };
  const labels = [...fixture.chunks.map((_, i) => 'part' + i), 'final'];
  const results = new Array(labels.length); let next = 0;
  await Promise.all(Array.from({ length: jobs }, async () => {
    while (next < labels.length) {
      const i = next++;
      results[i] = await (i < fixture.chunks.length ? prove(labels[i], 'chunk' + tier, programs.chunk, fixture.chunks[i]) : prove('final', 'final' + tier, programs.final, fixture.final));
    }
  }));
  return { parts: results.slice(0, -1), final: results.at(-1), timings, tier };
}

async function chain(file) {
  const fixture = JSON.parse(await readFile(file, 'utf8'));
  const started = performance.now();
  const { parts, final, timings, tier } = await proveChain(fixture, path.join(target, 'proofs', path.basename(file, '.json')));
  out(JSON.stringify({ tier, parts: parts.length, proveAllMs: Math.round(performance.now() - started), proofBytes: final.proof.length,
    finalInputBytes: final.inputs.length, timings }));
}

async function bundle(file) {
  const fixture = JSON.parse(await readFile(file, 'utf8')); const dir = path.join(target, 'proofs', path.basename(file, '.json'));
  const { parts, final } = await proveChain(fixture, dir, { reuse: true });
  const c = fixture.capsule, hexOf = a => Buffer.from(a).toString('hex');
  const { assembleLong3, verifyLongNode } = await import('../long/reader.mjs');
  const source = assembleLong3({ publicKeyHex: hexOf(c.public_key), events: fixture.events, checkpointRoots: c.checkpoint_roots, presenceRoots: c.presence_roots,
    signaturesHex: c.signatures.map(hexOf), presenceSignaturesHex: c.presence_signatures.map(hexOf), text: fixture.text },
    parts.map(p => ({ proof: p.proof.toString('base64'), publicInputs: p.inputs.toString('base64') })),
    { proof: final.proof.toString('base64'), publicInputs: final.inputs.toString('base64') });
  await writeFile(path.join(target, path.basename(file, '.json') + '-proof.json'), source);
  const t = performance.now(); const report = await verifyLongNode(source, { text: fixture.text });
  out(JSON.stringify({ bundleBytes: source.length, readerMs: Math.round(performance.now() - t), verified: report.verified, policy: report.journal.policy_satisfied,
    parts: report.chunks, signatures: report.signaturesVerified, presence: report.presenceSignaturesVerified }));
  const flip = b => { const raw = Buffer.from(b, 'base64'); raw[raw.length >> 1] ^= 1; return raw.toString('base64'); };
  const cases = {
    ChangedPartProof: p => { p.chunks[0] = flip(p.chunks[0]); },
    DroppedPart: p => { if (p.chunks.length > 1) { p.chunks.splice(1, 1); p.chunkInputs.splice(1, 1); } else p.chunks = []; },
    ReorderedParts: p => { if (p.chunks.length > 2) { [p.chunks[1], p.chunks[2]] = [p.chunks[2], p.chunks[1]]; [p.chunkInputs[1], p.chunkInputs[2]] = [p.chunkInputs[2], p.chunkInputs[1]]; } else p.final = flip(p.final); },
    ChangedFinalProof: p => { p.final = flip(p.final); },
    ChangedFinalInputs: p => { p.finalInputs = flip(p.finalInputs); },
    OtherKey: p => { const k = Buffer.from(p.publicKey, 'base64'); k[40] ^= 1; p.publicKey = k.toString('base64'); },
    ResignedWithAnotherKey: p => { p.signatures[0] = flip(p.signatures[0]); },
    ChangedRoot: p => { p.checkpointRoots[1] = String(BigInt(p.checkpointRoots[1]) + 1n); },
    ReorderedEvents: p => { const i = p.events.indexOf('2'); p.events = p.events.slice(0, i - 1) + '21' + p.events.slice(i + 1); },
    ChangedEmbeddedText: p => { p.text = p.text.replace('a', 'b'); },
    ExtraField: p => { p.owner = '0x00'; },
    V2Kind: p => { p.kind = 'huma-long-assurance-public-proof-v2'; },
  };
  const results = [];
  for (const [name, change] of Object.entries(cases)) {
    const p = JSON.parse(source); change(p); let ok; try { ok = (await verifyLongNode(JSON.stringify(p), { text: fixture.text })).verified === true; } catch { ok = false; }
    results.push({ case: 'Reject' + name, accepted: ok });
  }
  for (const [name, other] of [['TrailingSpaceAccepted', fixture.text + ' \t'], ['ChangedText', fixture.text.slice(0, -1)]]) {
    let ok; try { ok = (await verifyLongNode(source, { text: other })).verified === true; } catch { ok = false; }
    results.push({ case: name, accepted: ok });
  }
  const failed = results.filter(r => r.accepted !== (r.case === 'TrailingSpaceAccepted'));
  out(JSON.stringify({ checks: results.length, failed })); process.exitCode = failed.length ? 1 : 0;
}

const [command, ...rest] = process.argv.slice(2);
if (command === 'build') await build();
else if (command === 'check') await check(rest[0], rest.slice(1));
else if (command === 'chain') await chain(rest[0]);
else if (command === 'bundle') await bundle(rest[0]);
else if (command !== undefined) { process.stderr.write('Use: build | check <case.json> [--mutations] | chain <case.json> | bundle <case.json>\n'); process.exitCode = 2; }
