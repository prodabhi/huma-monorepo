// Proves a batch of published short-page proofs on the sharing server. Every input is already
// public (zero-knowledge page proofs and their statements); nothing private reaches this code.
import { readFile, writeFile, mkdtemp, rm } from 'node:fs/promises';
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { fieldsOf, leaf, root, toHex, SLOTS } from './commit.mjs';

const here = path.dirname(fileURLToPath(import.meta.url)), repo = path.resolve(here, '../../../..');
const PINS = { 'circuit.json': '0da9427cd43a38e5c5d63e4c462ac2f22fbaea9308f49eb8771a7e55e29d31de',
  'batch.vk': '854715ce8482322d12147e28b50b86330a944d0e1b5819693bfce554aa1f2712' };
const PROOF_FIELDS = 458;
const keys = JSON.parse(await readFile(path.join(here, 'keys.json'), 'utf8')).profiles;

/** The batch slot a published page proof occupies, or null if it can't be batched (long pages, other kinds). */
export function slotOf(publicProof) {
  const key = keys[publicProof?.profile];
  if (!key || typeof publicProof.proof !== 'string' || typeof publicProof.publicInputs !== 'string') return null;
  const statement = fieldsOf(publicProof.publicInputs), proof = fieldsOf(publicProof.proof);
  if (statement.length !== key.publicInputs || proof.length !== PROOF_FIELDS) return null;
  return { profile: publicProof.profile, size: key.publicInputs === 94 ? 'small' : 'large', keyHash: key.hash, keyFields: key.fields, proof, statement };
}
export const leafOf = async slot => toHex(await leaf(slot.keyHash, slot.statement));

const fillers = Object.fromEntries(await Promise.all(['small', 'large'].map(async size =>
  [size, slotOf(JSON.parse(await readFile(path.join(here, 'fillers', size + '.json'), 'utf8')))])));

/** Lays out up to two small and two large pages; empty slots get the public filler proofs. */
export async function layout(pages) {
  const small = pages.filter(p => p.size === 'small'), large = pages.filter(p => p.size === 'large');
  if (small.length > SLOTS.small || large.length > SLOTS.large) throw new Error('Too many pages for one batch.');
  const slots = [...small, ...Array(SLOTS.small - small.length).fill(fillers.small),
    ...large, ...Array(SLOTS.large - large.length).fill(fillers.large)];
  const leaves = await Promise.all(slots.map(leafOf));
  return { slots, leaves, root: toHex(await root(leaves)), filler: slots.map(s => s === fillers.small || s === fillers.large) };
}

function run(command, args) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { stdio: ['ignore', 'ignore', 'pipe'] });
    let stderr = ''; child.stderr.on('data', d => { stderr = (stderr + d).slice(-2000); });
    child.once('error', reject);
    child.once('close', code => code === 0 ? resolve() : reject(new Error(`${path.basename(command)} failed: ${stderr.trim().split('\n').pop()}`)));
  });
}
async function pinned(name) {
  const bytes = await readFile(path.join(here, name));
  if (createHash('sha256').update(bytes).digest('hex') !== PINS[name]) throw new Error(name + ' does not match its pin.');
  return bytes;
}

/** Proves a batch and returns its commitment, leaves and the EVM proof for HumaRegistry.submit. */
export async function proveBatch(pages, { bb = process.env.HUMA_BB ?? path.join(repo, 'build/research/noir-tools/bb/bb'),
  crs = process.env.HUMA_BATCH_CRS ?? path.join(repo, 'build/research/batch-crs'),
  noirJs = process.env.HUMA_NOIR_JS ?? path.join(repo, 'extra/experiments/noir-replay/runtime/node_modules/@noir-lang/noir_js/lib/index.mjs') } = {}) {
  const batch = await layout(pages);
  const hex = values => values.map(toHex);
  const part = (from, to) => batch.slots.slice(from, to);
  const inputs = {
    small_keys: part(0, 2).map(s => s.keyFields), small_proofs: part(0, 2).map(s => hex(s.proof)), small: part(0, 2).map(s => hex(s.statement)),
    large_keys: part(2, 4).map(s => s.keyFields), large_proofs: part(2, 4).map(s => hex(s.proof)), large: part(2, 4).map(s => hex(s.statement)),
  };
  const circuit = JSON.parse(await pinned('circuit.json')); await pinned('batch.vk');
  const { Noir } = await import(noirJs);
  const { witness, returnValue } = await new Noir(circuit).execute(inputs, async () => { throw new Error('foreign calls disabled'); });
  if (toHex(returnValue) !== batch.root) throw new Error('Batch commitment differs from the circuit.');
  const work = await mkdtemp(path.join(tmpdir(), 'huma-batch-'));
  try {
    await writeFile(path.join(work, 'witness.gz'), witness);
    await run(bb, ['prove', '-b', path.join(here, 'circuit.json'), '-w', path.join(work, 'witness.gz'), '-k', path.join(here, 'batch.vk'),
      '-t', 'evm-no-zk', '-c', crs, '-o', path.join(work, 'proof')]);
    const proof = await readFile(path.join(work, 'proof/proof')), publicInputs = await readFile(path.join(work, 'proof/public_inputs'));
    if ('0x' + publicInputs.toString('hex') !== batch.root) throw new Error('Proof commits to a different batch.');
    return { root: batch.root, leaves: batch.leaves, filler: batch.filler, profiles: batch.slots.map(s => s.profile), proof: '0x' + proof.toString('hex') };
  } finally { await rm(work, { recursive: true, force: true }); }
}
