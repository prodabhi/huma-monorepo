// Batch commitments, shared by the sharing server (when proving) and by readers (when checking
// that a page is in a batch verified on-chain). Same Poseidon2 framing as src/commit.nr.
import { poseidon2Permute } from '../../../../backend/integrations/noir/long/reader.mjs';

const FIELD = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
export const LEAF_DOMAIN = 0x48554d41b001n;
export const ROOT_DOMAIN = 0x48554d41b002n;
export const SLOTS = { small: 2, large: 2 };

/** commit::hash: absorb three fields per Poseidon2 permutation, length-tagged capacity. */
export async function hashFields(input) {
  let state = [0n, 0n, 0n, BigInt(input.length) * 18446744073709551616n];
  const blocks = Math.floor(input.length / 3);
  for (let block = 0; block < blocks; block++) {
    for (let j = 0; j < 3; j++) state[j] = (state[j] + input[block * 3 + j]) % FIELD;
    state = await poseidon2Permute(state);
  }
  for (let j = 0; j < input.length % 3; j++) state[j] = (state[j] + input[blocks * 3 + j]) % FIELD;
  return (await poseidon2Permute(state))[0];
}
/** A page's leaf: its circuit key hash and its complete public statement. */
export async function leaf(keyHash, statement) {
  return hashFields([LEAF_DOMAIN, BigInt(keyHash), await hashFields(statement.map(BigInt))]);
}
/** The batch commitment verified on-chain: small slots first, then large slots. */
export async function root(leaves) {
  if (leaves.length !== SLOTS.small + SLOTS.large) throw new Error('A batch has exactly four leaves.');
  return hashFields([ROOT_DOMAIN, ...leaves.map(BigInt)]);
}
export const toHex = value => '0x' + BigInt(value).toString(16).padStart(64, '0');
/** Field elements of a base64 public input or proof blob (32 bytes each, big-endian). */
export function fieldsOf(base64) {
  const raw = Uint8Array.from(atob(base64), c => c.charCodeAt(0));
  if (raw.length % 32) throw new Error('Not a field array.');
  const out = [];
  for (let i = 0; i < raw.length; i += 32) {
    const value = BigInt('0x' + Array.from(raw.subarray(i, i + 32), b => b.toString(16).padStart(2, '0')).join(''));
    if (value >= FIELD) throw new Error('Field element out of range.');
    out.push(value);
  }
  return out;
}

/** Pinned key hashes of the page circuits a batch accepts, and their statement sizes (as in src/main.nr). */
export const KEY_HASHES = {
  'assurance64-v1': ['0x17c103561f785a7b80c1d917db2612f276a1583d532f8935229bd4de5b04b30d', 'small'],
  'assurance256-v1': ['0x0157685ede27f32fdd79223af0fa1033773fcf97c772fe24f3351d41e002a5d0', 'small'],
  'assurance256-v2': ['0x12c5717ae7f3a2e98da5f6c6ae373c4999a9272679274b820aa3e3f05d18478a', 'small'],
  'assurance128-cp32-v1': ['0x218201853a8bf4dcf363c65ffaf94f94134fc3f576c9e1c43770d1e7dc32979d', 'large'],
  'assurance256-cp32-v1': ['0x194304d383ebb642f24f36ab60799f5b8586d6e817d9a7ceb86f1f9e87f9a924', 'large'],
};
/** The official HumaRegistry per network; a receipt naming any other contract is not trusted. Set at deployment. */
export const OFFICIAL_REGISTRIES = { 'base-sepolia': null, base: null };
export const RPC = { 'base-sepolia': 'https://sepolia.base.org', base: 'https://mainnet.base.org' };

/** Checks off-chain that a page proof is in the receipt's batch; returns the commitment to look up on-chain. */
export async function checkReceipt(publicProof, receipt) {
  const [keyHash, size] = KEY_HASHES[publicProof?.profile] ?? [];
  if (!keyHash) throw new Error('This kind of page is not batched.');
  const index = receipt?.index, leaves = receipt?.leaves;
  if (!Array.isArray(leaves) || leaves.length !== SLOTS.small + SLOTS.large || !Number.isInteger(index) ||
      (size === 'small' ? index < 0 || index >= SLOTS.small : index < SLOTS.small || index >= leaves.length)) throw new Error('Malformed batch receipt.');
  const mine = toHex(await leaf(keyHash, fieldsOf(publicProof.publicInputs)));
  if (leaves[index] !== mine) throw new Error('This page is not in that batch.');
  const commitment = toHex(await root(leaves));
  if (commitment !== receipt.root) throw new Error('The batch commitment does not match its pages.');
  return commitment;
}
/** Block where `registry` verified `commitment` (0 if never), read straight from a public Base RPC. */
export async function verifiedAt(network, registry, commitment) {
  if (!RPC[network] || !/^0x[0-9a-fA-F]{40}$/.test(registry) || !/^0x[0-9a-f]{64}$/.test(commitment)) throw new Error('Malformed batch receipt.');
  const response = await fetch(RPC[network], { method: 'POST', headers: { 'Content-Type': 'application/json' }, redirect: 'error',
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'eth_call', params: [{ to: registry, data: '0x56ec383c' + commitment.slice(2) }, 'latest'] }) });
  const { result } = await response.json();
  if (typeof result !== 'string' || !/^0x[0-9a-f]{64}$/.test(result)) throw new Error('The chain could not be read.');
  return Number(BigInt(result));
}
