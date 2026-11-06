// Reader side of HumaPages: a page's on-chain record, looked up by the reader's own browser from a
// public Base RPC. The record key is keccak256 of the page proof's 45 statement fields, so no host
// or receipt has to be trusted: a page shows as recorded only if HumaPages verified its proof.
const fail = message => { throw new Error(message); };

/** HumaPages per network; a record from any other contract is not shown as official. Set at deployment. */
export const OFFICIAL_CONTRACTS = { 'base-sepolia': '0x03e596f2f2d21d46421c90aa1651038e261b1b78', base: null };
/** Earlier Huma contracts whose records readers still accept (before every writing rule was required). */
export const LEGACY_CONTRACTS = { 'base-sepolia': ['0x350c2064f0ae37e343e6a1ab526fee9d4749c941'], base: [] };
export const RPC = { 'base-sepolia': 'https://sepolia.base.org', base: 'https://mainnet.base.org' };
export const EXPLORER = { 'base-sepolia': 'https://sepolia.basescan.org', base: 'https://basescan.org' };

// Keccak-256 (Ethereum's padding), small and dependency-free; checked against viem in web/test/relayer.test.mjs.
const RC = [0x1n, 0x8082n, 0x800000000000808an, 0x8000000080008000n, 0x808bn, 0x80000001n, 0x8000000080008081n, 0x8000000000008009n,
  0x8an, 0x88n, 0x80008009n, 0x8000000an, 0x8000808bn, 0x800000000000008bn, 0x8000000000008089n, 0x8000000000008003n,
  0x8000000000008002n, 0x8000000000000080n, 0x800an, 0x800000008000000an, 0x8000000080008081n, 0x8000000000008080n, 0x80000001n, 0x8000000080008008n];
const ROT = [[0, 36, 3, 41, 18], [1, 44, 10, 45, 2], [62, 6, 43, 15, 61], [28, 55, 25, 21, 56], [27, 20, 39, 8, 14]];
const MASK = (1n << 64n) - 1n;
const rotl = (v, n) => n ? ((v << BigInt(n)) | (v >> BigInt(64 - n))) & MASK : v;
function permute(a) {
  for (let round = 0; round < 24; round++) {
    const c = [0, 1, 2, 3, 4].map(x => a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20]);
    const d = [0, 1, 2, 3, 4].map(x => c[(x + 4) % 5] ^ rotl(c[(x + 1) % 5], 1));
    for (let i = 0; i < 25; i++) a[i] ^= d[i % 5];
    const b = new Array(25);
    for (let x = 0; x < 5; x++) for (let y = 0; y < 5; y++) b[y + 5 * ((2 * x + 3 * y) % 5)] = rotl(a[x + 5 * y], ROT[x][y]);
    for (let x = 0; x < 5; x++) for (let y = 0; y < 5; y++) a[x + 5 * y] = b[x + 5 * y] ^ (~b[(x + 1) % 5 + 5 * y] & MASK & b[(x + 2) % 5 + 5 * y]);
    a[0] ^= RC[round];
  }
}
export function keccak(bytes) {
  const rate = 136, padded = new Uint8Array(Math.floor(bytes.length / rate) * rate + rate);
  padded.set(bytes); padded[bytes.length] ^= 0x01; padded[padded.length - 1] ^= 0x80;
  const state = new Array(25).fill(0n);
  for (let at = 0; at < padded.length; at += rate) {
    for (let i = 0; i < rate / 8; i++) {
      let lane = 0n; for (let k = 7; k >= 0; k--) lane = (lane << 8n) | BigInt(padded[at + 8 * i + k]);
      state[i] ^= lane;
    }
    permute(state);
  }
  const out = new Uint8Array(32);
  for (let i = 0; i < 4; i++) for (let k = 0; k < 8; k++) out[8 * i + k] = Number((state[i] >> BigInt(8 * k)) & 0xffn);
  return out;
}
const hex = bytes => Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');

/** The page's record key from its v2 page proof (keccak256 of the 45 statement fields). */
export async function pageKey(page) {
  if (typeof page?.finalInputs !== 'string') fail('This page has no on-chain statement.');
  const raw = Uint8Array.from(atob(page.finalInputs), c => c.charCodeAt(0));
  if (raw.length !== 46 * 32) fail('This page has no on-chain statement.');
  return '0x' + hex(keccak(raw.subarray(0, 45 * 32)));
}

/** The wallet and block HumaPages recorded for `key`, or null, read straight from a public Base RPC. */
export async function pageRecord(network, contract, key) {
  if (!RPC[network] || !/^0x[0-9a-fA-F]{40}$/.test(contract) || !/^0x[0-9a-f]{64}$/.test(key)) fail('Malformed on-chain record.');
  const selector = hex(keccak(new TextEncoder().encode('pages(bytes32)')).subarray(0, 4));
  const response = await fetch(RPC[network], { method: 'POST', headers: { 'Content-Type': 'application/json' }, redirect: 'error',
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'eth_call', params: [{ to: contract, data: '0x' + selector + key.slice(2) }, 'latest'] }) });
  const { result } = await response.json();
  if (typeof result !== 'string' || !/^0x[0-9a-f]{128}$/.test(result)) fail('The chain could not be read.');
  const blockNumber = Number(BigInt('0x' + result.slice(66)));
  return blockNumber ? { owner: '0x' + result.slice(26, 66), blockNumber } : null;
}
