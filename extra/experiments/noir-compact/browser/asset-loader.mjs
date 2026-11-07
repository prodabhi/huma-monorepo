import { loadAsset } from './profile.mjs';

// Narrow replacement of bb.js's asset loader. Cryptographic SDK code is unchanged.
export async function fetchCode(shared, wasmPath) {
  if (wasmPath !== undefined) throw new Error('A proof cannot choose a WASM URL.');
  return loadAsset(shared ? 'barretenberg-threads.wasm' : 'barretenberg.wasm');
}
