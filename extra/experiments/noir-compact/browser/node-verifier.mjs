import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { webcrypto } from 'node:crypto';
import { createCompactVerifier } from './core.mjs';
import { createWasmVerifier } from './wasm.mjs';
import { checkAsset } from './profile.mjs';

if (!globalThis.crypto) globalThis.crypto = webcrypto;
export async function verifyCompactPublic(source, options = {}) {
  const load = async name => checkAsset(name, new Uint8Array(await readFile(new URL('./assets/' + name, import.meta.url))));
  const [verificationKey, journalABI, g2] = await Promise.all(['cast256.vk', 'journal-abi.json', 'g2.dat'].map(load));
  const wasm = 'barretenberg-threads.wasm';
  await load(wasm);
  const backend = await createWasmVerifier(g2, fileURLToPath(new URL('./assets/' + wasm, import.meta.url)));
  try {
    const verify = await createCompactVerifier({ verificationKey, journalABI, verifyZk: backend.verify });
    return await verify(source, options);
  } finally { await backend.destroy(); }
}
