// Internal engine; use frontend/verify-core/node.mjs for worker/deadline isolation.
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { createMediaVerifier } from './core.mjs';
import { checkKey } from './profile.mjs';
import { checkAsset } from '../../noir-compact/browser/profile.mjs';
import { createWasmVerifier } from '../../noir-compact/browser/wasm.mjs';
export async function verifyMediaPublic(source, options) {
  const load = async name => checkAsset(name, new Uint8Array(await readFile(new URL('../../noir-compact/browser/assets/' + name, import.meta.url))));
  const [verificationKey, g2] = await Promise.all([
    readFile(new URL('./assets/media-membership.vk', import.meta.url)).then(bytes => checkKey(new Uint8Array(bytes))), load('g2.dat'),
  ]);
  await load('barretenberg-threads.wasm');
  const backend = await createWasmVerifier(g2, fileURLToPath(new URL('../../noir-compact/browser/assets/barretenberg-threads.wasm', import.meta.url)));
  try { return await (await createMediaVerifier({ verificationKey, verifyZk: backend.verify }))(source, options); }
  finally { await backend.destroy(); }
}
