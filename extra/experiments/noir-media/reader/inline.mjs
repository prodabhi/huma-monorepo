import { createMediaVerifier } from './core.mjs';
import { loadKey } from './profile.mjs';
import { loadAsset } from '../../noir-compact/browser/profile.mjs';
import { createWasmVerifier } from '../../noir-compact/browser/wasm.mjs';
export async function verifyMediaInline(source, options) {
  if (typeof WorkerGlobalScope === 'undefined' || !(self instanceof WorkerGlobalScope)) throw new Error('A dedicated verification worker is required.');
  const [verificationKey, g2] = await Promise.all([loadKey(), loadAsset('g2.dat')]);
  const backend = await createWasmVerifier(g2);
  try { return await (await createMediaVerifier({ verificationKey, verifyZk: backend.verify }))(source, options); }
  finally { await backend.destroy(); }
}
