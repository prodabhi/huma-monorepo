// Only for a caller that already owns and bounds this dedicated worker.
import { createCompactVerifier } from './core.mjs';
import { createWasmVerifier } from './wasm.mjs';
import { loadAsset } from './profile.mjs';
export async function verifyCompactInline(source, options) {
  if (typeof WorkerGlobalScope === 'undefined' || !(self instanceof WorkerGlobalScope)) throw new Error('A dedicated verification worker is required.');
  const [verificationKey, journalABI, g2] = await Promise.all(['cast256.vk', 'journal-abi.json', 'g2.dat'].map(loadAsset));
  const backend = await createWasmVerifier(g2);
  try {
    const verify = await createCompactVerifier({ verificationKey, journalABI, verifyZk: backend.verify });
    return await verify(source, options);
  } finally { await backend.destroy(); }
}
