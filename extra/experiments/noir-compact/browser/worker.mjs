import { createCompactVerifier } from './core.mjs';
import { createWasmVerifier } from './wasm.mjs';
import { loadAsset, MAX_EXPORT_BYTES } from './profile.mjs';

let busy = false;
self.onmessage = async ({ data }) => {
  if (busy) return;
  busy = true;
  let backend;
  try {
    if (!data || typeof data.source !== 'string' || data.source.length > MAX_EXPORT_BYTES) throw new Error('Invalid public proof request.');
    const [verificationKey, journalABI, g2Point] = await Promise.all(['cast256.vk', 'journal-abi.json', 'g2.dat'].map(loadAsset));
    backend = await createWasmVerifier(g2Point);
    const verify = await createCompactVerifier({ verificationKey, journalABI, verifyZk: backend.verify });
    const result = await verify(data.source, data.options);
    self.postMessage({ result });
  } catch (error) {
    self.postMessage({ error: error instanceof Error ? error.message : 'Proof verification failed.' });
  } finally { if (backend) await backend.destroy(); self.close(); }
};
