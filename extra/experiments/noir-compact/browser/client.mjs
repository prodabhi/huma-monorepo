import { MAX_EXPORT_BYTES } from './profile.mjs';

let active = false;
export function verifyCompactProof(source, options = {}, { signal } = {}) {
  return new Promise((resolve, reject) => {
    if (active) return reject(new Error('A local proof check is already running.'));
    if (typeof source !== 'string' || source.length > MAX_EXPORT_BYTES) return reject(new Error('Public proof exceeds 512 KiB.'));
    if (signal?.aborted) return reject(new DOMException('Verification cancelled.', 'AbortError'));
    const worker = new Worker(new URL('./compact-worker.js', import.meta.url), { type: 'module' });
    active = true; let done = false;
    const finish = (error, result) => {
      if (done) return;
      done = true; active = false; clearTimeout(timer);
      signal?.removeEventListener('abort', cancel); worker.terminate();
      if (error) reject(error); else resolve(result);
    };
    const cancel = () => finish(new DOMException('Verification cancelled.', 'AbortError'));
    const timer = setTimeout(() => finish(new Error('Verification exceeded its 20-second limit.')), 20000);
    signal?.addEventListener('abort', cancel, { once: true });
    worker.onmessage = ({ data }) => {
      if (data?.error) finish(new Error(data.error));
      else if (data?.result?.verified === true) finish(null, data.result);
      else finish(new Error('Invalid verifier response.'));
    };
    worker.onerror = () => finish(new Error('Local verifier stopped before completion.'));
    worker.onmessageerror = () => finish(new Error('Invalid verifier response.'));
    try { worker.postMessage({ source, options }); }
    catch (error) { finish(error); }
  });
}
