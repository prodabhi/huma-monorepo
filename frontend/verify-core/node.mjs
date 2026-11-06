import { Worker } from 'node:worker_threads';
import { boundedJSON, verificationDeadline } from './contract.mjs';

let active = false;
function run(command, source, policy, content, attachments, { signal } = {}) {
  return new Promise((resolve, reject) => {
    if (active) return reject(new Error('A local evidence check is already running.'));
    let deadline;
    try {
      deadline = verificationDeadline(source);
      // Clone only the requested view. Structured cloning a tiny view otherwise
      // copies its potentially huge backing buffer into the worker.
      if (content instanceof Uint8Array) {
        if (content.byteLength > 32 * 1024 * 1024) throw new Error('Oversized master.');
        content = Uint8Array.from(content);
      }
      boundedJSON(JSON.stringify(policy), 48 * 1024);
      if (attachments !== undefined) boundedJSON(JSON.stringify(attachments), 2 * 1024 * 1024);
    } catch { return reject(new Error('Invalid evidence input.')); }
    if (signal?.aborted) return reject(new DOMException('Verification cancelled.', 'AbortError'));
    const worker = new Worker(new URL('./node-worker.mjs', import.meta.url), {
      execArgv: [],
      resourceLimits: { maxOldGenerationSizeMb: 128, maxYoungGenerationSizeMb: 32 },
    });
    active = true; let done = false;
    const finish = (error, result) => {
      if (done) return;
      done = true; clearTimeout(timer);
      signal?.removeEventListener('abort', cancel);
      void worker.terminate().finally(() => { active = false; error ? reject(error) : resolve(result); });
    };
    const cancel = () => finish(new DOMException('Verification cancelled.', 'AbortError'));
    const timer = setTimeout(() => finish(new Error('Verification exceeded its local time limit.')), deadline);
    signal?.addEventListener('abort', cancel, { once: true });
    worker.once('message', data => data?.result ? finish(null, data.result) : finish(new Error('Local evidence check failed.')));
    worker.once('error', () => finish(new Error('Local evidence verifier stopped.')));
    worker.once('exit', () => finish(new Error('Local evidence verifier stopped before completion.')));
    try { worker.postMessage({ command, source, policy, content, attachments }); }
    catch { finish(new Error('Invalid evidence request.')); }
  });
}
export const verify = (source, policy = {}, expectedContent, controls) => run('verify', source, policy, expectedContent, controls?.attachments, controls);
export const envelope = (source, policy = {}, expectedContent, attachments = {}, controls) => run('envelope', source, policy, expectedContent, attachments, controls);
