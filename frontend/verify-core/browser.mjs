import { boundedJSON, verificationDeadline } from './contract.mjs';
let active = false;
// A worker started by prepare() loads the checker while the page downloads the proof; the next check uses it.
let early;
export function prepare() {
  if (early) return;
  early = new Worker(new URL('./worker.mjs', import.meta.url), { type: 'module' });
  early.onerror = () => { early?.terminate(); early = undefined; };
  early.postMessage({ command: 'prepare' });
}
function run(command, source, policy, content, attachments, { signal } = {}) {
  return new Promise((resolve, reject) => {
    if (active) return reject(new Error('A local evidence check is already running.'));
    let deadline;
    try {
      deadline = verificationDeadline(source);
      if (content instanceof Uint8Array) {
        if (content.byteLength > 32 * 1024 * 1024) throw new Error('Oversized master.');
        content = Uint8Array.from(content);
      }
      boundedJSON(JSON.stringify(policy), 48 * 1024);
      if (attachments !== undefined) boundedJSON(JSON.stringify(attachments), 2 * 1024 * 1024);
    } catch { return reject(new Error('Invalid evidence input.')); }
    if (signal?.aborted) return reject(new DOMException('Verification cancelled.', 'AbortError'));
    const worker = early ?? new Worker(new URL('./worker.mjs', import.meta.url), { type: 'module' });
    early = undefined;
    active = true; let done = false;
    const finish = (error, result) => {
      if (done) return;
      done = true; active = false; clearTimeout(timer);
      signal?.removeEventListener('abort', cancel); worker.terminate();
      error ? reject(error) : resolve(result);
    };
    const cancel = () => finish(new DOMException('Verification cancelled.', 'AbortError'));
    const timer = setTimeout(() => finish(new Error("Couldn't finish checking in time. This doesn't mean the page is wrong; reload to try again.")), deadline);
    signal?.addEventListener('abort', cancel, { once: true });
    worker.onmessage = ({ data }) => data?.result ? finish(null, data.result) : finish(new Error('Local evidence check failed.'));
    worker.onerror = worker.onmessageerror = () => finish(new Error('Local evidence verifier stopped.'));
    try { worker.postMessage({ command, source, policy, content, attachments }); }
    catch { finish(new Error('Invalid evidence request.')); }
  });
}
export const verify = (source, policy = {}, expectedContent, controls) => run('verify', source, policy, expectedContent, controls?.attachments, controls);
export const envelope = (source, policy = {}, expectedContent, attachments = {}, controls) => run('envelope', source, policy, expectedContent, attachments, controls);
