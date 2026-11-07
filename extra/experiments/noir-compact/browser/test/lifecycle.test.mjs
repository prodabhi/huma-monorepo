import test, { afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { verifyCompactProof } from '../client.mjs';

const originalWorker = globalThis.Worker, originalTimeout = globalThis.setTimeout;
let workers = [];
class ControlledWorker {
  constructor(url, options) { this.url = url; this.options = options; workers.push(this); }
  postMessage(data) { this.data = data; }
  terminate() { this.terminated = true; }
}
globalThis.Worker = ControlledWorker;
afterEach(() => { globalThis.setTimeout = originalTimeout; });

test('only one worker is admitted and cancellation terminates it', async () => {
  const controller = new AbortController();
  const checking = verifyCompactProof('{}', {}, { signal: controller.signal });
  await assert.rejects(() => verifyCompactProof('{}'), /already running/);
  controller.abort();
  await assert.rejects(checking, { name: 'AbortError' });
  assert.equal(workers.at(-1).terminated, true);
});

test('success/error releases admission and terminates worker', async () => {
  const checking = verifyCompactProof('{}');
  const worker = workers.at(-1);
  worker.onmessage({ data: { result: { verified: true } } });
  assert.equal((await checking).verified, true);
  assert.equal(worker.terminated, true);
  const failed = verifyCompactProof('{}'); workers.at(-1).onerror();
  await assert.rejects(failed, /stopped/);
  assert.equal(workers.at(-1).terminated, true);
});

test('deadline kills a nonresponding worker and permits retry', async () => {
  globalThis.setTimeout = (callback, delay) => originalTimeout(callback, delay === 20000 ? 1 : delay);
  const checking = verifyCompactProof('{}');
  await assert.rejects(checking, /20-second/);
  assert.equal(workers.at(-1).terminated, true);
  const retry = verifyCompactProof('{}'); workers.at(-1).onmessage({ data: { error: 'Expected failure' } });
  await assert.rejects(retry, /Expected failure/);
});

test('pre-abort and oversized input never create a worker', async () => {
  const count = workers.length, controller = new AbortController(); controller.abort();
  await assert.rejects(() => verifyCompactProof('{}', {}, { signal: controller.signal }), { name: 'AbortError' });
  await assert.rejects(() => verifyCompactProof('x'.repeat(512 * 1024 + 1)), /512 KiB/);
  assert.equal(workers.length, count);
  globalThis.Worker = originalWorker;
});
