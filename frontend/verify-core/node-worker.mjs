import { parentPort } from 'node:worker_threads';
import { engine } from './node-engine.mjs';
parentPort.once('message', async data => {
  try {
    if (!['verify', 'envelope'].includes(data.command)) throw new Error('Unsupported command.');
    const result = data.command === 'verify' ? await engine.verify(data.source, data.policy, data.content, data.attachments)
      : await engine.envelope(data.source, data.policy, data.content, data.attachments);
    parentPort.postMessage({ result });
  } catch { parentPort.postMessage({ error: 'Local evidence check failed.' }); }
  finally { parentPort.close(); }
});
