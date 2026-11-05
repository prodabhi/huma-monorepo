// node:crypto: createHash('sha256') and webcrypto, over the native host.
import { Buffer } from 'buffer';
import { copy } from '../prelude.mjs';
export const webcrypto = globalThis.crypto;
export function createHash(name) {
  if (name !== 'sha256') throw new Error('Only sha256 is supported.');
  const parts = [];
  return {
    update(data, encoding) { parts.push(typeof data === 'string' ? Buffer.from(data, encoding ?? 'utf8') : Buffer.from(copy(data))); return this; },
    digest(encoding) { const out = Buffer.from(globalThis.__host.sha256(copy(Buffer.concat(parts)))); return encoding ? out.toString(encoding) : out; },
  };
}
