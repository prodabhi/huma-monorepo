// Small helpers the server's modules share.
import { createHash } from 'node:crypto';
import { fullMatch } from './verify-core/contract.mjs';

/** SHA-256 of a string or bytes, as lowercase hex. */
export const sha256Hex = value => createHash('sha256').update(value).digest('hex');
/** An error the server answers with `status` and `message` (registry.mjs). */
export const fail = (status, message) => Object.assign(new Error(message), { status });
/** A SHA-256 hex string: exactly 64 lowercase hex characters, and a string. */
export const isHash = value => fullMatch(/^[a-f0-9]{64}$/, value);
/** A request body as JSON, or a 400 "JSON required."; an empty body is `empty` when one is given. */
export function parseJSON(bytes, empty) {
  if (empty !== undefined && !bytes.length) return empty;
  try { return JSON.parse(bytes.toString('utf8')); } catch { throw fail(400, 'JSON required.'); }
}
