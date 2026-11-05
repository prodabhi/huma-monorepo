// World ID (IDKit), the server's side: a writer proves, with World ID, that one real and unique person writes under
// their Huma account. The page's own proof says how it was typed; this says a verified human is its author. It never
// says who the person is: the only thing kept is the proof's nullifier.
//
// A writer links World ID to their account once, before they finish their first page (documents.mjs,
// /api/documents/worldid). That proof's signal is the publishing key of the browser that asked (accountSignal), so it
// can't be replayed for another account, and one World ID links to one account only. Every page the account shares
// then carries it, so the same anonymous World ID shows on all of a writer's pages: their way to claim them. A proof
// made at a share for that page alone (pageSignal) is still accepted. The credential asked for is Proof of Human and nothing weaker: the
// badge claims "a unique human", and only that credential makes a person one-of-a-kind (Selfie Check shows a live
// face, a passport shows a document; neither stops one person badging as many). Verified here, in the server,
// against World's verify endpoint; the browser's answer is never trusted by itself.
//
// On only when HUMA_WORLD_APP_ID, HUMA_WORLD_RP_ID and WORLD_RP_SIGNING_KEY are all set; otherwise everything works as
// without it. When on, it is also required to finish and share a page written in a browser (the human check), unless
// HUMA_WORLD_REQUIRED=false makes it a badge a writer may leave out. Pages from the Mac app have no World ID screen
// and are never asked, as with Turnstile. The signing key stays in this closure: it is never logged, returned or sent anywhere.
import { createHash } from 'node:crypto';
import { signRequest } from '@worldcoin/idkit-core/signing';
import { hashSignal } from '@worldcoin/idkit-core/hashing';
import { clientIP } from './client-ip.mjs';
import { pageSignal, accountSignal } from './publication-contract.mjs';

export { pageSignal, accountSignal };
export const BRIDGE_ORIGIN = 'https://bridge.worldcoin.org';
export const VERIFY_URL = 'https://developer.world.org/api/v4/verify/';
export const NOT_VERIFIED = 'Couldn’t confirm World ID.';
export const WORLD_ID_REQUIRED = 'Verify you’re human with World ID to share this page.';
export const WORLD_ID_TAKEN = 'This World ID is already linked to another Huma account.';
export const WORLD_ID_LIMIT = 24 * 1024;
// World ID 4.0 names the credential proof_of_human, 3.0 (the Orb fallback) orb. Nothing else counts as unique.
const CREDENTIALS = new Map([['proof_of_human', 'proof_of_human'], ['orb', 'proof_of_human']]);
const APP_ID = /^app_[0-9A-Za-z_]{4,64}$/, RP_ID = /^rp_[0-9A-Za-z_]{4,64}$/, KEY = /^(0x)?[0-9a-fA-F]{64}$/, ACTION = /^[0-9A-Za-z_-]{1,64}$/;
const IN_FLIGHT = 16, CLIENT_PER_MINUTE = 20;

let warned = false;
/**
 * The World ID check as configured in `env`: { enabled, required, appId, rpId, action, environment, context(), verify(result, signal) }.
 * context() is the signed request IDKit needs (the signature is made here, never in the browser). verify resolves
 * { ok: true, record } (record: what is kept and shown: credential, nullifier, version, signal, verifiedAt, result), or
 * { ok: false, status, reason }: 400 for a malformed answer, 403 for one that isn't a unique human's for this signal,
 * 503 when World can't be reached, 429 when too many checks are waiting. It never rejects.
 */
export function configuredWorldID(env = process.env, { fetch: send = globalThis.fetch, timeout = 10000, now = Date.now } = {}) {
  const appId = env.HUMA_WORLD_APP_ID || null, rpId = env.HUMA_WORLD_RP_ID || null, key = env.WORLD_RP_SIGNING_KEY || null;
  const action = env.HUMA_WORLD_ACTION || 'verify-publisher';
  const environment = env.HUMA_WORLD_ENVIRONMENT === 'staging' ? 'staging' : 'production';
  const enabled = Boolean(appId && rpId && key && APP_ID.test(appId) && RP_ID.test(rpId) && KEY.test(key) && ACTION.test(action));
  if (!enabled && (appId || rpId || key) && !warned) {
    warned = true;
    console.warn('World ID is off: set HUMA_WORLD_APP_ID, HUMA_WORLD_RP_ID and WORLD_RP_SIGNING_KEY (all valid) to turn it on.');
  }
  const required = enabled && env.HUMA_WORLD_REQUIRED !== 'false';
  let waiting = 0;
  /** A fresh signed request for this action: what the browser hands IDKit as its rp_context. */
  function context() {
    if (!enabled) return null;
    const signed = signRequest({ signingKeyHex: key.replace(/^0x/, ''), action });
    return { rp_id: rpId, nonce: signed.nonce, created_at: signed.createdAt, expires_at: signed.expiresAt, signature: signed.sig };
  }
  async function verify(result, signal) {
    if (!enabled) return { ok: true, off: true };
    if (!result || typeof result !== 'object' || Array.isArray(result) || typeof signal !== 'string' || !signal) return { ok: false, status: 400, reason: 'missing' };
    // Staging and sandbox proofs are free to make: only the environment this server expects counts.
    if (result.environment !== environment) return { ok: false, status: 403, reason: 'environment' };
    if (result.action !== undefined && result.action !== action) return { ok: false, status: 403, reason: 'action' };
    const item = Array.isArray(result.responses) && result.responses.length === 1 ? result.responses[0] : null;
    if (!item || typeof item !== 'object') return { ok: false, status: 400, reason: 'responses' };
    const credential = CREDENTIALS.get(item.identifier);
    if (!credential) return { ok: false, status: 403, reason: 'credential' };
    const nullifier = typeof item.nullifier === 'string' ? item.nullifier : '';
    if (!/^0x[0-9a-fA-F]{1,64}$/.test(nullifier)) return { ok: false, status: 400, reason: 'nullifier' };
    // The proof was made for this signal (this page, or this account's browser): its signal hash is the signal's hash.
    if (typeof item.signal_hash !== 'string' || item.signal_hash.toLowerCase() !== hashSignal(signal).toLowerCase()) return { ok: false, status: 403, reason: 'signal' };
    if (waiting >= IN_FLIGHT) return { ok: false, status: 429, reason: 'busy' };
    waiting++;
    let data;
    try {
      const response = await send(VERIFY_URL + encodeURIComponent(rpId), { method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ...result, environment }), signal: AbortSignal.timeout(timeout) });
      // World answers a proof it rejects with a 4xx: that is "not a unique human", not "can't reach World".
      if (response.status >= 400 && response.status < 500) return { ok: false, status: 403, reason: 'rejected' };
      if (!response.ok) throw new Error();
      data = await response.json();
      if (!data || typeof data !== 'object') throw new Error();
    } catch { return { ok: false, status: 503, reason: 'unreachable' }; }
    finally { waiting--; }
    if (data.success !== true || (data.environment !== undefined && data.environment !== environment)) return { ok: false, status: 403, reason: 'failed' };
    return { ok: true, record: { credential, nullifier: nullifier.toLowerCase(), version: String(result.protocol_version ?? ''), action, environment,
      signal, verifiedAt: now(), result } };
  }
  return { enabled, required, appId: enabled ? appId : null, rpId: enabled ? rpId : null, action, environment, context, verify };
}

/** What a reader is shown of a stored record: never the proof or the nullifier itself, only a short fingerprint. */
export function publicWorldID(record) {
  if (!record || typeof record.nullifier !== 'string') return null;
  return { verified: true, credential: record.credential, version: record.version, verifiedAt: record.verifiedAt,
    fingerprint: createHash('sha256').update(record.nullifier).digest('hex').slice(0, 12) };
}

async function readSmallJSON(req, limit = 2048) {
  const chunks = []; let size = 0;
  for await (const chunk of req) { size += chunk.length; if (size > limit) return null; chunks.push(chunk); }
  try { const value = JSON.parse(Buffer.concat(chunks).toString('utf8')); return value && typeof value === 'object' ? value : null; } catch { return null; }
}

/**
 * GET /api/worldid → { appId, rpId, action, environment, required } (null and false when off), for the write page.
 * POST /api/worldid/context → { rp_context }, a fresh signed request: open to anyone, so it is limited per client.
 */
export function worldIDRoutes(world, { now = Date.now } = {}) {
  const clients = new Map(); let swept = null; // client → { minute, count }
  return async (req, res, pathname, { json }) => {
    if (pathname === '/api/worldid' && req.method === 'GET') {
      json(res, 200, world.enabled ? { appId: world.appId, rpId: world.rpId, action: world.action, environment: world.environment, required: world.required }
        : { appId: null, rpId: null, action: null, environment: null, required: false });
      return true;
    }
    if (pathname !== '/api/worldid/context') return false;
    if (req.method !== 'POST') { json(res, 405, { error: 'Method not allowed.' }); return true; }
    if (!world.enabled) { json(res, 404, { error: 'World ID is off.' }); return true; }
    if (!(req.headers['content-type'] ?? '').startsWith('application/json')) { json(res, 415, { error: 'JSON required.' }); return true; }
    const ip = clientIP(req), minute = Math.floor(now() / 60000);
    if (swept !== minute) { swept = minute; for (const [key, entry] of clients) if (entry.minute !== minute) clients.delete(key); }
    const client = clients.get(ip) ?? { minute, count: 0 };
    if (client.count >= CLIENT_PER_MINUTE || (!clients.has(ip) && clients.size >= 100000)) { json(res, 429, { error: NOT_VERIFIED }); return true; }
    client.count++; clients.set(ip, client);
    if (!(await readSmallJSON(req))) { json(res, 400, { error: 'Invalid request.' }); return true; }
    json(res, 200, { rp_context: world.context() });
    return true;
  };
}
