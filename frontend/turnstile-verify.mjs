// Cloudflare Turnstile, the server's side: checks that a browser was used by a person when it starts, finishes and
// publishes a page (frontend/write/turnstile.mjs makes the tokens). On only when both HUMA_TURNSTILE_SITE_KEY and
// TURNSTILE_SECRET_KEY are set; otherwise everything works as without it. The secret stays in this closure: it is
// never logged, returned or sent anywhere but Cloudflare's siteverify.
import { clientIP } from './client-ip.mjs';

export const TURNSTILE_ACTIONS = Object.freeze(['start', 'finish', 'publish']);
export const TURNSTILE_SCRIPT_ORIGIN = 'https://challenges.cloudflare.com';
export const SITEVERIFY = TURNSTILE_SCRIPT_ORIGIN + '/turnstile/v0/siteverify';
export const NOT_CONFIRMED = 'Couldn’t confirm this browser. Try again.';
// Cloudflare's published testing secrets (always pass, always fail, already spent). Their answers say
// result_with_testing_key and name example.com with no action, so only with these are hostname and action not checked.
const TESTING_SECRET = /^[123]x0{20,}AA$/;
const SITE_KEY = /^[0-9A-Za-z_-]{8,64}$/;
const TOKEN_LIMIT = 2048, IN_FLIGHT = 32;
// The page's own check (/api/turnstile/verify) is open to anyone, so per client it may have 2 waiting and 30 a minute.
const CLIENT_IN_FLIGHT = 2, CLIENT_PER_MINUTE = 30;

let warned = false;
/**
 * The Turnstile check as configured in `env`: { enabled, siteKey, verify(token, action, { hostname }) }.
 * verify resolves { ok: true } (or { ok: true, off: true } when Turnstile is off), or
 * { ok: false, status, reason }: 403 for a token that isn't a person's for this action and site, 503 when
 * Cloudflare can't be reached, 429 when too many checks are waiting. It never rejects. Publishing checks in its own
 * `pool`, so the open page check can't crowd it out.
 */
export function configuredTurnstile(env = process.env, { fetch: send = globalThis.fetch, timeout = 10000 } = {}) {
  const siteKey = env.HUMA_TURNSTILE_SITE_KEY || null, secret = env.TURNSTILE_SECRET_KEY || null;
  const enabled = Boolean(siteKey && secret && SITE_KEY.test(siteKey));
  if (!enabled && (siteKey || secret) && !warned) {
    warned = true;
    console.warn('Turnstile is off: set both HUMA_TURNSTILE_SITE_KEY and TURNSTILE_SECRET_KEY to turn it on.');
  }
  // More hostnames the widget may run on (comma-separated), besides the one each request was sent to.
  const hostnames = new Set((env.HUMA_TURNSTILE_HOSTNAMES ?? '').split(',').map(name => name.trim().toLowerCase()).filter(Boolean));
  const testing = enabled && TESTING_SECRET.test(secret);
  const waiting = { page: 0, publish: 0 };
  async function verify(token, action, { hostname = null, pool = 'page' } = {}) {
    if (!enabled) return { ok: true, off: true };
    if (!TURNSTILE_ACTIONS.includes(action)) return { ok: false, status: 400, reason: 'action' };
    if (typeof token !== 'string' || !token || token.length > TOKEN_LIMIT) return { ok: false, status: 403, reason: 'missing' };
    if (!Object.hasOwn(waiting, pool)) return { ok: false, status: 400, reason: 'pool' };
    if (waiting[pool] >= IN_FLIGHT) return { ok: false, status: 429, reason: 'busy' };
    waiting[pool]++;
    let data;
    try {
      const response = await send(SITEVERIFY, { method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ secret, response: token }), signal: AbortSignal.timeout(timeout) });
      data = await response.json();
      if (!data || typeof data !== 'object') throw new Error();
    } catch { return { ok: false, status: 503, reason: 'unreachable' }; }
    finally { waiting[pool]--; }
    if (data.success !== true) return { ok: false, status: 403, reason: 'failed' };
    if (testing && data.metadata?.result_with_testing_key === true) return { ok: true };
    if (data.action !== action) return { ok: false, status: 403, reason: 'action' };
    const solvedOn = typeof data.hostname === 'string' ? data.hostname.toLowerCase() : '';
    if (!solvedOn || (solvedOn !== hostname?.toLowerCase() && !hostnames.has(solvedOn))) return { ok: false, status: 403, reason: 'hostname' };
    return { ok: true };
  }
  return { enabled, siteKey: enabled ? siteKey : null, verify };
}

/** The hostname a request was sent to (its Host header without the port), or null. */
export function requestHostname(req) {
  const host = req.headers.host;
  if (typeof host !== 'string') return null;
  try { return new URL('http://' + host).hostname; } catch { return null; }
}

async function readSmallJSON(req, limit = 4096) {
  const chunks = []; let size = 0;
  for await (const chunk of req) { size += chunk.length; if (size > limit) return null; chunks.push(chunk); }
  try { const value = JSON.parse(Buffer.concat(chunks).toString('utf8')); return value && typeof value === 'object' ? value : null; } catch { return null; }
}

/**
 * GET /api/turnstile → { siteKey } (null when off), for the write page.
 * POST /api/turnstile/verify { token, action } → { ok } — the page's own check at Start and Finish. Publishing
 * checks its token itself (publications.mjs); this answer is only the page's gate.
 */
export function turnstileRoutes(turnstile, { now = Date.now } = {}) {
  const clients = new Map(); let swept = null; // client → { waiting, minute, count }
  return async (req, res, pathname, { json }) => {
    if (pathname === '/api/turnstile' && req.method === 'GET') { json(res, 200, { siteKey: turnstile.siteKey }); return true; }
    if (pathname !== '/api/turnstile/verify') return false;
    if (req.method !== 'POST') { json(res, 405, { error: 'Method not allowed.' }); return true; }
    if (!(req.headers['content-type'] ?? '').startsWith('application/json')) { json(res, 415, { error: 'JSON required.' }); return true; }
    const ip = clientIP(req), minute = Math.floor(now() / 60000);
    if (swept !== minute) { swept = minute; for (const [key, entry] of clients) if (!entry.waiting && entry.minute !== minute) clients.delete(key); }
    const client = clients.get(ip) ?? { waiting: 0, minute, count: 0 };
    if (client.minute !== minute) Object.assign(client, { minute, count: 0 });
    if (client.waiting >= CLIENT_IN_FLIGHT || client.count >= CLIENT_PER_MINUTE || (!clients.has(ip) && clients.size >= 100000)) {
      json(res, 429, { ok: false, error: NOT_CONFIRMED }); return true;
    }
    client.waiting++; client.count++; clients.set(ip, client);
    try {
      const body = await readSmallJSON(req);
      if (!body) { json(res, 400, { error: 'Invalid request.' }); return true; }
      const result = await turnstile.verify(body.token, body.action, { hostname: requestHostname(req) });
      if (result.ok) json(res, 200, { ok: true, ...(result.off ? { off: true } : {}) });
      else json(res, result.status, { ok: false, error: NOT_CONFIRMED });
      return true;
    } finally { client.waiting--; }
  };
}
