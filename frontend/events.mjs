// Where visitors stop: the pages post a few named steps to /api/events (pages/track.mjs), and this passes them on to
// PostHog in batches. On only when POSTHOG_KEY is set (POSTHOG_HOST picks the region, US by default); otherwise every
// event is dropped. PostHog sees the event, the page's path with names and codes taken out, the browser and system,
// and the random number the browser keeps — never a visitor's address (requests come from this server, geo lookup off),
// text, title or link. Session replays (pages/replay.mjs) come through here too, at /ph/, with every word hidden.
import { clientIP } from './client-ip.mjs';

export const EVENTS = Object.freeze(['$pageview', 'mac_download_clicked', 'sign_in_started', 'signed_in', 'recording_started',
  'recording_stopped', 'page_proved', 'page_shared', 'link_copied', 'posted_on_x', 'posted_on_linkedin', 'report_downloaded', 'document_downloaded']);
const FORMATS = ['pdf', 'docx', 'md', 'txt', 'html'];
const PER_MINUTE = 120, QUEUE = 500, BATCH = 100, FLUSH_MS = 10000;
// Replays: what PostHog's page script may ask for (its settings, flags, events and recordings), how much, how often.
const RELAYED = /^\/ph\/(?:(e|s|flags|i\/v0\/e)\/?|(array\/phc_[A-Za-z0-9_-]{20,80}\/config(?:\.js)?))$/;
const RELAY_BYTES = 5 * 1024 * 1024, RELAY_PER_MINUTE = 300;

/** Paths as PostHog sees them: a writer's handle, a page's code or id becomes a placeholder. */
export function eventPath(pathname) {
  if (typeof pathname !== 'string') return '/other';
  if (['/', '/download', '/write', '/verify', '/privacy', '/terms', '/ask', '/deck/'].includes(pathname)) return pathname;
  if (/^\/@[^/]+$/.test(pathname)) return '/@writer';
  if (/^\/p\/[^/]+$/.test(pathname)) return '/p/page';
  if (/^\/original\/[a-f0-9]{64}$/.test(pathname)) return '/original/page';
  return '/other';
}
function system(agent = '') {
  const os = /Windows/.test(agent) ? 'Windows' : /CrOS/.test(agent) ? 'Chrome OS' : /Android/.test(agent) ? 'Android'
    : /iPhone|iPad/.test(agent) ? 'iOS' : /Macintosh/.test(agent) ? 'Mac OS X' : /Linux/.test(agent) ? 'Linux' : 'Other';
  const browser = /Edg\//.test(agent) ? 'Microsoft Edge' : /Firefox\//.test(agent) ? 'Firefox' : /Chrome\//.test(agent) ? 'Chrome'
    : /Safari\//.test(agent) ? 'Safari' : 'Other';
  return { $os: os, $browser: browser };
}
/** The event's own properties, as allowed: anything else is dropped. Null for an event that isn't one of ours. */
export function eventFrom(body, agent) {
  if (!body || typeof body !== 'object' || !EVENTS.includes(body.event) || !/^[a-f0-9]{32}$/.test(body.id ?? '')) return null;
  const path = eventPath(body.path), properties = { $pathname: path, $current_url: 'https://huma.social' + path, ...system(agent),
    $process_person_profile: false, $geoip_disable: true, $lib: 'huma-web' };
  if (typeof body.referrer === 'string' && /^[a-z0-9.-]{1,100}$/.test(body.referrer)) properties.$referring_domain = body.referrer;
  if (typeof body.reason === 'string') properties.reason = body.reason.slice(0, 120);
  if (Number.isInteger(body.score) && body.score >= 0 && body.score <= 100) properties.score = body.score;
  if (FORMATS.includes(body.format)) properties.format = body.format;
  // How long Finish or saving took (milliseconds), and the computer's cores, to see where it's slow.
  if (Number.isInteger(body.ms) && body.ms >= 0 && body.ms <= 3600000) properties.ms = body.ms;
  if (Number.isInteger(body.cores) && body.cores >= 1 && body.cores <= 512) properties.cores = body.cores;
  return { event: body.event, distinct_id: body.id, properties };
}

export function configuredEvents(env = process.env, { fetch: send = globalThis.fetch, now = Date.now } = {}) {
  const key = /^phc_[A-Za-z0-9_-]{20,80}$/.test(env.POSTHOG_KEY ?? '') ? env.POSTHOG_KEY : null;
  let host = 'https://us.i.posthog.com';
  try { if (env.POSTHOG_HOST) { const url = new URL(env.POSTHOG_HOST); if (url.protocol === 'https:') host = url.origin; } } catch {}
  // Settings and the page script's own files come from the region's assets host (us-assets.i.posthog.com).
  const assets = host.replace(/^https:\/\/([a-z]+)\.i\.posthog\.com$/, 'https://$1-assets.i.posthog.com');
  const queue = [], clients = new Map(), relays = new Map(); let timer = null, swept = null, relaySwept = null;
  async function flush() {
    clearTimeout(timer); timer = null;
    while (queue.length) {
      const batch = queue.splice(0, BATCH);
      try { await send(host + '/batch/', { method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ api_key: key, batch }), signal: AbortSignal.timeout(10000) }); } catch {}
    }
  }
  return {
    enabled: Boolean(key), key, flush,
    /** Passes one replay request on to PostHog: the path, query, type, browser and body, never the visitor's address or
     *  cookies. Null when it isn’t one; 429 when this client sent too many this minute. */
    async relay(req, pathname, query, body) {
      const match = key && pathname.match(RELAYED);
      if (!match) return null;
      const ip = clientIP(req), minute = Math.floor(now() / 60000);
      if (relaySwept !== minute) { relaySwept = minute; for (const [client, entry] of relays) if (entry.minute !== minute) relays.delete(client); }
      const entry = relays.get(ip) ?? { minute, count: 0 };
      relays.set(ip, entry);
      if (++entry.count > RELAY_PER_MINUTE) return { status: 429, type: 'application/json', body: Buffer.from('{"error":"Too many."}') };
      const headers = { 'User-Agent': req.headers['user-agent'] ?? '' };
      if (req.headers['content-type']) headers['Content-Type'] = req.headers['content-type'];
      try {
        const response = await send((match[2] ? assets : host) + pathname.slice(3) + (query ?? ''), { method: req.method, headers,
          ...(req.method === 'POST' ? { body } : {}), signal: AbortSignal.timeout(15000) });
        return { status: response.status, type: response.headers.get('content-type') ?? 'application/json', body: Buffer.from(await response.arrayBuffer()) };
      } catch { return { status: 502, type: 'application/json', body: Buffer.from('{"error":"PostHog didn’t answer."}') }; }
    },
    /** Keeps one event to send (false when it isn't one, or this client sent too many this minute). */
    add(req, body) {
      const event = eventFrom(body, req.headers['user-agent']);
      if (!event) return false;
      const ip = clientIP(req), minute = Math.floor(now() / 60000);
      if (swept !== minute) { swept = minute; for (const [client, entry] of clients) if (entry.minute !== minute) clients.delete(client); }
      const entry = clients.get(ip) ?? { minute, count: 0 };
      clients.set(ip, entry);
      if (++entry.count > PER_MINUTE || !key || queue.length >= QUEUE) return true;
      queue.push({ ...event, timestamp: new Date(now()).toISOString() });
      if (queue.length >= BATCH) flush(); else timer ??= setTimeout(flush, FLUSH_MS);
      return true;
    },
  };
}

/** POST /api/events { event, id, path, referrer?, reason?, score?, format?, ms?, cores? } → 204; GET /api/replay → the
 *  key replays are sent with (PostHog's project key, which only adds events), or 404; /ph/… → PostHog, for replays. */
export function eventRoutes(events) {
  return async (req, res, pathname, { json }) => {
    if (pathname === '/api/replay') {
      if (!events.key) json(res, 404, { error: 'Replays are off.' }); else json(res, 200, { key: events.key });
      return true;
    }
    if (pathname.startsWith('/ph/')) {
      if (req.method !== 'GET' && req.method !== 'POST') { json(res, 405, { error: 'Method not allowed.' }); return true; }
      const chunks = []; let size = 0;
      for await (const chunk of req) { size += chunk.length; if (size > RELAY_BYTES) { json(res, 413, { error: 'Too large.' }); return true; } chunks.push(chunk); }
      const answer = await events.relay?.(req, pathname, req.url?.match(/\?.*$/)?.[0], Buffer.concat(chunks));
      if (!answer) { json(res, 404, { error: 'Not found.' }); return true; }
      res.writeHead(answer.status, { 'Content-Type': answer.type, 'Cache-Control': 'no-store' }); res.end(answer.body);
      return true;
    }
    if (pathname !== '/api/events') return false;
    if (req.method !== 'POST') { json(res, 405, { error: 'Method not allowed.' }); return true; }
    const chunks = []; let size = 0;
    for await (const chunk of req) { size += chunk.length; if (size > 2048) { json(res, 413, { error: 'Too large.' }); return true; } chunks.push(chunk); }
    let body = null;
    try { body = JSON.parse(Buffer.concat(chunks).toString('utf8')); } catch {}
    if (!events.add(req, body)) { json(res, 400, { error: 'Not an event.' }); return true; }
    res.writeHead(204, { 'Cache-Control': 'no-store' }); res.end();
    return true;
  };
}
