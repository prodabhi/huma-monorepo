import { createHash, randomBytes } from 'node:crypto';
import { changeState } from './documents.mjs';
import { clientIP } from './client-ip.mjs';

/** Server-anchored time for pages written in a browser. Everything on /write runs in the browser, its clock too, so a
 *  script could feed the recorder invented times and prove half an hour of typing in seconds. Instead, Start asks
 *  here for the session's nonce (POST /api/sessions): 16 random bytes the recorder makes the page's public nonce[0]
 *  (web.rs `start`, LiveAssuranceCapture::with_seed). This server keeps when it handed each one out, and a browser
 *  page is shared only if its nonce is one of them, unused by any other page, under a day old, and at least the
 *  page's claimed writing time (less a minute) has really passed since. Mac pages are never asked. No proof format or
 *  circuit changes: the nonce was already public and already random. */
export const SESSION_LIFETIME = 24 * 60 * 60 * 1000, SESSION_SLACK = 60 * 1000;
export const TIME_NOT_CONFIRMED = 'This page’s writing time couldn’t be confirmed. Write it again on huma.social.';
// Issued nonces live in 16 compare-and-swap states (sessions/<hash of the shard>), each pruned of entries past their
// lifetime on every write, so unused nonces never pile up: at most SHARD_LIMIT each, under 170 bytes apiece (a state
// holds at most QUOTA_STATE_LIMIT, 512 KB). A full shard drops its oldest entries rather than turn everyone away, and one
// client keeps at most OWN unused nonces in each shard (about 16 × OWN in all): more drop its own oldest, so no one
// address can fill the shards for everyone else.
const SHARDS = 16, SHARD_LIMIT = 3000, OWN = 24;
// Modest limits on handing them out, per ten minutes: per address (an IPv6 /64), per IPv6 /48, and overall. Past the
// overall budget, addresses that have had a few already wait, but one that hasn't still gets NEWCOMER: a busy
// window can't lock out someone just arriving.
const WINDOW = 10 * 60 * 1000, PER_CLIENT = 30, PER_NETWORK = 120, OVERALL = 3000, NEWCOMER = 3, CLIENTS = 10000;

const hash = value => createHash('sha256').update(value).digest('hex');
const fail = (status, message) => Object.assign(new Error(message), { status });
/** A page's public nonce[0] (decimal, as decodeFinal gives it) as the 32 hex characters this server issued, or null. */
export function nonceHex(field) {
  if (typeof field !== 'string' || !/^[1-9][0-9]{0,38}$/.test(field)) return null;
  const n = BigInt(field);
  return n > 0n && n < 1n << 128n ? n.toString(16).padStart(32, '0') : null;
}
/** What a browser page's journal says: its session nonce and how long it claims the writing took (milliseconds) —
 *  the longer of its recorded elapsed time and its device clock's start to end, as readers are shown both. */
export function sessionClaim(journal) {
  const elapsed = Number(journal?.elapsed), span = Number(journal?.end_unix) - Number(journal?.start_unix);
  const claimed = Math.max(elapsed, span);
  return { nonce: nonceHex(journal?.nonce?.[0]), claimed: Number.isFinite(claimed) && claimed >= 0 ? claimed : Infinity };
}
/** The address a request came from, for its limits (client-ip.mjs: Caddy's X-Forwarded-For, IPv6 by /64). */
export const clientAddress = req => clientIP(req);
/** The IPv6 /48 an address bucket sits in ('a:b:c:d::/64' → 'a:b:c::/48'), or null for IPv4 and anything else. */
export const networkOf = client => {
  const groups = typeof client === 'string' && client.endsWith('::/64') ? client.slice(0, -5).split(':') : [];
  return groups.length === 4 ? groups.slice(0, 3).join(':') + '::/48' : null;
};

/** `limits` is for tests: { shards, shardLimit, own, overall }. */
export function createSessions({ objectStore, now = Date.now, limits = {} }) {
  const { shards = SHARDS, shardLimit = SHARD_LIMIT, own: ownLimit = OWN, overall: overallLimit = OVERALL } = limits;
  const shardKey = nonceHash => 'sessions/' + hash('huma-sessions-v1\0' + (parseInt(nonceHash[0], 16) % shards));
  const counts = new Map(), salt = randomBytes(16).toString('hex'); let window = 0, overall = 0;
  const count = (key, value) => {
    if (counts.size >= CLIENTS && !counts.has(key)) counts.delete(counts.keys().next().value);
    counts.set(key, value);
  };
  function admit(client) {
    const at = now();
    if (at - window >= WINDOW) { counts.clear(); window = at; overall = 0; }
    const network = networkOf(client), mine = counts.get(client) ?? 0, theirs = network ? counts.get('net ' + network) ?? 0 : 0;
    if (mine >= PER_CLIENT || theirs >= PER_NETWORK || (overall >= overallLimit && mine >= NEWCOMER))
      throw fail(429, 'Too many new pages from here right now. Try again in a few minutes.');
    count(client, mine + 1); if (network) count('net ' + network, theirs + 1); overall++;
  }
  const prune = (state, at) => Object.fromEntries(Object.entries(state && typeof state === 'object' ? state : {})
    .filter(([, entry]) => Number.isFinite(entry?.issued) && entry.issued + SESSION_LIFETIME > at && entry.issued <= at));
  /** A fresh nonce for a page about to start: { nonce } as 32 hex characters. `client` is clientAddress(req). */
  async function issue(client) {
    client = typeof client === 'string' && client ? client : 'unknown';
    admit(client);
    let nonce;
    do nonce = randomBytes(16); while (nonce.every(b => b === 0));
    // Who asked, as a salted hash (this process's salt: never the address itself), to cap their unused nonces.
    const hex = nonce.toString('hex'), key = hash(hex), at = now(), by = hash(salt + '\0' + client).slice(0, 16);
    await changeState(objectStore, shardKey(key), {}, state => {
      const next = prune(state, at), oldest = (a, b) => a[1].issued - b[1].issued;
      // This client's unused nonces here, past OWN: its own oldest go.
      const own = Object.entries(next).filter(([, entry]) => entry.by === by && !entry.used).sort(oldest);
      for (const [gone] of own.slice(0, Math.max(0, own.length - ownLimit + 1))) delete next[gone];
      // A full shard drops its oldest: used ones first (their pages are already shared; an unknown nonce is refused,
      // so dropping one never lets a page through), then the oldest unused.
      const excess = Object.keys(next).length - shardLimit + 1;
      if (excess > 0) for (const [gone] of Object.entries(next).sort((a, b) => (a[1].used ? 0 : 1) - (b[1].used ? 0 : 1) || oldest(a, b)).slice(0, excess))
        delete next[gone];
      next[key] = { issued: at, by };
      return next;
    });
    return { nonce: hex };
  }
  /** Checks a browser page's claim and marks its nonce used by `proof` (the page proof's hash; the same proof may
   *  be shared again after a failed try, no other may). Returns when the server issued the nonce. */
  async function confirm({ nonce, claimed }, proof) {
    if (typeof nonce !== 'string' || !/^[a-f0-9]{32}$/.test(nonce) || typeof proof !== 'string') throw fail(403, TIME_NOT_CONFIRMED);
    const key = hash(nonce), at = now();
    let issued;
    await changeState(objectStore, shardKey(key), {}, state => {
      const entry = state?.[key];
      if (!Number.isFinite(entry?.issued) || entry.issued > at || entry.issued + SESSION_LIFETIME <= at ||
          (entry.used && entry.used !== proof) || at - entry.issued < claimed - SESSION_SLACK) throw fail(403, TIME_NOT_CONFIRMED);
      issued = entry.issued;
      return { ...prune(state, at), [key]: { issued, used: proof } };
    });
    return issued;
  }
  return { issue, confirm };
}
