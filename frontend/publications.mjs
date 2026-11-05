import { createHash, createPublicKey, randomBytes, timingSafeEqual, verify as verifySignature } from 'node:crypto';
import { spawn } from 'node:child_process';
import { promisify } from 'node:util';
import { brotliCompress, gzip, constants as zlib } from 'node:zlib';
import { fileURLToPath } from 'node:url';
import { configuredObjectStore, QUOTA_STATE_LIMIT } from './object-store.mjs';
import { worldIDSigninMessage, accountSignal, validateManifest, publicationMessage, removalMessage, replayMessage, requestMessage, listedMessage, titleMessage, signinMessage, cleanTitle, shortTitle, writerProfile, deviceAuthorizationMessage, humaScore, writtenInBrowser, MASTER_LIMIT, PROOF_LIMIT, UPLOAD_LIMIT, REPLAY_LIMIT } from './publication-contract.mjs';
import { PublicationQuotas } from './upload-quotas.mjs';
import { hashRecord, checkHashRecord, attestationKey, recordBytes } from './hash-record.mjs';
import { verifyMessage, getAddress } from 'viem';
import { verifyReplay } from './replay-core.mjs';
import { configuredTurnstile, requestHostname, NOT_CONFIRMED } from './turnstile-verify.mjs';
import { configuredWorldID, pageSignal, publicWorldID, NOT_VERIFIED, WORLD_ID_REQUIRED, WORLD_ID_LIMIT } from './worldid-verify.mjs';
import { createSessions, sessionClaim, clientAddress } from './sessions.mjs';
import { clientIP } from './client-ip.mjs';
import { deviceOwnerKey, deviceOwner, profileKey, writersIndexKey, readState, changeState, accountWorldID, worldIDKey, WRITER_PAGES } from './documents.mjs';
const brotli = promisify(brotliCompress), gzipped = promisify(gzip);

const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const fail = (status, message) => Object.assign(new Error(message), { status });
const strictHash = value => typeof value === 'string' && value.match(/^[a-f0-9]{64}$/)?.[0] === value;
const sameToken = (token, expected) => typeof token === 'string' && token.length <= 8192 &&
  typeof expected === 'string' && timingSafeEqual(Buffer.from(hash(token), 'hex'), Buffer.from(expected, 'hex'));
const bearer = req => req.headers.authorization?.match(/^Bearer ([A-Za-z0-9._~-]{1,8192})$/)?.[1];
// Short links, /p/<code>#<key>: both parts are worked out from the page's id and link token, so a page always gets
// the same short link and asking again stores nothing new. The key opens the page like the token does; only its hash
// is stored, and like the token it stays after the #, so it never reaches the server's logs or link-preview crawlers.
const BASE62 = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
const base62 = (bytes, length) => { let n = BigInt('0x' + bytes.toString('hex')), out = ''; while (out.length < length) { out += BASE62[Number(n % 62n)]; n /= 62n; } return out; };
const derive = (...parts) => createHash('sha256').update(parts.join('\0')).digest();
export const shortCode = value => typeof value === 'string' && /^[A-Za-z0-9]{8,12}$/.test(value);
// A reader who opened a short link sends "<code>.<key>" where a full link sends its token.
const shortBearer = token => token?.match(/^([A-Za-z0-9]{8,12})\.([A-Za-z0-9]{16})$/);
/** A page's Huma score and check tier, worked out here from what the verifier checked (publication-verifier.mjs), the
 *  way a reader does (verify.mjs): never what the uploader says. Pages without a page proof's journal have neither. */
export function verifiedScore(scoring) {
  const j = scoring?.journal;
  if (!j || typeof j !== 'object') return { score: null, tier: null };
  const browser = writtenInBrowser(j), passkey = browser && scoring.passkey === true;
  // A browser page whose uploaded replay's rhythm looked automated (replayRhythm, worked out by the verifier) is held at 50.
  const { value } = humaScore({ composition: scoring.composition ?? null, typingEdits: Number(j.typing), edits: Number(j.edits),
    rules: Array.isArray(j.rules) ? j.rules : [], presenceCount: Number(j.presence_count), onTime: Number(j.on_time), browser, passkey,
    rhythmAutomated: scoring.rhythmAutomated === true });
  return { score: Number.isInteger(value) ? value : null, tier: browser ? (passkey ? 'passkey' : 'web') : 'mac' };
}
/** The title a writer gave their page (up to 120 characters), or else its first line. */
/** The writer's title for a page, or a short name from its first line. */
const pageTitle = (title, text) => cleanTitle(title) || shortTitle((text ?? '').split('\n').find(line => line.trim()) ?? '');
const listedKey = id => 'listed/' + id;

/** A request's body, up to `limit` bytes. A client that stops sending for `idle` ms, or takes longer than `total`, is
 *  cut off, so a stalled upload can't hold a place for long. */
async function readBody(req, limit, message = 'Request too large.', { idle = 10000, total = 120000 } = {}) {
  if (Number(req.headers['content-length'] ?? 0) > limit) throw fail(413, message);
  const chunks = []; let size = 0, quiet;
  const wait = () => { clearTimeout(quiet); quiet = setTimeout(() => req.destroy(), idle); }, deadline = setTimeout(() => req.destroy(), total);
  wait();
  try {
    for await (const chunk of req) { wait(); size += chunk.length; if (size > limit) throw fail(413, message); chunks.push(chunk); }
    return Buffer.concat(chunks);
  } finally { clearTimeout(quiet); clearTimeout(deadline); }
}
export async function readPublicationUpload(req) {
  return new TextDecoder('utf-8', { fatal: true }).decode(await readBody(req, UPLOAD_LIMIT, 'Master or proof exceeds upload limits.'));
}
export function verifyPublicationUpload(source) {
  return new Promise((resolve, reject) => {
    const worker = spawn(process.execPath, ['--max-old-space-size=256', fileURLToPath(new URL('./publication-verifier.mjs', import.meta.url))], { stdio: ['pipe', 'pipe', 'pipe'] });
    const chunks = []; let bytes = 0, done = false;
    const finish = (error, value) => {
      if (done) return; done = true; clearTimeout(timer); worker.kill('SIGKILL');
      error ? reject(error) : resolve(value);
    };
    const timer = setTimeout(() => finish(fail(422, 'Proof verification exceeded its local limit.')), 25000);
    worker.stdout.on('data', chunk => {
      bytes += chunk.length;
      if (bytes > PROOF_LIMIT * 2 + REPLAY_LIMIT * 2 + 16384) finish(fail(422, 'Public proof exceeds limits.')); else chunks.push(chunk);
    });
    worker.stderr.on('data', () => {});
    worker.stdin.on('error', () => finish(fail(422, 'Proof verification failed.')));
    worker.once('error', () => finish(fail(422, 'Proof verification failed.')));
    worker.once('close', code => {
      if (code !== 0) { finish(fail(422, 'The proof does not verify against this master.')); return; }
      try { finish(null, JSON.parse(Buffer.concat(chunks))); } catch { finish(fail(422, 'Invalid public proof.')); }
    });
    worker.stdin.end(source);
  });
}
export { publicationMessage };
/** A valid signature from one of the signed-in user's wallets, or null when none was sent. */
async function signedBy(body, wallets, manifest) {
  if (body.wallet === undefined && body.signature === undefined) return null;
  if (typeof body.wallet !== 'string' || !/^0x[0-9a-fA-F]{40}$/.test(body.wallet) ||
      typeof body.signature !== 'string' || !/^0x[0-9a-fA-F]{130,4096}$/.test(body.signature)) throw fail(400, 'Invalid publication signature.');
  if (!wallets.some(w => w.toLowerCase() === body.wallet.toLowerCase())) throw fail(403, 'That wallet is not linked to this sign-in.');
  const message = publicationMessage(manifest);
  let valid = false;
  try { valid = await verifyMessage({ address: body.wallet, message, signature: body.signature }); } catch {}
  if (!valid) throw fail(403, 'The publication signature does not match.');
  return { wallet: getAddress(body.wallet), message, signature: body.signature };
}
export const deviceKey = value => typeof value === 'string' && /^04[0-9a-f]{128}$/.test(value) ? value : null;
const deviceRecord = (publicKey, wallet) => 'devices/' + hash('huma-device-v1\0' + publicKey + '\0' + wallet.toLowerCase());
/** A P-256 (Secure Enclave) signature over `message`, DER-encoded and base64, by the x9.63 `publicKey`. */
export function deviceSigned(publicKey, message, signature) {
  if (typeof signature !== 'string' || !/^[A-Za-z0-9+/=]{8,200}$/.test(signature)) return false;
  const point = Buffer.from(publicKey, 'hex'), b64url = bytes => bytes.toString('base64url');
  try {
    const key = createPublicKey({ format: 'jwk', key: { kty: 'EC', crv: 'P-256', x: b64url(point.subarray(1, 33)), y: b64url(point.subarray(33)) } });
    return verifySignature('sha256', Buffer.from(message), { key, dsaEncoding: 'der' }, Buffer.from(signature, 'base64'));
  } catch { return false; }
}
async function readSmallJSON(req, limit = 4096) {
  const body = await readBody(req, limit);
  try { const value = JSON.parse(body.toString('utf8') || '{}'); if (value && typeof value === 'object') return value; } catch {}
  throw fail(400, 'JSON required.');
}
/** The email or username a person signed in with (email, Google, Apple, X, GitHub, Discord…), for display. */
export function accountName(linked = []) {
  for (const a of linked) {
    if (a?.type === 'wallet') continue;
    const name = a?.type === 'email' ? a.address : a?.email ?? a?.username;
    if (typeof name === 'string' && name.length <= 200 && !/[\u0000-\u001f]/.test(name)) return name;
  }
  return null;
}

/** The account a World ID signs in to (/api/worldid/signin): one per person, found again on every device by its nullifier,
 *  in each World ID environment. It has no wallet: `wallet` is an address made from the account, which names it where a
 *  device is linked (devices/, owners/) as a Privy wallet's address did, and signs nothing. */
export function worldIDAccount(nullifier, environment) {
  const owner = hash('huma-world-account-v1\0' + environment + '\0' + nullifier);
  return { owner, wallet: getAddress('0x' + hash('huma-world-wallet-v1\0' + owner).slice(0, 40)) };
}

/** Privy sign-in for uploaders: verifies the access token, then reads the user's embedded
 *  Ethereum wallets, so a publication can be signed by one of them. */
export function privyAuthenticator(env = process.env) {
  let client;
  return async token => {
    if (!env.PRIVY_APP_ID || !env.PRIVY_APP_SECRET) throw fail(503, 'Publication sign-in is not configured.');
    if (!token || token.length > 8192) throw fail(401, 'Sign in to approve publication.');
    if (!client) {
      const { PrivyClient } = await import('@privy-io/node');
      client = new PrivyClient({ appId: env.PRIVY_APP_ID, appSecret: env.PRIVY_APP_SECRET });
    }
    let userId;
    try {
      ({ user_id: userId } = await client.utils().auth().verifyAccessToken(token));
      if (typeof userId !== 'string' || !userId || userId.length > 200) throw new Error();
    } catch { throw fail(401, 'Sign-in expired or could not be verified.'); }
    let wallets = [], account = null;
    try {
      const user = await client.users()._get(userId);
      wallets = user.linked_accounts.filter(a => a.type === 'wallet' && a.chain_type === 'ethereum' && a.connector_type === 'embedded')
        .map(a => a.address).filter(a => typeof a === 'string' && /^0x[0-9a-fA-F]{40}$/.test(a));
      account = accountName(user.linked_accounts);
    } catch { throw fail(503, 'Your wallet could not be looked up. Try again.'); }
    return { owner: hash('huma-privy-uploader-v1\0' + userId), wallets, account };
  };
}

// A stored record may carry a World ID proof (worldid-verify.mjs), so it is read with room for one.
const RECORD_LIMIT = 16384 + WORLD_ID_LIMIT;
export function createPublications({ directory, objectStore = configuredObjectStore(directory),
  authenticate = privyAuthenticator(), verifyUpload = verifyPublicationUpload, checkReplay = verifyReplay, now = Date.now,
  quotaLimits, turnstile = configuredTurnstile(), worldId = configuredWorldID() } = {}) {
  // Authenticators return an owner hash, or { owner, wallets } when they also know the user's wallets.
  const identify = async token => {
    const value = await authenticate(token);
    return typeof value === 'string' ? { owner: value, wallets: [], account: null } : value;
  };
  const quotas = new PublicationQuotas(objectStore, { now, ...(quotaLimits ? { limits: quotaLimits } : {}) });
  const sessions = createSessions({ objectStore, now });
  const pending = new Map(); let retained = 0, preparing = 0, publishing = 0, replaying = 0;
  // Onboarding sign-in: the app makes a secret code, the browser signs in and posts it with the
  // Privy token, and the app reads back who signed in. Keyed by the code's hash; ten minutes.
  const signins = new Map();
  const ttl = 10 * 60 * 1000, pendingLimit = 64 * 1024 * 1024;
  // Per client (client-ip.mjs): the big bodies it is sending, the pages it has waiting and its live sign-in codes, so
  // one client can't fill what everyone shares. Bodies being read also share one byte budget.
  const reading = new Map(); let inflight = 0;
  const READS_PER_CLIENT = 2, PENDING_COUNT = 64, PENDING_PER_CLIENT = 4, SIGNINS_PER_CLIENT = 20, INFLIGHT_LIMIT = 256 * 1024 * 1024;
  /** A place to read a big body from `ip`, reserving its Content-Length (or else `limit`) from the byte budget; returns its release. */
  function startRead(req, ip, limit) {
    const declared = Number(req.headers['content-length']), bytes = Number.isSafeInteger(declared) && declared >= 0 ? Math.min(declared, limit) : limit;
    if ((reading.get(ip) ?? 0) >= READS_PER_CLIENT) throw fail(429, 'Too many uploads from here at once; retry shortly.');
    if (inflight + bytes > INFLIGHT_LIMIT) throw fail(503, 'Huma is busy receiving other pages. Try again in a minute.');
    reading.set(ip, (reading.get(ip) ?? 0) + 1); inflight += bytes;
    return () => { inflight -= bytes; const left = reading.get(ip) - 1; left ? reading.set(ip, left) : reading.delete(ip); };
  }
  // A listed or title signature is taken once, within five minutes of its time (listedMessage).
  const used = new Map(), FRESH = 5 * 60 * 1000;
  function signedOnce(publicKey, message, signature, time) {
    if (!Number.isSafeInteger(time) || Math.abs(now() - time) > FRESH) throw fail(403, 'This request has expired. Try again.');
    if (!deviceSigned(publicKey, message, signature)) throw fail(403, 'The signature does not match.');
    for (const [key, until] of used) if (until <= now()) used.delete(key);
    const key = hash(publicKey + '\0' + message);
    if (used.has(key)) throw fail(409, 'This request was already made.');
    if (used.size >= 10000) throw fail(429, 'Huma is busy; try again in a minute.');
    used.set(key, time + FRESH);
  }
  function expire() {
    for (const [id, item] of pending) if (!item.publishing && item.expires <= now()) {
      retained -= item.bytes; pending.delete(id);
    }
  }
  const cleanup = setInterval(expire, 30000); cleanup.unref();
  function find(req, id, token = bearer(req)) {
    expire(); const item = pending.get(id);
    if (!item || !sameToken(token, item.ticketHash)) throw fail(404, 'Publication request not found or expired.');
    return item;
  }
  function summary(item) {
    return { status: item.result ? 'published' : 'awaiting-approval', expiresAt: item.expires,
      manifest: item.manifest, ...(item.text !== undefined ? { text: item.text } : {}),
      ...(item.approvalError ? { approvalError: item.approvalError } : {}),
      ...(item.result ? item.result : {}), storage: objectStore.kind };
  }
  async function removed(id) {
    try { await objectStore.get('removed/' + id, 4096); return true; } catch { return false; }
  }
  async function record(req, id) {
    if (await removed(id)) throw fail(410, 'The writer removed this page.');
    let value;
    try { value = JSON.parse(await objectStore.get('records/' + id, RECORD_LIMIT)); }
    catch { throw fail(404, 'Publication not found.'); }
    if (typeof value.manifest !== 'string' || hash(value.manifest) !== id) throw fail(422, 'Stored manifest changed.');
    const manifest = validateManifest(JSON.parse(value.manifest));
    const token = bearer(req), short = shortBearer(token);
    if (manifest.access === 'link' && !sameToken(token, value.tokenHash)) {
      const alias = short ? await shortPage(short[1]) : null;
      if (alias?.id !== id || !sameToken(short[2], alias.keyHash)) throw fail(404, 'Publication not found.');
    }
    return { source: value.manifest, manifest, owner: value.owner, ownerHash: value.ownerHash, profile: value.profile ?? null, replay: value.replay ?? null, worldId: value.worldId ?? null,
      serverStart: Number.isFinite(value.serverStart) ? value.serverStart : null, stored: value.stored ?? null };
  }
  /** Where Arkiv keeps a page's text and proof, for its record: { stored: { network, chainId, explorer, rpc, owner, master,
   *  proof } }, each file { entity, tx, chunks, at, expires }. Nothing for another store, or when a write gave no entity. */
  async function storedOn(master, proof) {
    if (objectStore.kind !== 'arkiv' || !master?.entity || !proof?.entity) return {};
    const network = await objectStore.network().catch(() => null);
    return network ? { stored: { ...network, master, proof } } : {};
  }
  /** Anchors a page's signed hash record (hash-record.mjs) on a store that has anchor(); never fails the share. */
  async function anchorRecord(id, fields) {
    if (typeof objectStore.anchor !== 'function') return null;
    try {
      const value = hashRecord(fields.manifest, fields.owner, now());
      return value ? await objectStore.anchor(attestationKey(id), recordBytes(value)) : null;
    } catch { return null; }
  }
  /** The anchored record of a page, read back from the store and checked against the page's manifest, or null. */
  async function attestation(id, manifestSource) {
    if (typeof objectStore.anchored !== 'function') return null;
    try {
      const row = await objectStore.anchored(attestationKey(id));
      if (!row) return null;
      const value = JSON.parse(row.bytes.toString('utf8')), check = await checkHashRecord(value, manifestSource);
      return { record: value, entity: row.entity, at: row.at, check: { ok: check.ok, signature: check.signature } };
    } catch { return null; }
  }
  /** What a short link's code points to: { id, keyHash }, or null. */
  async function shortPage(code) {
    if (!shortCode(code)) return null;
    try { const value = JSON.parse(await objectStore.get('short/' + hash(code), 1024)); return strictHash(value.id) ? value : null; } catch { return null; }
  }
  /** The short link for a page its reader can open (`token` is how they opened it). */
  async function shortLink(id, token) {
    const short = shortBearer(token);
    if (short) return '/p/' + short[1] + '#' + short[2];
    const key = token ? base62(derive('huma-short-key-v1', token), 16) : null, keyHash = key ? hash(key) : null;
    const seed = derive('huma-short-code-v1', id, token ?? '');
    // Eight characters, or a longer code in the rare case another page already has that one.
    for (const length of [8, 10, 12]) {
      const code = base62(seed, length), link = '/p/' + code + (key ? '#' + key : '');
      let stored = await shortPage(code);
      if (!stored) {
        try { await objectStore.put('short/' + hash(code), Buffer.from(JSON.stringify({ id, keyHash }))); } catch {}
        stored = await shortPage(code);
      }
      if (stored?.id === id && stored.keyHash === keyHash) return link;
    }
    throw fail(503, 'Couldn’t make a short link. Share the full link instead.');
  }
  async function handle(req, res, pathname, { json, headers }) {
    if (pathname === '/api/sessions') {
      // A browser page's session nonce, asked for at Start (sessions.mjs); its publish is checked against it.
      if (req.method !== 'POST') throw fail(405, 'Method not allowed.');
      json(res, 200, await sessions.issue(clientAddress(req)));
      return true;
    }
    if (!pathname.startsWith('/api/publications') && pathname !== '/api/worldid/signin') return false;
    const reply = (status, data) => json(res, status, data);
    // Proofs are base64 JSON, so they travel compressed when the reader accepts it: a 140 KB page proof sends 86 KB.
    // Browsers and the Mac app undo the encoding before anything reads or hashes the bytes.
    // Media masters are already compressed and up to 32 MB, so they go as stored rather than costing CPU on every GET.
    const raw = async (body, type, attachment, compress = true) => {
      const accepts = req.headers['accept-encoding'] ?? '';
      const encoding = !compress || body.length < 1024 ? null : /\bbr\b/.test(accepts) ? 'br' : /\bgzip\b/.test(accepts) ? 'gzip' : null;
      if (encoding === 'br') body = await brotli(body, { params: { [zlib.BROTLI_PARAM_QUALITY]: 4, [zlib.BROTLI_PARAM_SIZE_HINT]: body.length } });
      else if (encoding === 'gzip') body = await gzipped(body);
      res.writeHead(200, { ...headers, 'Content-Type': type, 'Content-Length': body.length, Vary: 'Accept-Encoding',
        ...(encoding ? { 'Content-Encoding': encoding } : {}),
        ...(attachment ? { 'Content-Disposition': `attachment; filename="${attachment}"` } : {}) }); res.end(body);
    };
    const issue = req.method === 'POST' && pathname === '/api/publications/prepare';
    const ticketID = pathname.match(/^\/api\/publications\/pending\/([a-f0-9]{64})(\/publish|\/publish-device)?$/);
    const publishedID = pathname.match(/^\/api\/publications\/([a-f0-9]{64})(?:\/(master|proof|replay|receipt|worldid|remove|short|listed|title))?$/);
    // Which page a short link's code names (its id, which opens nothing by itself without the key after the #): how a
    // browser finds the page it's renaming or deleting from the link it kept.
    const shortName = pathname.match(/^\/api\/publications\/short\/([A-Za-z0-9]+)$/)?.[1];
    if (shortName && req.method === 'GET') {
      const id = (await shortPage(shortName))?.id;
      if (!id) throw fail(404, 'Publication not found.');
      reply(200, { id }); return true;
    }
    // Sign-in with World ID, in place of Privy (frontend/write/worldid.mjs): a World ID made for this browser's publishing
    // key, and the request signed by that key. World confirms the proof here; the account is the World ID's own
    // (worldIDAccount), so one person has one account, the same on every device. The browser's key is linked to it as a
    // Privy sign-in linked it, and the account keeps its World ID for the pages it shares (documents.mjs).
    if (pathname === '/api/worldid/signin') {
      if (req.method !== 'POST') throw fail(405, 'Method not allowed.');
      if (!worldId.enabled) throw fail(404, 'World ID is off.');
      const raw = await readBody(req, WORLD_ID_LIMIT + 1024, 'World ID proof is too large.');
      let body = null;
      try { body = JSON.parse(raw.toString('utf8')); } catch {}
      const publicKey = deviceKey(body?.publicKey);
      if (!publicKey || !body.proof || typeof body.proof !== 'object' || Array.isArray(body.proof)) throw fail(400, 'Invalid sign-in.');
      if (!deviceSigned(publicKey, worldIDSigninMessage(publicKey, hash(raw)), req.headers['x-huma-signature'])) throw fail(403, 'The sign-in signature does not match.');
      const result = await worldId.verify(body.proof, accountSignal(publicKey));
      if (!result.ok) throw fail(result.status === 400 ? 403 : result.status, NOT_VERIFIED);
      const { wallet, account, shown } = await linkWorldDevice(publicKey, result.record, { browser: true });
      reply(200, { status: 'signed-in', wallet, account, worldId: shown }); return true;
    }
    if (pathname === '/api/publications/signin') {
      const code = req.headers['x-huma-signin'];
      if (!strictHash(code)) throw fail(400, 'Sign-in code required.');
      for (const [key, item] of signins) if (item.expires <= now()) signins.delete(key);
      if (req.method === 'GET') {
        const item = signins.get(hash(code));
        if (item && req.headers['x-huma-signature'] !== undefined) await bindBrowser(code, item, req.headers['x-huma-signature']);
        reply(200, item ? { status: 'signed-in', account: item.account, wallet: item.wallet, device: item.device } : { status: 'waiting' }); return true;
      }
      if (req.method !== 'POST') throw fail(405, 'Method not allowed.');
      // First sign-in wins: someone who later sees the code can't swap the account the Mac links to.
      if (signins.has(hash(code))) throw fail(409, 'This sign-in code was already used. Start again from Huma.');
      const ip = clientIP(req), live = (field, value) => [...signins.values()].filter(item => item[field] === value).length;
      if (signins.size >= 1024 || live('ip', ip) >= SIGNINS_PER_CLIENT) throw fail(429, 'Too many sign-ins right now; retry shortly.');
      const body = await readSmallJSON(req, 8192 + WORLD_ID_LIMIT);
      // The Mac signs in with World ID, in place of Privy (share/src/WorldSignIn.jsx): a World ID made for this Mac's
      // publishing key, checked with World here, links the key to that World ID's account. The Mac reads it back with
      // the code, as before.
      if (body.worldId !== undefined) {
        const publicKey = deviceKey(body.publicKey);
        if (!worldId.enabled) throw fail(404, 'World ID is off.');
        if (!publicKey || !body.worldId || typeof body.worldId !== 'object' || Array.isArray(body.worldId)) throw fail(400, 'Invalid sign-in.');
        const result = await worldId.verify(body.worldId, accountSignal(publicKey));
        if (!result.ok) throw fail(result.status === 400 ? 403 : result.status, NOT_VERIFIED);
        const { owner, wallet, account } = await linkWorldDevice(publicKey, result.record, { browser: false });
        if (signins.has(hash(code))) throw fail(409, 'This sign-in code was already used. Start again from Huma.');
        signins.set(hash(code), { account, wallet, device: true, owner, ip, publicKey, expires: now() + ttl });
        reply(200, { status: 'signed-in', account }); return true;
      }
      // Privy, off for now on the web and the Mac (World ID signs in instead): no page sends its token any more.
      const { owner, wallets = [], account = null } = await identify(bearer(req));
      if (!strictHash(owner)) throw fail(401, 'Sign-in could not be verified.');
      let wallet = wallets[0] ?? null, device = false, publicKey = null;
      if (body.publicKey !== undefined) {
        // The wallet authorizes this Mac's publishing key, so Finish can share without the browser.
        publicKey = deviceKey(body.publicKey);
        if (!publicKey || typeof body.wallet !== 'string' || !wallets.some(w => w.toLowerCase() === body.wallet.toLowerCase())) throw fail(403, 'That wallet is not linked to this sign-in.');
        const message = deviceAuthorizationMessage(body.wallet, publicKey);
        let valid = false;
        try { valid = await verifyMessage({ address: body.wallet, message, signature: body.signature }); } catch {}
        if (!valid) throw fail(403, 'The device authorization signature does not match.');
        wallet = getAddress(body.wallet);
        // A key kept as another account's is refused before anything is written.
        const bound = await deviceOwner(objectStore, publicKey);
        if (bound && bound.owner !== owner) throw fail(409, 'This browser is already linked to another account.');
        const key = deviceRecord(publicKey, wallet);
        let existing = null;
        try { existing = JSON.parse((await objectStore.get(key, 16384)).toString('utf8')); } catch {}
        if (!existing) await objectStore.put(key, Buffer.from(JSON.stringify({ wallet, owner, publicKey, authorization: { message, signature: body.signature } })));
        else if (existing.owner !== owner) throw fail(409, 'This Mac is already linked to another account for that wallet.');
        device = true;
      }
      if (signins.has(hash(code))) throw fail(409, 'This sign-in code was already used. Start again from Huma.');
      signins.set(hash(code), { account, wallet, device, owner, ip, publicKey, expires: now() + ttl });
      reply(200, { status: 'signed-in', account }); return true;
    }
    if (issue) {
      if (!(req.headers['content-type'] ?? '').startsWith('application/json')) throw fail(415, 'JSON required.');
      // Pages waiting for approval, all and from this client; a shared page no longer holds a place.
      const ip = clientIP(req), full = () => {
        expire(); const open = [...pending.values()].filter(item => !item.result);
        return open.length >= PENDING_COUNT || open.filter(item => item.ip === ip).length >= PENDING_PER_CLIENT;
      };
      if (full()) throw fail(429, 'Publication queue is full; retry later.');
      const release = startRead(req, ip, UPLOAD_LIMIT);
      let source;
      try { source = await readPublicationUpload(req); } finally { release(); }
      // A check takes its place only once the whole upload is here, so a slow upload holds no one else up.
      if (preparing >= 2 || full()) throw fail(429, 'Publication queue is full; retry later.');
      preparing++;
      try {
        const { manifest, proof, replay, scoring } = await verifyUpload(source);
        validateManifest(manifest);
        const master = Buffer.from(JSON.parse(source).master.base64, 'base64');
        const bytes = master.length + Buffer.byteLength(proof) + (replay ? Buffer.byteLength(replay) : 0);
        if (hash(master) !== manifest.master.hash || hash(proof) !== manifest.proof.hash) throw fail(422, 'Verified upload changed.');
        if (retained + bytes > pendingLimit) throw fail(429, 'Publication queue is full; retry later.');
        const id = randomBytes(32).toString('hex'), ticket = randomBytes(32).toString('hex');
        const browser = Boolean(scoring?.journal && writtenInBrowser(scoring.journal));
        pending.set(id, { ip, manifest, proof: Buffer.from(proof), master, bytes, ticketHash: hash(ticket), expires: now() + ttl,
          ...verifiedScore(scoring), browser, ...(browser ? { session: sessionClaim(scoring.journal) } : {}), ...(replay ? { replay: Buffer.from(replay) } : {}),
          ...(manifest.statement.contentKind === 'text' ? { text: new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(master) } : {}) });
        retained += bytes;
        reply(201, { id, ticket, expiresAt: now() + ttl, storage: objectStore.kind });
      } finally { preparing--; }
      return true;
    }
    if (ticketID && req.method === 'GET' && !ticketID[2]) { reply(200, summary(find(req, ticketID[1]))); return true; }
    if (ticketID?.[2] && req.method === 'POST') {
      const item = find(req, ticketID[1], req.headers['x-huma-ticket']);
      if (publishing >= 2 || item.publishing) throw fail(409, 'Publication is already in progress.');
      publishing++; item.publishing = true;
      try {
        const byDevice = ticketID[2] === '/publish-device', body = await readSmallJSON(req, byDevice ? 8192 + WORLD_ID_LIMIT : 4096);
        const { owner: ownerHash, wallets, signer } = byDevice ? await deviceSigner(body, item.manifest) : await identify(bearer(req));
        if (!strictHash(ownerHash)) throw fail(401, 'Uploader identity was not verified.');
        if (item.ownerHash && item.ownerHash !== ownerHash) throw fail(403, 'This publication belongs to another uploader.');
        item.ownerHash = ownerHash;
        if (item.result) { reply(200, summary(item)); return true; }
        await confirmPerson(req, item, body.turnstile);
        await confirmWorldID(item, body.worldId);
        await confirmTime(item);
        await claimWriter(item.manifest.statement.captureKeyHash, ownerHash);
        const manifest = JSON.stringify(item.manifest), id = hash(manifest);
        item.quotaDay ??= quotas.day();
        try {
          await quotas.reserve({ id, owner: ownerHash, bytes: item.bytes, proof: item.manifest.proof.hash, day: item.quotaDay });
          delete item.approvalError;
        } catch (error) {
          if (error.status === 429) {
            // Denial committed no reservation. A still-live request may retry
            // after midnight; ambiguous storage failures keep their old day.
            delete item.quotaDay; item.approvalError = 'daily-limit';
          }
          throw error;
        }
        // A retry after an ambiguous network result must use the same capability
        // and immutable record; it cannot rotate the link behind the user's back.
        if (!item.proposed) {
          const token = item.manifest.access === 'link' ? randomBytes(32).toString('hex') : null;
          const signed = byDevice ? signer : await signedBy(body, wallets, item.manifest);
          // The handle is the account's own (documents.mjs), never what a page says.
          const profile = writerProfile(body.profile && typeof body.profile === 'object' ? { name: body.profile.name, avatar: body.profile.avatar } : body.profile);
          if (body.listed !== undefined && typeof body.listed !== 'boolean') throw fail(400, 'Invalid publication.');
          item.proposed = { result: { id, path: '/original/' + id + (token ? '#' + token : '') }, token, listed: body.listed === true, title: pageTitle(body.title, item.text),
            fields: { manifest, tokenHash: token ? hash(token) : null, ownerHash,
              ...(signed ? { owner: signed } : {}), ...(profile ? { profile } : {}), ...(item.serverStart ? { serverStart: item.serverStart } : {}), ...(item.worldId ? { worldId: item.worldId } : {}),
              ...(item.replay ? { replay: { hash: hash(item.replay), byteLength: item.replay.length } } : {}) } };
        }
        const [master, proof] = await Promise.all([objectStore.put('objects/' + item.manifest.master.hash, item.master),
          objectStore.put('objects/' + item.manifest.proof.hash, item.proof),
          ...(item.replay ? [objectStore.put('objects/' + hash(item.replay), item.replay)] : [])]);
        // Read back the actual stored objects before making a link available.
        await Promise.all([objectStore.get('objects/' + item.manifest.master.hash, item.manifest.master.byteLength),
          objectStore.get('objects/' + item.manifest.proof.hash, item.manifest.proof.byteLength)]);
        // The record is made once, with where the files are kept, so a retry stores the very same one.
        item.proposed.record ??= Buffer.from(JSON.stringify({ ...item.proposed.fields, ...(await storedOn(master, proof)) }));
        // On a store that can anchor (Arkiv), the signed hash record goes public beside it. Best effort: the page is shared
        // either way, and the receipt shows the anchor only once it is there.
        await anchorRecord(id, item.proposed.fields);
        // The short link is made beside the record, so it comes with this answer instead of another request.
        const [short] = await Promise.all([shortLink(id, item.proposed.token).catch(() => null),
          objectStore.put('records/' + id, item.proposed.record).then(() => addToRecord(ownerHash, id, item))]);
        item.result = { ...item.proposed.result, ...(short ? { short } : {}) };
        // Its files are stored now: only its status stays, for whoever is waiting on it.
        retained -= item.bytes; item.bytes = 0; delete item.master; delete item.proof; delete item.replay;
        reply(200, summary(item));
      } finally { publishing--; item.publishing = false; }
      return true;
    }
    if (publishedID && publishedID[2] === 'replay' && req.method === 'POST') {
      reply(200, await setReplay(req, publishedID[1]));
      return true;
    }
    if (publishedID && publishedID[2] === 'title' && req.method === 'POST') {
      reply(200, await setTitle(req, publishedID[1]));
      return true;
    }
    if (publishedID && publishedID[2] === 'listed' && req.method === 'POST') {
      reply(200, await setListed(req, publishedID[1]));
      return true;
    }
    if (publishedID && publishedID[2] === 'remove' && req.method === 'POST') {
      reply(200, await removePublication(req, publishedID[1]));
      return true;
    }
    if (publishedID && publishedID[2] === 'short' && req.method === 'POST') {
      // A public page has one short link; a key sent with it is ignored, so it can't mint more.
      const { manifest } = await record(req, publishedID[1]);
      reply(200, { path: await shortLink(publishedID[1], manifest.access === 'link' ? bearer(req) : null) });
      return true;
    }
    if (publishedID && req.method === 'GET') {
      const { source, manifest, owner, ownerHash, profile, replay: shared, serverStart, worldId: human, stored } = await record(req, publishedID[1]);
      const part = publishedID[2];
      if (part === 'receipt') {
        // Who shared the page (as this host says), the writer's name and face, whether its replay is shared, the
        // writer's handle (their page, huma.social/@handle) and whether this page shows there. A browser page shared
        // since sessions.mjs also has serverStart: when this server issued its session nonce (milliseconds). A page kept on
        // Arkiv has stored: the entities and transactions holding its text and proof, so a reader can look them up there.
        const [replay, handle, listed, anchor] = await Promise.all([currentReplay(publishedID[1], shared), currentHandle(ownerHash), isListed(publishedID[1]), attestation(publishedID[1], source)]);
        reply(200, { owner: owner ?? null, profile, replay: Boolean(replay), handle, listed, ...(serverStart !== null ? { serverStart } : {}),
          ...(human ? { worldId: publicWorldID(human) } : {}), ...(stored ? { stored } : {}), ...(anchor ? { attestation: anchor } : {}) });
      } else if (part === 'worldid') {
        // What anyone needs to check the badge themselves: the proof as World's verify endpoint takes it, and the signal it was made for.
        if (!human) throw fail(404, 'No World ID was shared with this page.');
        reply(200, { rpId: worldId.rpId, action: human.action, environment: human.environment, signal: human.signal ?? pageSignal(manifest), result: human.result });
      } else if (!part) await raw(Buffer.from(source), 'application/json');
      else if (part === 'replay') {
        // The writer's replay; readers check it against the page proof themselves (replay-core.mjs).
        const replay = await currentReplay(publishedID[1], shared);
        if (!replay || !/^[a-f0-9]{64}$/.test(replay.hash) || !(replay.byteLength <= REPLAY_LIMIT)) throw fail(404, 'This page has no replay.');
        const bytes = await objectStore.get('objects/' + replay.hash, REPLAY_LIMIT);
        if (bytes.length !== replay.byteLength || hash(bytes) !== replay.hash) throw fail(422, 'Stored replay changed.');
        await raw(bytes, 'application/json');
      }
      else if (part === 'master' || part === 'proof') {
        const metadata = manifest[part];
        const bytes = await objectStore.get('objects/' + metadata.hash, part === 'master' ? MASTER_LIMIT : PROOF_LIMIT);
        if (bytes.length !== metadata.byteLength) throw fail(422, 'Stored file length changed.');
        const text = manifest.statement.contentKind === 'text';
        await raw(bytes, 'application/octet-stream', part === 'proof' ? 'Huma-evidence.json' : 'Huma-master' + (text ? '.txt' : '.bin'), part === 'proof' || text);
      }
      else throw fail(405, 'Method not allowed.');
      return true;
    }
    throw fail(404, 'Not found.');
  }
  /** A page written in a browser is shared only from a browser Cloudflare Turnstile says a person uses: its publish
   *  request carries a fresh token for 'publish' (frontend/write/turnstile.mjs). Checked once per request to share, so a
   *  retry after an ambiguous result needn't spend another token. Mac pages, and every page when Turnstile is off,
   *  aren't asked. */
  async function confirmPerson(req, item, token) {
    if (!turnstile?.enabled || !item.browser || item.person) return;
    const result = await turnstile.verify(token, 'publish', { hostname: requestHostname(req), pool: 'publish' });
    if (!result.ok) throw fail(result.status === 400 ? 403 : result.status, NOT_CONFIRMED);
    item.person = true;
  }
  /** Links a publishing key to the account a verified World ID `record` signs in to (worldIDAccount), as a Privy
   *  wallet's authorization did: its device record (devices/), so it can share pages, and for a browser (`browser`)
   *  also its owner (owners/), so it keeps documents in the account. The account keeps its World ID, for the pages it
   *  shares (documents.mjs). A key already linked to another account stays with it. */
  async function linkWorldDevice(publicKey, record, { browser }) {
    const { owner, wallet } = worldIDAccount(record.nullifier, worldId.environment), shown = publicWorldID(record);
    const bound = await deviceOwner(objectStore, publicKey), device = deviceRecord(publicKey, wallet);
    if (bound && bound.owner !== owner) throw fail(409, 'This device is already linked to another account.');
    let existing = null;
    try { existing = JSON.parse((await objectStore.get(device, 16384)).toString('utf8')); } catch {}
    if (existing && existing.owner !== owner) throw fail(409, 'This device is already linked to another account.');
    if (!existing) await objectStore.put(device, Buffer.from(JSON.stringify({ wallet, owner, publicKey, authorization: { worldId: shown.fingerprint } })));
    if (browser && !bound) await objectStore.put(deviceOwnerKey(publicKey), Buffer.from(JSON.stringify({ owner, wallet })));
    if (!(await accountWorldID(objectStore, owner, worldId.environment)))
      await objectStore.put(worldIDKey(owner, worldId.environment), Buffer.from(JSON.stringify(record)));
    return { owner, wallet, account: 'World ID ' + shown.fingerprint, shown };
  }
  /** The World ID a page is kept with: its account's (linked before the writer's first Finish, documents.mjs), so every
   *  page from one writer, Mac pages too, shows the same one. Without that, a World ID sent with this share is checked
   *  against World's verify endpoint for this page's own signal. With World ID on, a page written in a browser is
   *  shared only with one (the human check; HUMA_WORLD_REQUIRED=false makes it optional, and Mac pages are never
   *  asked). One that doesn't check out stops the share, so a badge is never half-given. Checked once per request to share. */
  async function confirmWorldID(item, proof) {
    if (item.worldId || item.proposed) return;
    const linked = worldId.enabled ? await accountWorldID(objectStore, item.ownerHash, worldId.environment) : null;
    if (linked) { item.worldId = linked; return; }
    if (proof === undefined || proof === null) {
      if (worldId.required && item.browser) throw fail(403, WORLD_ID_REQUIRED);
      return;
    }
    if (!worldId.enabled) throw fail(409, 'World ID is not turned on here.');
    if (JSON.stringify(proof).length > WORLD_ID_LIMIT) throw fail(413, 'World ID proof is too large.');
    const result = await worldId.verify(proof, pageSignal(item.manifest));
    if (!result.ok) throw fail(result.status === 400 ? 403 : result.status, NOT_VERIFIED);
    item.worldId = result.record;
  }
  /** A browser page's writing time, against when this server issued its session nonce (sessions.mjs): checked once
   *  per request to share, like confirmPerson. Mac pages aren't asked. */
  async function confirmTime(item) {
    if (!item.browser || item.serverStart) return;
    item.serverStart = await sessions.confirm(item.session ?? {}, item.manifest.proof.hash);
  }
  /** A browser reading back its sign-in shows it holds the publishing key the account linked (signinMessage); only then
   *  is the key kept as the account's (owners/), for its documents (documents.mjs). The Mac doesn't sign here (it keeps
   *  no documents), so a key someone only saw in a receipt can't be tied to their account. */
  async function bindBrowser(code, item, signature) {
    if (!item.publicKey || !deviceSigned(item.publicKey, signinMessage(code, item.publicKey), signature)) throw fail(403, 'The sign-in signature does not match.');
    if (item.bound) return;
    const bound = await deviceOwner(objectStore, item.publicKey);
    if (bound && bound.owner !== item.owner) throw fail(409, 'This browser is already linked to another account.');
    if (!bound) await objectStore.put(deviceOwnerKey(item.publicKey), Buffer.from(JSON.stringify({ owner: item.owner, wallet: item.wallet })));
    item.bound = true;
  }
  /** A writing key belongs to the first account that shares a page it signed (writers/<key hash>), so a copied
   *  page can't be shared again under someone else's name. Pages without a writing key aren't bound. */
  async function claimWriter(keyHash, owner) {
    if (!strictHash(keyHash)) return;
    const key = 'writers/' + keyHash, claimed = async () => JSON.parse(await objectStore.get(key, 1024)).owner;
    let first;
    try { first = await claimed(); }
    catch {
      try { await objectStore.put(key, Buffer.from(JSON.stringify({ owner }))); } catch {}
      first = await claimed();
    }
    if (first !== owner) throw fail(403, 'This writing was first shared from another Huma account, so it can’t be shared from this one.');
  }
  async function deviceSigner(body, manifest) {
    const publicKey = deviceKey(body.publicKey);
    if (!publicKey || typeof body.wallet !== 'string' || !/^0x[0-9a-fA-F]{40}$/.test(body.wallet)) throw fail(400, 'Invalid device publication.');
    let binding;
    try { binding = JSON.parse((await objectStore.get(deviceRecord(publicKey, body.wallet), 16384)).toString('utf8')); }
    catch { throw fail(401, 'This Mac is not linked to that wallet. Sign in again from Huma.'); }
    const message = publicationMessage(manifest);
    if (!deviceSigned(publicKey, message, body.signature)) throw fail(403, 'The publication signature does not match.');
    return { owner: binding.owner, wallets: [binding.wallet], signer: { wallet: getAddress(binding.wallet), message,
      device: { publicKey, signature: body.signature }, authorization: binding.authorization } };
  }
  /** Who may change a shared page: the device that shared it, or another browser signed in to the same account
   *  (its owners/ link), so a page shared from a browser that's gone (a closed private window) can still be renamed,
   *  hidden or deleted. The request is still signed by that browser's key. */
  async function mayChange(value, publicKey) {
    if (!publicKey) return false;
    if (value.owner?.device?.publicKey === publicKey) return true;
    return strictHash(value.ownerHash) && (await deviceOwner(objectStore, publicKey))?.owner === value.ownerHash;
  }
  /** The writer takes a link down from the device that shared it, or another of their signed-in browsers: the page's
   *  text and proof are deleted and the link stops working. */
  async function removePublication(req, id) {
    if (await removed(id)) return { status: 'removed' };
    let value;
    try { value = JSON.parse(await objectStore.get('records/' + id, RECORD_LIMIT)); }
    catch { throw fail(404, 'Publication not found.'); }
    if (typeof value.manifest !== 'string' || hash(value.manifest) !== id) throw fail(422, 'Stored manifest changed.');
    const manifest = validateManifest(JSON.parse(value.manifest));
    const body = await readSmallJSON(req);
    const publicKey = deviceKey(body.publicKey);
    if (!(await mayChange(value, publicKey))) throw fail(403, 'Only your account can delete this page. Sign in on this browser first.');
    if (!deviceSigned(publicKey, removalMessage(id), body.signature)) throw fail(403, 'The removal signature does not match.');
    // Off the writer's page and out of their record first, so a removed page is never listed.
    if (strictHash(value.ownerHash)) await changeState(objectStore, writersIndexKey(value.ownerHash), [], list => list.filter(page => page.id !== id));
    await objectStore.put('removed/' + id, Buffer.from(JSON.stringify({ removedAt: new Date(now()).toISOString() })));
    const current = await currentReplay(id, value.replay);
    await deleteUnused(id, [manifest.master, manifest.proof, ...[current, value.replay].filter(part => part?.hash)]);
    return { status: 'removed' };
  }
  /** The replay a page shows now: the writer's latest choice (replays/<id>, which can change), or else the one it
   *  was shared with. null when it has none. */
  async function currentReplay(id, shared) {
    let state = null;
    try { state = await objectStore.quotaRead?.('replays/' + id); } catch {}
    if (!state) return shared?.hash ? shared : null;
    try { const value = JSON.parse(Buffer.from(state.bytes).toString('utf8')); return strictHash(value.hash) ? value : null; } catch { return null; }
  }
  /** Files are stored by content, so another link can share one (the same text typed again). Deletes only the
   *  files no other live link uses; a file still in use stays for that link. */
  async function deleteUnused(id, parts) {
    const inUse = new Set();
    for (const other of await objectStore.recordIDs?.() ?? []) {
      if (other === id || await removed(other)) continue;
      try {
        const { manifest: source, replay } = JSON.parse(await objectStore.get('records/' + other, RECORD_LIMIT));
        const { master, proof } = JSON.parse(source); inUse.add(master?.hash); inUse.add(proof?.hash); inUse.add(replay?.hash);
        inUse.add((await currentReplay(other, replay))?.hash);
      } catch {}
    }
    for (const part of parts) if (!inUse.has(part.hash)) await objectStore.remove?.('objects/' + part.hash)?.catch(() => {});
  }
  /** Adds a shared page to its account's record (writers-index, read by /api/writers in documents.mjs): its title, words,
   *  score and tier as checked here, when it was shared, whether it shows on the writer's page and its short link. Up
   *  to 2000 pages, newest first, within what one kept value holds. */
  async function addToRecord(owner, id, item) {
    const { token, listed, title } = item.proposed;
    let path = item.proposed.result.path;
    try { path = await shortLink(id, token); } catch {}
    const page = { id, title, words: item.text ? item.text.split(/\s+/).filter(Boolean).length : 0, score: item.score ?? null, tier: item.tier ?? null,
      at: now(), listed, path };
    await changeState(objectStore, writersIndexKey(owner), [], list => {
      const was = list.find(p => p.id === id), next = [{ ...page, at: was?.at ?? page.at }, ...list.filter(p => p.id !== id)].slice(0, WRITER_PAGES);
      while (next.length > 1 && Buffer.byteLength(JSON.stringify(next)) > QUOTA_STATE_LIMIT) next.pop();
      return next;
    });
    await changeState(objectStore, listedKey(id), null, () => ({ listed }));
  }
  /** The account's handle now, or null. */
  async function currentHandle(owner) {
    if (!strictHash(owner)) return null;
    try { return writerProfile((await readState(objectStore, profileKey(owner), null)).value)?.handle ?? null; } catch { return null; }
  }
  async function isListed(id) {
    try { return (await readState(objectStore, listedKey(id), null)).value?.listed === true; } catch { return false; }
  }
  /** The writer shows their page on their writer page, or takes it off, from the device that shared it. */
  /** The writer renames a shared page, from the device that shared it: the name its writer page shows (the page's
   *  text and proof don't change). */
  async function setTitle(req, id) {
    if (await removed(id)) throw fail(410, 'The writer removed this page.');
    let value;
    try { value = JSON.parse(await objectStore.get('records/' + id, RECORD_LIMIT)); }
    catch { throw fail(404, 'Publication not found.'); }
    if (typeof value.manifest !== 'string' || hash(value.manifest) !== id) throw fail(422, 'Stored manifest changed.');
    const body = await readSmallJSON(req), publicKey = deviceKey(body.publicKey), title = cleanTitle(body.title);
    if (!title || title !== body.title) throw fail(400, 'Choose a title up to 80 characters.');
    if (!(await mayChange(value, publicKey))) throw fail(403, 'Only your account can rename this page. Sign in on this browser first.');
    signedOnce(publicKey, titleMessage(id, title, body.time), body.signature, body.time);
    if (!strictHash(value.ownerHash)) throw fail(409, 'This page was shared before writer pages.');
    await changeState(objectStore, writersIndexKey(value.ownerHash), [], list => {
      if (!list.some(page => page.id === id)) throw fail(409, 'This page was shared before writer pages.');
      return list.map(page => (page.id === id ? { ...page, title } : page));
    });
    return { title };
  }
  async function setListed(req, id) {
    // Whether it was taken down and its record, read at once (each is a round trip to the object store).
    // A record may carry a World ID proof, so it's read with room for one (RECORD_LIMIT).
    const [gone, stored] = await Promise.all([removed(id), objectStore.get('records/' + id, RECORD_LIMIT).catch(() => null)]);
    if (gone) throw fail(410, 'The writer removed this page.');
    let value;
    try { value = JSON.parse(stored ?? ''); }
    catch { throw fail(404, 'Publication not found.'); }
    if (typeof value.manifest !== 'string' || hash(value.manifest) !== id) throw fail(422, 'Stored manifest changed.');
    const body = await readSmallJSON(req), publicKey = deviceKey(body.publicKey);
    if (typeof body.listed !== 'boolean') throw fail(400, 'Invalid request.');
    if (!(await mayChange(value, publicKey))) throw fail(403, 'Only your account can change where this page shows. Sign in on this browser first.');
    signedOnce(publicKey, listedMessage(id, body.listed, body.time), body.signature, body.time);
    if (!strictHash(value.ownerHash)) throw fail(409, 'This page was shared before writer pages, so it can’t show on yours.');
    await changeState(objectStore, writersIndexKey(value.ownerHash), [], list => {
      if (!list.some(page => page.id === id)) throw fail(409, 'This page was shared before writer pages, so it can’t show on yours.');
      return list.map(page => (page.id === id ? { ...page, listed: body.listed } : page));
    });
    await changeState(objectStore, listedKey(id), null, () => ({ listed: body.listed }));
    return { listed: body.listed };
  }
  /** The writer turns their page's replay on or off at any time, from the Mac or browser that shared it. A replay must rebuild
   *  the page's exact text with its capture key's signatures (readers check that again themselves). Turning it off
   *  deletes it here; anyone who already watched may have kept a copy. */
  async function setReplay(req, id) {
    if (await removed(id)) throw fail(410, 'The writer removed this page.');
    let value;
    try { value = JSON.parse(await objectStore.get('records/' + id, RECORD_LIMIT)); }
    catch { throw fail(404, 'Publication not found.'); }
    if (typeof value.manifest !== 'string' || hash(value.manifest) !== id) throw fail(422, 'Stored manifest changed.');
    const manifest = validateManifest(JSON.parse(value.manifest));
    // Only a page a device shared can change its replay: refused before its (up to 8 MB) body is read.
    if (!deviceKey(value.owner?.device?.publicKey)) throw fail(403, 'Only the device that shared this page can change its replay.');
    const release = startRead(req, clientIP(req), REPLAY_LIMIT * 2 + 16384);
    let body;
    try { body = await readSmallJSON(req, REPLAY_LIMIT * 2 + 16384); } finally { release(); }
    const publicKey = deviceKey(body.publicKey), replay = body.replay ?? null;
    if (!publicKey || value.owner?.device?.publicKey !== publicKey) throw fail(403, 'Only the device that shared this page can change its replay.');
    if (replay !== null && (typeof replay !== 'string' || Buffer.byteLength(replay) > REPLAY_LIMIT)) throw fail(413, 'The replay is too large.');
    if (!deviceSigned(publicKey, replayMessage(id, replay === null ? null : hash(replay)), body.signature)) throw fail(403, 'The replay signature does not match.');
    const key = 'replays/' + id, before = await objectStore.quotaRead(key);
    const previous = await currentReplay(id, value.replay);
    let next = { off: true };
    if (replay !== null) {
      if (manifest.statement.contentKind !== 'text') throw fail(422, 'Only written pages have a replay.');
      const [master, stored] = await Promise.all([objectStore.get('objects/' + manifest.master.hash, MASTER_LIMIT),
        objectStore.get('objects/' + manifest.proof.hash, PROOF_LIMIT)]);
      const outer = JSON.parse(Buffer.from(stored).toString('utf8')), page = typeof outer.proof === 'string' ? JSON.parse(outer.proof) : outer;
      const text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(master);
      // Checking a replay runs here, on the server's main thread, so only two run at once.
      if (replaying >= 2) throw fail(429, 'Huma is busy checking other replays. Try again in a minute.');
      replaying++;
      try { await checkReplay(replay, { publicKey: page.publicKey, text }); } catch { throw fail(422, 'That replay isn’t this page’s.'); }
      finally { replaying--; }
      const bytes = Buffer.from(replay);
      await objectStore.put('objects/' + hash(bytes), bytes);
      await objectStore.get('objects/' + hash(bytes), REPLAY_LIMIT);
      next = { hash: hash(bytes), byteLength: bytes.length };
    }
    if (!await objectStore.quotaCAS(key, before?.version ?? null, Buffer.from(JSON.stringify(next))))
      throw fail(409, 'The replay was changed at the same time. Try again.');
    if (previous?.hash && previous.hash !== next.hash) await deleteUnused(id, [previous]);
    return { replay: replay !== null };
  }
  return { handle, close: () => { clearInterval(cleanup); pending.clear(); retained = 0; objectStore.close(); }, storage: objectStore.kind,
    releaseURL: (key, seconds, at) => objectStore.releaseURL?.(key, seconds, at) ?? null,
    releaseExists: async key => (await objectStore.releaseExists?.(key)) === true,
    /** A shared page sent to a writing request: checked like a reader opening the link (token, not removed), with
     *  what the requester's inbox shows. `signature` (optional) is the sharing Mac's signature of requestMessage. */
    requestPage: async (id, token, requestID, signature) => {
      const { manifest, owner, profile } = await record({ headers: { authorization: 'Bearer ' + token } }, id);
      if (manifest.statement.contentKind !== 'text') throw fail(422, 'Only written pages can be sent.');
      const text = new TextDecoder().decode(await objectStore.get('objects/' + manifest.master.hash, MASTER_LIMIT));
      const device = owner?.device?.publicKey;
      return { profile, words: text.split(/\s+/).filter(Boolean).length,
        fromMac: Boolean(device && signature && deviceSigned(device, requestMessage(requestID, id), signature)) };
    },
    objectStore,
    /** The page id a short link's code points to, or null (registry.mjs serves /p/<code> as that page). */
    shortPage: async code => (await shortPage(code))?.id ?? null,
    /** For link previews: the writer's chosen name only (never the text), or null. The link's token isn't sent to crawlers. */
    previewName: async id => {
      try {
        if (await removed(id)) return null;
        return writerProfile(JSON.parse(await objectStore.get('records/' + id, RECORD_LIMIT)).profile)?.name ?? null;
      } catch { return null; }
    },
  };
}
